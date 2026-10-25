"""Shard executors: where per-shard state lives and how the coordinator talks to it.

A *shard handler* is an object that owns the state of one shard (an ingest pipeline,
feature windows, a SENTINEL instance...) and answers named operations::

    class MyHandler:
        def handle(self, op: str, payload: Any) -> Any: ...

Handlers are created inside the executor by a picklable *factory* (``factory(shard_id)``),
so the same code runs in-process (:class:`InlineCluster`, tests and single-host pilots)
or in worker processes (:class:`ProcessCluster`, one process per worker hosting several
shards). The coordinator only ever calls :meth:`ShardCluster.call` with a mapping
``{shard_id: (op, payload)}`` and receives ``{shard_id: result}``: requests to different
workers run in parallel; requests to shards of one worker run sequentially in shard order.

Memory is bounded by construction: each worker has exactly one request in flight (a
synchronous pipe), so the coordinator never queues more than one batch per shard.

Distributed executors (Kafka partitions, Kubernetes workers) implement the same
:class:`ShardCluster` protocol; see ``aegis/scale/INTEGRATION.md``.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import time
import traceback
from multiprocessing.connection import Connection
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from aegis.scale.partition import assign_shards


@runtime_checkable
class ShardHandler(Protocol):
    def handle(self, op: str, payload: Any) -> Any: ...


HandlerFactory = Callable[[int], ShardHandler]

_CPU_PROBE = "__cpu__"

#: environment of worker processes: native libraries run one thread per worker
SINGLE_THREADED_NATIVE: dict[str, str] = {"OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1",
                                          "MKL_NUM_THREADS": "1", "NUMEXPR_NUM_THREADS": "1"}


class ShardError(RuntimeError):
    """A shard handler raised; carries the shard id and the remote traceback."""

    def __init__(self, shard_id: int, op: str, detail: str):
        super().__init__(f"shard {shard_id} failed on {op!r}:\n{detail}")
        self.shard_id = shard_id
        self.op = op
        self.detail = detail


class ShardCluster(Protocol):
    """Scatter/gather access to shard handlers.

    ``submit`` sends one request per shard without waiting (at most one batch may be in
    flight); ``collect`` waits for that batch's replies. ``call`` is ``submit`` + ``collect``.
    Pipelining ``submit`` with coordinator work (parsing the next batch) is how the
    coordinator overlaps with the shards.
    """
    n_shards: int

    def submit(self, requests: Mapping[int, tuple[str, Any]]) -> None: ...

    def collect(self) -> dict[int, Any]: ...

    def call(self, requests: Mapping[int, tuple[str, Any]]) -> dict[int, Any]: ...

    def close(self) -> None: ...


def _check(requests: Mapping[int, tuple[str, Any]], n_shards: int) -> None:
    for s in requests:
        if not isinstance(s, int) or not 0 <= s < n_shards:
            raise ValueError(f"unknown shard id {s!r} (cluster has {n_shards} shards)")


class InlineCluster:
    """All shards in the calling process (deterministic, no parallelism)."""

    def __init__(self, factory: HandlerFactory, n_shards: int):
        if n_shards < 1:
            raise ValueError("n_shards must be positive")
        self.n_shards = n_shards
        self.handlers = {s: factory(s) for s in range(n_shards)}
        self._pending: dict[int, Any] | None = None
        self._error: ShardError | None = None

    def submit(self, requests: Mapping[int, tuple[str, Any]]) -> None:
        if self._pending is not None or self._error is not None:
            raise RuntimeError("a batch is already in flight; collect() it first")
        _check(requests, self.n_shards)
        out: dict[int, Any] = {}
        for s in sorted(requests):
            op, payload = requests[s]
            try:
                out[s] = self.handlers[s].handle(op, payload)
            except Exception:  # same error surface as ProcessCluster
                self._error = ShardError(s, op, traceback.format_exc())
                return
        self._pending = out

    def collect(self) -> dict[int, Any]:
        if self._error is not None:
            err, self._error = self._error, None
            raise err
        if self._pending is None:
            raise RuntimeError("no batch in flight")
        out, self._pending = self._pending, None
        return out

    def call(self, requests: Mapping[int, tuple[str, Any]]) -> dict[int, Any]:
        self.submit(requests)
        return self.collect()

    def close(self) -> None:
        self.handlers.clear()

    def __enter__(self) -> "InlineCluster":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _worker_main(conn: Connection, factory: HandlerFactory, shard_ids: list[int]) -> None:
    handlers: dict[int, ShardHandler] = {}
    try:
        handlers = {s: factory(s) for s in shard_ids}
        conn.send(("ready", None))
    except Exception:
        conn.send(("error", (-1, "init", traceback.format_exc())))
        return
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            return
        if msg is None:
            return
        if msg == _CPU_PROBE:
            conn.send(("ok", time.process_time()))
            continue
        results: dict[int, Any] = {}
        failure = None
        for s, op, payload in msg:
            try:
                results[s] = handlers[s].handle(op, payload)
            except Exception:
                failure = (s, op, traceback.format_exc())
                break
        conn.send(("error", failure) if failure else ("ok", results))


class ProcessCluster:
    """Shards hosted by ``n_workers`` OS processes (``multiprocessing``).

    ``start_method`` defaults to ``"spawn"``: forking a parent that already loaded
    OpenMP-backed libraries (LightGBM, BLAS) can deadlock the child.

    ``worker_env`` is applied to the workers' environment. By default every worker runs
    single-threaded native code (``OMP_NUM_THREADS=1`` ...): the parallelism is the workers
    themselves, and letting each worker's LightGBM/BLAS also start one thread per core
    oversubscribes the host (measured: about 10x more CPU per scored window on 4 cores).
    """

    def __init__(self, factory: HandlerFactory, n_shards: int, n_workers: int | None = None, *,
                 start_method: str = "spawn", timeout_s: float = 3600.0,
                 worker_env: Mapping[str, str] | None = None):
        if n_shards < 1:
            raise ValueError("n_shards must be positive")
        n_workers = min(n_shards, n_workers or mp.cpu_count() or 1)
        self.n_shards = n_shards
        self.timeout_s = timeout_s
        ctx = mp.get_context(start_method)
        names = [f"worker-{i}" for i in range(n_workers)]
        self.assignment = assign_shards(n_shards, names)
        self._owner: dict[int, int] = {}
        self._conns: list[Connection] = []
        self._procs: list[Any] = []
        self._in_flight: list[int] | None = None
        env = dict(SINGLE_THREADED_NATIVE if worker_env is None else worker_env)
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            for i, name in enumerate(names):
                parent, child = ctx.Pipe()
                proc = ctx.Process(target=_worker_main, args=(child, factory, self.assignment[name]),
                                   name=f"aegis-shard-{name}", daemon=True)
                proc.start()
                child.close()
                self._conns.append(parent)
                self._procs.append(proc)
                for s in self.assignment[name]:
                    self._owner[s] = i
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        try:
            for i, conn in enumerate(self._conns):
                status, info = self._recv(conn, i)
                if status != "ready":
                    raise ShardError(info[0], info[1], info[2])
        except BaseException:
            self.close()
            raise

    def _recv(self, conn: Connection, worker: int) -> tuple[str, Any]:
        if not conn.poll(self.timeout_s):
            raise TimeoutError(f"worker {worker} did not answer within {self.timeout_s:.0f} s")
        try:
            return conn.recv()
        except EOFError as exc:
            raise RuntimeError(f"worker {worker} exited unexpectedly") from exc

    @property
    def n_workers(self) -> int:
        return len(self._conns)

    def submit(self, requests: Mapping[int, tuple[str, Any]]) -> None:
        if self._in_flight is not None:
            raise RuntimeError("a batch is already in flight; collect() it first")
        _check(requests, self.n_shards)
        per_worker: dict[int, list[tuple[int, str, Any]]] = {}
        for s in sorted(requests):
            op, payload = requests[s]
            per_worker.setdefault(self._owner[s], []).append((s, op, payload))
        for w, batch in per_worker.items():
            self._conns[w].send(batch)
        self._in_flight = list(per_worker)

    def call(self, requests: Mapping[int, tuple[str, Any]]) -> dict[int, Any]:
        self.submit(requests)
        return self.collect()

    def collect(self) -> dict[int, Any]:
        if self._in_flight is None:
            raise RuntimeError("no batch in flight")
        workers, self._in_flight = self._in_flight, None
        out: dict[int, Any] = {}
        first_error: ShardError | None = None
        for w in workers:                         # always drain every reply (keeps pipes in sync)
            status, info = self._recv(self._conns[w], w)
            if status == "ok":
                out.update(info)
            elif first_error is None:
                first_error = ShardError(info[0], info[1], info[2])
        if first_error is not None:
            raise first_error
        return out

    def worker_cpu_seconds(self) -> list[float]:
        """CPU seconds consumed so far by each worker process (load tests, capacity planning)."""
        if self._in_flight is not None:
            raise RuntimeError("collect() the in-flight batch first")
        for conn in self._conns:
            conn.send(_CPU_PROBE)
        return [float(self._recv(conn, i)[1]) for i, conn in enumerate(self._conns)]

    def close(self) -> None:
        for conn in self._conns:
            try:
                conn.send(None)
            except (OSError, BrokenPipeError):
                pass
        for proc in self._procs:
            proc.join(timeout=10)
            if proc.is_alive():
                proc.terminate()
        for conn in self._conns:
            conn.close()
        self._conns, self._procs = [], []

    def __enter__(self) -> "ProcessCluster":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def make_cluster(factory: HandlerFactory, n_shards: int, *, n_workers: int = 0,
                 start_method: str = "spawn") -> InlineCluster | ProcessCluster:
    """``n_workers == 0`` -> :class:`InlineCluster`; otherwise a :class:`ProcessCluster`."""
    if n_workers <= 0:
        return InlineCluster(factory, n_shards)
    return ProcessCluster(factory, n_shards, n_workers, start_method=start_method)
