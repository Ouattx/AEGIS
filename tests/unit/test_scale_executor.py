"""aegis.scale.executor: inline and multiprocess shard clusters behave identically."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import pytest

from aegis.scale.executor import InlineCluster, ProcessCluster, ShardError, make_cluster


class Counter:
    def __init__(self, shard_id: int):
        self.shard_id = shard_id
        self.total = 0

    def handle(self, op: str, payload: Any) -> Any:
        if op == "add":
            self.total += payload
            return (self.shard_id, self.total)
        if op == "env":
            return os.environ.get("OMP_NUM_THREADS")
        if op == "boom":
            raise RuntimeError(f"boom on {self.shard_id}")
        raise ValueError(op)


@dataclass
class CounterFactory:
    def __call__(self, shard_id: int) -> Counter:
        return Counter(shard_id)


@dataclass
class BrokenFactory:
    def __call__(self, shard_id: int) -> Counter:
        raise RuntimeError("cannot build")


def _exercise(cl):
    assert cl.call({0: ("add", 1), 2: ("add", 5)}) == {0: (0, 1), 2: (2, 5)}
    assert cl.call({s: ("add", 10) for s in range(cl.n_shards)})[2] == (2, 15)   # state persists per shard
    cl.submit({1: ("add", 3)})
    with pytest.raises(RuntimeError):
        cl.submit({1: ("add", 3)})             # one batch in flight at a time
    assert cl.collect() == {1: (1, 13)}
    with pytest.raises(RuntimeError):
        cl.collect()
    with pytest.raises(ValueError):
        cl.call({cl.n_shards: ("add", 1)})
    with pytest.raises(ShardError) as ei:
        cl.call({0: ("add", 1), 1: ("boom", None)})
    assert ei.value.shard_id == 1 and "boom on 1" in ei.value.detail
    # the cluster stays usable after a handler error
    assert cl.call({0: ("add", 0)}) == {0: (0, 12)}


def test_inline_cluster():
    with InlineCluster(CounterFactory(), 3) as cl:
        _exercise(cl)
    with pytest.raises(ValueError):
        InlineCluster(CounterFactory(), 0)


def test_process_cluster_matches_inline_and_pins_native_threads():
    with ProcessCluster(CounterFactory(), 3, n_workers=2) as cl:
        assert cl.n_workers == 2
        assert cl.assignment == {"worker-0": [0, 2], "worker-1": [1]}
        _exercise(cl)
        assert set(cl.call({s: ("env", None) for s in range(3)}).values()) == {"1"}
        cpu = cl.worker_cpu_seconds()
        assert len(cpu) == 2 and all(c >= 0 for c in cpu)


def test_process_cluster_init_failure_is_reported():
    with pytest.raises(ShardError) as ei:
        ProcessCluster(BrokenFactory(), 2, n_workers=1)
    assert "cannot build" in ei.value.detail


def test_make_cluster():
    cl = make_cluster(CounterFactory(), 2)
    assert isinstance(cl, InlineCluster)
    cl.close()
    with make_cluster(CounterFactory(), 2, n_workers=1) as pc:
        assert isinstance(pc, ProcessCluster)
        assert pc.call({1: ("add", 2)}) == {1: (1, 2)}
