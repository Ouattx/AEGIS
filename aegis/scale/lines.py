"""Line-sharded ingestion, feature windows and SENTINEL scoring.

Data path (one coordinator, ``n`` shards)::

    collector bytes --route by line pseudonym (RecordRouter)--> shard i
        shard i: parse + normalize + pseudonymize + validate + dedupe (IngestPipeline)
                 -> buffered events, compact descriptors back to the coordinator
    coordinator: TenantClock over descriptors in input order -> apply / barrier
        shard i: feature windows (ShardWindowStore) [-> SENTINEL scoring]

The coordinator only extracts each record's identifier and routes (NetFlow CSV and DNS
JSONL lines travel as original bytes; other formats are parsed on the coordinator); the
expensive parsing, normalization, validation, window aggregation and scoring run on the
shards in parallel, pipelined with the coordinator's routing of the next batch.
Events never leave their shard: ingestion shard ``i`` and feature shard ``i`` are the same
object, because both are keyed by the same line pseudonym hash.

Equivalence guarantee (tested): for any input, the merged result equals a single
:class:`~aegis.ingest.pipeline.IngestPipeline` feeding one ``WindowStore`` / ``Sentinel``
(same accepted events, quarantine reasons, duplicates, feature vectors and findings),
up to random ids (``event_id``, ``finding_id``) and output order.
"""
from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Literal

from aegis.contracts.models import FeatureVector, Finding, ObservationEvent
from aegis.ingest import parsers
from aegis.ingest.bus import OBSERVATIONS_TOPIC
from aegis.ingest.normalize import SourceConfig
from aegis.ingest.pipeline import IngestPipeline, IngestStats
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.ingest.validator import QuarantineStore, Quarantined, Validator, make_quarantined
from aegis.scale.executor import ShardCluster
from aegis.scale.partition import Partitioner
from aegis.scale.routing import (  # noqa: F401  (route_raw / routing_identifier re-exported)
    FormatContext,
    Item,
    RecordRouter,
    decode_items,
    route_raw,
    routing_identifier,
)
from aegis.scale.windows import (
    ClosePlan,
    EventDescriptor,
    ShardWindowStore,
    TenantClock,
    TenantGlobal,
    WindowContext,
    plan_close,
)
from aegis.sentinel.features import DEFAULT_MAX_SOURCE_EVENT_IDS, StateLimits

log = logging.getLogger(__name__)

Mode = Literal["ingest", "features", "sentinel"]
Collect = Literal["all", "count"]


# ----------------------------------------------------------------------------- helpers

@dataclass(frozen=True)
class FixedClock:
    """Picklable constant clock (replays, tests, load runs with a fixed ingest time)."""
    at: datetime

    def __call__(self) -> datetime:
        return self.at


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CollectingBus:
    """Synchronous :class:`~aegis.ingest.bus.EventBus`: every publish is delivered to the
    subscribers of its topic immediately, in order (no queue, so never backpressure)."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[[Any], None]]] = {}
        self.published = 0

    def publish(self, topic: str, event: Any) -> None:
        self.published += 1
        for h in self._handlers.get(topic, ()):
            h(event)

    def subscribe(self, topic: str, handler: Callable[[Any], None]) -> None:
        self._handlers.setdefault(topic, []).append(handler)

    def drain(self) -> int:
        return 0


def merge_ingest_stats(parts: Iterable[IngestStats], *, source_id: str, tenant_id: str, input_ref: str,
                       fmt: str) -> IngestStats:
    """Sum counters and reason dicts of per-shard :class:`IngestStats` (field-generic, so new
    counters added to ``IngestStats`` are merged without changes here)."""
    out = IngestStats(source_id=source_id, tenant_id=tenant_id, input_ref=input_ref, format=fmt)
    parts = list(parts)
    for f in fields(IngestStats):
        if f.name in ("source_id", "tenant_id", "input_ref", "format"):
            continue
        vals = [getattr(p, f.name) for p in parts]
        cur = getattr(out, f.name)
        if isinstance(cur, bool):
            continue
        if isinstance(cur, int):
            setattr(out, f.name, sum(vals))
        elif isinstance(cur, float):
            setattr(out, f.name, max(vals) if f.name == "elapsed_s" and vals else sum(vals))
        elif isinstance(cur, dict):
            c: Counter[str] = Counter()
            for v in vals:
                c.update(v)
            setattr(out, f.name, dict(sorted(c.items())))
    starts = [p.started_at for p in parts if p.started_at is not None]
    ends = [p.finished_at for p in parts if p.finished_at is not None]
    if starts:
        out.started_at = min(starts)
    out.finished_at = max(ends) if ends else None
    return out


# ----------------------------------------------------------------------------- shard side

@dataclass
class LineShardConfig:
    """Picklable factory of :class:`LineShard` (one per shard, built inside the executor).

    ``mode``: ``ingest`` (normalize/validate only), ``features`` (+ feature windows) or
    ``sentinel`` (+ SENTINEL scoring; requires ``model`` or ``model_dir``, optional ``bundle``).
    ``collect``: ``all`` keeps events / feature vectors / findings / quarantined records for
    :meth:`ShardedLinePipeline.finish`; ``count`` keeps only counters (load tests, bounded memory).
    """
    sources: dict[str, SourceConfig]
    tenant_keys: dict[str, bytes]
    mode: Mode = "features"
    collect: Collect = "all"
    clock: Callable[[], datetime] | None = None
    allowed_authorizations: dict[str, list[str]] | None = None
    max_clock_skew_s: int = 300
    dedupe_window: int = 1_000_000
    window: str = "24h"
    hop_s: int | None = None
    allowed_lateness_s: float = 120.0
    max_future_skew_s: float = 600.0
    min_population: int = 20
    max_source_event_ids: int | None = DEFAULT_MAX_SOURCE_EVENT_IDS
    model: Any = None
    model_dir: str | None = None
    bundle: Any = None
    window_ioc_bundle: bool = False
    window_limits: StateLimits | None = None
    sentinel_kwargs: dict[str, Any] = field(default_factory=dict)
    #: builds the shard's :class:`~aegis.provenance.evidence.EvidenceStore` (picklable for
    #: ProcessCluster, e.g. a top-level function opening the tenant database); ``None`` means
    #: findings are returned to the coordinator without persisted evidence (load tests only)
    evidence_factory: Callable[[], Any] | None = None

    def __post_init__(self) -> None:
        # Fail closed on tenancy: every source must belong to a tenant with a pseudonym key, and a
        # SENTINEL shard (which persists evidence and findings) serves exactly one tenant, so a
        # shared shard can never mix tenants' detector state or write into another tenant's store.
        foreign = sorted({src.tenant_id for src in self.sources.values()} - set(self.tenant_keys))
        if foreign:
            raise ValueError(f"sources of tenants without a pseudonym key: {foreign}")
        if self.mode == "sentinel":
            if len(self.tenant_keys) != 1:
                raise ValueError("mode='sentinel' serves exactly one tenant: run one pipeline per tenant")
            (tenant,) = self.tenant_keys
            given = self.sentinel_kwargs.get("tenant_id")
            if given is not None and given != tenant:
                raise ValueError("sentinel_kwargs['tenant_id'] does not match tenant_keys")
            self.sentinel_kwargs = {**self.sentinel_kwargs, "tenant_id": tenant}

    def window_kwargs(self) -> dict[str, Any]:
        return dict(hop=timedelta(seconds=self.hop_s) if self.hop_s else None,
                    allowed_lateness=timedelta(seconds=self.allowed_lateness_s),
                    max_future_skew=timedelta(seconds=self.max_future_skew_s),
                    min_population=self.min_population, max_source_event_ids=self.max_source_event_ids,
                    ioc_bundle=self.bundle if self.window_ioc_bundle else None, retain_bundle=self.bundle,
                    limits=self.window_limits)

    def __call__(self, shard_id: int) -> "LineShard":
        return LineShard(shard_id, self)


@dataclass
class ShardResult:
    shard_id: int
    quarantine_reasons: dict[str, dict[str, int]]
    events: list[ObservationEvent]
    quarantined: list[Quarantined]
    features: list[FeatureVector]
    findings: list[Finding]
    n_events: int
    n_features: int
    n_findings: int
    window_stats: dict[str, int]
    sentinel_stats: dict[str, Any]


class LineShard:
    """State of one line shard: ingest pipeline, buffered events, windows, SENTINEL."""

    def __init__(self, shard_id: int, cfg: LineShardConfig):
        self.shard_id = shard_id
        self.cfg = cfg
        clock = cfg.clock or utc_now
        self.quarantine = QuarantineStore(max_items=100_000 if cfg.collect == "all" else 1)
        validator = Validator(allowed_authorizations=cfg.allowed_authorizations, max_clock_skew_s=cfg.max_clock_skew_s,
                              clock=clock)
        self._pos = -1
        self._buffer: list[tuple[int, ObservationEvent]] = []
        self._descriptors: list[EventDescriptor] = []
        self.bus = CollectingBus()
        self.bus.subscribe(OBSERVATIONS_TOPIC, self._on_publish)
        self.pipeline = IngestPipeline(self.bus, validator, cfg.sources,
                                       pseudonymizers={t: Pseudonymizer(k) for t, k in cfg.tenant_keys.items()},
                                       quarantine=self.quarantine, clock=clock, dedupe_window=cfg.dedupe_window)
        self.events: list[ObservationEvent] = []
        self.features: list[FeatureVector] = []
        self.findings: list[Finding] = []
        self.n_events = self.n_features = self.n_findings = 0
        self.store: ShardWindowStore | None = None
        self.sentinel: Any = None
        if cfg.mode in ("features", "sentinel"):
            self.store = ShardWindowStore(cfg.window, **cfg.window_kwargs())  # type: ignore[arg-type]
        if cfg.mode == "sentinel":
            from aegis.sentinel.detector import Sentinel
            from aegis.sentinel.model import load as load_model
            model = cfg.model if cfg.model is not None else (load_model(cfg.model_dir) if cfg.model_dir else None)
            evidence = cfg.evidence_factory() if cfg.evidence_factory is not None else None
            self.sentinel = Sentinel(model, cfg.bundle, evidence, window_store=self.store, **cfg.sentinel_kwargs)

    # ------------------------------------------------------------------ ingest
    def _on_publish(self, ev: ObservationEvent) -> None:
        self.n_events += 1
        if self.cfg.collect == "all" and self.cfg.mode == "ingest":
            self.events.append(ev)
        if self.store is None:
            return
        ok = self.store.admissible(ev)
        if ok and self.sentinel is not None:
            from aegis.sentinel.detector import EventRejected
            try:
                self.sentinel.validate(ev)
            except EventRejected:
                ok = False
        self._buffer.append((self._pos, ev))
        self._descriptors.append(EventDescriptor(
            self._pos, ev.tenant_id, ev.observed_at.timestamp(), ev.ingested_at.timestamp(),
            ev.flow is not None, ev.dns is not None, ok))

    def _positioned(self, items: Iterable[tuple[int, dict[str, Any]]]) -> Iterator[dict[str, Any]]:
        for pos, raw in items:
            self._pos = pos
            yield raw

    def _ingest(self, payload: tuple[str, str, FormatContext, list[tuple[int, Item]]]
                ) -> tuple[list[EventDescriptor], IngestStats]:
        source_id, input_ref, context, items = payload
        self._descriptors = []
        stats = self.pipeline.ingest_records(self._positioned(decode_items(context, items)), source_id,
                                             name=input_ref)
        out, self._descriptors = self._descriptors, []
        return out, stats

    def _parse_failure(self, payload: tuple[str, str, str]) -> IngestStats:
        """Whole-input parse failure: same marker quarantine record as ``IngestPipeline``."""
        source_id, input_ref, message = payload
        src = self.pipeline.source(source_id)
        q = make_quarantined(message.encode("utf-8"), "unparseable_input", detail=message,
                             tenant_id=src.tenant_id, source_id=src.source_id, stage="parse",
                             raw_artifact_ref=f"raw://{src.source_id}/{input_ref}",
                             now=self.pipeline.clock(), retention_days=src.retention_days)
        self.quarantine.put(q)
        return IngestStats(source_id=src.source_id, tenant_id=src.tenant_id, input_ref=input_ref,
                           format=src.parser_format, quarantined=1, quarantine_reasons={q.reason: 1})

    # ------------------------------------------------------------------ windows
    def _apply(self, payload: tuple[int, dict[str, TenantGlobal]]) -> int:
        upto, primes = payload
        assert self.store is not None
        for tid, g in primes.items():
            self.store.prime(tid, g)
        n = 0
        keep: list[tuple[int, ObservationEvent]] = []
        for pos, ev in self._buffer:
            if pos > upto:
                keep.append((pos, ev))
                continue
            if self.sentinel is not None:
                self.sentinel.process(ev)
            else:
                self.store.update(ev)
            n += 1
        self._buffer = keep
        return n

    def _close(self, payload: tuple[ClosePlan, dict[int, WindowContext], TenantGlobal, datetime | None,
                                    datetime | None]) -> int:
        plan, contexts, g, closing_ingested_at, latest = payload
        assert self.store is not None
        fvs = self.store.close(plan, contexts, g)
        if self.sentinel is None:
            self.n_features += len(fvs)
            if self.cfg.collect == "all":
                self.features.extend(fvs)
            return len(fvs)
        s = self.sentinel
        # Mirror Sentinel.process/flush exactly: the single-node detector prunes idle entity state
        # against the latest window of the *global* close and stamps findings with the ingest
        # time of the event (or flush) that closed the windows.
        if latest is not None and (s._last_prune is None or latest - s._last_prune >= timedelta(days=1)):
            s.prune(latest)
            s._last_prune = latest
        if not fvs:
            return 0
        s._closing_ingested_at = closing_ingested_at
        found = s._handle(fvs)
        self.n_features += len(fvs)
        self.n_findings += len(found)
        if self.cfg.collect == "all":
            self.features.extend(fvs)
            self.findings.extend(found)
        return len(found)

    def _finish(self) -> ShardResult:
        tenants = sorted({src.tenant_id for src in self.cfg.sources.values()} | {"_unknown"})
        reasons = {t: self.quarantine.reasons(t) for t in tenants if self.quarantine.reasons(t)}
        quarantined = [q for t in tenants for q in self.quarantine.list(t, limit=10**9)] \
            if self.cfg.collect == "all" else []
        ws = vars(self.store.stats).copy() if self.store is not None else {}
        ss: dict[str, Any] = {}
        if self.sentinel is not None:
            st = self.sentinel.stats
            ss = {k: (dict(v) if isinstance(v, Counter) else v) for k, v in vars(st).items()}
        return ShardResult(self.shard_id, reasons, self.events, quarantined, self.features,
                           self.findings, self.n_events, self.n_features, self.n_findings, ws, ss)

    def _step(self, payload: tuple[tuple[int, dict[str, TenantGlobal]] | None,
                                   tuple[str, str, FormatContext, list[tuple[int, Item]]] | None]
              ) -> tuple[list[EventDescriptor], IngestStats | None]:
        """Apply buffered events up to a position (window state), then ingest a new batch."""
        apply, ingest = payload
        if apply is not None and self.store is not None:
            self._apply(apply)
        if ingest is None:
            return [], None
        return self._ingest(ingest)

    def handle(self, op: str, payload: Any) -> Any:
        if op == "step":
            return self._step(payload)
        if op == "ingest":
            return self._ingest(payload)
        if op == "parse_failure":
            return self._parse_failure(payload)
        if op == "apply":
            return self._apply(payload)
        if op == "bins":
            return self.store.bin_indices(payload) if self.store is not None else set()
        if op == "contexts":
            tenant_id, ends = payload
            return self.store.local_contexts(tenant_id, ends) if self.store is not None else {}
        if op == "close":
            return self._close(payload)
        if op == "finish":
            return self._finish()
        raise ValueError(f"unknown op {op!r}")


# ----------------------------------------------------------------------------- coordinator

@dataclass
class ShardedRunResult:
    ingest: list[IngestStats]
    quarantine_reasons: dict[str, dict[str, int]]
    events: list[ObservationEvent]
    quarantined: list[Quarantined]
    features: list[FeatureVector]
    findings: list[Finding]
    n_events: int
    n_features: int
    n_findings: int
    window_stats: dict[str, int]
    sentinel_stats: dict[str, Any]
    barriers: int
    per_shard_events: dict[int, int]


class ShardedLinePipeline:
    """Coordinator of line shards (see module docstring).

    ``cluster`` must have been built with a :class:`LineShardConfig` factory whose
    ``sources``/``tenant_keys`` match the ones given here. ``batch_size`` raw records are
    buffered (across shards) before a parallel dispatch: coordinator memory is
    ``O(batch_size)``, shard memory is the window state plus one batch.
    """

    def __init__(self, cluster: ShardCluster, cfg: LineShardConfig, *, batch_size: int = 5_000,
                 route_cache_size: int = 1_000_000):
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self.cluster = cluster
        self.cfg = cfg
        self.partitioner = Partitioner(cluster.n_shards)
        self.batch_size = batch_size
        self.pseudonymizers = {t: Pseudonymizer(k) for t, k in cfg.tenant_keys.items()}
        hop = timedelta(seconds=cfg.hop_s) if cfg.hop_s else None
        self.clock = TenantClock(cfg.window, hop, allowed_lateness=timedelta(seconds=cfg.allowed_lateness_s)) \
            if cfg.mode != "ingest" else None  # type: ignore[arg-type]
        self._pos = 0
        self.barriers = 0
        self.runs: list[IngestStats] = []
        self._in_flight = False
        self._pending_apply: int | None = None
        self._route_cache: dict[tuple[str, str], int] = {}
        self.route_cache_size = route_cache_size

    # ------------------------------------------------------------------ input
    def ingest_file(self, path: str | Path, source_id: str) -> IngestStats:
        """Ingest one collector file (``.gz`` supported) from a registered source."""
        p = Path(path)
        return self._run(p, None, self.cfg.sources[source_id], p.name)

    def ingest_text(self, data: str | bytes, source_id: str, name: str = "inline") -> IngestStats:
        """Ingest an in-memory payload (e.g. an API upload) from a registered source."""
        payload = data.encode("utf-8") if isinstance(data, str) else data
        return self._run(payload, None, self.cfg.sources[source_id], name)

    def ingest_records(self, records: Iterable[dict[str, Any]], source_id: str, name: str = "records") -> IngestStats:
        """Ingest already-parsed raw records (canonical keys, see ``aegis.ingest.parsers``)."""
        return self._run(None, iter(records), self.cfg.sources[source_id], name)

    def _run(self, payload: bytes | Path | None, records: Iterable[dict[str, Any]] | None, src: SourceConfig,
             input_ref: str) -> IngestStats:
        """Route, dispatch and merge one input; returns its merged :class:`IngestStats`.

        Dispatch is pipelined: while the shards process batch ``n`` the coordinator parses and
        routes batch ``n + 1``; the window bookkeeping of batch ``n`` (descriptors, barriers)
        runs when its replies arrive, and its ``apply`` step rides on the next batch's request.
        """
        router = RecordRouter(src, self.pseudonymizers[src.tenant_id], self.partitioner, self._route_cache,
                              self.route_cache_size)
        stream = router.route_records(records) if records is not None else router.route(payload)  # type: ignore[arg-type]
        buffers: dict[int, list[tuple[int, Item]]] = {}
        n_buf = 0
        parts: list[IngestStats] = []
        failure: str | None = None
        t0 = time.perf_counter()
        started = utc_now()
        try:
            for shard, item in stream:
                buffers.setdefault(shard, []).append((self._pos, item))
                self._pos += 1
                n_buf += 1
                if n_buf >= self.batch_size:
                    self._submit_batch(buffers, src, input_ref, router.context, parts)
                    buffers, n_buf = {}, 0
        except parsers.ParseError as exc:
            failure = str(exc)
        if buffers:
            self._submit_batch(buffers, src, input_ref, router.context, parts)
        self._drain(parts)
        if failure is not None:
            parts.append(self.cluster.call({0: ("parse_failure", (src.source_id, input_ref, failure))})[0])
        merged = merge_ingest_stats(parts, source_id=src.source_id, tenant_id=src.tenant_id, input_ref=input_ref,
                                    fmt=src.parser_format)
        merged.started_at = started
        merged.finished_at = utc_now()
        merged.elapsed_s = time.perf_counter() - t0
        self.runs.append(merged)
        log.info("sharded ingest of %s from %s over %d shards: %d read, %d published, %d quarantined, "
                 "%d duplicates in %.2f s", input_ref, src.source_id, self.cluster.n_shards, merged.records_read,
                 merged.published, merged.quarantined, merged.duplicates, merged.elapsed_s)
        return merged

    def _primes(self) -> dict[str, TenantGlobal]:
        assert self.clock is not None
        return {t: TenantGlobal(**vars(g)) for t, g in self.clock.tenants.items()}

    def _submit_batch(self, buffers: dict[int, list[tuple[int, Item]]], src: SourceConfig,
                      input_ref: str, context: FormatContext | None, parts: list[IngestStats]) -> None:
        if self._in_flight:
            self._collect(parts)
        apply = (self._pending_apply, self._primes()) if self._pending_apply is not None else None
        targets = range(self.cluster.n_shards) if apply is not None else sorted(buffers)
        ctx = context or FormatContext("records")
        self.cluster.submit({s: ("step", (apply, (src.source_id, input_ref, ctx, buffers[s]) if s in buffers else None))
                             for s in targets})
        self._pending_apply = None
        self._in_flight = True

    def _collect(self, parts: list[IngestStats]) -> None:
        replies = self.cluster.collect()
        self._in_flight = False
        descs: list[EventDescriptor] = []
        for s in sorted(replies):
            ds, st = replies[s]
            if st is not None:
                parts.append(st)
            descs.extend(ds)
        if self.clock is None or not descs:
            return
        descs.sort(key=lambda d: d.position)
        for d in descs:
            wm = self.clock.observe(d)
            if wm is not None:
                self._apply_now(d.position)
                closing = datetime.fromtimestamp(d.ingested_ts, tz=timezone.utc)
                self._barrier(d.tenant_id, wm, closing)
        self._pending_apply = descs[-1].position

    def _drain(self, parts: list[IngestStats] | None = None) -> None:
        if self._in_flight:
            self._collect(parts if parts is not None else [])
        if self._pending_apply is not None:
            self._apply_now(self._pending_apply)

    def _apply_now(self, pos: int) -> None:
        self.cluster.call({s: ("step", ((pos, self._primes()), None)) for s in range(self.cluster.n_shards)})
        self._pending_apply = None

    def _barrier(self, tenant_id: str, watermark: float, closing_ingested_at: datetime | None) -> None:
        assert self.clock is not None
        all_shards = range(self.cluster.n_shards)
        bins: set[int] = set()
        for b in self.cluster.call({s: ("bins", tenant_id) for s in all_shards}).values():
            bins |= b
        g = self.clock.tenants[tenant_id]
        plan = plan_close(bins, g.next_boundary_idx, watermark, self.clock.hop_s, self.clock.n_bins, tenant_id)
        self.barriers += 1
        contexts: dict[int, WindowContext] = {}
        if plan.end_indices:
            parts = self.cluster.call({s: ("contexts", (tenant_id, plan.end_indices)) for s in all_shards})
            for e in plan.end_indices:
                contexts[e] = WindowContext.merge(parts[s][e] for s in sorted(parts))
        latest = datetime.fromtimestamp(plan.end_indices[-1] * self.clock.hop_s, tz=timezone.utc) \
            if plan.end_indices else None
        snapshot = TenantGlobal(**vars(g))
        self.cluster.call({s: ("close", (plan, contexts, snapshot, closing_ingested_at, latest)) for s in all_shards})
        self.clock.apply_plan(plan)

    def flush(self, now: datetime) -> None:
        """Close every window ending at or before ``now`` (``WindowStore.flush`` / ``Sentinel.flush``).

        Findings closed by a flush are stamped with ``now`` as their ingest reference unless the
        SENTINEL config carries a clock (then that clock's time), exactly like ``Sentinel.flush``.
        """
        if self.clock is None:
            return
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        self._drain()
        sclock = self.cfg.sentinel_kwargs.get("clock")
        closing = sclock() if callable(sclock) else now
        for tid in sorted(self.clock.tenants):
            wm = self.clock.flush_watermark(tid, now.astimezone(timezone.utc).timestamp())
            self._barrier(tid, wm, closing)

    # ------------------------------------------------------------------ output
    def finish(self) -> ShardedRunResult:
        self._drain()
        replies: dict[int, ShardResult] = self.cluster.call({s: ("finish", None)
                                                             for s in range(self.cluster.n_shards)})
        results = [replies[s] for s in sorted(replies)]
        reasons: dict[str, Counter[str]] = {}
        for r in results:
            for t, rs in r.quarantine_reasons.items():
                reasons.setdefault(t, Counter()).update(rs)
        ws: Counter[str] = Counter()
        for r in results:
            ws.update(r.window_stats)
        ss: dict[str, Any] = {}
        for r in results:
            for k, v in r.sentinel_stats.items():
                if isinstance(v, dict):
                    c = Counter(ss.get(k, {}))
                    c.update(v)
                    ss[k] = dict(c)
                else:
                    ss[k] = ss.get(k, 0) + v
        return ShardedRunResult(
            ingest=list(self.runs), quarantine_reasons={t: dict(sorted(c.items())) for t, c in sorted(reasons.items())},
            events=[e for r in results for e in r.events], quarantined=[q for r in results for q in r.quarantined],
            features=[f for r in results for f in r.features], findings=[f for r in results for f in r.findings],
            n_events=sum(r.n_events for r in results), n_features=sum(r.n_features for r in results),
            n_findings=sum(r.n_findings for r in results), window_stats=dict(ws), sentinel_stats=ss,
            barriers=self.barriers, per_shard_events={r.shard_id: r.n_events for r in results})


__all__ = ["CollectingBus", "FixedClock", "LineShard", "LineShardConfig", "ShardResult", "ShardedLinePipeline",
           "ShardedRunResult", "merge_ingest_stats", "route_raw", "routing_identifier", "utc_now"]
