# aegis.scale — integration guide

Scale-out for AEGIS SHIELD: deterministic sharding, a local multiprocess executor, and
coordinators whose merged results are **identical** to the single-node pipeline on the
same input (tested in `tests/unit/test_scale_*.py` and `tests/fuzz/test_fuzz_scale_routing.py`).

Nothing in `aegis/service.py`, `aegis/api`, `web/` or `aegis/cli.py` calls this package yet.
This page lists the calls an integrator wires in.

## What shards, and on which key

| work | partition key | merge | exact? |
|---|---|---|---|
| parse → normalize → pseudonymize → validate → dedupe | line pseudonym (`Partitioner.line_shard`) | sum of `IngestStats` counters, union of quarantine | yes |
| SENTINEL feature windows + scoring | line pseudonym (same shard as ingest: events never move) | coordinator replays watermark / lateness, sums per-window population counts | yes |
| RESONANCE DNS-answer join | line pseudonym | union of contact rows | yes |
| RESONANCE destination population statistics | destination key (`Partitioner.destination_shard`) | disjoint keys, union of line sets | yes, bit for bit |
| RESONANCE detection (periodograms, permutation null, weighted BH) | not sharded | runs once on the coordinator's canonical table | equals single-node on the canonical table |

Why detection does not shard by destination: the null distribution replaces each member
line's series by *the same line's* series to other destinations, so testing one destination
needs every destination of its lines. At very large populations the remedy is to split the
tenant into independent sub-populations (region, BNG, CGNAT pool) and run one detector per
sub-population; that is a product decision (it changes what "popular" means), not a merge.

Placement is stable: `sha256(namespace || key)` → Lamping–Veach jump consistent hash.
Python's salted `hash()` is never used. Growing from `n` to `n + 1` shards moves about
`1 / (n + 1)` of the lines.

## Public API

```python
from aegis.scale import (
    Partitioner, assign_shards, kafka_partition_for_line, kafka_partition_for_destination,
    InlineCluster, ProcessCluster, make_cluster, ShardCluster, ShardError,
    LineShardConfig, ShardedLinePipeline, ShardedRunResult, FixedClock, merge_ingest_stats,
    ResonanceShardConfig, sharded_resonance_prep, canonical_table, same_population,
    single_node_population, ShardWindowStore, TenantClock, bounded_batches, rss_bytes,
)
```

### Line pipeline (ingest + windows + SENTINEL)

```python
cfg = LineShardConfig(
    sources={sid: source_config, ...},          # the tenant's registered SourceConfig objects
    tenant_keys={tenant_id: key_bytes},         # TenantKeyProvider.key_for(tenant_id)
    mode="sentinel",                            # "ingest" | "features" | "sentinel"
    collect="all",                              # "all": return findings/events; "count": counters only
    model_dir=str(model_dir),                   # or model=<TrainedModel> (pickled to workers)
    bundle=ioc_bundle,                          # verified IOCBundle or None
    allowed_authorizations={tenant_id: [auth_id, ...]},
    evidence_factory=open_tenant_evidence_store,  # picklable: returns EvidenceStore (see below)
    sentinel_kwargs={"tenant_id": tenant_id,
                     "authorized_collections": [...]},   # any Sentinel(...) keyword
)
with make_cluster(cfg, n_shards=8, n_workers=4) as cluster:   # n_workers=0 -> in-process
    pipe = ShardedLinePipeline(cluster, cfg, batch_size=20_000)
    stats = pipe.ingest_file(path, source_id)       # or ingest_text(bytes, source_id, name=...)
    pipe.flush(now)                                 # Sentinel.flush semantics
    result = pipe.finish()                          # ShardedRunResult
```

`ShardedRunResult`: `ingest` (one merged `IngestStats` per input), `quarantine_reasons`,
`events` (mode `ingest`), `features`, `findings`, `quarantined`, counters, `window_stats`,
`sentinel_stats`, `barriers`, `per_shard_events`.

Service wiring (suggested): in `AegisService.ingest_batch`, when `AEGIS_SHARDS > 1`, replace
`self._pipeline(tenant).ingest_text(...)` + `self._sentinel(tenant).process(...)` with one
`ShardedLinePipeline` per tenant kept for the service lifetime (it holds window state), and
persist `result.findings` exactly like the single-node path does. Keep the single-node path
as the default: below roughly 20k events/s one process is enough (see the load report).
`LineShardConfig` fails closed on tenancy: every source's tenant needs a key in `tenant_keys`, and
`mode="sentinel"` accepts exactly one tenant (its `sentinel_kwargs["tenant_id"]` is set from
`tenant_keys` when omitted, and a mismatch raises `ValueError`).

Evidence and ledger from workers: `evidence_factory` runs inside each worker and must return an
`EvidenceStore` on the shared database. The ledger serializes appends per tenant across
processes (PostgreSQL advisory lock; compare-and-swap on `ledger_heads` elsewhere), so chains
stay valid; entries from different shards interleave in arrival order. Use PostgreSQL when
`n_workers > 0`; SQLite works with `InlineCluster`.

Clocks: workers need picklable callables. Use `FixedClock(datetime)` for replays and leave
`clock=None` for wall-clock time.

### RESONANCE hourly job

```python
cluster = ProcessCluster(ResonanceShardConfig(resonance_config), n_shards=4, n_workers=4)
prep = sharded_resonance_prep(cluster, flows_df, dns_df, window=(now - 86_400, now))
prep.population          # PopulationStats: per-destination stats, active_lines, candidate_keys(cfg)
report = Resonance(cfg, context=ctx, history=history, tenant_id=t).detect(prep.table())
```

`prep.table()` is a canonical `EventTable` (vocabularies sorted). Detection on it equals a
single-node run on `canonical_table(build_event_table(...))`. A non-canonical single-node table
can differ (the reference-line sample of the null depends on vocabulary ids), so compare
against the canonical form.

### CLI and API (suggested surface)

- `aegis ingest <file> --source <id> --shards N --workers K` → `ShardedLinePipeline.ingest_file`.
- `aegis load-test [--quick]` → `python -m eval.load.run_load` (writes JSON + HTML).
- `/metrics`: export `ShardedRunResult.per_shard_events` (shard balance) and `barriers`.

## Distributed executors (Kafka partitions / Kubernetes workers)

The coordinator talks to shards only through `ShardCluster`:

```python
class ShardCluster(Protocol):
    n_shards: int
    def submit(self, requests: Mapping[int, tuple[str, Any]]) -> None: ...   # one batch in flight
    def collect(self) -> dict[int, Any]: ...
    def call(self, requests) -> dict[int, Any]: ...                         # submit + collect
    def close(self) -> None: ...
```

A distributed implementation maps shard `i` to a long-lived worker that owns `LineShard(i, cfg)`
(the handler is transport-agnostic: `handle(op, payload)`, payloads are picklable dataclasses).

- **Kubernetes**: a StatefulSet with `n_shards` replicas (or fewer, with `assign_shards`); pod
  ordinal `i` hosts shard `i`; the coordinator calls pods over gRPC/HTTP with the same
  `(op, payload)` messages. Shard state is in memory: on pod restart, rebuild it with
  `Sentinel.warm` from the replayable raw files (the window horizon, 24 h).
- **Kafka**: collectors (or an edge router running `aegis.scale.routing.RecordRouter`) produce
  raw records to a topic with `n_shards` partitions, choosing the partition explicitly with
  `kafka_partition_for_line(pseudonym, n)` (never the client's default key partitioner).
  Each consumer of partition `i` owns `LineShard(i, cfg)`; the coordinator role reduces to the
  window barriers, driven from the partitions' compact `EventDescriptor` stream (a small
  control topic). This removes the coordinator's parse/route cost, which is the measured
  bottleneck of the local executor.
- Exactness requirements for any executor: per-shard FIFO delivery of `step` requests, all
  shards answering every barrier (`bins`, `contexts`, `close`), and the global input order of
  descriptors (the coordinator sorts by position).

## Bounded memory

- Inputs are streamed (`aegis.ingest.parsers` yields record by record; `ingest_file` never loads
  a whole file), the coordinator buffers at most `batch_size` records, each worker holds one
  request (synchronous pipes), and `collect="count"` keeps no per-event output.
- Window state per line is bounded streaming state owned by `aegis.sentinel.features.WindowStore`
  (packed per-hop numpy records, tenant vocabularies shared by all lines, per-hop caps from
  `StateLimits` beyond which a hop keeps a coordinated sample). A shard holds
  `lines_on_shard x (measured bytes per line)` plus its own vocabularies; the measured per-line
  figure and the hard per-line bound are in `eval/load/report`. Pass `window_limits=StateLimits(...)`
  in `LineShardConfig` to change the caps; the IOC bundle given as `bundle` is always retained.
- RESONANCE prep: each destination shard holds only its keys' rows (stage 2), so per-shard memory
  is `events / n_shards` for the population statistics. Detection (stage 3) runs on one population;
  its peak RAM grows linearly with the lines of that population (fit in the load report). The
  bound for a large tenant is per sub-population: split it into independent sub-populations of at
  most `N` lines (region, BNG, CGNAT pool) and run one detector per sub-population, sequentially or
  in parallel; peak RAM is then that of one `N`-line run (measured for `N` = the largest run in the
  load report) times the runs executing at once. `ResonanceStream(max_events=...)` additionally caps
  one population's buffered events (thinning beyond the cap, which costs power).

## Coupling and tests

`ShardWindowStore` re-implements `WindowStore._advance/_emit` with the global context, and the
SENTINEL shard calls `Sentinel._handle` with the coordinator's closing time. Both are guarded
by equality tests against the reference classes (`tests/unit/test_scale_lines.py`); a change in
`aegis.sentinel` that breaks equality fails those tests.
