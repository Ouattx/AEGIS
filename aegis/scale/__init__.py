"""AEGIS scale-out: deterministic sharding, local multiprocess executor, exact merges.

Public API::

    from aegis.scale import (Partitioner, InlineCluster, ProcessCluster, make_cluster,
                             LineShardConfig, ShardedLinePipeline, FixedClock,
                             ResonanceShardConfig, sharded_resonance_prep, canonical_table)

    cfg = LineShardConfig(sources=sources, tenant_keys={tenant: key}, mode="sentinel", model=model)
    with make_cluster(cfg, n_shards=8, n_workers=4) as cluster:
        pipe = ShardedLinePipeline(cluster, cfg)
        pipe.ingest_file("netflow.csv", "netflow-par1")
        pipe.flush(now)
        result = pipe.finish()        # merged IngestStats, findings, feature vectors, quarantine

See ``aegis/scale/INTEGRATION.md`` for integration calls and the distributed-executor contract.
"""
from aegis.scale.executor import (
    InlineCluster,
    ProcessCluster,
    ShardCluster,
    ShardError,
    ShardHandler,
    make_cluster,
)
from aegis.scale.lines import (
    CollectingBus,
    FixedClock,
    LineShard,
    LineShardConfig,
    ShardedLinePipeline,
    ShardedRunResult,
    merge_ingest_stats,
    route_raw,
    routing_identifier,
)
from aegis.scale.partition import (
    Partitioner,
    assign_shards,
    jump_consistent_hash,
    kafka_partition_for_destination,
    kafka_partition_for_line,
    moved_fraction,
)
from aegis.scale.population import (
    ContactRows,
    PopulationStats,
    ResonanceShardConfig,
    ShardedPrepResult,
    canonical_table,
    line_contacts,
    merge_contacts,
    merge_population,
    same_population,
    sharded_resonance_prep,
    single_node_population,
)
from aegis.scale.streaming import bounded_batches, rss_bytes
from aegis.scale.windows import ShardWindowStore, TenantClock, WindowContext, plan_close

__all__ = [
    "InlineCluster", "ProcessCluster", "ShardCluster", "ShardError", "ShardHandler", "make_cluster",
    "CollectingBus", "FixedClock", "LineShard", "LineShardConfig", "ShardedLinePipeline", "ShardedRunResult",
    "merge_ingest_stats", "route_raw", "routing_identifier", "Partitioner", "assign_shards",
    "jump_consistent_hash", "kafka_partition_for_destination", "kafka_partition_for_line", "moved_fraction",
    "ContactRows", "PopulationStats", "ResonanceShardConfig", "ShardedPrepResult", "canonical_table",
    "line_contacts", "merge_contacts", "merge_population", "same_population", "sharded_resonance_prep",
    "single_node_population", "bounded_batches", "rss_bytes", "ShardWindowStore", "TenantClock",
    "WindowContext", "plan_close",
]
