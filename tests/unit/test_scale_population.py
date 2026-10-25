"""Destination-sharded RESONANCE population statistics equal single-node key_stats; detection on the
coordinator's canonical table equals single-node detection on the same canonical table."""
from __future__ import annotations

import numpy as np
import pytest

from aegis.resonance import DestinationContext, Resonance, ResonanceConfig, build_event_table
from aegis.resonance.sim import CampaignSpec, ScenarioSpec, generate_scenario
from aegis.scale import InlineCluster, Partitioner, ProcessCluster
from aegis.scale.population import (
    KeyPopulation,
    PopulationPartial,
    ResonanceShardConfig,
    canonical_table,
    line_contacts,
    merge_contacts,
    merge_population,
    same_population,
    sharded_resonance_prep,
    shuffle_by_destination,
    single_node_population,
    split_frames_by_line,
)

CFG = ResonanceConfig()


@pytest.fixture(scope="module")
def scenario():
    return generate_scenario(ScenarioSpec(n_lines=500, days=1.0, campaigns=[CampaignSpec("c2", prevalence=0.04)],
                                          seed=4), sampling=100)


@pytest.fixture(scope="module")
def single(scenario):
    return build_event_table(scenario.flows, scenario.dns, dns_join_ttl_s=CFG.dns_join_ttl_s)


@pytest.mark.parametrize("n_shards", [1, 3, 7])
def test_population_identical_to_single_node(scenario, single, n_shards):
    ref = single_node_population(single, CFG)
    with InlineCluster(ResonanceShardConfig(CFG), n_shards) as cl:
        res = sharded_resonance_prep(cl, scenario.flows, scenario.dns)
    assert same_population(ref, res.population)
    assert res.population.active_lines == 500
    assert res.population.candidate_keys(CFG) == ref.candidate_keys(CFG)
    assert res.population.popular_keys(CFG) == ref.popular_keys(CFG)
    assert res.population.key_ips == {k: v for k, v in ref.key_ips.items() if k in ref.keys}
    assert any(np.isnan(k.median_bytes) for k in ref.keys.values())       # DNS-only keys: NaN preserved
    assert res.window == single.window


def test_merged_table_equals_canonical_single_table(scenario, single):
    with InlineCluster(ResonanceShardConfig(CFG), 4) as cl:
        res = sharded_resonance_prep(cl, scenario.flows, scenario.dns)
    a, b = canonical_table(single), res.table()
    assert a.lines.items == b.lines.items and a.keys.items == b.keys.items
    assert np.array_equal(a.t, b.t)
    # rows are equal up to the order of *different lines'* rows sharing a timestamp; within every
    # (line, destination) group the order is identical (stable sort keeps it), which is all any
    # RESONANCE computation depends on (every statistic groups by line)
    oa, ob = np.lexsort((a.t, a.key, a.line)), np.lexsort((b.t, b.key, b.line))
    for col in ("t", "line", "key", "kind"):
        assert np.array_equal(getattr(a, col)[oa], getattr(b, col)[ob])
    assert np.array_equal(a.nbytes[oa], b.nbytes[ob], equal_nan=True)
    assert np.array_equal(a.dur_s[oa], b.dur_s[ob], equal_nan=True)
    assert a.key_ips == b.key_ips and a.window == b.window


def test_detection_on_coordinator_matches_single_node(scenario, single):
    with ProcessCluster(ResonanceShardConfig(CFG), 3, n_workers=2) as cl:
        res = sharded_resonance_prep(cl, scenario.flows, scenario.dns)
    ctx = DestinationContext(scenario.topology)
    r1 = Resonance(CFG, context=ctx, tenant_id="t").detect(canonical_table(single))
    r2 = Resonance(CFG, context=ctx, tenant_id="t").detect(res.table())
    assert r1.model_dump(exclude={"timings_s"}) == r2.model_dump(exclude={"timings_s"})
    keys = scenario.campaign_keys["c2"]
    assert any(set(c.destinations) & keys for c in r1.campaigns)


def test_stage_functions_and_merge_guards(scenario):
    part = Partitioner(2)
    frames = split_frames_by_line(scenario.flows, scenario.dns, part)
    lines0 = set(frames[0][0]["line"].astype(str)) | set(frames[0][1]["line"].astype(str))
    lines1 = set(frames[1][0]["line"].astype(str)) | set(frames[1][1]["line"].astype(str))
    assert not lines0 & lines1 and all(part.line_shard(x) == 0 for x in lines0)
    rows = [line_contacts(*frames[s], source_shard=s) for s in (0, 1)]
    routed = shuffle_by_destination(rows, part)
    for s, parts in routed.items():
        assert all(part.destination_shard(k) == s for p in parts for k in set(p.key.tolist()))
    tb = merge_contacts(rows)
    assert len(tb) == sum(len(r) for r in rows)
    dup = PopulationPartial(0, {"d:x": KeyPopulation(1, 1, 0.0, 0.0, float("nan"), float("nan"))}, {"l"}, {})
    with pytest.raises(ValueError):
        merge_population([dup, PopulationPartial(1, dup.keys, {"m"}, {})], (0.0, 1.0))
    empty = line_contacts(None, None)
    assert len(empty) == 0 and empty.extent is None
    with pytest.raises(ValueError):
        ResonanceShardConfig(CFG)(0).handle("nope", None)
