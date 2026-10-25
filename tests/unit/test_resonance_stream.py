"""RESONANCE streaming mode (bounded memory, stable identity) and performance."""
from __future__ import annotations

import os
import time

import pytest

from aegis.resonance import DestinationContext, Resonance, ResonanceConfig, ResonanceStream
from aegis.resonance.sim import CampaignSpec, ScenarioSpec, baseline_history, generate_scenario, standard_campaigns


def _feed(stream: ResonanceStream, sc, step_s: float = 3600.0):
    updates = []
    t0 = sc.start
    for h in range(1, int(sc.spec.days * 86400 / step_s) + 1):
        a, b = t0 + (h - 1) * step_s, t0 + h * step_s
        stream.ingest_frames(sc.flows[(sc.flows.t >= a) & (sc.flows.t < b)], sc.dns[(sc.dns.t >= a) & (sc.dns.t < b)])
        up = stream.advance(b)
        if up is not None:
            updates.append(up)
    return updates


def test_stream_detects_campaign_with_bounded_memory_and_abstains_early():
    spec = ScenarioSpec(n_lines=1200, seed=41, campaigns=[
        CampaignSpec("bb", period_s=600, jitter=0.15, prevalence=0.015, onset_s=2 * 3600, onset_spread_s=1800)])
    sc = generate_scenario(spec, 100)
    cfg = ResonanceConfig()
    hist = baseline_history(spec, cfg, sampling=100)
    budget = 150_000
    st = ResonanceStream(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t",
                         step_s=3600, max_events=budget, update_history=False)
    ups = _feed(st, sc)
    assert ups[0].report.status == "abstain"                       # 1 h of data < 6 h minimum window
    keys = sc.campaign_keys["bb"]
    det = [u for u in ups if any(set(c.destinations) & keys for c in u.report.campaigns)]
    assert det, "campaign never detected in streaming mode"
    delay_h = (det[0].now - sc.campaign_onset["bb"]) / 3600
    assert 3.5 <= delay_h <= 12                                     # >= min window after start, well within a day
    assert st.stats["thinned"] > 0 and st.buffered_events <= budget + 120_000
    # identity is stable: one canonical campaign for the destination set across windows
    canon = {st.canonical[c.campaign_id] for u in det for c in u.report.campaigns if set(c.destinations) & keys}
    assert len(canon) == 1
    assert sum(len(u.new_campaigns) for u in ups if any(set(c.destinations) & keys for c in u.new_campaigns)) == 1


def test_stream_matches_batch_at_end_of_day():
    spec = ScenarioSpec(n_lines=800, seed=42, campaigns=[CampaignSpec("bb", prevalence=0.02)])
    sc = generate_scenario(spec, 100)
    cfg = ResonanceConfig()
    hist = baseline_history(spec, cfg, sampling=100)
    st = ResonanceStream(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t",
                         step_s=6 * 3600, update_history=False)
    ups = _feed(st, sc, step_s=6 * 3600)
    batch = Resonance(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t").detect(sc.table(cfg))
    assert {tuple(c.destinations) for c in ups[-1].report.campaigns} == {tuple(c.destinations) for c in batch.campaigns}


def _perf(n_lines: int) -> dict:
    spec = ScenarioSpec(n_lines=n_lines, seed=43, campaigns=standard_campaigns(0.005))
    t0 = time.perf_counter()
    sc = generate_scenario(spec, 100)
    cfg = ResonanceConfig()
    tb = sc.table(cfg)
    t1 = time.perf_counter()
    hist = baseline_history(spec, cfg, sampling=100)
    det = Resonance(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t")
    t2 = time.perf_counter()
    rep = det.detect(tb)
    t3 = time.perf_counter()
    mal = sc.malicious_keys()
    return {"events": len(tb), "build_s": t1 - t0, "detect_s": t3 - t2, "rep": rep,
            "true": sum(1 for c in rep.campaigns if set(c.destinations) & mal),
            "false": sum(1 for c in rep.campaigns if not set(c.destinations) & mal)}


def test_performance_3k_lines_24h():
    r = _perf(3000)
    assert r["events"] > 1_000_000
    assert r["detect_s"] < 15.0, r["detect_s"]
    assert r["false"] == 0 and r["true"] >= 2


@pytest.mark.skipif(os.environ.get("AEGIS_PERF") != "1", reason="set AEGIS_PERF=1 for the 10k-line benchmark")
def test_performance_10k_lines_24h():
    r = _perf(10_000)
    # measured on a 4-core container: ~5.4 M events, detection ~2-4 s with history
    assert r["events"] > 4_000_000
    assert r["detect_s"] < 60.0, r["detect_s"]
    assert r["false"] == 0 and r["true"] >= 2
