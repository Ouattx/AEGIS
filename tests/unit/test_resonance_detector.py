"""RESONANCE detector: FDR control, benign safety, detection under sampling + NAT, abstention, determinism."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache

import numpy as np
import pandas as pd
import pytest

from aegis.contracts.models import Verdict
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.resonance import (
    FINDING_LABEL,
    DestinationContext,
    Resonance,
    ResonanceConfig,
    build_event_table,
    events_from_observations,
    pair_periodicities,
    to_findings,
)
from aegis.resonance.sim import CampaignSpec, ScenarioSpec, baseline_history, generate_scenario
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

T0 = 1_790_000_000.0
DAY = 86_400.0
IPTV_CDN = ("iptv-operator", "streamcdn", "edgefabric")


def _null_world(seed: int, n_lines: int = 400, n_dest: int = 300, series_per_line: int = 25) -> pd.DataFrame:
    """Exact null: periodic and bursty series exist, but destinations are assigned at random,
    so no destination is associated with a shared timer (destination labels exchangeable)."""
    rng = np.random.default_rng(seed)
    t_all, l_all, d_all = [], [], []
    for ln in range(n_lines):
        dests = rng.choice(n_dest, size=series_per_line, replace=False)
        for d in dests:
            kind = rng.random()
            if kind < 0.3:      # private timer with a random period, thinned (sampling)
                P = float(rng.uniform(120, 3600))
                n = int(DAY / P) + 2
                t = T0 + rng.uniform(0, P) + np.cumsum(P * (1 + rng.uniform(-0.1, 0.1, n)))
                t = t[(t < T0 + DAY) & (rng.random(n) < rng.uniform(0.05, 1.0))]
            elif kind < 0.6:    # bursty sessions
                c = rng.uniform(T0, T0 + DAY, rng.integers(1, 4))
                t = np.concatenate([ci + np.cumsum(rng.exponential(60, rng.integers(2, 15))) for ci in c])
            else:               # sparse Poisson
                t = rng.uniform(T0, T0 + DAY, rng.poisson(4))
            t = t[(t >= T0) & (t < T0 + DAY)]
            t_all.append(t)
            l_all.append(np.full(len(t), ln))
            d_all.append(np.full(len(t), d))
    t = np.concatenate(t_all)
    return pd.DataFrame({"t": t, "line": [f"L{x}" for x in np.concatenate(l_all)],
                         "dst_ip": [f"10.{x // 250}.{x % 250}.1" for x in np.concatenate(d_all)]})


def test_fdr_controlled_on_exact_null_across_seeds():
    """Under exchangeable destination labels every p-value is valid: BH at q=0.1 must
    produce a run with any (necessarily false) discovery in at most ~q of runs."""
    cfg = ResonanceConfig(q=0.1, n_permutations=400, min_permutations=60)
    runs_with_fd, pvals = 0, []
    seeds = range(6)
    for s in seeds:
        tb = build_event_table(_null_world(s), None, start=T0, end=T0 + DAY)
        rep = Resonance(cfg, tenant_id="null").detect(tb)
        assert rep.status == "ok" and rep.n_tested > 100
        runs_with_fd += bool(rep.campaigns)
        pvals += [u.p_value for u in rep.tested]
    assert runs_with_fd <= 2                          # expected <= 0.6 of 6 runs
    p = np.array(pvals)
    assert np.mean(p <= 0.05) <= 0.08                 # p-values are (super-)uniform
    assert np.mean(p <= 0.2) <= 0.25


@lru_cache(maxsize=None)
def _benign(seed: int, sampling: int, history: bool):
    spec = ScenarioSpec(n_lines=1200, campaigns=[], seed=seed)
    sc = generate_scenario(spec, sampling)
    cfg = ResonanceConfig()
    hist = baseline_history(spec, cfg, sampling=sampling) if history else None
    rep = Resonance(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t").detect(sc.table(cfg))
    return sc, rep


@pytest.mark.parametrize("seed", [31, 32, 33])
def test_benign_only_population_yields_no_campaign_with_history(seed):
    for sampling in (1, 100):
        _, rep = _benign(seed, sampling, True)
        assert rep.status == "ok"
        assert rep.campaigns == [], [c.destinations for c in rep.campaigns]


@pytest.mark.parametrize("history", [True, False])
def test_benign_iptv_and_cdn_destinations_never_yield_campaigns(history):
    for seed in (31, 32):
        sc, rep = _benign(seed, 100, history)
        for c in rep.campaigns:
            assert not any(m in d for d in c.destinations for m in IPTV_CDN), c.destinations
        # the population actually contains busy IPTV boxes and CDN streaming
        assert sc.flows["dst_ip"].astype(str).str.startswith("198.18.").any()
        tested = {d for u in rep.tested for d in u.destinations}
        assert not any(m in d and d.startswith("ip:") for d in tested for m in IPTV_CDN)
    # cold start (no history) reports only genuine shared timers, never IPTV/CDN; documented limitation
    if not history:
        _, rep = _benign(31, 100, False)
        assert all(c.statistic in ("period_lock", "free_periodicity") for c in rep.campaigns)


@lru_cache(maxsize=None)
def _campaign_run(seed: int = 21, sampling: int = 100):
    spec = ScenarioSpec(n_lines=1500, seed=seed, campaigns=[
        CampaignSpec("bb", period_s=600, jitter=0.2, prevalence=0.012, dns_mode="cached", double_infection=0.4)])
    sc = generate_scenario(spec, sampling)
    cfg = ResonanceConfig()
    hist = baseline_history(spec, cfg, sampling=sampling)
    tb = sc.table(cfg)
    det = Resonance(cfg, context=DestinationContext(sc.topology), history=hist, tenant_id="t")
    return sc, tb, det, det.detect(tb)


def test_emulated_campaign_detected_at_1_in_100_sampling_behind_nat():
    sc, tb, det, rep = _campaign_run()
    keys = sc.campaign_keys["bb"]
    hits = [c for c in rep.campaigns if set(c.destinations) & keys]
    assert len(hits) == 1, [c.destinations for c in rep.campaigns]
    c = hits[0]
    assert c.q_value <= 0.01 and c.p_value <= c.q_value * 50
    infected = {ln for ln, v in sc.infected.items() if "bb" in v}
    assert len(infected) >= 15
    members = set(c.member_lines)
    assert len(members & infected) / len(infected) >= 0.9
    assert members <= infected                               # no benign line pulled into the campaign
    assert all(not (set(x.destinations) & keys) is False or x is c for x in rep.campaigns)
    assert not [x for x in rep.campaigns if not set(x.destinations) & keys]
    assert c.enforcement_eligible and not c.shared_hosting_domain
    assert c.explanation and "device class" in c.explanation
    assert c.evidence_summary["uses_device_class"] is False
    assert c.period_s is not None
    # NAT: some infected lines carry two bots; campaign period still recovered near 600 s or the DNS-cache 3600 s
    assert min(abs(c.period_s - 600) / 600, abs(c.period_s - 3600) / 3600) < 0.12


def test_deterministic_with_seed():
    sc, tb, det, rep = _campaign_run()
    rep2 = det.detect(tb)
    strip = lambda r: r.model_dump(mode="json", exclude={"timings_s"})  # noqa: E731
    assert strip(rep) == strip(rep2)
    sc2 = generate_scenario(sc.spec, 100)
    assert sc2.flows.equals(sc.flows) and sc2.dns.equals(sc.dns)
    rep3 = Resonance(det.cfg, context=det.context, history=det.history, tenant_id="t").detect(sc2.table(det.cfg))
    assert [c.campaign_id for c in rep3.campaigns] == [c.campaign_id for c in rep.campaigns]
    assert [c.p_value for c in rep3.campaigns] == [c.p_value for c in rep.campaigns]


def test_abstains_on_short_window_and_too_few_lines():
    sc, tb, det, _ = _campaign_run()
    short = tb.select(tb.t < tb.window[0] + 3 * 3600, start=tb.window[0], end=tb.window[0] + 3 * 3600)
    rep = det.detect(short)
    assert rep.status == "abstain" and "too_short" in rep.abstain_reason and rep.campaigns == []
    findings = to_findings(rep, emit_abstain_for=["p_line000001"])
    assert [f.verdict for f in findings] == [Verdict.ABSTAIN]
    # 3 infected lines only: below min_lines -> abstention, never a campaign
    spec = ScenarioSpec(n_lines=1500, seed=22, campaigns=[CampaignSpec("tiny", prevalence=0.002)])
    sc3 = generate_scenario(spec, 1)
    cfg = ResonanceConfig()
    rep3 = Resonance(cfg, context=DestinationContext(sc3.topology), history=baseline_history(spec, cfg, sampling=1),
                     tenant_id="t").detect(sc3.table(cfg))
    keys = sc3.campaign_keys["tiny"]
    assert not [c for c in rep3.campaigns if set(c.destinations) & keys]
    assert [a for a in rep3.abstentions if set(a.destinations) & keys and "too_few_lines" in a.reason]


def test_abstains_when_lines_carry_no_timing_information():
    # hard-coded IP, no DNS, 1:1000 sampling of 4-packet beacons: lines see ~0-1 events per day
    spec = ScenarioSpec(n_lines=1200, seed=23, campaigns=[
        CampaignSpec("blind", period_s=1800, prevalence=0.02, dns_mode="none", beacon_pkts=(3, 4), tasking_per_h=0.0)])
    sc = generate_scenario(spec, 1000)
    cfg = ResonanceConfig()
    rep = Resonance(cfg, context=DestinationContext(sc.topology), history=baseline_history(spec, cfg, sampling=1000),
                    tenant_id="t").detect(sc.table(cfg))
    keys = sc.campaign_keys["blind"]
    assert not [c for c in rep.campaigns if set(c.destinations) & keys]
    assert [a for a in rep.abstentions if set(a.destinations) & keys]


def test_findings_evidence_and_ledger():
    sc, tb, det, rep = _campaign_run()
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in ("docs", "ledger_entries", "ledger_heads")])
    sf = make_session_factory(eng)
    store = EvidenceStore(DocStore(sf), Ledger(sf))
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    fs = to_findings(rep, cfg=det.cfg, evidence_store=store, now=now, authorization_id="auth-x")
    n_members = sum(c.n_lines for c in rep.campaigns)
    assert len(fs) == n_members > 0
    assert Counter(f.label for f in fs) == {FINDING_LABEL: n_members}
    for f in fs:
        assert f.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
        assert 0.0 <= f.score <= 1.0 and f.calibration_id is None and f.requires_review
        assert len(f.evidence_ids) == 2 and "not a probability" in f.explanation
        ev = store.get("t", f.evidence_ids[0])
        assert ev is not None and ev.payload["q_value"] == pytest.approx(f.component_scores["q_value"])
        assert "p_value" in ev.payload and ev.payload["config"]["q"] == det.cfg.q
        assert ev.source_independence_group == "operator-telemetry"
    assert store.ledger.verify_chain("t") == (True, None)
    assert [e for e in store.ledger.entries("t", entry_type="resonance_campaign")]


def test_never_uses_device_class_and_lab_adapter():
    from aegis.lab.corpus import generate_corpus
    corpus = generate_corpus(seed=5, days=1, n_devices=80, malicious_fraction=0.1)
    tb1 = events_from_observations(corpus.events, start=corpus.start, end=corpus.end)
    swapped = [e.model_copy(update={"device_class": "android_tv" if e.device_class != "android_tv" else "phone"})
               for e in corpus.events]
    tb2 = events_from_observations(swapped, start=corpus.start, end=corpus.end)
    cfg = ResonanceConfig(min_lines=3)
    ctx = DestinationContext(corpus.topology)
    r1 = Resonance(cfg, context=ctx, tenant_id=corpus.tenant_id).detect(tb1)
    r2 = Resonance(cfg, context=ctx, tenant_id=corpus.tenant_id).detect(tb2)
    strip = lambda r: r.model_dump(mode="json", exclude={"timings_s"})  # noqa: E731
    assert strip(r1) == strip(r2)
    pp = pair_periodicities(tb1, cfg)
    assert pp and all(p.p_nominal is None or 0 <= p.p_nominal <= 1 for p in pp)
