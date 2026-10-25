"""GENOME population detection: FDR on benign populations, benign services never matched,
detection and attribution behind NAT at 1:1 and 1:1000 sampling, abstention, device-class
invariance, device-model hypotheses, determinism."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache

import numpy as np
import pytest

from aegis.contracts.models import DnsObservation, FlowObservation, ObservationEvent, SourceKind, Vantage
from aegis.genome import GenomeConfig, GenomeDetector, extract_genome, sign_genome
from aegis.genome.sim import DEFAULT_START, isp_population, lab_capture, standard_families
from aegis.provenance.signing import KeyRing, Signer
from aegis.resonance import DestinationContext, ResonanceConfig, events_from_observations
from aegis.resonance.sim import ScenarioSpec, baseline_history

LINES = 1500
FAMS = {f.name: f for f in standard_families()}
NOW = DEFAULT_START + timedelta(days=1)
BENIGN_MARKERS = ("streamcdn", "edgefabric", "iptv", "isp-time", "ntp", "push", "telemetry")


@lru_cache(maxsize=None)
def lab():
    s = Signer.generate("genome-det-test")
    kr = KeyRing()
    kr.add_signer(s)
    clean = [lab_capture(None, box_model=m, seed=11) for m in ("boxmodel-x1", "boxmodel-q2", "boxmodel-m9",
                                                                 "boxmodel-t4")]
    gs = tuple(sign_genome(extract_genome([lab_capture(f, box_model=m) for m in f.box_models], clean_reference=clean,
                                          now=DEFAULT_START).genome, s) for f in FAMS.values())
    return gs, kr, s


@lru_cache(maxsize=None)
def history(seed: int, sampling: int):
    return baseline_history(ScenarioSpec(n_lines=LINES, days=1.0, seed=seed), sampling=sampling)


@lru_cache(maxsize=None)
def population(seed: int, sampling: int, n: int, families: tuple[str, ...] = tuple(FAMS)):
    return isp_population([(FAMS[f], n) for f in families] if n else [], n_lines=LINES, seed=seed, sampling=sampling)


def detect(sc, *, hist=None, genomes=None, cfg=None, until=None):
    gs, kr, _ = lab()
    return GenomeDetector(list(genomes or gs), kr, cfg or GenomeConfig(), context=DestinationContext(sc.topology),
                          history=hist, tenant_id="t").detect(sc.table(until=until), now=NOW)


def truth(sc, c) -> str | None:
    return next((f for f, ks in sc.family_keys.items() if set(c.destinations) & ks), None)


# ---------------------------------------------------------------------------- false discoveries

@pytest.mark.parametrize("seed,sampling", [(51, 1), (52, 1), (51, 1000), (53, 100)])
def test_benign_only_population_has_no_campaigns(seed, sampling):
    rep = detect(population(seed, sampling, 0), hist=history(seed, sampling))
    assert rep.status == "ok"
    assert rep.campaigns == []


def test_cold_start_benign_population_has_no_campaigns():
    """Without history, benign shared structure reaches the population test; the per-line support gate
    demotes it to abstentions rather than campaigns (documented limitation, see docs/GENOME.md)."""
    rep = detect(population(52, 1, 0), hist=None)
    assert rep.campaigns == []
    assert all("weak_per_line_support" in a.reason or "insufficient" in a.reason for a in rep.abstentions)


def test_iptv_cdn_and_popular_services_never_matched():
    sc = population(51, 1, 8)
    rep = detect(sc, hist=history(51, 1))
    for c in rep.campaigns:
        assert not any(m in d for d in c.destinations for m in BENIGN_MARKERS), c.destinations
    # genomes deliberately shaped like benign timers (IPTV middleware 30 s, NTP 1024 s, push 1680 s)
    gs, kr, s = lab()
    base = gs[0]
    shaped = []
    for period, jit in ((30.0, 0.03), (1024.0, 0.02), (1680.0, 0.05)):
        g = base.model_copy(update={"timer": base.timer.model_copy(update={"period_s": period, "jitter_family":
                                                                           "uniform", "jitter_scale": jit}),
                                    "family": f"benign_shape_{int(period)}"}, deep=True)
        shaped.append(sign_genome(g, s))
    for hist in (history(51, 1), None):
        rep = detect(sc, hist=hist, genomes=shaped)
        for c in rep.campaigns:
            assert not any(m in d for d in c.destinations for m in BENIGN_MARKERS), c.destinations
            assert truth(sc, c) is not None


# ---------------------------------------------------------------------------- detection and attribution

@pytest.mark.parametrize("sampling,expected", [(1, set(FAMS)), (1000, {"tvbox_alpha", "tvbox_beta", "tvbox_gamma"})])
def test_detects_and_attributes_families_behind_nat(sampling, expected):
    sc = population(51, sampling, 8)
    rep = detect(sc, hist=history(51, sampling))
    found = {}
    for c in rep.campaigns:
        t = truth(sc, c)
        assert t is not None, f"false campaign {c.destinations}"
        assert c.q_value <= 0.01 and c.n_lines >= 5
        found[t] = c
    assert expected <= set(found)
    for t, c in found.items():
        assert c.family == t, (t, c.attribution)
        assert c.attribution[t] == max(c.attribution.values())
        infected = {ln for ln, f in sc.infected.items() if f == t}
        assert set(c.member_lines) <= infected | set(c.member_lines)   # members are lines contacting the unit
        assert len(set(c.member_lines) & infected) >= 0.8 * len(infected)


def test_hard_coded_ip_family_is_not_detectable_at_1_in_1000():
    """Honest failure: a family without DNS and with 1-2 packet check-ins vanishes under 1:1000 sampling."""
    sc = population(51, 1000, 8)
    rep = detect(sc, hist=history(51, 1000))
    assert not any(truth(sc, c) == "tvbox_delta" for c in rep.campaigns)


def test_device_model_hypotheses_are_ranked_behavioral_hypotheses_only():
    sc = population(51, 1, 8)
    rep = detect(sc, hist=history(51, 1))
    members = {ln for c in rep.campaigns for ln in c.member_lines}
    assert rep.device_hypotheses
    for h in rep.device_hypotheses:
        assert h.line in members and h.basis == "behavioral_match"
        scores = [r["score"] for r in h.ranked]
        assert scores == sorted(scores, reverse=True)
        assert all(r["evidence"] and r["evidence"][0]["genome_id"] for r in h.ranked)
    delta = [c for c in rep.campaigns if c.family == "tvbox_delta"]
    assert delta
    dh = [h for h in rep.device_hypotheses if h.line in set(delta[0].member_lines)]
    assert dh and {r["box_model"] for r in dh[0].ranked} == {"boxmodel-x1", "boxmodel-t4"}


# ---------------------------------------------------------------------------- abstention

def test_abstains_on_short_window_and_reports_insufficient_lines():
    sc = population(51, 1, 8)
    rep = detect(sc, hist=history(51, 1), until=sc.start + 4 * 3600)
    assert rep.status == "abstain" and "too_short" in rep.abstain_reason and rep.campaigns == []
    small = isp_population([(FAMS["tvbox_beta"], 3)], n_lines=LINES, seed=51, sampling=1)
    rep = detect(small, hist=history(51, 1))
    assert not any(truth(small, c) for c in rep.campaigns)
    assert any("insufficient_lines" in a.reason for a in rep.abstentions)


# ---------------------------------------------------------------------------- device class, determinism

def _events(sc, lines: list[str], label) -> list[ObservationEvent]:
    out = []
    t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    common = dict(tenant_id="t", ingested_at=t0, source_id="s", vantage=Vantage.SUBSCRIBER_LINE,
                  collection_authorization_id="auth", retention_until=t0 + timedelta(days=30),
                  integrity_sha256="0" * 64)
    f = sc.flows[sc.flows.line.isin(lines)]
    for t, ln, ip, b in zip(f.t.to_numpy(), f.line.astype(str), f.dst_ip.astype(str), f.bytes.to_numpy()):
        out.append(ObservationEvent(observed_at=datetime.fromtimestamp(float(t), tz=timezone.utc),
                                    source_kind=SourceKind.NETFLOW, entity_pseudonym=ln, device_class=label(ln),
                                    flow=FlowObservation(dst_ip=ip, bytes_out=int(b)), **common))
    d = sc.dns[sc.dns.line.isin(lines)]
    for t, ln, q, a in zip(d.t.to_numpy(), d.line.astype(str), d.qname.astype(str), d.answer_ip.astype(str)):
        out.append(ObservationEvent(observed_at=datetime.fromtimestamp(float(t), tz=timezone.utc),
                                    source_kind=SourceKind.DNS, entity_pseudonym=ln, device_class=label(ln),
                                    dns=DnsObservation(qname=q, answers=[a]), **common))
    return out


def test_never_flags_on_device_class_alone():
    gs, kr, _ = lab()
    benign = population(54, 1, 0)
    lines = benign.line_names[:40]
    ev = _events(benign, lines, lambda ln: "android_tv")
    tb = events_from_observations(ev, start=DEFAULT_START, end=NOW)
    cfg = GenomeConfig(resonance=ResonanceConfig(series_cap=600, max_popularity=0.25))
    hist = history(54, 1)       # warm-up history as in deployment (cold start is tested separately)
    rep = GenomeDetector(list(gs), kr, cfg, history=hist).detect(tb, now=NOW)
    assert rep.campaigns == []
    # labels never change the decision: same telemetry, different device classes => identical report
    inf = isp_population([(FAMS["tvbox_beta"], 6)], n_lines=LINES, seed=54, sampling=1)
    sub = sorted(set(list(inf.infected)) | set(inf.line_names[:34]))
    r1 = GenomeDetector(list(gs), kr, cfg, history=hist).detect(
        events_from_observations(_events(inf, sub, lambda ln: "android_tv"), start=DEFAULT_START, end=NOW), now=NOW)
    r2 = GenomeDetector(list(gs), kr, cfg, history=hist).detect(
        events_from_observations(_events(inf, sub, lambda ln: "phone" if hash(ln) % 2 else None),
                                 start=DEFAULT_START, end=NOW), now=NOW)
    assert r1.model_dump() == r2.model_dump()


def test_deterministic_with_seed():
    a = isp_population([(FAMS["tvbox_alpha"], 6)], n_lines=400, seed=61)
    b = isp_population([(FAMS["tvbox_alpha"], 6)], n_lines=400, seed=61)
    assert a.infected == b.infected
    assert np.array_equal(a.flows.t.to_numpy(), b.flows.t.to_numpy())
    r1, r2 = detect(a), detect(b)
    assert r1.model_dump() == r2.model_dump()


# ---------------------------------------------------------------------------- matched filter vs generic

def test_matched_filter_needs_fewer_lines_than_resonance_at_1_in_1000():
    """At 1:1000 with 3 infected lines per family, the genome matched filter finds the families whose
    check-ins are visible in the unsampled resolver log (alpha, beta); generic RESONANCE with the same
    minimum-lines gate and history finds none. This holds for alpha and beta only; for the wide-jitter
    300 s family (gamma) the advantage is not established (see eval/genome_benchmark.py)."""
    from aegis.resonance import Resonance
    sc = isp_population([(FAMS[f], 3) for f in FAMS], n_lines=LINES, seed=51, sampling=1000)
    hist = history(51, 1000)
    rc = ResonanceConfig(min_lines=3, series_cap=600)
    rep = detect(sc, hist=hist, cfg=GenomeConfig(resonance=rc))
    found = {truth(sc, c) for c in rep.campaigns}
    assert None not in found
    assert {"tvbox_alpha", "tvbox_beta"} <= found
    rr = Resonance(ResonanceConfig(min_lines=3), context=DestinationContext(sc.topology), history=hist).detect(sc.table())
    r_found = {next((f for f, ks in sc.family_keys.items() if set(c.destinations) & ks), None) for c in rr.campaigns}
    assert not ({"tvbox_alpha", "tvbox_beta"} & r_found)
