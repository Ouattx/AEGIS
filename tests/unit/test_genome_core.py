"""GENOME: extraction, signing/verification, expiry, ledgering, early warning, findings."""
from __future__ import annotations

from datetime import timedelta
from functools import lru_cache

import pytest

from aegis.contracts.models import Verdict
from aegis.genome import (
    GenomeConfig,
    GenomeDetector,
    build_early_warning_bundle,
    detect_new_infrastructure,
    exposure_summary,
    extract_genome,
    ledger_genome,
    load_genomes,
    sign_genome,
    tenant_exposure,
    to_findings,
    verify_genome,
)
from aegis.genome.capture import capture_from_observations
from aegis.genome.early_warning import STATUS_SEEN, STATUS_UNSEEN, TAG_LAB, TAG_UNSEEN
from aegis.genome.models import GenomeReport
from aegis.genome.names import bigram_novelty, entropy_per_char
from aegis.genome.sim import DEFAULT_START, family_infra, isp_population, lab_capture, standard_families
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.resonance import ResonanceConfig
from aegis.sentinel.rules import BundleSignatureError, load_bundle
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory

FAMS = {f.name: f for f in standard_families()}
MODELS = ("boxmodel-x1", "boxmodel-q2", "boxmodel-m9", "boxmodel-t4")


@lru_cache(maxsize=None)
def signer() -> Signer:
    return Signer.generate("genome-lab-test")


def keyring() -> KeyRing:
    kr = KeyRing()
    kr.add_signer(signer())
    return kr


@lru_cache(maxsize=None)
def clean_refs():
    return tuple(lab_capture(None, box_model=m, seed=11) for m in MODELS)


@lru_cache(maxsize=None)
def extracted(name: str):
    f = FAMS[name]
    return extract_genome([lab_capture(f, box_model=m) for m in f.box_models], clean_reference=clean_refs(),
                          now=DEFAULT_START)


@lru_cache(maxsize=None)
def signed(name: str):
    return sign_genome(extracted(name).genome, signer())


# ---------------------------------------------------------------------------- extraction

@pytest.mark.parametrize("name", list(FAMS))
def test_extraction_recovers_timer_and_excludes_box_baseline(name):
    f = FAMS[name]
    res = extracted(name)
    assert res.reason is None and res.genome is not None
    g = res.genome
    assert abs(g.timer.period_s / f.period_s - 1) < 0.03
    assert g.family == name
    benign = {"ntp.isp-time.example", "telemetry.boxvendor.example", "push.platform-svc.example",
              "mw.licensed-iptv.example", "edge1.streamcdn.example"}
    assert not any(k.split(":", 1)[1] in benign for k in g.c2_keys)
    truth_ips = {"ip:" + ip for _, ip in family_infra(f)}
    assert truth_ips & set(g.c2_keys)
    assert g.provenance.lab_box_models == sorted(f.box_models)
    assert g.expires_at > g.created_at and 0 < g.confidence <= 1


def test_extraction_features_distinguish_families():
    a, b, c, d = (extracted(n).genome for n in ("tvbox_alpha", "tvbox_beta", "tvbox_gamma", "tvbox_delta"))
    assert a.timer.jitter_family == "uniform" and b.timer.jitter_family == "normal"
    assert abs(c.timer.jitter_scale - 0.25) < 0.05
    assert a.dns.lookups_per_beacon > 0.8 and d.dns.lookups_per_beacon == 0.0      # per-beacon vs hard-coded IPs
    assert c.dns.name_entropy_mean > b.dns.name_entropy_mean                         # DGA-like names
    assert round(c.burst.flows_per_beacon_mean) == 3 and round(a.burst.flows_per_beacon_mean) == 2
    assert d.activity.update_fetch_period_s and abs(d.activity.update_fetch_period_s / 86400 - 1) < 0.2


def test_clean_capture_yields_no_genome_and_extraction_is_deterministic():
    res = extract_genome([lab_capture(None, box_model="boxmodel-x1", seed=5)], clean_reference=clean_refs())
    assert res.genome is None and res.reason
    f = FAMS["tvbox_beta"]
    r1 = extract_genome([lab_capture(f)], clean_reference=clean_refs(), now=DEFAULT_START)
    r2 = extract_genome([lab_capture(f)], clean_reference=clean_refs(), now=DEFAULT_START)
    assert r1.genome.compute_hash() == r2.genome.compute_hash()


def test_without_clean_reference_confidence_is_halved():
    f = FAMS["tvbox_alpha"]
    with_ref = extracted("tvbox_alpha").genome
    without = extract_genome([lab_capture(f)], now=DEFAULT_START,
                             cfg=None).genome
    assert without is not None and without.confidence <= with_ref.confidence * 0.55


def test_name_statistics():
    assert entropy_per_char("aaaa") == 0
    assert bigram_novelty("x9qzkvj3w8") > bigram_novelty("weather")


def test_capture_adapter_from_observations_rejects_multiple_devices():
    from datetime import datetime, timezone

    from aegis.contracts.models import FlowObservation, ObservationEvent, SourceKind, Vantage
    t = datetime(2026, 10, 1, tzinfo=timezone.utc)

    def ev(p):
        return ObservationEvent(tenant_id="lab", observed_at=t, ingested_at=t, source_id="lab", vantage=Vantage.DEVICE,
                                source_kind=SourceKind.NETFLOW, collection_authorization_id="auth-lab",
                                entity_pseudonym=p, flow=FlowObservation(dst_ip="198.19.1.1", bytes_out=100),
                                retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)
    cap = capture_from_observations([ev("dev1")], capture_id="c", box_model="m", start=t, end=t + timedelta(days=1))
    assert len(cap.flows) == 1
    with pytest.raises(ValueError):
        capture_from_observations([ev("dev1"), ev("dev2")], capture_id="c", box_model="m", start=t,
                                  end=t + timedelta(days=1))


# ---------------------------------------------------------------------------- signing, expiry, ledger

def test_signed_genome_verifies_and_tampering_is_rejected():
    g = signed("tvbox_alpha")
    kr = keyring()
    assert verify_genome(g, kr)
    t = g.model_copy(update={"timer": g.timer.model_copy(update={"period_s": 900.0})}, deep=True)
    assert not verify_genome(t, kr)
    resealed = t.model_copy(update={"content_sha256": t.compute_hash()})
    assert not verify_genome(resealed, kr)                       # hash fixed, signature no longer matches
    other = KeyRing()
    other.add_signer(Signer.generate("someone-else"))
    assert not verify_genome(g, other)                           # untrusted key
    kr.revoke(signer().key_id)
    assert not verify_genome(g, kr)                              # revoked key


def test_load_genomes_ignores_expired_and_unverified():
    g = signed("tvbox_beta")
    bad = g.model_copy(update={"family": "renamed"})
    ok, ignored = load_genomes([g, bad], keyring(), DEFAULT_START)
    assert ok == [g] and ignored == {"unverified": 1}
    ok, ignored = load_genomes([g], keyring(), g.expires_at + timedelta(seconds=1))
    assert ok == [] and ignored == {"expired": 1}


def test_detector_abstains_when_only_expired_or_tampered_genomes():
    g = signed("tvbox_alpha")
    sc = isp_population([(FAMS["tvbox_alpha"], 6)], n_lines=300, seed=21)
    late = g.expires_at + timedelta(days=1)
    rep = GenomeDetector([g], keyring()).detect(sc.table(), now=late)
    assert rep.status == "abstain" and rep.campaigns == [] and rep.n_genomes_ignored == {"expired": 1}
    tampered = g.model_copy(update={"confidence": 1.0})
    rep = GenomeDetector([tampered], keyring()).detect(sc.table(), now=DEFAULT_START + timedelta(days=1))
    assert rep.status == "abstain" and rep.n_genomes_ignored == {"unverified": 1}


def test_genome_is_ledgered(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'g.db'}")
    init_db(eng)
    ledger = Ledger(make_session_factory(eng))
    g = signed("tvbox_gamma")
    e = ledger_genome(ledger, "lab", g)
    assert e.subject_id == g.genome_id and e.payload["content_sha256"] == g.content_sha256
    assert ledger.verify_chain("lab") == (True, None)


# ---------------------------------------------------------------------------- early warning

def test_early_warning_new_infrastructure_bundle_and_tenant_exposure():
    f = FAMS["tvbox_alpha"]
    g = signed("tvbox_alpha")
    cap = lab_capture(f, generation=1, capture_id="cap-alpha-gen1")
    cands = detect_new_infrastructure(g, cap, clean_reference=clean_refs())
    new_keys = {"d:" + n for n, _ in family_infra(f, generation=1)} | {"ip:" + i for _, i in family_infra(f, generation=1)}
    assert cands and {c.key for c in cands} <= new_keys
    assert not ({c.key for c in cands} & set(g.c2_keys))
    # old infrastructure is never re-announced; the clean box's own destinations never appear
    assert detect_new_infrastructure(g, lab_capture(f), clean_reference=clean_refs()) == []

    bundle = build_early_warning_bundle(cands, g, signer(), issued_at=DEFAULT_START + timedelta(days=3))
    kr = keyring()
    loaded = load_bundle(bundle, kr)                       # sentinel IOC bundle format, signature verified
    assert all(TAG_LAB in i.tags and TAG_UNSEEN in i.tags for i in loaded.indicators)
    assert all(i.malware_family == "tvbox_alpha" and i.verdict == "malicious" for i in loaded.indicators)
    tampered = dict(bundle, indicators=bundle["indicators"][:-1])
    with pytest.raises(BundleSignatureError):
        load_bundle(tampered, kr)

    infected = isp_population([(f, 5)], n_lines=200, seed=31, generation=1)
    clean = isp_population([], n_lines=200, seed=32)
    ra = tenant_exposure(bundle, "tenant-a", infected.table())
    rb = tenant_exposure(bundle, "tenant-b", clean.table())
    assert ra["contacted"] and not rb["contacted"]
    assert {p["status"] for p in rb["indicators"]} == {STATUS_UNSEEN}
    seen = [p for p in ra["indicators"] if p["status"] == STATUS_SEEN]
    assert seen and all(p["n_lines"] >= 1 for p in seen)
    summary = exposure_summary([ra, rb])
    assert summary["tenants_by_indicator"] and all(v == ["tenant-a"] for v in summary["tenants_by_indicator"].values())


# ---------------------------------------------------------------------------- findings

def test_findings_cite_evidence_and_require_review(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'f.db'}")
    init_db(eng)
    sf = make_session_factory(eng)
    ledger = Ledger(sf)
    store = EvidenceStore(DocStore(sf), ledger)
    g = signed("tvbox_beta")
    sc = isp_population([(FAMS["tvbox_beta"], 8)], n_lines=400, seed=41)
    cfg = GenomeConfig(resonance=ResonanceConfig(series_cap=600, max_popularity=0.2))
    rep = GenomeDetector([g], keyring(), cfg, tenant_id="t1").detect(sc.table(), now=DEFAULT_START + timedelta(days=1))
    assert rep.campaigns, rep.abstentions
    fs = to_findings(rep, [g], evidence_store=store, authorization_id="auth-test")
    assert fs and all(f.requires_review and f.evidence_ids and f.calibration_id is None for f in fs)
    assert all(f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) for f in fs)
    assert all(f.device_class == "unknown" for f in fs)
    assert not store.missing("t1", fs[0].evidence_ids)
    assert ledger.verify_chain("t1") == (True, None)
    assert to_findings(GenomeReport(**{**rep.model_dump(), "status": "abstain", "campaigns": []}), [g]) == []
