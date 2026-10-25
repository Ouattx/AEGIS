"""End-to-end Sentinel tests on an unseen lab corpus with the shipped default model.

Hard requirements (spec sections 4, 7, 15): benign IPTV / streaming boxes are not
flagged, emulated C2 boxes are detected, the device class alone never produces a
finding, and the whole path works without any LLM.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

import pytest

from aegis.contracts.models import Finding, Verdict
from aegis.lab import generate_corpus
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import Signer
from aegis.sentinel import Sentinel, WindowStore, load_default
from aegis.sentinel.detector import EventRejected
from aegis.sentinel.model import default_model_dir
from aegis.sentinel.training import evaluate_detector, lab_bundle
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory
from test_sentinel_helpers import T0, dns_event, flow_event

ALERT = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
TABLES = ["docs", "ledger_entries", "ledger_heads"]


@pytest.fixture(scope="module")
def corpus():
    # seed and tenant never used for training the shipped model (unseen devices/topology/campaigns)
    c = generate_corpus(seed=11, days=2, n_devices=90, malicious_fraction=0.12, tenant_id="pilot-isp")
    assert any(d.malicious_label == "c2_beaconing" for d in c.devices)
    assert c.hard_negatives()
    return c


@pytest.fixture(scope="module")
def model():
    return load_default()


@pytest.fixture(scope="module")
def bundle(corpus):
    return lab_bundle(corpus)


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    eng = make_engine(f"sqlite:///{tmp_path_factory.mktemp('sentinel') / 'e2e.db'}")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in TABLES])
    sf = make_session_factory(eng)
    yield EvidenceStore(DocStore(sf), Ledger(sf, signer=Signer.generate("ledger-k1")))
    eng.dispose()


@pytest.fixture(scope="module")
def run(corpus, model, bundle, store):
    s = Sentinel(model, bundle, store, record_decisions=True)
    findings = s.process_batch(corpus.events) + s.flush(corpus.end)
    return s, findings


def by_entity(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        out[f.entity_pseudonym].append(f)
    return out


# ------------------------------------------------------------------ hard requirements

def test_benign_iptv_and_streaming_boxes_not_flagged(run, corpus):
    s, findings = run
    ents = by_entity(findings)
    boxes = [d for d in corpus.devices if not d.malicious and d.device_class in ("android_tv", "smart_tv")]
    assert any(d.hard_negative for d in boxes)
    for d in boxes:
        alerts = [f for f in ents.get(d.entity_pseudonym, []) if f.verdict in ALERT]
        assert alerts == [], f"benign {d.profile} flagged: {[a.explanation for a in alerts]}"
    # not even in the un-emitted decision stream
    hard = {d.entity_pseudonym for d in corpus.hard_negatives()}
    assert not [r for r in s.decisions if r.entity_pseudonym in hard and r.verdict in ALERT]


def test_emulated_c2_boxes_detected(run, corpus):
    _, findings = run
    ents = by_entity(findings)
    for d in corpus.malicious_devices():
        alerts = [f for f in ents.get(d.entity_pseudonym, []) if f.verdict in ALERT]
        assert alerts, f"{d.malicious_label} device not detected"
        assert all(f.observed_window_end > d.infected_at for f in alerts)
    c2 = [d for d in corpus.malicious_devices() if d.malicious_label == "c2_beaconing"]
    assert c2
    # C2 boxes talking to published infrastructure reach MALICIOUS; novel infrastructure
    # (no indicator anywhere) is caught by behavior alone and at least raised as SUSPICIOUS
    for d in c2:
        verdicts = {f.verdict for f in ents[d.entity_pseudonym]}
        if d.c2_in_ioc_feed:
            assert Verdict.MALICIOUS in verdicts, d.c2_domain
        else:
            assert verdicts & set(ALERT), d.c2_domain


def test_no_false_alerts_on_benign_device_days(run, corpus):
    s, _ = run
    devices = {d.entity_pseudonym: d for d in corpus.devices}
    false_days = {(r.entity_pseudonym, (r.window_end - timedelta(microseconds=1)).date())
                  for r in s.decisions if r.verdict in ALERT and not devices[r.entity_pseudonym].malicious}
    benign_days = sum(1 for v in corpus.labels.values() if v == "benign")
    assert 1e4 * len(false_days) / benign_days <= 100      # <= 1 false alert per 100 benign device-days


def test_device_class_alone_never_produces_a_finding(corpus, model, bundle):
    """Relabel every benign device as the class TV-box malware targets: still no alert."""
    benign = {d.entity_pseudonym for d in corpus.devices if not d.malicious}
    events = [e.model_copy(update={"device_class": "android_tv"}) if e.entity_pseudonym in benign else e
              for e in corpus.events]
    s = Sentinel(model, bundle)
    findings = s.process_batch(events) + s.flush(corpus.end)
    assert not [f for f in findings if f.entity_pseudonym in benign and f.verdict in ALERT]


def test_works_without_any_llm():
    script = textwrap.dedent("""
        import os, sys
        from datetime import datetime, timedelta, timezone
        os.environ.pop("ANTHROPIC_API_KEY", None)
        sys.path.insert(0, %r)
        from test_sentinel_helpers import T0, flow_event
        from aegis.sentinel import Sentinel, load_default
        s = Sentinel(load_default(), None)
        evs = [flow_event(T0 + timedelta(seconds=30 * i), dst="198.18.0.%%d" %% (i %% 7)) for i in range(400)]
        s.process_batch(evs)
        s.flush(T0 + timedelta(hours=4))
        assert s.stats.windows > 0
        bad = [m for m in sys.modules if m == "anthropic" or m.startswith("anthropic.") or m.startswith("aegis.oracle")]
        assert not bad, bad
        print("ok", s.stats.windows)
    """) % str(Path(__file__).parent)
    r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120,
                       env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parents[2])})
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("ok")


# ------------------------------------------------------------------ evidence and provenance

def test_findings_cite_stored_evidence_and_ledger_verifies(run, store, corpus):
    s, findings = run
    assert findings
    for f in findings:
        assert f.tenant_id == "pilot-isp" and f.evidence_ids
        evs = store.list_for(f.tenant_id, f.evidence_ids)
        assert len(evs) == len(set(f.evidence_ids))
        assert all(store.verify(f.tenant_id, e.evidence_id) for e in evs)
        assert {e.kind.value for e in evs} >= {"observation"}
        for cid in f.counterevidence_ids:
            assert store.get(f.tenant_id, cid).supports is False
        assert f.explanation and "is not evidence" in f.explanation
        assert f.requires_review
        assert f.expires_at > f.created_at
        assert 0.0 <= f.score <= 1.0
        assert f.detector_version.startswith("sentinel/1.0.0+sentinel-lgbm-")
    ok, bad = store.ledger.verify_chain("pilot-isp")
    assert ok and bad is None
    finding_entries = store.ledger.entries("pilot-isp", entry_type=EntryType.FINDING)
    assert {e.subject_id for e in finding_entries} == {f.finding_id for f in findings}
    entry = finding_entries[0]
    assert entry.payload["fusion"]["policy_hash"] and entry.payload["rule_bundle"]["sha256"] == s.bundle.sha256


def test_model_evidence_has_calibrated_score_and_attributions(run, store):
    _, findings = run
    calibrated = [f for f in findings if f.calibration_id]
    assert calibrated
    f = calibrated[0]
    ev = [e for e in store.list_for(f.tenant_id, f.evidence_ids) if e.kind.value == "model_score"]
    assert ev and ev[0].payload["calibration_id"] == f.calibration_id
    assert ev[0].payload["top_contributions"]


def test_ioc_findings_reference_bundle_and_counter_evidence(run, store, corpus):
    _, findings = run
    with_ioc = [f for f in findings if f.component_scores.get("ioc")]
    assert with_ioc
    kinds = {e.kind.value for f in with_ioc for e in store.list_for(f.tenant_id, f.evidence_ids)}
    assert "ioc_match" in kinds
    # mirai emulation contacts a domain the sinkhole registry contradicts: counter-evidence + no MALICIOUS on it
    ddos = [d.entity_pseudonym for d in corpus.malicious_devices() if d.malicious_label == "ddos_bot"
            and d.c2_in_ioc_feed]
    contradicted = [f for f in findings if f.entity_pseudonym in ddos and f.counterevidence_ids]
    for f in contradicted:
        assert f.verdict != Verdict.MALICIOUS


def test_suppression_limits_repeats(run):
    _, findings = run
    last: dict[tuple[str, str], Finding] = {}
    rank = {Verdict.ABSTAIN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}
    for f in sorted(findings, key=lambda f: f.observed_window_end):
        key = (f.entity_pseudonym, f.label)
        prev = last.get(key)
        if prev is not None:
            gap = f.observed_window_end - prev.observed_window_end
            assert gap >= timedelta(hours=24) or rank[f.verdict] > rank[prev.verdict]
        last[key] = f


def test_full_detector_metrics_on_unseen_corpus(corpus, model, run):
    r = evaluate_detector(corpus, model)
    assert r["recall"] >= 0.9
    assert r["precision"] >= 0.9
    assert r["hard_negative_devices_alerted"] == 0
    assert r["malicious_devices_detected"] == r["malicious_devices"]
    # identical (deterministic) outcome to the run that persisted evidence
    s, findings = run
    assert r["findings_emitted"] == len(findings)
    assert r["verdicts"] == dict(s.stats.verdicts)


def test_rules_only_mode_never_calls_anything_benign(corpus, bundle):
    s = Sentinel(None, bundle, record_decisions=True)
    findings = s.process_batch(corpus.events[: len(corpus.events) // 2])
    assert "benign" not in s.stats.verdicts
    infected = {d.entity_pseudonym for d in corpus.malicious_devices() if d.c2_in_ioc_feed}
    assert all(f.entity_pseudonym in infected for f in findings if f.verdict in ALERT)


# ------------------------------------------------------------------ input validation / abstain

def test_unauthorized_and_foreign_tenant_events_rejected(model):
    s = Sentinel(model, None, tenant_id="t1", authorized_collections={"auth-ok"})
    assert s.process(flow_event(T0, auth="auth-other")) == []
    assert s.process(flow_event(T0, auth="auth-ok", tenant="t2")) == []
    assert s.stats.rejected_events == 2
    with pytest.raises(EventRejected):
        s.validate(flow_event(T0, auth=" "))
    with pytest.raises(EventRejected):
        s.validate(flow_event(T0, auth="auth-ok").model_copy(update={"entity_pseudonym": None}))
    s.validate(flow_event(T0, auth="auth-ok"))


def test_insufficient_context_with_indicator_hit_abstains(model, corpus, bundle):
    """Three events to a known C2: not enough context to convict, surfaced as ABSTAIN for review."""
    c2 = next(d for d in corpus.malicious_devices() if d.c2_in_ioc_feed and not d.c2_on_shared_infra
              and d.malicious_label in ("c2_beaconing", "dga_activity", "residential_proxy"))
    t = corpus.start + timedelta(hours=2)
    evs = [dns_event(t, c2.c2_domain, answers=[c2.c2_ip], tenant=corpus.tenant_id, auth="auth-lab-synthetic-001"),
           flow_event(t + timedelta(seconds=1), dst=c2.c2_ip, tenant=corpus.tenant_id),
           flow_event(t + timedelta(seconds=300), dst=c2.c2_ip, tenant=corpus.tenant_id)]
    s = Sentinel(model, bundle)
    findings = s.process_batch(evs) + s.flush(t + timedelta(hours=1))
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == Verdict.ABSTAIN and "insufficient context" in f.explanation
    assert f.component_scores["ioc"] >= 0.7


def test_quiet_benign_window_produces_no_finding(model):
    s = Sentinel(model, None)
    evs = [flow_event(T0 + timedelta(minutes=m), dst=f"198.18.1.{m % 5}") for m in range(0, 180)]
    assert s.process_batch(evs) + s.flush(T0 + timedelta(hours=3)) == []
    assert s.stats.windows == 3


def test_custom_window_store_and_clock(model):
    fixed = T0 + timedelta(days=100)
    s = Sentinel(model, None, window_store=WindowStore("24h", hop=timedelta(hours=2)), clock=lambda: fixed)
    s.process_batch([flow_event(T0 + timedelta(minutes=m)) for m in range(60)])
    s.flush(T0 + timedelta(hours=4))
    assert s.stats.windows == 2


# ------------------------------------------------------------------ shipped model artifact

def test_shipped_model_card_reports_required_metrics(model):
    card = model.card
    test = card["metrics"]["test"]
    for key in ("pr_auc", "ece", "brier", "roc_auc"):
        assert test[key] is not None
    op = test["operating_points"]["0.60"]
    assert op["device_day"]["precision"] is not None and op["device_day"]["recall"] is not None
    assert op["false_alerts_per_10k_device_days"] is not None and op["per_device_class"]
    assert card["split"]["shared_entities"] == 0 and card["split"]["shared_groups"] == 0
    hold = card["metrics"]["external_holdout_detector"]
    assert hold["recall"] >= 0.9 and hold["false_alerts_per_10k_device_days"] <= 50
    assert hold["hard_negative_devices_alerted"] == 0
    # evaluation corpora (seed 7 holdout, seed 11 here) never overlap the training corpora
    assert 7 not in card["data"]["seeds"] and 11 not in card["data"]["seeds"]


def test_shipped_artifact_small_and_integrity_checked():
    d = default_model_dir()
    total = sum(p.stat().st_size for p in d.iterdir())
    assert total < 5 * 1024 * 1024
    manifest = json.loads((d / "manifest.json").read_text())
    assert set(manifest["files"]) >= {"booster.txt", "calibration.json", "model_card.json", "anomaly.json"}


def test_idle_entity_state_is_pruned(model):
    s = Sentinel(model, None)
    s.process_batch([flow_event(T0 + timedelta(minutes=m), entity="p_old") for m in range(60)])
    s.flush(T0 + timedelta(hours=2))
    assert ("t1", "p_old") in s._streak
    later = T0 + timedelta(days=30)
    s.process_batch([flow_event(later + timedelta(minutes=m), entity="p_new") for m in range(60)])
    s.flush(later + timedelta(hours=2))
    assert ("t1", "p_old") not in s._streak and ("t1", "p_new") in s._streak
    assert s.prune(later + timedelta(days=60)) >= 1
