"""End to end on a real lab corpus: VERIFIED case (real CaseService) -> drafts -> frozen backtest
-> signed approval -> shadow -> gate -> promotion -> findings with rule id and version."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from aegis.contracts.models import CaseState, Evidence, EvidenceKind, Finding, Verdict
from aegis.detengine import (
    BacktestConfig,
    CaseMaterial,
    DetectionEngineering,
    FrozenDatasetMismatch,
    RulePromotionGate,
    RuleRegistry,
    RuleState,
    corpus_digest,
    dataset_from_corpus,
    load_frozen_lab_dataset,
    sign_approval,
)
from aegis.detengine.backtest import window_day
from aegis.lab.corpus import generate_corpus
from aegis.oracle.state_machine import CaseService
from aegis.sentinel.rules import ioc_match
from aegis.sentinel.training import lab_bundle
from test_detengine_support import Clock, make_stores

SEED, DEVICES, DAYS, FRACTION, TENANT = 5, 40, 3, 0.2, "lab"


@pytest.fixture(scope="module")
def corpus():
    return generate_corpus(seed=SEED, days=DAYS, n_devices=DEVICES, malicious_fraction=FRACTION, tenant_id=TENANT)


@pytest.fixture(scope="module")
def dataset(corpus):
    return dataset_from_corpus(corpus, name="lab-seed5", expected_digest=corpus_digest(corpus))


def test_frozen_dataset_and_digest_checks(corpus, dataset, tmp_path):
    assert dataset.frozen and dataset.synthetic and dataset.digest == corpus_digest(corpus)
    assert len(dataset.windows) == len(dataset.contacts) > 0
    assert sum(c is not None for c in dataset.contacts) == len(dataset.contacts)
    with pytest.raises(FrozenDatasetMismatch):
        dataset_from_corpus(corpus, name="tampered", expected_digest="0" * 64)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema": "aegis.eval.frozen/1", "datasets": {"lab-seed5": {
        "digest": dataset.digest, "spec": {"seed": SEED, "days": DAYS, "n_devices": DEVICES,
                                           "malicious_fraction": FRACTION, "tenant_id": TENANT,
                                           "start": corpus.start.isoformat()}}}}))
    again = load_frozen_lab_dataset("lab-seed5", manifest)
    assert again.frozen and again.digest == dataset.digest and len(again.windows) == len(dataset.windows)
    with pytest.raises(KeyError):
        load_frozen_lab_dataset("missing", manifest)
    bad = json.loads(manifest.read_text())
    bad["datasets"]["lab-seed5"]["digest"] = "f" * 64
    manifest.write_text(json.dumps(bad))
    with pytest.raises(FrozenDatasetMismatch):
        load_frozen_lab_dataset("lab-seed5", manifest)


def _verified_case(corpus, dataset, st, clock):
    """Open and verify a case for an infected device through the real ORACLE state machine."""
    split = dataset.default_split()
    dev = next(d for d in corpus.malicious_devices()
               if d.malicious_label == "residential_proxy" and d.infection_day == 0 and d.c2_in_ioc_feed)
    pairs = [(fv, c) for fv, c in zip(dataset.windows, dataset.contacts)
             if fv.entity_pseudonym == dev.entity_pseudonym and fv.window_end <= split
             and corpus.labels.get((fv.entity_pseudonym, window_day(fv))) != "benign"]
    fv, contacts = pairs[-1]
    from aegis.sentinel.features import ContactSummary
    cs = ContactSummary(fv.tenant_id, fv.entity_pseudonym, fv.window_end - timedelta(days=1), fv.window_end)
    for ip in contacts.dst_ips:
        cs.dst_ips[ip] += 1
    for q in contacts.qnames:
        cs.qnames[q] += 1
    cs.answers = {k: set(v) for k, v in contacts.answers.items()}
    cs.authorization_ids = set(contacts.authorization_ids)
    hits = [e for e in ioc_match(fv, cs, lab_bundle(corpus), fv.window_end) if e.supports]
    assert hits, "the lab C2 is in the signed feed"
    obs = Evidence(tenant_id=TENANT, kind=EvidenceKind.OBSERVATION, origin_source="sensor:lab-netflow",
                   source_independence_group="operator-telemetry", collected_at=fv.window_end,
                   summary="telemetry window", authorization_id="auth-lab-synthetic-001",
                   payload={"entity_pseudonym": fv.entity_pseudonym})
    stored = [st.evidence.append(e) for e in hits + [obs]]
    finding = Finding(tenant_id=TENANT, entity_pseudonym=fv.entity_pseudonym, device_class=fv.device_class,
                      detector_version="sentinel-test", label="residential_proxy", verdict=Verdict.SUSPICIOUS,
                      score=0.7, observed_window_start=fv.window_end - timedelta(days=1),
                      observed_window_end=fv.window_end, evidence_ids=[e.evidence_id for e in stored],
                      created_at=fv.window_end, expires_at=fv.window_end + timedelta(days=3))
    cases = CaseService(st.docs, st.evidence, st.ledger, clock=clock)
    case = cases.open_case(finding)
    for to in (CaseState.TRIAGE, CaseState.INVESTIGATING):
        case = cases.transition(TENANT, case.case_id, to, "analyst-1", "triage")
    cases.record_counter_hypothesis_review(TENANT, case.case_id, reviewer="analyst-1",
                                           alternatives=["licensed IPTV middleware"], notes="not IPTV: rare C2")
    case = cases.transition(TENANT, case.case_id, CaseState.VERIFIED, "analyst-1", "signed IOC + telemetry")
    windows = tuple(f for f, _ in pairs)
    return CaseMaterial(case=case, evidences=tuple(stored), windows=windows,
                        contacts=tuple(c for _, c in pairs)), dev


def test_verified_case_to_promoted_rule(corpus, dataset, tmp_path):
    st = make_stores(tmp_path)
    clock = Clock(now=dataset.end + timedelta(days=1))
    material, dev = _verified_case(corpus, dataset, st, clock)
    gate = RulePromotionGate(min_precision_lower=0.2, max_false_alerts_per_10k_upper=1000.0,
                             min_shadow_duration=timedelta(days=1), min_shadow_reviews=2)
    reg = RuleRegistry(st.docs, st.ledger, approver_keyring=st.keyring, gate=gate, clock=clock)
    wb = DetectionEngineering(reg, datasets=[dataset],
                              backtest_config=BacktestConfig(min_holdout_device_days=50,
                                                             min_holdout_positive_device_days=2))
    out = wb.draft_from_case(TENANT, material, hosting=corpus.topology)
    assert out.records, out.rejected
    assert all(r.state is RuleState.BACKTESTED for r in out.records)
    dest = next(r for r in out.records if r.spec.get("destinations"))
    report = out.backtests[dest.ref][0]
    m = report.metrics
    # held out: the case device is excluded and only post-split device-days are scored
    assert report.excluded_entities >= 1 and report.holdout_start == dataset.default_split()
    assert dev.entity_pseudonym not in {e["entity_pseudonym"] for e in report.missed_examples}
    assert m.tp >= 2 and m.fp == 0 and m.hard_negative_alerts == 0
    assert m.precision_ci_exact.low > 0.2 and m.false_alerts_per_10k_ci_exact.high < 1000
    assert report.sufficient and report.synthetic

    req = reg.approval_request(TENANT, dest.ref, purpose="approve", approver="alice", reason="matches the case")
    reg.approve(TENANT, sign_approval(req, st.alice))
    reg.start_shadow(TENANT, dest.ref, actor="alice", reason="shadow pilot")
    eng = reg.active_rules(TENANT, hosting=corpus.topology)
    assert [r.ref for r in eng.rules] == [dest.ref]
    holdout = [(f, c) for f, c in zip(dataset.windows, dataset.contacts) if f.window_end > dataset.default_split()]
    res = eng.process_many(holdout)
    assert res.findings == [] and len(res.shadow_findings) >= 2
    for f in res.shadow_findings[:2]:
        reg.record_shadow_review(TENANT, dest.ref, f.finding_id, outcome="true_positive", reviewer="carol")
    clock.advance(days=2)
    ev = reg.evaluate_promotion(TENANT, dest.ref, actor="alice")
    assert ev.passed, ev.failed_checks
    req = reg.approval_request(TENANT, dest.ref, purpose="promote", approver="bob", reason="gate passed",
                               promotion_evaluation_id=ev.doc_id)
    reg.promote(TENANT, sign_approval(req, st.bob))

    eng = reg.active_rules(TENANT, evidence_store=st.evidence, hosting=corpus.topology)
    res = eng.process_many(holdout)
    assert res.findings and not res.shadow_findings
    assert {f.detector_version for f in res.findings} == {f"detengine:{dest.ref}"}
    assert all(f.verdict is Verdict.SUSPICIOUS and f.requires_review for f in res.findings)
    flagged = {f.entity_pseudonym for f in res.findings}
    assert not flagged & dataset.hard_negatives          # busy IPTV boxes are not flagged
    assert st.ledger.verify_chain(TENANT) == (True, None)
