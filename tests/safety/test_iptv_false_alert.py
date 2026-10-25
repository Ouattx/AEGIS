"""Spec section 15 (benign IPTV untouched), worst case: the detector itself false-alerts.

On some small lab populations the calibrated model raises a model-only alert on a
benign IPTV box (shadow mode exists to measure exactly this). This test drives such
an alert through the real workflow under a signed **active** policy and shows that
it can never be verified, proposed or enforced: model-only evidence is a single
origin, and the VERIFIED guard requires two independent origins or a signed IOC hit.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

import pytest

from aegis.api.demo import demo_start
from aegis.contracts.models import CaseState, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.lab.iocs import lab_signer
from aegis.provenance.signing import Signer
from aegis.service import AegisService, ConflictError

from safety_kit import LEGAL_BASIS, active_policy, build_service

pytestmark = pytest.mark.safety

TENANT = "small-isp"
IPTV_PROFILES = frozenset({"android_tv_iptv", "iptv_busy_box"})


@pytest.fixture(scope="module")
def small_isp(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[AegisService, Corpus]]:
    tmp = tmp_path_factory.mktemp("small-isp")
    svc, rpz = build_service(tmp)
    corpus = generate_corpus(seed=11, days=2, n_devices=30, malicious_fraction=0.15, tenant_id=TENANT,
                             start=demo_start(2))
    paths = corpus.write_raw(tmp / "raw", zeek=False)
    svc.set_tenant_pseudonym_key(TENANT, corpus.tenant_key)
    for cfg in corpus.sources.values():
        svc.register_source(TENANT, "admin@isp", source_id=cfg.source_id, source_kind=cfg.source_kind,
                            vantage=cfg.vantage, collection_authorization_id=cfg.collection_authorization_id,
                            format=cfg.format, entity_field=cfg.entity_field)
    ioc = lab_signer(corpus.seed)
    svc.trust_key("ioc", ioc.key_id, ioc.public_pem())
    svc.load_ioc_bundle(TENANT, "admin@isp", corpus.ioc_bundle(ioc))
    svc.load_topology(TENANT, "admin@isp", corpus.topology.to_dict(include_ground_truth=False))
    operator = Signer.generate("small-isp-operator")
    svc.trust_key("policy", operator.key_id, operator.public_pem())
    svc.load_policy(TENANT, "admin@isp", active_policy(svc, TENANT, operator, policy_id="small-isp-active"))
    svc.ingest_files(TENANT, [(paths["netflow"], "lab-netflow"), (paths["dns"], "lab-dns")], flush_at=corpus.end)
    yield svc, corpus
    svc.close()


def test_benign_iptv_false_alert_is_never_enforceable(small_isp: tuple[AegisService, Corpus]) -> None:
    svc, corpus = small_isp
    false_alerts = []
    for f in svc.list_findings(TENANT, limit=10_000).items:
        device = corpus.device(f.entity_pseudonym)
        assert device is not None
        if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) and not device.malicious:
            false_alerts.append((f, device))
    iptv = [(f, d) for f, d in false_alerts if d.profile in IPTV_PROFILES]
    assert iptv, "this corpus is chosen because the model false-alerts on a benign IPTV box"

    for finding, device in false_alerts:
        found = svc.cases.case_for_finding(TENANT, finding.finding_id)
        assert found is not None
        case_id = found.case_id
        case = svc.get_case(TENANT, case_id)
        # evidence: telemetry-derived only (one origin), no indicator hit
        assessment = svc.cases.assess_evidence(case)
        assert assessment.supporting_origins == ["operator-telemetry"] and not assessment.signed_ioc_hits
        assert "needs_two_independent_origins_or_signed_ioc_hit" in assessment.verification_blockers()
        # the full analyst workflow cannot verify it, even with a human and a counter-hypothesis review
        if case.state is CaseState.NEW:
            svc.transition_case(TENANT, case_id, CaseState.TRIAGE, "analyst.alice", "triage")
            svc.transition_case(TENANT, case_id, CaseState.INVESTIGATING, "analyst.alice", "investigate")
        report = svc.investigate_case(TENANT, case_id, "analyst.alice")
        assert report.verification.recommendation != "verify"
        svc.review_case(TENANT, case_id, "analyst.alice", ["benign IPTV multi-room streaming"], "reviewed")
        with pytest.raises(ConflictError) as ei:
            svc.transition_case(TENANT, case_id, CaseState.VERIFIED, "analyst.alice", "looks malicious to me")
        assert "needs_two_independent_origins_or_signed_ioc_hit" in ei.value.failed
        # so no action can be proposed against the device, under an active enforcement policy
        with pytest.raises(ConflictError):
            svc.propose_action(TENANT, "analyst.alice", case_id=case_id, action_type="notify_subscriber",
                               targets=[device.entity_pseudonym], legal_basis=LEGAL_BASIS,
                               expires_at=svc.clock() + timedelta(hours=4))
        assert svc.list_actions(TENANT, case_id=case_id).total == 0
        assert svc.transition_case(TENANT, case_id, CaseState.REJECTED, "analyst.alice",
                                   "benign IPTV box: false alert").state is CaseState.REJECTED

    assert svc.metrics_summary(TENANT)["actions"]["enforcement_applied"] == 0
