"""Spec section 15: contradictory feeds downgrade finding (real composed system).

One deployment, two tenants, identical lab telemetry ingested from collector files.
Tenant ``feeds-clean`` loads the signed lab IOC bundle; tenant ``feeds-contested``
loads the same bundle plus, from an independent origin, a benign claim for every
malicious indicator. The contested tenant's findings must be downgraded, carry the
counter-evidence, and its cases must be contested (no automatic verification).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterator

import pytest

from aegis.api.demo import demo_start
from aegis.contracts.models import CaseState, Evidence, EvidenceKind, Finding, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.lab.iocs import lab_signer, sign_bundle
from aegis.oracle.state_machine import GuardError
from aegis.service import AegisService

from safety_kit import build_service

pytestmark = pytest.mark.safety

CLEAN, CONTESTED = "feeds-clean", "feeds-contested"
RANK = {Verdict.BENIGN: 0, Verdict.ABSTAIN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}
CONTRA_GROUP = "grp:registry-x"


@dataclass
class FeedsWorld:
    svc: AegisService
    corpus: Corpus
    findings: dict[str, list[Finding]]


def contested_bundle(clean: dict[str, Any], signer: Any) -> dict[str, Any]:
    """The clean bundle plus an independent benign claim (confidence 0.3) per malicious indicator."""
    out = copy.deepcopy(clean)
    out.pop("signature")
    claims = []
    for ind in clean["indicators"]:
        if ind["verdict"] != "malicious":
            continue
        claim = dict(ind, indicator_id=ind["indicator_id"] + "-registry-x", verdict="benign",
                     source="feed:registry-x", source_group=CONTRA_GROUP, confidence=0.3,
                     threat_label=None, malware_family=None,
                     description="registry-x lists this indicator as parked / sinkholed")
        claims.append(claim)
    assert claims
    out["indicators"] = out["indicators"] + claims
    out["version"] = clean["version"] + "+registry-x"
    return sign_bundle(out, signer)


@pytest.fixture(scope="module")
def feeds(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FeedsWorld]:
    tmp = tmp_path_factory.mktemp("feeds")
    svc, _ = build_service(tmp)
    corpus = generate_corpus(seed=21, days=2, n_devices=16, malicious_fraction=0.25, tenant_id="feeds",
                             start=demo_start(2))
    paths = corpus.write_raw(tmp / "raw", zeek=False)
    signer = lab_signer(corpus.seed)
    svc.trust_key("ioc", signer.key_id, signer.public_pem())
    clean = corpus.ioc_bundle(signer)
    findings: dict[str, list[Finding]] = {}
    for tenant, bundle in ((CLEAN, clean), (CONTESTED, contested_bundle(clean, signer))):
        svc.set_tenant_pseudonym_key(tenant, corpus.tenant_key)  # same pseudonyms in both tenants
        for cfg in corpus.sources.values():
            svc.register_source(tenant, "admin@isp", source_id=cfg.source_id, source_kind=cfg.source_kind,
                                vantage=cfg.vantage, collection_authorization_id=cfg.collection_authorization_id,
                                retention_days=cfg.retention_days, format=cfg.format, entity_field=cfg.entity_field)
        svc.load_ioc_bundle(tenant, "admin@isp", bundle)
        out = svc.ingest_files(tenant, [(paths["netflow"], "lab-netflow"), (paths["dns"], "lab-dns")],
                               flush_at=corpus.end)
        findings[tenant] = out.findings
    yield FeedsWorld(svc=svc, corpus=corpus, findings=findings)
    svc.close()


def _max_verdict(findings: list[Finding]) -> dict[str, Verdict]:
    out: dict[str, Verdict] = {}
    for f in findings:
        if RANK[f.verdict] > RANK.get(out.get(f.entity_pseudonym, Verdict.BENIGN), 0):
            out[f.entity_pseudonym] = f.verdict
    return out


def test_contradictory_feeds_downgrade_finding(feeds: FeedsWorld) -> None:
    svc = feeds.svc
    clean, contested = _max_verdict(feeds.findings[CLEAN]), _max_verdict(feeds.findings[CONTESTED])
    clean_mal = {e for e, v in clean.items() if v is Verdict.MALICIOUS}
    assert len(clean_mal) >= 3, "the clean tenant should detect the IOC-backed lab infections"
    # no entity is ever upgraded by a contradiction; IOC-backed MALICIOUS verdicts are downgraded
    for entity, v in contested.items():
        assert RANK[v] <= RANK[clean.get(entity, Verdict.BENIGN)], entity
    downgraded = {e for e in clean_mal if RANK[contested.get(e, Verdict.BENIGN)] < RANK[Verdict.MALICIOUS]}
    assert downgraded == clean_mal
    assert not any(f.verdict is Verdict.MALICIOUS for f in feeds.findings[CONTESTED])

    # every contested finding citing an indicator hit carries the contradiction as counter-evidence
    hits = 0
    for f in feeds.findings[CONTESTED]:
        evidence = [svc.evidence.get(CONTESTED, eid) for eid in f.evidence_ids]
        ioc = [e for e in evidence if e is not None and e.kind is EvidenceKind.IOC_MATCH]
        if not ioc:
            continue
        hits += 1
        assert all(e.payload["contradicted"] is True and CONTRA_GROUP not in e.source_independence_group
                   for e in ioc)
        assert all(e.payload["effective_confidence"] < e.payload["confidence"] for e in ioc)
        counter = [svc.evidence.get(CONTESTED, eid) for eid in f.counterevidence_ids]
        assert any(isinstance(c, Evidence) and c.source_independence_group == CONTRA_GROUP and not c.supports
                   for c in counter)
    assert hits >= 1


def test_contested_cases_cannot_be_verified_automatically(feeds: FeedsWorld) -> None:
    svc = feeds.svc
    cases = svc.list_cases(CONTESTED, limit=1000).items
    assert cases
    for case in cases:
        assessment = svc.cases.assess_evidence(case)
        assert assessment.contested and CONTRA_GROUP in assessment.contradicting_origins
        svc.cases.transition(CONTESTED, case.case_id, CaseState.TRIAGE, "system:triage", "queued")
        svc.cases.transition(CONTESTED, case.case_id, CaseState.INVESTIGATING, "system:triage", "investigate")
        svc.cases.record_counter_hypothesis_review(CONTESTED, case.case_id, reviewer="system:auto-review",
                                                   alternatives=["registry-x benign claim"], notes="automated")
        with pytest.raises(GuardError) as gi:
            svc.cases.transition(CONTESTED, case.case_id, CaseState.VERIFIED, "system:auto-verifier", "auto")
        assert "contested_case_requires_human_verifier" in gi.value.failed
        report = svc.investigate_case(CONTESTED, case.case_id, "analyst.alice")
        assert CONTRA_GROUP in report.contradicting_origins
        assert "contradictory_evidence" in report.escalation_reasons and report.escalate
    # in the clean tenant the same infections verify on evidence alone (no human needed for evidence)
    clean_cases = [c for c in svc.list_cases(CLEAN, limit=1000).items
                   if not svc.cases.assess_evidence(c).contested]
    assert clean_cases and all(not svc.cases.assess_evidence(c).verification_blockers() for c in clean_cases)
