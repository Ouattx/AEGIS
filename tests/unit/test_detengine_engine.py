"""Execution engine: promoted vs shadow findings, rule id + version, persistence, tenant isolation."""
from __future__ import annotations

import pytest

from aegis.contracts.models import EvidenceKind, Finding, Verdict
from aegis.detengine import ActiveRule, RuleEngine, RuleShadowFinding, RuleSpec
from aegis.detengine.engine import SHADOW_ENTRY, TELEMETRY_GROUP
from aegis.provenance.ledger import EntryType
from test_detengine_support import TENANT, contacts, fv, make_stores

NX = RuleSpec.from_dict({"rule_id": "dga-nx", "title": "NX storm", "label": "dga_activity", "severity": "high",
                         "conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}]})
C2 = RuleSpec.from_dict({"rule_id": "c2-dom", "title": "C2 domain", "label": "c2_beaconing",
                         "destinations": {"patterns": [{"kind": "domain_suffix", "value": "c2.example"}]}})


def active(spec: RuleSpec, mode: str, version: int = 1) -> ActiveRule:
    return ActiveRule(rule_id=spec.rule_id, version=version, spec=spec, mode=mode, spec_sha256=spec.sha256)


def test_promoted_rule_emits_reviewable_uncalibrated_findings():
    eng = RuleEngine(TENANT, [active(NX, "promoted", 3)])
    res = eng.process(fv(nxdomain_rate=0.95))
    assert len(res.findings) == 1 and not res.shadow_findings
    f = res.findings[0]
    assert f.detector_version == "detengine:dga-nx@v3"
    assert f.verdict is Verdict.SUSPICIOUS and f.requires_review and f.calibration_id is None
    assert f.score == 0.8 and f.label == "dga_activity" and f.component_scores == {"rule:dga-nx@v3": 0.8}
    assert "not a probability" in f.explanation
    assert eng.process(fv(nxdomain_rate=0.1)).findings == []


def test_shadow_rule_emits_only_shadow_findings():
    eng = RuleEngine(TENANT, [active(NX, "shadow"), active(C2, "promoted")])
    res = eng.process(fv(nxdomain_rate=0.95), contacts(names=("x.c2.example",)))
    assert [f.detector_version for f in res.findings] == ["detengine:c2-dom@v1"]
    assert [f.detector_version for f in res.shadow_findings] == ["detengine:dga-nx@v1+shadow"]
    assert "SHADOW" in res.shadow_findings[0].explanation
    assert eng.shadow[0].ref == "dga-nx@v1" and eng.promoted[0].ref == "c2-dom@v1"
    assert eng.versions() == {"c2-dom@v1": C2.sha256, "dga-nx@v1": NX.sha256}


def test_abstentions_are_reported_not_emitted():
    eng = RuleEngine(TENANT, [active(NX, "promoted"), active(C2, "promoted")])
    res = eng.process(fv(nxdomain_rate=None))          # NX: missing feature; C2: no contacts
    assert res.findings == [] and len(res.abstentions) == 2


def test_tenant_isolation_and_duplicates():
    eng = RuleEngine(TENANT, [active(NX, "promoted")])
    with pytest.raises(ValueError):
        eng.process(fv(tenant_id="other", nxdomain_rate=0.9))
    with pytest.raises(ValueError):
        RuleEngine(TENANT, [active(NX, "promoted"), active(NX, "shadow")])


def test_persistence_promoted_and_shadow(tmp_path):
    st = make_stores(tmp_path)
    eng = RuleEngine(TENANT, [active(NX, "promoted"), active(C2, "shadow")], evidence_store=st.evidence,
                     docstore=st.docs)
    res = eng.process(fv(nxdomain_rate=0.9), contacts(names=("c2.example",)))
    f = res.findings[0]
    ev = st.evidence.get(TENANT, f.evidence_ids[0])
    assert ev is not None and ev.kind is EvidenceKind.OBSERVATION and ev.sha256
    assert ev.source_independence_group == TELEMETRY_GROUP          # never a second independent witness
    assert ev.payload["rule_id"] == "dga-nx" and ev.payload["rule_version"] == 1
    assert ev.payload["spec_sha256"] == NX.sha256
    entries = st.ledger.entries(TENANT, subject_id=f.finding_id, entry_type=EntryType.FINDING)
    assert entries and entries[0].payload["rule_bundle_version"] == "detengine:dga-nx@v1"
    # shadow: stored apart from Finding documents, ledgered as shadow, evidence not in the evidence store
    sf = res.shadow_findings[0]
    assert st.docs.get(Finding, TENANT, sf.finding_id) is None
    rec = st.docs.get(RuleShadowFinding, TENANT, sf.finding_id)
    assert rec is not None and rec.rule_ref == "c2-dom@v1" and rec.evidence[0]["sha256"]
    assert st.evidence.get(TENANT, sf.evidence_ids[0]) is None
    assert st.ledger.entries(TENANT, subject_id=sf.finding_id, entry_type=SHADOW_ENTRY)
    ok, bad = st.ledger.verify_chain(TENANT)
    assert ok and bad is None
