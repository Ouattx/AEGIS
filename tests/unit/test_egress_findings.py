"""EGRESS verdicts -> Findings: evidence through aegis.provenance, ledger entries, abstention."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.contracts.models import EvidenceKind, FlowObservation, ObservationEvent, SourceKind, Vantage, Verdict
from aegis.egress import (
    CAMPAIGN_ENTRY,
    INDEPENDENCE_GROUP,
    LABEL_DDOS,
    SPOOF_INDEPENDENCE_GROUP,
    EgressConfig,
    EgressDetector,
    SpoofSignal,
    to_findings,
)
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType, Ledger
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
TENANT = "isp-a"
CFG = EgressConfig(min_flow_records=1)


def _flood(line: str, buckets: range, pps: float, *, uniflow: bool = False) -> list[ObservationEvent]:
    out = []
    for b in buckets:
        at = T0 + timedelta(seconds=b * 60)
        po = int(pps * 60)
        out.append(ObservationEvent(
            tenant_id=TENANT, observed_at=at, ingested_at=at, source_id="nf", source_kind=SourceKind.NETFLOW,
            vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-test", entity_pseudonym=line,
            device_class="android_tv", retention_until=at + timedelta(days=30), integrity_sha256="0" * 64,
            flow=FlowObservation(dst_ip="192.0.2.10", dst_port=80, protocol="udp", bytes_out=po * 512,
                                 bytes_in=None if uniflow else 0, packets_out=po,
                                 packets_in=None if uniflow else 0, duration_ms=60_000)))
    return out


@pytest.fixture()
def store() -> EvidenceStore:
    eng = make_engine("sqlite://")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in ("docs", "ledger_entries", "ledger_heads")])
    sf = make_session_factory(eng)
    return EvidenceStore(DocStore(sf), Ledger(sf))


def _detect(events, spoof=()):
    return EgressDetector(CFG, tenant_id=TENANT).detect(events, start=T0, end=T0 + timedelta(minutes=30),
                                                        spoof_signals=spoof)


def test_campaign_findings_cite_persisted_evidence_and_ledger(store):
    events = [e for i in range(3) for e in _flood(f"p_line0000{i}", range(3), 1_500)]
    rep = _detect(events)
    fs = to_findings(rep, cfg=CFG, evidence_store=store, authorization_id="auth-x")
    assert len(fs) == 3 and {f.verdict for f in fs} == {Verdict.MALICIOUS}
    camp_id = rep.campaigns[0].campaign_id
    for f in fs:
        assert f.requires_review is True and f.calibration_id is None and f.label == LABEL_DDOS
        assert f.evidence_ids and f.counterevidence_ids
        evs = store.list_for(TENANT, f.evidence_ids)
        assert len(evs) == len(f.evidence_ids)
        assert all(e.sha256 and e.authorization_id == "auth-x" for e in evs)
        assert {e.kind for e in evs} == {EvidenceKind.OBSERVATION, EvidenceKind.ANOMALY}
        assert all(e.source_independence_group == INDEPENDENCE_GROUP for e in evs)
        counter = store.list_for(TENANT, f.counterevidence_ids)
        assert all(not e.supports for e in counter)
        assert f.component_scores["peak_pps"] == 1500.0
    # the campaign evidence is written once and shared by every member finding
    shared = {eid for f in fs for eid in f.evidence_ids if store.get(TENANT, eid).kind is EvidenceKind.ANOMALY}
    assert len(shared) == 1
    assert len(store.ledger.entries(TENANT, entry_type=CAMPAIGN_ENTRY, subject_id=camp_id)) == 1
    assert len(store.ledger.entries(TENANT, entry_type=EntryType.FINDING)) == 3
    assert store.ledger.verify_chain(TENANT) == (True, None)


def test_spoofing_evidence_has_its_own_independence_group(store):
    sp = SpoofSignal(tenant_id=TENANT, entity_pseudonym="p_line00001", interval_start=T0,
                     interval_end=T0 + timedelta(minutes=5), packets_outside_prefix=5_000, packets_total=50_000,
                     source="urpf:bng-1")
    fs = to_findings(_detect(_flood("p_line00001", range(2), 1_200), [sp]), evidence_store=store)
    groups = {e.source_independence_group: e.origin_source for e in store.list_for(TENANT, fs[0].evidence_ids)}
    assert groups[SPOOF_INDEPENDENCE_GROUP] == "aegis:egress:urpf:bng-1"
    assert fs[0].verdict is Verdict.MALICIOUS


def test_abstain_finding_still_cites_evidence(store):
    fs = to_findings(_detect(_flood("p_line00001", range(3), 1_200, uniflow=True)), evidence_store=store)
    assert len(fs) == 1 and fs[0].verdict is Verdict.ABSTAIN and fs[0].score == 0.0
    ev = store.get(TENANT, fs[0].evidence_ids[0])
    assert ev.payload["abstention"]["abstain_reason"] == "reverse_counters_missing"


def test_report_level_abstention_produces_no_findings():
    rep = EgressDetector(tenant_id=TENANT).detect(_flood("p_line00001", range(2), 1_200))
    assert rep.status == "abstain"
    assert to_findings(rep) == []


def test_findings_without_store_and_naive_now_rejected():
    rep = _detect(_flood("p_line00001", range(2), 1_200))
    fs = to_findings(rep)
    assert len(fs) == 1 and fs[0].expires_at - fs[0].created_at == timedelta(hours=CFG.finding_ttl_hours)
    with pytest.raises(ValueError):
        to_findings(rep, now=datetime(2026, 10, 1))
