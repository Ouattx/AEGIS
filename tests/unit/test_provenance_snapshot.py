from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from aegis.contracts.models import Evidence, EvidenceKind
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import GENESIS_HASH, EntryType, Ledger
from aegis.provenance.snapshot import record_snapshot, replay, snapshot, verify_snapshot
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
TABLES = ["docs", "ledger_entries", "ledger_heads"]


def m(n: int) -> datetime:
    return T0 + timedelta(minutes=n)


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'snap.db'}")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in TABLES])
    yield eng
    eng.dispose()


@pytest.fixture
def ledger(engine):
    return Ledger(make_session_factory(engine))


@pytest.fixture
def store(engine, ledger):
    return EvidenceStore(DocStore(make_session_factory(engine)), ledger)


def ev(eid: str, group: str = "g1") -> Evidence:
    return Evidence(evidence_id=eid, tenant_id="t1", kind=EvidenceKind.OBSERVATION,
                    origin_source="sensor:a", source_independence_group=group,
                    collected_at=T0, summary=eid, authorization_id="auth-1")


# ------------------------------------------------------------------ snapshot

def test_snapshot_empty(ledger):
    s = snapshot("t1", ledger, T0)
    assert s["entry_count"] == 0 and s["head_hash"] == GENESIS_HASH
    assert s["snapshot_id"].startswith("snap_") and len(s["snapshot_hash"]) == 64


def test_snapshot_is_deterministic_and_prefix_based(ledger):
    for i in range(5):
        ledger.append("t1", "x", f"s{i}", {"i": i}, recorded_at=m(i))
    s2 = snapshot("t1", ledger, m(2))
    assert s2["entry_count"] == 3
    assert s2["head_hash"] == ledger.get("t1", 3).entry_hash
    assert snapshot("t1", ledger, m(2)) == s2
    # later appends do not change a past snapshot
    ledger.append("t1", "x", "late", {}, recorded_at=m(10))
    assert snapshot("t1", ledger, m(2)) == s2
    # same state, different as_of => different id (as_of is part of identity)
    assert snapshot("t1", ledger, m(2) + timedelta(seconds=1))["snapshot_id"] != s2["snapshot_id"]
    assert snapshot("t1", ledger, m(4))["snapshot_hash"] != s2["snapshot_hash"]
    with pytest.raises(ValueError):
        snapshot("t1", ledger, datetime(2026, 1, 1))


def test_snapshot_tenant_scoped(ledger):
    ledger.append("a", "x", "s", {"v": 1}, recorded_at=T0)
    ledger.append("b", "x", "s", {"v": 1}, recorded_at=T0)
    assert snapshot("a", ledger, T0)["snapshot_hash"] != snapshot("b", ledger, T0)["snapshot_hash"]


def test_verify_snapshot_detects_rewrite(ledger, engine):
    for i in range(3):
        ledger.append("t1", "x", f"s{i}", {"i": i}, recorded_at=m(i))
    s = snapshot("t1", ledger, m(5))
    assert verify_snapshot("t1", ledger, s)
    iso = dict(s, as_of=s["as_of"].isoformat())
    assert verify_snapshot("t1", ledger, iso)
    with engine.begin() as c:
        c.execute(text("DROP TRIGGER ledger_entries_no_delete"))
        c.execute(text("DELETE FROM ledger_entries WHERE seq=3"))
    assert not verify_snapshot("t1", ledger, s)
    assert not verify_snapshot("t1", ledger, {"snapshot_hash": "x"})
    assert not verify_snapshot("t1", ledger, {"as_of": "not a date"})


def test_record_snapshot_anchors_in_ledger(ledger):
    with pytest.raises(ValueError):
        record_snapshot("t1", ledger)
    ledger.append("t1", "x", "s", {}, recorded_at=T0)
    snap = record_snapshot("t1", ledger, reason="daily")
    entry = ledger.latest("t1")
    assert entry.entry_type == EntryType.SNAPSHOT
    assert entry.payload["snapshot_hash"] == snap["snapshot_hash"]
    assert entry.subject_id == snap["snapshot_id"]
    assert snap["entry_count"] == 1
    case_snap = record_snapshot("t1", ledger, m(1), reason="case VERIFIED", subject_id="case-1")
    assert ledger.latest("t1").subject_id == "case-1"
    assert case_snap["as_of"] == m(1)
    assert ledger.verify_chain("t1") == (True, None)


# ------------------------------------------------------------------ replay

def _scenario(store: EvidenceStore, ledger: Ledger) -> None:
    """Case opened from a finding at m(3); new evidence and a correction arrive later."""
    ledger.append("t1", EntryType.MODEL, "sentinel-gbm", {"version": "gbm-1.0"}, recorded_at=m(0))
    ledger.append("t1", EntryType.RULE_BUNDLE, "iocs", {"version": "iocs-2026.10.01"},
                  recorded_at=m(0))
    store.append(ev("e1"), recorded_at=m(1))
    store.append(ev("e2", group="g2"), recorded_at=m(2))
    ledger.append("t1", EntryType.FINDING, "f1", {
        "finding_id": "f1", "evidence_ids": ["e1", "e2"], "counterevidence_ids": [],
        "detector_version": "sentinel-1.0", "model_version": "gbm-1.0",
        "rule_bundle_version": "iocs-2026.10.01", "verdict": "suspicious",
    }, recorded_at=m(3))
    ledger.append("t1", EntryType.CASE_TRANSITION, "case-1", {
        "case_id": "case-1", "finding_ids": ["f1"], "from": "NEW", "to": "TRIAGE",
        "actor": "system"}, recorded_at=m(3))
    # --- after the original decision time
    store.append(ev("e3", group="g3"), recorded_at=m(10))
    ledger.append("t1", EntryType.FINDING, "f1", {
        "finding_id": "f1", "evidence_ids": ["e1", "e2", "e3"], "model_version": "gbm-2.0",
        "rule_bundle_version": "iocs-2026.10.02", "verdict": "malicious"}, recorded_at=m(11))
    store.correct("t1", "e2", ev("e2-v2", group="g2"), reason="bad parse", actor="analyst:x",
                  recorded_at=m(12))
    ledger.append("t1", EntryType.CASE_TRANSITION, "case-1", {
        "case_id": "case-1", "from": "TRIAGE", "to": "INVESTIGATING", "actor": "analyst:x",
        "model_versions": ["gbm-2.0"]}, recorded_at=m(13))
    # unrelated subject
    store.append(ev("other"), recorded_at=m(14))


def test_replay_uses_only_contemporaneous_evidence(store, ledger):
    _scenario(store, ledger)
    r = replay("t1", ledger, "case-1", m(5))
    assert r["evidence_ids"] == ["e1", "e2"]
    assert r["model_versions"] == ["gbm-1.0", "sentinel-1.0"]
    assert r["rule_bundle_versions"] == ["iocs-2026.10.01"]
    assert r["superseded_evidence_ids"] == {}
    assert r["non_contemporaneous_evidence_ids"] == []
    assert [d["entry_type"] for d in r["decisions"]] == [EntryType.FINDING,
                                                         EntryType.CASE_TRANSITION]
    assert all(d["recorded_at"] <= m(5) for d in r["entries"])
    assert r["snapshot"] == snapshot("t1", ledger, m(5))
    assert r["as_of"] == m(5) and r["subject_id"] == "case-1"


def test_replay_later_sees_new_state(store, ledger):
    _scenario(store, ledger)
    r = replay("t1", ledger, "case-1", m(20))
    assert r["evidence_ids"] == ["e1", "e2", "e2-v2", "e3"]
    assert "other" not in r["evidence_ids"]
    assert r["superseded_evidence_ids"] == {"e2": "e2-v2"}
    assert r["model_versions"] == ["gbm-1.0", "gbm-2.0", "sentinel-1.0"]
    assert r["rule_bundle_versions"] == ["iocs-2026.10.01", "iocs-2026.10.02"]
    assert len(r["decisions"]) == 4


def test_replay_before_anything(store, ledger):
    _scenario(store, ledger)
    r = replay("t1", ledger, "case-1", m(2))
    assert r["evidence_ids"] == [] and r["decisions"] == [] and r["entries"] == []
    assert r["snapshot"]["entry_count"] == 4


def test_replay_flags_non_contemporaneous_references(ledger):
    ledger.append("t1", EntryType.FINDING, "f9", {"finding_id": "f9", "evidence_ids": ["late"]},
                  recorded_at=m(1))
    ledger.append("t1", EntryType.EVIDENCE, "late", {"evidence_id": "late"}, recorded_at=m(5))
    r = replay("t1", ledger, "f9", m(2))
    assert r["evidence_ids"] == []
    assert r["non_contemporaneous_evidence_ids"] == ["late"]
    assert replay("t1", ledger, "f9", m(6))["evidence_ids"] == ["late"]


def test_replay_of_evidence_subject_and_tenant_scope(store, ledger):
    _scenario(store, ledger)
    r = replay("t1", ledger, "e1", m(20))
    assert r["evidence_ids"] == ["e1"]
    assert replay("t2", ledger, "case-1", m(20))["entries"] == []


def test_replay_handles_cycles(ledger):
    ledger.append("t1", EntryType.FINDING, "a", {"finding_id": "b"}, recorded_at=T0)
    ledger.append("t1", EntryType.FINDING, "b", {"finding_id": "a"}, recorded_at=T0)
    r = replay("t1", ledger, "a", m(1))
    assert {e["subject_id"] for e in r["entries"]} == {"a", "b"}
