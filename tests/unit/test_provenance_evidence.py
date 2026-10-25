from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from aegis.contracts.models import Evidence, EvidenceKind
from aegis.provenance.evidence import (
    EvidenceExistsError,
    EvidenceIntegrityError,
    EvidenceStore,
    evidence_hash,
    independent_origins,
)
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
TABLES = ["docs", "ledger_entries", "ledger_heads"]


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'ev.db'}")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in TABLES])
    yield eng
    eng.dispose()


@pytest.fixture
def signer():
    return Signer.generate("k1")


@pytest.fixture
def store(engine, signer):
    sf = make_session_factory(engine)
    return EvidenceStore(DocStore(sf), Ledger(sf, signer=signer))


def ev(**kw) -> Evidence:
    base = dict(tenant_id="t1", kind=EvidenceKind.IOC_MATCH, origin_source="feed:abuse_ch",
                source_independence_group="abuse_ch", collected_at=T0,
                summary="domain on C2 list", payload={"domain": "bad.example"},
                authorization_id="auth-1")
    base.update(kw)
    return Evidence(**base)


def test_append_fills_hash_and_writes_ledger(store):
    e = ev()
    stored = store.append(e)
    assert e.sha256 == ""  # input untouched
    assert stored.sha256 == evidence_hash(stored) and len(stored.sha256) == 64
    entries = store.ledger.entries("t1", subject_id=stored.evidence_id)
    assert len(entries) == 1 and entries[0].entry_type == EntryType.EVIDENCE
    assert entries[0].payload["sha256"] == stored.sha256
    assert entries[0].payload["source_independence_group"] == "abuse_ch"
    assert store.get("t1", stored.evidence_id) == stored
    assert store.verify("t1", stored.evidence_id)


def test_hash_is_content_addressed(store):
    a = ev(evidence_id="e-a")
    b = ev(evidence_id="e-a")
    assert evidence_hash(a) == evidence_hash(b)
    assert evidence_hash(a) != evidence_hash(ev(evidence_id="e-a", summary="different"))


def test_append_is_immutable(store):
    stored = store.append(ev(evidence_id="e1"))
    with pytest.raises(EvidenceExistsError):
        store.append(ev(evidence_id="e1", summary="overwrite attempt"))
    assert store.get("t1", "e1") == stored
    assert len(store.ledger.entries("t1", subject_id="e1")) == 1


def test_producer_hash_must_match(store):
    good = ev(evidence_id="e1")
    stored = store.append(good.model_copy(update={"sha256": evidence_hash(good)}))
    assert stored.sha256 == evidence_hash(good)
    with pytest.raises(EvidenceIntegrityError):
        store.append(ev(evidence_id="e2", sha256="f" * 64))
    assert store.get("t1", "e2") is None
    assert store.ledger.entries("t1", subject_id="e2") == []


def test_naive_timestamp_rejected(store):
    with pytest.raises(ValueError):
        store.append(ev(collected_at=datetime(2026, 1, 1)))


def test_tenant_isolation(store):
    stored = store.append(ev(evidence_id="e1"))
    assert store.get("t2", "e1") is None
    assert store.list_for("t2", ["e1"]) == []
    assert store.get("t1", "e1") == stored
    assert store.ledger.entries("t2") == []


def test_list_for_order_dedupe_and_missing(store):
    a = store.append(ev(evidence_id="a"))
    b = store.append(ev(evidence_id="b"))
    assert store.list_for("t1", ["b", "zzz", "a", "b"]) == [b, a]
    assert store.missing("t1", ["a", "zzz", "q", "zzz"]) == ["zzz", "q"]


def test_tampered_document_detected(store, engine):
    store.append(ev(evidence_id="e1"))
    with engine.begin() as c:
        body = c.execute(text("SELECT body FROM docs WHERE id='e1'")).scalar_one()
        forged = body.replace("bad.example", "innocent.example")
        c.execute(text("UPDATE docs SET body=:b WHERE id='e1'"), {"b": forged})
    with pytest.raises(EvidenceIntegrityError):
        store.get("t1", "e1")
    assert not store.verify("t1", "e1")


def test_rehashed_document_still_detected_via_ledger(store, engine):
    """Attacker edits the document and recomputes its sha256: the ledger record disagrees."""
    stored = store.append(ev(evidence_id="e1"))
    forged = stored.model_copy(update={"summary": "benign"})
    forged = forged.model_copy(update={"sha256": evidence_hash(forged)})
    store._docs.put(forged)  # direct write, bypassing append
    assert store.get("t1", "e1") == forged  # self-consistent document...
    assert not store.verify("t1", "e1")      # ...but not what was recorded in the ledger


def test_correction_creates_new_version(store):
    orig = store.append(ev(evidence_id="e1"), recorded_at=T0)
    fixed = store.correct("t1", "e1", ev(evidence_id="e1-v2", summary="corrected"),
                          reason="wrong feed timestamp", actor="analyst:bo",
                          recorded_at=T0 + timedelta(hours=1))
    assert store.get("t1", "e1") == orig  # original preserved
    assert store.superseded_by("t1", "e1") == "e1-v2"
    assert store.superseded_by("t1", "e1", as_of=T0 + timedelta(minutes=30)) is None
    assert store.current("t1", "e1") == fixed
    assert store.current("t1", "e1", as_of=T0 + timedelta(minutes=30)) == orig
    corr = store.ledger.entries("t1", subject_id="e1", entry_type=EntryType.CORRECTION)
    assert corr[0].payload["superseded_by"] == "e1-v2"
    v2 = store.ledger.entries("t1", subject_id="e1-v2")[0]
    assert v2.payload["corrects"] == "e1"
    # chained corrections
    store.correct("t1", "e1-v2", ev(evidence_id="e1-v3"), reason="again", actor="analyst:bo")
    assert store.current("t1", "e1").evidence_id == "e1-v3"
    keyring = KeyRing()
    keyring.add_signer(store.ledger.signer)
    assert store.ledger.verify_chain("t1", keyring) == (True, None)


def test_correction_validation(store):
    store.append(ev(evidence_id="e1"))
    with pytest.raises(LookupError):
        store.correct("t1", "nope", ev(evidence_id="x"), reason="r", actor="a")
    with pytest.raises(ValueError):
        store.correct("t1", "e1", ev(evidence_id="e1"), reason="r", actor="a")
    with pytest.raises(ValueError):
        store.correct("t1", "e1", ev(evidence_id="x", tenant_id="t2"), reason="r", actor="a")


# ------------------------------------------------------------------ independence

def test_syndicated_feeds_count_as_one_origin():
    feeds = [ev(origin_source=f"feed:{name}", source_independence_group="report:vendorX-2026-42")
             for name in ("alpha", "beta", "gamma", "delta")]
    assert independent_origins(feeds) == 1
    assert EvidenceStore.independent_origins(feeds) == 1


def test_distinct_groups_counted():
    items = [
        ev(source_independence_group="abuse_ch"),
        ev(source_independence_group="ABUSE_CH "),          # same group, normalized
        ev(source_independence_group="sensor:netflow-par1", kind=EvidenceKind.OBSERVATION),
        ev(source_independence_group="", origin_source="feed:solo"),  # falls back to origin
        ev(source_independence_group="vendor_y", supports=False),
    ]
    assert independent_origins(items) == 4
    assert independent_origins(items, supporting_only=True) == 3
    assert independent_origins([]) == 0
    assert independent_origins(iter(items)) == 4
