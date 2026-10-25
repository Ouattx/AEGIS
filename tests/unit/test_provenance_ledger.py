from __future__ import annotations

import os
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from aegis.provenance.ledger import (
    GENESIS_HASH,
    EntryType,
    Ledger,
    LedgerEntryRow,
    compute_entry_hash,
)
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import Base, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
PG_URL = os.environ.get("AEGIS_TEST_POSTGRES_URL")


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request, tmp_path):
    if request.param == "sqlite":
        eng = make_engine(f"sqlite:///{tmp_path / 'ledger.db'}")
    else:
        if not PG_URL:
            pytest.skip("AEGIS_TEST_POSTGRES_URL not set")
        eng = make_engine(PG_URL)
        Base.metadata.drop_all(eng, tables=[LedgerEntryRow.__table__,
                                            Base.metadata.tables["ledger_heads"]])
    Base.metadata.create_all(eng, tables=[LedgerEntryRow.__table__,
                                          Base.metadata.tables["ledger_heads"]])
    yield eng
    eng.dispose()


@pytest.fixture
def sf(engine):
    return make_session_factory(engine)


@pytest.fixture
def signer():
    return Signer.generate("ledger-k1")


@pytest.fixture
def keyring(signer):
    ring = KeyRing()
    ring.add_signer(signer)
    return ring


def _tamper(engine, sql: str, **params) -> None:
    """Simulate an attacker with direct database access (bypasses append-only triggers)."""
    with engine.begin() as c:
        if engine.dialect.name == "sqlite":
            c.execute(text("DROP TRIGGER IF EXISTS ledger_entries_no_update"))
            c.execute(text("DROP TRIGGER IF EXISTS ledger_entries_no_delete"))
        else:
            c.execute(text("ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_append_only"))
        c.execute(text(sql), params)
        if engine.dialect.name != "sqlite":
            c.execute(text("ALTER TABLE ledger_entries ENABLE TRIGGER ledger_entries_append_only"))


def _fill(ledger: Ledger, n: int = 5, tenant: str = "t1") -> list:
    return [ledger.append(tenant, EntryType.FINDING, f"f{i}", {"i": i, "score": i / 10},
                          recorded_at=T0 + timedelta(minutes=i)) for i in range(n)]


# ------------------------------------------------------------------ basics

def test_empty_chain(sf):
    ledger = Ledger(sf)
    assert ledger.head("t1") == GENESIS_HASH
    assert ledger.entries("t1") == []
    assert ledger.verify_chain("t1") == (True, None)
    assert ledger.count("t1") == 0


def test_append_links_chain(sf):
    ledger = Ledger(sf)
    es = _fill(ledger)
    assert [e.seq for e in es] == [1, 2, 3, 4, 5]
    assert es[0].prev_hash == GENESIS_HASH
    for a, b in zip(es, es[1:]):
        assert b.prev_hash == a.entry_hash
    assert ledger.head("t1") == es[-1].entry_hash
    assert ledger.entries("t1") == es
    assert ledger.verify_chain("t1") == (True, None)
    assert es[0].signature is None and es[0].signer_key_id is None


def test_entry_hash_is_reproducible(sf):
    e = Ledger(sf).append("t1", "model", "m1", {"version": "1.2"}, recorded_at=T0)
    assert e.entry_hash == compute_entry_hash(
        seq=1, tenant_id="t1", entry_type="model", subject_id="m1",
        payload_sha256=e.payload_sha256, prev_hash=GENESIS_HASH, recorded_at=T0,
        signer_key_id=None)


def test_payload_normalized_and_validated(sf):
    ledger = Ledger(sf)
    e = ledger.append("t1", "x", "s", {"when": T0, "tuple": (1, 2), "nested": {"b": 1, "a": 2}},
                      recorded_at=T0)
    assert e.payload["when"] == T0.isoformat()
    assert e.payload["tuple"] == [1, 2]
    assert ledger.entries("t1")[0].payload == e.payload
    with pytest.raises(ValueError):
        ledger.append("t1", "x", "s", {"bad": float("nan")})
    with pytest.raises(ValueError):
        ledger.append("", "x", "s", {})
    with pytest.raises(ValueError):
        ledger.append("t1", "x", "s" * 200, {})
    with pytest.raises(TypeError):
        ledger.append("t1", "x", "s", [1, 2])  # type: ignore[arg-type]


def test_rejects_naive_and_backdated_timestamps(sf):
    ledger = Ledger(sf)
    with pytest.raises(ValueError):
        ledger.append("t1", "x", "s", {}, recorded_at=datetime(2026, 1, 1))
    ledger.append("t1", "x", "s", {}, recorded_at=T0)
    with pytest.raises(ValueError, match="back-dated"):
        ledger.append("t1", "x", "s", {}, recorded_at=T0 - timedelta(seconds=1))
    # same instant is allowed (non-decreasing)
    ledger.append("t1", "x", "s", {}, recorded_at=T0)
    assert ledger.verify_chain("t1") == (True, None)


def test_implicit_timestamp_clamped_to_head(sf):
    ledger = Ledger(sf)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    ledger.append("t1", "x", "s", {}, recorded_at=future)
    e = ledger.append("t1", "x", "s", {})
    assert e.recorded_at == future
    assert ledger.verify_chain("t1") == (True, None)


def test_recorded_at_roundtrips_as_utc(sf):
    ledger = Ledger(sf)
    plus2 = timezone(timedelta(hours=2))
    ledger.append("t1", "x", "s", {}, recorded_at=datetime(2026, 10, 1, 10, 0, 0, 123456, tzinfo=plus2))
    got = ledger.entries("t1")[0].recorded_at
    assert got == datetime(2026, 10, 1, 8, 0, 0, 123456, tzinfo=timezone.utc)
    assert got.utcoffset() == timedelta(0)
    assert ledger.verify_chain("t1") == (True, None)


def test_tenants_are_isolated(sf):
    ledger = Ledger(sf)
    _fill(ledger, 3, "a")
    _fill(ledger, 2, "b")
    assert [e.seq for e in ledger.entries("b")] == [1, 2]
    assert all(e.tenant_id == "a" for e in ledger.entries("a"))
    assert ledger.entries("a", subject_id="f0")[0].tenant_id == "a"
    assert ledger.head("a") != ledger.head("b")
    assert ledger.get("b", 3) is None
    assert ledger.tenants() == ["a", "b"]
    assert ledger.verify_chain("a") == (True, None)
    assert ledger.verify_chain("b") == (True, None)


def test_filters_and_as_of(sf):
    ledger = Ledger(sf)
    es = _fill(ledger, 5)
    ledger.append("t1", EntryType.CASE_TRANSITION, "f1", {"to": "TRIAGE"},
                  recorded_at=T0 + timedelta(minutes=10))
    assert [e.seq for e in ledger.entries("t1", subject_id="f1")] == [2, 6]
    assert [e.seq for e in ledger.entries("t1", entry_type=EntryType.CASE_TRANSITION)] == [6]
    assert [e.seq for e in ledger.entries("t1", as_of=T0 + timedelta(minutes=2))] == [1, 2, 3]
    assert ledger.entries("t1", as_of=T0 - timedelta(seconds=1)) == []
    assert [e.seq for e in ledger.entries("t1", subject_id="f1", as_of=T0 + timedelta(minutes=5))] == [2]
    assert [e.seq for e in ledger.entries("t1", after_seq=4, limit=1)] == [5]
    assert ledger.latest("t1", as_of=T0 + timedelta(minutes=3, seconds=30)).seq == 4
    assert ledger.count("t1", as_of=T0 + timedelta(minutes=1)) == 2
    assert ledger.get("t1", 3) == es[2]
    subs = ledger.entries_for_subjects("t1", ["f1", "f3", "nope"], as_of=T0 + timedelta(minutes=5))
    assert [e.seq for e in subs] == [2, 4]
    with pytest.raises(ValueError):
        ledger.entries("t1", as_of=datetime(2026, 1, 1))


def test_correction_is_new_entry(sf):
    ledger = Ledger(sf)
    _fill(ledger, 3)
    original = ledger.get("t1", 2)
    c = ledger.correct("t1", 2, {"score": 0.05}, reason="mislabelled", actor="analyst:ana",
                       recorded_at=T0 + timedelta(hours=1))
    assert c.seq == 4 and c.entry_type == EntryType.CORRECTION
    assert c.subject_id == original.subject_id
    assert c.payload["corrects_seq"] == 2
    assert c.payload["corrects_entry_hash"] == original.entry_hash
    assert ledger.get("t1", 2) == original  # unchanged
    assert ledger.verify_chain("t1") == (True, None)
    with pytest.raises(LookupError):
        ledger.correct("t1", 99, {}, reason="x", actor="y")


def test_db_rejects_update_and_delete(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 2)
    with pytest.raises(DBAPIError):
        with engine.begin() as c:
            c.execute(text("UPDATE ledger_entries SET subject_id='x' WHERE seq=1"))
    with pytest.raises(DBAPIError):
        with engine.begin() as c:
            c.execute(text("DELETE FROM ledger_entries WHERE seq=2"))
    assert ledger.verify_chain("t1") == (True, None)


# ------------------------------------------------------------------ signatures

def test_signed_entries_verify_with_keyring(sf, signer, keyring):
    ledger = Ledger(sf, signer=signer)
    es = _fill(ledger, 4)
    assert all(e.signer_key_id == "ledger-k1" and e.signature for e in es)
    report = ledger.verify_report("t1", keyring)
    assert report.ok and report.signed_entries == 4 and report.entries_checked == 4
    assert report.head_hash == es[-1].entry_hash
    assert ledger.verify_chain("t1", keyring) == (True, None)


def test_unsigned_chain_fails_when_keyring_required(sf, keyring):
    ledger = Ledger(sf)
    _fill(ledger, 2)
    assert ledger.verify_chain("t1") == (True, None)
    assert ledger.verify_chain("t1", keyring) == (False, 1)
    assert ledger.verify_report("t1", keyring, require_signatures=False).ok
    with pytest.raises(ValueError):
        ledger.verify_report("t1", None, require_signatures=True)


def test_mixed_signed_unsigned(sf, signer, keyring):
    Ledger(sf).append("t1", "x", "a", {}, recorded_at=T0)
    Ledger(sf, signer=signer).append("t1", "x", "b", {}, recorded_at=T0)
    ledger = Ledger(sf)
    assert ledger.verify_chain("t1", keyring) == (False, 1)
    assert ledger.verify_report("t1", keyring, require_signatures=False).ok


def test_revoked_key_breaks_verification(sf, signer, keyring):
    ledger = Ledger(sf, signer=signer)
    _fill(ledger, 3)
    keyring.revoke(signer.key_id)
    ok, bad = ledger.verify_chain("t1", keyring)
    assert (ok, bad) == (False, 1)
    assert "revoked" in ledger.verify_report("t1", keyring).reason


def test_unknown_key_fails(sf, signer):
    ledger = Ledger(sf, signer=signer)
    _fill(ledger, 2)
    other = KeyRing()
    other.add_signer(Signer.generate("someone-else"))
    assert ledger.verify_chain("t1", other) == (False, 1)


def test_full_rewrite_without_key_is_caught_by_signatures(sf, engine, signer, keyring):
    """An attacker rewriting payload and recomputing every hash still lacks the key."""
    ledger = Ledger(sf, signer=signer)
    _fill(ledger, 3)
    rows = ledger.entries("t1")
    forged_payload = {"i": 1, "score": 0.0}
    from aegis.contracts.canonical import sha256_hex
    prev = rows[0].entry_hash
    attacker = Signer.generate("ledger-k1")  # same key id, different key
    updates = []
    for r in rows[1:]:
        payload = forged_payload if r.seq == 2 else r.payload
        psha = sha256_hex(payload)
        h = compute_entry_hash(seq=r.seq, tenant_id="t1", entry_type=r.entry_type,
                               subject_id=r.subject_id, payload_sha256=psha, prev_hash=prev,
                               recorded_at=r.recorded_at, signer_key_id=r.signer_key_id)
        updates.append((r.seq, payload, psha, prev, h, attacker.sign(h.encode())))
        prev = h
    import json
    for seq, payload, psha, p, h, sig in updates:
        _tamper(engine, "UPDATE ledger_entries SET payload=:pl, payload_sha256=:ps, prev_hash=:p, "
                        "entry_hash=:h, signature=:s WHERE tenant_id='t1' AND seq=:q",
                pl=json.dumps(payload), ps=psha, p=p, h=h, s=sig, q=seq)
    with engine.begin() as c:
        c.execute(text("UPDATE ledger_heads SET head_hash=:h WHERE tenant_id='t1'"), {"h": prev})
    assert ledger.verify_chain("t1") == (True, None)  # hash chain alone cannot tell
    assert ledger.verify_chain("t1", keyring) == (False, 2)


# ------------------------------------------------------------------ tamper detection

@pytest.mark.parametrize("column,value", [
    ("entry_type", "'action'"),
    ("subject_id", "'other-subject'"),
    ("payload_sha256", "'" + "a" * 64 + "'"),
    ("prev_hash", "'" + "b" * 64 + "'"),
    ("entry_hash", "'" + "c" * 64 + "'"),
    ("signer_key_id", "'evil'"),
    ("signature", "'AAAA'"),
])
def test_tamper_any_column_detected(sf, engine, signer, keyring, column, value):
    ledger = Ledger(sf, signer=signer)
    _fill(ledger, 5)
    _tamper(engine, f"UPDATE ledger_entries SET {column}={value} WHERE tenant_id='t1' AND seq=3")
    ok, bad = ledger.verify_chain("t1", keyring)
    assert not ok
    assert bad == 3


def test_tamper_payload_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 5)
    _tamper(engine, "UPDATE ledger_entries SET payload=:p WHERE tenant_id='t1' AND seq=4",
            p='{"i": 3, "score": 0.99}')
    assert ledger.verify_chain("t1") == (False, 4)
    assert "payload" in ledger.verify_report("t1").reason


def test_tamper_recorded_at_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 5)
    _tamper(engine, "UPDATE ledger_entries SET recorded_at=:t WHERE tenant_id='t1' AND seq=2",
            t="2026-10-01 08:01:30.000000"
            if engine.dialect.name == "sqlite" else T0 + timedelta(minutes=1, seconds=30))
    assert ledger.verify_chain("t1") == (False, 2)


def test_tamper_tenant_id_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 4)
    _tamper(engine, "UPDATE ledger_entries SET tenant_id='t2' WHERE tenant_id='t1' AND seq=2")
    assert ledger.verify_chain("t1") == (False, 2)


def test_tamper_seq_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 4)
    _tamper(engine, "UPDATE ledger_entries SET seq=10 WHERE tenant_id='t1' AND seq=4")
    ok, bad = ledger.verify_chain("t1")
    assert not ok and bad == 4


def test_middle_deletion_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 5)
    _tamper(engine, "DELETE FROM ledger_entries WHERE tenant_id='t1' AND seq=3")
    assert ledger.verify_chain("t1") == (False, 3)


def test_first_entry_deletion_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 3)
    _tamper(engine, "DELETE FROM ledger_entries WHERE tenant_id='t1' AND seq=1")
    assert ledger.verify_chain("t1") == (False, 1)


def test_tail_truncation_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 5)
    _tamper(engine, "DELETE FROM ledger_entries WHERE tenant_id='t1' AND seq>=4")
    assert ledger.verify_chain("t1") == (False, 4)
    assert "truncation" in ledger.verify_report("t1").reason


def test_full_deletion_detected_via_head(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 2)
    _tamper(engine, "DELETE FROM ledger_entries WHERE tenant_id='t1'")
    assert ledger.verify_chain("t1") == (False, 1)


def test_reordering_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 5)
    _tamper(engine, "UPDATE ledger_entries SET seq=-1 WHERE tenant_id='t1' AND seq=2")
    _tamper(engine, "UPDATE ledger_entries SET seq=2 WHERE tenant_id='t1' AND seq=3")
    _tamper(engine, "UPDATE ledger_entries SET seq=3 WHERE tenant_id='t1' AND seq=-1")
    ok, bad = ledger.verify_chain("t1")
    assert not ok and bad == 2


def test_missing_head_detected(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 2)
    with engine.begin() as c:
        c.execute(text("DELETE FROM ledger_heads WHERE tenant_id='t1'"))
    assert ledger.verify_chain("t1")[0] is False


def test_tamper_in_one_tenant_does_not_affect_other(sf, engine):
    ledger = Ledger(sf)
    _fill(ledger, 3, "a")
    _fill(ledger, 3, "b")
    _tamper(engine, "UPDATE ledger_entries SET subject_id='x' WHERE tenant_id='a' AND seq=2")
    assert ledger.verify_chain("a") == (False, 2)
    assert ledger.verify_chain("b") == (True, None)


def test_verify_in_small_batches(sf):
    ledger = Ledger(sf)
    _fill(ledger, 7)
    assert ledger.verify_report("t1", batch_size=2).entries_checked == 7


# ------------------------------------------------------------------ concurrency

def test_concurrent_appends_same_tenant(sf, signer, keyring):
    ledger = Ledger(sf, signer=signer)
    errors: list[BaseException] = []
    n_threads, per_thread = 8, 15

    def worker(k: int) -> None:
        try:
            own = Ledger(sf, signer=signer) if k % 2 else ledger  # separate instances share lock
            for i in range(per_thread):
                own.append("t1", "finding", f"w{k}-{i}", {"k": k, "i": i})
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(k,)) for k in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    es = ledger.entries("t1")
    assert [e.seq for e in es] == list(range(1, n_threads * per_thread + 1))
    assert len({e.subject_id for e in es}) == n_threads * per_thread
    assert ledger.verify_chain("t1", keyring) == (True, None)


def test_concurrent_appends_across_engines(tmp_path, engine):
    """Two engines on one database (as two processes would be) must not fork the chain."""
    if engine.dialect.name == "sqlite":
        url = str(engine.url)
    else:
        url = PG_URL
    e1, e2 = make_engine(url), make_engine(url)
    l1, l2 = Ledger(make_session_factory(e1)), Ledger(make_session_factory(e2))
    tenant = f"t-{uuid.uuid4().hex[:8]}"
    errors: list[BaseException] = []

    def worker(ledger: Ledger, tag: str) -> None:
        try:
            for i in range(25):
                ledger.append(tenant, "x", f"{tag}{i}", {"i": i})
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(lg, tag))
               for lg, tag in ((l1, "a"), (l2, "b"), (l1, "c"), (l2, "d"))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    e1.dispose()
    e2.dispose()
    assert not errors
    ledger = Ledger(make_session_factory(engine))
    assert ledger.count(tenant) == 100
    assert ledger.verify_chain(tenant) == (True, None)


def test_concurrent_appends_distinct_tenants(sf):
    ledger = Ledger(sf)

    def worker(t: str) -> None:
        for i in range(20):
            ledger.append(t, "x", f"s{i}", {"i": i})

    threads = [threading.Thread(target=worker, args=(f"t{k}",)) for k in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for k in range(4):
        assert ledger.count(f"t{k}") == 20
        assert ledger.verify_chain(f"t{k}") == (True, None)


# ------------------------------------------------------------------ external signed head anchor

def _rewind_head(engine, seq: int, head_hash: str) -> None:
    with engine.begin() as c:
        c.execute(text("UPDATE ledger_heads SET seq=:s, head_hash=:h WHERE tenant_id='t1'"),
                  {"s": seq, "h": head_hash})


def test_truncation_with_rewritten_head_is_caught_by_external_anchor(sf, engine, signer, tmp_path):
    """An attacker with database access deletes the tail AND rewinds ledger_heads: the
    in-database checks pass, the signed checkpoint outside the database does not."""
    from aegis.provenance.ledger import HeadAnchor

    anchor = HeadAnchor(tmp_path / "anchors" / "heads.jsonl", signer)
    ledger = Ledger(sf, signer=signer, anchor=anchor)
    entries = _fill(ledger, 5)
    ring = KeyRing()
    ring.add_signer(signer)
    assert ledger.verify_report("t1", ring).ok
    _tamper(engine, "DELETE FROM ledger_entries WHERE tenant_id='t1' AND seq>=4")
    _rewind_head(engine, 3, entries[2].entry_hash)
    assert Ledger(sf, signer=signer).verify_report("t1", ring).ok  # the database alone is fooled
    report = ledger.verify_report("t1", ring)
    assert not report.ok and report.first_bad_seq == 4
    assert "external signed head anchor" in report.reason


def test_anchor_ignores_forged_lines_and_detects_divergence(sf, engine, signer, tmp_path):
    from aegis.provenance.ledger import HeadAnchor

    path = tmp_path / "heads.jsonl"
    anchor = HeadAnchor(path, signer)
    ledger = Ledger(sf, signer=signer, anchor=anchor)
    _fill(ledger, 3)
    ring = KeyRing()
    ring.add_signer(signer)
    # garbage and an unsigned "head" claiming seq 99 are ignored
    with open(path, "a") as fh:
        fh.write("not json\n")
        fh.write('{"v":1,"tenant_id":"t1","seq":99,"head_hash":"00","recorded_at":"x",'
                 '"signer_key_id":"ledger-k1","signature":"AAAA"}\n')
    assert anchor.latest("t1", ring)["seq"] == 3
    assert ledger.verify_report("t1", ring).ok
    # an attacker-signed checkpoint (unknown key) does not verify either
    rogue = Signer.generate("rogue")
    HeadAnchor(path, rogue).record(ledger.latest("t1").model_copy(update={"seq": 50}))
    assert anchor.latest("t1", ring)["seq"] == 3


def test_anchor_is_per_tenant(sf, signer, tmp_path):
    from aegis.provenance.ledger import HeadAnchor

    anchor = HeadAnchor(tmp_path / "heads.jsonl", signer)
    ledger = Ledger(sf, signer=signer, anchor=anchor)
    _fill(ledger, 2, tenant="t1")
    _fill(ledger, 4, tenant="t2")
    ring = KeyRing()
    ring.add_signer(signer)
    assert anchor.latest("t1", ring)["seq"] == 2
    assert anchor.latest("t2", ring)["seq"] == 4
    assert anchor.latest("t3", ring) is None
    assert ledger.verify_report("t1", ring).ok and ledger.verify_report("t2", ring).ok
