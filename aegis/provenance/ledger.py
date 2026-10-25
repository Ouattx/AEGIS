"""Append-only, hash-chained, optionally signed provenance ledger (spec section 11).

Each tenant has an independent chain. Entry ``n`` commits to entry ``n-1`` through
``prev_hash``; the genesis ``prev_hash`` is ``"0" * 64``. ``entry_hash`` is SHA-256
over the RFC 8785 canonical JSON of every stored field except ``payload`` (covered
through ``payload_sha256``), ``entry_hash`` itself and ``signature``. When the ledger
has a :class:`~aegis.provenance.signing.Signer`, ``signature`` is an Ed25519
signature over the ASCII ``entry_hash``.

Integrity layers:

* the hash chain detects modification of any field, reordering and deletion;
* sequence numbers must be contiguous from 1, so a removed middle entry is a gap;
* ``ledger_heads`` records the latest (seq, hash) per tenant, so truncating the
  tail of the chain is detected;
* signatures (verified with a :class:`~aegis.provenance.signing.KeyRing`) stop an
  attacker with database access from rewriting the whole chain consistently;
* database triggers reject ``UPDATE`` and ``DELETE`` on ``ledger_entries`` on
  SQLite and PostgreSQL, so the application cannot mutate history by accident.

Corrections are new entries (:meth:`Ledger.correct`), never updates.

Concurrency: appends are serialized per tenant. In-process callers share a lock per
(database, tenant); across processes, PostgreSQL takes a transaction-scoped advisory
lock per tenant, and on every backend the unique ``(tenant_id, seq)`` constraint plus
a compare-and-swap on ``ledger_heads`` turns any remaining race into a retry rather
than a fork of the chain.

Timestamps: ``recorded_at`` is timezone-aware UTC and non-decreasing along a chain,
so ``as_of`` queries always select a prefix of the chain. A caller-supplied
``recorded_at`` earlier than the chain head is rejected (back-dating would let a
record appear to have been visible at an earlier decision time). When the caller
omits it, the current time is used, clamped to the head's time to absorb clock skew.

Payload conventions used by :mod:`aegis.provenance.snapshot` replay (other modules
should use these keys so decisions can be reconstructed):

* ``evidence_id`` / ``evidence_ids`` / ``counterevidence_ids``: evidence relied on
* ``finding_id`` / ``finding_ids``, ``case_id``, ``action_id``: related subjects
* ``model_version`` / ``model_versions`` / ``detector_version``: model identities
* ``rule_bundle_version`` / ``rule_bundle_versions``: IOC / rule bundle versions
"""
from __future__ import annotations

import json
import random
import threading
import time
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import (
    DDL,
    JSON,
    BigInteger,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    select,
    text,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.contracts.models import LedgerEntry
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import Base

GENESIS_HASH = "0" * 64
LEDGER_HASH_VERSION = 1


class EntryType:
    """Well-known ``entry_type`` values. Modules may add their own strings."""

    EVIDENCE = "evidence"
    FINDING = "finding"
    CASE_TRANSITION = "case_transition"
    ACTION = "action"
    AUTHORIZATION = "authorization"
    EXECUTION = "execution"
    MODEL = "model"
    RULE_BUNDLE = "rule_bundle"
    POLICY = "policy"
    CORRECTION = "correction"
    SNAPSHOT = "snapshot"


class LedgerError(RuntimeError):
    """Base class for ledger failures."""


class LedgerConflictError(LedgerError):
    """Raised when an append could not win the per-tenant race after many retries."""


class LedgerEntryRow(Base):
    __tablename__ = "ledger_entries"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    entry_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signer_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("tenant_id", "seq", name="uq_ledger_tenant_seq"),
        Index("ix_ledger_tenant_subject", "tenant_id", "subject_id"),
        Index("ix_ledger_tenant_type", "tenant_id", "entry_type"),
        Index("ix_ledger_tenant_recorded", "tenant_id", "recorded_at"),
    )


class LedgerHeadRow(Base):
    """Latest chain position per tenant (used for CAS appends and truncation checks)."""

    __tablename__ = "ledger_heads"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


# --------------------------------------------------------------- append-only triggers

_SQLITE_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS ledger_entries_no_update BEFORE UPDATE ON ledger_entries "
    "BEGIN SELECT RAISE(ABORT, 'ledger_entries is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS ledger_entries_no_delete BEFORE DELETE ON ledger_entries "
    "BEGIN SELECT RAISE(ABORT, 'ledger_entries is append-only'); END",
)

_PG_TRIGGERS = (
    "CREATE OR REPLACE FUNCTION aegis_ledger_append_only() RETURNS trigger AS $$ "
    "BEGIN RAISE EXCEPTION 'ledger_entries is append-only'; END; $$ LANGUAGE plpgsql",
    "DROP TRIGGER IF EXISTS ledger_entries_append_only ON ledger_entries",
    "CREATE TRIGGER ledger_entries_append_only BEFORE UPDATE OR DELETE ON ledger_entries "
    "FOR EACH ROW EXECUTE FUNCTION aegis_ledger_append_only()",
)

for _stmt in _SQLITE_TRIGGERS:
    event.listen(LedgerEntryRow.__table__, "after_create", DDL(_stmt).execute_if(dialect="sqlite"))
for _stmt in _PG_TRIGGERS:
    event.listen(LedgerEntryRow.__table__, "after_create",
                 DDL(_stmt).execute_if(dialect="postgresql"))


# --------------------------------------------------------------- helpers

def to_utc(dt: datetime) -> datetime:
    """Normalize an aware datetime to UTC; reject naive datetimes."""
    if not isinstance(dt, datetime):
        raise TypeError("expected a datetime")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _from_db(dt: datetime) -> datetime:
    """SQLite drops tzinfo; values are always stored as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_db(dt: datetime) -> datetime:
    return to_utc(dt)


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Convert to plain JSON exactly as it will round-trip through storage."""
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dict")
    try:
        return json.loads(canonical_bytes(payload))
    except Exception as exc:  # rfc8785 rejects NaN/inf and unsupported types
        raise ValueError(f"payload is not canonical-JSON serializable: {exc}") from exc


def compute_entry_hash(*, seq: int, tenant_id: str, entry_type: str, subject_id: str,
                       payload_sha256: str, prev_hash: str, recorded_at: datetime,
                       signer_key_id: str | None) -> str:
    return sha256_hex({
        "v": LEDGER_HASH_VERSION,
        "seq": seq,
        "tenant_id": tenant_id,
        "entry_type": entry_type,
        "subject_id": subject_id,
        "payload_sha256": payload_sha256,
        "prev_hash": prev_hash,
        "recorded_at": to_utc(recorded_at).isoformat(),
        "signer_key_id": signer_key_id,
    })


def _row_to_entry(row: LedgerEntryRow) -> LedgerEntry:
    return LedgerEntry(
        seq=row.seq, tenant_id=row.tenant_id, entry_type=row.entry_type,
        subject_id=row.subject_id, payload_sha256=row.payload_sha256,
        payload=row.payload, prev_hash=row.prev_hash, entry_hash=row.entry_hash,
        recorded_at=_from_db(row.recorded_at), signer_key_id=row.signer_key_id,
        signature=row.signature,
    )


def _check_str(name: str, value: str, max_len: int) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")


@dataclass(frozen=True)
class ChainReport:
    """Detailed result of :meth:`Ledger.verify_report`."""

    ok: bool
    first_bad_seq: int | None
    reason: str | None
    entries_checked: int
    head_hash: str
    signed_entries: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "first_bad_seq": self.first_bad_seq, "reason": self.reason,
            "entries_checked": self.entries_checked, "head_hash": self.head_hash,
            "signed_entries": self.signed_entries,
        }


# per (engine, tenant) in-process append locks
_LOCKS: "weakref.WeakKeyDictionary[Engine, dict[str, threading.Lock]]" = weakref.WeakKeyDictionary()
_LOCKS_GUARD = threading.Lock()

_PG_LOCK_CLASS = 0x4145  # advisory lock namespace ("AE")
_MAX_ATTEMPTS = 60


class Ledger:
    """Tenant-scoped append-only ledger. All reads require a ``tenant_id``."""

    def __init__(self, session_factory: sessionmaker[Session], signer: Signer | None = None):
        self._sf = session_factory
        self._signer = signer

    @property
    def signer(self) -> Signer | None:
        return self._signer

    # ---------------------------------------------------------------- writes

    def _tenant_lock(self, tenant_id: str) -> threading.Lock:
        bind = self._sf.kw.get("bind")
        key: Any = bind if bind is not None else self._sf
        with _LOCKS_GUARD:
            try:
                per_engine = _LOCKS.setdefault(key, {})
            except TypeError:  # unhashable / non-weakrefable bind: fall back to self
                per_engine = _LOCKS.setdefault(self._sf, {})  # type: ignore[arg-type]
            lock = per_engine.get(tenant_id)
            if lock is None:
                lock = per_engine[tenant_id] = threading.Lock()
            return lock

    def append(self, tenant_id: str, entry_type: str, subject_id: str,
               payload: dict[str, Any], recorded_at: datetime | None = None) -> LedgerEntry:
        """Append an entry to ``tenant_id``'s chain and return it."""
        _check_str("tenant_id", tenant_id, 64)
        _check_str("entry_type", entry_type, 64)
        _check_str("subject_id", subject_id, 128)
        body = normalize_payload(payload)
        payload_sha = sha256_hex(body)
        explicit_ts = to_utc(recorded_at) if recorded_at is not None else None

        last_exc: Exception | None = None
        with self._tenant_lock(tenant_id):
            for attempt in range(_MAX_ATTEMPTS):
                try:
                    return self._append_once(tenant_id, entry_type, subject_id, body,
                                             payload_sha, explicit_ts)
                except _Retry as exc:
                    last_exc = exc
                except IntegrityError as exc:
                    last_exc = exc
                except OperationalError as exc:
                    if not _is_transient(exc):
                        raise
                    last_exc = exc
                time.sleep(min(0.25, 0.002 * (2 ** min(attempt, 7))) * (0.5 + random.random()))
        raise LedgerConflictError(
            f"could not append to ledger for tenant {tenant_id!r} after {_MAX_ATTEMPTS} attempts"
        ) from last_exc

    def _append_once(self, tenant_id: str, entry_type: str, subject_id: str,
                     body: dict[str, Any], payload_sha: str,
                     explicit_ts: datetime | None) -> LedgerEntry:
        with self._sf.begin() as s:
            if s.get_bind().dialect.name == "postgresql":
                s.execute(text("SELECT pg_advisory_xact_lock(:c, hashtext(:t))"),
                          {"c": _PG_LOCK_CLASS, "t": tenant_id})
            head = s.get(LedgerHeadRow, tenant_id, populate_existing=True)
            if head is None:
                prev_seq, prev_hash, prev_ts = 0, GENESIS_HASH, None
            else:
                prev_seq, prev_hash, prev_ts = head.seq, head.head_hash, _from_db(head.recorded_at)

            if explicit_ts is not None:
                if prev_ts is not None and explicit_ts < prev_ts:
                    raise ValueError(
                        f"recorded_at {explicit_ts.isoformat()} is earlier than the chain head "
                        f"({prev_ts.isoformat()}); the ledger cannot be back-dated"
                    )
                ts = explicit_ts
            else:
                ts = datetime.now(timezone.utc)
                if prev_ts is not None and ts < prev_ts:
                    ts = prev_ts

            seq = prev_seq + 1
            key_id = self._signer.key_id if self._signer else None
            entry_hash = compute_entry_hash(
                seq=seq, tenant_id=tenant_id, entry_type=entry_type, subject_id=subject_id,
                payload_sha256=payload_sha, prev_hash=prev_hash, recorded_at=ts,
                signer_key_id=key_id,
            )
            signature = self._signer.sign(entry_hash.encode("ascii")) if self._signer else None

            if head is None:
                s.add(LedgerHeadRow(tenant_id=tenant_id, seq=seq, head_hash=entry_hash,
                                    recorded_at=_to_db(ts)))
                s.flush()  # raises IntegrityError if another writer created the head
            else:
                res = s.execute(
                    update(LedgerHeadRow)
                    .where(LedgerHeadRow.tenant_id == tenant_id, LedgerHeadRow.seq == prev_seq,
                           LedgerHeadRow.head_hash == prev_hash)
                    .values(seq=seq, head_hash=entry_hash, recorded_at=_to_db(ts))
                    .execution_options(synchronize_session=False)
                )
                if res.rowcount != 1:
                    raise _Retry("ledger head moved")
            row = LedgerEntryRow(
                tenant_id=tenant_id, seq=seq, entry_type=entry_type, subject_id=subject_id,
                payload_sha256=payload_sha, payload=body, prev_hash=prev_hash,
                entry_hash=entry_hash, recorded_at=_to_db(ts), signer_key_id=key_id,
                signature=signature,
            )
            s.add(row)
            s.flush()
            return LedgerEntry(
                seq=seq, tenant_id=tenant_id, entry_type=entry_type, subject_id=subject_id,
                payload_sha256=payload_sha, payload=body, prev_hash=prev_hash,
                entry_hash=entry_hash, recorded_at=ts, signer_key_id=key_id, signature=signature,
            )

    def correct(self, tenant_id: str, corrected_seq: int, correction: dict[str, Any],
                reason: str, actor: str, recorded_at: datetime | None = None) -> LedgerEntry:
        """Record a correction of an earlier entry as a new ``correction`` entry.

        The original entry is never modified. The correction shares the original's
        ``subject_id`` and references it by seq and hash.
        """
        _check_str("reason", reason, 4000)
        _check_str("actor", actor, 256)
        original = self.get(tenant_id, corrected_seq)
        if original is None:
            raise LookupError(f"no ledger entry seq={corrected_seq} for tenant {tenant_id!r}")
        return self.append(tenant_id, EntryType.CORRECTION, original.subject_id, {
            "corrects_seq": original.seq,
            "corrects_entry_hash": original.entry_hash,
            "corrects_entry_type": original.entry_type,
            "reason": reason,
            "actor": actor,
            "correction": correction,
        }, recorded_at=recorded_at)

    # ---------------------------------------------------------------- reads

    def entries(self, tenant_id: str, *, subject_id: str | None = None,
                entry_type: str | None = None, as_of: datetime | None = None,
                after_seq: int | None = None, limit: int | None = None) -> list[LedgerEntry]:
        """Entries of one tenant in chain order, optionally filtered.

        ``as_of`` returns only entries recorded at or before that instant.
        """
        _check_str("tenant_id", tenant_id, 64)
        q = select(LedgerEntryRow).where(LedgerEntryRow.tenant_id == tenant_id)
        if subject_id is not None:
            q = q.where(LedgerEntryRow.subject_id == subject_id)
        if entry_type is not None:
            q = q.where(LedgerEntryRow.entry_type == entry_type)
        if as_of is not None:
            q = q.where(LedgerEntryRow.recorded_at <= _to_db(as_of))
        if after_seq is not None:
            q = q.where(LedgerEntryRow.seq > after_seq)
        q = q.order_by(LedgerEntryRow.seq)
        if limit is not None:
            q = q.limit(limit)
        with self._sf() as s:
            return [_row_to_entry(r) for r in s.scalars(q)]

    def entries_for_subjects(self, tenant_id: str, subject_ids: Iterable[str], *,
                             as_of: datetime | None = None) -> list[LedgerEntry]:
        """Entries whose ``subject_id`` is in ``subject_ids``, in chain order."""
        _check_str("tenant_id", tenant_id, 64)
        ids = sorted({i for i in subject_ids if i})
        out: list[LedgerEntry] = []
        with self._sf() as s:
            for i in range(0, len(ids), 500):
                q = select(LedgerEntryRow).where(LedgerEntryRow.tenant_id == tenant_id,
                                                 LedgerEntryRow.subject_id.in_(ids[i:i + 500]))
                if as_of is not None:
                    q = q.where(LedgerEntryRow.recorded_at <= _to_db(as_of))
                out.extend(_row_to_entry(r) for r in s.scalars(q))
        out.sort(key=lambda e: e.seq)
        return out

    def get(self, tenant_id: str, seq: int) -> LedgerEntry | None:
        _check_str("tenant_id", tenant_id, 64)
        with self._sf() as s:
            row = s.scalars(select(LedgerEntryRow).where(
                LedgerEntryRow.tenant_id == tenant_id, LedgerEntryRow.seq == seq)).first()
            return _row_to_entry(row) if row is not None else None

    def latest(self, tenant_id: str, *, as_of: datetime | None = None) -> LedgerEntry | None:
        _check_str("tenant_id", tenant_id, 64)
        q = select(LedgerEntryRow).where(LedgerEntryRow.tenant_id == tenant_id)
        if as_of is not None:
            q = q.where(LedgerEntryRow.recorded_at <= _to_db(as_of))
        with self._sf() as s:
            row = s.scalars(q.order_by(LedgerEntryRow.seq.desc()).limit(1)).first()
            return _row_to_entry(row) if row is not None else None

    def head(self, tenant_id: str) -> str:
        """Latest ``entry_hash`` of the tenant's chain (``"0"*64`` when empty)."""
        entry = self.latest(tenant_id)
        return entry.entry_hash if entry is not None else GENESIS_HASH

    def count(self, tenant_id: str, *, as_of: datetime | None = None) -> int:
        entry = self.latest(tenant_id, as_of=as_of)
        return entry.seq if entry is not None else 0

    def tenants(self) -> list[str]:
        """Tenant ids that have a chain (administrative use, e.g. scheduled verification)."""
        with self._sf() as s:
            return sorted(s.scalars(select(LedgerHeadRow.tenant_id)))

    # ---------------------------------------------------------------- verification

    def verify_chain(self, tenant_id: str, keyring: KeyRing | None = None) -> tuple[bool, int | None]:
        """Verify the tenant's chain. Returns ``(ok, first_bad_seq)``.

        With a ``keyring`` every entry must carry a valid signature from a trusted,
        non-revoked key; unsigned entries then fail verification.
        """
        report = self.verify_report(tenant_id, keyring)
        return report.ok, report.first_bad_seq

    def verify_report(self, tenant_id: str, keyring: KeyRing | None = None, *,
                      require_signatures: bool | None = None,
                      batch_size: int = 2000) -> ChainReport:
        """Like :meth:`verify_chain` but with the failure reason and counts."""
        _check_str("tenant_id", tenant_id, 64)
        need_sig = keyring is not None if require_signatures is None else require_signatures
        if need_sig and keyring is None:
            raise ValueError("require_signatures=True needs a keyring")
        prev_hash = GENESIS_HASH
        prev_ts: datetime | None = None
        expected_seq = 1
        checked = 0
        signed = 0

        def fail(seq: int, reason: str) -> ChainReport:
            return ChainReport(False, seq, reason, checked, prev_hash, signed)

        with self._sf() as s:
            last_seq = 0
            while True:
                rows: Sequence[LedgerEntryRow] = s.scalars(
                    select(LedgerEntryRow)
                    .where(LedgerEntryRow.tenant_id == tenant_id, LedgerEntryRow.seq > last_seq)
                    .order_by(LedgerEntryRow.seq).limit(batch_size)
                ).all()
                if not rows:
                    break
                for row in rows:
                    if row.seq != expected_seq:
                        return fail(min(row.seq, expected_seq), "sequence gap or reordering")
                    if row.prev_hash != prev_hash:
                        return fail(row.seq, "prev_hash does not link to previous entry")
                    try:
                        payload_ok = sha256_hex(row.payload) == row.payload_sha256
                    except Exception:
                        payload_ok = False
                    if not payload_ok:
                        return fail(row.seq, "payload does not match payload_sha256")
                    ts = _from_db(row.recorded_at)
                    if prev_ts is not None and ts < prev_ts:
                        return fail(row.seq, "recorded_at moves backwards")
                    recomputed = compute_entry_hash(
                        seq=row.seq, tenant_id=row.tenant_id, entry_type=row.entry_type,
                        subject_id=row.subject_id, payload_sha256=row.payload_sha256,
                        prev_hash=row.prev_hash, recorded_at=ts, signer_key_id=row.signer_key_id,
                    )
                    if recomputed != row.entry_hash:
                        return fail(row.seq, "entry_hash mismatch")
                    has_sig = bool(row.signature) or bool(row.signer_key_id)
                    if has_sig:
                        signed += 1
                    if keyring is not None and has_sig:
                        if not keyring.verify(row.signer_key_id, row.entry_hash.encode("ascii"),
                                              row.signature):
                            return fail(row.seq, "invalid, unknown or revoked signature")
                    elif need_sig:
                        return fail(row.seq, "entry is unsigned")
                    prev_hash = row.entry_hash
                    prev_ts = ts
                    expected_seq += 1
                    checked += 1
                    last_seq = row.seq
            head = s.get(LedgerHeadRow, tenant_id)
        if head is None:
            if checked:
                return fail(checked, "ledger head record missing")
            return ChainReport(True, None, None, 0, GENESIS_HASH, 0)
        if head.seq != checked or head.head_hash != prev_hash:
            # entries after the last verified one were removed (tail truncation),
            # or the head record itself was tampered with
            return fail(checked + 1 if head.seq > checked else max(head.seq, 1),
                        "chain does not reach the recorded head (truncation or head tampering)")
        return ChainReport(True, None, None, checked, prev_hash, signed)


class _Retry(Exception):
    pass


def _is_transient(exc: OperationalError) -> bool:
    msg = str(exc.orig if exc.orig is not None else exc).lower()
    return any(t in msg for t in ("database is locked", "deadlock", "could not serialize",
                                  "busy", "lock timeout"))
