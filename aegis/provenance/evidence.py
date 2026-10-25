"""Immutable, content-hashed evidence store (spec sections 3.2 and 11).

Evidence is written once. ``append`` fills ``sha256`` (SHA-256 over the canonical
evidence with ``sha256`` blanked), records an ``evidence`` ledger entry and then
stores the document. Re-appending an existing ``evidence_id`` is refused; a
correction is a new evidence record linked to the one it supersedes through
:meth:`EvidenceStore.correct`, which also writes a ``correction`` ledger entry.

Source independence: corroboration is counted in independent *origins*, not in
records. Feeds syndicating the same upstream report share a
``source_independence_group`` and count once (:func:`independent_origins`).
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import Evidence
from aegis.provenance.ledger import EntryType, Ledger, to_utc
from aegis.storage.db import DocStore


class EvidenceError(RuntimeError):
    """Base class for evidence store failures."""


class EvidenceExistsError(EvidenceError):
    """Raised when appending an ``evidence_id`` that is already stored (evidence is immutable)."""


class EvidenceIntegrityError(EvidenceError):
    """Raised when stored evidence no longer matches its recorded hash."""


def evidence_hash(ev: Evidence) -> str:
    """Content hash of ``ev`` with ``sha256`` excluded."""
    body = ev.model_dump(mode="json")
    body.pop("sha256", None)
    return sha256_hex(body)


def origin_key(ev: Evidence) -> str:
    """Normalized independence key: the group, or the origin source if the group is blank."""
    group = (ev.source_independence_group or "").strip()
    if not group:
        group = (ev.origin_source or "").strip()
    return group.casefold()


def independent_origins(evidences: Iterable[Evidence], *, supporting_only: bool = False) -> int:
    """Number of distinct independent origins among ``evidences``.

    Records sharing a ``source_independence_group`` (case-insensitive, whitespace
    trimmed) are one origin, so N feeds syndicating one report count as 1. With
    ``supporting_only`` counter-evidence (``supports=False``) is ignored.
    """
    keys = {origin_key(ev) for ev in evidences if not supporting_only or ev.supports}
    keys.discard("")
    return len(keys)


class EvidenceStore:
    """Tenant-scoped evidence persistence backed by ``DocStore`` and the ledger."""

    def __init__(self, docstore: DocStore, ledger: Ledger):
        self._docs = docstore
        self._ledger = ledger

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def append(self, ev: Evidence, *, recorded_at: datetime | None = None,
               corrects: str | None = None) -> Evidence:
        """Store new evidence and return it with ``sha256`` filled.

        If ``ev.sha256`` is already set it must equal the computed content hash
        (end-to-end integrity from the producer); otherwise ``EvidenceIntegrityError``.
        """
        to_utc(ev.collected_at)  # reject naive timestamps early
        if self._docs.get(Evidence, ev.tenant_id, ev.evidence_id) is not None:
            raise EvidenceExistsError(
                f"evidence {ev.evidence_id!r} already exists; record a correction instead")
        digest = evidence_hash(ev)
        if ev.sha256 and ev.sha256 != digest:
            raise EvidenceIntegrityError(
                f"evidence {ev.evidence_id!r} sha256 does not match its content")
        stored = ev.model_copy(update={"sha256": digest}, deep=True)
        payload: dict[str, object] = {
            "evidence_id": stored.evidence_id,
            "sha256": digest,
            "kind": stored.kind.value,
            "origin_source": stored.origin_source,
            "source_independence_group": stored.source_independence_group,
            "collected_at": stored.collected_at,
            "authorization_id": stored.authorization_id,
            "supports": stored.supports,
            "artifact_ref": stored.artifact_ref,
            "license": stored.license,
        }
        if corrects is not None:
            payload["corrects"] = corrects
        # ledger first: evidence must never be visible without its provenance record
        self._ledger.append(stored.tenant_id, EntryType.EVIDENCE, stored.evidence_id, payload,
                            recorded_at=recorded_at)
        self._docs.put(stored)
        return stored

    def correct(self, tenant_id: str, original_id: str, replacement: Evidence, *,
                reason: str, actor: str, recorded_at: datetime | None = None) -> Evidence:
        """Supersede ``original_id`` with ``replacement`` (a new evidence record).

        The original stays stored and hash-verifiable; replay at an earlier time
        still sees it.
        """
        if replacement.tenant_id != tenant_id:
            raise ValueError("replacement evidence belongs to a different tenant")
        if replacement.evidence_id == original_id:
            raise ValueError("a correction must have a new evidence_id")
        original = self.get(tenant_id, original_id)
        if original is None:
            raise LookupError(f"evidence {original_id!r} not found for tenant {tenant_id!r}")
        stored = self.append(replacement, recorded_at=recorded_at, corrects=original_id)
        self._ledger.append(tenant_id, EntryType.CORRECTION, original_id, {
            "evidence_id": original_id,
            "superseded_by": stored.evidence_id,
            "superseded_by_sha256": stored.sha256,
            "reason": reason,
            "actor": actor,
        }, recorded_at=recorded_at)
        return stored

    def get(self, tenant_id: str, evidence_id: str) -> Evidence | None:
        """Fetch evidence; raises ``EvidenceIntegrityError`` if its content was altered."""
        ev = self._docs.get(Evidence, tenant_id, evidence_id)
        if ev is None:
            return None
        if evidence_hash(ev) != ev.sha256:
            raise EvidenceIntegrityError(f"evidence {evidence_id!r} content hash mismatch")
        return ev

    def list_for(self, tenant_id: str, ids: Iterable[str]) -> list[Evidence]:
        """Evidence for ``ids`` in the given order (duplicates and unknown ids skipped)."""
        seen: set[str] = set()
        out: list[Evidence] = []
        for evidence_id in ids:
            if evidence_id in seen:
                continue
            seen.add(evidence_id)
            ev = self.get(tenant_id, evidence_id)
            if ev is not None:
                out.append(ev)
        return out

    def missing(self, tenant_id: str, ids: Iterable[str]) -> list[str]:
        """Ids among ``ids`` with no stored evidence for this tenant."""
        return [i for i in dict.fromkeys(ids) if self._docs.get(Evidence, tenant_id, i) is None]

    def verify(self, tenant_id: str, evidence_id: str) -> bool:
        """True if the stored content hash matches both the document and the ledger record."""
        ev = self._docs.get(Evidence, tenant_id, evidence_id)
        if ev is None or evidence_hash(ev) != ev.sha256:
            return False
        recorded = [e for e in self._ledger.entries(tenant_id, subject_id=evidence_id,
                                                    entry_type=EntryType.EVIDENCE)]
        return len(recorded) == 1 and recorded[0].payload.get("sha256") == ev.sha256

    def superseded_by(self, tenant_id: str, evidence_id: str, *,
                      as_of: datetime | None = None) -> str | None:
        """Id of the evidence that corrected ``evidence_id`` (as known at ``as_of``)."""
        corrections = self._ledger.entries(tenant_id, subject_id=evidence_id,
                                           entry_type=EntryType.CORRECTION, as_of=as_of)
        for entry in reversed(corrections):
            nxt = entry.payload.get("superseded_by")
            if isinstance(nxt, str):
                return nxt
        return None

    def current(self, tenant_id: str, evidence_id: str, *,
                as_of: datetime | None = None) -> Evidence | None:
        """Follow the correction chain to the latest version (as known at ``as_of``)."""
        seen = {evidence_id}
        cur = evidence_id
        while True:
            nxt = self.superseded_by(tenant_id, cur, as_of=as_of)
            if nxt is None or nxt in seen:
                break
            seen.add(nxt)
            cur = nxt
        return self.get(tenant_id, cur)

    @staticmethod
    def independent_origins(evidences: Iterable[Evidence], *, supporting_only: bool = False) -> int:
        return independent_origins(evidences, supporting_only=supporting_only)
