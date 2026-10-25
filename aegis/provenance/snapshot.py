"""Content-hashed ledger snapshots and contemporaneous replay (spec sections 5, 11, 15).

A snapshot identifies the exact state of a tenant's ledger at ``as_of``. Because
``recorded_at`` is non-decreasing along a chain, the entries visible at ``as_of``
are a prefix of the chain and the head hash of that prefix commits to all of them.
The snapshot hash is SHA-256 over the canonical ``{tenant_id, as_of, entry_count,
head_seq, head_hash}``; the snapshot id is derived from it, so identical state always
yields the identical, immutable id.

Replay reconstructs what an investigator could see when a decision was made: the
evidence, model versions, rule bundle versions and decisions linked to a subject
that were recorded at or before ``as_of``. Anything recorded later (new evidence,
corrections, decisions) is excluded, and evidence a visible decision referenced but
that had not yet been recorded is reported as ``non_contemporaneous_evidence_ids``
rather than silently included.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import LedgerEntry
from aegis.provenance.ledger import GENESIS_HASH, EntryType, Ledger, to_utc

SNAPSHOT_VERSION = 1

_LINK_SINGLE = ("evidence_id", "finding_id", "case_id", "action_id")
_LINK_LIST = ("evidence_ids", "counterevidence_ids", "finding_ids")
_MODEL_SINGLE = ("model_version", "detector_version")
_MODEL_LIST = ("model_versions",)
_RULE_SINGLE = ("rule_bundle_version",)
_RULE_LIST = ("rule_bundle_versions",)
_EVIDENCE_SINGLE = ("evidence_id",)
_EVIDENCE_LIST = ("evidence_ids", "counterevidence_ids")

DECISION_TYPES = frozenset({
    EntryType.FINDING, EntryType.CASE_TRANSITION, EntryType.ACTION,
    EntryType.AUTHORIZATION, EntryType.EXECUTION,
})

_MAX_REPLAY_ROUNDS = 32


def _strings(payload: dict[str, Any], single: tuple[str, ...], many: tuple[str, ...]) -> set[str]:
    out: set[str] = set()
    for key in single:
        v = payload.get(key)
        if isinstance(v, str) and v:
            out.add(v)
    for key in many:
        v = payload.get(key)
        if isinstance(v, list):
            out.update(x for x in v if isinstance(x, str) and x)
    return out


def _snapshot_body(tenant_id: str, as_of: datetime, head: LedgerEntry | None) -> dict[str, Any]:
    return {
        "v": SNAPSHOT_VERSION,
        "tenant_id": tenant_id,
        "as_of": to_utc(as_of).isoformat(),
        "entry_count": head.seq if head else 0,
        "head_seq": head.seq if head else 0,
        "head_hash": head.entry_hash if head else GENESIS_HASH,
    }


def snapshot(tenant_id: str, ledger: Ledger, as_of: datetime) -> dict[str, Any]:
    """Content-hashed description of the tenant's ledger state at ``as_of``."""
    as_of = to_utc(as_of)
    body = _snapshot_body(tenant_id, as_of, ledger.latest(tenant_id, as_of=as_of))
    digest = sha256_hex(body)
    return {
        "snapshot_id": f"snap_{digest[:32]}",
        "snapshot_hash": digest,
        "tenant_id": tenant_id,
        "as_of": as_of,
        "entry_count": body["entry_count"],
        "head_seq": body["head_seq"],
        "head_hash": body["head_hash"],
    }


def verify_snapshot(tenant_id: str, ledger: Ledger, snap: dict[str, Any]) -> bool:
    """True if ``snap`` still matches the ledger (detects rewritten history)."""
    try:
        as_of = snap["as_of"]
        if isinstance(as_of, str):
            as_of = datetime.fromisoformat(as_of)
        fresh = snapshot(tenant_id, ledger, as_of)
    except (KeyError, TypeError, ValueError):
        return False
    return (fresh["snapshot_hash"] == snap.get("snapshot_hash")
            and fresh["snapshot_id"] == snap.get("snapshot_id")
            and fresh["head_hash"] == snap.get("head_hash")
            and fresh["entry_count"] == snap.get("entry_count"))


def record_snapshot(tenant_id: str, ledger: Ledger, as_of: datetime | None = None, *,
                    reason: str = "scheduled", subject_id: str | None = None) -> dict[str, Any]:
    """Compute a snapshot and anchor it in the ledger as a ``snapshot`` entry.

    Used daily and on major case transitions (pass the case id as ``subject_id``).
    Without ``as_of`` the snapshot covers the chain up to its current head.
    """
    if as_of is None:
        head = ledger.latest(tenant_id)
        as_of = head.recorded_at if head is not None else None
    if as_of is None:
        raise ValueError("cannot snapshot an empty ledger without as_of")
    snap = snapshot(tenant_id, ledger, as_of)
    ledger.append(tenant_id, EntryType.SNAPSHOT, subject_id or snap["snapshot_id"], {
        "snapshot_id": snap["snapshot_id"],
        "snapshot_hash": snap["snapshot_hash"],
        "as_of": snap["as_of"],
        "entry_count": snap["entry_count"],
        "head_hash": snap["head_hash"],
        "reason": reason,
    })
    return snap


def _entry_view(e: LedgerEntry) -> dict[str, Any]:
    return {
        "seq": e.seq, "entry_type": e.entry_type, "subject_id": e.subject_id,
        "recorded_at": e.recorded_at, "entry_hash": e.entry_hash, "payload": e.payload,
    }


def replay(tenant_id: str, ledger: Ledger, subject_id: str, as_of: datetime) -> dict[str, Any]:
    """Reconstruct what was known about ``subject_id`` at ``as_of``.

    Starting from the subject, entries recorded at or before ``as_of`` are collected
    and linked ids in their payloads (findings, evidence, cases, actions) are
    followed transitively. Returns::

        {
          "tenant_id", "subject_id", "as_of", "snapshot": {...},
          "evidence_ids": [...],                 # recorded by as_of, referenced or the subject
          "superseded_evidence_ids": {old: new}, # corrections recorded by as_of
          "non_contemporaneous_evidence_ids": [...],  # referenced but not recorded by as_of
          "model_versions": [...], "rule_bundle_versions": [...],
          "decisions": [{seq, entry_type, subject_id, recorded_at, entry_hash, payload}],
          "entries": [...same shape, every linked entry...],
        }
    """
    as_of = to_utc(as_of)
    frontier = {subject_id}
    visited: set[str] = set()
    by_seq: dict[int, LedgerEntry] = {}
    referenced_evidence: set[str] = set()

    for _ in range(_MAX_REPLAY_ROUNDS):
        frontier -= visited
        if not frontier:
            break
        visited |= frontier
        found = ledger.entries_for_subjects(tenant_id, frontier, as_of=as_of)
        nxt: set[str] = set()
        for e in found:
            by_seq[e.seq] = e
            if e.entry_type == EntryType.SNAPSHOT:
                continue
            nxt |= _strings(e.payload, _LINK_SINGLE, _LINK_LIST)
            referenced_evidence |= _strings(e.payload, _EVIDENCE_SINGLE, _EVIDENCE_LIST)
            if e.entry_type == EntryType.CORRECTION:
                sup = e.payload.get("superseded_by")
                if isinstance(sup, str):
                    nxt.add(sup)
        frontier = nxt

    linked = [by_seq[k] for k in sorted(by_seq)]
    recorded_evidence = {e.subject_id for e in linked if e.entry_type == EntryType.EVIDENCE}
    superseded: dict[str, str] = {}
    model_versions: set[str] = set()
    rule_versions: set[str] = set()
    for e in linked:
        model_versions |= _strings(e.payload, _MODEL_SINGLE, _MODEL_LIST)
        rule_versions |= _strings(e.payload, _RULE_SINGLE, _RULE_LIST)
        if e.entry_type == EntryType.MODEL:
            model_versions |= _strings(e.payload, ("version",), ())
        if e.entry_type == EntryType.RULE_BUNDLE:
            rule_versions |= _strings(e.payload, ("version",), ())
        if e.entry_type == EntryType.CORRECTION:
            sup = e.payload.get("superseded_by")
            if isinstance(sup, str) and sup in recorded_evidence:
                superseded[e.subject_id] = sup

    return {
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "as_of": as_of,
        "snapshot": snapshot(tenant_id, ledger, as_of),
        "evidence_ids": sorted(recorded_evidence),
        "superseded_evidence_ids": dict(sorted(superseded.items())),
        "non_contemporaneous_evidence_ids": sorted(referenced_evidence - recorded_evidence),
        "model_versions": sorted(model_versions),
        "rule_bundle_versions": sorted(rule_versions),
        "decisions": [_entry_view(e) for e in linked if e.entry_type in DECISION_TYPES],
        "entries": [_entry_view(e) for e in linked],
    }
