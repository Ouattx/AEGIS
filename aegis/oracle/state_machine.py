"""ORACLE case state machine with deterministic guards (spec section 6).

States and transitions follow the spec diagram exactly::

    NEW -> TRIAGE -> INVESTIGATING -> {VERIFIED, REJECTED, INCONCLUSIVE}
        -> {PROPOSED, CLOSED} -> {APPROVED, DENIED} -> {EXECUTED, ROLLED_BACK, EXPIRED}

with these fail-closed refinements of the set-to-set arrows:

* ``PROPOSED`` is only reachable from ``VERIFIED`` (an action is never proposed
  for a rejected or inconclusive case);
* ``DENIED`` is terminal; ``APPROVED -> {EXECUTED, EXPIRED}``;
  ``EXECUTED -> {ROLLED_BACK, EXPIRED}`` (a rollback needs a prior execution).

Guards (all deterministic; no model output is consulted):

* ``VERIFIED``: qualifying supporting evidence from >= 2 independent origins OR a
  verified signed IOC hit, plus a recorded counter-hypothesis review. When any
  independent origin contradicts the hypothesis the case is *contested*: a signed
  IOC hit alone no longer suffices, supporting origins must outnumber
  contradicting ones, and only a human may verify (contradictory feeds downgrade).
* ``PROPOSED``: an authorization assessment for a stored action of this case.
  The case is then bound to that action: approval, denial and execution apply
  to it only.
* ``APPROVED``: a human approver and an assessment that allowed the action the
  case was proposed for.
* ``EXECUTED``: an operator policy whose signature verifies against the trusted
  keyring (active mode, legal signoff, valid now, action type allowed), an
  allowed authorization bound to that policy, a MIRROR result of ``SAFE`` and a
  recorded human approval *of this very action* (an approval never carries over
  to a sibling action of the same case).
* ``ROLLED_BACK`` / ``EXPIRED`` from ``EXECUTED``: no enforcement for the case may
  still be live (checked through the optional ``live_execution_probe``).

Agents (actors ``agent:*``) can never change case state. Every transition, and
case creation, is written to the provenance ledger before the case document is
updated; major transitions also anchor ledger (and CONSTELLATION, if attached) snapshots.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal

from pydantic import BaseModel, ConfigDict

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import (
    AuthorizationDecision,
    Case,
    CaseDecision,
    CaseState,
    Evidence,
    EvidenceKind,
    Finding,
    FindingStatus,
    MirrorResult,
    MirrorVerdict,
    OperatorPolicy,
    ProposedAction,
    Verdict,
)
from aegis.provenance.evidence import EvidenceIntegrityError, EvidenceStore, origin_key
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing, verify_model
from aegis.provenance.snapshot import record_snapshot
from aegis.storage.db import DocStore

S = CaseState

ALLOWED_TRANSITIONS: dict[CaseState, frozenset[CaseState]] = {
    S.NEW: frozenset({S.TRIAGE}),
    S.TRIAGE: frozenset({S.INVESTIGATING}),
    S.INVESTIGATING: frozenset({S.VERIFIED, S.REJECTED, S.INCONCLUSIVE}),
    S.VERIFIED: frozenset({S.PROPOSED, S.CLOSED}),
    S.REJECTED: frozenset({S.CLOSED}),
    S.INCONCLUSIVE: frozenset({S.CLOSED}),
    S.PROPOSED: frozenset({S.APPROVED, S.DENIED}),
    S.CLOSED: frozenset(),
    S.APPROVED: frozenset({S.EXECUTED, S.EXPIRED}),
    S.DENIED: frozenset(),
    S.EXECUTED: frozenset({S.ROLLED_BACK, S.EXPIRED}),
    S.ROLLED_BACK: frozenset(),
    S.EXPIRED: frozenset(),
}

TERMINAL_STATES = frozenset(s for s, nxt in ALLOWED_TRANSITIONS.items() if not nxt)

#: Transitions that anchor a content-hashed snapshot (spec section 5).
MAJOR_TRANSITIONS = frozenset({S.VERIFIED, S.PROPOSED, S.APPROVED, S.EXECUTED, S.ROLLED_BACK})

#: Evidence kinds that may support verification. Graph links (possibly
#: candidate/co-hosting), analyst notes and agent counterarguments never qualify.
QUALIFYING_KINDS = frozenset({
    EvidenceKind.OBSERVATION, EvidenceKind.IOC_MATCH, EvidenceKind.MODEL_SCORE,
    EvidenceKind.ANOMALY, EvidenceKind.CHANGE_POINT, EvidenceKind.THREAT_FEED,
})

#: Evidence kinds whose ``supports=False`` records count as independent contradiction.
CONTRADICTING_KINDS = frozenset({
    EvidenceKind.OBSERVATION, EvidenceKind.IOC_MATCH, EvidenceKind.THREAT_FEED,
    EvidenceKind.BENIGN_BASELINE,
})

#: Payload flag a detector sets on IOC_MATCH evidence when the indicator came from a
#: bundle whose signature verified against the trusted keyring and was fresh.
SIGNED_IOC_FLAG = "signed_bundle_verified"
#: Payload key set by ORACLE on evidence appended by an agent.
AGENT_APPENDED_KEY = "appended_by"

CASE_OPENED = "case_opened"
CASE_FINDING_ATTACHED = "case_finding_attached"
FINDING_STATUS_ENTRY = "finding_status"

#: States of a case that a new finding on the same device joins instead of opening a
#: new case (one incident, one case). Decided (REJECTED / INCONCLUSIVE) and terminal
#: cases do not absorb new findings: a fresh case is opened.
ATTACHABLE_STATES = frozenset({S.NEW, S.TRIAGE, S.INVESTIGATING, S.VERIFIED, S.PROPOSED, S.APPROVED,
                               S.EXECUTED})
CASE_REVIEW = "case_counter_hypothesis_review"
CASE_EVIDENCE = "case_evidence_attached"


class GuardError(PermissionError):
    """A transition was refused. ``failed`` lists the machine-readable reasons."""

    def __init__(self, message: str, failed: Iterable[str] = ()):
        super().__init__(message)
        self.failed: list[str] = list(failed)


class EntityCaseIndex(BaseModel):
    """Latest case opened for a device (``doc_id = <tenant>:<entity>``): de-duplication index."""
    model_config = ConfigDict(extra="forbid")

    doc_id: str
    tenant_id: str
    entity_pseudonym: str
    case_id: str


def finding_status_for(case: Case) -> FindingStatus | None:
    """Finding status implied by the case: ``None`` keeps the findings' current status."""
    reached = {d.to_state for d in case.decisions} | {case.state}
    if reached & {S.VERIFIED, S.PROPOSED, S.APPROVED, S.DENIED, S.EXECUTED, S.ROLLED_BACK}:
        return FindingStatus.VERIFIED
    if S.REJECTED in reached:
        return FindingStatus.REJECTED
    if case.state is S.CLOSED:
        return None
    if reached & {S.TRIAGE, S.INVESTIGATING, S.INCONCLUSIVE}:
        return FindingStatus.TRIAGE
    return None


def is_agent(actor: str) -> bool:
    return actor.strip().lower().startswith("agent:")


def is_human(actor: str) -> bool:
    a = actor.strip().lower()
    return bool(a) and not a.startswith("agent:") and not a.startswith("system")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- evidence assessment


class EvidenceAssessment:
    """Deterministic summary of a case's evidence used by the VERIFIED guard."""

    def __init__(self, evidences: list[Evidence], integrity: dict[str, bool], now: datetime):
        self.evidences = evidences
        self.integrity = integrity
        self.qualifying: list[Evidence] = []
        self.contradicting: list[Evidence] = []
        self.signed_ioc_hits: list[Evidence] = []
        self.rejected: dict[str, str] = {}
        for ev in evidences:
            if not integrity.get(ev.evidence_id, False):
                self.rejected[ev.evidence_id] = "integrity_check_failed"
                continue
            if ev.payload.get("investigative_only") is True:
                self.rejected[ev.evidence_id] = "investigative_only"
                continue
            if ev.supports and ev.kind in QUALIFYING_KINDS:
                if _is_stale(ev, now):
                    self.rejected[ev.evidence_id] = "stale_indicator"
                    continue
                self.qualifying.append(ev)
                if is_signed_ioc_hit(ev):
                    self.signed_ioc_hits.append(ev)
            elif not ev.supports and ev.kind in CONTRADICTING_KINDS:
                self.contradicting.append(ev)
        self.supporting_origins = sorted({origin_key(e) for e in self.qualifying} - {""})
        self.contradicting_origins = sorted({origin_key(e) for e in self.contradicting} - {""})

    @property
    def contested(self) -> bool:
        return bool(self.contradicting_origins)

    def verification_blockers(self) -> list[str]:
        """Reasons the evidence alone cannot support VERIFIED (empty = sufficient)."""
        out: list[str] = []
        n_sup = len(self.supporting_origins)
        if self.contested:
            if n_sup < 2:
                out.append("contested_requires_two_independent_supporting_origins")
            if n_sup <= len(self.contradicting_origins):
                out.append("contradicting_origins_not_outweighed")
        elif n_sup < 2 and not self.signed_ioc_hits:
            out.append("needs_two_independent_origins_or_signed_ioc_hit")
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "qualifying_evidence_ids": [e.evidence_id for e in self.qualifying],
            "contradicting_evidence_ids": [e.evidence_id for e in self.contradicting],
            "signed_ioc_hit_ids": [e.evidence_id for e in self.signed_ioc_hits],
            "supporting_origins": self.supporting_origins,
            "contradicting_origins": self.contradicting_origins,
            "rejected": dict(sorted(self.rejected.items())),
        }


def is_signed_ioc_hit(ev: Evidence) -> bool:
    """True for a verified, uncontradicted IOC contact from a signed bundle.

    Accepted forms: SENTINEL ``ioc_match`` evidence (payload ``bundle`` with
    ``signer_key_id`` and ``sha256`` — bundles only load after signature
    verification — and ``verified_contact`` true), or any producer setting
    ``SIGNED_IOC_FLAG``. A contradicted match or agent-appended evidence never counts.
    """
    if ev.kind is not EvidenceKind.IOC_MATCH or not ev.supports:
        return False
    p = ev.payload
    if AGENT_APPENDED_KEY in p or p.get("contradicted") is True:
        return False
    if p.get(SIGNED_IOC_FLAG) is True:
        return True
    bundle = p.get("bundle")
    return (isinstance(bundle, dict) and isinstance(bundle.get("signer_key_id"), str)
            and bool(bundle.get("signer_key_id")) and isinstance(bundle.get("sha256"), str)
            and bool(bundle.get("sha256")) and p.get("verified_contact") is True)


def _is_stale(ev: Evidence, now: datetime) -> bool:
    exp = ev.payload.get("indicator_expires_at") or ev.payload.get("expires_at")
    if not isinstance(exp, str):
        return False
    try:
        return _aware(datetime.fromisoformat(exp.replace("Z", "+00:00"))) <= now
    except ValueError:
        return True  # unparseable expiry: fail closed


# ----------------------------------------------------------------------------- service


class CaseService:
    """Case lifecycle with spec section 6 guards. All operations are tenant-scoped.

    ``keyring`` holds the trusted operator-policy signing keys; without it, the
    ``EXECUTED`` guard always fails closed. ``constellation`` (optional) gets a graph
    snapshot on major transitions.
    """

    def __init__(self, docstore: DocStore, evidence_store: EvidenceStore, ledger: Ledger, *,
                 keyring: KeyRing | None = None, constellation: Any | None = None,
                 clock: Callable[[], datetime] | None = None,
                 live_execution_probe: Callable[[str, str], list[str]] | None = None):
        self._docs = docstore
        #: ``(tenant_id, case_id) -> live action ids``; leaving EXECUTED is refused while
        #: any enforcement for the case is still in place
        self._live_probe = live_execution_probe
        self._evidence = evidence_store
        self._ledger = ledger
        self._keyring = keyring
        self._constellation = constellation
        self._clock = clock or _now
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._indexed_tenants: set[str] = set()

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def evidence_store(self) -> EvidenceStore:
        return self._evidence

    def _lock(self, tenant_id: str, case_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault((tenant_id, case_id), threading.Lock())

    # ------------------------------------------------------------------ queries

    def get(self, tenant_id: str, case_id: str) -> Case | None:
        return self._docs.get(Case, tenant_id, case_id)

    def require(self, tenant_id: str, case_id: str) -> Case:
        case = self.get(tenant_id, case_id)
        if case is None:
            raise LookupError(f"case {case_id!r} not found for tenant {tenant_id!r}")
        return case

    def list_cases(self, tenant_id: str, *, state: CaseState | None = None) -> list[Case]:
        cases = self._docs.list(Case, tenant_id)
        return [c for c in cases if state is None or c.state is state]

    def history(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        """Ledger view of the case: creation, transitions, reviews, snapshots."""
        return [{"seq": e.seq, "entry_type": e.entry_type, "recorded_at": e.recorded_at,
                 "entry_hash": e.entry_hash, "payload": e.payload}
                for e in self._ledger.entries(tenant_id, subject_id=case_id)]

    def assess_evidence(self, case: Case) -> EvidenceAssessment:
        evs: list[Evidence] = []
        integrity: dict[str, bool] = {}
        for eid in dict.fromkeys(case.evidence_ids):
            try:
                ev = self._evidence.get(case.tenant_id, eid)
            except EvidenceIntegrityError:
                ev = self._docs.get(Evidence, case.tenant_id, eid)  # tampered: kept, never qualifies
                if ev is not None:
                    evs.append(ev)
                    integrity[eid] = False
                continue
            if ev is None:
                continue
            evs.append(ev)
            integrity[eid] = self._evidence.verify(case.tenant_id, eid)
        return EvidenceAssessment(evs, integrity, self._clock())

    # ------------------------------------------------------------------ creation

    @staticmethod
    def case_id_for(tenant_id: str, finding_id: str) -> str:
        """Deterministic case id: re-opening the same finding returns the same case."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"aegis:case:{tenant_id}:{finding_id}"))

    def open_case(self, finding: Finding, *, actor: str = "system") -> Case:
        """Open (idempotently) a case for a finding that requires review.

        One incident, one case: while the device already has a case in an
        :data:`ATTACHABLE_STATES` state, the finding and its evidence are appended to
        that case (ledger ``case_finding_attached``) instead of opening another one.
        """
        if is_agent(actor):
            raise GuardError("agents cannot open cases", ["agent_actor"])
        if finding.verdict is Verdict.BENIGN:
            raise ValueError("benign findings do not open cases")
        tenant = finding.tenant_id
        with self._lock(tenant, "entity:" + finding.entity_pseudonym):
            open_case = self._open_case_for_entity(tenant, finding.entity_pseudonym)
            if open_case is not None:
                if finding.finding_id in open_case.finding_ids:
                    return open_case
                return self._attach_finding(open_case, finding, actor)
            case = self._new_case(finding, actor)
            self._docs.put(EntityCaseIndex(doc_id=f"{tenant}:{finding.entity_pseudonym}", tenant_id=tenant,
                                           entity_pseudonym=finding.entity_pseudonym, case_id=case.case_id))
            return case

    def case_for_finding(self, tenant_id: str, finding_id: str) -> Case | None:
        """The case a finding belongs to (the case it opened, or the one it was attached to)."""
        own = self.get(tenant_id, self.case_id_for(tenant_id, finding_id))
        if own is not None and finding_id in own.finding_ids:
            return own
        f = self._docs.get(Finding, tenant_id, finding_id)
        if f is not None:
            idx = self._docs.get(EntityCaseIndex, tenant_id, f"{tenant_id}:{f.entity_pseudonym}")
            if idx is not None:
                c = self.get(tenant_id, idx.case_id)
                if c is not None and finding_id in c.finding_ids:
                    return c
        for c in self._docs.iter_all(Case, tenant_id):
            if finding_id in c.finding_ids:
                return c
        return None

    def _open_case_for_entity(self, tenant_id: str, entity: str) -> Case | None:
        self._ensure_entity_index(tenant_id)
        idx = self._docs.get(EntityCaseIndex, tenant_id, f"{tenant_id}:{entity}")
        if idx is None:
            return None
        case = self.get(tenant_id, idx.case_id)
        return case if case is not None and case.state in ATTACHABLE_STATES else None

    def _ensure_entity_index(self, tenant_id: str) -> None:
        """Index cases stored before de-duplication existed (one pass per tenant and process)."""
        if tenant_id in self._indexed_tenants:
            return
        with self._locks_guard:
            if tenant_id in self._indexed_tenants:
                return
            latest: dict[str, Case] = {}
            for c in self._docs.iter_all(Case, tenant_id):
                if c.state not in ATTACHABLE_STATES:
                    continue
                for fid in c.finding_ids:
                    f = self._docs.get(Finding, tenant_id, fid)
                    if f is None:
                        continue
                    prev = latest.get(f.entity_pseudonym)
                    if prev is None or _aware(c.created_at) > _aware(prev.created_at):
                        latest[f.entity_pseudonym] = c
            for entity, c in latest.items():
                if self._docs.get(EntityCaseIndex, tenant_id, f"{tenant_id}:{entity}") is None:
                    self._docs.put(EntityCaseIndex(doc_id=f"{tenant_id}:{entity}", tenant_id=tenant_id,
                                                   entity_pseudonym=entity, case_id=c.case_id))
            self._indexed_tenants.add(tenant_id)

    def _attach_finding(self, case: Case, finding: Finding, actor: str) -> Case:
        with self._lock(case.tenant_id, case.case_id):
            case = self.require(case.tenant_id, case.case_id)
            if finding.finding_id in case.finding_ids:
                return case
            new_ev = [i for i in dict.fromkeys(finding.evidence_ids + finding.counterevidence_ids)
                      if i not in case.evidence_ids]
            severity = max(case.severity, _severity(finding), key=lambda s: _SEVERITY_ORDER[s])
            self._ledger.append(case.tenant_id, CASE_FINDING_ATTACHED, case.case_id, {
                "event": CASE_FINDING_ATTACHED, "case_id": case.case_id, "finding_id": finding.finding_id,
                "label": finding.label, "verdict": finding.verdict.value, "evidence_ids": new_ev,
                "model_version": finding.detector_version, "severity": severity, "actor": actor})
            case = case.model_copy(update={
                "finding_ids": case.finding_ids + [finding.finding_id],
                "evidence_ids": case.evidence_ids + new_ev,
                "model_versions": list(dict.fromkeys(case.model_versions + [finding.detector_version])),
                "severity": severity, "updated_at": self._clock()}, deep=True)
            self._docs.put(case)
            self._sync_finding_status(case, actor)
            return case

    def _new_case(self, finding: Finding, actor: str) -> Case:
        case_id = self.case_id_for(finding.tenant_id, finding.finding_id)
        with self._lock(finding.tenant_id, case_id):
            existing = self.get(finding.tenant_id, case_id)
            if existing is not None:
                return existing
            now = self._clock()
            evidence_ids = list(dict.fromkeys(finding.evidence_ids + finding.counterevidence_ids))
            case = Case(
                case_id=case_id, tenant_id=finding.tenant_id,
                title=f"{finding.label} on {finding.device_class} device {finding.entity_pseudonym}",
                hypothesis=(f"Device {finding.entity_pseudonym} ({finding.device_class}) exhibits "
                            f"{finding.label.replace('_', ' ')} "
                            f"(detector {finding.detector_version}, verdict {finding.verdict.value}, "
                            f"score {finding.score:.2f}"
                            f"{', calibrated' if finding.calibration_id else ', uncalibrated'})."),
                finding_ids=[finding.finding_id], evidence_ids=evidence_ids,
                severity=_severity(finding), model_versions=[finding.detector_version],
                created_at=now, updated_at=now)
            self._ledger.append(case.tenant_id, EntryType.CASE_TRANSITION, case_id, {
                "event": CASE_OPENED, "case_id": case_id, "from_state": None,
                "to_state": CaseState.NEW.value, "actor": actor,
                "reason": f"opened from finding {finding.finding_id}",
                "finding_ids": case.finding_ids, "evidence_ids": evidence_ids,
                "model_versions": case.model_versions, "severity": case.severity,
            })
            self._docs.put(case)
            return case

    # ------------------------------------------------------------------ append-only updates

    def attach_evidence(self, tenant_id: str, case_id: str, evidence_ids: Iterable[str], *,
                        actor: str) -> Case:
        """Append evidence ids (which must exist for this tenant) to the case."""
        ids = [i for i in dict.fromkeys(evidence_ids) if i]
        missing = self._evidence.missing(tenant_id, ids)
        if missing:
            raise LookupError(f"unknown evidence for tenant {tenant_id!r}: {missing}")
        with self._lock(tenant_id, case_id):
            case = self.require(tenant_id, case_id)
            new = [i for i in ids if i not in case.evidence_ids]
            if not new:
                return case
            self._ledger.append(tenant_id, CASE_EVIDENCE, case_id, {
                "case_id": case_id, "evidence_ids": new, "actor": actor})
            case = case.model_copy(update={"evidence_ids": case.evidence_ids + new,
                                           "updated_at": self._clock()}, deep=True)
            self._docs.put(case)
            return case

    def record_counter_hypothesis_review(self, tenant_id: str, case_id: str, *, reviewer: str,
                                         alternatives: list[str], notes: str) -> Case:
        """Record that alternative explanations were considered (VERIFIED prerequisite).

        A review needs at least one written alternative and notes, and cannot be
        recorded by an agent: agents append counterarguments, people (or the
        deterministic system orchestrator) sign off on them.
        """
        if is_agent(reviewer) or not reviewer.strip():
            raise GuardError("counter-hypothesis review must be recorded by a human or the system",
                             ["review_actor_not_allowed"])
        alts = [a.strip()[:500] for a in alternatives if isinstance(a, str) and a.strip()]
        if not alts:
            raise GuardError("a counter-hypothesis review needs at least one alternative",
                             ["no_alternatives"])
        if not notes or not notes.strip():
            raise GuardError("a counter-hypothesis review needs notes", ["no_review_notes"])
        with self._lock(tenant_id, case_id):
            case = self.require(tenant_id, case_id)
            if case.state in TERMINAL_STATES:
                raise GuardError(f"case is {case.state.value}", ["terminal_state"])
            merged = list(dict.fromkeys(case.alternative_hypotheses + alts))
            self._ledger.append(tenant_id, CASE_REVIEW, case_id, {
                "case_id": case_id, "reviewer": reviewer, "alternatives": alts,
                "notes": notes.strip()[:4000]})
            case = case.model_copy(update={
                "alternative_hypotheses": merged, "counter_hypothesis_reviewed": True,
                "reviewer": reviewer, "updated_at": self._clock()}, deep=True)
            self._docs.put(case)
            return case

    # ------------------------------------------------------------------ transitions

    def check_transition(self, tenant_id: str, case_id: str, to_state: CaseState, actor: str, *,
                         authorization: AuthorizationDecision | None = None,
                         mirror: MirrorResult | None = None,
                         policy: OperatorPolicy | None = None) -> list[str]:
        """Dry-run the guards; returns the failed checks (empty list = allowed)."""
        case = self.require(tenant_id, case_id)
        failed, _ = self._evaluate(case, CaseState(to_state), actor, authorization, mirror, policy)
        return failed

    def transition(self, tenant_id: str, case_id: str, to_state: CaseState, actor: str,
                   reason: str, *, authorization: AuthorizationDecision | None = None,
                   mirror: MirrorResult | None = None,
                   policy: OperatorPolicy | None = None) -> Case:
        """Move a case to ``to_state`` or raise :class:`GuardError`.

        ``authorization`` is the MIRROR/authorize() assessment (PROPOSED, APPROVED,
        EXECUTED); ``mirror`` the simulation result and ``policy`` the signed
        operator policy (EXECUTED).
        """
        to_state = CaseState(to_state)
        if not isinstance(reason, str) or not reason.strip():
            raise GuardError("a transition requires a reason", ["missing_reason"])
        if not isinstance(actor, str) or not actor.strip():
            raise GuardError("a transition requires an actor", ["missing_actor"])
        with self._lock(tenant_id, case_id):
            case = self.require(tenant_id, case_id)
            failed, context = self._evaluate(case, to_state, actor, authorization, mirror, policy)
            if failed:
                self._ledger.append(tenant_id, "case_transition_refused", case_id, {
                    "case_id": case_id, "from_state": case.state.value,
                    "to_state": to_state.value, "actor": actor, "reason": reason.strip()[:2000],
                    "failed_checks": failed})
                raise GuardError(
                    f"transition {case.state.value} -> {to_state.value} refused: "
                    + ", ".join(failed), failed)
            now = self._clock()
            payload = {
                "event": "transition", "case_id": case_id, "from_state": case.state.value,
                "to_state": to_state.value, "actor": actor, "reason": reason.strip()[:2000],
                "finding_ids": case.finding_ids, "evidence_ids": case.evidence_ids,
                "model_versions": case.model_versions, "guards": context,
            }
            action_id: str | None = None
            authz_sha: str | None = None
            if authorization is not None:
                # top-level link so a replay of the case follows the action, its authorization
                # assessments and its executions (snapshot.replay follows *_id keys); the
                # signed entry also binds an approval to exactly this action
                action_id = authorization.action_id
                authz_sha = sha256_hex(authorization)
                payload["action_id"] = action_id
                payload["authorization_sha256"] = authz_sha
            entry = self._ledger.append(tenant_id, EntryType.CASE_TRANSITION, case_id, payload)
            decision = CaseDecision(from_state=case.state, to_state=to_state, actor=actor,
                                    reason=reason.strip()[:2000], at=now,
                                    ledger_entry_hash=entry.entry_hash, action_id=action_id,
                                    authorization_sha256=authz_sha)
            update: dict[str, Any] = {"state": to_state, "updated_at": now,
                                      "decisions": case.decisions + [decision]}
            if to_state in MAJOR_TRANSITIONS:
                snap = record_snapshot(tenant_id, self._ledger, reason=f"case_transition:{to_state.value}",
                                       subject_id=case_id)
                update["snapshot_hash"] = snap["snapshot_hash"]
                if self._constellation is not None:
                    self._constellation.record_snapshot(tenant_id, reason=f"case_transition:{to_state.value}",
                                                subject_id=case_id)
            case = case.model_copy(update=update, deep=True)
            self._docs.put(case)
            self._sync_finding_status(case, actor)
            return case

    def _sync_finding_status(self, case: Case, actor: str) -> None:
        """Mirror the case outcome onto its findings' ``status`` (ledgered once per change)."""
        status = finding_status_for(case)
        if status is None:
            return
        changed: list[str] = []
        for fid in case.finding_ids:
            f = self._docs.get(Finding, case.tenant_id, fid)
            if f is None or f.status is status:
                continue
            self._docs.put(f.model_copy(update={"status": status}))
            changed.append(fid)
        if changed:
            self._ledger.append(case.tenant_id, FINDING_STATUS_ENTRY, case.case_id, {
                "case_id": case.case_id, "case_state": case.state.value, "finding_ids": changed,
                "status": status.value, "actor": actor})

    def rebind_proposal(self, tenant_id: str, case_id: str, actor: str, reason: str, *,
                        authorization: AuthorizationDecision) -> Case:
        """Re-point a PROPOSED (not yet approved) case at another of its actions.

        Recorded as a ``PROPOSED -> PROPOSED`` decision carrying the new action id, so
        any later approval, denial or execution applies to that action only. Once a
        case is APPROVED its action can no longer change.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise GuardError("a rebinding requires a reason", ["missing_reason"])
        with self._lock(tenant_id, case_id):
            case = self.require(tenant_id, case_id)
            failed: list[str] = []
            ctx: dict[str, Any] = {}
            if is_agent(actor) or not actor.strip():
                failed.append("agent_cannot_change_case_state")
            if case.state is not S.PROPOSED:
                failed.append(f"rebind_requires_proposed_state:{case.state.value}")
            failed += self._check_assessment(case, authorization, ctx, self._clock())
            if failed:
                self._ledger.append(tenant_id, "case_transition_refused", case_id, {
                    "case_id": case_id, "from_state": case.state.value, "to_state": S.PROPOSED.value,
                    "actor": actor, "reason": reason.strip()[:2000], "failed_checks": failed,
                    "action_id": authorization.action_id})
                raise GuardError("proposal rebinding refused: " + ", ".join(failed), failed)
            now = self._clock()
            authz_sha = sha256_hex(authorization)
            entry = self._ledger.append(tenant_id, EntryType.CASE_TRANSITION, case_id, {
                "event": "proposal_rebound", "case_id": case_id, "from_state": S.PROPOSED.value,
                "to_state": S.PROPOSED.value, "actor": actor, "reason": reason.strip()[:2000],
                "previous_action_id": self.bound_action_id(case), "action_id": authorization.action_id,
                "authorization_sha256": authz_sha, "guards": ctx})
            decision = CaseDecision(from_state=S.PROPOSED, to_state=S.PROPOSED, actor=actor,
                                    reason=reason.strip()[:2000], at=now, ledger_entry_hash=entry.entry_hash,
                                    action_id=authorization.action_id, authorization_sha256=authz_sha)
            case = case.model_copy(update={"decisions": case.decisions + [decision], "updated_at": now},
                                   deep=True)
            self._docs.put(case)
            return case

    # ------------------------------------------------------------------ guards

    def _evaluate(self, case: Case, to: CaseState, actor: str,
                  authorization: AuthorizationDecision | None, mirror: MirrorResult | None,
                  policy: OperatorPolicy | None) -> tuple[list[str], dict[str, Any]]:
        failed: list[str] = []
        ctx: dict[str, Any] = {}
        if is_agent(actor):
            return ["agent_cannot_change_case_state"], ctx
        if to not in ALLOWED_TRANSITIONS[case.state]:
            return [f"transition_not_allowed:{case.state.value}->{to.value}"], ctx
        now = self._clock()

        if to is S.VERIFIED:
            assessment = self.assess_evidence(case)
            ctx["evidence"] = assessment.as_dict()
            failed += assessment.verification_blockers()
            if not case.counter_hypothesis_reviewed:
                failed.append("counter_hypothesis_review_missing")
            if assessment.contested and not is_human(actor):
                failed.append("contested_case_requires_human_verifier")

        elif to is S.PROPOSED:
            failed += self._check_assessment(case, authorization, ctx, now)

        elif to in (S.APPROVED, S.DENIED):
            if to is S.APPROVED and not is_human(actor):
                failed.append("approval_requires_human_approver")
            if to is S.APPROVED or authorization is not None:
                failed += self._check_assessment(case, authorization, ctx, now)
                failed += self._check_bound_action(case, authorization)
            if to is S.APPROVED and authorization is not None and not authorization.allowed:
                failed.append("authorization_not_allowed")

        elif to is S.EXECUTED:
            failed += self._check_execution(case, authorization, mirror, policy, ctx, now)

        elif case.state is S.EXECUTED and to in (S.ROLLED_BACK, S.EXPIRED):
            live = self._live_actions(case)
            if live is None and self._live_probe is not None:
                failed.append("live_execution_state_unknown")
            elif live:
                ctx["live_actions"] = live
                failed.append("enforcement_still_live")

        return failed, ctx

    def _live_actions(self, case: Case) -> list[str] | None:
        if self._live_probe is None:
            return None
        try:
            return list(self._live_probe(case.tenant_id, case.case_id))
        except Exception:  # an unanswerable probe fails closed
            return None

    @staticmethod
    def bound_action_id(case: Case) -> str | None:
        """The action the case was last proposed for (``None`` before PROPOSED)."""
        for d in reversed(case.decisions):
            if d.to_state is S.PROPOSED:
                return d.action_id
        return None

    @staticmethod
    def approved_action_id(case: Case) -> str | None:
        """The action of the latest human approval recorded on the case."""
        for d in reversed(case.decisions):
            if d.to_state is S.APPROVED and is_human(d.actor):
                return d.action_id
        return None

    def _check_bound_action(self, case: Case, authorization: AuthorizationDecision | None) -> list[str]:
        if authorization is None:
            return []
        bound = self.bound_action_id(case)
        if bound is None:
            return ["proposed_action_unknown"]
        if bound != authorization.action_id:
            return ["action_is_not_the_proposed_action"]
        return []

    def _check_assessment(self, case: Case, authorization: AuthorizationDecision | None,
                          ctx: dict[str, Any], now: datetime) -> list[str]:
        if authorization is None:
            return ["authorization_assessment_missing"]
        failed: list[str] = []
        action = self._docs.get(ProposedAction, case.tenant_id, authorization.action_id)
        if action is None:
            failed.append("proposed_action_not_found")
        elif action.case_id != case.case_id:
            failed.append("action_belongs_to_another_case")
        if _aware(authorization.evaluated_at) > now:
            failed.append("authorization_evaluated_in_future")
        ctx["authorization"] = {"action_id": authorization.action_id,
                                "allowed": authorization.allowed,
                                "failed_checks": authorization.failed_checks,
                                "policy_id": authorization.policy_id,
                                "requires_human_approval": authorization.requires_human_approval}
        return failed

    def _check_execution(self, case: Case, authorization: AuthorizationDecision | None,
                         mirror: MirrorResult | None, policy: OperatorPolicy | None,
                         ctx: dict[str, Any], now: datetime) -> list[str]:
        failed = self._check_assessment(case, authorization, ctx, now)
        if authorization is not None and not authorization.allowed:
            failed.append("authorization_not_allowed")
        approved = self.approved_action_id(case)
        if not any(d.to_state is S.APPROVED and is_human(d.actor) for d in case.decisions):
            failed.append("no_human_approval_recorded")
        elif authorization is not None and approved != authorization.action_id:
            # an approval authorizes exactly one action: never a sibling of the same case
            failed.append("action_not_approved")
        # signed policy
        if policy is None:
            failed.append("signed_policy_missing")
        else:
            ctx["policy"] = {"policy_id": policy.policy_id, "mode": policy.mode,
                             "signer_key_id": policy.signer_key_id}
            if self._keyring is None or not verify_model(policy, self._keyring):
                failed.append("policy_signature_invalid")
            if policy.tenant_id != case.tenant_id:
                failed.append("policy_tenant_mismatch")
            if policy.mode != "active":
                failed.append("policy_not_active_mode")
            if not policy.legal_signoff_ref:
                failed.append("policy_missing_legal_signoff")
            if not (_aware(policy.valid_from) <= now < _aware(policy.valid_until)):
                failed.append("policy_not_valid_now")
            if authorization is not None and authorization.policy_id != policy.policy_id:
                failed.append("authorization_not_bound_to_policy")
            action = (self._docs.get(ProposedAction, case.tenant_id, authorization.action_id)
                      if authorization is not None else None)
            if action is not None:
                if action.action_type not in policy.allowed_actions:
                    failed.append("action_type_not_allowed_by_policy")
                if action.expires_at is None:
                    failed.append("action_without_expiry")
                elif _aware(action.expires_at) <= now:
                    failed.append("action_expired")
        # MIRROR
        if mirror is None:
            failed.append("mirror_result_missing")
        else:
            ctx["mirror"] = {"verdict": mirror.verdict.value, "action_id": mirror.action_id}
            if mirror.verdict is not MirrorVerdict.SAFE:
                failed.append(f"mirror_not_safe:{mirror.verdict.value}")
            if authorization is not None and mirror.action_id != authorization.action_id:
                failed.append("mirror_result_for_other_action")
        return failed


_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

#: Threat classes whose impact on third parties (botnet C2, DDoS, proxying abuse) raises triage priority.
HIGH_IMPACT_LABELS = frozenset({"c2_beaconing", "ddos_bot", "residential_proxy"})


def _severity(finding: Finding) -> Literal["low", "medium", "high", "critical"]:
    """Triage severity from verification-grade evidence and threat class, never from the score alone.

    * critical - MALICIOUS backed by indicator evidence from >= 2 independent origins;
    * high     - any other MALICIOUS (a verified signed-indicator contact);
    * medium   - SUSPICIOUS with an indicator match, or of a high-impact threat class;
    * low      - other SUSPICIOUS, and ABSTAIN held for review.
    """
    comps = finding.component_scores or {}
    origins = comps.get("ioc_independent_origins") or 0.0
    ioc = comps.get("ioc") or 0.0
    if finding.verdict is Verdict.MALICIOUS:
        return "critical" if origins >= 2 else "high"
    if finding.verdict is Verdict.SUSPICIOUS:
        return "medium" if (ioc > 0 or finding.label in HIGH_IMPACT_LABELS) else "low"
    return "low"
