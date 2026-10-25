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
* ``APPROVED``: a human approver and an assessment that allowed the action.
* ``EXECUTED``: an operator policy whose signature verifies against the trusted
  keyring (active mode, legal signoff, valid now, action type allowed), an
  allowed authorization bound to that policy, and a MIRROR result of ``SAFE``.

Agents (actors ``agent:*``) can never change case state. Every transition, and
case creation, is written to the provenance ledger before the case document is
updated; major transitions also anchor ledger (and ATLAS, if attached) snapshots.
"""
from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal

from aegis.contracts.models import (
    AuthorizationDecision,
    Case,
    CaseDecision,
    CaseState,
    Evidence,
    EvidenceKind,
    Finding,
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
CASE_REVIEW = "case_counter_hypothesis_review"
CASE_EVIDENCE = "case_evidence_attached"


class GuardError(PermissionError):
    """A transition was refused. ``failed`` lists the machine-readable reasons."""

    def __init__(self, message: str, failed: Iterable[str] = ()):
        super().__init__(message)
        self.failed: list[str] = list(failed)


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
    ``EXECUTED`` guard always fails closed. ``atlas`` (optional) gets a graph
    snapshot on major transitions.
    """

    def __init__(self, docstore: DocStore, evidence_store: EvidenceStore, ledger: Ledger, *,
                 keyring: KeyRing | None = None, atlas: Any | None = None,
                 clock: Callable[[], datetime] | None = None):
        self._docs = docstore
        self._evidence = evidence_store
        self._ledger = ledger
        self._keyring = keyring
        self._atlas = atlas
        self._clock = clock or _now
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        self._locks_guard = threading.Lock()

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
        """Open (idempotently) a case for a finding that requires review."""
        if is_agent(actor):
            raise GuardError("agents cannot open cases", ["agent_actor"])
        if finding.verdict is Verdict.BENIGN:
            raise ValueError("benign findings do not open cases")
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
            entry = self._ledger.append(tenant_id, EntryType.CASE_TRANSITION, case_id, payload)
            decision = CaseDecision(from_state=case.state, to_state=to_state, actor=actor,
                                    reason=reason.strip()[:2000], at=now,
                                    ledger_entry_hash=entry.entry_hash)
            update: dict[str, Any] = {"state": to_state, "updated_at": now,
                                      "decisions": case.decisions + [decision]}
            if to_state in MAJOR_TRANSITIONS:
                snap = record_snapshot(tenant_id, self._ledger, reason=f"case_transition:{to_state.value}",
                                       subject_id=case_id)
                update["snapshot_hash"] = snap["snapshot_hash"]
                if self._atlas is not None:
                    self._atlas.record_snapshot(tenant_id, reason=f"case_transition:{to_state.value}",
                                                subject_id=case_id)
            case = case.model_copy(update=update, deep=True)
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

        elif to is S.APPROVED:
            if not is_human(actor):
                failed.append("approval_requires_human_approver")
            failed += self._check_assessment(case, authorization, ctx, now)
            if authorization is not None and not authorization.allowed:
                failed.append("authorization_not_allowed")

        elif to is S.EXECUTED:
            failed += self._check_execution(case, authorization, mirror, policy, ctx, now)

        return failed, ctx

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
        if not any(d.to_state is S.APPROVED and is_human(d.actor) for d in case.decisions):
            failed.append("no_human_approval_recorded")
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


def _severity(finding: Finding) -> Literal["low", "medium", "high", "critical"]:
    if finding.verdict is Verdict.MALICIOUS:
        return "critical" if finding.score >= 0.9 else "high"
    if finding.verdict is Verdict.SUSPICIOUS:
        return "medium" if finding.score >= 0.5 else "low"
    return "low"
