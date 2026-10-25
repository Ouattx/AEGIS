"""Detection-rule registry and lifecycle (persisted in DocStore, every change ledgered).

Lifecycle::

    draft --backtest--> backtested --signed human approval--> approved
          --human--> shadow --gate evaluation + signed human promotion--> promoted
    (any state) --human or system--> retired

Rules that this module enforces in code:

* **Validation cannot be bypassed.** :meth:`RuleRegistry.submit_draft` re-runs the
  static validator; a failing rule is never stored.
* **Specs are immutable.** Each version stores its spec and content hash; any edit is
  a new version. Approvals, backtests and gate evaluations are bound to the hash.
* **Humans approve, AI never does.** Approval, shadow start and promotion need a
  human actor (``agent:*``, ``llm*``, ``system*``, ``generator*``, ``auto*`` are refused)
  who is not the drafter. Approvals are :class:`RuleApproval` documents signed by the
  approver's Ed25519 key; the signature must verify against the approver keyring and
  the key must belong to the approver (``key_owners``, or key id == approver id).
* **Never auto-promote.** Promotion is only reachable through :meth:`promote`, which
  requires a fresh, passing :class:`RulePromotionEvaluation` of the pre-registered
  :class:`RulePromotionGate` (backtest confidence bounds, shadow duration, reviewed
  shadow findings) and a second signed approval, by default from a different person
  than the first approver. No code path calls it on its own.
* **Integrity on load.** :meth:`active_rules` only loads shadow/promoted rules whose
  spec hash, approval signatures and latest ledger record all agree (optionally
  re-validated against the current topology); anything else is reported as rejected.
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict

from aegis.contracts.canonical import sha256_hex
from aegis.detengine.backtest import RuleBacktestReport, summarize_reports
from aegis.detengine.engine import ActiveRule, RejectedRule, RuleEngine, RuleShadowFinding, rule_ref
from aegis.detengine.language import RuleSpec, RuleSpecError, spec_sha256
from aegis.detengine.validation import HostingContext, RuleValidationError, validate_rule
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer, sign_model, verify_model
from aegis.storage.db import DocStore

RULE_ENTRY = "detection_rule"
DrafterKind = Literal["llm", "generator", "human"]
ReviewOutcome = Literal["true_positive", "false_positive", "inconclusive"]
_NON_HUMAN_PREFIXES = ("agent:", "llm", "system", "generator", "auto", "bot:")


class RuleState(str, Enum):
    DRAFT = "draft"
    BACKTESTED = "backtested"
    APPROVED = "approved"
    SHADOW = "shadow"
    PROMOTED = "promoted"
    RETIRED = "retired"


R = RuleState
ALLOWED_RULE_TRANSITIONS: dict[RuleState, frozenset[RuleState]] = {
    R.DRAFT: frozenset({R.BACKTESTED, R.RETIRED}),
    R.BACKTESTED: frozenset({R.BACKTESTED, R.APPROVED, R.RETIRED}),
    R.APPROVED: frozenset({R.SHADOW, R.RETIRED}),
    R.SHADOW: frozenset({R.PROMOTED, R.RETIRED}),
    R.PROMOTED: frozenset({R.RETIRED}),
    R.RETIRED: frozenset(),
}


def is_human(actor: str) -> bool:
    a = (actor or "").strip().lower()
    return bool(a) and not a.startswith(_NON_HUMAN_PREFIXES)


class RuleRegistryError(RuntimeError):
    """Unknown rule or malformed request."""


class RuleLifecycleError(PermissionError):
    """A lifecycle step was refused; ``failed`` lists machine-readable reasons."""

    def __init__(self, message: str, failed: Iterable[str] = ()):
        super().__init__(message)
        self.failed = list(failed)


# ----------------------------------------------------------------------------- documents


class _Doc(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuleTransition(_Doc):
    from_state: RuleState | None
    to_state: RuleState
    actor: str
    reason: str
    at: datetime
    ledger_entry_hash: str


class RuleRecord(_Doc):
    doc_id: str                      # = rule_ref (rule_id@vN)
    tenant_id: str
    rule_id: str
    version: int
    spec: dict[str, Any]
    spec_sha256: str
    state: RuleState
    drafted_by: str
    drafter_kind: DrafterKind
    source_case_ids: list[str]
    source_evidence_ids: list[str]
    validation: dict[str, Any]
    backtest_ids: list[str] = []
    approval_id: str | None = None
    promotion_approval_id: str | None = None
    promotion_evaluation_id: str | None = None
    shadow_started_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    history: list[RuleTransition] = []

    @property
    def ref(self) -> str:
        return self.doc_id

    def rule_spec(self) -> RuleSpec:
        return RuleSpec.from_dict(self.spec)


class RuleApproval(_Doc):
    """A human decision bound to one spec hash; signed by the approver (see :func:`sign_approval`)."""
    doc_id: str                      # = approval id
    tenant_id: str
    rule_ref: str
    rule_id: str
    version: int
    spec_sha256: str
    purpose: Literal["approve", "promote"]
    approver: str
    reason: str
    backtest_ids: list[str]
    promotion_evaluation_id: str | None = None
    issued_at: datetime
    signer_key_id: str = ""
    signature: str = ""


class RuleShadowReview(_Doc):
    doc_id: str                      # = shadow finding id (one review per finding; the latest wins)
    tenant_id: str
    rule_ref: str
    finding_id: str
    outcome: ReviewOutcome
    reviewer: str
    notes: str
    reviewed_at: datetime


class RulePromotionEvaluation(_Doc):
    doc_id: str
    tenant_id: str
    rule_ref: str
    spec_sha256: str
    gate_id: str
    gate: dict[str, Any]
    passed: bool
    failed_checks: list[str]
    backtests: list[dict[str, Any]]
    pooled: dict[str, Any]
    shadow: dict[str, Any]
    evaluated_by: str
    evaluated_at: datetime


@dataclass(frozen=True)
class RulePromotionGate:
    """Pre-registered promotion gate. Change it only by issuing a new gate (new ``gate_id``).

    Thresholds apply to the *confidence bounds* of every backtest, not the point estimates.
    """
    min_precision_lower: float = 0.5
    min_recall_lower: float = 0.05
    max_false_alerts_per_10k_upper: float = 50.0
    max_hard_negative_alerts: int = 0
    require_sufficient_backtests: bool = True
    allow_synthetic_only: bool = True
    min_shadow_duration: timedelta = timedelta(days=7)
    min_shadow_reviews: int = 10
    max_shadow_false_positive_share: float = 0.2
    max_evaluation_age: timedelta = timedelta(hours=24)
    require_distinct_promoter: bool = True

    @property
    def gate_id(self) -> str:
        return "rgate-" + sha256_hex(self._body())[:16]

    def _body(self) -> dict[str, Any]:
        return {k: (v.total_seconds() if isinstance(v, timedelta) else v) for k, v in asdict(self).items()}

    def describe(self) -> dict[str, Any]:
        return {**self._body(), "gate_id": self.gate_id}


def sign_approval(approval: RuleApproval, signer: Signer) -> RuleApproval:
    """Sign an approval with the approver's key (the key id is covered by the signature)."""
    return sign_model(approval, signer)


# ----------------------------------------------------------------------------- registry


class RuleRegistry:
    """Tenant-scoped rule registry. Every read and write takes the caller's ``tenant_id``."""

    def __init__(self, docstore: DocStore, ledger: Ledger, *, approver_keyring: KeyRing,
                 key_owners: Mapping[str, str] | None = None, gate: RulePromotionGate | None = None,
                 clock: Callable[[], datetime] | None = None, max_approval_age: timedelta = timedelta(hours=24),
                 max_clock_skew: timedelta = timedelta(minutes=5)):
        self.docs = docstore
        self.ledger = ledger
        self.keyring = approver_keyring
        self.key_owners = dict(key_owners) if key_owners is not None else None
        self.gate = gate or RulePromotionGate()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_approval_age = max_approval_age
        self.max_clock_skew = max_clock_skew
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ queries
    def get(self, tenant_id: str, ref: str) -> RuleRecord | None:
        return self.docs.get(RuleRecord, tenant_id, ref)

    def require(self, tenant_id: str, ref: str) -> RuleRecord:
        rec = self.get(tenant_id, ref)
        if rec is None:
            raise RuleRegistryError(f"unknown rule {ref!r}")
        return rec

    def list_rules(self, tenant_id: str, *, state: RuleState | None = None, rule_id: str | None = None) -> list[RuleRecord]:
        out = [r for r in self.docs.iter_all(RuleRecord, tenant_id)
               if (state is None or r.state == state) and (rule_id is None or r.rule_id == rule_id)]
        return sorted(out, key=lambda r: (r.rule_id, r.version))

    def backtests(self, tenant_id: str, ref: str) -> list[RuleBacktestReport]:
        rec = self.require(tenant_id, ref)
        out = [self.docs.get(RuleBacktestReport, tenant_id, bid) for bid in rec.backtest_ids]
        return [b for b in out if b is not None]

    def approvals(self, tenant_id: str, ref: str) -> list[RuleApproval]:
        rec = self.require(tenant_id, ref)
        ids = [i for i in (rec.approval_id, rec.promotion_approval_id) if i]
        return [a for a in (self.docs.get(RuleApproval, tenant_id, i) for i in ids) if a is not None]

    def shadow_findings(self, tenant_id: str, ref: str) -> list[RuleShadowFinding]:
        return [s for s in self.docs.iter_all(RuleShadowFinding, tenant_id) if s.rule_ref == ref]

    def shadow_reviews(self, tenant_id: str, ref: str) -> list[RuleShadowReview]:
        return [s for s in self.docs.iter_all(RuleShadowReview, tenant_id) if s.rule_ref == ref]

    def history(self, tenant_id: str, ref: str) -> list[dict[str, Any]]:
        return [e.model_dump(mode="json") for e in self.ledger.entries(tenant_id, subject_id=ref,
                                                                         entry_type=RULE_ENTRY)]

    # ------------------------------------------------------------------ internals
    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return now.astimezone(timezone.utc)

    def _transition(self, rec: RuleRecord, to: RuleState, actor: str, reason: str,
                    extra: dict[str, Any] | None = None, *, update: dict[str, Any] | None = None) -> RuleRecord:
        frm = rec.state
        if to not in ALLOWED_RULE_TRANSITIONS[frm]:
            raise RuleLifecycleError(f"transition {frm.value} -> {to.value} is not allowed",
                                     [f"transition_not_allowed:{frm.value}->{to.value}"])
        return self._write(rec, frm, to, actor, reason, extra, update)

    def _write(self, rec: RuleRecord, frm: RuleState | None, to: RuleState, actor: str, reason: str,
               extra: dict[str, Any] | None, update: dict[str, Any] | None) -> RuleRecord:
        now = self._now()
        payload = {"event": "rule_transition", "rule_id": rec.rule_id, "version": rec.version, "rule_ref": rec.ref,
                   "spec_sha256": rec.spec_sha256, "from_state": frm.value if frm else None, "to_state": to.value,
                   "actor": actor, "reason": reason, "rule_bundle_version": f"detengine:{rec.ref}", **(extra or {})}
        entry = self.ledger.append(rec.tenant_id, RULE_ENTRY, rec.ref, payload)
        hist = rec.history + [RuleTransition(from_state=frm, to_state=to, actor=actor, reason=reason, at=now,
                                             ledger_entry_hash=entry.entry_hash)]
        new = rec.model_copy(update={**(update or {}), "state": to, "updated_at": now, "history": hist}, deep=True)
        self.docs.put(new)
        return new

    @staticmethod
    def _require_human(actor: str, what: str) -> None:
        if not is_human(actor):
            raise RuleLifecycleError(f"{what} requires a human actor, got {actor!r}", ["human_required"])

    def _verify_approval(self, approval: RuleApproval, rec: RuleRecord, purpose: str) -> list[str]:
        failed: list[str] = []
        if approval.tenant_id != rec.tenant_id:
            failed.append("approval_tenant_mismatch")
        if approval.purpose != purpose:
            failed.append("approval_purpose_mismatch")
        if approval.rule_ref != rec.ref or approval.rule_id != rec.rule_id or approval.version != rec.version:
            failed.append("approval_rule_mismatch")
        if approval.spec_sha256 != rec.spec_sha256:
            failed.append("approval_spec_mismatch")
        if not is_human(approval.approver):
            failed.append("human_required")
        if approval.approver.strip().lower() == rec.drafted_by.strip().lower():
            failed.append("approver_is_drafter")
        if not approval.reason.strip():
            failed.append("reason_required")
        now = self._now()
        issued = approval.issued_at.astimezone(timezone.utc) if approval.issued_at.tzinfo else None
        if issued is None or issued > now + self.max_clock_skew or now - issued > self.max_approval_age:
            failed.append("approval_not_fresh")
        if not verify_model(approval, self.keyring):
            failed.append("approval_signature_invalid")
        owner = (self.key_owners.get(approval.signer_key_id) if self.key_owners is not None
                 else approval.signer_key_id)
        if owner is None or owner != approval.approver:
            failed.append("approval_key_not_owned_by_approver")
        return failed

    # ------------------------------------------------------------------ lifecycle
    def submit_draft(self, tenant_id: str, spec: RuleSpec, *, actor: str, drafter_kind: DrafterKind,
                     source_case_ids: Sequence[str] = (), source_evidence_ids: Sequence[str] = (),
                     hosting: HostingContext | None = None, allowlist: Iterable[str] = ()) -> RuleRecord:
        """Validate and store a new draft version (idempotent for an identical live spec)."""
        a = (actor or "").strip().lower()
        if drafter_kind == "llm" and not a.startswith("llm:"):
            raise RuleLifecycleError("LLM drafts must carry an 'llm:<model>' actor", ["drafter_actor_mismatch"])
        if drafter_kind == "generator" and not a.startswith("generator:"):
            raise RuleLifecycleError("generated drafts must carry a 'generator:<name>' actor",
                                     ["drafter_actor_mismatch"])
        if drafter_kind == "human" and not is_human(actor):
            raise RuleLifecycleError("human drafts need a human actor", ["drafter_actor_mismatch"])
        try:
            spec = RuleSpec.from_dict(spec.to_dict())  # normalize through the strict parser
        except RuleSpecError as exc:
            raise RuleValidationError(exc.errors) from exc
        result = validate_rule(spec, hosting=hosting, allowlist=allowlist)
        if not result.ok:
            raise RuleValidationError(result.errors)
        sha = spec_sha256(spec)
        with self._lock:
            versions = self.list_rules(tenant_id, rule_id=spec.rule_id)
            for r in versions:
                if r.spec_sha256 == sha and r.state != RuleState.RETIRED:
                    return r
            version = max((r.version for r in versions), default=0) + 1
            now = self._now()
            rec = RuleRecord(
                doc_id=rule_ref(spec.rule_id, version), tenant_id=tenant_id, rule_id=spec.rule_id, version=version,
                spec=spec.to_dict(), spec_sha256=sha, state=RuleState.DRAFT, drafted_by=actor,
                drafter_kind=drafter_kind, source_case_ids=list(source_case_ids),
                source_evidence_ids=list(source_evidence_ids), validation=result.as_dict(), created_at=now,
                updated_at=now)
            return self._write(rec, None, RuleState.DRAFT, actor, "draft submitted",
                               {"drafter_kind": drafter_kind, "source_case_ids": list(source_case_ids),
                                "evidence_ids": list(source_evidence_ids), "validation": result.as_dict()}, None)

    def record_backtests(self, tenant_id: str, ref: str, reports: Sequence[RuleBacktestReport], *,
                         actor: str) -> RuleRecord:
        """Attach backtest reports for this exact spec; moves the rule to ``backtested``."""
        a = (actor or "").strip().lower()
        if a.startswith(("agent:", "llm")) or not a:
            raise RuleLifecycleError("backtests are recorded by the platform or a human", ["actor_not_allowed"])
        if not reports:
            raise RuleLifecycleError("at least one backtest report is required", ["no_backtest"])
        with self._lock:
            rec = self.require(tenant_id, ref)
            failed = []
            for r in reports:
                if r.tenant_id != tenant_id:
                    failed.append("backtest_tenant_mismatch")
                if r.spec_sha256 != rec.spec_sha256:
                    failed.append("backtest_spec_mismatch")
            if failed:
                raise RuleLifecycleError("backtest reports do not match the rule", sorted(set(failed)))
            if rec.state not in (RuleState.DRAFT, RuleState.BACKTESTED):
                raise RuleLifecycleError(f"cannot backtest a rule in state {rec.state.value}",
                                         [f"transition_not_allowed:{rec.state.value}->backtested"])
            stored = []
            for r in reports:
                r = r.model_copy(update={"rule_ref": ref})
                self.docs.put(r)
                stored.append(r)
            return self._transition(rec, RuleState.BACKTESTED, actor, "backtested on frozen datasets",
                                    {"backtest_ids": [r.doc_id for r in stored],
                                     "backtests": [r.summary() for r in stored]},
                                    update={"backtest_ids": [r.doc_id for r in stored]})

    def approval_request(self, tenant_id: str, ref: str, *, purpose: Literal["approve", "promote"], approver: str,
                         reason: str, promotion_evaluation_id: str | None = None) -> RuleApproval:
        """An unsigned approval for the approver to sign (:func:`sign_approval`)."""
        self._require_human(approver, "approval")
        rec = self.require(tenant_id, ref)
        return RuleApproval(doc_id=str(uuid.uuid4()), tenant_id=tenant_id, rule_ref=rec.ref, rule_id=rec.rule_id,
                            version=rec.version, spec_sha256=rec.spec_sha256, purpose=purpose, approver=approver,
                            reason=reason, backtest_ids=list(rec.backtest_ids),
                            promotion_evaluation_id=promotion_evaluation_id, issued_at=self._now())

    def approve(self, tenant_id: str, approval: RuleApproval) -> RuleRecord:
        """``backtested`` -> ``approved`` with a signed human approval."""
        with self._lock:
            rec = self.require(tenant_id, approval.rule_ref)
            if rec.state != RuleState.BACKTESTED:
                raise RuleLifecycleError(f"only backtested rules can be approved (state {rec.state.value})",
                                         [f"transition_not_allowed:{rec.state.value}->approved"])
            failed = self._verify_approval(approval, rec, "approve")
            if not rec.backtest_ids:
                failed.append("no_backtest")
            if sorted(approval.backtest_ids) != sorted(rec.backtest_ids):
                failed.append("approval_backtests_mismatch")
            if failed:
                raise RuleLifecycleError("approval refused", sorted(set(failed)))
            self.docs.put(approval)
            return self._transition(rec, RuleState.APPROVED, approval.approver, approval.reason,
                                    {"approval_id": approval.doc_id, "signer_key_id": approval.signer_key_id,
                                     "approval_signature": approval.signature, "backtest_ids": approval.backtest_ids},
                                    update={"approval_id": approval.doc_id})

    def start_shadow(self, tenant_id: str, ref: str, *, actor: str, reason: str) -> RuleRecord:
        """``approved`` -> ``shadow``: the rule runs and emits shadow findings only."""
        self._require_human(actor, "starting shadow mode")
        with self._lock:
            rec = self.require(tenant_id, ref)
            return self._transition(rec, RuleState.SHADOW, actor, reason or "shadow mode started",
                                    update={"shadow_started_at": self._now()})

    def record_shadow_review(self, tenant_id: str, ref: str, finding_id: str, *, outcome: ReviewOutcome,
                             reviewer: str, notes: str = "") -> RuleShadowReview:
        """An analyst verdict on one shadow finding (input to the promotion gate)."""
        self._require_human(reviewer, "reviewing shadow findings")
        if outcome not in ("true_positive", "false_positive", "inconclusive"):
            raise RuleRegistryError(f"invalid outcome {outcome!r}")
        with self._lock:
            rec = self.require(tenant_id, ref)
            if rec.state != RuleState.SHADOW:
                raise RuleLifecycleError("only rules in shadow mode take shadow reviews", ["not_in_shadow"])
            sf = self.docs.get(RuleShadowFinding, tenant_id, finding_id)
            if sf is None or sf.rule_ref != ref:
                raise RuleRegistryError(f"no shadow finding {finding_id!r} for rule {ref!r}")
            review = RuleShadowReview(doc_id=finding_id, tenant_id=tenant_id, rule_ref=ref, finding_id=finding_id,
                                  outcome=outcome, reviewer=reviewer, notes=notes[:2000], reviewed_at=self._now())
            self.ledger.append(tenant_id, RULE_ENTRY, ref, {
                "event": "shadow_review", "rule_ref": ref, "finding_id": finding_id, "outcome": outcome,
                "actor": reviewer, "spec_sha256": rec.spec_sha256, "rule_bundle_version": f"detengine:{ref}"})
            self.docs.put(review)
            return review

    def evaluate_promotion(self, tenant_id: str, ref: str, *, actor: str) -> RulePromotionEvaluation:
        """Run the pre-registered gate. Stored and ledgered; never promotes by itself."""
        g = self.gate
        with self._lock:
            rec = self.require(tenant_id, ref)
            failed: list[str] = []
            if rec.state != RuleState.SHADOW:
                failed.append(f"not_in_shadow:{rec.state.value}")
            reports = self.backtests(tenant_id, ref)
            if not reports:
                failed.append("no_backtest")
            for r in reports:
                ds = r.dataset.get("name", r.doc_id)
                m = r.metrics
                if r.spec_sha256 != rec.spec_sha256:
                    failed.append(f"backtest_spec_mismatch:{ds}")
                if g.require_sufficient_backtests and not r.sufficient:
                    failed.append(f"backtest_insufficient:{ds}")
                if m.precision_ci_exact is None or m.precision_ci_exact.low < g.min_precision_lower:
                    failed.append(f"precision_below_gate:{ds}")
                if m.recall_ci_exact is None or m.recall_ci_exact.low < g.min_recall_lower:
                    failed.append(f"recall_below_gate:{ds}")
                if (m.false_alerts_per_10k_ci_exact is None
                        or m.false_alerts_per_10k_ci_exact.high > g.max_false_alerts_per_10k_upper):
                    failed.append(f"false_alerts_above_gate:{ds}")
                if m.hard_negative_alerts > g.max_hard_negative_alerts:
                    failed.append(f"hard_negative_alerts:{ds}")
            if reports and all(r.synthetic for r in reports) and not g.allow_synthetic_only:
                failed.append("synthetic_only_backtests")
            now = self._now()
            started = rec.shadow_started_at
            shadow_age = (now - started) if started is not None else None
            if shadow_age is None or shadow_age < g.min_shadow_duration:
                failed.append("shadow_period_too_short")
            reviews = self.shadow_reviews(tenant_id, ref)
            tp = sum(1 for r in reviews if r.outcome == "true_positive")
            fp = sum(1 for r in reviews if r.outcome == "false_positive")
            if tp + fp < g.min_shadow_reviews:
                failed.append("too_few_shadow_reviews")
            fp_share = fp / (tp + fp) if tp + fp else None
            if fp_share is not None and fp_share > g.max_shadow_false_positive_share:
                failed.append("shadow_false_positive_share")
            shadow = {"started_at": started.isoformat() if started else None,
                      "duration_hours": shadow_age.total_seconds() / 3600 if shadow_age is not None else None,
                      "findings": len(self.shadow_findings(tenant_id, ref)), "reviews": len(reviews),
                      "true_positive": tp, "false_positive": fp, "false_positive_share": fp_share}
            ev = RulePromotionEvaluation(
                doc_id=str(uuid.uuid4()), tenant_id=tenant_id, rule_ref=ref, spec_sha256=rec.spec_sha256,
                gate_id=g.gate_id, gate=g.describe(), passed=not failed, failed_checks=failed,
                backtests=[r.summary() for r in reports], pooled=summarize_reports(reports), shadow=shadow,
                evaluated_by=actor, evaluated_at=now)
            self.ledger.append(tenant_id, RULE_ENTRY, ref, {
                "event": "promotion_evaluated", "rule_ref": ref, "evaluation_id": ev.doc_id,
                "spec_sha256": rec.spec_sha256, "gate_id": g.gate_id, "passed": ev.passed,
                "failed_checks": failed, "actor": actor, "rule_bundle_version": f"detengine:{ref}"})
            self.docs.put(ev)
            return ev

    def promote(self, tenant_id: str, approval: RuleApproval) -> RuleRecord:
        """``shadow`` -> ``promoted``: explicit, signed, human, behind a passing fresh gate evaluation."""
        with self._lock:
            rec = self.require(tenant_id, approval.rule_ref)
            if rec.state != RuleState.SHADOW:
                raise RuleLifecycleError(f"only shadow rules can be promoted (state {rec.state.value})",
                                         [f"transition_not_allowed:{rec.state.value}->promoted"])
            failed = self._verify_approval(approval, rec, "promote")
            ev = (self.docs.get(RulePromotionEvaluation, tenant_id, approval.promotion_evaluation_id)
                  if approval.promotion_evaluation_id else None)
            if ev is None:
                failed.append("no_promotion_evaluation")
            else:
                if ev.rule_ref != rec.ref or ev.spec_sha256 != rec.spec_sha256:
                    failed.append("promotion_evaluation_mismatch")
                if ev.gate_id != self.gate.gate_id:
                    failed.append("promotion_gate_changed")
                if not ev.passed:
                    failed.append("promotion_gate_failed")
                    failed.extend(ev.failed_checks)
                if self._now() - ev.evaluated_at.astimezone(timezone.utc) > self.gate.max_evaluation_age:
                    failed.append("promotion_evaluation_stale")
            first = self.docs.get(RuleApproval, tenant_id, rec.approval_id) if rec.approval_id else None
            if first is None:
                failed.append("missing_first_approval")
            elif (self.gate.require_distinct_promoter
                  and first.approver.strip().lower() == approval.approver.strip().lower()):
                failed.append("promoter_is_first_approver")
            if failed:
                raise RuleLifecycleError("promotion refused", list(dict.fromkeys(failed)))
            self.docs.put(approval)
            promoted = self._transition(rec, RuleState.PROMOTED, approval.approver, approval.reason, {
                "approval_id": approval.doc_id, "signer_key_id": approval.signer_key_id,
                "approval_signature": approval.signature, "evaluation_id": approval.promotion_evaluation_id,
                "gate_id": self.gate.gate_id,
            }, update={"promotion_approval_id": approval.doc_id,
                       "promotion_evaluation_id": approval.promotion_evaluation_id})
            for other in self.list_rules(tenant_id, rule_id=rec.rule_id):
                if other.ref != rec.ref and other.state in (RuleState.PROMOTED, RuleState.SHADOW):
                    self._transition(other, RuleState.RETIRED, approval.approver, f"superseded by {rec.ref}")
            return promoted

    def retire(self, tenant_id: str, ref: str, *, actor: str, reason: str) -> RuleRecord:
        """Retire a rule version (humans, or the platform e.g. on expiry; never an AI)."""
        a = (actor or "").strip().lower()
        if not a or a.startswith(("agent:", "llm", "generator", "auto", "bot:")):
            raise RuleLifecycleError("rules are retired by a human or the platform", ["actor_not_allowed"])
        if not reason.strip():
            raise RuleLifecycleError("a reason is required", ["reason_required"])
        with self._lock:
            return self._transition(self.require(tenant_id, ref), RuleState.RETIRED, actor, reason)

    # ------------------------------------------------------------------ loading
    def verify_record(self, rec: RuleRecord, *, hosting: HostingContext | None = None,
                      allowlist: Iterable[str] = ()) -> list[str]:
        """Integrity problems that keep ``rec`` from running (empty list = loadable)."""
        problems: list[str] = []
        try:
            spec = RuleSpec.from_dict(rec.spec)
        except RuleSpecError:
            return ["spec_unparseable"]
        if spec_sha256(spec) != rec.spec_sha256 or spec.rule_id != rec.rule_id:
            problems.append("spec_hash_mismatch")
        approvals: list[tuple[str | None, str]] = [(rec.approval_id, "approve")]
        if rec.state == RuleState.PROMOTED:
            approvals.append((rec.promotion_approval_id, "promote"))
        for aid, purpose in approvals:
            ap = self.docs.get(RuleApproval, rec.tenant_id, aid) if aid else None
            if ap is None:
                problems.append(f"missing_{purpose}_approval")
                continue
            if (ap.purpose != purpose or ap.spec_sha256 != rec.spec_sha256 or ap.rule_ref != rec.ref
                    or not verify_model(ap, self.keyring)):
                problems.append(f"{purpose}_approval_invalid")
        transitions = [e for e in self.ledger.entries(rec.tenant_id, subject_id=rec.ref, entry_type=RULE_ENTRY)
                       if e.payload.get("event") == "rule_transition"]
        last = transitions[-1] if transitions else None
        if last is None or last.payload.get("to_state") != rec.state.value \
                or last.payload.get("spec_sha256") != rec.spec_sha256:
            problems.append("ledger_mismatch")
        if hosting is not None:
            res = validate_rule(spec, hosting=hosting, allowlist=allowlist)
            problems.extend(f"revalidation_failed:{e}" for e in res.errors)
        return problems

    def active_rules(self, tenant_id: str, *, evidence_store: EvidenceStore | None = None,
                     docstore: DocStore | None = None, clock: Callable[[], datetime] | None = None,
                     hosting: HostingContext | None = None, allowlist: Iterable[str] = ()) -> RuleEngine:
        """A :class:`RuleEngine` over the tenant's verified shadow and promoted rules."""
        allow = list(allowlist)
        active: list[ActiveRule] = []
        rejected: list[RejectedRule] = []
        for rec in self.list_rules(tenant_id):
            if rec.state not in (RuleState.SHADOW, RuleState.PROMOTED):
                continue
            problems = self.verify_record(rec, hosting=hosting, allowlist=allow)
            if problems:
                rejected.append(RejectedRule(rec.ref, tuple(problems)))
                continue
            active.append(ActiveRule(rule_id=rec.rule_id, version=rec.version, spec=rec.rule_spec(),
                                     mode="promoted" if rec.state == RuleState.PROMOTED else "shadow",
                                     spec_sha256=rec.spec_sha256))
        return RuleEngine(tenant_id, active, evidence_store=evidence_store,
                          docstore=docstore if docstore is not None else self.docs, clock=clock, rejected=rejected)


__all__ = [
    "ALLOWED_RULE_TRANSITIONS", "RulePromotionEvaluation", "RULE_ENTRY", "RuleApproval", "RuleLifecycleError",
    "RulePromotionGate", "RuleRecord", "RuleRegistry", "RuleRegistryError", "RuleState", "RuleTransition",
    "RuleShadowReview", "is_human", "sign_approval",
]
