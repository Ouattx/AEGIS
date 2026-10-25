"""Enforcement executor: the only path from an authorization decision to an adapter.

``Executor.execute`` refuses (and records the refusal in the ledger) unless:

* the circuit breaker is closed;
* the decision is for this action, is fresh (``max_decision_age``) and allowed.
  A dry-run adapter additionally accepts a decision whose *only* failed check is
  ``policy_not_active_mode`` - shadow mode can rehearse "would have executed"
  but a real adapter always needs an active-mode, fully allowed decision;
* the action has an expiry in the future and valid targets the adapter supports;
* a human approver is named whenever the decision requires one, the approver is
  not the proposer (four-eyes) and no agent identity ever executes;
* the action is not already live.

Every operation is written to the provenance ledger *before* the adapter is
called (intent) and after (outcome), and the outcome entry carries the adapter's
``prior_state`` so a rollback can be performed even after a process restart
(:meth:`Executor.recover`). A rollback restores the enforcement point to that
prior state. A circuit-breaker trip rolls the action back automatically, and
:meth:`Executor.sweep_expired` removes actions whose authorization expired.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from aegis.contracts.models import AuthorizationDecision, ProposedAction
from aegis.mirror.base import (
    EnforcementAdapter,
    ExecutionRecord,
    ExecutionStatus,
    InvalidTargetError,
    RollbackRehearsal,
    is_human,
    normalized_targets,
)
from aegis.mirror.breaker import CircuitBreaker
from aegis.provenance.ledger import EntryType, Ledger

#: ledger entry type of a rollback rehearsal
ROLLBACK_REHEARSAL_ENTRY = "rollback_rehearsal"
DRY_RUN_TOLERATED_CHECKS = frozenset({"policy_not_active_mode"})
DEFAULT_MAX_DECISION_AGE = timedelta(minutes=30)
_CLOCK_SKEW = timedelta(seconds=60)
_LIVE = (ExecutionStatus.APPLIED, ExecutionStatus.DRY_RUN)


class ExecutionError(RuntimeError):
    """The executor could not complete an operation safely."""


@dataclass
class _Live:
    action: ProposedAction
    record: ExecutionRecord


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class Executor:
    """Runs authorized actions through one adapter, with ledger, breaker and rollback."""

    def __init__(self, adapter: EnforcementAdapter, ledger: Ledger,
                 breaker: CircuitBreaker | None = None, *,
                 clock: Callable[[], datetime] | None = None,
                 max_decision_age: timedelta = DEFAULT_MAX_DECISION_AGE):
        self.adapter = adapter
        self.ledger = ledger
        self.breaker = breaker
        self._clock = clock or _utc_now
        self.max_decision_age = max_decision_age
        self._lock = threading.RLock()
        self._live: dict[str, _Live] = {}
        self._history: dict[str, list[ExecutionRecord]] = {}
        if breaker is not None:
            breaker.subscribe(self._on_breaker_trip)

    # ------------------------------------------------------------------ queries
    def active(self) -> list[str]:
        with self._lock:
            return list(self._live)

    def records(self, action_id: str) -> list[ExecutionRecord]:
        with self._lock:
            return list(self._history.get(action_id, []))

    # ------------------------------------------------------------------ execute
    def execute(self, action: ProposedAction, decision: AuthorizationDecision | None,
                approver: str | None, *,
                baseline_error_rate: float | None = None) -> ExecutionRecord:
        """Enforce ``action`` if every precondition holds; otherwise record a refusal.

        ``baseline_error_rate`` is the legitimate-traffic error rate measured before
        enforcement; the circuit breaker compares live samples against it (the
        breaker's default baseline is used when omitted).
        """
        with self._lock:
            now = _utc(self._clock())
            reasons = self._refusal_reasons(action, decision, approver, now)
            base = dict(tenant_id=action.tenant_id, action_id=action.action_id,
                        case_id=action.case_id, operation="execute", adapter=self.adapter.name,
                        dry_run=self.adapter.dry_run, actor=(approver or "").strip() or "unknown",
                        policy_id=decision.policy_id if decision is not None else None)
            if reasons:
                rec = ExecutionRecord(status=ExecutionStatus.REFUSED, refusal_reasons=reasons,
                                      reason="refused by executor", at=now, **base)
                return self._finish(rec, action, decision)

            self._write(action.tenant_id, action.action_id, {
                "phase": "intent", "operation": "execute", "adapter": self.adapter.name,
                "dry_run": self.adapter.dry_run, "actor": base["actor"],
                "action": action.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json") if decision else None,
                "at": now.isoformat()})
            try:
                result = self.adapter.apply(action, now=now)
            except Exception as exc:
                rec = ExecutionRecord(status=ExecutionStatus.FAILED, at=now,
                                      reason=f"adapter error: {type(exc).__name__}: {exc}"[:2000],
                                      **base)
                return self._finish(rec, action, decision)

            status = ExecutionStatus.DRY_RUN if self.adapter.dry_run else ExecutionStatus.APPLIED
            rec = ExecutionRecord(status=status, prior_state=result.prior_state,
                                  details=result.details, at=now,
                                  reason="dry run (shadow mode)" if self.adapter.dry_run
                                  else "enforcement applied", **base)
            try:
                rec = self._finish(rec, action, decision)
            except Exception as exc:
                # never leave unrecorded enforcement in place
                try:
                    self.adapter.revert(action, result.prior_state, now=now)
                except Exception as revert_exc:
                    raise ExecutionError(
                        "ledger write failed after enforcement and the revert also failed: "
                        f"{revert_exc}") from exc
                raise ExecutionError("ledger write failed; enforcement reverted") from exc
            self._live[action.action_id] = _Live(action=action, record=rec)
            if self.breaker is not None:
                self.breaker.watch(action.action_id, baseline_error_rate)
            return rec

    def _refusal_reasons(self, action: ProposedAction, decision: AuthorizationDecision | None,
                         approver: str | None, now: datetime) -> list[str]:
        reasons: list[str] = []
        if self.breaker is not None and self.breaker.is_open:
            reasons.append("circuit_breaker_open")
        if decision is None:
            reasons.append("authorization_decision_missing")
        else:
            if decision.action_id != action.action_id:
                reasons.append("decision_for_other_action")
            if not decision.allowed:
                tolerated = (self.adapter.dry_run and decision.failed_checks
                             and set(decision.failed_checks) <= DRY_RUN_TOLERATED_CHECKS)
                if not tolerated:
                    reasons.append("authorization_denied")
                    reasons.extend(f"failed_check:{c}" for c in decision.failed_checks)
            evaluated = _utc(decision.evaluated_at)
            if evaluated > now + _CLOCK_SKEW:
                reasons.append("decision_from_future")
            elif now - evaluated > self.max_decision_age:
                reasons.append("decision_stale")
        if action.expires_at is None:
            reasons.append("action_without_expiry")
        elif _utc(action.expires_at) <= now:
            reasons.append("action_expired")
        if not self.adapter.supports(action.action_type):
            reasons.append("adapter_unsupported_action")
        try:
            if not normalized_targets(action):
                reasons.append("no_targets")
        except InvalidTargetError:
            reasons.append("invalid_targets")
        who = (approver or "").strip()
        if who.lower().startswith("agent:"):
            reasons.append("agent_cannot_execute")
        needs_human = decision is None or decision.requires_human_approval
        if needs_human:
            if not is_human(who):
                reasons.append("human_approval_required")
            elif who == (action.created_by or "").strip():
                reasons.append("approver_is_proposer")
        if action.action_id in self._live:
            reasons.append("already_active")
        return list(dict.fromkeys(reasons))

    # ------------------------------------------------------------------ rehearsal
    def rehearse_rollback(self, action: ProposedAction) -> RollbackRehearsal:
        """Rehearse apply + rollback on the adapter without enforcing anything.

        The outcome is written to the ledger (``rollback_rehearsal``); only a passing
        rehearsal lets an action carry ``rollback_verified``.
        """
        now = _utc(self._clock())
        try:
            result = self.adapter.rehearse_rollback(action, now=now)
        except Exception as exc:  # a crashing rehearsal is a failed rehearsal
            result = RollbackRehearsal(ok=False, method="error",
                                       detail=f"{type(exc).__name__}: {exc}"[:500])
        self.ledger.append(action.tenant_id, ROLLBACK_REHEARSAL_ENTRY, action.action_id, {
            "action_id": action.action_id, "case_id": action.case_id, "adapter": self.adapter.name,
            "dry_run": self.adapter.dry_run, "ok": result.ok, "method": result.method,
            "checks": result.checks, "detail": result.detail, "at": now.isoformat()})
        return result

    # ------------------------------------------------------------------ rollback
    def rollback(self, action_id: str, *, actor: str = "system", reason: str = "rollback",
                 tenant_id: str | None = None) -> ExecutionRecord:
        """Undo a live action, restoring the enforcement point's prior state.

        Idempotent: rolling back an action already rolled back returns that
        record. ``tenant_id`` lets a fresh executor recover live actions from the
        ledger first. A failed revert returns a ``ROLLBACK_FAILED`` record and the
        action stays live so the rollback can be retried.
        """
        with self._lock:
            if action_id not in self._live and tenant_id is not None:
                self.recover(tenant_id)
            live = self._live.get(action_id)
            if live is None:
                for rec in reversed(self._history.get(action_id, [])):
                    if rec.operation == "rollback" and rec.status is ExecutionStatus.ROLLED_BACK:
                        return rec
                raise ExecutionError(f"no live execution for action {action_id!r}")
            action = live.action
            now = _utc(self._clock())
            actor = (actor or "").strip() or "system"
            base = dict(tenant_id=action.tenant_id, action_id=action_id, case_id=action.case_id,
                        operation="rollback", adapter=self.adapter.name,
                        dry_run=self.adapter.dry_run, actor=actor,
                        policy_id=live.record.policy_id)
            self._write(action.tenant_id, action_id, {
                "phase": "intent", "operation": "rollback", "adapter": self.adapter.name,
                "actor": actor, "reason": reason, "at": now.isoformat()})
            try:
                result = self.adapter.revert(action, live.record.prior_state, now=now)
            except Exception as exc:
                rec = ExecutionRecord(status=ExecutionStatus.ROLLBACK_FAILED, at=now,
                                      reason=f"{reason}; revert error: {type(exc).__name__}: "
                                             f"{exc}"[:2000], **base)
                return self._finish(rec, action, None)
            rec = ExecutionRecord(status=ExecutionStatus.ROLLED_BACK, at=now, reason=reason,
                                  prior_state=live.record.prior_state, details=result.details,
                                  **base)
            rec = self._finish(rec, action, None)
            del self._live[action_id]
            if self.breaker is not None:
                self.breaker.unwatch(action_id)
            return rec

    def sweep_expired(self) -> list[ExecutionRecord]:
        """Roll back every live action whose expiry has passed."""
        with self._lock:
            now = _utc(self._clock())
            due = [aid for aid, live in self._live.items()
                   if live.action.expires_at is None or _utc(live.action.expires_at) <= now]
        return [self.rollback(aid, actor="system:expiry", reason="authorization expired")
                for aid in due]

    def observe_legit_traffic(self, action_id: str, requests: int, errors: int,
                              at: datetime | None = None) -> bool:
        """Feed a legitimate-traffic health sample; True if it tripped the breaker.

        A trip rolls the action back automatically via the breaker subscription.
        """
        if self.breaker is None:
            raise ExecutionError("no circuit breaker configured")
        return self.breaker.record(action_id, requests, errors, at)

    def _on_breaker_trip(self, action_id: str, reason: str) -> None:
        with self._lock:
            if action_id not in self._live:
                return
        rec = self.rollback(action_id, actor="system:circuit_breaker",
                            reason=f"circuit breaker: {reason}")
        if rec.status is not ExecutionStatus.ROLLED_BACK:
            raise ExecutionError(f"automatic rollback of {action_id} failed: {rec.reason}")

    # ------------------------------------------------------------------ recovery
    def recover(self, tenant_id: str) -> list[str]:
        """Rebuild live actions for ``tenant_id`` from the ledger (after a restart)."""
        with self._lock:
            latest: dict[str, dict[str, Any]] = {}
            actions: dict[str, dict[str, Any]] = {}
            for entry in self.ledger.entries(tenant_id, entry_type=EntryType.EXECUTION):
                p = entry.payload
                if p.get("adapter") != self.adapter.name:
                    continue
                if p.get("phase") == "intent" and p.get("operation") == "execute":
                    actions[entry.subject_id] = p["action"]
                if p.get("phase") == "outcome":
                    latest[entry.subject_id] = p
            recovered: list[str] = []
            for aid, p in latest.items():
                if aid in self._live or aid not in actions:
                    continue
                rec = ExecutionRecord.model_validate(p["record"])
                live_now = (rec.operation == "execute" and rec.status in _LIVE) or \
                           (rec.operation == "rollback"
                            and rec.status is ExecutionStatus.ROLLBACK_FAILED)
                if not live_now:
                    continue
                exec_rec = rec
                if rec.operation == "rollback":
                    exec_rec = self._last_execute_outcome(tenant_id, aid) or rec
                self._live[aid] = _Live(action=ProposedAction.model_validate(actions[aid]),
                                        record=exec_rec)
                self._history.setdefault(aid, []).append(exec_rec)
                if self.breaker is not None:
                    self.breaker.watch(aid)
                recovered.append(aid)
            return recovered

    def _last_execute_outcome(self, tenant_id: str, action_id: str) -> ExecutionRecord | None:
        out = None
        for entry in self.ledger.entries(tenant_id, subject_id=action_id,
                                         entry_type=EntryType.EXECUTION):
            p = entry.payload
            if p.get("phase") == "outcome" and p["record"]["operation"] == "execute":
                out = ExecutionRecord.model_validate(p["record"])
        return out

    # ------------------------------------------------------------------ ledger
    def _write(self, tenant_id: str, action_id: str, payload: dict[str, Any]) -> str:
        entry = self.ledger.append(tenant_id, EntryType.EXECUTION, action_id, payload)
        return entry.entry_hash

    def _finish(self, rec: ExecutionRecord, action: ProposedAction,
                decision: AuthorizationDecision | None) -> ExecutionRecord:
        payload: dict[str, Any] = {
            "phase": "outcome", "operation": rec.operation, "adapter": rec.adapter,
            "status": rec.status.value, "record": rec.model_dump(mode="json"),
        }
        if rec.status is ExecutionStatus.REFUSED:
            payload["action"] = action.model_dump(mode="json")
            payload["decision"] = decision.model_dump(mode="json") if decision else None
        h = self._write(rec.tenant_id, rec.action_id, payload)
        rec = rec.model_copy(update={"ledger_entry_hash": h})
        self._history.setdefault(rec.action_id, []).append(rec)
        return rec
