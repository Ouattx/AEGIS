"""MIRROR enforcement adapters and execution control (public entry point).

``DryRunAdapter`` is defined here; the RPZ and webhook adapters, the circuit
breaker and the executor live in their own modules and are re-exported so the
interface documented in ``docs/ARCHITECTURE.md`` is importable from this module.
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any

from aegis.contracts.models import ActionType, ProposedAction
from aegis.mirror.base import (
    AdapterError,
    AdapterResult,
    EnforcementAdapter,
    ExecutionRecord,
    ExecutionStatus,
    InvalidTargetError,
    UnsupportedActionError,
    action_summary,
    normalized_targets,
)
from aegis.mirror.breaker import BreakerState, CircuitBreaker, HealthSample
from aegis.mirror.executor import ExecutionError, Executor
from aegis.mirror.rpz import RPZAdapter, rpz_ip_owner
from aegis.mirror.webhook import WebhookAdapter, sign_webhook, verify_webhook_signature


class DryRunAdapter(EnforcementAdapter):
    """Shadow-mode adapter: records what *would* be enforced, changes nothing."""

    name = "dry_run"
    dry_run = True
    supported_actions = frozenset(ActionType)

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, dict[str, Any]] = {}
        self.operations: list[dict[str, Any]] = []

    def apply(self, action: ProposedAction, *, now: datetime) -> AdapterResult:
        self.check_supported(action)
        targets = normalized_targets(action)
        with self._lock:
            prior = self._active.get(action.action_id)
            self._active[action.action_id] = {"targets": targets,
                                              "action_type": action.action_type.value}
            self.operations.append({"op": "apply", "action_id": action.action_id,
                                    "targets": targets, "at": now.isoformat()})
        return AdapterResult(adapter=self.name, operation="apply", dry_run=True,
                             prior_state={"simulated": True, "entry": prior},
                             details={"would_enforce": action_summary(action)})

    def revert(self, action: ProposedAction, prior_state: dict[str, Any], *,
               now: datetime) -> AdapterResult:
        with self._lock:
            self._active.pop(action.action_id, None)
            entry = prior_state.get("entry") if isinstance(prior_state, dict) else None
            if isinstance(entry, dict):
                self._active[action.action_id] = entry
            self.operations.append({"op": "revert", "action_id": action.action_id,
                                    "at": now.isoformat()})
        return AdapterResult(adapter=self.name, operation="revert", dry_run=True)

    def active(self) -> dict[str, dict[str, Any]]:
        """Simulated enforcement currently in place, by action id."""
        with self._lock:
            return {k: dict(v) for k, v in self._active.items()}


__all__ = [
    "AdapterError", "AdapterResult", "BreakerState", "CircuitBreaker", "DryRunAdapter",
    "EnforcementAdapter", "ExecutionError", "ExecutionRecord", "ExecutionStatus", "Executor",
    "HealthSample", "InvalidTargetError", "RPZAdapter", "UnsupportedActionError",
    "WebhookAdapter", "rpz_ip_owner", "sign_webhook", "verify_webhook_signature",
]
