"""Shared MIRROR types: adapter protocol, execution records and target validation.

An *adapter* is the only component that touches an enforcement point (RPZ zone,
firewall, walled-garden webhook...). Adapters are dumb on purpose: they never
decide anything. The :class:`aegis.mirror.executor.Executor` checks the
authorization decision and the human approval, writes the provenance ledger, and
only then calls the adapter. Every adapter must be able to undo what it applied
from the ``prior_state`` it returned, so a rollback restores service exactly.
"""
from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis.contracts.models import ActionType, ProposedAction, new_id


class AdapterError(RuntimeError):
    """An enforcement point refused or failed an operation."""


class UnsupportedActionError(AdapterError):
    """The adapter cannot enforce this action type."""


class InvalidTargetError(AdapterError, ValueError):
    """A target is syntactically invalid for the action type (never sent anywhere)."""


class AdapterResult(BaseModel):
    """Outcome of one adapter operation.

    ``prior_state`` is a JSON-serializable snapshot of what the enforcement point
    looked like before ``apply``; the executor persists it in the ledger and hands
    it back to ``revert``.
    """
    model_config = ConfigDict(extra="forbid")

    adapter: str
    operation: Literal["apply", "revert"]
    dry_run: bool = False
    prior_state: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)


class EnforcementAdapter(ABC):
    """Interface every enforcement adapter implements."""

    #: Short identifier written to the ledger.
    name: str = "adapter"
    #: True when the adapter never changes any real system (shadow mode).
    dry_run: bool = False
    #: Action types this adapter can enforce.
    supported_actions: frozenset[ActionType] = frozenset()

    def supports(self, action_type: ActionType) -> bool:
        return action_type in self.supported_actions

    def check_supported(self, action: ProposedAction) -> None:
        if not self.supports(action.action_type):
            raise UnsupportedActionError(
                f"{self.name} adapter does not support {action.action_type.value}")

    @abstractmethod
    def apply(self, action: ProposedAction, *, now: datetime) -> AdapterResult:
        """Enforce ``action``; return the prior state needed to undo it."""

    @abstractmethod
    def revert(self, action: ProposedAction, prior_state: dict[str, Any], *,
               now: datetime) -> AdapterResult:
        """Restore the enforcement point to ``prior_state`` for ``action``."""


class ExecutionStatus(str, Enum):
    APPLIED = "applied"            # enforcement is live
    DRY_RUN = "dry_run"            # simulated in shadow mode; nothing changed
    REFUSED = "refused"            # executor refused; adapter never called
    FAILED = "failed"              # adapter raised; enforcement point unchanged or restored
    ROLLED_BACK = "rolled_back"    # enforcement removed, prior state restored
    ROLLBACK_FAILED = "rollback_failed"


class ExecutionRecord(BaseModel):
    """One executor operation (execute or rollback), mirrored in the ledger."""
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(default_factory=new_id)
    tenant_id: str
    action_id: str
    case_id: str
    operation: Literal["execute", "rollback"]
    status: ExecutionStatus
    adapter: str
    dry_run: bool = False
    actor: str                                  # approver (execute) or rollback actor
    reason: str = ""
    refusal_reasons: list[str] = Field(default_factory=list)
    policy_id: str | None = None
    prior_state: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)
    at: datetime
    ledger_entry_hash: str | None = None


def is_human(actor: str | None) -> bool:
    """A human actor: non-empty and not an agent (``agent:*``) or system identity."""
    if not isinstance(actor, str):
        return False
    a = actor.strip().lower()
    return bool(a) and not a.startswith("agent:") and not a.startswith("system")


# --------------------------------------------------------------------------- targets

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_PSEUDONYM = re.compile(r"^p_[A-Za-z0-9_-]{8,128}$")


def normalize_domain(value: str) -> str:
    """Canonical lower-case domain; raises :class:`InvalidTargetError` when invalid.

    Strict on purpose: targets end up in zone files and firewall configs, so
    anything that could inject syntax (whitespace, ``;``, wildcards, quotes) is
    rejected rather than escaped.
    """
    if not isinstance(value, str):
        raise InvalidTargetError("domain must be a string")
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > 253:
        raise InvalidTargetError(f"invalid domain {value!r}")
    labels = v.split(".")
    if len(labels) < 2 or not all(_LABEL.match(lbl) for lbl in labels):
        raise InvalidTargetError(f"invalid domain {value!r}")
    if v.endswith((".rpz-ip", ".rpz-nsip", ".rpz-nsdname")):
        raise InvalidTargetError(f"reserved RPZ name {value!r}")
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return v
    raise InvalidTargetError(f"{value!r} is an IP address, not a domain")


def normalize_ip(value: str) -> str:
    """Canonical compressed IP address; networks are not accepted (one host only)."""
    if not isinstance(value, str):
        raise InvalidTargetError("IP must be a string")
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError as exc:
        raise InvalidTargetError(f"invalid IP address {value!r}") from exc


def normalize_pseudonym(value: str) -> str:
    if not isinstance(value, str) or not _PSEUDONYM.match(value.strip()):
        raise InvalidTargetError(f"invalid entity pseudonym {value!r} (expected 'p_...')")
    return value.strip()


def normalize_target(action_type: ActionType, value: str) -> str:
    """Validate one target for ``action_type`` and return its canonical form."""
    if action_type is ActionType.DNS_SINKHOLE:
        return normalize_domain(value)
    if action_type is ActionType.IP_BLOCK:
        return normalize_ip(value)
    return normalize_pseudonym(value)


def normalized_targets(action: ProposedAction) -> list[str]:
    """Canonical, de-duplicated targets (order preserved); raises on any invalid one."""
    return list(dict.fromkeys(normalize_target(action.action_type, t) for t in action.targets))


def action_summary(action: ProposedAction) -> dict[str, Any]:
    """Ledger-friendly summary of an action."""
    return {
        "action_id": action.action_id,
        "case_id": action.case_id,
        "action_type": action.action_type.value,
        "targets": list(action.targets),
        "scope": action.scope,
        "legal_basis": action.legal_basis,
        "authorization_id": action.authorization_id,
        "expires_at": action.expires_at.isoformat() if action.expires_at else None,
        "rollback_plan": action.rollback_plan,
        "rollback_verified": action.rollback_verified,
        "created_by": action.created_by,
    }
