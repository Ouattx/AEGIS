"""Deterministic enforcement authorization (spec sections 9 and 12).

Implements, check for check::

    authorize(action) = signed_operator_policy
                    AND legal_basis_valid(action)
                    AND evidence_quality_pass(action)
                    AND mirror_result == SAFE
                    AND action.scope <= approved_scope
                    AND action.expires_at != null
                    AND rollback_plan_verified(action)

Every conjunct that fails is reported by name in ``failed_checks`` (all checks
are always evaluated, so an operator sees every reason at once). ``allowed`` is
True only when the list is empty. Nothing here consults a language model, and no
input can widen the policy: the policy is only trusted if its Ed25519 signature
verifies against the operator's key ring.

``signed_operator_policy`` expands to: policy present, signature valid, same
tenant, inside its validity window, ``mode == "active"`` (shadow-mode policies
never authorize a real change), a legal signoff reference (spec 12: no live
enforcement before written authorization and legal signoff), and the action
type among ``allowed_actions``.

``action.scope <= approved_scope`` expands to: target count within
``max_targets_per_action`` and every key of ``action.scope`` bounded by the
same key of ``approved_scope`` (numbers <=, lists subset, booleans may only
narrow, strings equal, dicts recursively). ``action.expires_at != null`` is
tightened to "set, in the future and within ``max_ttl_hours``".

Reserved ``approved_scope`` keys (never compared against ``action.scope``):

* ``legal_bases``: list of accepted ``legal_basis`` values;
* ``max_affected_entities``: ceiling on MIRROR's ``affected_entities``;
* ``auto_approve_actions``: action types that may run without a human approver
  when MIRROR reports no uncertainty at all. Absent => a human always approves.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from aegis.contracts.models import (
    AuthorizationDecision,
    MirrorResult,
    MirrorVerdict,
    OperatorPolicy,
    ProposedAction,
)
from aegis.mirror.base import InvalidTargetError, normalized_targets
from aegis.provenance.signing import KeyRing, verify_model

RESERVED_SCOPE_KEYS = frozenset({"legal_bases", "max_affected_entities", "auto_approve_actions"})

#: A MIRROR result older than this is stale: the world may have changed since.
DEFAULT_MAX_MIRROR_AGE = timedelta(hours=1)

#: The check names ``authorize`` can emit (stable identifiers for UI and tests).
CHECK_NAMES = (
    "policy_missing", "policy_signature_invalid", "policy_tenant_mismatch",
    "policy_not_yet_valid", "policy_expired", "policy_not_active_mode",
    "policy_missing_legal_signoff", "action_type_not_allowed",
    "legal_basis_missing", "legal_basis_not_approved",
    "evidence_quality_failed",
    "mirror_missing", "mirror_action_mismatch", "mirror_not_safe", "mirror_stale",
    "mirror_from_future",
    "targets_empty", "targets_invalid", "targets_exceed_max",
    "scope_reserved_key", "scope_key_not_approved", "scope_exceeds_approved",
    "affected_entities_unknown", "affected_entities_exceed_approved",
    "expires_at_missing", "expires_at_not_in_future", "expires_at_exceeds_max_ttl",
    "rollback_plan_missing", "rollback_not_verified",
)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def scope_violations(requested: Any, approved: Any, path: str = "") -> list[str]:
    """Paths where ``requested`` is not within ``approved`` (empty list => within).

    Semantics per type of the requested value:
    numbers (not bool): ``requested <= approved``; booleans: ``True`` only if
    approved is ``True``; strings: equal (or member when approved is a list);
    lists: subset of the approved list; dicts: recursively for each key.
    A key absent from the approved scope is a violation (default deny).
    """
    label = path or "<root>"
    if isinstance(requested, dict):
        if not isinstance(approved, dict):
            return [label]
        out: list[str] = []
        for k, v in requested.items():
            sub = f"{path}.{k}" if path else str(k)
            if k not in approved:
                out.append(f"missing:{sub}")
            else:
                out.extend(scope_violations(v, approved[k], sub))
        return out
    if isinstance(requested, bool):
        if not isinstance(approved, bool):
            return [label]
        return [label] if requested and not approved else []
    if isinstance(requested, (int, float)):
        if isinstance(approved, bool) or not isinstance(approved, (int, float)):
            return [label]
        return [label] if requested > approved else []
    if isinstance(requested, str):
        if isinstance(approved, list):
            return [] if requested in approved else [label]
        return [] if requested == approved else [label]
    if isinstance(requested, list):
        if not isinstance(approved, list):
            return [label]
        allowed = list(approved)
        return [] if all(r in allowed for r in requested) else [label]
    if requested is None:
        return []
    return [label]


def authorize(action: ProposedAction, policy: OperatorPolicy | None, keyring: KeyRing | None,
              mirror_result: MirrorResult | None, evidence_quality_ok: bool,
              now: datetime | None = None, *,
              max_mirror_age: timedelta = DEFAULT_MAX_MIRROR_AGE) -> AuthorizationDecision:
    """Evaluate every authorization conjunct for ``action``; see module docstring."""
    now = _utc(now) if now is not None else datetime.now(timezone.utc)
    failed: list[str] = []

    # -- signed_operator_policy -------------------------------------------------------
    policy_ok_for_scope = False
    if policy is None:
        failed.append("policy_missing")
    else:
        if keyring is None or not verify_model(policy, keyring):
            failed.append("policy_signature_invalid")
        else:
            policy_ok_for_scope = True
        if policy.tenant_id != action.tenant_id:
            failed.append("policy_tenant_mismatch")
        if now < _utc(policy.valid_from):
            failed.append("policy_not_yet_valid")
        if now >= _utc(policy.valid_until):
            failed.append("policy_expired")
        if policy.mode != "active":
            failed.append("policy_not_active_mode")
        if not (policy.legal_signoff_ref or "").strip():
            failed.append("policy_missing_legal_signoff")
        if action.action_type not in policy.allowed_actions:
            failed.append("action_type_not_allowed")

    # -- legal_basis_valid ------------------------------------------------------------
    basis = (action.legal_basis or "").strip()
    if not basis:
        failed.append("legal_basis_missing")
    elif policy is not None:
        bases = policy.approved_scope.get("legal_bases")
        if bases is not None and (not isinstance(bases, list) or basis not in bases):
            failed.append("legal_basis_not_approved")

    # -- evidence_quality_pass --------------------------------------------------------
    if evidence_quality_ok is not True:
        failed.append("evidence_quality_failed")

    # -- mirror_result == SAFE --------------------------------------------------------
    if mirror_result is None:
        failed.append("mirror_missing")
    else:
        if mirror_result.action_id != action.action_id:
            failed.append("mirror_action_mismatch")
        if mirror_result.verdict is not MirrorVerdict.SAFE:
            failed.append("mirror_not_safe")
        computed = _utc(mirror_result.computed_at)
        if computed > now:
            failed.append("mirror_from_future")
        elif now - computed > max_mirror_age:
            failed.append("mirror_stale")

    # -- action.scope <= approved_scope -----------------------------------------------
    if not action.targets:
        failed.append("targets_empty")
    try:
        targets = normalized_targets(action)
    except InvalidTargetError:
        failed.append("targets_invalid")
        targets = list(action.targets)
    if policy is not None:
        if len(targets) > policy.max_targets_per_action:
            failed.append("targets_exceed_max")
        reserved = RESERVED_SCOPE_KEYS & set(action.scope)
        if reserved:
            failed.append("scope_reserved_key")
        requested = {k: v for k, v in action.scope.items() if k not in RESERVED_SCOPE_KEYS}
        approved = {k: v for k, v in policy.approved_scope.items()
                    if k not in RESERVED_SCOPE_KEYS}
        violations = scope_violations(requested, approved)
        if any(v.startswith("missing:") for v in violations):
            failed.append("scope_key_not_approved")
        if any(not v.startswith("missing:") for v in violations):
            failed.append("scope_exceeds_approved")
        max_aff = policy.approved_scope.get("max_affected_entities")
        if max_aff is not None:
            aff = mirror_result.affected_entities if mirror_result is not None else None
            if aff is None:
                failed.append("affected_entities_unknown")
            elif isinstance(max_aff, bool) or not isinstance(max_aff, (int, float)) \
                    or aff > max_aff:
                failed.append("affected_entities_exceed_approved")
    elif not policy_ok_for_scope:
        # without a policy there is no approved scope; scope check fails closed
        failed.append("scope_exceeds_approved")

    # -- action.expires_at != null (bounded by policy TTL) ----------------------------
    if action.expires_at is None:
        failed.append("expires_at_missing")
    else:
        exp = _utc(action.expires_at)
        if exp <= now:
            failed.append("expires_at_not_in_future")
        if policy is not None and exp - now > timedelta(hours=policy.max_ttl_hours):
            failed.append("expires_at_exceeds_max_ttl")

    # -- rollback_plan_verified -------------------------------------------------------
    if not (action.rollback_plan or "").strip():
        failed.append("rollback_plan_missing")
    if action.rollback_verified is not True:
        failed.append("rollback_not_verified")

    failed = list(dict.fromkeys(failed))
    return AuthorizationDecision(
        action_id=action.action_id,
        allowed=not failed,
        failed_checks=failed,
        requires_human_approval=requires_human_approval(action, policy, mirror_result),
        evaluated_at=now,
        policy_id=policy.policy_id if policy is not None else None,
    )


def requires_human_approval(action: ProposedAction, policy: OperatorPolicy | None,
                            mirror_result: MirrorResult | None) -> bool:
    """Human approval rule: required unless collateral is provably nil and policy opts out.

    Shared hosting, any legitimate co-tenant, any MIRROR unknown, a non-SAFE
    verdict, an unknown affected-entity count, or MIRROR's own flag => required.
    Otherwise required unless the action type is in the policy's
    ``auto_approve_actions``.
    """
    if mirror_result is None or policy is None:
        return True
    if (mirror_result.verdict is not MirrorVerdict.SAFE or mirror_result.requires_human_approval
            or mirror_result.shared_infrastructure or mirror_result.legitimate_cotenants
            or mirror_result.unknowns or mirror_result.affected_entities is None
            or mirror_result.historic_daily_legit_flows is None):
        return True
    auto = policy.approved_scope.get("auto_approve_actions")
    if not isinstance(auto, list):
        return True
    return action.action_type.value not in [str(getattr(a, "value", a)) for a in auto]
