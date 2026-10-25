from __future__ import annotations

from datetime import timedelta

import pytest
from test_mirror_helpers import T0, action, policy, safe_mirror, signer_and_ring

from aegis.contracts.models import ActionType, MirrorVerdict
from aegis.mirror import CHECK_NAMES, authorize, scope_violations
from aegis.provenance.signing import KeyRing


@pytest.fixture
def keys():
    return signer_and_ring()


def run(keys, act=None, pol=None, mirror="safe", eq=True, now=T0, **pol_kw):
    signer, ring = keys
    act = act or action()
    pol = pol if pol is not None else policy(signer, **pol_kw)
    m = safe_mirror(act) if mirror == "safe" else mirror
    return authorize(act, pol, ring, m, eq, now)


def test_all_checks_pass(keys):
    act = action()
    d = run(keys, act)
    assert d.allowed is True
    assert d.failed_checks == []
    assert d.action_id == act.action_id
    assert d.policy_id == "pol-1"
    assert d.evaluated_at == T0
    # no auto-approval configured => a human still approves
    assert d.requires_human_approval is True


def test_check_names_are_declared(keys):
    _signer, _ring = keys
    act = action(legal_basis=None, expires_at=None, rollback_plan=None, rollback_verified=False,
                 targets=[], scope={"unknown": 1, "legal_bases": ["x"]})
    d = authorize(act, None, None, None, False, T0)
    assert not d.allowed
    for c in d.failed_checks:
        assert c in CHECK_NAMES, c


def test_missing_policy(keys):
    _signer, ring = keys
    d = authorize(action(), None, ring, safe_mirror(action()), True, T0)
    assert "policy_missing" in d.failed_checks
    assert d.requires_human_approval is True
    assert d.policy_id is None


def test_tampered_policy_signature(keys):
    signer, _ring = keys
    pol = policy(signer).model_copy(update={"max_targets_per_action": 1000})
    d = run(keys, pol=pol)
    assert d.failed_checks == ["policy_signature_invalid"]


def test_unknown_or_revoked_key(keys):
    signer, ring = keys
    other, _ = signer_and_ring("rogue")
    d = run(keys, pol=policy(other))
    assert "policy_signature_invalid" in d.failed_checks
    ring.revoke(signer.key_id)
    d2 = run(keys)
    assert "policy_signature_invalid" in d2.failed_checks
    d3 = authorize(action(), policy(signer), None, safe_mirror(action()), True, T0)
    assert "policy_signature_invalid" in d3.failed_checks


def test_policy_validity_window(keys):
    d = run(keys, now=T0 + timedelta(days=31), act=action(expires_at=T0 + timedelta(days=31, hours=1)))
    assert "policy_expired" in d.failed_checks
    d2 = run(keys, valid_from=T0 + timedelta(hours=1))
    assert d2.failed_checks == ["policy_not_yet_valid"]


def test_expired_authorization_prevents_action(keys):
    """Spec 15: expired authorization prevents action."""
    signer, ring = keys
    act = action(expires_at=T0 + timedelta(hours=1))
    pol = policy(signer, valid_until=T0 + timedelta(hours=2))
    later = T0 + timedelta(hours=3)
    d = authorize(act, pol, ring, safe_mirror(act, computed_at=later), True, later)
    assert not d.allowed
    assert {"policy_expired", "expires_at_not_in_future"} <= set(d.failed_checks)


def test_shadow_mode_never_allows(keys):
    d = run(keys, mode="shadow")
    assert d.failed_checks == ["policy_not_active_mode"]
    assert not d.allowed


def test_legal_signoff_required(keys):
    d = run(keys, legal_signoff_ref=None)
    assert d.failed_checks == ["policy_missing_legal_signoff"]
    d2 = run(keys, legal_signoff_ref="   ")
    assert d2.failed_checks == ["policy_missing_legal_signoff"]


def test_tenant_mismatch(keys):
    d = run(keys, tenant_id="isp-b")
    assert d.failed_checks == ["policy_tenant_mismatch"]


def test_action_type_must_be_allowed(keys):
    d = run(keys, act=action(ActionType.DEVICE_QUARANTINE, ["p_abcdef123456"]))
    assert "action_type_not_allowed" in d.failed_checks


def test_legal_basis(keys):
    assert run(keys, act=action(legal_basis=None)).failed_checks == ["legal_basis_missing"]
    assert run(keys, act=action(legal_basis="because")).failed_checks == ["legal_basis_not_approved"]
    signer, _ = keys
    scope = {"include_subdomains": False}
    d = run(keys, pol=policy(signer, approved_scope=scope), act=action(legal_basis="anything"))
    assert d.allowed  # no legal_bases list configured: any non-empty basis accepted


def test_evidence_quality(keys):
    assert run(keys, eq=False).failed_checks == ["evidence_quality_failed"]
    # only the literal True passes
    assert "evidence_quality_failed" in run(keys, eq=1).failed_checks  # type: ignore[arg-type]


@pytest.mark.parametrize("verdict", [MirrorVerdict.UNSAFE, MirrorVerdict.UNKNOWN])
def test_mirror_must_be_safe(keys, verdict):
    act = action()
    d = run(keys, act=act, mirror=safe_mirror(act, verdict=verdict))
    assert d.failed_checks == ["mirror_not_safe"]
    assert d.requires_human_approval


def test_mirror_missing_mismatch_stale_future(keys):
    act = action()
    assert run(keys, act=act, mirror=None).failed_checks == ["mirror_missing"]
    other = action()
    assert run(keys, act=act, mirror=safe_mirror(other)).failed_checks == ["mirror_action_mismatch"]
    stale = safe_mirror(act, computed_at=T0 - timedelta(hours=2))
    assert run(keys, act=act, mirror=stale).failed_checks == ["mirror_stale"]
    future = safe_mirror(act, computed_at=T0 + timedelta(minutes=5))
    assert run(keys, act=act, mirror=future).failed_checks == ["mirror_from_future"]


def test_targets_limits(keys):
    many = action(targets=[f"bad{i}.example" for i in range(4)])
    assert run(keys, act=many).failed_checks == ["targets_exceed_max"]
    assert "targets_empty" in run(keys, act=action(targets=[])).failed_checks
    assert "targets_invalid" in run(keys, act=action(targets=["x y.example"])).failed_checks
    # duplicates collapse before counting
    dup = action(targets=["a.example", "A.example.", "b.example", "c.example"])
    assert run(keys, act=dup).allowed


def test_scope_within_approved(keys):
    ok = action(scope={"max_entities": 5, "regions": ["paris"], "include_subdomains": False})
    assert run(keys, act=ok).allowed
    wider = action(scope={"max_entities": 50})
    assert run(keys, act=wider).failed_checks == ["scope_exceeds_approved"]
    region = action(scope={"regions": ["paris", "marseille"]})
    assert run(keys, act=region).failed_checks == ["scope_exceeds_approved"]
    wildcard = action(scope={"include_subdomains": True})
    assert run(keys, act=wildcard).failed_checks == ["scope_exceeds_approved"]
    unknown = action(scope={"asn": 64700})
    assert run(keys, act=unknown).failed_checks == ["scope_key_not_approved"]
    reserved = action(scope={"legal_bases": ["anything"]})
    assert "scope_reserved_key" in run(keys, act=reserved).failed_checks


def test_scope_violations_semantics():
    assert scope_violations({}, {}) == []
    assert scope_violations({"a": 1}, {"a": 1.5}) == []
    assert scope_violations({"a": 2}, {"a": 1}) == ["a"]
    assert scope_violations({"a": True}, {"a": False}) == ["a"]
    assert scope_violations({"a": False}, {"a": True}) == []
    assert scope_violations({"a": 1}, {"a": True}) == ["a"]
    assert scope_violations({"a": True}, {"a": 1}) == ["a"]
    assert scope_violations({"r": "paris"}, {"r": ["paris", "lyon"]}) == []
    assert scope_violations({"r": "nice"}, {"r": "paris"}) == ["r"]
    assert scope_violations({"d": {"x": 1}}, {"d": {"x": 2}}) == []
    assert scope_violations({"d": {"y": 1}}, {"d": {"x": 2}}) == ["missing:d.y"]
    assert scope_violations({"l": [1, 2]}, {"l": 3}) == ["l"]
    assert scope_violations({"n": None}, {"n": 1}) == []


def test_max_affected_entities(keys):
    signer, _ = keys
    scope = {"max_affected_entities": 5, "legal_bases": ["operator_tos_security_clause"]}
    act = action()
    assert run(keys, act=act, pol=policy(signer, approved_scope=scope)).allowed
    big = safe_mirror(act, affected_entities=50)
    d = run(keys, act=act, pol=policy(signer, approved_scope=scope), mirror=big)
    assert d.failed_checks == ["affected_entities_exceed_approved"]
    unknown = safe_mirror(act, affected_entities=None)
    d2 = run(keys, act=act, pol=policy(signer, approved_scope=scope), mirror=unknown)
    assert d2.failed_checks == ["affected_entities_unknown"]


def test_expiry_checks(keys):
    assert run(keys, act=action(expires_at=None)).failed_checks == ["expires_at_missing"]
    assert run(keys, act=action(expires_at=T0)).failed_checks == ["expires_at_not_in_future"]
    long = action(expires_at=T0 + timedelta(hours=25))
    assert run(keys, act=long).failed_checks == ["expires_at_exceeds_max_ttl"]


def test_rollback_checks(keys):
    assert run(keys, act=action(rollback_plan=None)).failed_checks == ["rollback_plan_missing"]
    assert run(keys, act=action(rollback_verified=False)).failed_checks == ["rollback_not_verified"]


def test_all_failures_reported_together(keys):
    signer, ring = keys
    act = action(legal_basis=None, expires_at=None, rollback_verified=False)
    pol = policy(signer, mode="shadow")
    d = authorize(act, pol, ring, safe_mirror(act, verdict=MirrorVerdict.UNKNOWN), False, T0)
    assert set(d.failed_checks) == {"policy_not_active_mode", "legal_basis_missing",
                                    "evidence_quality_failed", "mirror_not_safe",
                                    "expires_at_missing", "rollback_not_verified"}


# ------------------------------------------------------------------ human approval

def _auto_policy(signer):
    return policy(signer, approved_scope={"auto_approve_actions": ["dns_sinkhole"],
                                          "legal_bases": ["operator_tos_security_clause"]})


def test_auto_approval_only_when_collateral_provably_nil(keys):
    signer, ring = keys
    act = action()
    d = authorize(act, _auto_policy(signer), ring, safe_mirror(act), True, T0)
    assert d.allowed and d.requires_human_approval is False


@pytest.mark.parametrize("update", [
    {"shared_infrastructure": True},
    {"legitimate_cotenants": ["www.news.example"]},
    {"unknowns": ["traffic_history_unavailable"]},
    {"requires_human_approval": True},
    {"affected_entities": None},
    {"historic_daily_legit_flows": None},
])
def test_uncertain_collateral_requires_human(keys, update):
    signer, ring = keys
    act = action()
    d = authorize(act, _auto_policy(signer), ring, safe_mirror(act, **update), True, T0)
    assert d.requires_human_approval is True


def test_auto_approval_scoped_to_action_type(keys):
    signer, ring = keys
    act = action(ActionType.IP_BLOCK, ["203.0.113.10"])
    d = authorize(act, _auto_policy(signer), ring, safe_mirror(act), True, T0)
    assert d.allowed and d.requires_human_approval is True


def test_naive_datetimes_are_treated_as_utc(keys):
    signer, ring = keys
    act = action()
    d = authorize(act, policy(signer), ring, safe_mirror(act), True, T0.replace(tzinfo=None))
    assert d.allowed


def test_keyring_type(keys):
    signer, _ = keys
    assert "policy_signature_invalid" in authorize(
        action(), policy(signer), KeyRing(), safe_mirror(action()), True, T0).failed_checks
