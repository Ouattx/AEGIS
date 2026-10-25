"""Spec section 15 mandatory tests on the enforcement path (real composed system).

The ``enforcement`` world runs a signed **active** operator policy with a legal
sign-off reference and a real RPZ adapter: these tests show that even when
enforcement is switched on, nothing is enforced unless every deterministic gate
holds, and that what was enforced can be undone. Each test claims its own case.
"""
from __future__ import annotations

import shutil
from datetime import timedelta

import pytest

from aegis.contracts.models import ActionType, CaseState, EvidenceKind, MirrorVerdict, OperatorPolicy, ProposedAction
from aegis.lab.iocs import lab_signer
from aegis.mirror.authorize import authorize
from aegis.mirror.base import ExecutionStatus
from aegis.mirror.rpz import RPZAdapter, rpz_ip_owner
from aegis.oracle.state_machine import GuardError
from aegis.oracle.tools import AgentName, ReadTool, ScopeViolation
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.model import load_default
from aegis.service import AegisService, AuthorizationRecord, ConflictError, InvalidInputError, MirrorRecord

from safety_kit import (
    LEGAL_BASIS,
    World,
    active_policy,
    case_indicators,
    claim_verified_case,
    make_settings,
    propose,
    safe_sinkhole,
    zone_owners,
)

pytestmark = pytest.mark.safety

APPROVER = "approver.bob"


def _enforced(world: World, target: str) -> bool:
    return any(owner == target or owner.endswith("." + target) for owner in zone_owners(world))


def _authorize_and_approve(world: World, action_id: str) -> None:
    out = world.svc.authorize_action(world.tenant, "analyst.alice", action_id)
    assert out["decision"].allowed is True, out["decision"].failed_checks
    case = world.svc.decide_action(world.tenant, APPROVER, action_id, approve=True, reason="collateral reviewed")
    assert case.state is CaseState.APPROVED


# ============================================================================ shared CDN


def test_shared_cdn_not_indiscriminately_blocked(enforcement: World) -> None:
    """Blocking the shared CDN address behind a C2 name is UNSAFE and refused at every gate;
    the precise alternative (sinkhole only the malicious name) is allowed."""
    w = enforcement
    shared_c2 = next(d for d in w.corpus.malicious_devices() if d.c2_on_shared_infra)
    domain = shared_c2.c2_domain
    assert domain is not None
    case_id = next(cid for cid in w.case_pool if domain in case_indicators(w, cid))
    w.case_pool.remove(case_id)
    w.case_pool.insert(0, case_id)
    case_id = claim_verified_case(w)
    cdn_ip = next(ip for ip, h in w.corpus.topology.hosts.items() if domain in h.hostnames)
    assert len(w.corpus.topology.hosts[cdn_ip].hostnames) > 5  # many legitimate co-tenants

    block = propose(w, case_id, [cdn_ip], action_type="ip_block")
    precise = propose(w, case_id, [domain])
    sim = w.svc.simulate_action(w.tenant, "analyst.alice", block)
    assert sim.verdict is MirrorVerdict.UNSAFE
    assert sim.shared_infrastructure and len(sim.legitimate_cotenants) >= 5 and sim.requires_human_approval
    out = w.svc.authorize_action(w.tenant, "analyst.alice", block)
    assert out["decision"].allowed is False and "mirror_not_safe" in out["decision"].failed_checks
    assert out["case_state"] == "PROPOSED"
    with pytest.raises(ConflictError) as ei:
        w.svc.decide_action(w.tenant, APPROVER, block, approve=True, reason="block it all")
    assert "authorization_not_allowed" in ei.value.failed
    r = w.client.post(f"/api/v1/actions/{block}/execute", json={"reason": "go"}, headers=w.h("approver", sub=APPROVER))
    assert r.status_code == 409
    record = w.svc.docs.get(AuthorizationRecord, w.tenant, block)
    assert record is not None
    rec = w.svc.executor.execute(w.svc.get_action(w.tenant, block), record.decision, APPROVER)
    assert rec.status is ExecutionStatus.REFUSED and "failed_check:mirror_not_safe" in rec.refusal_reasons
    assert rpz_ip_owner(cdn_ip) not in zone_owners(w)

    # the precise, name-level action is SAFE and authorized under the same policy
    assert w.svc.simulate_action(w.tenant, "analyst.alice", precise).verdict is MirrorVerdict.SAFE
    ok = w.svc.authorize_action(w.tenant, "analyst.alice", precise)
    assert ok["decision"].allowed is True, ok["decision"].failed_checks
    assert rpz_ip_owner(cdn_ip) not in zone_owners(w)


# ============================================================================ expiry


def test_expired_authorization_prevents_action(enforcement: World) -> None:
    """An approved action whose expiry passed, or whose policy expired, is never executed."""
    w = enforcement
    try:
        # 1. the approved action itself expires before execution
        case_id = claim_verified_case(w)
        action_id, target = safe_sinkhole(w, case_id)
        action = w.svc.get_action(w.tenant, action_id)
        assert action.expires_at is not None
        _authorize_and_approve(w, action_id)
        w.clock.advance(action.expires_at - w.svc.clock() + timedelta(minutes=5))
        assert w.svc.simulate_action(w.tenant, "analyst.alice", action_id).verdict is MirrorVerdict.SAFE  # fresh
        with pytest.raises(ConflictError) as ei:
            w.svc.execute_action(w.tenant, APPROVER, action_id, reason="late")
        assert "expires_at_not_in_future" in ei.value.failed or "action_expired" in ei.value.failed
        assert not _enforced(w, target)
        refused = w.svc.ledger.entries(w.tenant, subject_id=action_id, entry_type="execution_refused")
        assert refused and refused[-1].payload["failed_checks"] == ei.value.failed
        assert case_id in w.svc.sweep_expired()
        assert w.svc.get_case(w.tenant, case_id).state is CaseState.EXPIRED
        w.clock.reset()

        # 2. the signed operator policy expires between approval and execution
        case_id = claim_verified_case(w)
        action_id, target = safe_sinkhole(w, case_id)
        _authorize_and_approve(w, action_id)
        w.clock.advance(timedelta(days=31))
        actives = [p for p in w.svc.list_policies(w.tenant) if p["policy"]["mode"] == "active"]
        assert actives and all(p["valid_now"] is False for p in actives)
        w.svc.simulate_action(w.tenant, "analyst.alice", action_id)
        with pytest.raises(ConflictError) as ei:
            w.svc.execute_action(w.tenant, APPROVER, action_id, reason="after policy expiry")
        assert "authorization_not_allowed" in ei.value.failed
        record = w.svc.docs.get(AuthorizationRecord, w.tenant, action_id)
        assert record is not None
        decision = record.decision
        assert not decision.allowed and decision.policy_id != w.active_policy_id  # only shadow policy remains
        policy = w.svc.docs.get(OperatorPolicy, w.tenant, w.active_policy_id or "")
        mirror = w.svc.docs.get(MirrorRecord, w.tenant, action_id)
        assert policy is not None and mirror is not None
        explicit = authorize(w.svc.get_action(w.tenant, action_id), policy, w.svc.policy_keyring, mirror.result,
                             True, w.svc.clock())
        assert not explicit.allowed and "policy_expired" in explicit.failed_checks
        rec = w.svc.executor.execute(w.svc.get_action(w.tenant, action_id), decision, APPROVER)
        assert rec.status is ExecutionStatus.REFUSED and "action_expired" in rec.refusal_reasons
        assert not _enforced(w, target)
        assert w.svc.metrics_summary(w.tenant)["actions"]["live_enforcements"] == 0
    finally:
        w.clock.reset()


# ============================================================================ rollback


def test_rollback_restores_service(enforcement: World) -> None:
    """An executed sinkhole is removed from the resolver zone by an operator rollback, and
    automatically when the circuit breaker sees legitimate traffic failing."""
    w = enforcement
    zone_before = zone_owners(w)

    case_id = claim_verified_case(w)
    action_id, target = safe_sinkhole(w, case_id)
    _authorize_and_approve(w, action_id)
    r = w.client.post(f"/api/v1/actions/{action_id}/execute", json={"reason": "contain C2"},
                      headers=w.h("approver", sub=APPROVER))
    assert r.status_code == 200, r.text
    assert r.json()["execution"]["status"] == "applied" and r.json()["case_state"] == "EXECUTED"
    assert _enforced(w, target) and target in w.rpz.zone_path.read_text()
    assert action_id in w.svc.executor.active()

    r = w.client.post(f"/api/v1/actions/{action_id}/rollback", json={"reason": "customer impact drill"},
                      headers=w.h("approver", sub=APPROVER))
    assert r.status_code == 200, r.text
    assert r.json()["execution"]["status"] == "rolled_back" and r.json()["case_state"] == "ROLLED_BACK"
    assert not _enforced(w, target) and target not in w.rpz.zone_path.read_text()
    assert zone_owners(w) == zone_before
    assert action_id not in w.svc.executor.active()
    assert [e.status for e in w.svc.execution_records(w.tenant, action_id)] == [
        ExecutionStatus.APPLIED, ExecutionStatus.ROLLED_BACK]
    # idempotent: a second rollback changes nothing
    again = w.client.post(f"/api/v1/actions/{action_id}/rollback", json={"reason": "retry"},
                          headers=w.h("approver", sub=APPROVER))
    assert again.status_code == 200 and not _enforced(w, target)

    # automatic rollback when legitimate traffic breaks (circuit breaker)
    case_id = claim_verified_case(w)
    action_id, target = safe_sinkhole(w, case_id)
    _authorize_and_approve(w, action_id)
    out = w.svc.execute_action(w.tenant, APPROVER, action_id, reason="contain C2")
    assert out["execution"].status is ExecutionStatus.APPLIED and _enforced(w, target)
    try:
        assert w.svc.report_legit_traffic(w.tenant, action_id, requests=200, errors=2)["tripped"] is False
        res = w.svc.report_legit_traffic(w.tenant, action_id, requests=1000, errors=400)
        assert res["tripped"] is True and res["live"] is False
        assert not _enforced(w, target) and zone_owners(w) == zone_before
        case = w.svc.get_case(w.tenant, case_id)
        assert case.state is CaseState.ROLLED_BACK and case.decisions[-1].actor == "system:circuit_breaker"
        # while the breaker is open nothing else can be enforced
        assert w.svc.breaker.is_open
    finally:
        w.svc.breaker.reset("noc.oncall", "incident reviewed; breaker closed after rollback drill")
    assert w.svc.verify_ledger(w.tenant)["ok"] is True


# ============================================================================ compromised agent


def test_compromised_agent_cannot_alter_policy(enforcement: World) -> None:
    """An ORACLE agent (or anything acting as one) cannot change policy, case state, approvals
    or enforcement, whatever it writes."""
    w = enforcement
    svc, tenant = w.svc, w.tenant
    policies_before = [(p["policy"]["policy_id"], p["policy"]["mode"], p["policy"]["signature"])
                       for p in svc.list_policies(tenant)]
    trusted_before = svc.policy_keyring.key_ids()
    case_id = claim_verified_case(w)
    case = svc.get_case(tenant, case_id)

    # 1. agents never change case state
    for to in (CaseState.CLOSED, CaseState.PROPOSED):
        with pytest.raises(GuardError) as gi:
            svc.cases.transition(tenant, case_id, to, AgentName.VERIFIER.actor, "agent decided")
        assert gi.value.failed == ["agent_cannot_change_case_state"]

    # 2. an agent-forged or tampered policy never loads
    rogue = Signer.generate("agent-rogue-key")
    forged = active_policy(svc, tenant, rogue, policy_id="agent-forged-active")
    with pytest.raises(InvalidInputError) as ii:
        svc.load_policy(tenant, AgentName.POLICY_CHECKER.actor, forged)
    assert "policy_signature_invalid" in ii.value.failed
    shadow = next(p["policy"] for p in svc.list_policies(tenant) if p["policy"]["mode"] == "shadow")
    tampered = dict(shadow, policy_id="tampered-to-active", mode="active", legal_signoff_ref="FORGED")
    with pytest.raises(InvalidInputError):
        svc.load_policy(tenant, AgentName.POLICY_CHECKER.actor, tampered)
    r = w.client.post("/api/v1/policies", json=forged, headers=w.h("integration", sub="agent-runtime"))
    assert r.status_code == 403

    # 3. tools stay read-only and scoped to their agent
    with pytest.raises(ScopeViolation):
        svc.toolset.register(ReadTool(name="set_policy_mode", agent=AgentName.POLICY_CHECKER,
                                      description="flip mode", fn=lambda c, a: {}))
    with pytest.raises(ScopeViolation):
        svc.toolset.scope(AgentName.POLICY_CHECKER, case).tool("case_evidence")
    with pytest.raises(ScopeViolation):
        svc.toolset.scope(AgentName.EVIDENCE_COLLECTOR, case).writer().append(
            kind=EvidenceKind.IOC_MATCH, origin_source="agent", source_group="agent", summary="fake hit",
            payload={"signed_bundle_verified": True}, authorization_id="x", supports=True)
    assert not hasattr(svc.toolset.scope(AgentName.RESPONSE_PLANNER, case).writer(), "approve")

    # 4. a draft from the response planner is stripped of authority and never authorizable
    legit_id, legit_target = safe_sinkhole(w, case_id)  # a genuine human proposal (case still VERIFIED)
    writer = svc.toolset.scope(AgentName.RESPONSE_PLANNER, case).writer()
    draft = writer.propose(ProposedAction(tenant_id=tenant, case_id=case_id, action_type=ActionType.DNS_SINKHOLE,
                                          targets=[legit_target], scope={"max_entities": 1}, legal_basis=LEGAL_BASIS,
                                          authorization_id="forged-authorization", rollback_verified=True,
                                          expires_at=svc.clock() + timedelta(hours=6), created_by="analyst.alice",
                                          created_at=svc.clock()))
    assert draft.rollback_verified is False and draft.authorization_id is None
    assert draft.created_by == AgentName.RESPONSE_PLANNER.actor
    svc.simulate_action(tenant, "analyst.alice", draft.action_id)
    out = svc.authorize_action(tenant, "analyst.alice", draft.action_id)
    assert out["decision"].allowed is False and "rollback_not_verified" in out["decision"].failed_checks
    with pytest.raises(ConflictError):
        svc.decide_action(tenant, APPROVER, draft.action_id, approve=True, reason="approve the agent draft")

    # 5. agents can neither approve nor execute, even a fully authorized human proposal
    allowed = svc.authorize_action(tenant, "analyst.alice", legit_id)["decision"]
    assert allowed.allowed is True
    with pytest.raises(ConflictError) as ci:
        svc.decide_action(tenant, AgentName.POLICY_CHECKER.actor, legit_id, approve=True, reason="agent approves")
    assert {"approval_requires_human_approver", "agent_cannot_change_case_state"} & set(ci.value.failed)
    rec = svc.executor.execute(svc.get_action(tenant, legit_id), allowed, AgentName.RESPONSE_PLANNER.actor)
    assert rec.status is ExecutionStatus.REFUSED and "agent_cannot_execute" in rec.refusal_reasons
    with pytest.raises(ConflictError):
        svc.execute_action(tenant, AgentName.RESPONSE_PLANNER.actor, legit_id)
    assert not _enforced(w, legit_target)

    # nothing about policy or trust changed
    assert [(p["policy"]["policy_id"], p["policy"]["mode"], p["policy"]["signature"])
            for p in svc.list_policies(tenant)] == policies_before
    assert svc.policy_keyring.key_ids() == trusted_before
    assert svc.get_case(tenant, case_id).state is CaseState.PROPOSED  # moved only by the human analyst


# ============================================================================ key revocation


def test_revoked_signing_key_rejected(enforcement: World) -> None:
    """Revoking a compromised key immediately stops everything it signed, survives a restart,
    and cannot be undone by re-trusting the key.

    Runs on a restarted copy of the enforcement deployment (same database, keys and zone),
    so the revocation does not leak into other tests.
    """
    w = enforcement
    case_id = claim_verified_case(w)
    action_id, target = safe_sinkhole(w, case_id)
    _authorize_and_approve(w, action_id)

    copy_dir = w.tmp.parent / (w.tmp.name + "-restarted")
    shutil.copytree(w.tmp, copy_dir)
    svc = AegisService(make_settings(copy_dir, enforcement_tenant=w.tenant), model=load_default(),
                       adapter=RPZAdapter(copy_dir / "enforcement" / "aegis.rpz"), use_env_llm=False)
    try:
        tenant = w.tenant
        assert svc.get_case(tenant, case_id).state is CaseState.APPROVED  # restored from storage
        assert w.operator is not None
        operator_key = w.operator.key_id
        out = svc.revoke_key("policy", operator_key, actor="secops.carol", reason="operator HSM compromise")
        assert operator_key in out["revoked"]

        # 1. the approved action can no longer be executed
        svc.simulate_action(tenant, "analyst.alice", action_id)
        with pytest.raises(ConflictError) as ei:
            svc.execute_action(tenant, APPROVER, action_id, reason="after revocation")
        assert "authorization_not_allowed" in ei.value.failed
        record = svc.docs.get(AuthorizationRecord, tenant, action_id)
        policy = svc.docs.get(OperatorPolicy, tenant, w.active_policy_id or "")
        mirror = svc.docs.get(MirrorRecord, tenant, action_id)
        assert record is not None and policy is not None and mirror is not None
        assert record.decision.policy_id != w.active_policy_id  # the revoked-key policy is no longer selectable
        explicit = authorize(svc.get_action(tenant, action_id), policy, svc.policy_keyring, mirror.result, True,
                             svc.clock())
        assert not explicit.allowed and "policy_signature_invalid" in explicit.failed_checks
        assert all(not p["signature_valid"] for p in svc.list_policies(tenant)
                   if p["policy"]["signer_key_id"] == operator_key)
        # 2. nothing new signed with it loads, and the key cannot be re-trusted
        with pytest.raises(InvalidInputError):
            svc.load_policy(tenant, "admin@isp", active_policy(svc, tenant, w.operator, policy_id="post-revocation"))
        with pytest.raises(InvalidInputError):
            svc.trust_key("policy", operator_key, w.operator.public_pem())
        # 3. IOC bundles signed by a revoked key are deactivated and refused
        ioc = lab_signer(w.corpus.seed)
        assert svc.ioc_status(tenant) is not None
        revoked_ioc = svc.revoke_key("ioc", ioc.key_id, actor="secops.carol", reason="feed signer leaked")
        assert tenant in revoked_ioc["ioc_bundles_deactivated"] and svc.ioc_status(tenant) is None
        with pytest.raises(InvalidInputError) as bi:
            svc.load_ioc_bundle(tenant, "admin@isp", w.corpus.ioc_bundle(ioc))
        assert bi.value.code == "bundle_rejected"
        # 4. ledger entries signed by a revoked ledger key fail verification; the live key is protected
        ring = KeyRing()
        ring.add_signer(svc.ledger_signer)
        assert svc.ledger.verify_report(tenant, ring).ok
        ring.revoke(svc.ledger_signer.key_id)
        assert not svc.ledger.verify_report(tenant, ring).ok
        with pytest.raises(ConflictError):
            svc.revoke_key("ledger", svc.ledger_signer.key_id, actor="secops.carol", reason="x")
        # revocations are on every tenant's ledger and the chain still verifies
        revocations = [e for e in svc.ledger.entries(tenant, entry_type="configuration")
                       if e.payload.get("event") == "key_revoked"]
        assert {e.payload["key_id"] for e in revocations} == {operator_key, ioc.key_id}
        assert svc.verify_ledger(tenant)["ok"] is True
    finally:
        svc.close()

    # 5. the revocation survives a restart even though the public key file is still on disk
    assert (copy_dir / "trusted" / "policy" / f"{operator_key}.pem").exists()
    again = AegisService(make_settings(copy_dir, enforcement_tenant=w.tenant), model=load_default(),
                         adapter=RPZAdapter(copy_dir / "enforcement" / "aegis.rpz"), use_env_llm=False)
    try:
        assert again.policy_keyring.is_revoked(operator_key)
        assert operator_key not in again.policy_keyring.key_ids()
        assert again.ioc_status(w.tenant) is None
        assert all(not p["signature_valid"] for p in again.list_policies(w.tenant)
                   if p["policy"]["signer_key_id"] == operator_key)
    finally:
        again.close()
    # the original deployment was not touched by the copy's revocation
    assert w.svc.policy_keyring.is_trusted(operator_key)
    assert not _enforced(w, target)
