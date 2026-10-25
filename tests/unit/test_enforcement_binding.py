"""Regression tests for the enforcement gates (action-bound approval, case-linked targets,
authoritative policy, rollback rehearsal, ledger-backed approval, leaving EXECUTED)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.contracts.models import ActionType, Case, CaseDecision, CaseState
from aegis.mirror.executor import ROLLBACK_REHEARSAL_ENTRY
from aegis.service import AegisService, ConflictError, InvalidInputError
from test_api_helpers import (
    C2_DOMAIN,
    ENTITY,
    auth,
    make_client,
    make_service,
    operator_signer,
    prepare_enforceable,
    propose_body,
    seed_case,
    signed_policy,
    verify_case,
)

#: spec section 15 safety tests (selected by ``pytest -m safety`` with tests/safety)
pytestmark = pytest.mark.safety

T = "isp-a"


@pytest.fixture()
def svc(tmp_path):
    s = make_service(tmp_path)
    yield s
    s.close()


def _verified_case(svc: AegisService, *, mode: str = "active") -> str:
    prepare_enforceable(svc, T)
    svc.load_policy(T, "admin", signed_policy(svc, T, operator_signer(svc), mode=mode))
    _f, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    return case_id


def _propose(svc: AegisService, case_id: str, **kw) -> str:
    body = propose_body(case_id, **kw)
    body.pop("expires_in_hours")
    body["expires_at"] = svc.clock() + timedelta(hours=12)
    return svc.propose_action(T, "ana", **body).action_id


def test_approval_of_one_action_never_executes_a_sibling(svc: AegisService) -> None:
    """Reproduction of the review blocker: approve A, then execute B on the same case."""
    case_id = _verified_case(svc)
    client = make_client(svc)
    ana, bob = auth(svc, T, "analyst", sub="ana"), auth(svc, T, "approver", sub="bob")
    a = client.post("/api/v1/actions", json=propose_body(case_id, action_type="notify_subscriber",
                                                          targets=[ENTITY]), headers=ana).json()["action_id"]
    b = client.post("/api/v1/actions", json=propose_body(case_id), headers=ana).json()["action_id"]
    for aid in (a, b):
        assert client.post(f"/api/v1/actions/{aid}/simulate", headers=ana).status_code == 200
    assert client.post(f"/api/v1/actions/{a}/authorize", headers=ana).status_code == 200
    r = client.post(f"/api/v1/actions/{a}/approve", json={"reason": "notify the subscriber"}, headers=bob)
    assert r.status_code == 200, r.text
    r = client.post(f"/api/v1/actions/{b}/execute", json={"reason": "sneak"}, headers=bob)
    assert r.status_code == 409
    assert "action_not_approved" in r.json()["failed_checks"]
    assert svc.get_case(T, case_id).state is CaseState.APPROVED
    assert b not in svc.executor.active()
    # a sibling cannot be re-assessed once the case is APPROVED either
    r = client.post(f"/api/v1/actions/{b}/authorize", headers=ana)
    assert r.status_code == 409
    # the approval is bound to A in the signed ledger
    approved = [e for e in svc.ledger.entries(T, subject_id=case_id) if e.payload.get("to_state") == "APPROVED"]
    assert approved[-1].payload["action_id"] == a and approved[-1].payload["authorization_sha256"]


def test_sibling_reassessment_before_approval_rebinds_the_case(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    a = _propose(svc, case_id)
    b = _propose(svc, case_id)
    svc.simulate_action(T, "ana", a)
    svc.simulate_action(T, "ana", b)
    svc.authorize_action(T, "ana", a)
    svc.authorize_action(T, "ana", b)
    case = svc.get_case(T, case_id)
    assert case.decisions[-1].from_state is CaseState.PROPOSED and case.decisions[-1].action_id == b
    with pytest.raises(ConflictError) as ei:
        svc.decide_action(T, "bob", a, approve=True, reason="old proposal")
    assert "action_is_not_the_proposed_action" in ei.value.failed
    svc.decide_action(T, "bob", b, approve=True, reason="ok")
    out = svc.execute_action(T, "bob", b, reason="go")
    assert out["case_state"] == "EXECUTED"


def test_unlinked_target_is_refused_at_proposal(svc: AegisService) -> None:
    """Pointing a verified C2 case at an unrelated legitimate CDN name is refused."""
    case_id = _verified_case(svc)
    with pytest.raises(InvalidInputError) as ei:
        _propose(svc, case_id, targets=["a.cdn.example"])
    assert ei.value.failed == ["target_not_in_case_evidence"]
    # with the explicit override the simulation is UNSAFE (shared CDN) and needs a human anyway
    aid = _propose(svc, case_id, targets=["a.cdn.example"], scope={"max_entities": 1, "allow_unlinked_targets": True})
    sim = svc.simulate_action(T, "ana", aid)
    assert sim.verdict.value == "UNSAFE" and sim.requires_human_approval
    with pytest.raises(InvalidInputError) as ei:
        _propose(svc, case_id, action_type="notify_subscriber", targets=["p_" + "b" * 32])
    assert ei.value.failed == ["target_not_a_case_entity"]


def test_newer_shadow_policy_switches_enforcement_off(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    signer = operator_signer(svc, "op-2")
    aid = _propose(svc, case_id)
    svc.simulate_action(T, "ana", aid)
    assert svc.authorize_action(T, "ana", aid)["decision"].allowed
    svc.decide_action(T, "bob", aid, approve=True, reason="ok")
    later = signed_policy(svc, T, signer, mode="shadow", policy_id="p-shadow-new")
    later["valid_from"] = (svc.clock() - timedelta(minutes=5)).isoformat()
    from aegis.contracts.models import OperatorPolicy
    from aegis.provenance.signing import sign_model
    later = sign_model(OperatorPolicy.model_validate({**later, "signature": ""}), signer).model_dump(mode="json")
    svc.load_policy(T, "admin", later)
    assert svc.authoritative_policy(T).policy_id == "p-shadow-new"
    with pytest.raises(ConflictError) as ei:
        svc.execute_action(T, "bob", aid, reason="go")
    assert any("policy_not_active_mode" in f for f in ei.value.failed)
    assert aid not in svc.executor.active()
    with pytest.raises(ConflictError) as ei:
        svc._select_policy(T, svc.get_action(T, aid), f"{T}-active-policy")
    assert ei.value.failed == ["policy_superseded"]


def test_rollback_verified_comes_from_the_adapter_rehearsal(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    aid = _propose(svc, case_id, rollback_verified=False)
    action = svc.get_action(T, aid)
    assert action.rollback_verified is True  # rehearsed on the adapter, not taken from the body
    entries = svc.ledger.entries(T, subject_id=aid, entry_type=ROLLBACK_REHEARSAL_ENTRY)
    assert entries and entries[-1].payload["ok"] is True and entries[-1].payload["method"] == "scratch_apply_revert"
    no_plan = _propose(svc, case_id, rollback_plan=None, rollback_verified=True)
    assert svc.get_action(T, no_plan).rollback_verified is False


def test_forged_rollback_flag_without_ledger_rehearsal_fails_authorization(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    aid = _propose(svc, case_id, rollback_plan=None)
    svc.docs.put(svc.get_action(T, aid).model_copy(update={"rollback_plan": "x", "rollback_verified": True}))
    svc.simulate_action(T, "ana", aid)
    d = svc.authorize_action(T, "ana", aid)["decision"]
    assert "rollback_not_verified" in d.failed_checks


def test_approval_forged_in_the_database_is_refused(svc: AegisService) -> None:
    """An APPROVED decision written straight into the case document (no signed ledger entry)
    does not pass the execution gate."""
    case_id = _verified_case(svc)
    aid = _propose(svc, case_id)
    svc.simulate_action(T, "ana", aid)
    svc.authorize_action(T, "ana", aid)
    case = svc.get_case(T, case_id)
    forged = CaseDecision(from_state=CaseState.PROPOSED, to_state=CaseState.APPROVED, actor="bob",
                          reason="forged", at=svc.clock(), ledger_entry_hash="f" * 64, action_id=aid)
    svc.docs.put(case.model_copy(update={"state": CaseState.APPROVED, "decisions": case.decisions + [forged]}))
    with pytest.raises(ConflictError) as ei:
        svc.execute_action(T, "bob", aid, reason="go")
    assert "approval_not_in_signed_ledger" in ei.value.failed
    assert aid not in svc.executor.active()


def test_execute_reruns_mirror_instead_of_trusting_the_stored_result(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    aid = _propose(svc, case_id)
    svc.simulate_action(T, "ana", aid)
    svc.authorize_action(T, "ana", aid)
    svc.decide_action(T, "bob", aid, approve=True, reason="ok")
    before = len(svc.ledger.entries(T, subject_id=aid, entry_type="mirror_simulation"))
    # the topology disappears after approval: a fresh simulation is UNKNOWN, execution refused
    svc._topologies.pop(T)
    with pytest.raises(ConflictError) as ei:
        svc.execute_action(T, "bob", aid, reason="go")
    assert any(f.startswith("mirror_not_safe") or "mirror_not_safe" in f for f in ei.value.failed)
    assert len(svc.ledger.entries(T, subject_id=aid, entry_type="mirror_simulation")) == before + 1


def test_executed_case_cannot_be_expired_while_enforcement_is_live(svc: AegisService) -> None:
    case_id = _verified_case(svc)
    client = make_client(svc)
    aid = _propose(svc, case_id)
    svc.simulate_action(T, "ana", aid)
    svc.authorize_action(T, "ana", aid)
    svc.decide_action(T, "bob", aid, approve=True, reason="ok")
    svc.execute_action(T, "bob", aid, reason="go")
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "EXPIRED", "reason": "done"},
                    headers=auth(svc, T, "approver", sub="bob"))
    assert r.status_code == 409 and "use_rollback_for_executed_case" in r.json()["failed_checks"]
    assert aid in svc.executor.active() and svc.get_case(T, case_id).state is CaseState.EXECUTED
    # the state machine itself refuses while the execution is live
    from aegis.oracle.state_machine import GuardError
    with pytest.raises(GuardError) as ei:
        svc.cases.transition(T, case_id, CaseState.EXPIRED, "bob", "done")
    assert "enforcement_still_live" in ei.value.failed
    out = svc.rollback_action(T, "bob", aid, reason="stop")
    assert out["case_state"] == "ROLLED_BACK" and aid not in svc.executor.active()


def test_case_decision_schema_is_backward_compatible() -> None:
    old = {"from_state": "NEW", "to_state": "TRIAGE", "actor": "a", "reason": "r", "at": "2026-10-01T00:00:00Z"}
    d = CaseDecision.model_validate(old)
    assert d.action_id is None and d.authorization_sha256 is None
    assert Case.model_fields["decisions"]
    assert ActionType.DNS_SINKHOLE.value == "dns_sinkhole" and C2_DOMAIN


def test_live_adapter_is_bound_to_the_enforcement_tenant(tmp_path) -> None:
    from aegis.mirror.rpz import RPZAdapter
    from test_api_helpers import make_settings

    rpz = RPZAdapter(tmp_path / "zone" / "aegis.rpz")
    svc = AegisService(make_settings(tmp_path, enforcement_tenant="isp-other"), load_default_model=False,
                       use_env_llm=False, adapter=rpz)
    try:
        case_id = _verified_case(svc)
        aid = _propose(svc, case_id)
        svc.simulate_action(T, "ana", aid)
        svc.authorize_action(T, "ana", aid)
        svc.decide_action(T, "bob", aid, approve=True, reason="ok")
        with pytest.raises(ConflictError) as ei:
            svc.execute_action(T, "bob", aid, reason="go")
        assert "tenant_not_authorized_for_live_enforcement" in ei.value.failed
        assert rpz.records() == []
    finally:
        svc.close()


def test_tenant_bound_policy_key_cannot_sign_for_another_tenant(svc: AegisService) -> None:
    from aegis.provenance.signing import Signer

    signer = Signer.generate("isp-b-key")
    d = svc.settings.trusted_dir / "policy" / "isp-b"
    d.mkdir(parents=True)
    (d / "isp-b-key.pem").write_bytes(signer.public_pem())
    svc.reload_trusted_keys()
    with pytest.raises(InvalidInputError) as ei:
        svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    assert ei.value.failed == ["policy_key_tenant_mismatch"]
    svc.load_policy("isp-b", "admin", signed_policy(svc, "isp-b", signer))
    assert svc.authoritative_policy("isp-b") is not None


def test_settings_require_an_enforcement_tenant_for_live_adapters(tmp_path) -> None:
    from aegis.api.settings import SettingsError
    from test_api_helpers import make_settings

    with pytest.raises((SettingsError, ValueError), match="AEGIS_ENFORCEMENT_TENANT"):
        make_settings(tmp_path, enforcement_adapter="rpz", rpz_zone_path=tmp_path / "z.rpz")
    s = make_settings(tmp_path, enforcement_adapter="rpz", rpz_zone_path=tmp_path / "z.rpz", enforcement_tenant=T)
    assert s.enforcement_tenant == T


def test_action_document_changed_after_approval_is_refused(svc: AegisService) -> None:
    """Rewriting the stored action (e.g. its targets) after approval never reaches the adapter."""
    case_id = _verified_case(svc)
    aid = _propose(svc, case_id)
    svc.simulate_action(T, "ana", aid)
    svc.authorize_action(T, "ana", aid)
    svc.decide_action(T, "bob", aid, approve=True, reason="ok")
    action = svc.get_action(T, aid)
    svc.docs.put(action.model_copy(update={"expires_at": action.expires_at + timedelta(hours=1)}))
    with pytest.raises(ConflictError) as ei:
        svc.execute_action(T, "bob", aid, reason="go")
    assert "action_differs_from_signed_proposal" in ei.value.failed
    svc.docs.put(action)  # restored exactly: allowed again
    assert svc.execute_action(T, "bob", aid, reason="go")["case_state"] == "EXECUTED"
