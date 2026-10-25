"""Enforcement workflow through the API: nobody executes without authorization."""
from __future__ import annotations

import pytest

from aegis.contracts.models import CaseState
from aegis.provenance.ledger import EntryType

from test_api_helpers import (
    C2_DOMAIN,
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

T = "isp-a"


@pytest.fixture()
def env(tmp_path):
    svc = make_service(tmp_path)
    client = make_client(svc)
    _, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    return svc, client, case_id


def _propose(client, svc, case_id, sub="analyst-1", **kw):
    r = client.post("/api/v1/actions", json=propose_body(case_id, **kw), headers=auth(svc, T, "analyst", sub=sub))
    assert r.status_code == 201, r.text
    return r.json()["action_id"]


def _sim_auth(client, svc, action_id, sub="analyst-1"):
    h = auth(svc, T, "analyst", sub=sub)
    sim = client.post(f"/api/v1/actions/{action_id}/simulate", headers=h)
    assert sim.status_code == 200, sim.text
    az = client.post(f"/api/v1/actions/{action_id}/authorize", headers=h)
    assert az.status_code == 200, az.text
    return sim.json(), az.json()


def test_full_authorized_path_executes_in_dry_run_and_rolls_back(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id)
    sim, az = _sim_auth(client, svc, action_id)
    assert sim["verdict"] == "SAFE"
    assert az["decision"]["allowed"] is True, az
    assert az["case_state"] == "PROPOSED"

    approver = auth(svc, T, "approver", sub="bob")
    r = client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "collateral reviewed"}, headers=approver)
    assert r.status_code == 200, r.text
    assert r.json()["case"]["state"] == "APPROVED"

    r = client.post(f"/api/v1/actions/{action_id}/execute", json={"reason": "go"}, headers=approver)
    assert r.status_code == 200, r.text
    assert r.json()["execution"]["status"] == "dry_run"
    assert r.json()["case_state"] == "EXECUTED"
    detail = client.get(f"/api/v1/actions/{action_id}", headers=approver).json()
    assert detail["live"] is True
    assert [e["status"] for e in detail["executions"]] == ["dry_run"]

    r = client.post(f"/api/v1/actions/{action_id}/rollback", json={"reason": "pilot rollback test"}, headers=approver)
    assert r.status_code == 200, r.text
    assert r.json()["execution"]["status"] == "rolled_back"
    assert svc.get_case(T, case_id).state is CaseState.ROLLED_BACK
    assert svc.verify_ledger(T)["ok"] is True


def test_analyst_cannot_approve_execute_or_rollback(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id)
    _sim_auth(client, svc, action_id)
    analyst = auth(svc, T, "analyst", sub="analyst-2")
    for step, body in (("approve", {"reason": "x"}), ("deny", {"reason": "x"}), ("execute", {"reason": "x"}),
                       ("rollback", {"reason": "x"})):
        r = client.post(f"/api/v1/actions/{action_id}/{step}", json=body, headers=analyst)
        assert r.status_code == 403, (step, r.text)
        assert r.json()["error"] == "forbidden"
    assert svc.get_case(T, case_id).state is CaseState.PROPOSED
    # an analyst cannot reach APPROVED through the generic transition route either
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "APPROVED", "reason": "x"},
                    headers=analyst)
    assert r.status_code == 422
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "DENIED", "reason": "x"},
                    headers=analyst)
    assert r.status_code == 403


def test_proposer_cannot_approve_own_action(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id, sub="carol")
    _sim_auth(client, svc, action_id, sub="carol")
    both = auth(svc, T, "analyst", "approver", sub="carol")
    r = client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "mine"}, headers=both)
    assert r.status_code == 403
    assert r.json()["failed_checks"] == ["approver_is_proposer"]
    assert svc.get_case(T, case_id).state is CaseState.PROPOSED


def test_shadow_policy_never_authorizes_and_approval_is_refused(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer, mode="shadow", legal=None))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id)
    _, az = _sim_auth(client, svc, action_id)
    assert az["decision"]["allowed"] is False
    assert "policy_not_active_mode" in az["decision"]["failed_checks"]
    approver = auth(svc, T, "approver", sub="bob")
    r = client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "please"}, headers=approver)
    assert r.status_code == 409
    assert "authorization_not_allowed" in r.json()["failed_checks"]
    r = client.post(f"/api/v1/actions/{action_id}/execute", json={}, headers=approver)
    assert r.status_code == 409
    assert "case_state:PROPOSED" in r.json()["failed_checks"]
    r = client.post(f"/api/v1/actions/{action_id}/deny", json={"reason": "shadow pilot"}, headers=approver)
    assert r.status_code == 200
    assert r.json()["case"]["state"] == "DENIED"
    assert svc.executor.active() == []


def test_no_policy_means_no_execution(env):
    svc, client, case_id = env
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id)
    _, az = _sim_auth(client, svc, action_id)
    assert az["decision"]["allowed"] is False
    assert "policy_missing" in az["decision"]["failed_checks"]
    approver = auth(svc, T, "approver", sub="bob")
    assert client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "x"},
                       headers=approver).status_code == 409
    assert client.post(f"/api/v1/actions/{action_id}/execute", json={},
                       headers=approver).status_code == 409
    refusals = svc.ledger.entries(T, subject_id=action_id, entry_type="execution_refused")
    assert len(refusals) == 1
    assert svc.executor.active() == []


def test_execute_refused_when_unsimulated_or_unknown_topology(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    # no topology loaded: simulation is UNKNOWN (fail closed)
    action_id = _propose(client, svc, case_id)
    sim, az = _sim_auth(client, svc, action_id)
    assert sim["verdict"] == "UNKNOWN"
    assert az["decision"]["allowed"] is False
    assert "mirror_not_safe" in az["decision"]["failed_checks"]


def test_policy_revoked_between_approval_and_execution_blocks(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id)
    _sim_auth(client, svc, action_id)
    approver = auth(svc, T, "approver", sub="bob")
    assert client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "ok"},
                       headers=approver).status_code == 200
    svc.policy_keyring.revoke(signer.key_id)
    r = client.post(f"/api/v1/actions/{action_id}/execute", json={}, headers=approver)
    assert r.status_code == 409
    assert "policy_signature_invalid" in r.json()["failed_checks"] or \
        "authorization_not_allowed" in r.json()["failed_checks"]
    assert svc.get_case(T, case_id).state is CaseState.APPROVED
    assert svc.executor.active() == []


def test_proposer_cannot_execute_even_with_approver_role(env):
    svc, client, case_id = env
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    action_id = _propose(client, svc, case_id, sub="dave")
    _sim_auth(client, svc, action_id, sub="dave")
    assert client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "ok"},
                       headers=auth(svc, T, "approver", sub="bob")).status_code == 200
    r = client.post(f"/api/v1/actions/{action_id}/execute", json={},
                    headers=auth(svc, T, "approver", sub="dave"))
    assert r.status_code == 409
    assert "approver_is_proposer" in r.json()["failed_checks"]


def test_propose_requires_verified_case_and_valid_targets(tmp_path):
    svc = make_service(tmp_path)
    client = make_client(svc)
    _, case_id = seed_case(svc, T)
    h = auth(svc, T, "analyst")
    r = client.post("/api/v1/actions", json=propose_body(case_id), headers=h)
    assert r.status_code == 409
    assert r.json()["failed_checks"] == ["case_state:NEW"]
    verify_case(svc, T, case_id)
    r = client.post("/api/v1/actions", json=propose_body(case_id, targets=["not a domain!"]), headers=h)
    assert r.status_code == 422
    r = client.post("/api/v1/actions", json=propose_body(case_id, expires_in_hours=None,
                                                         expires_at="2020-01-01T00:00:00Z"), headers=h)
    assert r.status_code == 422
    r = client.post("/api/v1/actions", json={**propose_body(case_id), "unexpected": 1}, headers=h)
    assert r.status_code == 422
    r = client.post("/api/v1/actions", json=propose_body("missing-case"), headers=h)
    assert r.status_code == 404


def test_action_ledger_trail(env):
    svc, client, case_id = env
    action_id = _propose(client, svc, case_id)
    _sim_auth(client, svc, action_id)
    types = [e.entry_type for e in svc.ledger.entries(T, subject_id=action_id)]
    assert EntryType.ACTION in types
    assert "mirror_simulation" in types
    assert EntryType.AUTHORIZATION in types
    listing = client.get(f"/api/v1/actions?case_id={case_id}", headers=auth(svc, T, "viewer")).json()
    assert listing["total"] == 1 and listing["items"][0]["targets"] == [C2_DOMAIN]
