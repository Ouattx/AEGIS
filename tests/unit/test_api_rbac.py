"""Role checks for every route: each role gets exactly its permissions."""
from __future__ import annotations

import pytest

from aegis.api.auth import Principal, Role
from aegis.api.rbac import ROLE_PERMISSIONS, Permission, allowed, permissions_of

from test_api_helpers import auth, make_client, make_service, propose_body, seed_case, topology_doc, verify_case

T = "isp-a"
ROLES = ("viewer", "analyst", "approver", "admin", "integration")


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    svc = make_service(tmp_path_factory.mktemp("rbac"), rate_limit_burst=10_000, rate_limit_rps=10_000)
    client = make_client(svc)
    finding, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    action = svc.propose_action(T, "proposer", **{k: v for k, v in propose_body(case_id).items()
                                                  if k not in ("expires_in_hours",)})
    return svc, client, finding, case_id, action.action_id


def _routes(finding, case_id, action_id):
    # (method, path, json body, roles allowed)
    read = {"viewer", "analyst", "approver", "admin"}
    return [
        ("GET", "/api/v1/findings", None, read),
        ("GET", f"/api/v1/findings/{finding.finding_id}", None, read),
        ("GET", "/api/v1/cases", None, read),
        ("GET", f"/api/v1/cases/{case_id}", None, read),
        ("GET", f"/api/v1/cases/{case_id}/evidence", None, read),
        ("GET", f"/api/v1/cases/{case_id}/history", None, read),
        ("GET", f"/api/v1/cases/{case_id}/replay", None, read),
        ("GET", f"/api/v1/evidence/{finding.evidence_ids[0]}", None, read),
        ("GET", "/api/v1/ledger/verify", None, read),
        ("GET", "/api/v1/ledger/entries", None, {"admin"}),
        ("GET", "/api/v1/ingest/quarantine", None, {"admin"}),
        ("GET", "/api/v1/actions", None, read),
        ("GET", f"/api/v1/actions/{action_id}", None, read),
        ("GET", "/api/v1/metrics/summary", None, read),
        ("GET", "/api/v1/reports/pov?format=json", None, read),
        ("GET", "/api/v1/sources", None, read),
        ("GET", "/api/v1/policies", None, read),
        ("POST", "/api/v1/sources", {"source_id": "s-{role}", "source_kind": "dns", "vantage": "device",
                                     "collection_authorization_id": "a"}, {"admin"}),
        ("POST", "/api/v1/topology", topology_doc(), {"admin"}),
        ("POST", "/api/v1/ingest/events", {"events": [{"tenant_id": T}]}, {"integration"}),
        ("POST", f"/api/v1/cases/{case_id}/review", {"alternatives": ["x"], "notes": "y"}, {"analyst"}),
        ("POST", f"/api/v1/cases/{case_id}/notes", {"note": "n"}, {"analyst"}),
        ("POST", f"/api/v1/cases/{case_id}/investigate", None, {"analyst"}),
        ("POST", f"/api/v1/cases/{case_id}/transition", {"to_state": "CLOSED", "reason": "r"}, {"analyst"}),
        ("POST", "/api/v1/actions", propose_body(case_id), {"analyst"}),
        ("POST", f"/api/v1/actions/{action_id}/simulate", None, {"analyst"}),
        ("POST", f"/api/v1/actions/{action_id}/approve", {"reason": "r"}, {"approver"}),
        ("POST", f"/api/v1/actions/{action_id}/deny", {"reason": "r"}, {"approver"}),
        ("POST", f"/api/v1/actions/{action_id}/execute", {"reason": "r"}, {"approver"}),
        ("POST", f"/api/v1/actions/{action_id}/rollback", {"reason": "r"}, {"approver"}),
        ("POST", "/api/v1/policies", {"policy_id": "x"}, {"admin"}),
        ("POST", "/api/v1/iocs", {"schema": "x"}, {"admin"}),
    ]


def test_role_matrix(env):
    svc, client, finding, case_id, action_id = env
    failures = []
    for method, path, body, allowed_roles in _routes(finding, case_id, action_id):
        for role in ROLES:
            if isinstance(body, dict) and "source_id" in body:
                body = {**body, "source_id": f"s-{role}"}
            r = client.request(method, path, json=body, headers=auth(svc, T, role, sub=f"user-{role}"))
            denied = r.status_code == 403
            if (role in allowed_roles) == denied or r.status_code == 401:
                failures.append((method, path, role, r.status_code, r.text[:200]))
    assert not failures, failures


def test_unauthenticated_requests_are_401(env):
    svc, client, finding, case_id, action_id = env
    for method, path, body, _ in _routes(finding, case_id, action_id):
        r = client.request(method, path, json=body)
        assert r.status_code == 401, (method, path, r.status_code)
        assert r.headers["WWW-Authenticate"].startswith("Bearer")
    r = client.get("/api/v1/cases", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    r = client.get("/api/v1/cases", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_permission_matrix_is_least_privilege():
    assert Permission.APPROVE not in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.EXECUTE not in ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.APPROVE not in ROLE_PERMISSIONS[Role.ADMIN]
    assert Permission.EXECUTE not in ROLE_PERMISSIONS[Role.ADMIN]
    assert ROLE_PERMISSIONS[Role.INTEGRATION] == frozenset({Permission.INGEST})
    assert ROLE_PERMISSIONS[Role.VIEWER] == frozenset({Permission.READ})
    p = Principal(sub="x", tenant_id="t", roles=frozenset({Role.ANALYST, Role.VIEWER}))
    assert allowed(p, Permission.PROPOSE) and not allowed(p, Permission.APPROVE)
    assert permissions_of(Principal(sub="x", tenant_id="t", roles=frozenset())) == frozenset()


def test_viewer_cannot_change_any_case_state(env):
    svc, client, _, case_id, _ = env
    h = auth(svc, T, "viewer")
    for state in ("TRIAGE", "INVESTIGATING", "VERIFIED", "REJECTED", "CLOSED", "DENIED", "EXPIRED"):
        r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": state, "reason": "x"}, headers=h)
        assert r.status_code == 403, state
    for state in ("PROPOSED", "APPROVED", "EXECUTED", "ROLLED_BACK"):
        r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": state, "reason": "x"},
                        headers=auth(svc, T, "analyst", "approver"))
        assert r.status_code == 422 and r.json()["error"] == "use_actions_workflow", state
