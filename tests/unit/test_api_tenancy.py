"""Strict tenant isolation: the tenant comes from the token only, other tenants' ids are 404."""
from __future__ import annotations

import pytest

from aegis.contracts.models import CaseState, OperatorPolicy

from test_api_helpers import (
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

A, B = "isp-a", "isp-b"


@pytest.fixture()
def env(tmp_path):
    svc = make_service(tmp_path)
    client = make_client(svc)
    finding, case_id = seed_case(svc, A)
    verify_case(svc, A, case_id)
    prepare_enforceable(svc, A)
    r = client.post("/api/v1/actions", json=propose_body(case_id), headers=auth(svc, A, "analyst"))
    assert r.status_code == 201
    return svc, client, finding, case_id, r.json()["action_id"]


def test_other_tenant_reads_are_404(env):
    svc, client, finding, case_id, action_id = env
    hb = auth(svc, B, "viewer", "analyst", "approver", "admin")
    evidence_id = finding.evidence_ids[0]
    for path in (f"/api/v1/findings/{finding.finding_id}", f"/api/v1/cases/{case_id}",
                 f"/api/v1/cases/{case_id}/evidence", f"/api/v1/cases/{case_id}/history",
                 f"/api/v1/cases/{case_id}/replay", f"/api/v1/cases/{case_id}/investigation",
                 f"/api/v1/evidence/{evidence_id}", f"/api/v1/actions/{action_id}"):
        r = client.get(path, headers=hb)
        assert r.status_code == 404, (path, r.status_code, r.text)
    ha = auth(svc, A, "viewer")
    assert client.get(f"/api/v1/cases/{case_id}", headers=ha).status_code == 200
    assert client.get(f"/api/v1/evidence/{evidence_id}", headers=ha).status_code == 200


def test_other_tenant_listings_are_empty(env):
    svc, client, *_ = env
    hb = auth(svc, B, "viewer", "admin")
    for path in ("/api/v1/findings", "/api/v1/cases", "/api/v1/actions", "/api/v1/ledger/entries"):
        body = client.get(path, headers=hb).json()
        assert body["total"] == 0 and body["items"] == [], path
    ha = auth(svc, A, "viewer")
    assert client.get("/api/v1/cases", headers=ha).json()["total"] == 1
    assert client.get("/api/v1/findings", headers=ha).json()["total"] == 1
    assert client.get("/api/v1/metrics/summary", headers=hb).json()["cases"]["total"] == 0
    assert client.get("/api/v1/topology", headers=hb).json()["topology"] is None


def test_other_tenant_mutations_are_404_and_change_nothing(env):
    svc, client, finding, case_id, action_id = env
    hb = auth(svc, B, "analyst", "approver", sub="mallory")
    calls = [
        (f"/api/v1/cases/{case_id}/transition", {"to_state": "CLOSED", "reason": "x"}),
        (f"/api/v1/cases/{case_id}/review", {"alternatives": ["x"], "notes": "y"}),
        (f"/api/v1/cases/{case_id}/notes", {"note": "x"}),
        (f"/api/v1/cases/{case_id}/investigate", None),
        (f"/api/v1/actions/{action_id}/simulate", None),
        (f"/api/v1/actions/{action_id}/authorize", None),
        (f"/api/v1/actions/{action_id}/approve", {"reason": "x"}),
        (f"/api/v1/actions/{action_id}/deny", {"reason": "x"}),
        (f"/api/v1/actions/{action_id}/execute", {"reason": "x"}),
        (f"/api/v1/actions/{action_id}/rollback", {"reason": "x"}),
        ("/api/v1/actions", propose_body(case_id)),
    ]
    before = svc.ledger.count(A)
    for path, body in calls:
        r = client.post(path, json=body, headers=hb)
        assert r.status_code == 404, (path, r.status_code, r.text)
    assert svc.get_case(A, case_id).state is CaseState.VERIFIED
    assert svc.ledger.count(A) == before  # B's calls are audited in B's own chain only
    assert all(e.payload.get("actor") != "mallory" for e in svc.ledger.entries(A))
    audit_b = svc.ledger.entries(B, entry_type="api_audit")
    assert len(audit_b) == len(calls)
    assert {e.payload["status"] for e in audit_b} == {404}


def test_tenant_comes_only_from_token(env):
    svc, client, _, case_id, _ = env
    hb = auth(svc, B, "viewer")
    # query / header attempts to pick another tenant are ignored
    r = client.get(f"/api/v1/cases/{case_id}?tenant_id={A}", headers={**hb, "X-Tenant-ID": A})
    assert r.status_code == 404
    assert client.get("/api/v1/me", headers=hb).json()["tenant_id"] == B


def test_policy_and_events_for_another_tenant_are_rejected(env):
    svc, client, *_ = env
    signer = operator_signer(svc, "op-b")
    r = client.post("/api/v1/policies", json=signed_policy(svc, A, signer, policy_id="cross-tenant"),
                    headers=auth(svc, B, "admin"))
    assert r.status_code == 422
    assert r.json()["failed_checks"] == ["policy_tenant_mismatch"]
    r = client.post("/api/v1/ingest/events", json={"events": [{"tenant_id": A, "source_id": "x"}]},
                    headers=auth(svc, B, "integration"))
    assert r.status_code == 200
    assert r.json()["rejected"] == [{"index": 0, "reason": "tenant_mismatch"}]
    assert svc.quarantine.count(A) == 0


def test_policy_ids_cannot_collide_across_tenants(env):
    svc, client, *_ = env
    signer = operator_signer(svc, "op-shared")
    r = client.post("/api/v1/policies", json=signed_policy(svc, A, signer, policy_id="pol-1"),
                    headers=auth(svc, A, "admin"))
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/policies", json=signed_policy(svc, B, signer, policy_id="pol-1"),
                    headers=auth(svc, B, "admin"))
    assert r.status_code == 409
    # tenant A's policy is intact
    stored = svc.docs.get(OperatorPolicy, A, "pol-1")
    assert stored is not None and stored.tenant_id == A
    assert svc.docs.get(OperatorPolicy, B, "pol-1") is None


def test_ingest_into_other_tenants_source_is_404(env):
    svc, client, *_ = env
    svc.register_source(A, "admin", source_id="nf-1", source_kind="netflow", vantage="device",
                        collection_authorization_id="auth-a")
    r = client.post("/api/v1/ingest?source_id=nf-1", content=b"ts,src,dst\n", headers=auth(svc, B, "integration"))
    assert r.status_code == 404
    assert r.json()["error"] == "unknown_source"


def test_sources_with_same_id_are_independent_per_tenant(env):
    svc, client, *_ = env
    body = {"source_id": "netflow-core", "source_kind": "netflow", "vantage": "subscriber_line",
            "collection_authorization_id": "auth-x"}
    assert client.post("/api/v1/sources", json=body, headers=auth(svc, A, "admin")).status_code == 201
    assert client.post("/api/v1/sources", json={**body, "collection_authorization_id": "auth-b"},
                       headers=auth(svc, B, "admin")).status_code == 201
    a = client.get("/api/v1/sources", headers=auth(svc, A, "viewer")).json()["items"]
    b = client.get("/api/v1/sources", headers=auth(svc, B, "viewer")).json()["items"]
    assert [s["collection_authorization_id"] for s in a] == ["auth-x"]
    assert [s["collection_authorization_id"] for s in b] == ["auth-b"]
