"""End to end on the seeded lab demo: corpus -> pipeline -> SENTINEL -> cases -> API workflow."""
from __future__ import annotations

import ipaddress

import pytest

from aegis.api.demo import seed_lab_demo
from aegis.sentinel.model import load_default

from test_api_helpers import auth, make_client, make_service

T = "demo"


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    svc = make_service(tmp_path_factory.mktemp("demo"), demo_tenant=T, rate_limit_burst=10_000)
    svc.model = load_default()
    summary = seed_lab_demo(svc, tenant_id=T, n_devices=40, days=2, leave_open=3)
    return svc, make_client(svc), summary


def test_seed_summary(demo):
    svc, _, summary = demo
    assert summary.events > 10_000
    assert summary.alerts >= 1 and 1 <= summary.cases <= summary.alerts  # de-duplicated per device incident
    assert sum(summary.dispositions.values()) == summary.cases
    assert summary.dispositions["open"] == len(summary.open_case_ids) <= 3
    assert summary.period_start.hour == 0 and (summary.period_end - summary.period_start).days == 2
    assert svc.verify_ledger(T)["ok"] is True
    assert svc.model is not None and "nomodel" not in svc.detector_version(T)


def test_demo_tokens_drive_the_console_workflow(demo):
    svc, client, summary = demo
    tok = client.get("/api/v1/demo/token?role=analyst").json()["access_token"]
    analyst = {"Authorization": f"Bearer {tok}"}
    cases = client.get("/api/v1/cases?state=INVESTIGATING", headers=analyst).json()
    assert {c["case_id"] for c in cases["items"]} == set(summary.open_case_ids)
    case_id = None
    for cid in summary.open_case_ids:
        detail = client.get(f"/api/v1/cases/{cid}", headers=analyst).json()
        assert detail["investigation"] is not None  # investigated during seeding
        if not detail["evidence_assessment"]["verification_blockers"]:
            case_id = cid
            break
    if case_id is None:
        pytest.skip("no open demo case has verification-grade evidence in this small corpus")
    r = client.post(f"/api/v1/cases/{case_id}/review",
                    json={"alternatives": ["benign IPTV middleware"], "notes": "beacon period inconsistent with IPTV"},
                    headers=analyst)
    assert r.status_code == 200
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "VERIFIED", "reason": "confirmed"},
                    headers=analyst)
    assert r.status_code == 200, r.text
    domains = [i for i in svc._case_indicators(svc.get_case(T, case_id)) if not _is_ip(i)]
    target = domains[0] if domains else None
    body = ({"case_id": case_id, "action_type": "dns_sinkhole", "targets": [target]} if target else
            {"case_id": case_id, "action_type": "notify_subscriber",
             "targets": [svc.get_finding(T, svc.get_case(T, case_id).finding_ids[0]).entity_pseudonym]})
    body.update({"legal_basis": "operator_tos_security_clause", "expires_in_hours": 24,
                 "rollback_plan": "remove the RPZ entry", "rollback_verified": True, "scope": {"max_entities": 1}})
    r = client.post("/api/v1/actions", json=body, headers=analyst)
    assert r.status_code == 201, r.text
    action_id = r.json()["action_id"]
    assert client.post(f"/api/v1/actions/{action_id}/simulate", headers=analyst).status_code == 200
    az = client.post(f"/api/v1/actions/{action_id}/authorize", headers=analyst).json()
    assert az["case_state"] == "PROPOSED"
    assert az["decision"]["allowed"] is False  # shadow-mode demo policy never authorizes enforcement
    assert "policy_not_active_mode" in az["decision"]["failed_checks"]
    approver = auth(svc, T, "approver", sub="demo-approver")
    assert client.post(f"/api/v1/actions/{action_id}/approve", json={"reason": "x"},
                       headers=approver).status_code == 409
    r = client.post(f"/api/v1/actions/{action_id}/deny", json={"reason": "shadow pilot: report only"},
                    headers=approver)
    assert r.status_code == 200 and r.json()["case"]["state"] == "DENIED"
    summary_after = client.get("/api/v1/metrics/summary", headers=analyst).json()
    assert summary_after["actions"]["enforcement_applied"] == 0
    assert summary_after["actions"]["live_enforcements"] == 0


def test_pov_report_for_demo(demo):
    svc, client, summary = demo
    h = auth(svc, T, "viewer")
    j = client.get("/api/v1/reports/pov?format=json", headers=h).json()
    assert j["ledger"]["ok"] is True
    assert j["alerts"]["alerts"] == summary.alerts
    assert j["validation"] is not None  # lab ground truth registered by the demo seeding
    html = client.get("/api/v1/reports/pov", headers=h).text
    assert "AEGIS" in html


def test_demo_graph_and_iocs(demo):
    svc, client, _ = demo
    h = auth(svc, T, "viewer")
    ioc = client.get("/api/v1/iocs", headers=h).json()["bundle"]
    assert ioc["signer_key_id"].startswith("lab-ioc-signer") and ioc["indicators"] > 0
    topo = client.get("/api/v1/topology", headers=h).json()["topology"]
    assert topo["complete"] is True and topo["hosts"] > 0
    policies = client.get("/api/v1/policies", headers=h).json()["items"]
    assert policies[0]["signature_valid"] is True and policies[0]["policy"]["mode"] == "shadow"
    edges = svc.constellation.edges(T)
    assert edges, "resolver answers should populate CONSTELLATION"
    node = edges[0].src
    r = client.get(f"/api/v1/graph/{node}", headers=h)
    assert r.status_code == 200 and r.json()["degree"] >= 1


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def test_demo_report_is_labelled_synthetic_on_every_surface(demo):
    """The synthetic-demo banner does not depend on the in-memory lab context: a restarted
    service (what `aegis report` uses) renders it too, with exact intervals and n."""
    from aegis.service import AegisService

    svc, client, _ = demo
    j = client.get("/api/v1/reports/pov?format=json", headers=auth(svc, T, "viewer")).json()
    assert j["synthetic"] is True and "SYNTHETIC LAB DEMO" in j["synthetic_notice"]
    assert j["headline"].startswith("Synthetic lab demo")
    assert "verified by analysts" not in j["headline"]
    assert j["validation"]["recall_ci"] is not None and j["false_alerts"]["per_10k_ci_upper"] is not None
    restarted = AegisService(svc.settings, load_default_model=False, use_env_llm=False)
    try:
        assert restarted.is_lab_tenant(T)
        html = restarted.pov_report(T)
        assert "Synthetic lab demo" in html and "simulated analyst" in html
        assert "Verified by analysts" not in html
        assert restarted.pov_report(T, fmt="json")["validation"] is not None
    finally:
        restarted.close()


def test_report_inputs_drive_the_cost_section(demo):
    svc, client, _ = demo
    admin = auth(svc, T, "admin")
    bad = client.put("/api/v1/reports/inputs", json={"cost": {"bogus": 1}}, headers=admin)
    assert bad.status_code == 422
    r = client.put("/api/v1/reports/inputs", headers=admin, json={
        "cost": {"license_monthly": 2500, "infrastructure_monthly": 400, "monitored_devices": 50_000}})
    assert r.status_code == 200 and r.json()["configured"] is True
    assert client.put("/api/v1/reports/inputs", json={}, headers=auth(svc, T, "analyst")).status_code == 403
    j = client.get("/api/v1/reports/pov?format=json", headers=auth(svc, T, "viewer")).json()
    assert j["cost"]["operator_inputs_configured"] is True and j["cost"]["monitored_devices"] == 50_000
    assert j["cost"]["per_1000_devices_month"] is not None and j["cost"]["per_incident"] is not None
    assert any("per 1,000 monitored device-months" in line for line in j["summary"])
    client.put("/api/v1/reports/inputs", json={}, headers=admin)  # back to defaults for other tests
    j = client.get("/api/v1/reports/pov?format=json", headers=auth(svc, T, "viewer")).json()
    assert not any("USD" in line for line in j["summary"])  # unconfigured: no cost in the headline summary
