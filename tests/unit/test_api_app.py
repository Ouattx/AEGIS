"""Application plumbing: health, readiness, metrics, audit, headers, limits, pagination, console."""
from __future__ import annotations

import pytest

from aegis.api.metrics import ApiMetrics, Counter, Histogram
from aegis.api.ratelimit import RateLimiter

from test_api_helpers import auth, make_client, make_service, seed_case, verify_case

T = "isp-a"


@pytest.fixture()
def env(tmp_path):
    svc = make_service(tmp_path)
    return svc, make_client(svc)


def test_health_and_readiness(env):
    svc, client = env
    assert client.get("/healthz").json()["status"] == "ok"
    r = client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True and body["checks"]["database"] == "ok"
    assert body["checks"]["model"].startswith("not_loaded")
    assert body["checks"]["enforcement_adapter"] == "dry_run"


def test_readiness_fails_when_database_is_gone(env):
    svc, client = env
    svc.engine.dispose()
    import sqlalchemy
    svc.engine = sqlalchemy.create_engine("sqlite:////nonexistent-dir/x.db")
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["ready"] is False


def test_prometheus_metrics(env):
    svc, client = env
    client.get("/api/v1/cases", headers=auth(svc, T, "viewer"))
    client.get("/api/v1/cases")
    text = client.get("/metrics").text
    assert '# TYPE aegis_http_requests_total counter' in text
    assert 'aegis_http_requests_total{method="GET",route="/api/v1/cases",status="200"} 1' in text
    assert 'aegis_auth_failures_total{reason="missing_token"} 1' in text
    assert 'aegis_http_request_duration_seconds_bucket{method="GET",route="/api/v1/cases",le="+Inf"} 2' in text
    assert "aegis_ready 1" in text
    assert T not in text  # no tenant ids in metric labels


def test_metrics_token(tmp_path):
    svc = make_service(tmp_path, metrics_token="scrape-secret-123")
    client = make_client(svc)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer scrape-secret-123"}).status_code == 200


def test_request_id_and_security_headers(env):
    svc, client = env
    r = client.get("/api/v1/cases", headers={**auth(svc, T, "viewer"), "X-Request-ID": "abc12345-req"})
    assert r.headers["X-Request-ID"] == "abc12345-req"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    r = client.get("/healthz", headers={"X-Request-ID": "bad id with spaces"})
    assert r.headers["X-Request-ID"] != "bad id with spaces" and len(r.headers["X-Request-ID"]) == 32


def test_every_mutating_call_is_audited_including_refusals(env):
    svc, client = env
    _, case_id = seed_case(svc, T)
    h = auth(svc, T, "analyst", sub="alice")
    ok = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "TRIAGE", "reason": "look"}, headers=h)
    assert ok.status_code == 200
    refused = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "VERIFIED", "reason": "x"},
                          headers=h)
    assert refused.status_code == 409
    assert refused.json()["failed_checks"] == ["transition_not_allowed:TRIAGE->VERIFIED"]
    denied = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "CLOSED", "reason": "x"},
                         headers=auth(svc, T, "viewer", sub="victor"))
    assert denied.status_code == 403
    invalid = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "NOPE"}, headers=h)
    assert invalid.status_code == 422
    audit = svc.ledger.entries(T, entry_type="api_audit")
    by_status = {e.payload["status"]: e.payload for e in audit}
    assert set(by_status) == {200, 409, 403, 422}
    assert by_status[200]["actor"] == "alice" and by_status[200]["outcome"] == "ok"
    assert by_status[200]["route"] == "/api/v1/cases/{case_id}/transition"
    assert by_status[200]["path_params"] == {"case_id": case_id}
    assert len(by_status[200]["body_sha256"]) == 64
    assert by_status[409]["outcome"] == "refused"
    assert by_status[409]["failed_checks"] == ["transition_not_allowed:TRIAGE->VERIFIED"]
    assert by_status[403]["actor"] == "victor" and by_status[403]["denied_permission"] == "case_work"
    assert svc.verify_ledger(T)["ok"] is True
    # reads are not audited
    client.get("/api/v1/cases", headers=h)
    assert len(svc.ledger.entries(T, entry_type="api_audit")) == 4


def test_per_tenant_rate_limit(tmp_path):
    svc = make_service(tmp_path, rate_limit_rps=0.001, rate_limit_burst=3)
    client = make_client(svc)
    ha, hb = auth(svc, "isp-a", "viewer"), auth(svc, "isp-b", "viewer")
    codes = [client.get("/api/v1/cases", headers=ha).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = client.get("/api/v1/cases", headers=ha)
    assert int(r.headers["Retry-After"]) >= 1 and r.json()["error"] == "rate_limited"
    assert client.get("/api/v1/cases", headers=hb).status_code == 200  # other tenants unaffected


def test_rate_limiter_refills():
    clock = [0.0]
    rl = RateLimiter(2.0, 2, monotonic=lambda: clock[0])
    assert rl.acquire("k") == (True, 0.0) and rl.acquire("k")[0]
    ok, retry = rl.acquire("k")
    assert not ok and retry == pytest.approx(0.5)
    clock[0] += 0.5
    assert rl.acquire("k")[0]
    small = RateLimiter(1.0, 1, monotonic=lambda: clock[0], max_keys=4)
    for i in range(10):
        small.acquire(f"k{i}")
    assert len(small._buckets) <= 4


def test_pagination_and_filters(env):
    svc, client = env
    ids = [seed_case(svc, T, entity=f"p_{i:032d}")[1] for i in range(5)]  # one case per device incident
    h = auth(svc, T, "viewer")
    page = client.get("/api/v1/cases?limit=2&offset=0", headers=h).json()
    assert page["total"] == 5 and len(page["items"]) == 2 and page["limit"] == 2
    rest = client.get("/api/v1/cases?limit=10&offset=2", headers=h).json()
    assert len(rest["items"]) == 3
    seen = {c["case_id"] for c in page["items"]} | {c["case_id"] for c in rest["items"]}
    assert seen == set(ids)
    assert client.get("/api/v1/cases?state=NEW", headers=h).json()["total"] == 5
    assert client.get("/api/v1/cases?state=VERIFIED", headers=h).json()["total"] == 0
    assert client.get("/api/v1/findings?verdict=malicious&label=c2_beaconing", headers=h).json()["total"] == 5
    assert client.get("/api/v1/findings?verdict=benign", headers=h).json()["total"] == 0
    assert client.get("/api/v1/cases?limit=0", headers=h).status_code == 422
    assert client.get("/api/v1/cases?offset=-1", headers=h).status_code == 422
    assert client.get("/api/v1/cases?state=BOGUS", headers=h).status_code == 422


def test_case_work_endpoints(env):
    svc, client = env
    finding, case_id = seed_case(svc, T)
    h = auth(svc, T, "analyst", sub="alice")
    for state in ("TRIAGE", "INVESTIGATING"):
        assert client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": state, "reason": "go"},
                           headers=h).status_code == 200
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "VERIFIED", "reason": "go"}, headers=h)
    assert r.status_code == 409 and "counter_hypothesis_review_missing" in r.json()["failed_checks"]
    note = client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "called the subscriber"}, headers=h)
    assert note.status_code == 201 and note.json()["kind"] == "analyst_note"
    r = client.post(f"/api/v1/cases/{case_id}/review",
                    json={"alternatives": ["benign IPTV app", "  "], "notes": "device history reviewed"}, headers=h)
    assert r.status_code == 200 and r.json()["counter_hypothesis_reviewed"] is True
    inv = client.post(f"/api/v1/cases/{case_id}/investigate", headers=h)
    assert inv.status_code == 200, inv.text
    assert inv.json()["mode"] == "deterministic" and inv.json()["case_id"] == case_id
    assert client.get(f"/api/v1/cases/{case_id}/investigation", headers=h).json()["report_id"] == \
        inv.json()["report_id"]
    r = client.post(f"/api/v1/cases/{case_id}/transition", json={"to_state": "VERIFIED", "reason": "confirmed"},
                    headers=h)
    assert r.status_code == 200 and r.json()["state"] == "VERIFIED"
    detail = client.get(f"/api/v1/cases/{case_id}", headers=h).json()
    assert detail["case"]["state"] == "VERIFIED"
    assert detail["evidence_assessment"]["verification_blockers"] == []
    assert "PROPOSED" in detail["allowed_transitions"]
    assert detail["findings"][0]["finding_id"] == finding.finding_id
    evid = client.get(f"/api/v1/cases/{case_id}/evidence", headers=h).json()
    assert evid["total"] >= 3 and all(e["integrity_verified"] for e in evid["items"])
    history = client.get(f"/api/v1/cases/{case_id}/history", headers=h).json()["items"]
    assert [x["payload"].get("to_state") for x in history if x["entry_type"] == "case_transition"][-1] == "VERIFIED"
    replay = client.get(f"/api/v1/cases/{case_id}/replay", headers=h).json()
    assert set(finding.evidence_ids) <= set(replay["evidence_ids"])
    early = client.get(f"/api/v1/cases/{case_id}/replay?as_of=2000-01-01T00:00:00Z", headers=h).json()
    assert early["evidence_ids"] == []


def test_evidence_and_ledger_endpoints(env):
    svc, client = env
    finding, case_id = seed_case(svc, T)
    h = auth(svc, T, "viewer")
    ev = client.get(f"/api/v1/evidence/{finding.evidence_ids[0]}", headers=h).json()
    assert ev["integrity_verified"] is True and ev["evidence"]["sha256"]
    assert client.get("/api/v1/evidence/unknown-id", headers=h).status_code == 404
    v = client.get("/api/v1/ledger/verify", headers=h).json()
    assert v["ok"] is True and v["entry_count"] == v["entries_checked"] and v["signed_entries"] == v["entry_count"]
    entries = client.get(f"/api/v1/ledger/entries?subject_id={case_id}", headers=auth(svc, T, "admin")).json()
    assert entries["total"] >= 1 and entries["items"][0]["subject_id"] == case_id


def test_graph_endpoint(env):
    svc, client = env
    from datetime import datetime, timezone
    from aegis.constellation.graph import EdgeType, EvidenceGrade
    now = datetime.now(timezone.utc)
    svc.constellation.upsert_edge(T, "domain:c2.badbox.example", "ip:203.0.113.10", EdgeType.OBSERVED_RESOLVES_TO, now,
                          "ev-1:203.0.113.10", EvidenceGrade.B, "sensor:dns")
    h = auth(svc, T, "viewer")
    r = client.get("/api/v1/graph/c2.badbox.example", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["node"]["node_id"] == "domain:c2.badbox.example" and body["degree"] == 1
    assert body["neighbors"][0]["node_id"] == "ip:203.0.113.10"
    assert client.get("/api/v1/graph/ip:203.0.113.10", headers=h).json()["degree"] == 1
    assert client.get("/api/v1/graph/unknown.example", headers=h).status_code == 404
    assert client.get("/api/v1/graph/c2.badbox.example", headers=auth(svc, "isp-b", "viewer")).status_code == 404


def test_reports_endpoint(env):
    svc, client = env
    _, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    h = auth(svc, T, "viewer")
    r = client.get("/api/v1/reports/pov", headers=h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "<html" in r.text.lower()
    j = client.get("/api/v1/reports/pov?format=json", headers=h).json()
    assert j["tenant_id"] == T and j["ledger"]["ok"] is True
    assert client.get("/api/v1/reports/pov?start=2026-10-01T00:00:00Z", headers=h).status_code == 422
    assert client.get("/api/v1/reports/pov?start=2026-10-02T00:00:00Z&end=2026-10-01T00:00:00Z",
                      headers=h).status_code == 422
    ranged = client.get("/api/v1/reports/pov?format=json&start=2020-01-01T00:00:00Z&end=2020-01-02T00:00:00Z",
                        headers=h).json()
    assert ranged["alerts"]["alerts"] == 0


def test_demo_token_endpoint_only_in_dev_demo_mode(tmp_path):
    svc = make_service(tmp_path / "a")
    client = make_client(svc)
    assert client.get("/api/v1/demo/token?role=analyst").status_code == 404  # no demo tenant configured
    demo = make_service(tmp_path / "b", demo_tenant="demo")
    dc = make_client(demo)
    r = dc.get("/api/v1/demo/token?role=approver")
    assert r.status_code == 200
    tok = r.json()["access_token"]
    me = dc.get("/api/v1/me", headers={"Authorization": f"Bearer {tok}"}).json()
    assert me["tenant_id"] == "demo" and me["roles"] == ["approver"]
    assert dc.get("/api/v1/demo/token?role=root").status_code == 422
    assert dc.get("/api/v1/auth/config").json()["demo"] is True


def test_console_static_files_and_spa_fallback(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>AEGIS console</title>")
    (dist / "assets" / "app.js").write_text("console.log('aegis')")
    (tmp_path / "secret.txt").write_text("do not serve")
    svc = make_service(tmp_path / "data", web_dist=dist)
    client = make_client(svc)
    assert "AEGIS console" in client.get("/").text
    assert "AEGIS console" in client.get("/cases/123").text  # client-side route
    js = client.get("/assets/app.js")
    assert js.status_code == 200 and "immutable" in js.headers["Cache-Control"]
    assert "do not serve" not in client.get("/../secret.txt").text
    assert "do not serve" not in client.get("/%2e%2e/secret.txt").text
    r = client.get("/api/v1/does-not-exist")
    assert r.status_code == 404 and r.json()["error"] == "not_found"


def test_root_without_console(env):
    _, client = env
    body = client.get("/").json()
    assert body["api"] == "/api/v1"
    assert client.get("/nothing-here").status_code == 404


def test_metric_primitives():
    c = Counter("x_total", "x", ["a"])
    c.inc(a="1")
    c.inc(2, a="1")
    assert c.value(a="1") == 3
    with pytest.raises(ValueError):
        c.inc(-1, a="1")
    with pytest.raises(ValueError):
        c.inc(b="2")
    h = Histogram("h_seconds", "h", buckets=(0.1, 1.0))
    h.observe(0.05)
    h.observe(5)
    out = "\n".join(h.render())
    assert 'h_seconds_bucket{le="0.1"} 1' in out and 'h_seconds_bucket{le="+Inf"} 2' in out
    assert "h_seconds_count 2" in out
    m = ApiMetrics("9.9")
    assert 'aegis_build_info{version="9.9"} 1' in m.render()
