"""Telemetry ingest through the API: sources, raw payloads, events, quarantine, detection."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis.contracts.canonical import sha256_hex

from test_api_helpers import auth, make_client, make_service

T = "isp-a"
SAMPLE = Path(__file__).resolve().parents[2] / "sample_data"
SOURCE = {"source_id": "nf-core", "source_kind": "netflow", "vantage": "device",
          "collection_authorization_id": "auth-isp-a-001"}


@pytest.fixture()
def env(tmp_path):
    svc = make_service(tmp_path)
    client = make_client(svc)
    r = client.post("/api/v1/sources", json=SOURCE, headers=auth(svc, T, "admin"))
    assert r.status_code == 201, r.text
    return svc, client


def test_source_registration_rules(env):
    svc, client = env
    h = auth(svc, T, "admin")
    assert client.post("/api/v1/sources", json=SOURCE, headers=h).status_code == 409
    assert client.post("/api/v1/sources", json={**SOURCE, "source_id": "bad id!"}, headers=h).status_code == 422
    assert client.post("/api/v1/sources", json={**SOURCE, "source_id": "x", "source_kind": "pcap"},
                       headers=h).status_code == 422
    assert client.post("/api/v1/sources", json={**SOURCE, "source_id": "y", "format": "nonsense"},
                       headers=h).status_code == 422
    items = client.get("/api/v1/sources", headers=auth(svc, T, "viewer")).json()["items"]
    assert [i["source_id"] for i in items] == ["nf-core"]
    assert items[0]["tenant_id"] == T
    assert any(e.payload.get("event") == "source_registered" for e in svc.ledger.entries(T, entry_type="configuration"))


def test_raw_netflow_ingest_runs_detection(env):
    svc, client = env
    data = (SAMPLE / "lab" / "netflow.csv").read_bytes()
    r = client.post("/api/v1/ingest?source_id=nf-core&flush=true&name=netflow.csv", content=data,
                    headers={**auth(svc, T, "integration"), "Content-Type": "text/csv"})
    assert r.status_code == 200, r.text
    body = r.json()
    stats = body["stats"][0]
    assert stats["records_read"] == 6703 and stats["accepted"] == 6703 and stats["quarantined"] == 0
    assert body["events"] == 6703
    summary = client.get("/api/v1/metrics/summary", headers=auth(svc, T, "viewer")).json()
    assert summary["coverage"]["devices_observed"] > 0
    assert summary["coverage"]["events"] == 6703
    assert summary["ingest"]["sources"] == ["nf-core"]
    ingest_entries = svc.ledger.entries(T, entry_type="ingest_batch")
    assert ingest_entries and ingest_entries[-1].payload["events"] == 6703
    # the raw upload's hash is in the audit trail
    audit = [e for e in svc.ledger.entries(T, entry_type="api_audit") if e.payload["route"] == "/api/v1/ingest"]
    assert audit[-1].payload["body_sha256"] == sha256_hex(data)


def test_malformed_records_are_quarantined_not_dropped(env):
    svc, client = env
    data = (SAMPLE / "formats" / "malformed_netflow.csv").read_bytes()
    r = client.post("/api/v1/ingest?source_id=nf-core", content=data, headers=auth(svc, T, "integration"))
    assert r.status_code == 200
    stats = r.json()["stats"][0]
    assert stats["quarantined"] > 0
    assert stats["accepted"] + stats["quarantined"] + stats["duplicates"] == stats["records_read"]
    q = client.get("/api/v1/ingest/quarantine", headers=auth(svc, T, "admin")).json()
    assert q["total"] == stats["quarantined"]
    assert all("raw_b64" not in item for item in q["items"])
    assert client.get("/api/v1/ingest/quarantine", headers=auth(svc, T, "analyst")).status_code == 403


def test_unknown_source_and_empty_payload(env):
    svc, client = env
    h = auth(svc, T, "integration")
    r = client.post("/api/v1/ingest?source_id=nope", content=b"x", headers=h)
    assert r.status_code == 404 and r.json()["error"] == "unknown_source"
    assert client.post("/api/v1/ingest?source_id=nf-core", content=b"  ", headers=h).status_code == 422
    assert client.post("/api/v1/ingest", content=b"x", headers=h).status_code == 422


def test_payload_size_limit(tmp_path):
    svc = make_service(tmp_path, max_ingest_bytes=2048)
    client = make_client(svc)
    svc.register_source(T, "admin", **SOURCE)
    r = client.post("/api/v1/ingest?source_id=nf-core", content=b"x" * 5000, headers=auth(svc, T, "integration"))
    assert r.status_code == 413
    assert r.json()["error"] == "payload_too_large"


def test_events_endpoint_validates_and_quarantines(env):
    svc, client = env
    now = datetime.now(timezone.utc).replace(microsecond=0)
    good = {"tenant_id": T, "observed_at": now.isoformat(), "ingested_at": now.isoformat(),
            "source_id": "nf-core", "source_kind": "netflow", "vantage": "device",
            "collection_authorization_id": "auth-isp-a-001", "entity_pseudonym": "p_" + "b" * 32,
            "device_class": "smart_tv", "flow": {"dst_ip": "198.51.100.7", "dst_port": 443, "protocol": "tcp",
                                                  "bytes_out": 100, "bytes_in": 1000},
            "retention_until": now.replace(year=now.year + 1).isoformat(), "integrity_sha256": "a" * 64}
    raw_id = {**good, "entity_pseudonym": "02:00:5e:00:00:01"}
    wrong_auth = {**good, "collection_authorization_id": "stolen"}
    r = client.post("/api/v1/ingest/events", json={"events": [good, raw_id, wrong_auth, "nope"]},
                    headers=auth(svc, T, "integration"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["events"] == 1
    reasons = {x["index"]: x["reason"] for x in body["rejected"]}
    assert reasons[1] == "raw_identifier"
    assert reasons[2] == "source_mismatch"
    assert reasons[3] == "not_an_object"
    assert client.post("/api/v1/ingest/events", json={"events": []},
                       headers=auth(svc, T, "integration")).status_code == 422
