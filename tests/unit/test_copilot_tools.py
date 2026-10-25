"""Copilot tools: read-only surface, schemas, tenant scoping, campaign / graph / ingest / simulate behavior."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from aegis.atlas.graph import EdgeType, EvidenceGrade
from aegis.contracts.models import LedgerEntry
from aegis.copilot import DEFAULT_TOOLS, ServiceDataSource
from aegis.copilot.tools import ToolContext, ToolNotFound, analyze_ingest, tool_map
from aegis.oracle.tools import _MUTATING_NAME

from test_api_helpers import C2_DOMAIN, C2_IP, prepare_enforceable
from test_copilot_helpers import A, B, build_service, seed_campaign


@pytest.fixture()
def env(tmp_path):
    svc, ids = build_service(tmp_path)
    yield svc, ids
    svc.close()


def _ctx(svc, tenant=A):
    return ToolContext(tenant_id=tenant, ds=ServiceDataSource(svc), now=svc.clock())


def _call(svc, name, args, tenant=A):
    tool = tool_map()[name]
    return tool.handler(_ctx(svc, tenant), tool.parse(args))


def test_tool_surface_is_read_only_and_typed():
    names = [t.name for t in DEFAULT_TOOLS]
    assert len(names) == len(set(names)) == 13
    for t in DEFAULT_TOOLS:
        assert not _MUTATING_NAME.search(t.name), t.name
        s = t.schema()
        assert s["input_schema"]["type"] == "object"
        assert s["input_schema"]["additionalProperties"] is False
        assert "tenant_id" not in s["input_schema"]["properties"]
        with pytest.raises(ValidationError):
            t.parse({"tenant_id": "isp-b"})


def test_argument_validation_rejects_bad_ids_and_types():
    tools = tool_map()
    with pytest.raises(ValidationError):
        tools["get_case"].parse({"case_id": "../../etc/passwd"})
    with pytest.raises(ValidationError):
        tools["search_findings"].parse({"limit": 10_000})
    with pytest.raises(ValidationError):
        tools["search_findings"].parse({"verdict": "pwned"})
    with pytest.raises(ValueError):
        tools["metrics_summary"].parse(["not", "an", "object"])


def test_get_case_scoped_to_tenant(env):
    svc, ids = env
    out = _call(svc, "get_case", {"case_id": ids["case_a"]})
    assert out.data["case_id"] == ids["case_a"] and ("case", ids["case_a"]) in out.refs
    assert ("evidence", ids["poisoned"]) in out.refs
    with pytest.raises(ToolNotFound):
        _call(svc, "get_case", {"case_id": ids["case_b"]})
    with pytest.raises(ToolNotFound):
        _call(svc, "get_evidence", {"evidence_id": ids["evidence_b"]})
    with pytest.raises(ToolNotFound):
        _call(svc, "get_finding", {"finding_id": ids["finding_b"]})


def test_search_findings_refs_and_score_kind(env):
    svc, ids = env
    out = _call(svc, "search_findings", {"verdict": "malicious"})
    assert out.data["total_matching"] == 1
    f = out.data["findings"][0]
    assert f["finding_id"] == ids["finding_a"] and f["score_kind"] == "calibrated probability"
    assert out.data["result_ref"].startswith("query:q-")
    kinds = {k for k, _ in out.refs}
    assert {"query", "finding", "evidence"} <= kinds


def test_campaigns_from_ledger(env):
    svc, _ = env
    cid, findings = seed_campaign(svc, A)
    out = _call(svc, "list_campaigns", {})
    row = out.data["campaigns"][0]
    assert row["campaign_id"] == cid and row["n_lines"] == 6 and row["period_s"] == 900.0
    assert row["evidence_id"] and row["enforcement_eligible"] is True
    assert ("campaign", cid) in out.refs
    assert "not establish maliciousness" in out.data["interpretation"]
    assert ServiceDataSource(svc).exists(A, "campaign", cid)
    assert not ServiceDataSource(svc).exists(B, "campaign", cid)
    assert _call(svc, "list_campaigns", {}, tenant=B).data["campaigns"] == []


def test_graph_neighbors(env):
    svc, _ = env
    now = svc.clock()
    svc.atlas.upsert_edge(A, f"domain:{C2_DOMAIN}", f"ip:{C2_IP}", EdgeType.OBSERVED_RESOLVES_TO, now, "prov-1",
                          EvidenceGrade.B, "sensor")
    out = _call(svc, "graph_neighbors", {"node": C2_DOMAIN})
    assert out.data["node_id"] == f"domain:{C2_DOMAIN}" and out.data["degree"] == 1
    n = out.data["neighbors"][0]
    assert n["node_id"] == f"ip:{C2_IP}" and n["edge_type"] == "observed_resolves_to"
    assert ("node", f"ip:{C2_IP}") in out.refs
    with pytest.raises(ToolNotFound):
        _call(svc, "graph_neighbors", {"node": C2_DOMAIN}, tenant=B)


def test_ledger_query_and_verification(env):
    svc, ids = env
    v = _call(svc, "verify_ledger", {})
    assert v.data["ok"] is True and v.data["entries_checked"] == svc.ledger.count(A)
    assert tool_map()["ledger_query"].permission == "read_audit"
    assert tool_map()["verify_ledger"].permission == "read"
    out = _call(svc, "ledger_query", {"subject_id": ids["case_a"]})
    assert all(e["subject_id"] == ids["case_a"] for e in out.data["entries"])
    seq = out.data["entries"][0]["seq"]
    single = _call(svc, "ledger_query", {"seq": seq})
    assert single.data["entries"][0]["seq"] == seq and ("ledger", str(seq)) in single.refs
    latest = _call(svc, "ledger_query", {"limit": 3})
    seqs = [e["seq"] for e in latest.data["entries"]]
    assert seqs == sorted(seqs, reverse=True) and len(seqs) == 3 and seqs[0] == svc.ledger.count(A)


def test_simulate_existing_action_stores_nothing(env):
    from test_api_helpers import operator_signer, propose_body, signed_policy, verify_case
    svc, ids = env
    verify_case(svc, A, ids["case_a"])
    svc.load_policy(A, "admin", signed_policy(svc, A, operator_signer(svc)))
    prepare_enforceable(svc, A)
    body = propose_body(ids["case_a"])
    body.pop("expires_in_hours")
    action = svc.propose_action(A, "alice", expires_at=svc.clock() + timedelta(hours=2), **body)
    before = svc.ledger.count(A)
    out = _call(svc, "simulate_action_readonly", {"action_id": action.action_id})
    assert out.data["simulation_only"] is True and out.data["verdict"] == "SAFE"
    assert svc.ledger.count(A) == before
    assert svc.action_detail(A, action.action_id)["mirror"] is None   # no MirrorRecord stored
    with pytest.raises(ToolNotFound):
        _call(svc, "simulate_action_readonly", {"action_id": action.action_id}, tenant=B)
    hypo = _call(svc, "simulate_action_readonly", {"case_id": ids["case_a"], "action_type": "ip_block",
                                                   "targets": ["203.0.113.20"]})
    assert hypo.data["hypothetical"] is True and hypo.data["verdict"] != "SAFE"   # shared CDN IP
    assert svc.list_actions(A).total == 1


def test_health_and_metrics(env):
    svc, _ = env
    h = _call(svc, "health_status", {})
    assert h.data["ready"] is True and "bus_inflight" in h.data["tenant"]
    assert h.data["result_ref"].startswith("health:h-")
    m = _call(svc, "metrics_summary", {})
    assert m.data["tenant_id"] == A and m.data["result_ref"].startswith("metrics:m-")


def _entry(seq, rec, payload):
    return LedgerEntry(seq=seq, tenant_id="t", entry_type="ingest_batch", subject_id=f"ingest:{seq}",
                       payload_sha256="0" * 64, payload=payload, prev_hash="0" * 64, entry_hash=f"{seq:064x}",
                       recorded_at=rec)


def test_analyze_ingest_detects_processing_time_and_volume():
    t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    entries = []
    for i in range(10):
        slow = i >= 5
        entries.append(_entry(i + 1, t0 + timedelta(minutes=5 * i), {
            "events": 10, "last_event_at": (t0 + timedelta(minutes=5 * i, seconds=-20)).isoformat(),
            "sources": [{"records_read": 5000 if slow else 1000, "quarantined": 0, "duplicates": 0,
                         "elapsed_s": 12.0 if slow else 2.0}]}))
    res = analyze_ingest(entries)
    codes = {o["code"] for o in res["observations"]}
    assert codes == {"processing_time_up", "volume_up"}
    assert res["baseline"]["median_elapsed_s"] == 2.0 and res["recent"]["median_elapsed_s"] == 12.0


def test_analyze_ingest_needs_history_and_stays_quiet_when_stable():
    t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert analyze_ingest([_entry(1, t0, {"sources": []})])["status"] == "insufficient_history"
    stable = [_entry(i + 1, t0 + timedelta(minutes=5 * i), {
        "events": 10, "last_event_at": (t0 + timedelta(minutes=5 * i, seconds=-20)).isoformat(),
        "sources": [{"records_read": 1000, "quarantined": 3, "duplicates": 1}]}) for i in range(8)]
    res = analyze_ingest(stable)
    assert res["status"] == "ok" and res["observations"] == []


def test_health_gauges_never_disclose_other_tenants(env, monkeypatch):
    """The executor and bus are process-wide: health shows only this tenant's live actions."""
    from aegis.contracts.models import ActionType, ProposedAction

    svc, _ = env
    a_action = ProposedAction(tenant_id=A, case_id="case-x", action_type=list(ActionType)[0], targets=["192.0.2.1"],
                              created_by="analyst", created_at=svc.clock())
    svc.docs.put(a_action)
    monkeypatch.setattr(svc.executor, "active", lambda: [a_action.action_id, "foreign-action-id"])
    ha = _call(svc, "health_status", {}, tenant=A).data["tenant"]
    hb = _call(svc, "health_status", {}, tenant=B).data["tenant"]
    assert ha["live_enforcements"] == 1 and hb["live_enforcements"] == 0
    assert "bus_depth_total" not in ha and "bus_depth_total" not in hb
