"""End-to-end: the complete pilot demo flow on one deployment, through the public API.

corpus -> collector files -> ingest -> detection -> case -> investigate -> verify ->
propose -> simulate -> authorize -> approve -> execute -> rollback -> PoV report ->
ledger verify.

The deployment is the real composed system (``AegisService`` + FastAPI app, the
shipped calibrated model, a real RPZ zone file as the enforcement point). Operator
trust anchors (IOC and policy signing keys, the tenant pseudonymization key) are
installed on disk exactly as an operator would; everything else goes through
``/api/v1`` with role-scoped tokens.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.auth import mint_dev_token
from aegis.api.demo import demo_start
from aegis.api.settings import Settings
from aegis.contracts.models import ActionType, OperatorPolicy
from aegis.lab.corpus import generate_corpus
from aegis.lab.iocs import lab_signer
from aegis.mirror.rpz import RPZAdapter
from aegis.provenance.signing import Signer, sign_model
from aegis.reports.inputs import ReportPeriod
from aegis.reports.lab import LAB_LABEL_SOURCE
from aegis.sentinel.model import load_default
from aegis.service import AegisService, LabContext

TENANT = "acme-isp"
LEGAL_BASIS = "operator_tos_security_clause"


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _auth(svc: AegisService, role: str, sub: str) -> dict[str, str]:
    return {"Authorization": "Bearer " + mint_dev_token(svc.settings, sub=sub, tenant_id=TENANT, roles=[role])}


def _ok(r: Any, status: int = 200) -> Any:
    assert r.status_code == status, (r.status_code, r.text)
    return r.json()


def test_full_pilot_demo_flow(tmp_path: Path) -> None:
    settings = Settings(auth_mode="dev", data_dir=tmp_path / "data", dev_jwt_secret="i" * 48, log_format="text",
                        sweep_interval_s=0, llm_enabled=False, rate_limit_burst=100_000, rate_limit_rps=10_000.0,
                        web_dist=tmp_path / "no-console", enforcement_tenant=TENANT)
    rpz = RPZAdapter(tmp_path / "resolver" / "aegis.rpz")
    svc = AegisService(settings, model=load_default(), adapter=rpz, use_env_llm=False)
    client = TestClient(create_app(settings, service=svc))
    admin, analyst = _auth(svc, "admin", "admin.ana"), _auth(svc, "analyst", "analyst.alice")
    approver, viewer = _auth(svc, "approver", "approver.bob"), _auth(svc, "viewer", "noc.viewer")
    try:
        # ---------------------------------------------------------------- 1. corpus -> collector files
        corpus = generate_corpus(seed=11, days=2, n_devices=30, malicious_fraction=0.15, tenant_id=TENANT,
                                 start=demo_start(2))
        paths = corpus.write_raw(tmp_path / "collector", zeek=False)
        assert paths["netflow"].stat().st_size > 0 and paths["dns"].stat().st_size > 0

        # ---------------------------------------------------------------- 2. operator configuration
        svc.set_tenant_pseudonym_key(TENANT, corpus.tenant_key)
        for cfg in corpus.sources.values():
            _ok(client.post("/api/v1/sources", headers=admin, json={
                "source_id": cfg.source_id, "source_kind": cfg.source_kind.value, "vantage": cfg.vantage.value,
                "collection_authorization_id": cfg.collection_authorization_id,
                "retention_days": cfg.retention_days, "format": cfg.format, "entity_field": cfg.entity_field}), 201)
        ioc = lab_signer(corpus.seed)
        svc.trust_key("ioc", ioc.key_id, ioc.public_pem())
        _ok(client.post("/api/v1/iocs", headers=admin, json=corpus.ioc_bundle(ioc)), 201)
        _ok(client.post("/api/v1/topology", headers=admin,
                        json=corpus.topology.to_dict(include_ground_truth=False)), 201)
        operator = Signer.generate("acme-operator-2026")
        svc.trust_key("policy", operator.key_id, operator.public_pem())
        now = svc.clock()
        policy = sign_model(OperatorPolicy(
            policy_id="acme-active-2026-q4", tenant_id=TENANT, mode="active",
            allowed_actions=[ActionType.DNS_SINKHOLE, ActionType.NOTIFY_SUBSCRIBER], max_targets_per_action=3,
            max_ttl_hours=48, approved_scope={"max_entities": 3, "legal_bases": [LEGAL_BASIS],
                                              "max_affected_entities": 50},
            legal_signoff_ref="ACME-LEGAL-2026-031", valid_from=now - timedelta(hours=1),
            valid_until=now + timedelta(days=60), signer_key_id=operator.key_id, signature=""), operator)
        assert _ok(client.post("/api/v1/policies", headers=admin, json=policy.model_dump(mode="json")), 201)[
            "signature_valid"] is True

        # ---------------------------------------------------------------- 3. ingest files -> detection
        outcome = svc.ingest_files(TENANT, [(paths["netflow"], "lab-netflow"), (paths["dns"], "lab-dns")],
                                   flush_at=corpus.end)
        assert outcome.events == len(corpus.events) and outcome.cases_opened
        findings = _ok(client.get("/api/v1/findings", params={"verdict": "malicious", "limit": 500}, headers=viewer))
        assert findings["total"] >= 1
        truth_bad = {d.entity_pseudonym for d in corpus.malicious_devices()}
        assert {f["entity_pseudonym"] for f in findings["items"]} & truth_bad
        # a false alert on a benign device (possible: shadow mode measures exactly this) is
        # single-origin model evidence, which the VERIFIED guard never accepts -> never enforceable
        for f in findings["items"]:
            if f["entity_pseudonym"] not in truth_bad:
                case = svc.cases.case_for_finding(TENANT, f["finding_id"])
                assert case is not None
                assert svc.cases.assess_evidence(case).verification_blockers()

        # ---------------------------------------------------------------- 4. case -> investigate -> verify
        cases = _ok(client.get("/api/v1/cases", params={"state": "NEW", "limit": 500}, headers=viewer))["items"]
        assert len(cases) == len(set(outcome.cases_opened))
        chosen: dict[str, Any] | None = None
        for c in sorted(cases, key=lambda c: c["severity"] != "critical"):
            detail = _ok(client.get(f"/api/v1/cases/{c['case_id']}", headers=viewer))
            if detail["findings"][0]["entity_pseudonym"] in truth_bad \
                    and not detail["evidence_assessment"]["verification_blockers"]:
                chosen = detail
                break
        assert chosen is not None, "no verifiable case for a malicious lab device"
        case_id = chosen["case"]["case_id"]
        for state in ("TRIAGE", "INVESTIGATING"):
            assert _ok(client.post(f"/api/v1/cases/{case_id}/transition", headers=analyst,
                                   json={"to_state": state, "reason": f"pilot walk-through: {state}"}))[
                "state"] == state
        report = _ok(client.post(f"/api/v1/cases/{case_id}/investigate", headers=analyst))
        assert report["mode"] == "deterministic" and report["verification"]["recommendation"] == "verify"
        assert report["alternative_hypotheses"] and report["evidence"]
        assert "ledger_chain_verification_failed" not in report["escalation_reasons"]
        _ok(client.post(f"/api/v1/cases/{case_id}/review", headers=analyst, json={
            "alternatives": [h["title"] for h in report["alternative_hypotheses"]][:5],
            "notes": "periodic beacon to a signed C2 indicator; benign streaming and CDN co-hosting ruled out"}))
        assert _ok(client.post(f"/api/v1/cases/{case_id}/transition", headers=analyst,
                               json={"to_state": "VERIFIED", "reason": "compromise confirmed"}))["state"] == "VERIFIED"

        # ---------------------------------------------------------------- 5. propose -> simulate -> authorize
        evidence = _ok(client.get(f"/api/v1/cases/{case_id}/evidence", headers=viewer))["items"]
        names = [e["evidence"]["payload"].get("indicator_value") for e in evidence
                 if e["evidence"]["kind"] == "ioc_match" and e["evidence"]["supports"]]
        domains = [n for n in dict.fromkeys(names) if n and not _is_ip(n)]
        assert domains
        action_id = sim = None
        for domain in domains:
            action = _ok(client.post("/api/v1/actions", headers=analyst, json={
                "case_id": case_id, "action_type": "dns_sinkhole", "targets": [domain], "scope": {"max_entities": 1},
                "legal_basis": LEGAL_BASIS, "expires_in_hours": 24, "rollback_plan": "remove RPZ entry, reload",
                "rollback_verified": True}), 201)
            sim = _ok(client.post(f"/api/v1/actions/{action['action_id']}/simulate", headers=analyst))
            if sim["verdict"] == "SAFE":
                action_id, target = action["action_id"], domain
                break
        assert action_id is not None and sim is not None and sim["verdict"] == "SAFE"
        authz = _ok(client.post(f"/api/v1/actions/{action_id}/authorize", headers=analyst))
        assert authz["decision"]["allowed"] is True and authz["case_state"] == "PROPOSED"

        # ---------------------------------------------------------------- 6. approve -> execute -> rollback
        assert _ok(client.post(f"/api/v1/actions/{action_id}/approve", headers=approver,
                               json={"reason": "collateral reviewed: dedicated C2 name"}))["case"]["state"] == "APPROVED"
        done = _ok(client.post(f"/api/v1/actions/{action_id}/execute", headers=approver,
                               json={"reason": "contain C2"}))
        assert done["execution"]["status"] == "applied" and done["case_state"] == "EXECUTED"
        assert any(owner == target or owner.endswith("." + target) for owner, _ in rpz.records(svc.clock()))
        assert _ok(client.get(f"/api/v1/actions/{action_id}", headers=viewer))["live"] is True
        back = _ok(client.post(f"/api/v1/actions/{action_id}/rollback", headers=approver,
                               json={"reason": "pilot rollback drill"}))
        assert back["execution"]["status"] == "rolled_back" and back["case_state"] == "ROLLED_BACK"
        assert rpz.records(svc.clock()) == [] and target not in rpz.zone_path.read_text()
        history = _ok(client.get(f"/api/v1/cases/{case_id}/history", headers=viewer))["items"]
        states = [h["payload"]["to_state"] for h in history if h["entry_type"] == "case_transition"]
        assert states[-7:] == ["TRIAGE", "INVESTIGATING", "VERIFIED", "PROPOSED", "APPROVED", "EXECUTED", "ROLLED_BACK"]

        # ---------------------------------------------------------------- 7. PoV report
        truth = dict(corpus.labels)
        onsets = {d.entity_pseudonym: d.infected_at for d in corpus.devices if d.malicious and d.infected_at}
        svc.register_lab_context(TENANT, LabContext(onsets=onsets, ground_truth=truth, source=LAB_LABEL_SOURCE,
                                                    period=ReportPeriod(corpus.start, corpus.end)))
        params = {"format": "json", "start": corpus.start.isoformat(),
                  "end": (svc.clock() + timedelta(hours=1)).isoformat()}
        pov = _ok(client.get("/api/v1/reports/pov", params=params, headers=viewer))
        assert pov["tenant_id"] == TENANT and pov["alerts"]["alerts"] >= 1
        assert pov["attestation"]["live_executions"] == 1 and pov["attestation"]["rollbacks"] == 1
        assert pov["attestation"]["status"] == "enforcement_recorded"
        validation = pov["validation"]
        assert validation is not None and validation["tp"] >= 1 and validation["device_days"] > 0
        assert pov["ledger"]["ok"] is True and pov["evidence"]
        html = client.get("/api/v1/reports/pov", params={"start": params["start"], "end": params["end"]},
                          headers=viewer)
        assert html.status_code == 200 and "AEGIS" in html.text and "<html" in html.text.lower()

        # ---------------------------------------------------------------- 8. ledger verify + replay
        ledger = _ok(client.get("/api/v1/ledger/verify", headers=viewer))
        assert ledger["ok"] is True and ledger["entry_count"] > 100 and ledger["first_bad_seq"] is None
        replay = _ok(client.get(f"/api/v1/cases/{case_id}/replay", headers=viewer))
        kinds = {d["entry_type"] for d in replay["decisions"]}
        assert {"case_transition", "action", "authorization", "execution"} <= kinds
        metrics = _ok(client.get("/api/v1/metrics/summary", headers=viewer))
        assert metrics["actions"]["enforcement_applied"] == 1 and metrics["actions"]["live_enforcements"] == 0
        assert isinstance(datetime.fromisoformat(str(pov["generated_at"]).replace("Z", "+00:00")), datetime)
    finally:
        svc.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
