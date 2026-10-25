"""Shared builders for the API test modules (no tests here)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.auth import mint_dev_token
from aegis.api.settings import Settings
from aegis.contracts.models import ActionType, Evidence, EvidenceKind, Finding, OperatorPolicy, Verdict
from aegis.provenance.signing import Signer, sign_model
from aegis.service import AegisService

C2_DOMAIN = "c2.badbox.example"
C2_IP = "203.0.113.10"
ENTITY = "p_" + "a" * 32


def make_settings(tmp: Path, **kw: Any) -> Settings:
    base: dict[str, Any] = dict(auth_mode="dev", data_dir=tmp, dev_jwt_secret="s" * 48, log_format="text",
                                sweep_interval_s=0, llm_enabled=False,
                                # hermetic: a locally built web/dist must not change API test outcomes
                                web_dist=tmp / "no-console")
    base.update(kw)
    return Settings(**base)


def make_service(tmp: Path, **kw: Any) -> AegisService:
    return AegisService(make_settings(tmp, **kw), load_default_model=False, use_env_llm=False)


def make_client(svc: AegisService) -> TestClient:
    return TestClient(create_app(svc.settings, service=svc))


def token(svc: AegisService, tenant: str, *roles: str, sub: str | None = None) -> str:
    return mint_dev_token(svc.settings, sub=sub or f"{tenant}-{'-'.join(roles)}", tenant_id=tenant,
                          roles=list(roles))


def auth(svc: AegisService, tenant: str, *roles: str, sub: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(svc, tenant, *roles, sub=sub)}"}


def seed_case(svc: AegisService, tenant: str, *, origins: int = 2, domain: str = C2_DOMAIN) -> tuple[Finding, str]:
    """A MALICIOUS finding backed by ``origins`` independent observations, and its opened case."""
    now = svc.clock()
    ids = []
    for i in range(origins):
        ev = svc.evidence.append(Evidence(
            tenant_id=tenant, kind=EvidenceKind.OBSERVATION, origin_source=f"sensor:test-{i}",
            source_independence_group=f"group-{i}", collected_at=now, summary=f"beacon to {domain}",
            payload={"domain": domain, "ip": C2_IP}, authorization_id="auth-test"))
        ids.append(ev.evidence_id)
    f = Finding(tenant_id=tenant, entity_pseudonym=ENTITY, device_class="android_tv", detector_version="test/1",
                label="c2_beaconing", verdict=Verdict.MALICIOUS, score=0.97, calibration_id="cal-test",
                observed_window_start=now - timedelta(hours=1), observed_window_end=now, evidence_ids=ids,
                created_at=now, expires_at=now + timedelta(days=3))
    svc.docs.put(f)
    case = svc.cases.open_case(f)
    return f, case.case_id


def verify_case(svc: AegisService, tenant: str, case_id: str, actor: str = "alice") -> None:
    from aegis.contracts.models import CaseState
    svc.cases.transition(tenant, case_id, CaseState.TRIAGE, actor, "triage")
    svc.cases.transition(tenant, case_id, CaseState.INVESTIGATING, actor, "investigate")
    svc.cases.record_counter_hypothesis_review(tenant, case_id, reviewer=actor, alternatives=["benign IPTV"],
                                               notes="ruled out")
    svc.cases.transition(tenant, case_id, CaseState.VERIFIED, actor, "confirmed")


def operator_signer(svc: AegisService, key_id: str = "operator-key") -> Signer:
    signer = Signer.generate(key_id)
    svc.trust_key("policy", key_id, signer.public_pem())
    return signer


def signed_policy(svc: AegisService, tenant: str, signer: Signer, *, mode: str = "active",
                  policy_id: str | None = None, legal: str | None = "LEGAL-2026-001",
                  valid_until: datetime | None = None) -> dict[str, Any]:
    now = svc.clock()
    p = OperatorPolicy(policy_id=policy_id or f"{tenant}-{mode}-policy", tenant_id=tenant, mode=mode,  # type: ignore[arg-type]
                       allowed_actions=[ActionType.DNS_SINKHOLE, ActionType.NOTIFY_SUBSCRIBER],
                       max_targets_per_action=3, max_ttl_hours=48,
                       approved_scope={"max_entities": 3, "legal_bases": ["operator_tos_security_clause"]},
                       legal_signoff_ref=legal, valid_from=now - timedelta(hours=1),
                       valid_until=valid_until or now + timedelta(days=30), signer_key_id=signer.key_id,
                       signature="")
    return sign_model(p, signer).model_dump(mode="json")


def topology_doc(domain: str = C2_DOMAIN, ip: str = C2_IP) -> dict[str, Any]:
    return {"topology_id": "test-topology", "complete": True, "prefixes": ["203.0.113.0/24"],
            "hosts": [{"ip": ip, "kind": "dedicated", "hostnames": [domain]},
                      {"ip": "203.0.113.20", "kind": "shared_cdn", "hostnames": ["a.cdn.example", "b.cdn.example"]}]}


def prepare_enforceable(svc: AegisService, tenant: str) -> None:
    """Topology + traffic history so a sinkhole of the C2 domain simulates SAFE."""
    svc.load_topology(tenant, "admin", topology_doc())
    svc.history.add(tenant, C2_DOMAIN, entity=ENTITY)
    svc.history.set_window(tenant, 1.0)


def propose_body(case_id: str, **kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"case_id": case_id, "action_type": "dns_sinkhole", "targets": [C2_DOMAIN],
                            "scope": {"max_entities": 1}, "legal_basis": "operator_tos_security_clause",
                            "expires_in_hours": 12, "rollback_plan": "remove the RPZ entry",
                            "rollback_verified": True}
    body.update(kw)
    return body


def utc(*a: int) -> datetime:
    return datetime(*a, tzinfo=timezone.utc)  # type: ignore[misc]
