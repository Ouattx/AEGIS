"""Shared fixtures-as-functions for the MIRROR tests (no tests in this module)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from aegis.contracts.models import (
    ActionType,
    MirrorResult,
    MirrorVerdict,
    OperatorPolicy,
    ProposedAction,
)
from aegis.lab.topology import Endpoint, HostingTopology, HostRecord
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer, sign_model
from aegis.storage.db import init_db, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
TENANT = "isp-a"

C2_IP = "203.0.113.10"
C2_DOMAIN = "c2.bad.example"
CDN_IP = "198.18.0.10"
CDN_NAMES = ["edge01.streamcdn.example", "www.news1.example", "www.shop2.example",
             "img.bad.example"]
RESOLVER_IP = "198.18.255.53"
VICTIM_IP = "192.0.2.10"
LEGIT_API_IP = "198.18.64.5"
LEGIT_API = "api.legit.example"
TVBOX_BAD_IP = "203.0.113.11"
TVBOX_FW_IP = "198.18.64.7"


def topology(complete: bool = True) -> HostingTopology:
    hosts = [
        HostRecord(ip=C2_IP, asn=64700, provider="BulletHost VPS", kind="dedicated",
                   hostnames=[C2_DOMAIN]),
        HostRecord(ip=CDN_IP, asn=64600, provider="StreamCDN Global", kind="shared_cdn",
                   hostnames=list(CDN_NAMES)),
        HostRecord(ip=RESOLVER_IP, asn=64670, provider="ISP Core Services", kind="resolver",
                   hostnames=["resolver.isp.example"]),
        HostRecord(ip=VICTIM_IP, asn=64710, provider="Victim Hosting", kind="victim",
                   hostnames=["shop0.victim-hosting.example"]),
        HostRecord(ip=LEGIT_API_IP, asn=64630, provider="Hyperscale Cloud", kind="cloud",
                   hostnames=[LEGIT_API]),
        HostRecord(ip=TVBOX_BAD_IP, asn=64700, provider="BulletHost VPS", kind="dedicated",
                   hostnames=["api.tvbox.example"]),
        HostRecord(ip=TVBOX_FW_IP, asn=64630, provider="Hyperscale Cloud", kind="cloud",
                   hostnames=["fw.tvbox.example"]),
    ]
    services = {"web": [Endpoint(LEGIT_API, LEGIT_API_IP, 443)],
                "firmware": [Endpoint("fw.tvbox.example", TVBOX_FW_IP, 443)]}
    return HostingTopology("topo-test", hosts, services, complete=complete)


def action(action_type: ActionType = ActionType.DNS_SINKHOLE, targets: list[str] | None = None,
           **kw: Any) -> ProposedAction:
    defaults: dict[str, Any] = dict(
        tenant_id=TENANT, case_id="case-1", action_type=action_type,
        targets=targets if targets is not None else [C2_DOMAIN],
        legal_basis="operator_tos_security_clause",
        expires_at=T0 + timedelta(hours=12),
        rollback_plan="remove RPZ entry and reload resolver",
        rollback_verified=True, created_by="agent:response_planner", created_at=T0)
    defaults.update(kw)
    return ProposedAction(**defaults)


def signer_and_ring(key_id: str = "op-key-1") -> tuple[Signer, KeyRing]:
    s = Signer.generate(key_id)
    ring = KeyRing()
    ring.add_signer(s)
    return s, ring


def policy(signer: Signer, **kw: Any) -> OperatorPolicy:
    defaults: dict[str, Any] = dict(
        policy_id="pol-1", tenant_id=TENANT, mode="active",
        allowed_actions=[ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK],
        max_targets_per_action=3, max_ttl_hours=24,
        approved_scope={"include_subdomains": False, "max_entities": 10,
                        "regions": ["paris", "lyon"],
                        "legal_bases": ["operator_tos_security_clause"]},
        legal_signoff_ref="LEGAL-2026-014",
        valid_from=T0 - timedelta(days=1), valid_until=T0 + timedelta(days=30),
        signer_key_id="placeholder", signature="")
    defaults.update(kw)
    return sign_model(OperatorPolicy(**defaults), signer)


def safe_mirror(act: ProposedAction, **kw: Any) -> MirrorResult:
    defaults: dict[str, Any] = dict(
        action_id=act.action_id, verdict=MirrorVerdict.SAFE, affected_entities=3,
        legitimate_cotenants=[], shared_infrastructure=False, historic_daily_legit_flows=0,
        reversibility="minutes", unknowns=[], requires_human_approval=False,
        rationale="test", computed_at=T0 - timedelta(minutes=1))
    defaults.update(kw)
    return MirrorResult(**defaults)


def ledger(tmp_path, signer: Signer | None = None) -> Ledger:
    eng = make_engine(f"sqlite:///{tmp_path / 'mirror.db'}")
    init_db(eng)
    return Ledger(make_session_factory(eng), signer=signer)


def session_factory(tmp_path, name: str = "constellation.db"):
    eng = make_engine(f"sqlite:///{tmp_path / name}")
    init_db(eng)
    return make_session_factory(eng)


class Clock:
    """Mutable test clock."""

    def __init__(self, t: datetime = T0):
        self.t = t

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t = self.t + timedelta(**kw)
