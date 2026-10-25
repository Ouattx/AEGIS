"""Shared worlds and helpers for the spec section 15 safety tests (fixtures registered in conftest.py).

Every world is the real composed system: an :class:`aegis.service.AegisService`
on its own SQLite store and data directory, the shipped calibrated detection
model, a real RPZ enforcement adapter writing a zone file, the FastAPI app on top,
and lab telemetry ingested from collector files through the production pipeline
(:func:`aegis.api.demo.seed_lab_demo`). Nothing is mocked except the language
model, which is either absent or a deliberately failing / hostile client.

* ``pilot``       - a paid shadow-mode pilot: signed **shadow** operator policy,
                    no LLM. Read-mostly; used by detection, isolation, telemetry
                    and shadow-mode tests.
* ``enforcement`` - the same lab corpus in another tenant of another deployment
                    whose LLM is configured but unreachable, with a signed
                    **active** operator policy (legal sign-off) and a controllable
                    clock. Used by the enforcement-path tests; each test claims its
                    own case from a pool so tests stay independent.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient

from aegis.api.app import create_app
from aegis.api.auth import mint_dev_token
from aegis.api.demo import DemoSummary, demo_start, seed_lab_demo
from aegis.api.settings import Settings
from aegis.contracts.models import ActionType, CaseState, Evidence, OperatorPolicy
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.mirror.rpz import RPZAdapter
from aegis.oracle.llm import LLMResponse
from aegis.oracle.tools import indicators_from_evidence
from aegis.provenance.signing import Signer, sign_model
from aegis.sentinel.model import TrainedModel, load_default
from aegis.service import AegisService

#: one lab configuration for every world, so worlds are comparable device by device
# one case per device incident: enough compromised devices that every enforcement test claims its own case
LAB = dict(seed=7, days=2, n_devices=64, malicious_fraction=0.2)
LEAVE_OPEN = 5
START = demo_start(LAB["days"])
PILOT_TENANT = "pilot-isp"
ENFORCE_TENANT = "enforce-isp"
LEGAL_BASIS = "operator_tos_security_clause"


class Clock:
    """Controllable UTC clock handed to the service (starts at real time)."""

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(timezone.utc) + self.offset

    def advance(self, delta: timedelta) -> None:
        self.offset += delta

    def reset(self) -> None:
        self.offset = timedelta(0)


class FailingLLM:
    """An LLM endpoint that is configured but down: every call raises."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, *, system: str, messages: list[dict[str, str]], max_tokens: int) -> LLMResponse | None:
        self.calls += 1
        raise ConnectionError("LLM endpoint unreachable")


def make_settings(tmp: Path, **kw: Any) -> Settings:
    base: dict[str, Any] = dict(auth_mode="dev", data_dir=tmp, dev_jwt_secret="s" * 48, log_format="text",
                                sweep_interval_s=0, llm_enabled=False, rate_limit_burst=100_000,
                                rate_limit_rps=10_000.0, web_dist=tmp / "no-console")
    base.update(kw)
    return Settings(**base)


def build_service(tmp: Path, *, clock: Clock | None = None, llm: Any | None = None,
                  model: TrainedModel | None = None) -> tuple[AegisService, RPZAdapter]:
    rpz = RPZAdapter(tmp / "enforcement" / "aegis.rpz")
    # the live RPZ adapter is bound to the enforcement tenant, as AEGIS_ENFORCEMENT_TENANT does in production
    svc = AegisService(make_settings(tmp, enforcement_tenant=ENFORCE_TENANT), model=model or load_default(),
                       adapter=rpz, llm=llm, use_env_llm=False, clock=clock)
    return svc, rpz


def headers(svc: AegisService, tenant: str, *roles: str, sub: str | None = None) -> dict[str, str]:
    tok = mint_dev_token(svc.settings, sub=sub or f"{tenant}-{'-'.join(roles)}", tenant_id=tenant,
                         roles=list(roles))
    return {"Authorization": f"Bearer {tok}"}


def lab_corpus(tenant: str) -> Corpus:
    return generate_corpus(seed=LAB["seed"], days=LAB["days"], n_devices=LAB["n_devices"],
                           malicious_fraction=LAB["malicious_fraction"], tenant_id=tenant, start=START)


@dataclass
class World:
    tenant: str
    svc: AegisService
    client: TestClient
    rpz: RPZAdapter
    clock: Clock
    corpus: Corpus
    summary: DemoSummary
    tmp: Path
    llm: Any | None = None
    operator: Signer | None = None
    active_policy_id: str | None = None
    case_pool: list[str] = field(default_factory=list)

    def h(self, *roles: str, sub: str | None = None) -> dict[str, str]:
        return headers(self.svc, self.tenant, *roles, sub=sub)


def _seed(tmp: Path, tenant: str, *, llm: Any | None) -> World:
    clock = Clock()
    svc, rpz = build_service(tmp, clock=clock, llm=llm)
    summary = seed_lab_demo(svc, tenant_id=tenant, leave_open=LEAVE_OPEN, start=START, **LAB)
    return World(tenant=tenant, svc=svc, client=TestClient(create_app(svc.settings, service=svc)), rpz=rpz,
                 clock=clock, corpus=lab_corpus(tenant), summary=summary, tmp=tmp, llm=llm)


@pytest.fixture(scope="session")
def pilot(tmp_path_factory: pytest.TempPathFactory) -> Iterator[World]:
    w = _seed(tmp_path_factory.mktemp("pilot"), PILOT_TENANT, llm=None)
    yield w
    w.svc.close()


def active_policy(svc: AegisService, tenant: str, signer: Signer, *, policy_id: str,
                  valid_for: timedelta = timedelta(days=30)) -> dict[str, Any]:
    now = svc.clock()
    p = OperatorPolicy(policy_id=policy_id, tenant_id=tenant, mode="active",
                       allowed_actions=[ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK, ActionType.NOTIFY_SUBSCRIBER],
                       max_targets_per_action=5, max_ttl_hours=72,
                       approved_scope={"max_entities": 5, "legal_bases": [LEGAL_BASIS], "max_affected_entities": 50},
                       legal_signoff_ref="LEGAL-PILOT-2026-014", valid_from=now - timedelta(hours=1),
                       valid_until=now + valid_for, signer_key_id=signer.key_id, signature="")
    return sign_model(p, signer).model_dump(mode="json")


@pytest.fixture(scope="session")
def enforcement(tmp_path_factory: pytest.TempPathFactory) -> Iterator[World]:
    w = _seed(tmp_path_factory.mktemp("enforcement"), ENFORCE_TENANT, llm=FailingLLM())
    signer = Signer.generate("isp-operator-1")
    w.svc.trust_key("policy", signer.key_id, signer.public_pem())
    w.operator = signer
    w.active_policy_id = f"{ENFORCE_TENANT}-active-1"
    w.svc.load_policy(w.tenant, "admin@isp", active_policy(w.svc, w.tenant, signer, policy_id=w.active_policy_id))
    cases = w.svc.list_cases(w.tenant, limit=1000).items
    w.case_pool = sorted(c.case_id for c in cases if c.state in (CaseState.VERIFIED, CaseState.INVESTIGATING)
                         and not w.svc.cases.assess_evidence(c).contested)
    yield w
    w.svc.close()


# ----------------------------------------------------------------------------- case helpers


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def case_indicators(world: World, case_id: str) -> list[str]:
    svc = world.svc
    case = svc.get_case(world.tenant, case_id)
    evs = [e for e in (svc.docs.get(Evidence, world.tenant, eid) for eid in case.evidence_ids)
           if e is not None and e.supports]
    return indicators_from_evidence(evs)


def claim_verified_case(world: World, *, analyst: str = "analyst.alice") -> str:
    """Take the next case from the pool and make sure it is VERIFIED (by a human analyst)."""
    assert world.case_pool, "enforcement world has no unclaimed verifiable case left"
    case_id = world.case_pool.pop(0)
    svc = world.svc
    case = svc.get_case(world.tenant, case_id)
    if case.state is CaseState.INVESTIGATING:
        svc.review_case(world.tenant, case_id, analyst, ["benign IPTV or streaming workload",
                                                         "shared CDN co-hosting the indicator"],
                        "beacon periodicity and signed IOC contact inconsistent with benign streaming")
        svc.transition_case(world.tenant, case_id, CaseState.VERIFIED, analyst, "compromise confirmed")
    assert svc.get_case(world.tenant, case_id).state is CaseState.VERIFIED
    return case_id


def propose(world: World, case_id: str, targets: list[str], *, action_type: str = "dns_sinkhole",
            proposer: str = "analyst.alice", expires_in: timedelta = timedelta(hours=12),
            rollback_verified: bool = True) -> str:
    action = world.svc.propose_action(world.tenant, proposer, case_id=case_id, action_type=action_type,
                                      targets=targets, scope={"max_entities": 1}, legal_basis=LEGAL_BASIS,
                                      expires_at=world.svc.clock() + expires_in,
                                      rollback_plan="remove the RPZ entry and reload the resolver",
                                      rollback_verified=rollback_verified)
    return action.action_id


def safe_sinkhole(world: World, case_id: str, *, proposer: str = "analyst.alice") -> tuple[str, str]:
    """Propose a DNS sinkhole of one of the case's malicious names that MIRROR finds SAFE."""
    for target in [i for i in case_indicators(world, case_id) if not is_ip(i)]:
        action_id = propose(world, case_id, [target], proposer=proposer)
        if world.svc.simulate_action(world.tenant, proposer, action_id).verdict.value == "SAFE":
            return action_id, target
    raise AssertionError(f"no SAFE sinkhole target for case {case_id}")


def zone_owners(world: World) -> set[str]:
    return {owner for owner, _ in world.rpz.records(world.svc.clock())}
