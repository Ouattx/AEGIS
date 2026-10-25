"""Spec section 15 mandatory tests that MIRROR owns, run end to end.

simulate -> authorize -> Executor(RPZAdapter) with the lab topology, a real
ledger and a real signed policy.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from test_mirror_helpers import (
    T0,
    TENANT,
    Clock,
    action,
    ledger,
    policy,
    signer_and_ring,
)

from aegis.contracts.models import ActionType, MirrorVerdict
from aegis.lab.topology import generate_topology
from aegis.mirror import (
    AggregateTrafficHistory,
    CircuitBreaker,
    ExecutionStatus,
    Executor,
    RPZAdapter,
    authorize,
    simulate,
)
from aegis.provenance.ledger import EntryType
from aegis.provenance.signing import Signer

pytestmark = pytest.mark.safety


@pytest.fixture
def world(tmp_path):
    topo = generate_topology(7)
    bb = topo.malicious["badbox2_emu"]
    hist = AggregateTrafficHistory()
    hist.set_window(TENANT, 1)
    for i in range(5):
        hist.add(TENANT, bb.c2_ips[0], flows=20, entity=f"p_infected{i:04d}")
        hist.add(TENANT, bb.c2_domains[0], flows=20, entity=f"p_infected{i:04d}")
        hist.add(TENANT, "img.tvsync-update.example", flows=5, entity=f"p_infected{i:04d}")
    signer, ring = signer_and_ring()
    clock = Clock()
    led = ledger(tmp_path, signer=Signer.generate("ledger-key"))
    rpz = RPZAdapter(tmp_path / "aegis.rpz")
    breaker = CircuitBreaker(clock=clock, min_requests=20)
    ex = Executor(rpz, led, breaker, clock=clock)
    return dict(topo=topo, bb=bb, hist=hist, signer=signer, ring=ring, clock=clock, led=led,
                rpz=rpz, ex=ex, breaker=breaker)


def _pipeline(w, act, *, pol=None, case_indicators=(), approver="analyst.alice", now=None):
    now = now or w["clock"]()
    m = simulate(act, w["topo"], None, w["hist"], now=now, case_indicators=case_indicators)
    d = authorize(act, pol if pol is not None else policy(w["signer"]), w["ring"], m, True, now)
    rec = w["ex"].execute(act, d, approver)
    return m, d, rec


def test_shared_cdn_not_indiscriminately_blocked(world):
    w = world
    cdn = next(ip for ip, h in w["topo"].hosts.items()
               if "img.tvsync-update.example" in h.hostnames)
    act = action(ActionType.IP_BLOCK, [cdn])
    m, d, rec = _pipeline(w, act, case_indicators=w["bb"].c2_domains + w["bb"].cohosted_domains)
    assert m.verdict is MirrorVerdict.UNSAFE and m.shared_infrastructure
    assert len(m.legitimate_cotenants) >= 20
    assert not d.allowed and "mirror_not_safe" in d.failed_checks
    assert d.requires_human_approval
    assert rec.status is ExecutionStatus.REFUSED
    assert w["rpz"].records(T0) == []
    # the precise alternative - sinkhole only the malicious name - goes through
    precise = action(targets=["img.tvsync-update.example"])
    m2, d2, rec2 = _pipeline(w, precise, case_indicators=["img.tvsync-update.example"])
    assert m2.verdict is MirrorVerdict.SAFE, m2.rationale
    assert d2.allowed
    assert rec2.status is ExecutionStatus.APPLIED
    assert w["rpz"].records(T0) == [("img.tvsync-update.example", ".")]


def test_expired_authorization_prevents_action(world):
    w = world
    act = action(targets=[w["bb"].c2_domains[0]], expires_at=T0 + timedelta(minutes=30))
    m = simulate(act, w["topo"], None, w["hist"], now=T0)
    d = authorize(act, policy(w["signer"]), w["ring"], m, True, T0)
    assert d.allowed
    w["clock"].advance(minutes=31)
    rec = w["ex"].execute(act, d, "analyst.alice")
    assert rec.status is ExecutionStatus.REFUSED
    assert "action_expired" in rec.refusal_reasons
    assert w["rpz"].records(w["clock"]()) == []
    # an expired operator policy denies at authorization time as well
    late = T0 + timedelta(days=40)
    act2 = action(targets=[w["bb"].c2_domains[0]], expires_at=late + timedelta(hours=1))
    m2 = simulate(act2, w["topo"], None, w["hist"], now=late)
    d2 = authorize(act2, policy(w["signer"]), w["ring"], m2, True, late)
    assert "policy_expired" in d2.failed_checks and not d2.allowed


def test_live_enforcement_expires_with_authorization(world):
    w = world
    act = action(targets=[w["bb"].c2_domains[0]], expires_at=T0 + timedelta(hours=1))
    _, _d, rec = _pipeline(w, act)
    assert rec.status is ExecutionStatus.APPLIED
    w["clock"].advance(hours=1, seconds=1)
    swept = w["ex"].sweep_expired()
    assert [r.status for r in swept] == [ExecutionStatus.ROLLED_BACK]
    assert w["rpz"].records(T0) == []


def test_rollback_restores_service(world):
    w = world
    bystander = action(targets=["cfg.boxhelper.example"])
    _pipeline(w, bystander)
    baseline_zone = w["rpz"].records(T0)
    act = action(targets=[w["bb"].c2_domains[0]])
    _, _, rec = _pipeline(w, act)
    assert rec.status is ExecutionStatus.APPLIED
    assert (w["bb"].c2_domains[0], ".") in w["rpz"].records(T0)
    # legit traffic degrades: breaker trips and service is restored automatically
    w["ex"].observe_legit_traffic(act.action_id, 100, 1)
    assert w["ex"].observe_legit_traffic(act.action_id, 100, 40)
    assert w["rpz"].records(T0) == baseline_zone
    assert w["ex"].records(act.action_id)[-1].status is ExecutionStatus.ROLLED_BACK
    ok, bad = w["led"].verify_chain(TENANT)
    assert ok and bad is None


@pytest.mark.parametrize("variant", ["no_policy", "shadow", "forged", "no_signoff",
                                     "agent_approver", "no_approver", "unsafe_mirror"])
def test_unauthorized_blocking_is_impossible(world, variant):
    w = world
    act = action(targets=[w["bb"].c2_domains[0]])
    now = w["clock"]()
    m = simulate(act, w["topo"], None, w["hist"], now=now)
    pol = policy(w["signer"])
    approver = "analyst.alice"
    if variant == "no_policy":
        pol = None
    elif variant == "shadow":
        pol = policy(w["signer"], mode="shadow")
    elif variant == "forged":
        rogue, _ = signer_and_ring("attacker")
        pol = policy(rogue)
    elif variant == "no_signoff":
        pol = policy(w["signer"], legal_signoff_ref=None)
    elif variant == "agent_approver":
        approver = "agent:response_planner"
    elif variant == "no_approver":
        approver = ""
    elif variant == "unsafe_mirror":
        m = m.model_copy(update={"verdict": MirrorVerdict.UNKNOWN})
    d = authorize(act, pol, w["ring"], m, True, now)
    rec = w["ex"].execute(act, d, approver)
    assert rec.status is ExecutionStatus.REFUSED
    assert w["rpz"].records(now) == []
    assert not w["rpz"].zone_path.exists()
    entries = w["led"].entries(TENANT, subject_id=act.action_id, entry_type=EntryType.EXECUTION)
    assert [e.payload["status"] for e in entries] == ["refused"]
