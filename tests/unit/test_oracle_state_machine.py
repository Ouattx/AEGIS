from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.constellation import Constellation
from aegis.contracts.models import (
    ActionType,
    AuthorizationDecision,
    CaseState,
    Evidence,
    EvidenceKind,
    Finding,
    MirrorResult,
    MirrorVerdict,
    OperatorPolicy,
    ProposedAction,
    Verdict,
)
from aegis.oracle.state_machine import (
    ALLOWED_TRANSITIONS,
    MAJOR_TRANSITIONS,
    SIGNED_IOC_FLAG,
    TERMINAL_STATES,
    CaseService,
    GuardError,
    is_signed_ioc_hit,
)
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing, Signer, sign_model
from aegis.provenance.snapshot import replay
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory

S = CaseState
TEN = "isp-a"
NOW = datetime.now(timezone.utc)


class Env:
    def __init__(self, tmp_path, *, with_keyring: bool = True):
        self.engine = make_engine(f"sqlite:///{tmp_path / 'oracle.db'}")
        init_db(self.engine)
        sf = make_session_factory(self.engine)
        self.sf = sf
        self.ledger_signer = Signer.generate("ledger-k")
        self.ledger = Ledger(sf, self.ledger_signer)
        self.docs = DocStore(sf)
        self.evidence = EvidenceStore(self.docs, self.ledger)
        self.policy_signer = Signer.generate("policy-k")
        self.ring = KeyRing()
        self.ring.add_signer(self.policy_signer)
        self.ring.add_signer(self.ledger_signer)
        self.constellation = Constellation(sf, ledger=self.ledger)
        self.svc = CaseService(self.docs, self.evidence, self.ledger,
                               keyring=self.ring if with_keyring else None, constellation=self.constellation)

    def ev(self, group: str, *, kind=EvidenceKind.OBSERVATION, supports=True, payload=None,
           origin=None) -> Evidence:
        return self.evidence.append(Evidence(
            tenant_id=TEN, kind=kind, origin_source=origin or f"src:{group}",
            source_independence_group=group, collected_at=NOW - timedelta(minutes=5),
            summary=f"{kind.value} from {group}", payload=payload or {},
            authorization_id="auth-collect-1", supports=supports))

    def finding(self, evidence: list[Evidence], *, verdict=Verdict.SUSPICIOUS) -> Finding:
        f = Finding(tenant_id=TEN, entity_pseudonym="p_dev1", device_class="android_tv",
                    detector_version="sentinel-1.0", label="c2_beaconing", verdict=verdict,
                    score=0.82, calibration_id="cal-1", observed_window_start=NOW - timedelta(hours=1),
                    observed_window_end=NOW,
                    evidence_ids=[e.evidence_id for e in evidence if e.supports],
                    counterevidence_ids=[e.evidence_id for e in evidence if not e.supports],
                    created_at=NOW, expires_at=NOW + timedelta(days=7))
        self.docs.put(f)
        return f

    def investigating(self, evidence: list[Evidence]):
        case = self.svc.open_case(self.finding(evidence))
        self.svc.transition(TEN, case.case_id, S.TRIAGE, "system", "auto triage")
        return self.svc.transition(TEN, case.case_id, S.INVESTIGATING, "system", "investigate")

    def review(self, case_id: str, reviewer: str = "analyst@isp"):
        return self.svc.record_counter_hypothesis_review(
            TEN, case_id, reviewer=reviewer, alternatives=["IPTV licence polling"],
            notes="destination is dedicated hosting, not an IPTV provider")

    def verified(self):
        case = self.investigating([self.ev("sensor:netflow"), self.ev("grp:alpha",
                                                                       kind=EvidenceKind.IOC_MATCH)])
        self.review(case.case_id)
        return self.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "two origins")

    def action(self, case_id: str, *, expires=True, atype=ActionType.DNS_SINKHOLE) -> ProposedAction:
        a = ProposedAction(tenant_id=TEN, case_id=case_id, action_type=atype,
                           targets=["c2.example"], scope={"max_entities": 1},
                           legal_basis="operator_tos_security_clause",
                           expires_at=NOW + timedelta(hours=12) if expires else None,
                           rollback_plan="remove RPZ entry", rollback_verified=True,
                           created_by="analyst@isp", created_at=NOW)
        self.docs.put(a)
        return a

    def policy(self, *, mode="active", signoff="LEGAL-2026-17", valid_until=None,
               allowed=(ActionType.DNS_SINKHOLE,), signer=None) -> OperatorPolicy:
        p = OperatorPolicy(policy_id="pol-1", tenant_id=TEN, mode=mode, allowed_actions=list(allowed),
                           legal_signoff_ref=signoff, valid_from=NOW - timedelta(days=1),
                           valid_until=valid_until or NOW + timedelta(days=30),
                           signer_key_id="", signature="")
        return sign_model(p, signer or self.policy_signer)

    def authz(self, action: ProposedAction, *, allowed=True, policy_id="pol-1") -> AuthorizationDecision:
        return AuthorizationDecision(action_id=action.action_id, allowed=allowed,
                                     failed_checks=[] if allowed else ["mirror_unsafe"],
                                     requires_human_approval=True, evaluated_at=NOW,
                                     policy_id=policy_id)

    def mirror(self, action: ProposedAction, verdict=MirrorVerdict.SAFE) -> MirrorResult:
        return MirrorResult(action_id=action.action_id, verdict=verdict, affected_entities=1,
                            reversibility="instant", requires_human_approval=False,
                            rationale="dedicated C2 name, no co-tenants", computed_at=NOW)

    def approved(self):
        case = self.verified()
        act = self.action(case.case_id)
        au = self.authz(act)
        self.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "propose sinkhole",
                            authorization=au)
        case = self.svc.transition(TEN, case.case_id, S.APPROVED, "approver@isp", "approved",
                                   authorization=au)
        return case, act, au


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.engine.dispose()


def failed_checks(excinfo) -> list[str]:
    return excinfo.value.failed


# ----------------------------------------------------------------------------- table

def test_allowed_transitions_follow_spec():
    assert ALLOWED_TRANSITIONS[S.NEW] == {S.TRIAGE}
    assert ALLOWED_TRANSITIONS[S.TRIAGE] == {S.INVESTIGATING}
    assert ALLOWED_TRANSITIONS[S.INVESTIGATING] == {S.VERIFIED, S.REJECTED, S.INCONCLUSIVE}
    assert ALLOWED_TRANSITIONS[S.VERIFIED] == {S.PROPOSED, S.CLOSED}
    assert ALLOWED_TRANSITIONS[S.REJECTED] == {S.CLOSED}
    assert ALLOWED_TRANSITIONS[S.INCONCLUSIVE] == {S.CLOSED}
    assert ALLOWED_TRANSITIONS[S.PROPOSED] == {S.APPROVED, S.DENIED}
    assert ALLOWED_TRANSITIONS[S.APPROVED] == {S.EXECUTED, S.EXPIRED}
    assert ALLOWED_TRANSITIONS[S.EXECUTED] == {S.ROLLED_BACK, S.EXPIRED}
    assert TERMINAL_STATES == {S.CLOSED, S.DENIED, S.ROLLED_BACK, S.EXPIRED}
    assert set(ALLOWED_TRANSITIONS) == set(CaseState)
    # PROPOSED is only reachable from VERIFIED
    assert [s for s, nxt in ALLOWED_TRANSITIONS.items() if S.PROPOSED in nxt] == [S.VERIFIED]


# ----------------------------------------------------------------------------- open

def test_open_case_is_idempotent_and_ledgered(env):
    evs = [env.ev("sensor:netflow"), env.ev("grp:sinkhole", kind=EvidenceKind.THREAT_FEED, supports=False)]
    f = env.finding(evs)
    c1 = env.svc.open_case(f)
    c2 = env.svc.open_case(f)
    assert c1.case_id == c2.case_id == CaseService.case_id_for(TEN, f.finding_id)
    assert c1.state is S.NEW and set(c1.evidence_ids) == {e.evidence_id for e in evs}
    assert c1.model_versions == ["sentinel-1.0"] and c1.severity == "medium"
    opened = env.ledger.entries(TEN, subject_id=c1.case_id, entry_type=EntryType.CASE_TRANSITION)
    assert len(opened) == 1 and opened[0].payload["to_state"] == "NEW"
    assert opened[0].payload["finding_ids"] == [f.finding_id]


def test_open_case_refusals(env):
    f = env.finding([env.ev("s")], verdict=Verdict.BENIGN)
    with pytest.raises(ValueError):
        env.svc.open_case(f)
    f2 = env.finding([env.ev("s2")])
    with pytest.raises(GuardError):
        env.svc.open_case(f2, actor="agent:response_planner")


def test_severity_mapping(env):
    """Severity follows verification-grade evidence and threat class, not the score."""
    f = env.finding([env.ev("s")], verdict=Verdict.MALICIOUS)
    f = f.model_copy(update={"score": 0.95, "component_scores": {"ioc": 0.9, "ioc_independent_origins": 2.0}})
    assert env.svc.open_case(f).severity == "critical"
    f2 = env.finding([env.ev("s2")], verdict=Verdict.MALICIOUS)
    f2 = f2.model_copy(update={"score": 0.99, "entity_pseudonym": "p_dev2",
                               "component_scores": {"ioc": 0.9, "ioc_independent_origins": 1.0}})
    assert env.svc.open_case(f2).severity == "high"
    f3 = env.finding([env.ev("s3")], verdict=Verdict.SUSPICIOUS)
    f3 = f3.model_copy(update={"score": 0.99, "label": "ddos_bot", "entity_pseudonym": "p_dev3",
                               "component_scores": {"ioc": 0.0}})
    assert env.svc.open_case(f3).severity == "medium"
    f4 = env.finding([env.ev("s4")], verdict=Verdict.SUSPICIOUS)
    f4 = f4.model_copy(update={"score": 0.99, "label": "dga_activity", "entity_pseudonym": "p_dev4",
                               "component_scores": {"ioc": 0.0}})
    assert env.svc.open_case(f4).severity == "low"


# ----------------------------------------------------------------------------- basic transitions

def test_disallowed_transition_refused_and_logged(env):
    case = env.svc.open_case(env.finding([env.ev("s")]))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "skip ahead")
    assert failed_checks(ei) == ["transition_not_allowed:NEW->VERIFIED"]
    refused = env.ledger.entries(TEN, subject_id=case.case_id, entry_type="case_transition_refused")
    assert len(refused) == 1 and refused[0].payload["to_state"] == "VERIFIED"
    assert env.svc.get(TEN, case.case_id).state is S.NEW


def test_transition_requires_reason_and_actor(env):
    case = env.svc.open_case(env.finding([env.ev("s")]))
    with pytest.raises(GuardError):
        env.svc.transition(TEN, case.case_id, S.TRIAGE, "system", "  ")
    with pytest.raises(GuardError):
        env.svc.transition(TEN, case.case_id, S.TRIAGE, "", "x")


def test_agents_can_never_change_state(env):
    case = env.svc.open_case(env.finding([env.ev("s")]))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.TRIAGE, "agent:verifier", "I recommend")
    assert failed_checks(ei) == ["agent_cannot_change_case_state"]


def test_every_transition_is_ledgered_with_decision_hash(env):
    case = env.investigating([env.ev("a")])
    case = env.svc.transition(TEN, case.case_id, S.REJECTED, "analyst@isp", "benign IPTV")
    case = env.svc.transition(TEN, case.case_id, S.CLOSED, "analyst@isp", "done")
    assert [d.to_state for d in case.decisions] == [S.TRIAGE, S.INVESTIGATING, S.REJECTED, S.CLOSED]
    hashes = {e.entry_hash for e in env.ledger.entries(TEN, subject_id=case.case_id)}
    assert all(d.ledger_entry_hash in hashes for d in case.decisions)
    assert env.ledger.verify_chain(TEN, env.ring) == (True, None)
    with pytest.raises(GuardError):
        env.svc.transition(TEN, case.case_id, S.TRIAGE, "analyst@isp", "reopen")
    hist = env.svc.history(TEN, case.case_id)
    assert hist[0]["payload"]["event"] == "case_opened"


def test_unknown_or_cross_tenant_case(env):
    case = env.svc.open_case(env.finding([env.ev("s")]))
    with pytest.raises(LookupError):
        env.svc.transition("other-tenant", case.case_id, S.TRIAGE, "system", "x")
    assert env.svc.get("other-tenant", case.case_id) is None
    assert env.svc.list_cases("other-tenant") == []
    assert [c.case_id for c in env.svc.list_cases(TEN, state=S.NEW)] == [case.case_id]


# ----------------------------------------------------------------------------- VERIFIED guard

def test_verified_requires_two_independent_origins(env):
    case = env.investigating([env.ev("sensor:netflow")])
    env.review(case.case_id)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "one origin")
    assert "needs_two_independent_origins_or_signed_ioc_hit" in failed_checks(ei)


def test_syndicated_feeds_count_once(env):
    evs = [env.ev("grp:alpha", kind=EvidenceKind.THREAT_FEED, origin="feed:alpha"),
           env.ev("grp:alpha", kind=EvidenceKind.THREAT_FEED, origin="feed:alpha_mirror")]
    case = env.investigating(evs)
    env.review(case.case_id)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "two feeds")
    assert "needs_two_independent_origins_or_signed_ioc_hit" in failed_checks(ei)


def test_verified_requires_counter_hypothesis_review(env):
    case = env.investigating([env.ev("sensor:netflow"), env.ev("grp:alpha")])
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "x")
    assert failed_checks(ei) == ["counter_hypothesis_review_missing"]
    assert env.svc.check_transition(TEN, case.case_id, S.VERIFIED, "analyst@isp") == \
        ["counter_hypothesis_review_missing"]
    env.review(case.case_id)
    assert env.svc.check_transition(TEN, case.case_id, S.VERIFIED, "analyst@isp") == []
    case = env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "two origins")
    assert case.state is S.VERIFIED and case.snapshot_hash
    assert case.reviewer == "analyst@isp" and case.alternative_hypotheses


def test_verified_snapshots_ledger_and_constellation(env):
    case = env.verified()
    snaps = env.ledger.entries(TEN, subject_id=case.case_id, entry_type=EntryType.SNAPSHOT)
    assert snaps and snaps[-1].payload["snapshot_hash"] == case.snapshot_hash
    assert env.ledger.entries(TEN, subject_id=case.case_id, entry_type="constellation_snapshot")
    assert S.VERIFIED in MAJOR_TRANSITIONS


def test_signed_ioc_hit_alone_suffices(env):
    ioc = env.ev("grp:alpha", kind=EvidenceKind.IOC_MATCH,
                 payload={"bundle": {"signer_key_id": "lab-ioc", "sha256": "ab" * 32},
                          "verified_contact": True, "contradicted": False})
    assert is_signed_ioc_hit(ioc)
    case = env.investigating([ioc])
    env.review(case.case_id, reviewer="system")
    case = env.svc.transition(TEN, case.case_id, S.VERIFIED, "system", "signed IOC hit")
    assert case.state is S.VERIFIED


def test_signed_ioc_flag_and_negative_forms(env):
    flagged = env.ev("g1", kind=EvidenceKind.IOC_MATCH, payload={SIGNED_IOC_FLAG: True})
    assert is_signed_ioc_hit(flagged)
    lookup_only = env.ev("g2", kind=EvidenceKind.IOC_MATCH,
                         payload={"bundle": {"signer_key_id": "k", "sha256": "x"}, "verified_contact": False})
    contradicted = env.ev("g3", kind=EvidenceKind.IOC_MATCH,
                          payload={SIGNED_IOC_FLAG: True, "contradicted": True})
    agent_made = env.ev("g4", kind=EvidenceKind.IOC_MATCH,
                        payload={SIGNED_IOC_FLAG: True, "appended_by": "agent:evidence_collector"})
    feed = env.ev("g5", kind=EvidenceKind.THREAT_FEED, payload={SIGNED_IOC_FLAG: True})
    for ev in (lookup_only, contradicted, agent_made, feed):
        assert not is_signed_ioc_hit(ev)


def test_contradictory_feeds_downgrade(env):
    """Spec §15: contradictory feeds downgrade finding."""
    ioc = env.ev("grp:alpha", kind=EvidenceKind.IOC_MATCH, payload={SIGNED_IOC_FLAG: True})
    contra = env.ev("grp:sinkhole", kind=EvidenceKind.THREAT_FEED, supports=False)
    case = env.investigating([ioc, contra])
    env.review(case.case_id)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "signed hit")
    assert "contested_requires_two_independent_supporting_origins" in failed_checks(ei)
    assert "contradicting_origins_not_outweighed" in failed_checks(ei)
    # the case can still be routed to INCONCLUSIVE for human follow-up
    case = env.svc.transition(TEN, case.case_id, S.INCONCLUSIVE, "system", "contradictory evidence")
    assert case.state is S.INCONCLUSIVE


@pytest.mark.safety
def test_contested_case_requires_human_verifier(env):
    evs = [env.ev("sensor:netflow"), env.ev("grp:alpha", kind=EvidenceKind.THREAT_FEED),
           env.ev("grp:sinkhole", kind=EvidenceKind.THREAT_FEED, supports=False)]
    case = env.investigating(evs)
    env.review(case.case_id)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "system", "auto")
    assert failed_checks(ei) == ["contested_case_requires_human_verifier"]
    case = env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "2 vs 1, reviewed")
    assert case.state is S.VERIFIED


def test_tampered_and_stale_and_graph_evidence_do_not_qualify(env):
    good = env.ev("sensor:netflow")
    tampered = env.ev("grp:alpha")
    env.docs.put(tampered.model_copy(update={"summary": "rewritten"}))  # bypasses the store
    stale = env.ev("grp:delta", kind=EvidenceKind.IOC_MATCH,
                   payload={"indicator_expires_at": (NOW - timedelta(days=1)).isoformat()})
    graph = env.ev("grp:graph", kind=EvidenceKind.GRAPH_LINK)
    investigative = env.ev("grp:pred", payload={"investigative_only": True})
    case = env.investigating([good, tampered, stale, graph, investigative])
    a = env.svc.assess_evidence(env.svc.get(TEN, case.case_id))
    assert a.supporting_origins == ["sensor:netflow"]
    assert a.rejected == {tampered.evidence_id: "integrity_check_failed",
                          stale.evidence_id: "stale_indicator",
                          investigative.evidence_id: "investigative_only"}
    env.review(case.case_id)
    with pytest.raises(GuardError):
        env.svc.transition(TEN, case.case_id, S.VERIFIED, "analyst@isp", "x")


def test_counter_hypothesis_review_rules(env):
    case = env.investigating([env.ev("a")])
    with pytest.raises(GuardError):
        env.svc.record_counter_hypothesis_review(TEN, case.case_id, reviewer="agent:alternative_hypothesis",
                                                 alternatives=["x"], notes="y")
    with pytest.raises(GuardError):
        env.svc.record_counter_hypothesis_review(TEN, case.case_id, reviewer="analyst",
                                                 alternatives=["  "], notes="y")
    with pytest.raises(GuardError):
        env.svc.record_counter_hypothesis_review(TEN, case.case_id, reviewer="analyst",
                                                 alternatives=["x"], notes="")
    case = env.review(case.case_id)
    assert case.counter_hypothesis_reviewed
    assert env.ledger.entries(TEN, subject_id=case.case_id, entry_type="case_counter_hypothesis_review")


def test_attach_evidence_append_only(env):
    case = env.investigating([env.ev("a")])
    extra = env.ev("b")
    case2 = env.svc.attach_evidence(TEN, case.case_id, [extra.evidence_id], actor="analyst")
    assert case2.evidence_ids[-1] == extra.evidence_id
    assert env.svc.attach_evidence(TEN, case.case_id, [extra.evidence_id], actor="analyst") == case2
    with pytest.raises(LookupError):
        env.svc.attach_evidence(TEN, case.case_id, ["nope"], actor="analyst")


# ----------------------------------------------------------------------------- PROPOSED / APPROVED

def test_proposed_requires_authorization_assessment(env):
    case = env.verified()
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "propose")
    assert failed_checks(ei) == ["authorization_assessment_missing"]
    ghost = AuthorizationDecision(action_id="missing", allowed=True, evaluated_at=NOW)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p", authorization=ghost)
    assert "proposed_action_not_found" in failed_checks(ei)
    other = env.action("another-case")
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p",
                           authorization=env.authz(other))
    assert "action_belongs_to_another_case" in failed_checks(ei)
    act = env.action(case.case_id)
    future = env.authz(act).model_copy(update={"evaluated_at": NOW + timedelta(days=1)})
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p", authorization=future)
    assert "authorization_evaluated_in_future" in failed_checks(ei)
    # an assessment that denied still allows proposing (it will then be DENIED)
    case = env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p",
                              authorization=env.authz(act, allowed=False))
    assert case.state is S.PROPOSED
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.APPROVED, "approver@isp", "ok",
                           authorization=env.authz(act, allowed=False))
    assert "authorization_not_allowed" in failed_checks(ei)
    case = env.svc.transition(TEN, case.case_id, S.DENIED, "system", "authorization denied")
    assert case.state is S.DENIED


def test_approval_requires_human(env):
    case = env.verified()
    act = env.action(case.case_id)
    env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p", authorization=env.authz(act))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.APPROVED, "system", "auto", authorization=env.authz(act))
    assert "approval_requires_human_approver" in failed_checks(ei)


# ----------------------------------------------------------------------------- EXECUTED

def test_executed_happy_path_and_rollback(env):
    case, act, au = env.approved()
    case = env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "execute",
                              authorization=au, mirror=env.mirror(act), policy=env.policy())
    assert case.state is S.EXECUTED
    last = env.ledger.entries(TEN, subject_id=case.case_id, entry_type=EntryType.CASE_TRANSITION)[-1]
    assert last.payload["guards"]["mirror"]["verdict"] == "SAFE"
    assert last.payload["guards"]["policy"]["policy_id"] == "pol-1"
    case = env.svc.transition(TEN, case.case_id, S.ROLLED_BACK, "operator@isp", "legit errors")
    assert case.state is S.ROLLED_BACK
    assert env.ledger.verify_chain(TEN, env.ring) == (True, None)
    rp = replay(TEN, env.ledger, case.case_id, NOW + timedelta(days=1))
    assert rp  # replay can reconstruct the case decisions


@pytest.mark.parametrize("mutate,expected", [
    (lambda e, a: {"policy": None}, "signed_policy_missing"),
    (lambda e, a: {"policy": e.policy(mode="shadow")}, "policy_not_active_mode"),
    (lambda e, a: {"policy": e.policy(signoff=None)}, "policy_missing_legal_signoff"),
    (lambda e, a: {"policy": e.policy(signer=Signer.generate("rogue"))}, "policy_signature_invalid"),
    (lambda e, a: {"policy": e.policy().model_copy(update={"mode": "active", "max_targets_per_action": 99})},
     "policy_signature_invalid"),
    (lambda e, a: {"policy": e.policy(allowed=(ActionType.IP_BLOCK,))}, "action_type_not_allowed_by_policy"),
    (lambda e, a: {"mirror": None}, "mirror_result_missing"),
    (lambda e, a: {"mirror": e.mirror(a, MirrorVerdict.UNSAFE)}, "mirror_not_safe:UNSAFE"),
    (lambda e, a: {"mirror": e.mirror(a, MirrorVerdict.UNKNOWN)}, "mirror_not_safe:UNKNOWN"),
    (lambda e, a: {"authorization": None}, "authorization_assessment_missing"),
    (lambda e, a: {"authorization": e.authz(a, policy_id="pol-other")}, "authorization_not_bound_to_policy"),
])
def test_executed_guard_failures(env, mutate, expected):
    case, act, au = env.approved()
    kwargs = {"authorization": au, "mirror": env.mirror(act), "policy": env.policy()}
    kwargs.update(mutate(env, act))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "execute", **kwargs)
    assert expected in failed_checks(ei)
    assert env.svc.get(TEN, case.case_id).state is S.APPROVED


@pytest.mark.safety
def test_expired_authorization_prevents_action(env):
    """Spec §15: expired authorization prevents action."""
    case, act, au = env.approved()
    expired_policy = env.policy(valid_until=NOW - timedelta(minutes=1))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "execute",
                           authorization=au, mirror=env.mirror(act), policy=expired_policy)
    assert "policy_not_valid_now" in failed_checks(ei)
    env.docs.put(act.model_copy(update={"expires_at": NOW - timedelta(minutes=1)}))
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "execute",
                           authorization=au, mirror=env.mirror(act), policy=env.policy())
    assert "action_expired" in failed_checks(ei)
    case = env.svc.transition(TEN, case.case_id, S.EXPIRED, "system", "approval window lapsed")
    assert case.state is S.EXPIRED


def test_action_without_expiry_never_executes(env):
    case = env.verified()
    act = env.action(case.case_id, expires=False)
    au = env.authz(act)
    env.svc.transition(TEN, case.case_id, S.PROPOSED, "analyst@isp", "p", authorization=au)
    env.svc.transition(TEN, case.case_id, S.APPROVED, "approver@isp", "ok", authorization=au)
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "x",
                           authorization=au, mirror=env.mirror(act), policy=env.policy())
    assert "action_without_expiry" in failed_checks(ei)


def test_execution_fails_closed_without_keyring(tmp_path):
    env = Env(tmp_path, with_keyring=False)
    case, act, au = env.approved()
    with pytest.raises(GuardError) as ei:
        env.svc.transition(TEN, case.case_id, S.EXECUTED, "system:executor", "x",
                           authorization=au, mirror=env.mirror(act), policy=env.policy())
    assert "policy_signature_invalid" in failed_checks(ei)
    env.engine.dispose()



# ----------------------------------------------------------------------------- de-duplication / finding status

def test_one_incident_one_case_and_finding_status_follows_the_case(env):
    from aegis.contracts.models import FindingStatus
    f1 = env.finding([env.ev("a")])
    case = env.svc.open_case(f1)
    f2 = env.finding([env.ev("b")]).model_copy(update={"label": "ddos_bot", "verdict": Verdict.MALICIOUS,
                                                       "component_scores": {"ioc_independent_origins": 2.0}})
    env.docs.put(f2)
    same = env.svc.open_case(f2)
    assert same.case_id == case.case_id and same.finding_ids == [f1.finding_id, f2.finding_id]
    assert same.severity == "critical"  # escalates with the stronger finding
    assert env.svc.open_case(f2).finding_ids == same.finding_ids  # idempotent
    assert len(env.svc.list_cases(TEN)) == 1
    attached = [e for e in env.ledger.entries(TEN, subject_id=case.case_id) if e.entry_type == "case_finding_attached"]
    assert attached and attached[0].payload["finding_id"] == f2.finding_id
    env.svc.transition(TEN, case.case_id, CaseState.TRIAGE, "alice", "look")
    assert {env.docs.get(Finding, TEN, f.finding_id).status for f in (f1, f2)} == {FindingStatus.TRIAGE}
    env.svc.transition(TEN, case.case_id, CaseState.INVESTIGATING, "alice", "dig")
    env.svc.transition(TEN, case.case_id, CaseState.REJECTED, "alice", "benign IPTV")
    assert {env.docs.get(Finding, TEN, f.finding_id).status for f in (f1, f2)} == {FindingStatus.REJECTED}
    # a decided case does not absorb new findings: the next alert opens a fresh case
    f3 = env.finding([env.ev("c")])
    fresh = env.svc.open_case(f3)
    assert fresh.case_id != case.case_id and fresh.finding_ids == [f3.finding_id]
