"""Rule lifecycle: draft -> backtested -> approved -> shadow -> promoted -> retired.

Humans approve with signatures, an LLM never can, nothing auto-promotes, and only
verified rules are loaded for execution.
"""
from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.detengine import (
    BacktestConfig,
    Backtester,
    RuleLifecycleError,
    RulePromotionGate,
    RuleRecord,
    RuleRegistry,
    RuleSpec,
    RuleState,
    RuleValidationError,
    sign_approval,
)
from aegis.detengine.registry import RULE_ENTRY, is_human
from test_detengine_support import TENANT, Clock, fv, make_stores, synthetic_dataset

SPEC = RuleSpec.from_dict({"rule_id": "dga-nx", "title": "NX storm", "label": "dga_activity",
                           "conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}],
                           "baseline": {"device_classes": ["android_tv", "phone"]}})
GATE = RulePromotionGate(min_shadow_duration=timedelta(days=2), min_shadow_reviews=2)
GOOD_DS = synthetic_dataset(n_benign=400, hard_negative_hits=0)


@pytest.fixture
def env(tmp_path):
    st = make_stores(tmp_path)
    clock = Clock()
    reg = RuleRegistry(st.docs, st.ledger, approver_keyring=st.keyring, gate=GATE, clock=clock)
    return st, clock, reg


def backtested(reg: RuleRegistry, clock: Clock, spec: RuleSpec = SPEC, ds=GOOD_DS,
               actor: str = "generator:detengine-deterministic", kind: str = "generator") -> RuleRecord:
    rec = reg.submit_draft(TENANT, spec, actor=actor, drafter_kind=kind, source_case_ids=["case-1"])
    report = Backtester(clock=clock).run(rec.rule_spec(), ds, tenant_id=TENANT, actor="system:detengine-backtest",
                                         config=BacktestConfig(min_holdout_device_days=100), rule_ref=rec.ref)
    return reg.record_backtests(TENANT, rec.ref, [report], actor="system:detengine-backtest")


def approve(reg, st, ref, approver="alice", signer=None, purpose="approve", **kw):
    req = reg.approval_request(TENANT, ref, purpose=purpose, approver=approver, reason="looks right", **kw)
    return sign_approval(req, signer or getattr(st, approver))


def to_shadow(reg, st, clock) -> RuleRecord:
    rec = backtested(reg, clock)
    reg.approve(TENANT, approve(reg, st, rec.ref))
    return reg.start_shadow(TENANT, rec.ref, actor="alice", reason="pilot")


def test_happy_path_full_lifecycle(env):
    st, clock, reg = env
    rec = backtested(reg, clock)
    assert rec.ref == "dga-nx@v1" and rec.state is RuleState.BACKTESTED and len(rec.backtest_ids) == 1
    rec = reg.approve(TENANT, approve(reg, st, rec.ref))
    assert rec.state is RuleState.APPROVED and rec.approval_id
    rec = reg.start_shadow(TENANT, rec.ref, actor="alice", reason="pilot")
    assert rec.state is RuleState.SHADOW

    eng = reg.active_rules(TENANT)
    assert [r.mode for r in eng.rules] == ["shadow"] and eng.rejected == ()
    shadow_ids = []
    for i in range(3):
        res = eng.process(fv(f"p_x{i}", nxdomain_rate=0.9))
        assert res.findings == []
        shadow_ids += [f.finding_id for f in res.shadow_findings]
    assert len(reg.shadow_findings(TENANT, rec.ref)) == 3
    for fid in shadow_ids[:2]:
        reg.record_shadow_review(TENANT, rec.ref, fid, outcome="true_positive", reviewer="carol")

    early = reg.evaluate_promotion(TENANT, rec.ref, actor="alice")
    assert not early.passed and early.failed_checks == ["shadow_period_too_short"]
    assert reg.require(TENANT, rec.ref).state is RuleState.SHADOW     # evaluation never promotes
    clock.advance(days=3)
    ev = reg.evaluate_promotion(TENANT, rec.ref, actor="alice")
    assert ev.passed, ev.failed_checks
    assert ev.shadow["findings"] == 3 and ev.shadow["true_positive"] == 2
    assert reg.require(TENANT, rec.ref).state is RuleState.SHADOW     # still not promoted

    rec = reg.promote(TENANT, approve(reg, st, rec.ref, approver="bob", purpose="promote",
                                      promotion_evaluation_id=ev.doc_id))
    assert rec.state is RuleState.PROMOTED and rec.promotion_evaluation_id == ev.doc_id
    eng = reg.active_rules(TENANT)
    assert [r.mode for r in eng.rules] == ["promoted"]
    res = eng.process(fv("p_y", nxdomain_rate=0.9))
    assert res.findings[0].detector_version == "detengine:dga-nx@v1"

    rec = reg.retire(TENANT, rec.ref, actor="alice", reason="campaign over")
    assert rec.state is RuleState.RETIRED and reg.active_rules(TENANT).rules == ()
    states = [h.to_state.value for h in rec.history]
    assert states == ["draft", "backtested", "approved", "shadow", "promoted", "retired"]
    hist = reg.history(TENANT, rec.ref)
    assert all(e["payload"]["spec_sha256"] == rec.spec_sha256 for e in hist)
    assert st.ledger.verify_chain(TENANT) == (True, None)


def test_validation_cannot_be_bypassed(env):
    _, _, reg = env
    bad = RuleSpec.from_dict({"rule_id": "tv-only", "title": "TV", "label": "c2_beaconing",
                              "baseline": {"device_classes": ["android_tv"]}})
    with pytest.raises(RuleValidationError) as exc:
        reg.submit_draft(TENANT, bad, actor="alice", drafter_kind="human")
    assert exc.value.errors == ["device_class_only"]
    assert reg.list_rules(TENANT) == []


def test_drafter_identity_must_match_kind(env):
    _, _, reg = env
    with pytest.raises(RuleLifecycleError):
        reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="llm")
    with pytest.raises(RuleLifecycleError):
        reg.submit_draft(TENANT, SPEC, actor="llm:claude", drafter_kind="human")
    with pytest.raises(RuleLifecycleError):
        reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="generator")


def test_versions_are_immutable_and_submission_idempotent(env):
    _, clock, reg = env
    a = reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="human")
    assert reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="human").ref == a.ref
    edited = RuleSpec.from_dict({**SPEC.to_dict(), "severity": "high"})
    b = reg.submit_draft(TENANT, edited, actor="alice", drafter_kind="human")
    assert (a.version, b.version) == (1, 2) and a.spec_sha256 != b.spec_sha256


@pytest.mark.parametrize("approver", ["llm:claude-sonnet-5-5", "agent:verifier", "system", "generator:x", "auto"])
def test_ai_and_system_can_never_approve(env, approver):
    st, clock, reg = env
    rec = backtested(reg, clock)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approval_request(TENANT, rec.ref, purpose="approve", approver=approver, reason="x")
    assert exc.value.failed == ["human_required"]
    # even a hand-built, validly signed approval naming a non-human approver is refused
    forged = reg.approval_request(TENANT, rec.ref, purpose="approve", approver="alice", reason="x")
    forged = sign_approval(forged.model_copy(update={"approver": approver}), st.alice)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, forged)
    assert "human_required" in exc.value.failed
    assert not is_human(approver)


def test_approval_signature_and_binding_checks(env):
    st, clock, reg = env
    rec = backtested(reg, clock)
    unsigned = reg.approval_request(TENANT, rec.ref, purpose="approve", approver="alice", reason="ok")
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, unsigned)
    assert "approval_signature_invalid" in exc.value.failed
    # untrusted key
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, approve(reg, st, rec.ref, approver="alice", signer=st.mallory))
    assert "approval_signature_invalid" in exc.value.failed
    # bob's key cannot sign for alice
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, approve(reg, st, rec.ref, approver="alice", signer=st.bob))
    assert "approval_key_not_owned_by_approver" in exc.value.failed
    # tampering after signing breaks the signature
    good = approve(reg, st, rec.ref)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, good.model_copy(update={"reason": "changed"}))
    assert "approval_signature_invalid" in exc.value.failed
    # stale approvals are refused
    stale = approve(reg, st, rec.ref)
    clock.advance(days=2)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, stale)
    assert "approval_not_fresh" in exc.value.failed
    # wrong purpose
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, approve(reg, st, rec.ref, purpose="promote"))
    assert "approval_purpose_mismatch" in exc.value.failed
    assert reg.require(TENANT, rec.ref).state is RuleState.BACKTESTED


def test_key_owner_mapping(tmp_path):
    st = make_stores(tmp_path)
    clock = Clock()
    reg = RuleRegistry(st.docs, st.ledger, approver_keyring=st.keyring, key_owners={"bob": "alice@isp.example"},
                       gate=GATE, clock=clock)
    rec = backtested(reg, clock)
    req = reg.approval_request(TENANT, rec.ref, purpose="approve", approver="alice@isp.example", reason="ok")
    assert reg.approve(TENANT, sign_approval(req, st.bob)).state is RuleState.APPROVED


def test_drafter_cannot_approve_own_rule(env):
    st, clock, reg = env
    rec = backtested(reg, clock, actor="alice", kind="human")
    with pytest.raises(RuleLifecycleError) as exc:
        reg.approve(TENANT, approve(reg, st, rec.ref, approver="alice"))
    assert "approver_is_drafter" in exc.value.failed
    assert reg.approve(TENANT, approve(reg, st, rec.ref, approver="bob")).state is RuleState.APPROVED


def test_state_machine_refuses_skips(env):
    st, clock, reg = env
    rec = reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="human")
    with pytest.raises(RuleLifecycleError):                     # no backtest yet
        reg.approve(TENANT, approve(reg, st, rec.ref, approver="bob"))
    with pytest.raises(RuleLifecycleError):
        reg.start_shadow(TENANT, rec.ref, actor="bob", reason="skip")
    with pytest.raises(RuleLifecycleError):
        reg.start_shadow(TENANT, rec.ref, actor="llm:claude", reason="x")
    with pytest.raises(RuleLifecycleError):
        reg.retire(TENANT, rec.ref, actor="agent:x", reason="x")
    assert reg.retire(TENANT, rec.ref, actor="system", reason="expired").state is RuleState.RETIRED


def test_backtest_must_match_spec(env):
    _, clock, reg = env
    rec = reg.submit_draft(TENANT, SPEC, actor="alice", drafter_kind="human")
    other = RuleSpec.from_dict({**SPEC.to_dict(), "severity": "low"})
    report = Backtester(clock=clock).run(other, GOOD_DS, tenant_id=TENANT, actor="system:t")
    with pytest.raises(RuleLifecycleError) as exc:
        reg.record_backtests(TENANT, rec.ref, [report], actor="system:t")
    assert exc.value.failed == ["backtest_spec_mismatch"]
    with pytest.raises(RuleLifecycleError):
        reg.record_backtests(TENANT, rec.ref, [], actor="system:t")
    with pytest.raises(RuleLifecycleError):
        reg.record_backtests(TENANT, rec.ref, [report], actor="llm:claude")


def test_promotion_gate_blocks_bad_metrics(env):
    st, clock, reg = env
    noisy = synthetic_dataset(hard_negative_hits=5)              # false alerts on hard negatives
    rec = backtested(reg, clock, ds=noisy)
    reg.approve(TENANT, approve(reg, st, rec.ref))
    reg.start_shadow(TENANT, rec.ref, actor="alice", reason="pilot")
    clock.advance(days=3)
    ev = reg.evaluate_promotion(TENANT, rec.ref, actor="alice")
    assert not ev.passed
    assert {"backtest_insufficient:synthetic", "false_alerts_above_gate:synthetic",
            "hard_negative_alerts:synthetic", "too_few_shadow_reviews"} <= set(ev.failed_checks)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.promote(TENANT, approve(reg, st, rec.ref, approver="bob", purpose="promote",
                                    promotion_evaluation_id=ev.doc_id))
    assert "promotion_gate_failed" in exc.value.failed


def test_shadow_false_positives_block_promotion(env):
    st, clock, reg = env
    rec = to_shadow(reg, st, clock)
    eng = reg.active_rules(TENANT)
    ids = [eng.process(fv(f"p_{i}", nxdomain_rate=0.9)).shadow_findings[0].finding_id for i in range(3)]
    reg.record_shadow_review(TENANT, rec.ref, ids[0], outcome="true_positive", reviewer="carol")
    reg.record_shadow_review(TENANT, rec.ref, ids[1], outcome="false_positive", reviewer="carol")
    with pytest.raises(RuleLifecycleError):
        reg.record_shadow_review(TENANT, rec.ref, ids[2], outcome="true_positive", reviewer="llm:claude")
    clock.advance(days=3)
    ev = reg.evaluate_promotion(TENANT, rec.ref, actor="alice")
    assert ev.failed_checks == ["shadow_false_positive_share"]


def test_promotion_requires_evaluation_distinct_promoter_and_freshness(env):
    st, clock, reg = env
    rec = to_shadow(reg, st, clock)
    eng = reg.active_rules(TENANT)
    for i in range(2):
        fid = eng.process(fv(f"p_{i}", nxdomain_rate=0.9)).shadow_findings[0].finding_id
        reg.record_shadow_review(TENANT, rec.ref, fid, outcome="true_positive", reviewer="carol")
    clock.advance(days=3)
    with pytest.raises(RuleLifecycleError) as exc:            # no gate evaluation
        reg.promote(TENANT, approve(reg, st, rec.ref, approver="bob", purpose="promote"))
    assert "no_promotion_evaluation" in exc.value.failed
    ev = reg.evaluate_promotion(TENANT, rec.ref, actor="alice")
    assert ev.passed
    with pytest.raises(RuleLifecycleError) as exc:            # four eyes: not the first approver
        reg.promote(TENANT, approve(reg, st, rec.ref, approver="alice", purpose="promote",
                                    promotion_evaluation_id=ev.doc_id))
    assert "promoter_is_first_approver" in exc.value.failed
    clock.advance(days=2)
    with pytest.raises(RuleLifecycleError) as exc:
        reg.promote(TENANT, approve(reg, st, rec.ref, approver="bob", purpose="promote",
                                    promotion_evaluation_id=ev.doc_id))
    assert "promotion_evaluation_stale" in exc.value.failed
    assert reg.require(TENANT, rec.ref).state is RuleState.SHADOW


def test_promoting_a_new_version_supersedes_the_old(env):
    st, clock, reg = env
    v1 = to_shadow(reg, st, clock)
    v2_spec = RuleSpec.from_dict({**SPEC.to_dict(), "severity": "high"})
    v2 = backtested(reg, clock, spec=v2_spec)
    reg.approve(TENANT, approve(reg, st, v2.ref))
    reg.start_shadow(TENANT, v2.ref, actor="alice", reason="pilot v2")
    eng = reg.active_rules(TENANT)
    for i in range(2):
        for f in eng.process(fv(f"p_{i}", nxdomain_rate=0.9)).shadow_findings:
            if f.detector_version.startswith("detengine:dga-nx@v2"):
                reg.record_shadow_review(TENANT, v2.ref, f.finding_id, outcome="true_positive", reviewer="carol")
    clock.advance(days=3)
    ev = reg.evaluate_promotion(TENANT, v2.ref, actor="alice")
    reg.promote(TENANT, approve(reg, st, v2.ref, approver="bob", purpose="promote", promotion_evaluation_id=ev.doc_id))
    assert reg.require(TENANT, v1.ref).state is RuleState.RETIRED
    assert [r.ref for r in reg.active_rules(TENANT).rules] == ["dga-nx@v2"]


def test_tampered_rules_are_not_loaded(env):
    st, clock, reg = env
    rec = to_shadow(reg, st, clock)
    assert reg.active_rules(TENANT).rejected == ()
    # someone with database access widens the rule without going through the lifecycle
    widened = dict(rec.spec)
    widened["conditions"] = [{"feature": "nxdomain_rate", "op": "ge", "value": 0.01}]
    st.docs.put(rec.model_copy(update={"spec": widened}))
    eng = reg.active_rules(TENANT)
    assert eng.rules == () and eng.rejected[0].reasons == ("spec_hash_mismatch",)
    # ... or flips the state to promoted directly
    st.docs.put(rec.model_copy(update={"state": RuleState.PROMOTED}))
    reasons = set(reg.active_rules(TENANT).rejected[0].reasons)
    assert {"missing_promote_approval", "ledger_mismatch"} <= reasons


def test_revalidation_against_current_topology(env):
    from aegis.api.topology import parse_topology
    st, clock, reg = env
    def topo(kind: str):
        return parse_topology({"topology_id": "t", "complete": True, "prefixes": ["203.0.113.0/24"],
                               "hosts": [{"ip": "203.0.113.9", "kind": kind, "hostnames": ["c2.bad.example"]}]})
    ip_rule = RuleSpec.from_dict({"rule_id": "c2-ip", "title": "C2 IP", "label": "c2_beaconing",
                                  "destinations": {"patterns": [{"kind": "ip", "value": "203.0.113.9"}]}})
    rec = reg.submit_draft(TENANT, ip_rule, actor="alice", drafter_kind="human", hosting=topo("dedicated"))
    report = Backtester(clock=clock).run(ip_rule, GOOD_DS, tenant_id=TENANT, actor="system:t")
    reg.record_backtests(TENANT, rec.ref, [report], actor="system:t")
    reg.approve(TENANT, approve(reg, st, rec.ref, approver="bob"))
    reg.start_shadow(TENANT, rec.ref, actor="bob", reason="pilot")
    assert len(reg.active_rules(TENANT, hosting=topo("dedicated")).rules) == 1
    # the address became shared hosting since approval: the rule is no longer loaded
    eng = reg.active_rules(TENANT, hosting=topo("shared_cdn"))
    assert eng.rules == () and "revalidation_failed:shared_hosting_ip:203.0.113.9" in eng.rejected[0].reasons


def test_registry_is_tenant_scoped(env):
    st, clock, reg = env
    rec = backtested(reg, clock)
    assert reg.get("other-tenant", rec.ref) is None
    assert reg.list_rules("other-tenant") == []
    assert st.ledger.entries("other-tenant", entry_type=RULE_ENTRY) == []


def test_no_code_path_promotes_automatically():
    """Only RuleRegistry.promote moves a rule to PROMOTED, and nothing in the package calls it."""
    import pathlib
    import aegis.detengine as pkg
    root = pathlib.Path(pkg.__file__).parent
    callers = [p.name for p in root.glob("*.py") if ".promote(" in p.read_text()]
    assert callers == []
    reg_src = (root / "registry.py").read_text()
    assert reg_src.count("RuleState.PROMOTED, approval.approver") == 1
