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
    safe_mirror,
    signer_and_ring,
)

from aegis.contracts.models import ActionType, AuthorizationDecision
from aegis.mirror import (
    AdapterError,
    BreakerState,
    CircuitBreaker,
    DryRunAdapter,
    EnforcementAdapter,
    ExecutionError,
    ExecutionStatus,
    Executor,
    RPZAdapter,
    authorize,
)
from aegis.mirror.base import AdapterResult
from aegis.provenance.ledger import EntryType


def decision(act, *, allowed=True, failed=None, human=True, at=T0, policy_id="pol-1"):
    return AuthorizationDecision(action_id=act.action_id, allowed=allowed,
                                 failed_checks=failed or [], requires_human_approval=human,
                                 evaluated_at=at, policy_id=policy_id)


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    led = ledger(tmp_path)
    rpz = RPZAdapter(tmp_path / "z.rpz")
    breaker = CircuitBreaker(clock=clock, min_requests=10)
    ex = Executor(rpz, led, breaker, clock=clock)
    return ex, rpz, led, breaker, clock


def outcomes(led, act):
    return [e.payload for e in led.entries(TENANT, subject_id=act.action_id,
                                           entry_type=EntryType.EXECUTION)]


def test_execute_applies_and_writes_ledger(env):
    ex, rpz, led, breaker, _ = env
    act = action()
    rec = ex.execute(act, decision(act), "alice@isp")
    assert rec.status is ExecutionStatus.APPLIED
    assert rec.ledger_entry_hash
    assert rpz.records(T0) == [("c2.bad.example", ".")]
    phases = [(p["phase"], p["operation"]) for p in outcomes(led, act)]
    assert phases == [("intent", "execute"), ("outcome", "execute")]
    assert outcomes(led, act)[1]["record"]["actor"] == "alice@isp"
    assert ex.active() == [act.action_id]
    assert breaker.watching() == [act.action_id]
    assert led.verify_chain(TENANT)[0]


@pytest.mark.parametrize("kw,reason", [
    (dict(decision=None), "authorization_decision_missing"),
    (dict(allowed=False, failed=["mirror_not_safe"]), "authorization_denied"),
    (dict(allowed=False, failed=["policy_not_active_mode"]), "authorization_denied"),
    (dict(at=T0 - timedelta(hours=2)), "decision_stale"),
    (dict(at=T0 + timedelta(hours=2)), "decision_from_future"),
])
def test_refusals_never_touch_adapter(env, kw, reason):
    ex, rpz, led, _, _ = env
    act = action()
    d = None if "decision" in kw else decision(act, **kw)
    rec = ex.execute(act, d, "alice@isp")
    assert rec.status is ExecutionStatus.REFUSED
    assert reason in rec.refusal_reasons
    assert rpz.records(T0) == []
    assert not (rpz.zone_path.exists())
    entries = outcomes(led, act)
    assert len(entries) == 1 and entries[0]["status"] == "refused"
    assert entries[0]["action"]["action_id"] == act.action_id


def test_denied_decision_lists_failed_checks(env):
    ex, *_ = env
    act = action()
    rec = ex.execute(act, decision(act, allowed=False, failed=["legal_basis_missing"]), "alice")
    assert "failed_check:legal_basis_missing" in rec.refusal_reasons


def test_decision_for_other_action(env):
    ex, *_ = env
    act = action()
    rec = ex.execute(act, decision(action()), "alice")
    assert "decision_for_other_action" in rec.refusal_reasons


def test_human_approval_rules(env):
    ex, rpz, *_ = env
    act = action(created_by="bob@isp")
    for who, reason in [(None, "human_approval_required"), ("", "human_approval_required"),
                        ("system", "human_approval_required"),
                        ("agent:response_planner", "agent_cannot_execute"),
                        ("bob@isp", "approver_is_proposer")]:
        rec = ex.execute(act, decision(act), who)
        assert rec.status is ExecutionStatus.REFUSED, who
        assert reason in rec.refusal_reasons, who
    assert rpz.records(T0) == []
    # no human needed: a system actor may run it, an agent never can
    rec = ex.execute(act, decision(act, human=False), "agent:x")
    assert "agent_cannot_execute" in rec.refusal_reasons
    rec = ex.execute(act, decision(act, human=False), "system:auto")
    assert rec.status is ExecutionStatus.APPLIED


def test_expired_action_refused(env):
    ex, _rpz, _, _, clock = env
    act = action(expires_at=T0 + timedelta(minutes=10))
    d = decision(act)
    clock.advance(minutes=11)
    rec = ex.execute(act, d, "alice")
    assert "action_expired" in rec.refusal_reasons
    no_exp = action(expires_at=None)
    assert "action_without_expiry" in ex.execute(no_exp, decision(no_exp), "alice").refusal_reasons


def test_unsupported_and_invalid_targets_refused(env):
    ex, *_ = env
    q = action(ActionType.DEVICE_QUARANTINE, ["p_abcdef123456"])
    assert "adapter_unsupported_action" in ex.execute(q, decision(q), "alice").refusal_reasons
    bad = action(targets=["x y"])
    assert "invalid_targets" in ex.execute(bad, decision(bad), "alice").refusal_reasons


def test_already_active_refused(env):
    ex, *_ = env
    act = action()
    assert ex.execute(act, decision(act), "alice").status is ExecutionStatus.APPLIED
    assert "already_active" in ex.execute(act, decision(act), "alice").refusal_reasons


def test_rollback_restores_service(env):
    """Spec 15: rollback restores service."""
    ex, rpz, led, breaker, clock = env
    prior = action(targets=["pre-existing.example"])
    ex.execute(prior, decision(prior), "alice")
    before = rpz.records(T0)
    act = action()
    ex.execute(act, decision(act), "alice")
    assert ("c2.bad.example", ".") in rpz.records(T0)
    clock.advance(minutes=5)
    rb = ex.rollback(act.action_id, actor="alice", reason="false positive")
    assert rb.status is ExecutionStatus.ROLLED_BACK
    assert rpz.records(T0) == before
    assert act.action_id not in ex.active()
    assert act.action_id not in breaker.watching()
    # idempotent
    assert ex.rollback(act.action_id).execution_id == rb.execution_id
    with pytest.raises(ExecutionError):
        ex.rollback("never-executed")
    assert [p["operation"] for p in outcomes(led, act)] == ["execute"] * 2 + ["rollback"] * 2


def test_breaker_trip_auto_rolls_back_and_blocks(env):
    ex, rpz, _led, breaker, _clock = env
    act = action()
    ex.execute(act, decision(act), "alice", baseline_error_rate=0.01)
    assert ex.observe_legit_traffic(act.action_id, 100, 2) is False
    assert breaker.state is BreakerState.CLOSED
    tripped = ex.observe_legit_traffic(act.action_id, 100, 30)
    assert tripped is True
    assert breaker.is_open
    assert rpz.records(T0) == []
    last = ex.records(act.action_id)[-1]
    assert last.status is ExecutionStatus.ROLLED_BACK
    assert last.actor == "system:circuit_breaker"
    assert "circuit breaker" in last.reason
    # breaker open: no new enforcement until a human resets it
    nxt = action(targets=["next.example"])
    assert "circuit_breaker_open" in ex.execute(nxt, decision(nxt), "alice").refusal_reasons
    with pytest.raises(PermissionError):
        breaker.reset("system", "auto")
    with pytest.raises(ValueError):
        breaker.reset("alice", " ")
    breaker.reset("alice", "root cause fixed")
    assert ex.execute(nxt, decision(nxt), "alice").status is ExecutionStatus.APPLIED


def test_sweep_expired(env):
    ex, rpz, _, _, clock = env
    short = action(targets=["short.example"], expires_at=T0 + timedelta(minutes=5))
    long = action(targets=["long.example"], expires_at=T0 + timedelta(hours=5))
    ex.execute(short, decision(short), "alice")
    ex.execute(long, decision(long), "alice")
    clock.advance(minutes=6)
    recs = ex.sweep_expired()
    assert [r.action_id for r in recs] == [short.action_id]
    assert recs[0].actor == "system:expiry"
    assert ex.active() == [long.action_id]
    assert rpz.records(clock.t) == [("long.example", ".")]


def test_recover_after_restart_and_rollback(tmp_path, env):
    ex, rpz, led, _, clock = env
    act = action()
    ex.execute(act, decision(act), "alice")
    fresh = Executor(RPZAdapter(rpz.zone_path), led, CircuitBreaker(clock=clock), clock=clock)
    assert fresh.active() == []
    rec = fresh.rollback(act.action_id, actor="alice", reason="restart", tenant_id=TENANT)
    assert rec.status is ExecutionStatus.ROLLED_BACK
    assert rpz.records(T0) == []
    assert fresh.recover(TENANT) == []


class FlakyAdapter(EnforcementAdapter):
    name = "flaky"
    supported_actions = frozenset(ActionType)

    def __init__(self, fail_apply=False, fail_revert=False):
        self.fail_apply, self.fail_revert = fail_apply, fail_revert
        self.applied: list[str] = []

    def apply(self, action, *, now):
        if self.fail_apply:
            raise AdapterError("enforcement point down")
        self.applied.append(action.action_id)
        return AdapterResult(adapter=self.name, operation="apply", prior_state={"x": 1})

    def revert(self, action, prior_state, *, now):
        if self.fail_revert:
            raise AdapterError("cannot revert")
        self.applied.remove(action.action_id)
        return AdapterResult(adapter=self.name, operation="revert")


def test_adapter_failure_recorded(tmp_path):
    led = ledger(tmp_path)
    ex = Executor(FlakyAdapter(fail_apply=True), led, clock=Clock())
    act = action()
    rec = ex.execute(act, decision(act), "alice")
    assert rec.status is ExecutionStatus.FAILED
    assert "enforcement point down" in rec.reason
    assert ex.active() == []
    assert outcomes(led, act)[-1]["status"] == "failed"


def test_rollback_failure_keeps_action_live_and_recoverable(tmp_path):
    led = ledger(tmp_path)
    adapter = FlakyAdapter(fail_revert=True)
    ex = Executor(adapter, led, clock=Clock())
    act = action()
    ex.execute(act, decision(act), "alice")
    rec = ex.rollback(act.action_id, actor="alice")
    assert rec.status is ExecutionStatus.ROLLBACK_FAILED
    assert ex.active() == [act.action_id]
    fresh_adapter = FlakyAdapter()
    fresh_adapter.applied.append(act.action_id)
    fresh = Executor(fresh_adapter, led, clock=Clock())
    assert fresh.recover(TENANT) == [act.action_id]
    ok = fresh.rollback(act.action_id, actor="alice")
    assert ok.status is ExecutionStatus.ROLLED_BACK
    assert ok.prior_state == {"x": 1}


def test_ledger_failure_after_apply_reverts(tmp_path):
    led = ledger(tmp_path)
    adapter = FlakyAdapter()
    ex = Executor(adapter, led, clock=Clock())
    act = action()
    calls = {"n": 0}
    real = led.append

    def failing(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:  # the outcome entry
            raise RuntimeError("db gone")
        return real(*a, **k)

    led.append = failing  # type: ignore[method-assign]
    with pytest.raises(ExecutionError, match="reverted"):
        ex.execute(act, decision(act), "alice")
    assert adapter.applied == []
    assert ex.active() == []


def test_dry_run_in_shadow_mode(tmp_path):
    signer, ring = signer_and_ring()
    led = ledger(tmp_path)
    act = action()
    pol = policy(signer, mode="shadow")
    d = authorize(act, pol, ring, safe_mirror(act), True, T0)
    assert d.failed_checks == ["policy_not_active_mode"]
    dry = DryRunAdapter()
    rec = Executor(dry, led, clock=Clock()).execute(act, d, "alice")
    assert rec.status is ExecutionStatus.DRY_RUN and rec.dry_run
    assert act.action_id in dry.active()
    # the same shadow decision never reaches a real adapter
    rpz = RPZAdapter(tmp_path / "z.rpz")
    rec2 = Executor(rpz, led, clock=Clock()).execute(act, d, "alice")
    assert rec2.status is ExecutionStatus.REFUSED
    assert "failed_check:policy_not_active_mode" in rec2.refusal_reasons
    # a dry run still refuses other failures
    bad = authorize(act, pol, ring, None, True, T0)
    rec3 = Executor(DryRunAdapter(), led, clock=Clock()).execute(act, bad, "alice")
    assert rec3.status is ExecutionStatus.REFUSED
    assert "failed_check:mirror_missing" in rec3.refusal_reasons


# ------------------------------------------------------------------ breaker unit

def test_breaker_thresholds_and_window():
    clock = Clock()
    b = CircuitBreaker(baseline_error_rate=0.05, relative_factor=2.0, absolute_margin=0.02,
                       max_error_rate=0.5, min_requests=100, window=timedelta(minutes=5),
                       clock=clock)
    b.watch("a")
    assert b.threshold("a") == pytest.approx(0.10)
    assert b.record("a", 50, 40) is False          # below min_requests: no trip on noise
    clock.advance(minutes=6)
    assert b.record("a", 60, 3) is False           # old sample expired from the window
    rate, req = b.error_rate("a")
    assert req == 60 and rate == pytest.approx(0.05)
    assert b.record("a", 60, 20) is True           # 23/120 > 0.10
    assert b.trips[0].action_id == "a"
    assert b.record("a", 100, 100) is False        # already tripped
    assert b.record("unknown", 100, 100) is False
    with pytest.raises(ValueError):
        b.record("a", 1, 2)
    b.watch("low", baseline_error_rate=0.0)
    assert b.threshold("low") == pytest.approx(0.02)
    b.watch("high", baseline_error_rate=0.4)
    assert b.threshold("high") == pytest.approx(0.5)


def test_breaker_callback_errors_are_captured():
    b = CircuitBreaker(min_requests=1)

    def bad(action_id, reason):
        raise RuntimeError("nope")

    seen = []
    b.subscribe(bad)
    b.subscribe(lambda a, r: seen.append(a))
    b.watch("a")
    assert b.record("a", 10, 10)
    assert seen == ["a"]
    assert b.trips[0].callback_errors == ["RuntimeError: nope"]


@pytest.mark.parametrize("kw", [dict(baseline_error_rate=1.0), dict(relative_factor=0.5),
                                dict(absolute_margin=-1), dict(max_error_rate=0),
                                dict(min_requests=0), dict(window=timedelta(0))])
def test_breaker_config_validation(kw):
    with pytest.raises(ValueError):
        CircuitBreaker(**kw)


def test_executor_without_breaker():
    from aegis.mirror.executor import Executor as E

    class L:
        pass

    ex = E(DryRunAdapter(), L())  # type: ignore[arg-type]
    with pytest.raises(ExecutionError):
        ex.observe_legit_traffic("a", 1, 1)
