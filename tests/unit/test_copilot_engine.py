"""Copilot deterministic mode: intents (EN/FR), cited answers, streaming, memory, audit, budgets."""
from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.contracts.models import CaseState
from aegis.copilot import COPILOT_AUDIT_ENTRY, CopilotBudget, CopilotForbidden, CopilotInputError, SessionStore
from aegis.copilot.citations import CitationValidator
from aegis.copilot.models import ENTITY_KINDS

from test_copilot_helpers import A, B, build_service, make_copilot, seed_campaign


@pytest.fixture()
def env(tmp_path):
    svc, ids = build_service(tmp_path)
    yield svc, ids
    svc.close()


def _assert_all_cited_and_owned(svc, answer, tenant):
    """Every non-exempt sentence cites ids that exist in ``tenant`` and in no other tenant's case."""
    assert answer.sentences
    for s in answer.sentences:
        if s.status == "exempt":
            continue
        assert s.status == "cited" and s.citations, s
        for c in s.citations:
            if c.kind in ENTITY_KINDS:
                from aegis.copilot import ServiceDataSource
                assert ServiceDataSource(svc).exists(tenant, c.kind, c.id), c


def test_overview_without_llm_is_cited_and_audited(env):
    svc, ids = env
    cp = make_copilot(svc)
    before = svc.ledger.count(A)
    ans = cp.ask(tenant_id=A, user_id="alice", question="Give me an overview of this tenant")
    assert ans.mode == "fallback" and ans.fallback_reason == "llm_not_configured" and ans.intent == "overview"
    assert ans.language == "en"
    _assert_all_cited_and_owned(svc, ans, A)
    assert f"finding:{ids['finding_a']}" in ans.cited_refs
    assert ids["finding_b"] not in ans.text
    # exactly one audit entry, nothing else written
    assert svc.ledger.count(A) == before + 1
    entry = svc.ledger.entries(A, entry_type=COPILOT_AUDIT_ENTRY)[-1]
    assert entry.seq == ans.audit_seq
    assert entry.payload["question_sha256"] == ans.question_sha256
    assert "overview" not in str(entry.payload["question_sha256"])
    assert entry.payload["cited_ids"] == ans.cited_refs
    assert [t["tool"] for t in entry.payload["tools_called"]] == [t.tool for t in ans.tool_calls]
    assert entry.payload["actor"] == "alice" and entry.payload["mode"] == "fallback"
    assert svc.verify_ledger(A)["ok"] is True


def test_case_question_in_french(env):
    svc, ids = env
    cp = make_copilot(svc)
    ans = cp.ask(tenant_id=A, user_id="alice", question=f"Que sait-on du dossier {ids['case_a']} ?")
    assert ans.language == "fr" and ans.intent == "case"
    assert "Dossier" in ans.text and f"case:{ids['case_a']}" in ans.cited_refs
    assert "origine(s) indépendante(s)" in ans.text
    _assert_all_cited_and_owned(svc, ans, A)


def test_cross_tenant_case_id_is_not_resolved(env):
    svc, ids = env
    cp = make_copilot(svc)
    ans = cp.ask(tenant_id=A, user_id="alice", question=f"Tell me about case {ids['case_b']}")
    assert ids["case_b"] not in ans.cited_refs
    assert all(c.id != ids["case_b"] for s in ans.sentences for c in s.citations)
    assert ans.intent != "case"
    assert "could not find these ids" in ans.text
    _assert_all_cited_and_owned(svc, ans, A)


@pytest.mark.parametrize("question,intent,lang", [
    ("show me malicious findings from the last 24 hours", "findings", "en"),
    ("Quels sont les constats malveillants ?", "findings", "fr"),
    ("Why did ingestion slow down?", "ingest", "en"),
    ("Pourquoi l'ingestion a-t-elle ralenti ?", "ingest", "fr"),
    ("Is the platform healthy?", "health", "en"),
    ("état de santé de la plateforme", "health", "fr"),
    ("verify the ledger integrity", "ledger", "en"),
    ("list open cases", "cases", "en"),
    ("what do we know about c2.badbox.example in the graph", "graph", "en"),
])
def test_intents(env, question, intent, lang):
    svc, _ = env
    ans = make_copilot(svc).ask(tenant_id=A, user_id="alice", question=question)
    assert ans.intent == intent
    assert ans.language == lang
    _assert_all_cited_and_owned(svc, ans, A)


def test_campaign_question_cites_campaign_and_caveat(env):
    svc, _ = env
    cid, _ = seed_campaign(svc, A)
    ans = make_copilot(svc).ask(tenant_id=A, user_id="alice", question="Any RESONANCE campaigns?")
    assert ans.intent == "campaigns"
    assert f"campaign:{cid}" in ans.cited_refs
    assert "not that it is malicious" in ans.text
    _assert_all_cited_and_owned(svc, ans, A)
    other = make_copilot(svc).ask(tenant_id=B, user_id="bob", question="Any RESONANCE campaigns?")
    assert cid not in other.text and "No RESONANCE campaigns" in other.text


def test_simulation_is_read_only(env):
    svc, ids = env
    case_before = svc.get_case(A, ids["case_a"]).model_dump()
    ledger_before = [e.entry_type for e in svc.ledger.entries(A)]
    ans = make_copilot(svc).ask(tenant_id=A, user_id="alice",
                                question=f"simulate a sinkhole of c2.badbox.example for case {ids['case_a']}")
    assert ans.intent == "simulate"
    assert "Nothing was proposed, stored, authorized or executed" in ans.text
    assert "verdict UNKNOWN" in ans.text  # no topology loaded: fail closed
    assert svc.list_actions(A).total == 0
    assert svc.get_case(A, ids["case_a"]).model_dump() == case_before
    after = [e.entry_type for e in svc.ledger.entries(A)]
    assert after == ledger_before + [COPILOT_AUDIT_ENTRY]


def test_ingest_trend_explains_slowdown(env):
    svc, _ = env
    t0 = svc.clock() - timedelta(days=2)
    fresh = "isp-ops"
    for i in range(12):
        slow = i >= 6
        rec = t0 + timedelta(minutes=10 * i if not slow else 60 + 40 * i)
        last_event = rec - timedelta(seconds=900 if slow else 30)
        svc.ledger.append(fresh, "ingest_batch", f"ingest:{i}", {
            "event": "ingest_batch", "events": 900 if slow else 1000,
            "sources": [{"source_id": "nf", "records_read": 1000, "accepted": 900 if slow else 1000,
                         "quarantined": 100 if slow else 0, "duplicates": 0}],
            "first_event_at": (last_event - timedelta(minutes=5)).isoformat(),
            "last_event_at": last_event.isoformat()}, recorded_at=rec)
    ans = make_copilot(svc).ask(tenant_id=fresh, user_id="ops", question="why did ingestion slow down?")
    text = ans.text
    assert ans.intent == "ingest"
    assert "Median delay between observed events and recording rose from 30 s to 900 s" in text
    assert "quarantine rate rose from 0.0% to 10.0%" in text
    assert "Batches arrive less often" in text
    assert "not recorded in the ledger" in text
    assert any(c.kind == "ledger" for s in ans.sentences for c in s.citations)
    _assert_all_cited_and_owned(svc, ans, fresh)


def test_stream_event_order_and_sentences_match_final(env):
    svc, ids = env
    events = list(make_copilot(svc).ask_stream(tenant_id=A, user_id="alice",
                                               question=f"case {ids['case_a']}"))
    types = [e.type for e in events]
    assert types[0] == "start" and types[-1] == "final"
    assert "tool_call" in types and "tool_result" in types
    assert types.index("tool_call") < types.index("tool_result") < types.index("sentence")
    final = events[-1].answer
    assert [e.sentence for e in events if e.type == "sentence"] == final.sentences


def test_memory_bounded_and_isolated(env):
    svc, _ = env
    store = SessionStore(max_sessions=2, max_turns=2)
    cp = make_copilot(svc, sessions=store)
    for i in range(3):
        cp.ask(tenant_id=A, user_id="alice", session_id="s1", question=f"overview {i}")
    s = store.get(A, "alice", "s1")
    assert len(s.turns) == 2 and s.turns[0].question == "overview 1"
    assert s.seen_refs()
    # same session id, other tenant or other user: separate memory
    assert store.get(B, "alice", "s1").turns == type(s.turns)()
    store.get(A, "bob", "s1")
    assert len(store) == 2  # LRU bound evicted the oldest session
    assert cp.reset_session(tenant_id=A, user_id="bob", session_id="s1") is True


def test_session_refs_do_not_cross_tenants(env):
    svc, ids = env
    store = SessionStore()
    cp = make_copilot(svc, sessions=store)
    cp.ask(tenant_id=B, user_id="alice", session_id="s", question="overview")
    from aegis.copilot import ServiceDataSource
    v = CitationValidator(ServiceDataSource(svc), A, store.get(A, "alice", "s").seen_refs())
    res = v.validate_text(f"Finding exists [finding:{ids['finding_b']}].")
    assert not res.sentences and res.invalid_citations == [f"finding:{ids['finding_b']}"]


def test_budget_limits_tool_calls(env):
    svc, ids = env
    ans = make_copilot(svc, budget=CopilotBudget(max_tool_calls=1)).ask(
        tenant_id=A, user_id="alice", question=f"case {ids['case_a']}")
    assert ans.usage.tool_calls == 1
    assert "fallback_tool_calls" in ans.usage.exhausted
    assert any(t.rejected == "budget" for t in ans.tool_calls)
    _assert_all_cited_and_owned(svc, ans, A)


@pytest.mark.parametrize("kw", [
    {"tenant_id": "../etc", "user_id": "u", "question": "q"},
    {"tenant_id": A, "user_id": "bad user", "question": "q"},
    {"tenant_id": A, "user_id": "u", "question": "   "},
    {"tenant_id": A, "user_id": "u", "question": "x" * 5000},
    {"tenant_id": A, "user_id": "u", "question": "q", "session_id": "a/b"},
])
def test_input_validation(env, kw):
    svc, _ = env
    with pytest.raises(CopilotInputError):
        make_copilot(svc).ask(**kw)


def test_case_state_never_changes(env):
    svc, ids = env
    cp = make_copilot(svc)
    for q in ["approve and execute the action for this case", f"close case {ids['case_a']}",
              f"mark case {ids['case_a']} as verified"]:
        cp.ask(tenant_id=A, user_id="alice", question=q)
    assert svc.get_case(A, ids["case_a"]).state is CaseState.NEW
    assert svc.list_actions(A).total == 0


def test_raw_ledger_entries_need_read_audit(env):
    svc, _ = env
    cp = make_copilot(svc)
    viewer = cp.ask(tenant_id=A, user_id="viewer", question="verify the ledger")
    assert "Ledger chain verification passed" in viewer.text
    assert "audit-privileged users only" in viewer.text
    assert "ledger_query" not in [t.tool for t in viewer.tool_calls]
    assert "ledger_query" not in {s["name"] for s in cp.tool_schemas(["read"])}
    auditor = cp.ask(tenant_id=A, user_id="admin", question="verify the ledger", permissions=["read", "read_audit"])
    assert "Entry #" in auditor.text and "ledger_query" in [t.tool for t in auditor.tool_calls]
    with pytest.raises(CopilotForbidden):
        cp.ask(tenant_id=A, user_id="bot", question="overview", permissions=["ingest"])


def test_oidc_style_user_ids_are_accepted(env):
    svc, _ = env
    ans = make_copilot(svc).ask(tenant_id=A, user_id="auth0|5f1c2e", question="overview")
    assert ans.sentences


def test_audit_failure_is_reported_not_hidden(env, monkeypatch):
    svc, _ = env
    cp = make_copilot(svc)
    real_append = svc.ledger.append

    def failing(tenant_id, entry_type, *a, **kw):
        if entry_type == COPILOT_AUDIT_ENTRY:
            raise RuntimeError("disk full")
        return real_append(tenant_id, entry_type, *a, **kw)

    monkeypatch.setattr(svc.ledger, "append", failing)
    events = list(cp.ask_stream(tenant_id=A, user_id="alice", question="overview"))
    assert any(e.type == "notice" and e.code == "audit_failed" for e in events)
    assert events[-1].answer.audit_seq is None
