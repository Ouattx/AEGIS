# AEGIS Copilot: integration guide

`aegis/copilot/` is self-contained. It is not yet wired into the service, API, CLI or console.
This page lists the exact calls an integrator needs.

## 1. Composition root (`aegis/service.py`)

```python
from aegis.copilot import Copilot, ServiceDataSource, copilot_llm_from_env

# in AegisService.__init__, after self.executor is built:
copilot_llm = copilot_llm_from_env() if (use_env_llm and settings.llm_enabled) else None
self.copilot = Copilot(ServiceDataSource(self), llm=copilot_llm)
```

* `ServiceDataSource` uses only the service's read paths: `list_findings`, `get_finding`,
  `list_cases`, `case_detail`, `evidence_view`, `get_action`, `graph_view`, `verify_ledger`,
  `metrics_summary`, `ready`, `ioc_status`, `topology_status`, `list_sources`, plus
  `ledger.entries/get/latest`, `evidence.get`, `docs.get`, `cases.get`, `atlas.get_node`,
  `quarantine`, `bus.depth`, `executor.active`.
* MIRROR simulation uses `service._simulate_for_agent` (read-only: no `MirrorRecord`, no ledger
  entry). If that private method is renamed, pass the simulator explicitly:
  `ServiceDataSource(self, simulator=self.simulate_readonly)`. A public
  `simulate_readonly(action) -> MirrorResult` on the service is recommended.
* The only write is one `copilot_qa` ledger entry per answered question (entry type exported as
  `aegis.copilot.COPILOT_AUDIT_ENTRY`). It stores the question's SHA-256 (never its text), the
  actor, the tools called, the cited ids, removed-claim counts, injection patterns and budget usage.
* `ready()` could report `"copilot": "llm" | "deterministic"` from `self.copilot.llm is not None`.

## 2. API (`aegis/api/routes.py`)

Suggested routes (roles: `viewer`, `analyst`, `approver`, `admin`; not `integration`). The tenant and user
come from the verified token, never from the request body.

```python
class CopilotAsk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=1, max_length=2000)
    session_id: str = Field(default="default", pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")

@router.post("/copilot/ask")
def copilot_ask(body: CopilotAsk, p=Depends(require_roles("viewer", "analyst", "approver", "admin"))):
    try:
        ans = svc.copilot.ask(tenant_id=p.tenant_id, user_id=p.sub, session_id=body.session_id,
                              question=body.question)
    except CopilotInputError as exc:
        raise HTTPException(422, str(exc))
    return ans.model_dump(mode="json") | {"text": ans.text, "cited_refs": ans.cited_refs}

@router.post("/copilot/stream")          # Server-Sent Events
def copilot_stream(body: CopilotAsk, p=Depends(...)):
    events = svc.copilot.ask_stream(tenant_id=p.tenant_id, user_id=p.sub, session_id=body.session_id,
                                    question=body.question)          # raises CopilotInputError eagerly
    def sse():
        for ev in events:
            yield f"event: {ev.type}\ndata: {ev.model_dump_json(exclude_none=True)}\n\n"
    return StreamingResponse(sse(), media_type="text/event-stream")

@router.delete("/copilot/sessions/{session_id}")
def copilot_reset(session_id: str, p=Depends(...)):
    return {"dropped": svc.copilot.reset_session(tenant_id=p.tenant_id, user_id=p.sub, session_id=session_id)}
```

`ask_stream` validates identity and question before returning the generator, so input errors surface
before the response starts. The generator runs blocking store reads and LLM calls; FastAPI runs a sync
generator in its threadpool. Apply the existing per-tenant rate limiter to these routes: each question
can trigger several LLM calls.

## 3. Streaming events (`CopilotEvent.type`)

| type | fields | meaning |
|---|---|---|
| `start` | `language` | question accepted |
| `tool_call` | `tool`, `call_id`, `args` | a read-only tool is running |
| `tool_result` | `trace` (`ok`, `error`, `rejected`, `refs`, `injection_patterns`) | tool finished or was rejected |
| `notice` | `code`, `message` | `budget_exhausted`, `injection_detected`, `claims_removed`, `fallback`, `audit_failed` |
| `sentence` | `sentence` (`text`, `citations[]`, `status`) | one validated sentence (sent only after validation) |
| `final` | `answer` (`CopilotAnswer`) | always last |

Console rendering: render each `sentence.citations` entry as a link
(`finding` → finding drawer, `case` → `/cases/{id}`, `evidence` → `/evidence/{id}`, `ledger` → ledger
entry, `node` → graph view, `action` → action detail, `campaign` → campaign view). `query`, `metrics`
and `health` refs name a tool result; show them as a "source" chip with the tool name from `tool_calls`.
Show `mode == "fallback"` as "deterministic answer" and display `removed_claims` count as
"n unsupported statements removed".

## 4. CLI (optional)

```python
# aegis copilot ask --tenant T "question"
ans = svc.copilot.ask(tenant_id=args.tenant, user_id="cli:" + getpass.getuser(), question=args.question)
print(ans.text)
```

## 5. Configuration

| setting | effect |
|---|---|
| `ANTHROPIC_API_KEY` unset | deterministic mode (intent classification + templated, cited answers) |
| `AEGIS_LLM_MODEL` | model id (default `claude-sonnet-5-5`) |
| `Copilot(budget=CopilotBudget(...))` | max tool calls (8), LLM calls (6), output tokens per call (2000), total tokens (80k), deadline (60 s), question length (2000) |
| `Copilot(uncited_policy="flag")` | keep uncited sentences marked `[uncited]` instead of stripping them |
| `Copilot(require_seen_refs=False)` | allow citing ids that exist in the tenant but no tool returned this session (not recommended) |
| `AnthropicToolLLM(effort="low"/"medium"/...)` | sends `output_config.effort` (omit for models that reject it) |
| `SessionStore(max_sessions, max_turns, max_refs, idle_ttl_s)` | memory bounds (1000 sessions, 8 turns, 4000 refs, 1 h idle) |

Sessions are in process memory: with several API workers, a follow-up question may land on a worker that
has no memory of the session. It still answers correctly, without the earlier context.

## 6. Tests

`tests/unit/test_copilot_*.py` (fake LLM clients, including a malicious one; no network).
