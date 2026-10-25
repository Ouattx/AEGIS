"""``/api/v1`` routes. Every handler scopes all reads and writes to ``principal.tenant_id``.

The tenant is never taken from the URL, query string or body; object ids from
another tenant are indistinguishable from missing ones (404).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from aegis.api.auth import ALL_ROLES, AuthError, Principal, Role, mint_dev_token
from aegis.api.deps import ApiError, get_principal, require, service_of, settings_of
from aegis.api.rbac import Permission, permissions_of
from aegis.api.schemas import (
    AuthorizeIn,
    BreakerResetIn,
    DecisionIn,
    EventsIn,
    ExecuteIn,
    HealthIn,
    NoteIn,
    ProposeIn,
    ReportInputsIn,
    ReviewIn,
    SourceIn,
    TokenGrantIn,
    TransitionIn,
)
from aegis.contracts.models import CaseState
from aegis.service import AegisService, Page

router = APIRouter(prefix="/api/v1")

#: console route that receives the authorization code (registered as redirect URI at the IdP)
CONSOLE_CALLBACK_PATH = "/auth/callback"



def _id() -> Any:
    # a fresh parameter object per use: FastAPI binds each one to its own path parameter
    return Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _limit_q() -> Any:
    return Query(50, ge=1, le=10_000)


def _offset_q() -> Any:
    return Query(0, ge=0, le=100_000_000)

R_READ = require(Permission.READ)
R_AUDIT = require(Permission.READ_AUDIT)
R_INGEST = require(Permission.INGEST)
R_CASE = require(Permission.CASE_WORK)
R_INVESTIGATE = require(Permission.INVESTIGATE)
R_PROPOSE = require(Permission.PROPOSE)
R_APPROVE = require(Permission.APPROVE)
R_EXECUTE = require(Permission.EXECUTE)
R_CONFIGURE = require(Permission.CONFIGURE)

#: target states an analyst may set through ``/cases/{id}/transition``
ANALYST_STATES = frozenset({CaseState.TRIAGE, CaseState.INVESTIGATING, CaseState.VERIFIED, CaseState.REJECTED,
                            CaseState.INCONCLUSIVE, CaseState.CLOSED})
#: target states reserved to approvers on that route
APPROVER_STATES = frozenset({CaseState.DENIED, CaseState.EXPIRED})


def _svc(request: Request) -> AegisService:
    return service_of(request)


def _limit(request: Request, limit: int) -> int:
    return min(limit, settings_of(request).max_page_size)


def _page(p: Page) -> dict[str, Any]:
    return {"items": p.items, "total": p.total, "limit": p.limit, "offset": p.offset}


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


# ============================================================================ identity


@router.get("/auth/config", tags=["auth"])
def auth_config(request: Request) -> dict[str, Any]:
    """Public: how the console should obtain a token (browser sign-in when an OIDC client is set)."""
    s = settings_of(request)
    login = request.app.state.oidc_login
    oidc: dict[str, Any] | None = None
    oidc_error: str | None = None
    if login.enabled:
        try:
            oidc = login.public_config()
        except AuthError as exc:
            oidc_error = exc.reason
    return {"auth_mode": s.auth_mode, "oidc_issuer": s.oidc_issuer if s.auth_mode == "oidc" else None,
            "oidc_audience": s.oidc_audience if s.auth_mode == "oidc" else None,
            "oidc_login": oidc, "oidc_login_error": oidc_error,
            "demo": s.auth_mode == "dev" and s.demo_tenant is not None,
            "roles": [r.value for r in ALL_ROLES]}


@router.post("/auth/token", tags=["auth"])
def auth_token(body: TokenGrantIn, request: Request) -> dict[str, Any]:
    """Public: relay the console's authorization-code (PKCE) or refresh grant to the IdP.

    The redirect URI must point at this console's own callback, so the relay cannot be
    used to complete flows for another site. Rate-limited per client address.
    """
    login = request.app.state.oidc_login
    if not login.enabled:
        raise ApiError(404, "not_found", "not found")
    client = request.client.host if request.client else "unknown"
    ok, retry = request.app.state.ip_limiter.acquire(f"token:{client}")
    if not ok:
        request.app.state.metrics.rate_limited.inc(scope="auth_token")
        raise ApiError(429, "rate_limited", "too many token requests",
                       headers={"Retry-After": str(max(1, int(retry + 0.999)))})
    if body.grant_type == "authorization_code":
        expected = str(request.base_url).rstrip("/") + CONSOLE_CALLBACK_PATH
        if (body.redirect_uri or "").rstrip("/") != expected:
            raise ApiError(422, "invalid", "redirect_uri must be this console's callback")
    try:
        return login.exchange(body.model_dump(exclude_none=True))
    except AuthError as exc:
        raise ApiError(401 if exc.reason == "token_exchange_failed" else 502, exc.reason, exc.detail) from exc


@router.get("/me", tags=["auth"])
def me(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """The verified caller (any role)."""
    return {**principal.public(), "permissions": sorted(p.value for p in permissions_of(principal))}


@router.get("/demo/token", tags=["auth"])
def demo_token(request: Request, role: Role = Query(...)) -> dict[str, Any]:
    """Dev-mode only: a short-lived token for the seeded demo tenant (404 otherwise)."""
    s = settings_of(request)
    if s.auth_mode != "dev" or not s.demo_tenant:
        raise ApiError(404, "not_found", "not found")
    client = request.client.host if request.client else "unknown"
    ok, retry = request.app.state.ip_limiter.acquire(f"demo:{client}")
    if not ok:
        request.app.state.metrics.rate_limited.inc(scope="demo_token")
        raise ApiError(429, "rate_limited", "too many token requests",
                       headers={"Retry-After": str(max(1, int(retry + 0.999)))})
    try:
        token = mint_dev_token(s, sub=f"demo-{role.value}", tenant_id=s.demo_tenant, roles=[role.value])
    except AuthError as exc:  # pragma: no cover - guarded by the mode check above
        raise ApiError(404, "not_found", "not found") from exc
    return {"access_token": token, "token_type": "bearer", "expires_in": s.dev_token_ttl_s,
            "role": role.value, "tenant_id": s.demo_tenant, "sub": f"demo-{role.value}"}


# ============================================================================ configuration


@router.get("/sources", tags=["configuration"])
def list_sources(request: Request, principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    items = [c.model_dump(mode="json") for c in _svc(request).list_sources(principal.tenant_id)]
    return {"items": items, "total": len(items)}


@router.post("/sources", status_code=201, tags=["configuration"])
def create_source(body: SourceIn, request: Request, principal: Principal = Depends(R_CONFIGURE)) -> dict[str, Any]:
    cfg = _svc(request).register_source(principal.tenant_id, principal.actor, **body.model_dump())
    return cfg.model_dump(mode="json")


@router.get("/iocs", tags=["configuration"])
def ioc_status(request: Request, principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return {"bundle": _svc(request).ioc_status(principal.tenant_id)}


@router.post("/iocs", status_code=201, tags=["configuration"])
def load_iocs(body: dict[str, Any], request: Request, principal: Principal = Depends(R_CONFIGURE)) -> dict[str, Any]:
    svc = _svc(request)
    svc.load_ioc_bundle(principal.tenant_id, principal.actor, body)
    return {"bundle": svc.ioc_status(principal.tenant_id)}


@router.get("/topology", tags=["configuration"])
def topology_status(request: Request, principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return {"topology": _svc(request).topology_status(principal.tenant_id)}


@router.post("/topology", status_code=201, tags=["configuration"])
def load_topology(body: dict[str, Any], request: Request,
                  principal: Principal = Depends(R_CONFIGURE)) -> dict[str, Any]:
    topo = _svc(request).load_topology(principal.tenant_id, principal.actor, body)
    return {"topology": topo.summary()}


@router.get("/policies", tags=["configuration"])
def list_policies(request: Request, principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    items = _svc(request).list_policies(principal.tenant_id)
    return {"items": items, "total": len(items)}


@router.post("/policies", status_code=201, tags=["configuration"])
def load_policy(body: dict[str, Any], request: Request, principal: Principal = Depends(R_CONFIGURE)) -> dict[str, Any]:
    policy = _svc(request).load_policy(principal.tenant_id, principal.actor, body)
    return {"policy": policy.model_dump(mode="json"), "signature_valid": True}


# ============================================================================ ingest


@router.post("/ingest", tags=["ingest"])
async def ingest_raw(request: Request, source_id: str = Query(..., min_length=1, max_length=128),
                     flush: bool = Query(False), name: str = Query("upload", max_length=200),
                     principal: Principal = Depends(R_INGEST)) -> dict[str, Any]:
    """Raw collector payload (NetFlow CSV, DNS JSONL, Zeek log, CPE JSON) from a registered source."""
    data = await request.body()
    if not data.strip():
        raise ApiError(422, "invalid", "empty payload")
    outcome = await run_in_threadpool(_svc(request).ingest_text, principal.tenant_id, source_id, data,
                                      name=name, flush=flush)
    _count_ingest(request, outcome)
    return outcome.summary()


@router.post("/ingest/events", tags=["ingest"])
def ingest_events(body: EventsIn, request: Request, principal: Principal = Depends(R_INGEST)) -> dict[str, Any]:
    """Pre-normalized ``ObservationEvent`` objects (schema 3.0) from a registered source."""
    outcome = _svc(request).ingest_events(principal.tenant_id, body.events, flush=body.flush)
    _count_ingest(request, outcome)
    return outcome.summary()


def _count_ingest(request: Request, outcome: Any) -> None:
    m = request.app.state.metrics
    for s in outcome.stats:
        m.ingest_records.inc(float(s.get("accepted") or 0), outcome="accepted")
        m.ingest_records.inc(float(s.get("quarantined") or 0), outcome="quarantined")
        m.ingest_records.inc(float(s.get("duplicates") or 0), outcome="duplicate")
    for f in outcome.findings:
        m.findings.inc(verdict=f.verdict.value)
    if outcome.cases_opened:
        m.cases_opened.inc(float(len(outcome.cases_opened)))


@router.get("/ingest/quarantine", tags=["ingest"])
def quarantine(request: Request, limit: int = _limit_q(), offset: int = _offset_q(),
               principal: Principal = Depends(R_AUDIT)) -> dict[str, Any]:
    p = _svc(request).list_quarantine(principal.tenant_id, limit=_limit(request, limit), offset=offset)
    p.items = [q.model_dump(mode="json", exclude={"raw_b64"}) for q in p.items]
    return _page(p)


# ============================================================================ findings


@router.get("/findings", tags=["findings"])
def list_findings(request: Request, verdict: str | None = Query(None, max_length=32),
                  label: str | None = Query(None, max_length=64), status: str | None = Query(None, max_length=32),
                  entity: str | None = Query(None, max_length=128), since: datetime | None = None,
                  until: datetime | None = None, limit: int = _limit_q(), offset: int = _offset_q(),
                  principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return _page(_svc(request).list_findings(principal.tenant_id, verdict=verdict, label=label, status=status,
                                             entity=entity, since=_aware(since), until=_aware(until),
                                             limit=_limit(request, limit), offset=offset))


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(request: Request, finding_id: str = _id(), principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).get_finding(principal.tenant_id, finding_id)


# ============================================================================ cases


@router.get("/cases", tags=["cases"])
def list_cases(request: Request, state: CaseState | None = None,
               severity: Literal["low", "medium", "high", "critical"] | None = None,
               limit: int = _limit_q(), offset: int = _offset_q(),
               principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return _page(_svc(request).list_cases(principal.tenant_id, state=state.value if state else None,
                                          severity=severity, limit=_limit(request, limit), offset=offset))


@router.get("/cases/{case_id}", tags=["cases"])
def get_case(request: Request, case_id: str = _id(), principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return _svc(request).case_detail(principal.tenant_id, case_id)


@router.get("/cases/{case_id}/evidence", tags=["cases"])
def case_evidence(request: Request, case_id: str = _id(), principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    items = _svc(request).case_evidence(principal.tenant_id, case_id)
    return {"items": items, "total": len(items)}


@router.get("/cases/{case_id}/history", tags=["cases"])
def case_history(request: Request, case_id: str = _id(), principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    items = _svc(request).case_history(principal.tenant_id, case_id)
    return {"items": items, "total": len(items)}


@router.get("/cases/{case_id}/investigation", tags=["cases"])
def case_investigation(request: Request, case_id: str = _id(), principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).latest_investigation(principal.tenant_id, case_id)


@router.post("/cases/{case_id}/transition", tags=["cases"])
def transition_case(body: TransitionIn, request: Request, case_id: str = _id(),
                    principal: Principal = Depends(R_READ)) -> Any:
    perms = permissions_of(principal)
    if body.to_state in ANALYST_STATES:
        needed = Permission.CASE_WORK
    elif body.to_state in APPROVER_STATES:
        needed = Permission.APPROVE
    else:
        raise ApiError(422, "use_actions_workflow",
                       f"{body.to_state.value} is reached through /actions (authorize, approve, execute, rollback)")
    if needed not in perms:
        request.app.state.metrics.forbidden.inc(permission=needed.value)
        request.state.denied_permission = needed.value
        raise ApiError(403, "forbidden", f"moving a case to {body.to_state.value} requires permission "
                                         f"'{needed.value}'")
    case = _svc(request).transition_case(principal.tenant_id, case_id, body.to_state, principal.actor, body.reason)
    request.app.state.metrics.case_transitions.inc(to_state=body.to_state.value, outcome="ok")
    return case


@router.post("/cases/{case_id}/review", tags=["cases"])
def review_case(body: ReviewIn, request: Request, case_id: str = _id(), principal: Principal = Depends(R_CASE)) -> Any:
    return _svc(request).review_case(principal.tenant_id, case_id, principal.actor, body.alternatives, body.notes)


@router.post("/cases/{case_id}/notes", status_code=201, tags=["cases"])
def add_note(body: NoteIn, request: Request, case_id: str = _id(), principal: Principal = Depends(R_CASE)) -> Any:
    return _svc(request).add_case_note(principal.tenant_id, case_id, principal.actor, body.note)


@router.post("/cases/{case_id}/investigate", tags=["cases"])
def investigate(request: Request, case_id: str = _id(), principal: Principal = Depends(R_INVESTIGATE)) -> Any:
    return _svc(request).investigate_case(principal.tenant_id, case_id, principal.actor)


@router.get("/cases/{case_id}/replay", tags=["cases"])
def replay(request: Request, case_id: str = _id(), as_of: datetime | None = None,
           principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).replay_case(principal.tenant_id, case_id, _aware(as_of))


# ============================================================================ evidence, ledger, graph


@router.get("/evidence/{evidence_id}", tags=["evidence"])
def get_evidence(request: Request, evidence_id: str = _id(), principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).evidence_view(principal.tenant_id, evidence_id)


@router.get("/ledger/verify", tags=["ledger"])
def verify_ledger(request: Request, principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).verify_ledger(principal.tenant_id)


@router.get("/ledger/entries", tags=["ledger"])
def ledger_entries(request: Request, subject_id: str | None = Query(None, max_length=128),
                   entry_type: str | None = Query(None, max_length=64), limit: int = _limit_q(),
                   offset: int = _offset_q(),
                   principal: Principal = Depends(R_AUDIT)) -> dict[str, Any]:
    return _page(_svc(request).ledger_entries(principal.tenant_id, subject_id=subject_id, entry_type=entry_type,
                                              limit=_limit(request, limit), offset=offset))


@router.get("/graph/{node:path}", tags=["graph"])
def graph(request: Request, node: str, as_of: datetime | None = None,
          principal: Principal = Depends(R_READ)) -> Any:
    if not node or len(node) > 300:
        raise ApiError(422, "invalid", "node must be 1..300 characters")
    return _svc(request).graph_view(principal.tenant_id, node, _aware(as_of))


# ============================================================================ actions


@router.get("/actions", tags=["actions"])
def list_actions(request: Request, case_id: str | None = Query(None, max_length=128), limit: int = _limit_q(),
                 offset: int = _offset_q(), principal: Principal = Depends(R_READ)) -> dict[str, Any]:
    return _page(_svc(request).list_actions(principal.tenant_id, case_id=case_id, limit=_limit(request, limit),
                                            offset=offset))


@router.post("/actions", status_code=201, tags=["actions"])
def propose_action(body: ProposeIn, request: Request, principal: Principal = Depends(R_PROPOSE)) -> Any:
    expires = body.expires_at
    if expires is None and body.expires_in_hours is not None:
        expires = _svc(request).clock() + timedelta(hours=body.expires_in_hours)
    action = _svc(request).propose_action(
        principal.tenant_id, principal.actor, case_id=body.case_id, action_type=body.action_type,
        targets=body.targets, scope=body.scope, legal_basis=body.legal_basis, expires_at=expires,
        rollback_plan=body.rollback_plan, rollback_verified=body.rollback_verified)
    request.app.state.metrics.actions.inc(step="propose", outcome="ok")
    return action


@router.get("/actions/{action_id}", tags=["actions"])
def get_action(request: Request, action_id: str = _id(), principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).action_detail(principal.tenant_id, action_id)


@router.post("/actions/{action_id}/simulate", tags=["actions"])
def simulate_action(request: Request, action_id: str = _id(), principal: Principal = Depends(R_PROPOSE)) -> Any:
    result = _svc(request).simulate_action(principal.tenant_id, principal.actor, action_id)
    request.app.state.metrics.actions.inc(step="simulate", outcome=result.verdict.value)
    return result


@router.post("/actions/{action_id}/authorize", tags=["actions"])
def authorize_action(request: Request, body: AuthorizeIn | None = None, action_id: str = _id(),
                     principal: Principal = Depends(R_PROPOSE)) -> Any:
    out = _svc(request).authorize_action(principal.tenant_id, principal.actor, action_id,
                                         policy_id=body.policy_id if body else None)
    request.app.state.metrics.actions.inc(step="authorize",
                                          outcome="allowed" if out["decision"].allowed else "not_allowed")
    return out


@router.post("/actions/{action_id}/approve", tags=["actions"])
def approve_action(body: DecisionIn, request: Request, action_id: str = _id(),
                   principal: Principal = Depends(R_APPROVE)) -> Any:
    case = _svc(request).decide_action(principal.tenant_id, principal.actor, action_id, approve=True,
                                       reason=body.reason)
    request.app.state.metrics.actions.inc(step="approve", outcome="ok")
    return {"case": case}


@router.post("/actions/{action_id}/deny", tags=["actions"])
def deny_action(body: DecisionIn, request: Request, action_id: str = _id(),
                principal: Principal = Depends(R_APPROVE)) -> Any:
    case = _svc(request).decide_action(principal.tenant_id, principal.actor, action_id, approve=False,
                                       reason=body.reason)
    request.app.state.metrics.actions.inc(step="deny", outcome="ok")
    return {"case": case}


@router.post("/actions/{action_id}/execute", tags=["actions"])
def execute_action(request: Request, body: ExecuteIn | None = None, action_id: str = _id(),
                   principal: Principal = Depends(R_EXECUTE)) -> Any:
    out = _svc(request).execute_action(principal.tenant_id, principal.actor, action_id,
                                       reason=body.reason if body else "")
    request.app.state.metrics.actions.inc(step="execute", outcome=out["execution"].status.value)
    return out


@router.post("/actions/{action_id}/rollback", tags=["actions"])
def rollback_action(body: DecisionIn, request: Request, action_id: str = _id(),
                    principal: Principal = Depends(R_EXECUTE)) -> Any:
    out = _svc(request).rollback_action(principal.tenant_id, principal.actor, action_id, reason=body.reason)
    request.app.state.metrics.actions.inc(step="rollback", outcome=out["execution"].status.value)
    return out


@router.post("/actions/{action_id}/health", tags=["actions"])
def action_health(body: HealthIn, request: Request, action_id: str = _id(),
                  principal: Principal = Depends(get_principal)) -> Any:
    """Legitimate-traffic health sample for a live action (integration collectors or approvers).

    An abnormal error rate trips the circuit breaker: the action is rolled back
    automatically and its case moves to ROLLED_BACK.
    """
    perms = permissions_of(principal)
    if Permission.INGEST not in perms and Permission.EXECUTE not in perms:
        request.app.state.metrics.forbidden.inc(permission="ingest|execute")
        request.state.denied_permission = "ingest|execute"
        raise ApiError(403, "forbidden", "reporting action health requires permission 'ingest' or 'execute'")
    out = _svc(request).report_legit_traffic(principal.tenant_id, action_id, requests=body.requests,
                                             errors=body.errors)
    if out["tripped"]:
        request.app.state.metrics.actions.inc(step="breaker_trip", outcome="rolled_back")
    return out


@router.get("/enforcement/breaker", tags=["actions"])
def breaker_status(request: Request, principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).breaker_status()


@router.post("/enforcement/breaker/reset", tags=["actions"])
def breaker_reset(body: BreakerResetIn, request: Request, principal: Principal = Depends(R_EXECUTE)) -> Any:
    """Close a tripped circuit breaker (approver; a human with a recorded reason)."""
    return _svc(request).reset_breaker(principal.tenant_id, principal.actor, body.reason)


# ============================================================================ reports and metrics


@router.get("/reports/pov", tags=["reports"])
def pov_report(request: Request, start: datetime | None = None, end: datetime | None = None,
               format: Literal["html", "json"] = "html", operator: str | None = Query(None, max_length=120),
               budget: float | None = Query(None, ge=0, le=10_000),
               principal: Principal = Depends(R_READ)) -> Any:
    if (start is None) != (end is None):
        raise ApiError(422, "invalid", "give both start and end, or neither")
    if start is not None and end is not None and _aware(end) <= _aware(start):  # type: ignore[operator]
        raise ApiError(422, "invalid", "end must be after start")
    out = _svc(request).pov_report(principal.tenant_id, start=_aware(start), end=_aware(end), operator_name=operator,
                                   false_alert_budget_per_10k=budget, fmt=format)
    if format == "json":
        return JSONResponse(json.loads(json.dumps(out, default=str)))
    return HTMLResponse(str(out), headers={"Content-Disposition": 'inline; filename="aegis-pov-report.html"'})


@router.get("/reports/inputs", tags=["reports"])
def get_report_inputs(request: Request, principal: Principal = Depends(R_READ)) -> Any:
    """Cost inputs and analyst effort model used by the PoV report."""
    return _svc(request).report_inputs(principal.tenant_id)


@router.put("/reports/inputs", tags=["reports"])
def put_report_inputs(body: ReportInputsIn, request: Request, principal: Principal = Depends(R_CONFIGURE)) -> Any:
    """Set the operator's cost inputs (license, infrastructure, monitored devices...) and effort model."""
    return _svc(request).set_report_inputs(principal.tenant_id, principal.actor, cost=body.cost, effort=body.effort)


@router.get("/metrics/summary", tags=["reports"])
def metrics_summary(request: Request, principal: Principal = Depends(R_READ)) -> Any:
    return _svc(request).metrics_summary(principal.tenant_id)


__all__ = ["ANALYST_STATES", "APPROVER_STATES", "router"]
