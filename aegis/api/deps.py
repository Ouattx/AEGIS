"""FastAPI dependencies: authentication, per-tenant rate limiting and RBAC."""
from __future__ import annotations

import hashlib
from typing import Any, Callable

from fastapi import Depends, Request
from starlette.concurrency import run_in_threadpool

from aegis.api.auth import AuthError, Authenticator, Principal
from aegis.api.metrics import ApiMetrics
from aegis.api.rbac import Permission, allowed
from aegis.api.ratelimit import RateLimiter
from aegis.api.settings import Settings
from aegis.service import AegisService

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class ApiError(Exception):
    """An error rendered as ``{"error", "detail", "failed_checks", "request_id"}``."""

    def __init__(self, status: int, code: str, detail: str, *, failed: list[str] | None = None,
                 headers: dict[str, str] | None = None):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.failed = failed or []
        self.headers = headers or {}


def service_of(request: Request) -> AegisService:
    return request.app.state.service


def settings_of(request: Request) -> Settings:
    return request.app.state.settings


def metrics_of(request: Request) -> ApiMetrics:
    return request.app.state.metrics


async def get_principal(request: Request) -> Principal:
    """Verify the bearer token, apply the tenant rate limit, remember the caller for audit."""
    authn: Authenticator = request.app.state.authenticator
    metrics = metrics_of(request)
    try:
        principal = await run_in_threadpool(authn.authenticate, request.headers.get("authorization"))
    except AuthError as exc:
        metrics.auth_failures.inc(reason=exc.reason)
        raise ApiError(401, "unauthenticated", exc.detail,
                       headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from exc
    request.state.principal = principal
    limiter: RateLimiter = request.app.state.tenant_limiter
    ok, retry = limiter.acquire(f"tenant:{principal.tenant_id}")
    if not ok:
        metrics.rate_limited.inc(scope="tenant")
        raise ApiError(429, "rate_limited", "tenant request rate exceeded",
                       headers={"Retry-After": str(max(1, int(retry + 0.999)))})
    if request.method in MUTATING_METHODS:
        body = await request.body()
        request.state.body_sha256 = hashlib.sha256(body).hexdigest()
        request.state.body_bytes = len(body)
    return principal


def require(permission: Permission) -> Callable[..., Any]:
    """Dependency factory: the caller must hold ``permission`` (through one of its roles)."""

    async def dependency(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        if not allowed(principal, permission):
            metrics_of(request).forbidden.inc(permission=permission.value)
            request.state.denied_permission = permission.value
            raise ApiError(403, "forbidden", f"role(s) {sorted(r.value for r in principal.roles)} lack "
                                             f"permission '{permission.value}'")
        return principal

    dependency.__name__ = f"require_{permission.value}"
    return dependency


__all__ = ["ApiError", "MUTATING_METHODS", "get_principal", "metrics_of", "require", "service_of", "settings_of"]
