"""FastAPI application factory for AEGIS SHIELD.

``create_app(settings)`` wires the composition root (:class:`aegis.service.AegisService`)
behind:

* bearer-token authentication (OIDC RS256 via JWKS, or dev HS256) with the tenant
  taken from the token only, per-tenant rate limiting and role-based permissions;
* an HTTP middleware that assigns a request id, logs one structured JSON line per
  request, records Prometheus metrics, adds security headers and writes an
  ``api_audit`` ledger entry for every mutating call of an authenticated caller
  (including refused ones);
* ``/healthz`` (liveness), ``/readyz`` (database reachable), ``/metrics``
  (Prometheus text, optionally token-protected);
* the analyst console from ``web/dist`` with single-page-app fallback.
"""
from __future__ import annotations

import hmac
import logging
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from aegis.api.auth import Authenticator, OIDCLogin
from aegis.api.deps import MUTATING_METHODS, ApiError
from aegis.api.logs import configure_logging, request_context
from aegis.api.metrics import CONTENT_TYPE, ApiMetrics
from aegis.api.ratelimit import RateLimiter
from aegis.api.routes import router
from aegis.api.settings import Settings
from aegis.service import AEGIS_VERSION, AegisService, ServiceError

log = logging.getLogger("aegis.api")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
INGEST_PREFIX = "/api/v1/ingest"
DEFAULT_MAX_BODY = 16 * 1024 * 1024


class BodySizeLimit:
    """Pure ASGI middleware rejecting request bodies above a limit (413) before buffering them."""

    def __init__(self, app: ASGIApp, *, default_limit: int, ingest_limit: int):
        self.app = app
        self.default_limit = default_limit
        self.ingest_limit = ingest_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        limit = self.ingest_limit if path.startswith(INGEST_PREFIX) else self.default_limit
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > limit:
                        await _send_413(send, limit)
                        return
                except ValueError:
                    await _send_json(send, 400, {"error": "bad_request", "detail": "invalid Content-Length"})
                    return
        received = 0
        too_large = False
        replaced = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    too_large = True
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message: Message) -> None:
            # whatever the inner layers answer once the limit was hit, the client gets a 413
            nonlocal replaced
            if too_large:
                if not replaced and message["type"] == "http.response.start":
                    replaced = True
                    await _send_413(send, limit)
                return
            await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            if not replaced:
                await _send_413(send, limit)


class _BodyTooLarge(Exception):
    pass


async def _send_json(send: Send, status: int, body: dict[str, Any]) -> None:
    import json
    data = json.dumps(body).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


async def _send_413(send: Send, limit: int) -> None:
    await _send_json(send, 413, {"error": "payload_too_large", "detail": f"request body exceeds {limit} bytes"})


def _error_body(request: Request, code: str, detail: str, failed: list[str] | None = None) -> dict[str, Any]:
    return {"error": code, "detail": detail, "failed_checks": failed or [],
            "request_id": getattr(request.state, "request_id", None)}


def _security_headers(response: Response, path: str) -> None:
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if path.startswith("/api/v1/docs") or path.startswith("/api/v1/redoc"):
        return  # interactive docs load their assets from a CDN
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                 "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
    if path.startswith("/api/"):
        h.setdefault("Cache-Control", "no-store")


def create_app(settings: Settings | None = None, *, service: AegisService | None = None) -> FastAPI:
    """Build the AEGIS API. ``service`` lets callers (CLI demo, tests) share a prepared service."""
    settings = settings or (service.settings if service is not None else Settings.from_env())
    configure_logging(settings.log_level, settings.log_format)
    svc = service or AegisService(settings)
    metrics = ApiMetrics(AEGIS_VERSION)
    stop = threading.Event()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        sweeper: threading.Thread | None = None
        if settings.sweep_interval_s > 0:
            sweeper = threading.Thread(target=_sweep_loop, args=(svc, settings.sweep_interval_s, stop),
                                       name="aegis-expiry-sweeper", daemon=True)
            sweeper.start()
        log.info("AEGIS API started", extra={"settings": settings.public_summary()})
        try:
            yield
        finally:
            stop.set()
            if sweeper is not None:
                sweeper.join(timeout=5)

    app = FastAPI(title="AEGIS OMEGA SHIELD API", version=AEGIS_VERSION, lifespan=lifespan,
                  docs_url="/api/v1/docs", redoc_url=None, openapi_url="/api/v1/openapi.json")
    app.state.settings = settings
    app.state.service = svc
    app.state.metrics = metrics
    app.state.authenticator = Authenticator(settings)
    app.state.oidc_login = OIDCLogin(settings)
    app.state.tenant_limiter = RateLimiter(settings.rate_limit_rps, settings.rate_limit_burst)
    app.state.ip_limiter = RateLimiter(1.0, 20)

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_credentials=False,
                           allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type",
                                                                         "X-Request-ID"])

    app.add_middleware(BodySizeLimit, default_limit=DEFAULT_MAX_BODY, ingest_limit=settings.max_ingest_bytes)

    @app.middleware("http")
    async def observe(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        request.state.request_id = rid
        token = request_context.set({"request_id": rid})
        t0 = time.perf_counter()
        status = 500
        response: Response | None = None
        try:
            response = await call_next(request)
            status = response.status_code
        except Exception:
            log.exception("unhandled error")
            response = JSONResponse(_error_body(request, "internal_error", "internal server error"), status_code=500)
            status = 500
        finally:
            elapsed = time.perf_counter() - t0
            route = request.scope.get("route")
            route_path = getattr(route, "path", None) or ("static" if not request.url.path.startswith("/api/")
                                                          else "unmatched")
            metrics.http_requests.inc(method=request.method, route=route_path, status=str(status))
            metrics.http_latency.observe(elapsed, method=request.method, route=route_path)
            principal = getattr(request.state, "principal", None)
            extra = {"method": request.method, "path": request.url.path, "route": route_path, "status": status,
                     "duration_ms": round(elapsed * 1000, 2)}
            if principal is not None:
                extra.update({"tenant_id": principal.tenant_id, "sub": principal.sub})
            if request.url.path not in ("/healthz", "/readyz", "/metrics"):
                log.info("request", extra=extra)
            if principal is not None and request.method in MUTATING_METHODS:
                await _audit(request, svc, metrics, principal, route_path, status, elapsed)
            request_context.reset(token)
        assert response is not None
        response.headers["X-Request-ID"] = rid
        _security_headers(response, request.url.path)
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(_error_body(request, exc.code, exc.detail, exc.failed), status_code=exc.status,
                            headers=exc.headers)

    @app.exception_handler(ServiceError)
    async def service_error(request: Request, exc: ServiceError) -> JSONResponse:
        if exc.status == 409:
            request.state.refused_checks = exc.failed
        return JSONResponse(_error_body(request, exc.code, exc.detail, exc.failed), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg"), "type": e.get("type")}
                  for e in exc.errors()]
        body = _error_body(request, "invalid", "request validation failed")
        body["errors"] = errors
        return JSONResponse(body, status_code=422)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": AEGIS_VERSION}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        state = svc.ready()
        metrics.ready.set(1 if state["ready"] else 0)
        return JSONResponse(state, status_code=200 if state["ready"] else 503)

    @app.get("/metrics", include_in_schema=False)
    def prometheus(request: Request) -> Response:
        if settings.metrics_token:
            supplied = request.headers.get("authorization", "")
            if not hmac.compare_digest(supplied.encode(), f"Bearer {settings.metrics_token}".encode()):
                return JSONResponse(_error_body(request, "unauthenticated", "metrics token required"),
                                    status_code=401)
        metrics.ready.set(1 if svc.ready()["ready"] else 0)
        return PlainTextResponse(metrics.render(), media_type=CONTENT_TYPE)

    app.include_router(router)
    _mount_console(app, settings.web_dist)
    return app


async def _audit(request: Request, svc: AegisService, metrics: ApiMetrics, principal: Any, route_path: str,
                 status: int, elapsed: float) -> None:
    payload = {
        "request_id": request.state.request_id, "actor": principal.sub,
        "roles": sorted(r.value for r in principal.roles), "method": request.method,
        "path": request.url.path, "route": route_path,
        "path_params": {k: str(v) for k, v in request.path_params.items()},
        "query": {k: v[:200] for k, v in request.query_params.items()},
        "status": status, "outcome": ("ok" if status < 400 else "denied" if status in (401, 403)
                                      else "rate_limited" if status == 429 else "refused" if status == 409
                                      else "error"),
        "body_sha256": getattr(request.state, "body_sha256", None),
        "body_bytes": getattr(request.state, "body_bytes", None),
        "denied_permission": getattr(request.state, "denied_permission", None),
        "failed_checks": getattr(request.state, "refused_checks", None),
        "client": request.client.host if request.client else None,
        "duration_ms": round(elapsed * 1000, 2),
    }
    try:
        await run_in_threadpool(svc.audit, principal.tenant_id, request.state.request_id, payload)
    except Exception:
        metrics.audit_failures.inc()
        log.exception("audit ledger write failed")


def _sweep_loop(svc: AegisService, interval: float, stop: threading.Event) -> None:
    while not stop.wait(interval):
        try:
            changed = svc.sweep_expired()
            if changed:
                log.info("expired actions swept", extra={"cases": changed})
        except Exception:
            log.exception("expiry sweep failed")


def _mount_console(app: FastAPI, web_dist: Path) -> None:
    """Serve the built console with SPA fallback; API paths never fall through to it."""
    root = web_dist.resolve()
    index = root / "index.html"

    @app.get("/{full_path:path}", include_in_schema=False)
    def console(full_path: str, request: Request) -> Response:
        if full_path.startswith("api/") or full_path == "api":
            return JSONResponse(_error_body(request, "not_found", "not found"), status_code=404)
        if not index.is_file():
            if full_path == "":
                return JSONResponse({"service": "AEGIS OMEGA SHIELD", "version": AEGIS_VERSION,
                                     "api": "/api/v1", "docs": "/api/v1/docs",
                                     "console": "not built (run the web build to produce web/dist)"})
            return JSONResponse(_error_body(request, "not_found", "not found"), status_code=404)
        if full_path:
            candidate = (root / full_path).resolve()
            if candidate.is_file() and (candidate == root or root in candidate.parents):
                headers = {"Cache-Control": "public, max-age=31536000, immutable"} \
                    if "/assets/" in f"/{full_path}" else {}
                return FileResponse(candidate, headers=headers)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


__all__ = ["BodySizeLimit", "create_app"]
