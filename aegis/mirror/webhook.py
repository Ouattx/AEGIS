"""Signed webhook adapter for operator-side enforcement systems.

Delivers ``apply`` / ``revert`` requests as JSON to an operator endpoint (walled
garden controller, firewall orchestrator, SOAR). Each request is authenticated
with HMAC-SHA256 over ``"<unix timestamp>." + body`` using a per-endpoint shared
secret::

    X-Aegis-Timestamp: 1767225600
    X-Aegis-Delivery:  <uuid>             (stable across retries: idempotency key)
    X-Aegis-Signature: v1=<hex digest>

Receivers verify with :func:`verify_webhook_signature`, which also rejects
timestamps outside a tolerance window (replay protection).

Retries: transport errors, 408, 429 and 5xx are retried with exponential backoff
using the same delivery id; other 4xx responses fail immediately. The receiver
may return ``{"prior_state": {...}}``; it is handed back on ``revert``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import ActionType, ProposedAction, new_id
from aegis.mirror.base import (
    AdapterError,
    AdapterResult,
    EnforcementAdapter,
    action_summary,
    normalized_targets,
)

SIGNATURE_HEADER = "X-Aegis-Signature"
TIMESTAMP_HEADER = "X-Aegis-Timestamp"
DELIVERY_HEADER = "X-Aegis-Delivery"
EVENT_HEADER = "X-Aegis-Event"
MIN_SECRET_BYTES = 32
_RETRY_STATUS = frozenset({408, 429})


def sign_webhook(secret: bytes, timestamp: int, body: bytes) -> str:
    """Signature header value for ``body`` sent at ``timestamp``."""
    mac = hmac.new(secret, f"{timestamp}.".encode("ascii") + body, hashlib.sha256)
    return "v1=" + mac.hexdigest()


def verify_webhook_signature(secret: bytes, timestamp: str | int, body: bytes, signature: str,
                             *, now: float | None = None, tolerance_s: int = 300) -> bool:
    """Receiver-side check: constant-time HMAC compare plus timestamp freshness."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > tolerance_s:
        return False
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(sign_webhook(secret, ts, body), signature.strip())


class WebhookAdapter(EnforcementAdapter):
    """POSTs HMAC-signed enforcement requests to an operator endpoint."""

    name = "webhook"
    dry_run = False
    supported_actions = frozenset(ActionType)

    def __init__(self, url: str, secret: bytes, *, client: httpx.Client | None = None,
                 timeout_s: float = 10.0, max_attempts: int = 3, backoff_s: float = 0.5,
                 allow_insecure_http: bool = False,
                 supported_actions: frozenset[ActionType] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        parsed = urlparse(url)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            raise ValueError("webhook url must be an absolute http(s) URL")
        if parsed.scheme == "http" and not allow_insecure_http:
            raise ValueError("webhook url must use https (set allow_insecure_http for lab use)")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_SECRET_BYTES:
            raise ValueError(f"webhook secret must be at least {MIN_SECRET_BYTES} bytes")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.url = url
        self._secret = bytes(secret)
        self._client = client or httpx.Client(timeout=timeout_s)
        self._timeout = timeout_s
        self.max_attempts = max_attempts
        self.backoff_s = backoff_s
        self._sleep = sleep
        if supported_actions is not None:
            self.supported_actions = frozenset(supported_actions)

    def __repr__(self) -> str:  # never leak the secret
        return f"WebhookAdapter(url={self.url!r})"

    def apply(self, action: ProposedAction, *, now: datetime) -> AdapterResult:
        self.check_supported(action)
        normalized_targets(action)  # validate before anything leaves the process
        reply, delivery = self._deliver("apply", action, now, None)
        prior = reply.get("prior_state") if isinstance(reply.get("prior_state"), dict) else {}
        return AdapterResult(adapter=self.name, operation="apply",
                             prior_state={"remote": prior, "apply_delivery_id": delivery},
                             details={"delivery_id": delivery, "response": reply})

    def revert(self, action: ProposedAction, prior_state: dict[str, Any], *,
               now: datetime) -> AdapterResult:
        reply, delivery = self._deliver("revert", action, now, prior_state)
        return AdapterResult(adapter=self.name, operation="revert",
                             details={"delivery_id": delivery, "response": reply})

    # ------------------------------------------------------------------ internals
    def _deliver(self, operation: str, action: ProposedAction, now: datetime,
                 prior_state: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
        delivery = new_id()
        sent_at = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        doc: dict[str, Any] = {
            "event": f"aegis.enforcement.{operation}",
            "delivery_id": delivery,
            "sent_at": sent_at.isoformat(),
            "tenant_id": action.tenant_id,
            "action": action_summary(action),
        }
        if prior_state is not None:
            doc["prior_state"] = prior_state
        body = canonical_bytes(doc)
        last_error = "no attempt made"
        for attempt in range(1, self.max_attempts + 1):
            ts = int(time.time())
            headers = {
                "Content-Type": "application/json",
                TIMESTAMP_HEADER: str(ts),
                DELIVERY_HEADER: delivery,
                EVENT_HEADER: doc["event"],
                SIGNATURE_HEADER: sign_webhook(self._secret, ts, body),
            }
            try:
                resp = self._client.post(self.url, content=body, headers=headers,
                                         timeout=self._timeout)
            except httpx.HTTPError as exc:
                last_error = f"transport error: {type(exc).__name__}"
            else:
                if 200 <= resp.status_code < 300:
                    return self._parse(resp), delivery
                last_error = f"HTTP {resp.status_code}"
                if resp.status_code < 500 and resp.status_code not in _RETRY_STATUS:
                    raise AdapterError(f"webhook {operation} rejected: {last_error}")
            if attempt < self.max_attempts:
                self._sleep(self.backoff_s * (2 ** (attempt - 1)))
        raise AdapterError(f"webhook {operation} failed after {self.max_attempts} "
                           f"attempt(s): {last_error}")

    @staticmethod
    def _parse(resp: httpx.Response) -> dict[str, Any]:
        if not resp.content:
            return {}
        try:
            data = json.loads(resp.content)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
