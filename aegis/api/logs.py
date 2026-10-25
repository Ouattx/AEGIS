"""Structured JSON logging. One JSON object per line on stderr.

Request context (request id, tenant, subject) is attached through a context
variable so every log line emitted while serving a request carries it. Tokens,
secrets and request bodies are never logged.
"""
from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

request_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "aegis_request_context", default=None)

_RESERVED = set(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        ctx = request_context.get()
        if ctx:
            out.update({k: v for k, v in ctx.items() if v is not None})
        for k, v in vars(record).items():
            if k not in _RESERVED and not k.startswith("_"):
                out[k] = v
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str, separators=(",", ":"))


class _ContextTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        ctx = request_context.get()
        if ctx and ctx.get("request_id"):
            return f"{base} [request_id={ctx['request_id']}]"
        return base


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Install one stderr handler on the root logger (idempotent)."""
    root = logging.getLogger()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else
                         _ContextTextFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler._aegis = True  # type: ignore[attr-defined]
    for h in list(root.handlers):
        if getattr(h, "_aegis", False):
            root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(level.upper())
    for noisy in ("uvicorn.access", "httpx", "httpx2", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


__all__ = ["JsonFormatter", "configure_logging", "request_context"]
