"""Optional LLM client for ORACLE narrative synthesis.

The LLM is strictly optional: the whole detection and investigation path works
without it (``ANTHROPIC_API_KEY`` unset or the ``anthropic`` package missing).
Every failure — import error, network error, timeout, refusal, empty output —
returns ``None`` so callers fall back to the deterministic analysis.

The client only produces text. It is never given tools that act on the system,
and its output is parsed and validated by :mod:`aegis.oracle.investigation`
before anything is used.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

log = logging.getLogger(__name__)

#: Configured default model id (override with ``AEGIS_LLM_MODEL``).
DEFAULT_LLM_MODEL = "claude-sonnet-5-5"
DEFAULT_TIMEOUT_S = 60.0


@dataclass(frozen=True)
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    model: str


@runtime_checkable
class LLMClient(Protocol):
    """Anything that turns (system, messages) into text, or ``None`` on failure."""

    def complete(self, *, system: str, messages: list[dict[str, str]],
                 max_tokens: int) -> LLMResponse | None: ...


def configured_model() -> str:
    return os.environ.get("AEGIS_LLM_MODEL", "").strip() or DEFAULT_LLM_MODEL


class AnthropicLLM:
    """Thin wrapper over the Anthropic Messages API that never raises."""

    def __init__(self, *, api_key: str | None = None, model: str | None = None,
                 timeout_s: float = DEFAULT_TIMEOUT_S, client: Any | None = None):
        self.model = model or configured_model()
        self._timeout = timeout_s
        self._client = client
        self._api_key = api_key

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import anthropic  # optional dependency (extra "llm")
        except ImportError:
            log.info("anthropic package not installed; LLM disabled")
            return None
        key = self._api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return None
        try:
            self._client = anthropic.Anthropic(api_key=key, timeout=self._timeout, max_retries=0)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("could not construct Anthropic client: %s", type(exc).__name__)
            return None
        return self._client

    def complete(self, *, system: str, messages: list[dict[str, str]],
                 max_tokens: int) -> LLMResponse | None:
        client = self._get_client()
        if client is None:
            return None
        try:
            resp = client.messages.create(model=self.model, max_tokens=max_tokens,
                                          system=system, messages=messages)
            parts = [getattr(b, "text", "") for b in getattr(resp, "content", []) or []
                     if getattr(b, "type", "text") == "text"]
            text = "".join(p for p in parts if isinstance(p, str)).strip()
            if not text:
                return None
            usage = getattr(resp, "usage", None)
            return LLMResponse(
                text=text,
                input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                model=str(getattr(resp, "model", self.model) or self.model))
        except Exception as exc:
            # never log content: it may include case details
            log.warning("LLM call failed (%s); using deterministic fallback", type(exc).__name__)
            return None


def llm_from_env() -> AnthropicLLM | None:
    """An :class:`AnthropicLLM` if ``ANTHROPIC_API_KEY`` is set and the SDK imports, else None."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return None
    return AnthropicLLM()
