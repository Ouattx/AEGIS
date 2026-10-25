"""Tool-use LLM port for the Copilot, and its Anthropic Messages API adapter.

The Copilot drives a manual tool-use loop (it owns budgets, tool validation and the
untrusted-data wrapping), so the port is one call: ``(system, messages, tools) ->``
:class:`LLMTurn`. Any failure returns ``None`` and the engine answers with the
deterministic fallback. The adapter never logs prompt or response content.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from aegis.oracle.llm import configured_model

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 45.0


@dataclass(frozen=True)
class ToolUse:
    id: str
    name: str
    input: Any


@dataclass
class LLMTurn:
    """One model response, normalized.

    ``raw_content`` is appended back to the conversation unchanged (it may hold
    thinking blocks that must be passed back as they came).
    """
    raw_content: list[Any]
    text: str
    tool_uses: list[ToolUse] = field(default_factory=list)
    stop_reason: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""

    @classmethod
    def from_blocks(cls, blocks: list[Any], *, stop_reason: str | None = None, input_tokens: int = 0,
                    output_tokens: int = 0, model: str = "") -> "LLMTurn":
        """Build from SDK content blocks or plain dicts (``{"type": "text"|"tool_use", ...}``)."""
        texts: list[str] = []
        uses: list[ToolUse] = []
        for b in blocks:
            btype = _get(b, "type")
            if btype == "text":
                t = _get(b, "text")
                if isinstance(t, str):
                    texts.append(t)
            elif btype == "tool_use":
                uses.append(ToolUse(id=str(_get(b, "id") or ""), name=str(_get(b, "name") or ""),
                                    input=_get(b, "input")))
        return cls(raw_content=list(blocks), text="".join(texts).strip(), tool_uses=uses, stop_reason=stop_reason,
                   input_tokens=int(input_tokens or 0), output_tokens=int(output_tokens or 0), model=model)


def _get(block: Any, key: str) -> Any:
    if isinstance(block, dict):
        return block.get(key)
    return getattr(block, key, None)


@runtime_checkable
class ToolLLM(Protocol):
    model: str

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout_s: float) -> LLMTurn | None: ...


class AnthropicToolLLM:
    """Anthropic Messages API with client-side tools. Never raises; ``None`` on any failure.

    Model: ``AEGIS_LLM_MODEL`` (default ``claude-sonnet-5-5``). Thinking is left at the
    model default; ``effort`` is sent only when configured (older models reject it).
    """

    def __init__(self, *, api_key: str | None = None, model: str | None = None, client: Any | None = None,
                 timeout_s: float = DEFAULT_TIMEOUT_S, effort: str | None = None, cache_prompt: bool = True):
        self.model = model or configured_model()
        self._api_key = api_key
        self._client = client
        self._timeout = timeout_s
        self._effort = effort
        self._cache = cache_prompt

    def _get_client(self) -> Any | None:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError:
            log.info("anthropic package not installed; copilot uses its deterministic mode")
            return None
        key = self._api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return None
        try:
            self._client = anthropic.Anthropic(api_key=key, timeout=self._timeout, max_retries=1)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("could not construct Anthropic client: %s", type(exc).__name__)
            return None
        return self._client

    def create(self, *, system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
               max_tokens: int, timeout_s: float) -> LLMTurn | None:
        client = self._get_client()
        if client is None:
            return None
        kwargs: dict[str, Any] = {"model": self.model, "max_tokens": max_tokens, "system": system,
                                  "messages": messages, "tools": tools, "tool_choice": {"type": "auto"},
                                  "timeout": max(1.0, min(timeout_s, self._timeout))}
        if self._effort:
            kwargs["output_config"] = {"effort": self._effort}
        if self._cache:
            kwargs["cache_control"] = {"type": "ephemeral"}
        try:
            try:
                resp = client.messages.create(**kwargs)
            except TypeError:
                # older SDKs (pyproject allows anthropic>=0.40) lack these optional keywords
                for optional in ("cache_control", "output_config"):
                    kwargs.pop(optional, None)
                resp = client.messages.create(**kwargs)
        except Exception as exc:
            log.warning("copilot LLM call failed (%s); deterministic fallback", type(exc).__name__)
            return None
        usage = getattr(resp, "usage", None)
        return LLMTurn.from_blocks(list(getattr(resp, "content", None) or []),
                                   stop_reason=getattr(resp, "stop_reason", None),
                                   input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                                   output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                                   model=str(getattr(resp, "model", self.model) or self.model))


def copilot_llm_from_env() -> AnthropicToolLLM | None:
    """An adapter when ``ANTHROPIC_API_KEY`` is set and the SDK imports; otherwise ``None``."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return None
    return AnthropicToolLLM()
