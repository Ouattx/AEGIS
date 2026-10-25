"""Typed values exchanged by AEGIS Copilot (module-local; shared contracts stay in aegis.contracts)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

#: Kinds of ids an answer sentence may cite, written ``[kind:id]``.
#: Entity kinds are resolved against the tenant's stores; ``query``/``metrics``/``health``
#: refs name a tool result produced in the same session (aggregate or negative facts).
CitationKind = Literal["finding", "case", "evidence", "campaign", "action", "ledger", "node",
                       "query", "metrics", "health"]
ENTITY_KINDS: frozenset[str] = frozenset({"finding", "case", "evidence", "campaign", "action", "ledger", "node"})
RESULT_KINDS: frozenset[str] = frozenset({"query", "metrics", "health"})
ALL_KINDS: frozenset[str] = ENTITY_KINDS | RESULT_KINDS

Language = Literal["en", "fr"]
AnswerMode = Literal["llm", "fallback"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CopilotBudget(_M):
    """Hard bounds for one question. Exhaustion degrades the answer, it never raises."""
    max_tool_calls: int = Field(default=8, ge=1, le=24)
    max_llm_calls: int = Field(default=6, ge=1, le=12)
    max_output_tokens: int = Field(default=2_000, ge=64, le=16_000)
    max_total_tokens: int = Field(default=80_000, ge=1_000, le=1_000_000)
    deadline_s: float = Field(default=60.0, gt=0, le=600)
    max_question_chars: int = Field(default=2_000, ge=16, le=20_000)


class Citation(_M):
    kind: CitationKind
    id: str

    @property
    def ref(self) -> str:
        return f"{self.kind}:{self.id}"


class AnswerSentence(_M):
    text: str                                   # sentence text with citation markers removed
    citations: list[Citation] = Field(default_factory=list)
    status: Literal["cited", "exempt", "flagged"] = "cited"


class ToolCallTrace(_M):
    call_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    error: str | None = None                    # our own message, never echoed tool data
    rejected: Literal["unknown_tool", "not_permitted", "invalid_args", "budget", "deadline"] | None = None
    refs: list[str] = Field(default_factory=list)   # "kind:id" refs the result exposed
    injection_patterns: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0


class BudgetUsage(_M):
    tool_calls: int = 0
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_s: float = 0.0
    exhausted: list[str] = Field(default_factory=list)


class CopilotAnswer(_M):
    answer_id: str
    tenant_id: str
    session_id: str
    language: Language
    mode: AnswerMode
    model: str | None = None
    fallback_reason: str | None = None
    intent: str | None = None                   # deterministic intent (fallback mode)
    sentences: list[AnswerSentence] = Field(default_factory=list)
    removed_claims: list[str] = Field(default_factory=list)      # uncited sentences stripped
    invalid_citations: list[str] = Field(default_factory=list)   # refs that failed validation
    tool_calls: list[ToolCallTrace] = Field(default_factory=list)
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    question_sha256: str
    audit_seq: int | None = None
    created_at: datetime

    @property
    def text(self) -> str:
        """Plain answer with citation markers re-attached (``[kind:id]`` after each sentence)."""
        return render_sentences(self.sentences)

    @property
    def cited_refs(self) -> list[str]:
        seen: dict[str, None] = {}
        for s in self.sentences:
            for c in s.citations:
                seen.setdefault(c.ref, None)
        return list(seen)


def render_sentences(sentences: list[AnswerSentence]) -> str:
    parts: list[str] = []
    for s in sentences:
        marks = "".join(f"[{c.ref}]" for c in s.citations)
        flag = " [uncited]" if s.status == "flagged" else ""
        parts.append(f"{s.text}{(' ' + marks) if marks else ''}{flag}".strip())
    return "\n".join(p for p in parts if p)


class CopilotEvent(_M):
    """One streaming event. ``type`` decides which fields are set.

    * ``start``       -- question accepted (``language``)
    * ``tool_call``   -- a tool is about to run (``tool``, ``call_id``, ``args``)
    * ``tool_result`` -- a tool finished (``trace``)
    * ``notice``      -- budget exhausted, injection detected, fallback engaged ... (``message``, ``code``)
    * ``sentence``    -- one validated answer sentence (``sentence``)
    * ``final``       -- the complete :class:`CopilotAnswer` (``answer``); always the last event
    """
    type: Literal["start", "tool_call", "tool_result", "notice", "sentence", "final"]
    language: Language | None = None
    tool: str | None = None
    call_id: str | None = None
    args: dict[str, Any] | None = None
    trace: ToolCallTrace | None = None
    code: str | None = None
    message: str | None = None
    sentence: AnswerSentence | None = None
    answer: CopilotAnswer | None = None
