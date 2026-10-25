"""AEGIS Copilot: read-only, cited, tenant-scoped analyst assistant (English / French).

Public API::

    from aegis.copilot import Copilot, ServiceDataSource, AnthropicToolLLM, copilot_llm_from_env

    copilot = Copilot(ServiceDataSource(service), llm=copilot_llm_from_env())   # llm=None: deterministic
    answer = copilot.ask(tenant_id=t, user_id=sub, session_id=sid, question="Why did ingestion slow down?")
    for event in copilot.ask_stream(tenant_id=t, user_id=sub, session_id=sid, question=q):
        ...   # start / tool_call / tool_result / notice / sentence / final

See aegis/copilot/INTEGRATION.md for service, API and console wiring.
"""
from aegis.copilot.citations import CitationValidator, parse_citations, split_segments
from aegis.copilot.datasource import (
    COPILOT_AUDIT_ENTRY,
    CopilotDataSource,
    DataSourceError,
    InvalidQuery,
    ServiceDataSource,
)
from aegis.copilot.engine import Copilot, CopilotForbidden, CopilotInputError
from aegis.copilot.fallback import classify, detect_language
from aegis.copilot.llm import AnthropicToolLLM, LLMTurn, ToolLLM, ToolUse, copilot_llm_from_env
from aegis.copilot.memory import ConversationSession, SessionStore
from aegis.copilot.models import (
    AnswerSentence,
    BudgetUsage,
    Citation,
    CopilotAnswer,
    CopilotBudget,
    CopilotEvent,
    ToolCallTrace,
)
from aegis.copilot.prompt import SYSTEM_PROMPT
from aegis.copilot.tools import DEFAULT_TOOLS, CopilotTool, ToolContext, ToolOutput

__all__ = [
    "AnswerSentence", "AnthropicToolLLM", "BudgetUsage", "COPILOT_AUDIT_ENTRY", "Citation", "CitationValidator",
    "ConversationSession", "Copilot", "CopilotAnswer", "CopilotBudget", "CopilotDataSource", "CopilotEvent",
    "CopilotForbidden", "CopilotInputError", "CopilotTool", "DEFAULT_TOOLS", "DataSourceError", "InvalidQuery", "LLMTurn",
    "SYSTEM_PROMPT", "ServiceDataSource", "SessionStore", "ToolCallTrace", "ToolContext", "ToolLLM", "ToolOutput",
    "ToolUse", "classify", "copilot_llm_from_env", "detect_language", "parse_citations", "split_segments",
]
