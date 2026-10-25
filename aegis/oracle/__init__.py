"""ORACLE: case state machine and bounded AI investigation (spec section 6)."""
from aegis.oracle.investigation import (
    Budget,
    Hypothesis,
    InvestigationReport,
    Investigator,
    VerificationRecommendation,
)
from aegis.oracle.llm import DEFAULT_LLM_MODEL, AnthropicLLM, LLMClient, LLMResponse, llm_from_env
from aegis.oracle.state_machine import (
    ALLOWED_TRANSITIONS,
    SIGNED_IOC_FLAG,
    CaseService,
    EvidenceAssessment,
    GuardError,
)
from aegis.oracle.tools import (
    AgentName,
    IntelConnector,
    ReadTool,
    ScopeViolation,
    StaticIntelConnector,
    Toolset,
    build_default_toolset,
    wrap_untrusted,
)

__all__ = [
    "ALLOWED_TRANSITIONS", "AgentName", "AnthropicLLM", "Budget", "CaseService",
    "DEFAULT_LLM_MODEL", "EvidenceAssessment", "GuardError", "Hypothesis", "IntelConnector",
    "InvestigationReport", "Investigator", "LLMClient", "LLMResponse", "ReadTool",
    "SIGNED_IOC_FLAG", "ScopeViolation", "StaticIntelConnector", "Toolset",
    "VerificationRecommendation", "build_default_toolset", "llm_from_env", "wrap_untrusted",
]
