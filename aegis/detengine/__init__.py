"""AEGIS detection engineering: AI-assisted, human-approved detection rules.

AI proposes; deterministic code validates, backtests and executes; humans approve.

Public API::

    from aegis.detengine import (
        RuleSpec, parse_rule, evaluate_rule, Contacts,                 # rule language
        validate_rule, RuleValidationError,                            # static checks
        CaseMaterial, RuleDrafter, DeterministicDrafter, LLMDrafter,   # drafting from VERIFIED cases
        BacktestDataset, dataset_from_corpus, load_frozen_lab_dataset, Backtester, BacktestConfig,
        RuleRegistry, RuleState, RulePromotionGate, sign_approval,    # lifecycle
        RuleEngine, ActiveRule,                                        # execution
        DetectionEngineering,                                          # facade
    )

See ``aegis/detengine/INTEGRATION.md`` for the calls the service, API and CLI should make.
"""
from aegis.detengine.backtest import (
    BacktestConfig,
    BacktestDataset,
    BacktestMetrics,
    Backtester,
    FrozenDatasetMismatch,
    OverlapStats,
    RuleBacktestReport,
    alerts_from_findings,
    alerts_from_predicate,
    alerts_from_rules,
    corpus_digest,
    dataset_from_corpus,
    load_frozen_lab_dataset,
)
from aegis.detengine.drafting import (
    CaseMaterial,
    DeterministicDrafter,
    DraftBatch,
    DraftingError,
    DraftProposal,
    LLMDrafter,
    RuleDrafter,
    material_from_case,
    was_verified,
    windows_from_evidence,
)
from aegis.detengine.engine import ActiveRule, EngineResult, RuleEngine, RuleMatch, RuleShadowFinding
from aegis.detengine.language import (
    DETENGINE_VERSION,
    RULE_SCHEMA,
    BaselineSelector,
    Condition,
    Contacts,
    DestinationClause,
    DestinationPattern,
    PeriodicityConstraint,
    RuleEvaluation,
    RuleSpec,
    RuleSpecError,
    evaluate_rule,
    parse_rule,
    spec_sha256,
)
from aegis.detengine.registry import (
    ALLOWED_RULE_TRANSITIONS,
    RuleApproval,
    RuleLifecycleError,
    RulePromotionEvaluation,
    RulePromotionGate,
    RuleRecord,
    RuleRegistry,
    RuleRegistryError,
    RuleShadowReview,
    RuleState,
    sign_approval,
)
from aegis.detengine.validation import RuleValidationError, ValidationLimits, ValidationResult, validate_rule
from aegis.detengine.workbench import DetectionEngineering, DraftOutcome

__all__ = [
    "ALLOWED_RULE_TRANSITIONS", "ActiveRule", "BacktestConfig", "BacktestDataset", "BacktestMetrics", "Backtester",
    "BaselineSelector", "CaseMaterial", "Condition", "Contacts", "DETENGINE_VERSION", "DestinationClause",
    "DestinationPattern", "DetectionEngineering", "DeterministicDrafter", "DraftBatch", "DraftOutcome",
    "DraftProposal", "DraftingError", "EngineResult", "FrozenDatasetMismatch", "LLMDrafter", "OverlapStats",
    "PeriodicityConstraint", "RULE_SCHEMA", "RuleApproval", "RuleBacktestReport", "RuleDrafter", "RuleEngine",
    "RuleEvaluation", "RuleLifecycleError", "RuleMatch", "RulePromotionEvaluation", "RulePromotionGate",
    "RuleRecord", "RuleRegistry", "RuleRegistryError", "RuleShadowFinding", "RuleShadowReview", "RuleSpec",
    "RuleSpecError", "RuleState", "RuleValidationError", "ValidationLimits", "ValidationResult",
    "alerts_from_findings", "alerts_from_predicate", "alerts_from_rules", "corpus_digest", "dataset_from_corpus",
    "evaluate_rule", "load_frozen_lab_dataset", "parse_rule", "sign_approval", "spec_sha256", "validate_rule",
    "material_from_case", "was_verified", "windows_from_evidence",
]
