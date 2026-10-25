"""MIRROR: enforcement impact simulation, authorization and controlled execution (spec 9).

Flow: ``simulate`` -> ``authorize`` -> ``Executor.execute`` (adapter) with a
``CircuitBreaker`` watching legitimate traffic and ``Executor.rollback``
restoring the prior state. Every step fails closed.
"""
from aegis.mirror.adapters import DryRunAdapter
from aegis.mirror.authorize import (
    CHECK_NAMES,
    RESERVED_SCOPE_KEYS,
    authorize,
    requires_human_approval,
    scope_violations,
)
from aegis.mirror.base import (
    AdapterError,
    AdapterResult,
    EnforcementAdapter,
    ExecutionRecord,
    ExecutionStatus,
    InvalidTargetError,
    UnsupportedActionError,
)
from aegis.mirror.breaker import BreakerState, CircuitBreaker
from aegis.mirror.executor import ExecutionError, Executor
from aegis.mirror.history import AggregateTrafficHistory, TrafficHistory
from aegis.mirror.rpz import RPZAdapter, rpz_ip_owner
from aegis.mirror.simulate import TopologyView, simulate
from aegis.mirror.webhook import WebhookAdapter, sign_webhook, verify_webhook_signature

__all__ = [
    "AdapterError", "AdapterResult", "AggregateTrafficHistory", "BreakerState", "CHECK_NAMES",
    "CircuitBreaker", "DryRunAdapter", "EnforcementAdapter", "ExecutionError",
    "ExecutionRecord", "ExecutionStatus", "Executor", "InvalidTargetError",
    "RESERVED_SCOPE_KEYS", "RPZAdapter", "TopologyView", "TrafficHistory",
    "UnsupportedActionError", "WebhookAdapter", "authorize", "requires_human_approval",
    "rpz_ip_owner", "scope_violations", "simulate", "sign_webhook", "verify_webhook_signature",
]
