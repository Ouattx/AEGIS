"""Request bodies (strict: unknown fields are rejected) and the pagination envelope."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.contracts.models import ActionType, CaseState, SourceKind, Vantage

T = TypeVar("T")


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PageOut(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class SourceIn(_In):
    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    source_kind: SourceKind
    vantage: Vantage
    collection_authorization_id: str = Field(min_length=1, max_length=256)
    retention_days: int = Field(default=30, ge=1, le=3650)
    format: str | None = Field(default=None, max_length=64)
    entity_field: Literal["auto", "device_id", "src_ip"] = "auto"
    assume_utc_for_naive: bool = False
    subscriber_prefixes: list[str] = Field(default_factory=list, max_length=4096)
    flow_direction: Literal["auto", "biflow", "uniflow"] = "auto"


class EventsIn(_In):
    events: list[Any] = Field(min_length=1, max_length=50_000)  # per-item problems are reported, not fatal
    flush: bool = False


class TransitionIn(_In):
    to_state: CaseState
    reason: str = Field(min_length=1, max_length=2000)


class ReviewIn(_In):
    alternatives: list[str] = Field(min_length=1, max_length=20)
    notes: str = Field(min_length=1, max_length=4000)

    @field_validator("alternatives")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        out = [a.strip() for a in v if isinstance(a, str) and a.strip()]
        if not out:
            raise ValueError("at least one non-empty alternative is required")
        if any(len(a) > 500 for a in out):
            raise ValueError("alternatives are limited to 500 characters")
        return out


class NoteIn(_In):
    note: str = Field(min_length=1, max_length=8000)


class ProposeIn(_In):
    case_id: str = Field(min_length=1, max_length=64)
    action_type: ActionType
    targets: list[str] = Field(min_length=1, max_length=1000)
    scope: dict[str, Any] = Field(default_factory=dict)
    legal_basis: str | None = Field(default=None, max_length=256)
    expires_at: datetime | None = None
    expires_in_hours: float | None = Field(default=None, gt=0, le=24 * 365)
    rollback_plan: str | None = Field(default=None, max_length=4000)
    rollback_verified: bool = False

    @model_validator(mode="after")
    def _one_expiry(self) -> "ProposeIn":
        if self.expires_at is not None and self.expires_in_hours is not None:
            raise ValueError("give expires_at or expires_in_hours, not both")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a UTC offset")
        return self


class AuthorizeIn(_In):
    policy_id: str | None = Field(default=None, max_length=128)


class DecisionIn(_In):
    reason: str = Field(min_length=1, max_length=2000)


class ExecuteIn(_In):
    reason: str = Field(default="", max_length=2000)


__all__ = ["AuthorizeIn", "DecisionIn", "EventsIn", "ExecuteIn", "NoteIn", "PageOut", "ProposeIn", "ReviewIn",
           "SourceIn", "TransitionIn"]


class HealthIn(_In):
    """Legitimate-traffic health sample for a live action (resolver / NOC telemetry)."""
    requests: int = Field(ge=0, le=10_000_000_000)
    errors: int = Field(ge=0, le=10_000_000_000)

    @model_validator(mode="after")
    def _bounded(self) -> "HealthIn":
        if self.errors > self.requests:
            raise ValueError("errors cannot exceed requests")
        return self


class BreakerResetIn(_In):
    reason: str = Field(min_length=1, max_length=2000)


class ReportInputsIn(_In):
    """PoV report inputs; keys are validated against ``CostInputs`` / ``AnalystEffortModel``."""
    cost: dict[str, Any] = Field(default_factory=dict)
    effort: dict[str, Any] = Field(default_factory=dict)


class TokenGrantIn(_In):
    """Console OIDC grant relayed to the IdP token endpoint."""
    grant_type: Literal["authorization_code", "refresh_token"]
    code: str | None = Field(default=None, max_length=4096)
    code_verifier: str | None = Field(default=None, min_length=43, max_length=128,
                                      pattern=r"^[A-Za-z0-9._~-]+$")
    redirect_uri: str | None = Field(default=None, max_length=2048)
    refresh_token: str | None = Field(default=None, max_length=16384)
