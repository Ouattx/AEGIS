"""EGRESS input side-channel and output models (module-local; shared contracts stay in aegis.contracts)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


SignalKind = Literal[
    "flood", "sync_burst", "spoofing", "amplification_request", "abused_reflector",
    "proxy_relay", "spam", "credential_stuffing", "auth_fanout",
]


class SpoofSignal(_M):
    """Anti-spoofing counters for one line over one interval (optional input).

    Flow records never carry the subscriber source address (ingest drops it), and a
    spoofed packet cannot be attributed to a line from its source address anyway. The only
    trustworthy attribution is at the subscriber-facing interface: BNG / CMTS / OLT uRPF
    (BCP 38 / BCP 84) drop counters, or CPE agent counters of packets whose source lies
    outside the line's assigned prefix. The integrator feeds those here, keyed by the same
    line pseudonym the flow events use.
    """
    tenant_id: str
    entity_pseudonym: str
    interval_start: datetime
    interval_end: datetime
    packets_outside_prefix: int = Field(ge=0)
    packets_total: int | None = Field(default=None, ge=0)   # None = denominator not exported
    source: str = "urpf"                                    # e.g. "urpf:bng-par1", "cpe-agent"

    @field_validator("interval_start", "interval_end")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware")
        return v


class LineSignal(_M):
    """One behavioral signal observed on one line (raw input to the verdict policy)."""
    entity_pseudonym: str
    kind: SignalKind
    label: str
    strong: bool
    start: datetime
    end: datetime
    targets: list[str] = Field(default_factory=list)       # external destination IPs / prefixes
    metrics: dict[str, Any] = Field(default_factory=dict)
    summary: str


class EgressCampaign(_M):
    """Cross-line correlation: several unrelated lines doing the same thing at the same time."""
    campaign_id: str
    tenant_id: str
    label: str
    kind: Literal["sync_burst", "shared_sink", "shared_target", "shared_reflector_port", "shared_mx_set"]
    member_lines: list[str]
    n_lines: int
    targets: list[str]
    start: datetime
    end: datetime
    metrics: dict[str, Any] = Field(default_factory=dict)
    explanation: str


class Abstention(_M):
    """A candidate the detector could not judge: the data needed to decide is missing."""
    entity_pseudonym: str
    label: str
    reason: str
    detail: dict[str, Any] = Field(default_factory=dict)


class LineVerdict(_M):
    """Final per-line, per-label decision (what becomes a Finding)."""
    entity_pseudonym: str
    device_class: str
    label: str
    verdict: Literal["malicious", "suspicious", "abstain"]
    score: float                                            # ranking in [0, 1]; not a probability
    signals: list[LineSignal] = Field(default_factory=list)
    campaign_ids: list[str] = Field(default_factory=list)
    corroboration: list[str] = Field(default_factory=list)
    alternatives: list[str] = Field(default_factory=list)  # benign explanations a reviewer must rule out
    counter_facts: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    start: datetime
    end: datetime


class EgressReport(_M):
    tenant_id: str
    detector_version: str
    config_hash: str
    window_start: datetime
    window_end: datetime
    status: Literal["ok", "abstain"]
    abstain_reason: str | None = None
    verdicts: list[LineVerdict] = Field(default_factory=list)
    campaigns: list[EgressCampaign] = Field(default_factory=list)
    abstentions: list[Abstention] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)

    def flagged_lines(self, label: str | None = None) -> set[str]:
        """Lines with a MALICIOUS or SUSPICIOUS verdict (optionally for one label)."""
        return {v.entity_pseudonym for v in self.verdicts
                if v.verdict != "abstain" and (label is None or v.label == label)}
