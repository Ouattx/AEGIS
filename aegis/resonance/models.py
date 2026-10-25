"""Output models of RESONANCE (module-local; shared contracts stay in aegis.contracts)."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LineSupport(_M):
    """One member line's own timer evidence for the campaign."""
    line: str
    n_events: int
    raw_events: int
    first_contact: datetime
    period_s: float | None            # line's own strongest period (None = not estimable)
    strength: float | None            # signed difference-fold concentration R (1 = perfect timer)
    z_at_campaign_period: float | None
    p_nominal: float | None           # per-line nominal (uncalibrated) cosine-fold p-value
    persistence: float                # around-the-clock activity ratio in [0, 1]
    supports: bool                    # z_at_campaign_period >= support_z (or own-period z for free stat)


class Campaign(_M):
    campaign_id: str
    tenant_id: str
    detector_version: str
    config_hash: str
    destinations: list[str]           # destination keys ("d:<domain>" / "ip:<addr>")
    destination_ips: list[str]
    asns: list[int] = Field(default_factory=list)
    shared_hosting_domain: bool = False   # True => enforce on the domain only, never on the IPs
    topology_unknown: bool = False        # True => not enforcement-eligible (fail closed)
    enforcement_eligible: bool = False
    member_lines: list[str]
    supporting_lines: list[str]
    n_lines: int
    popularity: float
    destination_age_days: float | None
    statistic: Literal["period_lock", "free_periodicity"]
    period_s: float | None
    period_agreement: float | None    # fraction of member lines whose own period is within 10 % of period_s
    resonance_statistic: float        # (observed - null mean) / null sd of the winning statistic
    null_mean: float
    null_sd: float
    p_value: float
    p_lock: float
    p_free: float
    p_method: str                     # "empirical" | "sequential" | "gpd_tail"
    n_permutations: int
    weight: float
    weight_parts: dict[str, float] = Field(default_factory=dict)
    q_value: float
    q_target: float
    phase_locking: float | None = None    # cross-line absolute-phase PLV at period_s
    phase_locking_p: float | None = None
    onset_at: datetime | None = None
    onset_sync: float | None = None       # fraction of non-censored lines starting within +-1 h of the median onset
    window_start: datetime
    window_end: datetime
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    lines: list[LineSupport] = Field(default_factory=list)


class TestedUnit(_M):
    unit_id: str
    destinations: list[str]
    n_lines: int
    popularity: float
    weight: float
    p_value: float
    p_lock: float
    p_free: float
    q_value: float
    period_s: float | None
    rejected: bool


class Abstention(_M):
    unit_id: str
    destinations: list[str]
    n_lines: int
    reason: str


class ResonanceReport(_M):
    tenant_id: str
    detector_version: str
    config_hash: str
    status: Literal["ok", "abstain"]
    abstain_reason: str | None = None
    window_start: datetime
    window_end: datetime
    active_lines: int
    n_events: int
    n_series: int
    n_tested: int
    n_ineligible: int
    ineligible_reasons: dict[str, int] = Field(default_factory=dict)
    campaigns: list[Campaign] = Field(default_factory=list)
    tested: list[TestedUnit] = Field(default_factory=list)
    abstentions: list[Abstention] = Field(default_factory=list)
    timings_s: dict[str, float] = Field(default_factory=dict)
