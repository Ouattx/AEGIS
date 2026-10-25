"""GENOME data model: versioned, content-hashed, signed behavioral fingerprints.

A genome summarizes the *network metadata timing behavior* of one family as observed
on isolated lab devices: timer period and jitter, beacon burst and size rhythm, DNS
cadence and name statistics, destination-infrastructure churn. It carries no payloads
and no executable content. It is signed with :mod:`aegis.provenance.signing` and is
ignored (fail closed) when unsigned, tampered, signed by an untrusted key, or expired.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis.contracts.canonical import sha256_hex

GENOME_SCHEMA = "aegis.genome/1"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimerModel(_M):
    """Renewal-timer model of the beacon: interval = period * (1 + u)."""
    period_s: float
    secondary_periods_s: list[float] = Field(default_factory=list)
    jitter_family: Literal["uniform", "normal", "empirical"] = "uniform"
    jitter_scale: float                       # half-width (uniform) or sd (normal), as a fraction of period
    jitter_quantiles: list[float] = Field(default_factory=list)   # empirical u quantiles at 5..95 %
    n_intervals: int


class BurstModel(_M):
    """Per-beacon structure: flows per check-in and size rhythm (bytes per flow)."""
    flows_per_beacon_mean: float
    bytes_log_mean: float | None               # mean of log(bytes); None = sizes unknown
    bytes_log_sd: float | None
    bytes_quantiles: list[float] = Field(default_factory=list)


class DnsModel(_M):
    lookups_per_beacon: float                  # 1 = every check-in resolves; ~0 = cached / hard-coded IPs
    distinct_names: int
    rotation_s: float | None                   # median dwell time on one name before switching
    name_entropy_mean: float | None            # Shannon entropy per character of the leftmost label
    name_bigram_novelty: float | None          # share of label bigrams absent from a common-word bigram set
    name_length_mean: float | None
    resolver_count: int | None = None


class InfraModel(_M):
    distinct_ips: int
    distinct_prefix24: int
    distinct_asns: int | None
    ip_churn_per_day: float                    # new IPs per day of capture
    prefix24_churn_per_day: float


class ActivityModel(_M):
    """Background fetches and idle/active differences (lab boxes are driven idle and active)."""
    update_fetch_period_s: float | None        # large transfers cadence (firmware/config fetch)
    idle_period_s: float | None
    active_period_s: float | None
    idle_active_ratio: float | None            # active / idle period; None when one phase missing


class GenomeProvenance(_M):
    capture_ids: list[str]
    lab_box_models: list[str]                  # box model labels, lab metadata only
    firmware: list[str] = Field(default_factory=list)
    lab_id: str = "boxfarm-lab"
    licence: str = "operator-internal"
    capture_start: datetime
    capture_end: datetime
    n_events: int
    extractor_version: str


class Genome(_M):
    schema_: Literal["aegis.genome/1"] = Field(GENOME_SCHEMA, alias="schema")
    genome_id: str = ""                        # "gn-" + content hash prefix (set by seal)
    family: str | None                         # None = unlabeled lab capture
    version: int = 1
    timer: TimerModel
    dns_timer: TimerModel | None = None        # timer of resolver lookups alone (the channel that survives
                                               # heavy NetFlow sampling); differs from ``timer`` under caching
    burst: BurstModel
    dns: DnsModel
    infra: InfraModel
    activity: ActivityModel
    c2_keys: list[str] = Field(default_factory=list)       # destination keys observed in the lab (d:/ip:)
    provenance: GenomeProvenance
    confidence: float                          # extraction quality in [0, 1] (not a probability of maliciousness)
    created_at: datetime
    expires_at: datetime
    content_sha256: str = ""
    signer_key_id: str | None = None
    signature: str | None = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    def content_body(self) -> dict[str, Any]:
        d = self.model_dump(mode="json", by_alias=True)
        for k in ("genome_id", "content_sha256", "signer_key_id", "signature"):
            d.pop(k, None)
        return d

    def compute_hash(self) -> str:
        return sha256_hex(self.content_body())

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at <= now


class GenomeScore(_M):
    """Matched-filter statistic for one (line, destination) series against one genome."""
    line: str
    key: str
    genome_id: str
    family: str | None
    n_events: int
    llr: float                                 # timer+size log-likelihood ratio vs the renewal-free null
    timer_llr: float
    size_llr: float


class GenomeCampaign(_M):
    genome_id: str
    family: str | None
    destinations: list[str]
    member_lines: list[str]
    n_lines: int
    statistic: float
    p_value: float
    q_value: float
    q_target: float
    n_permutations: int
    attribution: dict[str, float]              # family -> share of evidence (sums to 1 over tested genomes)
    attribution_confidence: float
    evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: str


class DeviceModelHypothesis(_M):
    """Ranked hypothesis only: never asserted from device class or model alone."""
    line: str
    ranked: list[dict[str, Any]]               # [{"box_model", "score", "evidence": [...]}]
    basis: Literal["behavioral_match"] = "behavioral_match"
    note: str = ("hypothesis ranked from behavioral genome match; device model is never inferred "
                 "from device class, vendor or IPTV usage alone")


class GenomeAbstention(_M):
    genome_id: str
    destinations: list[str]
    reason: str


class GenomeReport(_M):
    tenant_id: str
    detector_version: str
    status: Literal["ok", "abstain"]
    abstain_reason: str | None = None
    n_genomes_loaded: int
    n_genomes_ignored: dict[str, int] = Field(default_factory=dict)   # reason -> count (expired, unverified...)
    n_tested: int
    campaigns: list[GenomeCampaign] = Field(default_factory=list)
    device_hypotheses: list[DeviceModelHypothesis] = Field(default_factory=list)
    abstentions: list[GenomeAbstention] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
