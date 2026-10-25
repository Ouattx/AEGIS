"""RESONANCE configuration (pre-registered operator parameters).

Every threshold that influences a decision lives here so a run is fully described
by ``ResonanceConfig.as_dict()`` (stored in every campaign's evidence payload) and
its hash (``config_hash``), and replay can reproduce a decision exactly.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any

from aegis.contracts.canonical import sha256_hex

RESONANCE_VERSION = "1.0.0"
FINDING_LABEL = "c2_beaconing_campaign"


@dataclass(frozen=True)
class ResonanceConfig:
    # ---------------------------------------------------------------- statistical control
    q: float = 0.01                      # target false discovery rate (Benjamini-Hochberg, weighted)
    q_malicious: float = 0.001           # campaign q at or below which line findings may be MALICIOUS
    n_permutations: int = 1000           # maximum null draws per hypothesis
    sequential_h: int = 10               # Besag-Clifford: stop after h null exceedances
    min_permutations: int = 100          # never stop before this many draws
    tail_fit: bool = True                # GPD tail approximation when exceedances < tail_min_exceed
    tail_min_exceed: int = 10
    p_floor: float = 1e-12

    # ---------------------------------------------------------------- abstention
    min_lines: int = 5                   # unrelated lines needed before a destination is testable
    min_span_s: float = 6 * 3600.0       # minimum observation window for any decision
    min_cycles: float = 4.0              # a period is identifiable only if span >= min_cycles * period

    # ---------------------------------------------------------------- timer recovery
    period_min_s: float = 50.0
    period_max_s: float = 7200.0
    period_step: float = 0.03            # log spacing of the candidate period grid
    max_multiple: int = 4                # pair differences up to max_multiple periods contribute
    multiple_weights: tuple[float, ...] = (1.0, 0.8, 0.6, 0.45)
    neighbors: int = 8                   # pairs formed with up to this many following events
    bin_ratio: float = 0.0175            # relative width of log-spaced difference bins
    coalesce_s: float = 5.0              # events closer than this on one series are one event
    series_cap: int = 600                # events per (line, destination) series kept (deterministic thinning)
    free_min_events: int = 8             # per-line max-over-period evidence needs at least this many events
    z_cap: float = 8.0                   # per-line contribution clip (no single line dominates)
    persistence_weighting: bool = True   # timers running around the clock weigh more than session-gated ones
    persistence_block_s: float = 3600.0

    # ---------------------------------------------------------------- population model
    max_popularity: float = 0.20         # destinations reached by more lines are never campaign targets
    dns_join_ttl_s: float = 3600.0       # flow -> domain attribution window after a DNS answer
    heavy_line_bytes: float = 2e9        # median bytes per line-day above this: streaming-like, ineligible
    light_line_bytes: float = 2e7        # full weight below this (per-line volume is robust to packet sampling)
    heavy_long_flow_frac: float = 0.6
    long_flow_s: float = 30.0            # records at least this long are long-lived connections
    new_days: float = 7.0
    established_days: float = 14.0
    surge_factor: float = 2.0            # established destination re-enters testing when lines surge
    surge_min_extra: int = 5
    shared_domain_weight: float = 0.5    # domain on shared hosting: testable, down-weighted, never IP-enforced
    no_history_weight: float = 0.7
    cluster_prefix24: bool = True        # cluster dedicated-hosting IPs by /24 (requires topology)
    allowlist: tuple[str, ...] = ()      # operator known-service keys/suffixes (never campaign targets)

    # ---------------------------------------------------------------- output
    support_z: float = 2.0               # per-line one-sided z at the campaign period counted as support
    finding_ttl_hours: float = 72.0
    seed: int = 7
    authorization_id: str = "auth-resonance-unset"
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 < self.q < 1 or not 0 < self.q_malicious <= self.q:
            raise ValueError("require 0 < q_malicious <= q < 1")
        if self.period_min_s <= 0 or self.period_max_s <= self.period_min_s:
            raise ValueError("invalid period range")
        if len(self.multiple_weights) < self.max_multiple:
            raise ValueError("multiple_weights must cover max_multiple")
        if self.min_lines < 2:
            raise ValueError("min_lines must be >= 2 (resonance is a cross-line property)")
        if not 0 < self.max_popularity <= 1:
            raise ValueError("max_popularity must be within (0, 1]")

    def with_(self, **kw: Any) -> "ResonanceConfig":
        return replace(self, **kw)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["multiple_weights"] = list(self.multiple_weights)
        d["allowlist"] = list(self.allowlist)
        return d

    @property
    def config_hash(self) -> str:
        return sha256_hex(self.as_dict())

    @property
    def detector_version(self) -> str:
        return f"resonance/{RESONANCE_VERSION}+cfg:{self.config_hash[:12]}"
