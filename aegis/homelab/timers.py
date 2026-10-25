"""Timer / heartbeat analysis of one lab device.

For every destination the device contacted, the module estimates whether the contacts
follow a timer, using RESONANCE's line-level method (known-phase difference folding,
robust to jitter; see ``docs/RESONANCE.md`` section 3.1) through its public functions.
It also computes, for charts and for comparison with classical tools, the full
difference-fold periodogram ``Z(P)``, the Lomb-Scargle power of the binned event
train, and the inter-arrival histogram.

Honest reading
    Many benign services poll on timers (NTP, connectivity checks, push keepalives,
    telemetry, player heartbeats), so *a timer is not evidence of compromise*. In a
    single home there is no population to tell a vendor-wide benign timer from a
    campaign; that is what RESONANCE does at ISP scale. What a home lab adds is the
    owner's knowledge of when the device was used: a timer that keeps running while
    the device is idle is worth a look, one that follows viewing sessions usually is
    not. ``p_nominal`` is a look-elsewhere-corrected *nominal* value, not calibrated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Sequence

import numpy as np

from aegis.contracts.models import ObservationEvent
from aegis.homelab.usage import ResolvedUsage
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import events_from_observations, prepare_series
from aegis.resonance.periodicity import (
    best_periods,
    lomb_scargle_power,
    make_grid,
    nominal_p,
    periodogram,
    phase_rayleigh,
)

ActivityPattern = Literal["runs_while_idle", "active_only", "mixed", "idle_only", "insufficient"]

#: pre-registered thresholds (descriptive classification only, never a verdict on their own)
TIMER_MIN_EVENTS = 8
TIMER_MIN_Z = 5.0
ACTIVE_MIN_HOURS = 0.5
IDLE_MIN_HOURS = 1.0
IDLE_RATE_RATIO = 0.5
ACTIVE_ONLY_RATIO = 0.1
IDLE_COVERAGE_MIN = 0.5


@dataclass(frozen=True)
class ActivitySplit:
    active_events: int
    idle_events: int
    active_hours: float
    idle_hours: float
    active_rate_h: float | None
    idle_rate_h: float | None
    idle_hour_coverage: float | None      # share of (mostly) idle hours with at least one contact
    pattern: ActivityPattern

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class TimerCandidate:
    key: str                              # "d:<domain>" or "ip:<address>"
    n_events: int                         # after burst coalescing / continuation removal
    raw_events: int
    first_seen: datetime
    last_seen: datetime
    period_s: float | None
    z: float | None
    strength: float | None
    p_nominal: float | None
    phase_coherence: float | None
    is_timer: bool
    activity: ActivitySplit | None = None
    periods: list[float] = field(default_factory=list)
    z_curve: list[float | None] = field(default_factory=list)
    lomb_curve: list[float] = field(default_factory=list)
    times: list[float] = field(default_factory=list)
    interarrival_edges: list[float] = field(default_factory=list)
    interarrival_counts: list[int] = field(default_factory=list)

    @property
    def display(self) -> str:
        return self.key.split(":", 1)[1]

    @property
    def kind(self) -> str:
        return "domain" if self.key.startswith("d:") else "ip"

    def to_dict(self, *, curves: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "key": self.key, "n_events": self.n_events, "raw_events": self.raw_events,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "period_s": self.period_s, "z": self.z, "strength": self.strength, "p_nominal": self.p_nominal,
            "p_nominal_note": "nominal look-elsewhere-corrected value, not calibrated",
            "phase_coherence": self.phase_coherence, "is_timer": self.is_timer,
            "activity": self.activity.to_dict() if self.activity else None}
        if curves:
            d.update(periods=self.periods, z_curve=self.z_curve, lomb_curve=self.lomb_curve,
                     interarrival_edges=self.interarrival_edges, interarrival_counts=self.interarrival_counts)
        return d


@dataclass
class TimerAnalysis:
    entity_pseudonym: str
    start: datetime
    end: datetime
    candidates: list[TimerCandidate]
    usage_available: bool
    n_destinations: int
    config_hash: str
    notes: list[str] = field(default_factory=list)

    @property
    def timers(self) -> list[TimerCandidate]:
        return [c for c in self.candidates if c.is_timer]

    def idle_timers(self) -> list[TimerCandidate]:
        return [c for c in self.timers if c.activity is not None and c.activity.pattern in ("runs_while_idle",
                                                                                              "idle_only")]

    def to_dict(self) -> dict[str, Any]:
        return {"entity_pseudonym": self.entity_pseudonym, "start": self.start.isoformat(),
                "end": self.end.isoformat(), "usage_available": self.usage_available,
                "n_destinations": self.n_destinations, "config_hash": self.config_hash, "notes": self.notes,
                "timers": [c.to_dict() for c in self.timers],
                "candidates": [c.to_dict() for c in self.candidates]}


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(float(ts), timezone.utc)


def activity_split(times: np.ndarray, usage: ResolvedUsage) -> ActivitySplit:
    """Compare a destination's contact rate in active and idle periods (descriptive)."""
    state = usage.state_of(times)
    a_ev, i_ev = int((state == 1).sum()), int((state == 0).sum())
    a_h, i_h = usage.active_s / 3600.0, usage.idle_s / 3600.0
    a_rate = a_ev / a_h if a_h > 0 else None
    i_rate = i_ev / i_h if i_h > 0 else None
    blocks = [h for h, cov in usage.hours("idle") if cov >= 1800.0]
    cov: float | None = None
    if blocks:
        hours_hit = set(np.floor(np.asarray(times)[state == 0] / 3600.0) * 3600.0)
        cov = sum(1 for h in blocks if h in hours_hit) / len(blocks)
    pattern: ActivityPattern
    if a_h < ACTIVE_MIN_HOURS or i_h < IDLE_MIN_HOURS:
        pattern = "insufficient"
    elif a_ev == 0 and i_ev > 0:
        pattern = "idle_only"
    elif i_ev == 0 or (a_rate and i_rate is not None and i_rate <= ACTIVE_ONLY_RATIO * a_rate):
        pattern = "active_only"
    elif i_rate is not None and a_rate is not None and i_rate >= IDLE_RATE_RATIO * a_rate and \
            (cov is not None and cov >= IDLE_COVERAGE_MIN):
        pattern = "runs_while_idle"
    else:
        pattern = "mixed"
    return ActivitySplit(a_ev, i_ev, round(a_h, 3), round(i_h, 3), None if a_rate is None else round(a_rate, 3),
                         None if i_rate is None else round(i_rate, 3), None if cov is None else round(cov, 3), pattern)


def _interarrival(times: np.ndarray, n_bins: int = 40) -> tuple[list[float], list[int]]:
    d = np.diff(np.sort(times))
    d = d[d > 0]
    if len(d) == 0:
        return [], []
    # a wide fixed margin around the data so that a narrow (regular) gap distribution looks narrow
    lo, hi = max(1.0, float(d.min()) / 4.0), max(4.0, float(d.max()) * 4.0)
    edges = np.geomspace(lo, hi, n_bins + 1)
    counts, _ = np.histogram(d, bins=edges)
    return [float(x) for x in edges], [int(c) for c in counts]


def analyze_timers(events: Sequence[ObservationEvent], entity_pseudonym: str, *, start: datetime, end: datetime,
                   usage: ResolvedUsage | None = None, cfg: ResonanceConfig | None = None,
                   max_candidates: int = 25, max_raster_points: int = 3000,
                   lomb_candidates: int = 8) -> TimerAnalysis:
    """Per-destination timer estimates for one device over ``[start, end]``."""
    cfg = cfg or ResonanceConfig()
    dev = [e for e in events if e.entity_pseudonym == entity_pseudonym]
    notes: list[str] = []
    span = (end - start).total_seconds()
    table = events_from_observations(dev, cfg, start=start, end=end)
    if len(table) == 0:
        return TimerAnalysis(entity_pseudonym, start, end, [], usage is not None, 0, cfg.config_hash,
                             ["no flow or DNS events for this device"])
    S = prepare_series(table, cfg)
    grid = make_grid(cfg)
    pg = periodogram(S, grid, cfg)
    usable = grid.usable(span, cfg.min_cycles)
    if not usable.any():
        notes.append(f"capture span {span / 3600:.1f} h is too short to identify any period "
                     f"(needs {cfg.min_cycles:g} cycles of the shortest candidate)")
    per, zb, rb = best_periods(pg, grid, usable)
    periods = [float(p) for p in grid.periods]
    order = np.argsort(-np.nan_to_num(zb, nan=-np.inf))
    cands: list[TimerCandidate] = []
    lomb_bin = max(float(grid.periods.min()) / 8.0, span / 4096.0, 1.0)
    for rank, i in enumerate(order[:max_candidates]):
        times = S.times(int(i))
        ok = bool(np.isfinite(per[i]))
        z = float(zb[i]) if ok else None
        pn = float(nominal_p(zb[i], grid.n_eff)) if ok else None
        pc = phase_rayleigh(times, float(per[i]))[0] if ok else None
        n = int(S.counts[i])
        zc = [float(v) if (u and h) else None for v, u, h in zip(pg.Z[i], usable, pg.has_pairs[i])]
        lomb = (lomb_scargle_power(times, grid.periods, bin_s=lomb_bin).tolist()
                if n >= 3 and rank < lomb_candidates else [])
        edges, counts = _interarrival(times)
        raster = times if len(times) <= max_raster_points else np.sort(
            np.random.default_rng(cfg.seed).choice(times, max_raster_points, replace=False))
        cands.append(TimerCandidate(
            key=table.keys.items[int(S.key[i])], n_events=n, raw_events=int(S.raw_counts[i]),
            first_seen=_utc(times[0]), last_seen=_utc(times[-1]), period_s=float(per[i]) if ok else None, z=z,
            strength=float(rb[i]) if ok else None, p_nominal=pn, phase_coherence=pc,
            is_timer=ok and n >= TIMER_MIN_EVENTS and z is not None and z >= TIMER_MIN_Z,
            activity=activity_split(times, usage) if usage is not None else None,
            periods=periods, z_curve=zc, lomb_curve=[float(x) for x in lomb], times=[float(t) for t in raster],
            interarrival_edges=edges, interarrival_counts=counts))
    if usage is None:
        notes.append("no usage windows provided: active/idle comparison unavailable")
    return TimerAnalysis(entity_pseudonym, start, end, cands, usage is not None, int(S.n_series), cfg.config_hash,
                         notes)


__all__ = ["ActivityPattern", "ActivitySplit", "TIMER_MIN_EVENTS", "TIMER_MIN_Z", "TimerAnalysis", "TimerCandidate",
           "activity_split", "analyze_timers"]
