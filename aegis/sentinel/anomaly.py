"""Robust per-device-class anomaly scoring and CUSUM change-point detection (spec section 4).

Anomaly (detector C)
    For each device class, every feature in :data:`ANOMALY_FEATURES` gets a robust
    location/scale (median and max(1.4826*MAD, IQR/1.349, floor)). A window's
    aggregate deviation is the mean of its three largest absolute robust z-scores,
    and is reported as an *empirical percentile* against the fitted population of
    that class, so "0.995" means "more unusual than 99.5% of the reference
    windows of this device class". This normalizes by device class: a busy IPTV
    box is compared with other boxes, not with phones. The device class is the
    *baseline selector* only, it is never evidence. Classes without enough
    reference windows fall back to the all-class baseline, flagged as such.

Change-point (detector D)
    Two-sided tabular CUSUM per entity on the latest-hop metrics
    (``recent_flows_log``, ``recent_bytes_out_log``, ``recent_unique_dst``). The
    baseline is the robust mean/scale of the first ``warmup`` points; after an
    alarm the detector re-baselines on the new regime so a persistent shift
    produces one change point, not a stream of them.

Neither detector asserts maliciousness: both only corroborate in fusion.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import median
from typing import Any, Iterable

from aegis.contracts.models import FeatureVector

GLOBAL_BASELINE = "__all__"

#: features used by the anomaly detector and the floor of their robust scale
ANOMALY_FEATURES: dict[str, float] = {
    "flow_rate_h": 0.1,          # compared on log10(1+x)
    "dns_rate_h": 0.1,           # log10(1+x)
    "bytes_out_rate_log": 0.1,
    "bytes_in_rate_log": 0.1,
    "out_ratio": 0.02,
    "unique_dst_ip": 0.1,        # log10(1+x)
    "dst_entropy": 0.1,
    "small_flow_frac": 0.02,
    "zero_reply_frac": 0.02,
    "peak_out_pps_log": 0.1,
    "nxdomain_rate": 0.02,
    "nx_unique": 0.1,            # log10(1+x)
    "active_bin_frac": 0.05,
    "out_heavy_bin_frac": 0.05,
    "rare_dst_frac": 0.02,
    "rare_qname_frac": 0.02,
}
_LOG_FEATURES = {"flow_rate_h", "dns_rate_h", "unique_dst_ip", "nx_unique"}
Z_CLIP = 20.0
TOP_K = 3


def _transform(name: str, x: float) -> float:
    return math.log10(1.0 + max(0.0, x)) if name in _LOG_FEATURES else x


def _quantile(sorted_vals: list[float], q: float) -> float:
    pos = (len(sorted_vals) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


@dataclass(frozen=True)
class FeatureDeviation:
    feature: str
    value: float
    baseline_median: float
    z: float


@dataclass(frozen=True)
class AnomalyScore:
    percentile: float                 # empirical percentile of the aggregate deviation in [0, 1]
    aggregate: float                  # mean of the top-k |z|
    top: tuple[FeatureDeviation, ...]
    baseline: str                     # device class used, or GLOBAL_BASELINE
    fallback: bool                    # True when the class had no baseline of its own
    features_used: int

    def as_dict(self) -> dict[str, Any]:
        return {"percentile": self.percentile, "aggregate": self.aggregate, "baseline": self.baseline,
                "fallback": self.fallback, "features_used": self.features_used,
                "top": [{"feature": d.feature, "value": d.value, "baseline_median": d.baseline_median,
                         "z": d.z} for d in self.top]}


@dataclass
class _ClassBaseline:
    n: int
    location: dict[str, float]
    scale: dict[str, float]
    reference: list[float]            # sorted aggregate deviations (subsampled quantiles)


class RobustAnomalyModel:
    """Per-device-class robust z-score anomaly model with empirical percentiles."""

    def __init__(self, baselines: dict[str, _ClassBaseline] | None = None, *, min_samples: int = 30):
        self.baselines: dict[str, _ClassBaseline] = baselines or {}
        self.min_samples = min_samples

    @staticmethod
    def _vector(fv: FeatureVector) -> dict[str, float]:
        out = {}
        for name in ANOMALY_FEATURES:
            v = fv.values.get(name)
            if v is not None and not fv.missing.get(name, False) and math.isfinite(v):
                out[name] = _transform(name, float(v))
        return out

    @classmethod
    def fit(cls, features: Iterable[FeatureVector], *, min_samples: int = 30,
            reference_points: int = 1001) -> "RobustAnomalyModel":
        """Fit baselines on (assumed mostly benign) windows. Robust to light contamination."""
        by_class: dict[str, list[dict[str, float]]] = defaultdict(list)
        for fv in features:
            vec = cls._vector(fv)
            if vec:
                by_class[fv.device_class].append(vec)
                by_class[GLOBAL_BASELINE].append(vec)
        model = cls(min_samples=min_samples)
        for klass, vecs in by_class.items():
            if len(vecs) < min_samples:
                continue
            loc: dict[str, float] = {}
            scale: dict[str, float] = {}
            for name, floor in ANOMALY_FEATURES.items():
                xs = sorted(v[name] for v in vecs if name in v)
                if len(xs) < min_samples:
                    continue
                med = _quantile(xs, 0.5)
                mad = median(abs(x - med) for x in xs)
                iqr = _quantile(xs, 0.75) - _quantile(xs, 0.25)
                loc[name] = med
                scale[name] = max(1.4826 * mad, iqr / 1.349, floor)
            base = _ClassBaseline(n=len(vecs), location=loc, scale=scale, reference=[])
            aggs = sorted(a for a in (cls._aggregate(v, base)[0] for v in vecs) if a is not None)
            if not aggs:
                continue
            if len(aggs) > reference_points:
                aggs = [_quantile(aggs, i / (reference_points - 1)) for i in range(reference_points)]
            base.reference = aggs
            model.baselines[klass] = base
        return model

    @staticmethod
    def _aggregate(vec: dict[str, float], base: _ClassBaseline
                   ) -> tuple[float | None, list[tuple[float, str, float]]]:
        zs: list[tuple[float, str, float]] = []
        for name, x in vec.items():
            if name not in base.location:
                continue
            z = (x - base.location[name]) / base.scale[name]
            zs.append((max(-Z_CLIP, min(Z_CLIP, z)), name, x))
        if not zs:
            return None, []
        zs.sort(key=lambda t: -abs(t[0]))
        top = zs[:TOP_K]
        return sum(abs(z) for z, _, _ in top) / len(top), zs

    def score(self, fv: FeatureVector) -> AnomalyScore | None:
        """Score one window, or ``None`` when no baseline/feature is available (missing)."""
        base_name = fv.device_class if fv.device_class in self.baselines else GLOBAL_BASELINE
        base = self.baselines.get(base_name)
        if base is None or not base.reference:
            return None
        vec = self._vector(fv)
        agg, zs = self._aggregate(vec, base)
        if agg is None:
            return None
        ref = base.reference
        # empirical percentile: fraction of reference aggregates strictly below this one
        lo, hi = 0, len(ref)
        while lo < hi:
            mid = (lo + hi) // 2
            if ref[mid] < agg:
                lo = mid + 1
            else:
                hi = mid
        pct = lo / len(ref)
        top = tuple(FeatureDeviation(feature=n, value=round(_inverse(n, x), 6),
                                     baseline_median=round(_inverse(n, base.location[n]), 6), z=round(z, 3))
                    for z, n, x in zs[:TOP_K])
        return AnomalyScore(percentile=pct, aggregate=round(agg, 4), top=top, baseline=base_name,
                            fallback=base_name == GLOBAL_BASELINE and fv.device_class != GLOBAL_BASELINE,
                            features_used=len(zs))

    # ------------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        return {"kind": "robust_z_per_device_class", "version": 1, "min_samples": self.min_samples,
                "features": dict(ANOMALY_FEATURES), "top_k": TOP_K, "z_clip": Z_CLIP,
                "baselines": {k: {"n": b.n, "location": b.location, "scale": b.scale,
                                  "reference": b.reference} for k, b in sorted(self.baselines.items())}}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "RobustAnomalyModel":
        if d.get("kind") != "robust_z_per_device_class":
            raise ValueError("not a robust anomaly model")
        bases = {k: _ClassBaseline(n=int(b["n"]), location={n: float(x) for n, x in b["location"].items()},
                                   scale={n: float(x) for n, x in b["scale"].items()},
                                   reference=[float(x) for x in b["reference"]])
                 for k, b in d.get("baselines", {}).items()}
        return cls(bases, min_samples=int(d.get("min_samples", 30)))


def _inverse(name: str, x: float) -> float:
    return 10 ** x - 1.0 if name in _LOG_FEATURES else x


# ---------------------------------------------------------------------------- change points

@dataclass(frozen=True)
class ChangePoint:
    tenant_id: str
    entity_pseudonym: str
    metric: str
    direction: str                    # "up" or "down"
    detected_at: datetime
    statistic: float                  # CUSUM value at alarm (in scale units)
    baseline_mean: float
    baseline_scale: float
    value: float

    def as_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "direction": self.direction, "detected_at": self.detected_at.isoformat(),
                "statistic": round(self.statistic, 3), "baseline_mean": round(self.baseline_mean, 4),
                "baseline_scale": round(self.baseline_scale, 4), "value": round(self.value, 4)}


@dataclass
class CusumDetector:
    """Two-sided tabular CUSUM with robust warm-up baseline and re-baselining after alarms."""
    k: float = 0.5                    # allowance, in scale units
    h: float = 6.0                    # decision threshold, in scale units
    warmup: int = 12
    min_scale: float = 0.1
    _warm: list[float] = field(default_factory=list)
    _mean: float | None = None
    _scale: float = 1.0
    _pos: float = 0.0
    _neg: float = 0.0

    @property
    def ready(self) -> bool:
        return self._mean is not None

    def update(self, x: float) -> tuple[str, float, float, float] | None:
        """Feed one value; returns ``(direction, statistic, mean, scale)`` on alarm."""
        if self._mean is None:
            self._warm.append(x)
            if len(self._warm) >= self.warmup:
                med = median(self._warm)
                mad = median(abs(v - med) for v in self._warm)
                self._mean, self._scale = med, max(1.4826 * mad, self.min_scale)
                self._warm = []
            return None
        z = (x - self._mean) / self._scale
        self._pos = max(0.0, self._pos + z - self.k)
        self._neg = max(0.0, self._neg - z - self.k)
        if self._pos > self.h or self._neg > self.h:
            direction = "up" if self._pos > self.h else "down"
            stat = self._pos if direction == "up" else self._neg
            mean, scale = self._mean, self._scale
            # re-baseline on the new regime
            self._mean, self._pos, self._neg, self._warm = None, 0.0, 0.0, [x]
            return direction, stat, mean, scale
        return None


CHANGE_METRICS = ("recent_flows_log", "recent_bytes_out_log", "recent_unique_dst")


class ChangePointMonitor:
    """Per-entity CUSUM over the latest-hop metrics of successive windows."""

    def __init__(self, *, k: float = 0.5, h: float = 6.0, warmup: int = 12,
                 horizon: timedelta = timedelta(hours=24), idle_ttl: timedelta = timedelta(days=7)):
        self.k, self.h, self.warmup = k, h, warmup
        self.horizon = horizon
        self.idle_ttl = idle_ttl
        self._det: dict[tuple[str, str], dict[str, CusumDetector]] = {}
        self._last: dict[tuple[str, str], datetime] = {}
        self._recent: dict[tuple[str, str], list[ChangePoint]] = {}

    def update(self, fv: FeatureVector) -> list[ChangePoint]:
        """Feed a window; returns change points detected at this window."""
        key = (fv.tenant_id, fv.entity_pseudonym)
        last = self._last.get(key)
        if last is not None and fv.window_end <= last:
            return []                 # replayed or out-of-order window: ignore
        self._last[key] = fv.window_end
        dets = self._det.setdefault(key, {})
        found: list[ChangePoint] = []
        for metric in CHANGE_METRICS:
            x = fv.values.get(metric)
            if x is None or fv.missing.get(metric, False):
                continue
            det = dets.get(metric)
            if det is None:
                det = dets[metric] = CusumDetector(self.k, self.h, self.warmup)
            alarm = det.update(float(x))
            if alarm is not None:
                direction, stat, mean, scale = alarm
                found.append(ChangePoint(fv.tenant_id, fv.entity_pseudonym, metric, direction, fv.window_end,
                                         stat, mean, scale, float(x)))
        if found:
            self._recent.setdefault(key, []).extend(found)
        return found

    def recent(self, tenant_id: str, entity: str, now: datetime) -> list[ChangePoint]:
        """Change points of the entity within ``horizon`` before ``now``."""
        cps = [c for c in self._recent.get((tenant_id, entity), []) if now - c.detected_at <= self.horizon]
        if cps:
            self._recent[(tenant_id, entity)] = cps
        else:
            self._recent.pop((tenant_id, entity), None)
        return cps

    def prune(self, now: datetime) -> int:
        """Forget entities idle for longer than ``idle_ttl``; returns how many were dropped."""
        stale = [k for k, t in self._last.items() if now - t > self.idle_ttl]
        for k in stale:
            self._last.pop(k, None)
            self._det.pop(k, None)
            self._recent.pop(k, None)
        return len(stale)


__all__ = [
    "ANOMALY_FEATURES", "CHANGE_METRICS", "GLOBAL_BASELINE", "AnomalyScore", "ChangePoint",
    "ChangePointMonitor", "CusumDetector", "FeatureDeviation", "RobustAnomalyModel",
]
