"""Drift monitors: feature PSI / KS, missingness shift, score shift and calibration drift.

A :class:`DriftReference` is a frozen, JSON-serializable summary of the data a
model was trained (or last validated) on: per-feature quantile bins and a sample
of observed values, missing rates, the calibrated score distribution and,
when labels were given, the reference expected calibration error (ECE).

:class:`DriftMonitor` compares a window of recent data against it:

* **feature PSI** over the reference quantile bins plus a dedicated *missing* bin
  (a sensor that stops reporting a field is drift too);
* **two-sample Kolmogorov-Smirnov** on observed values; with thousands of windows
  any difference is "significant", so an alert needs both a Bonferroni-corrected
  p-value and an effect size ``D >= ks_alert_d``;
* **missing-rate shift** (absolute change);
* **score distribution** PSI and KS of the calibrated model score;
* **calibration drift**: ECE on recent *labelled* windows (analyst-confirmed
  outcomes), alerting on an absolute limit or an increase over the reference.

Status is ``ok`` / ``warn`` / ``alert`` / ``unknown``. Too little recent data is
``unknown``, never ``ok``: a promotion gate treats unknown as blocking (fail closed).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Literal, Mapping, Sequence

import numpy as np

from aegis.assurance._common import (
    AssuranceError,
    check_scores,
    content_id,
    feature_matrix,
    finite_or_none,
    label_array,
)
from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import MODEL_FEATURES, expected_calibration_error

DRIFT_FORMAT = "aegis.assurance.drift/1"
Status = Literal["ok", "warn", "alert", "unknown"]
_RANK: dict[str, int] = {"ok": 0, "warn": 1, "unknown": 2, "alert": 3}
SCORE_EDGES: tuple[float, ...] = (0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.000000001)
_EPS = 1e-4


def psi(ref_fractions: Sequence[float], cur_fractions: Sequence[float]) -> float:
    """Population stability index between two binned distributions (eps-smoothed)."""
    r = np.clip(np.asarray(ref_fractions, dtype=float), _EPS, None)
    c = np.clip(np.asarray(cur_fractions, dtype=float), _EPS, None)
    r, c = r / r.sum(), c / c.sum()
    return float(np.sum((c - r) * np.log(c / r)))


def _bin_fractions(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    """Fractions over ``len(edges) + 1`` value bins plus one trailing missing bin."""
    finite = np.isfinite(values)
    counts = np.zeros(len(edges) + 2)
    if finite.any():
        idx = np.searchsorted(edges, values[finite], side="right")
        counts[: len(edges) + 1] = np.bincount(idx, minlength=len(edges) + 1)
    counts[-1] = (~finite).sum()
    return counts / max(1.0, counts.sum())


def _ks(a: np.ndarray, b: np.ndarray) -> tuple[float | None, float | None]:
    if len(a) < 2 or len(b) < 2:
        return None, None
    from scipy.stats import ks_2samp
    res = ks_2samp(a, b)
    return float(res.statistic), float(res.pvalue)


def _worst(statuses: Iterable[str]) -> Status:
    worst: str = "ok"
    for s in statuses:
        if _RANK[s] > _RANK[worst]:
            worst = s
    return worst  # type: ignore[return-value]


# ----------------------------------------------------------------------------- reference


@dataclass
class FeatureReference:
    feature: str
    edges: list[float]
    fractions: list[float]           # len(edges) + 1 value bins, then the missing bin
    missing_rate: float
    sample: list[float]              # sorted sample of observed values (for KS)
    quantiles: dict[str, float | None]   # p10/p25/p50/p75/p90 of observed values
    n: int


@dataclass
class DriftReference:
    """Frozen summary of reference data for drift monitoring."""
    features: dict[str, FeatureReference]
    score_fractions: list[float] | None = None
    score_sample: list[float] | None = None
    ece: float | None = None
    windows: int = 0
    model_id: str | None = None
    calibration_id: str | None = None
    info: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, features: Sequence[FeatureVector], *, scores: Iterable[float] | None = None,
              labels: Iterable[Any] | None = None, bins: int = 10, sample_size: int = 2000, seed: int = 7,
              model_id: str | None = None, calibration_id: str | None = None,
              info: Mapping[str, Any] | None = None) -> "DriftReference":
        fvs = list(features)
        if not fvs:
            raise AssuranceError("reference set is empty")
        X = feature_matrix(fvs)
        rng = np.random.default_rng(seed)
        qs = np.linspace(0, 1, bins + 1)[1:-1]
        refs: dict[str, FeatureReference] = {}
        for j, name in enumerate(MODEL_FEATURES):
            col = X[:, j]
            obs = col[np.isfinite(col)]
            edges = np.unique(np.quantile(obs, qs)) if obs.size else np.empty(0)
            sample = obs if obs.size <= sample_size else rng.choice(obs, size=sample_size, replace=False)
            quant: dict[str, float | None] = {
                f"p{int(round(q * 100))}": (float(np.quantile(obs, q)) if obs.size else None)
                for q in (0.1, 0.25, 0.5, 0.75, 0.9)}
            refs[name] = FeatureReference(
                feature=name, edges=[float(e) for e in edges],
                fractions=[float(f) for f in _bin_fractions(col, edges)],
                missing_rate=float((~np.isfinite(col)).mean()),
                sample=sorted(float(v) for v in sample), quantiles=quant, n=int(obs.size))
        sf = ss = None
        ece = None
        if scores is not None:
            s = check_scores(scores)
            if len(s) != len(fvs):
                raise AssuranceError("scores and features must have the same length")
            counts, _ = np.histogram(s, bins=np.asarray(SCORE_EDGES))
            sf = [float(c) for c in counts / max(1, counts.sum())]
            ss = sorted(float(v) for v in (s if len(s) <= sample_size
                                             else rng.choice(s, size=sample_size, replace=False)))
            if labels is not None:
                y = label_array(labels)
                if len(y) != len(s):
                    raise AssuranceError("labels and scores must have the same length")
                keep = y >= 0
                if keep.any():
                    ece = float(expected_calibration_error(y[keep].astype(float), s[keep]))
        return cls(features=refs, score_fractions=sf, score_sample=ss, ece=ece, windows=len(fvs),
                   model_id=model_id, calibration_id=calibration_id, info=dict(info or {}))

    @classmethod
    def from_model(cls, model: Any, features: Sequence[FeatureVector], labels: Iterable[Any] | None = None,
                   **kwargs: Any) -> "DriftReference":
        return cls.build(features, scores=model.predict_many(features), labels=labels, model_id=model.model_id,
                         calibration_id=model.calibration_id, **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {"format": DRIFT_FORMAT, "windows": self.windows, "model_id": self.model_id,
                "calibration_id": self.calibration_id, "info": self.info,
                "ece": finite_or_none(self.ece), "score_fractions": self.score_fractions,
                "score_sample": self.score_sample,
                "features": {k: asdict(v) for k, v in self.features.items()}}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "DriftReference":
        if d.get("format") != DRIFT_FORMAT:
            raise AssuranceError(f"unsupported drift reference format {d.get('format')!r}")
        feats = {k: FeatureReference(**v) for k, v in d["features"].items()}
        for fr in feats.values():
            if len(fr.fractions) != len(fr.edges) + 2:
                raise AssuranceError(f"invalid reference bins for {fr.feature}")
        return cls(features=feats, score_fractions=d.get("score_fractions"), score_sample=d.get("score_sample"),
                   ece=d.get("ece"), windows=int(d.get("windows", 0)), model_id=d.get("model_id"),
                   calibration_id=d.get("calibration_id"), info=dict(d.get("info") or {}))

    @property
    def reference_id(self) -> str:
        return content_id("dref", self.to_dict())


# ----------------------------------------------------------------------------- monitor


@dataclass(frozen=True)
class DriftThresholds:
    """Pre-registered alert thresholds. Change them only by issuing new thresholds."""
    psi_warn: float = 0.10
    psi_alert: float = 0.25
    ks_alert_d: float = 0.15
    ks_alpha: float = 0.01                    # family-wise, Bonferroni over features
    missing_rate_alert: float = 0.10          # absolute change in the missing share
    score_psi_alert: float = 0.25
    score_ks_alert_d: float = 0.15
    ece_alert: float = 0.05                   # absolute ECE limit on recent labelled data
    ece_increase_alert: float = 0.03          # increase over the reference ECE
    min_windows: int = 200
    min_labelled: int = 200
    min_labelled_positives: int = 20

    @property
    def thresholds_id(self) -> str:
        return content_id("dthr", asdict(self))


@dataclass(frozen=True)
class FeatureDrift:
    feature: str
    psi: float | None
    ks_d: float | None
    ks_p: float | None
    missing_rate_ref: float
    missing_rate_cur: float
    status: Status
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "psi": finite_or_none(self.psi), "ks_d": finite_or_none(self.ks_d),
                "ks_p": finite_or_none(self.ks_p, 8), "missing_rate_ref": round(self.missing_rate_ref, 6),
                "missing_rate_cur": round(self.missing_rate_cur, 6), "status": self.status,
                "reasons": list(self.reasons)}


@dataclass(frozen=True)
class DriftReport:
    status: Status
    alerts: tuple[str, ...]          # machine-readable, e.g. "feature_psi:unique_dst_ip"
    warnings: tuple[str, ...]
    windows: int
    unmeasured: tuple[str, ...]      # "score" / "calibration" when they could not be measured
    features: tuple[FeatureDrift, ...]
    score: dict[str, Any]
    calibration: dict[str, Any]
    reference_id: str
    thresholds_id: str

    def drifted_features(self) -> list[str]:
        return [f.feature for f in self.features if f.status == "alert"]

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "alerts": list(self.alerts), "warnings": list(self.warnings),
                "windows": self.windows, "unmeasured": list(self.unmeasured),
                "features": [f.to_dict() for f in self.features],
                "score": self.score, "calibration": self.calibration, "reference_id": self.reference_id,
                "thresholds_id": self.thresholds_id}


class DriftMonitor:
    """Compare recent windows (and optionally their scores / labels) against a reference."""

    def __init__(self, reference: DriftReference, thresholds: DriftThresholds | None = None):
        self.reference = reference
        self.thresholds = thresholds or DriftThresholds()

    def evaluate(self, features: Sequence[FeatureVector], *, scores: Iterable[float] | None = None,
                 labels: Iterable[Any] | None = None) -> DriftReport:
        th = self.thresholds
        fvs = list(features)
        n = len(fvs)
        alerts: list[str] = []
        warnings: list[str] = []
        feats: list[FeatureDrift] = []
        if n < th.min_windows:
            alerts.append(f"insufficient_windows:{n}<{th.min_windows}")
        X = feature_matrix(fvs) if fvs else np.empty((0, len(MODEL_FEATURES)))
        bonf = th.ks_alpha / max(1, len(MODEL_FEATURES))
        for j, name in enumerate(MODEL_FEATURES):
            fr = self.reference.features.get(name)
            if fr is None:
                continue
            col = X[:, j]
            obs = col[np.isfinite(col)]
            cur_missing = float((~np.isfinite(col)).mean()) if n else 0.0
            p = psi(fr.fractions, _bin_fractions(col, np.asarray(fr.edges))) if n else None
            d, pv = _ks(np.asarray(fr.sample), obs)
            reasons: list[str] = []
            status: Status = "ok"
            if n < th.min_windows:
                status = "unknown"
            else:
                if p is not None and p >= th.psi_alert:
                    reasons.append(f"psi {p:.3f} >= {th.psi_alert}")
                if d is not None and pv is not None and d >= th.ks_alert_d and pv < bonf:
                    reasons.append(f"ks D {d:.3f} >= {th.ks_alert_d} (p {pv:.2g})")
                if abs(cur_missing - fr.missing_rate) >= th.missing_rate_alert:
                    reasons.append(f"missing rate {fr.missing_rate:.1%} -> {cur_missing:.1%}")
                if reasons:
                    status = "alert"
                    alerts.append(f"feature_drift:{name}")
                elif p is not None and p >= th.psi_warn:
                    status = "warn"
                    reasons.append(f"psi {p:.3f} >= {th.psi_warn}")
                    warnings.append(f"feature_psi_warn:{name}")
            feats.append(FeatureDrift(name, p, d, pv, fr.missing_rate, cur_missing, status, tuple(reasons)))
        score = self._score_drift(scores, n, alerts)
        calibration = self._calibration_drift(scores, labels, warnings, alerts)
        unmeasured = tuple(k for k, v in (("score", score), ("calibration", calibration))
                           if v["status"] == "unknown")
        statuses = [f.status for f in feats] + [score["status"], calibration["status"]]
        status = "unknown" if n < th.min_windows else _worst(s for s in statuses if s != "unknown")
        return DriftReport(status=status, alerts=tuple(alerts), warnings=tuple(warnings), windows=n,
                           unmeasured=unmeasured,
                           features=tuple(feats), score=score, calibration=calibration,
                           reference_id=self.reference.reference_id, thresholds_id=th.thresholds_id)

    def _score_drift(self, scores: Iterable[float] | None, n: int, alerts: list[str]) -> dict[str, Any]:
        th = self.thresholds
        ref = self.reference
        if scores is None or ref.score_fractions is None or ref.score_sample is None:
            return {"status": "unknown", "psi": None, "ks_d": None, "ks_p": None,
                    "reason": "no scores" if scores is None else "reference has no score distribution"}
        s = check_scores(scores)
        if len(s) != n:
            raise AssuranceError("scores and features must have the same length")
        if n < th.min_windows:
            return {"status": "unknown", "psi": None, "ks_d": None, "ks_p": None, "reason": "insufficient windows"}
        counts, _ = np.histogram(s, bins=np.asarray(SCORE_EDGES))
        p = psi(ref.score_fractions, counts / max(1, counts.sum()))
        d, pv = _ks(np.asarray(ref.score_sample), s)
        reasons = []
        if p >= th.score_psi_alert:
            reasons.append(f"score psi {p:.3f} >= {th.score_psi_alert}")
        if d is not None and pv is not None and d >= th.score_ks_alert_d and pv < th.ks_alpha:
            reasons.append(f"score ks D {d:.3f} >= {th.score_ks_alert_d}")
        if reasons:
            alerts.append("score_drift")
        return {"status": "alert" if reasons else "ok", "psi": finite_or_none(p), "ks_d": finite_or_none(d),
                "ks_p": finite_or_none(pv, 8), "reasons": reasons}

    def _calibration_drift(self, scores: Iterable[float] | None, labels: Iterable[Any] | None,
                           warnings: list[str], alerts: list[str]) -> dict[str, Any]:
        th = self.thresholds
        base = {"ece_reference": finite_or_none(self.reference.ece)}
        if scores is None or labels is None:
            return base | {"status": "unknown", "ece": None, "labelled": 0, "positives": 0,
                           "reason": "no labelled recent windows"}
        s = check_scores(scores)
        y = label_array(labels)
        if len(y) != len(s):
            raise AssuranceError("labels and scores must have the same length")
        keep = y >= 0
        n_lab, n_pos = int(keep.sum()), int((y == 1).sum())
        if n_lab < th.min_labelled or n_pos < th.min_labelled_positives:
            warnings.append("calibration_unmeasured")
            return base | {"status": "unknown", "ece": None, "labelled": n_lab, "positives": n_pos,
                           "reason": "too few labelled windows or positives"}
        ece = float(expected_calibration_error(y[keep].astype(float), s[keep]))
        reasons = []
        if ece > th.ece_alert:
            reasons.append(f"ece {ece:.3f} > {th.ece_alert}")
        if self.reference.ece is not None and ece - self.reference.ece > th.ece_increase_alert:
            reasons.append(f"ece rose {self.reference.ece:.3f} -> {ece:.3f}")
        if reasons:
            alerts.append("calibration_drift")
        return base | {"status": "alert" if reasons else "ok", "ece": finite_or_none(ece), "labelled": n_lab,
                       "positives": n_pos, "reasons": reasons}


def worst_status(*statuses: str) -> Status:
    return _worst(statuses)


__all__ = ["DRIFT_FORMAT", "DriftMonitor", "DriftReference", "DriftReport", "DriftThresholds", "FeatureDrift",
           "FeatureReference", "SCORE_EDGES", "Status", "psi", "worst_status"]
