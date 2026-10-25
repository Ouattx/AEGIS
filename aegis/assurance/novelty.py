"""Open-set novelty detection: distance to the training manifold in feature space.

A supervised model always answers with one of the labels it was trained on. A
behavior it has never seen (a new malware family, a new benign application) is
forced onto a known label, often with high confidence. This detector flags such
windows as **novel** instead, so they go to a human rather than being labelled.

Method
------
1. *Representation.* The model's behavioral features (``MODEL_FEATURES``) are
   robustly scaled per feature on the reference set (median and IQR), compressed
   with a signed ``log1p`` so heavy-tailed counts do not dominate, and missing
   values become 0 plus a weighted missingness indicator (missing is a fact about
   the window, never imputed as an observation).
2. *Manifold.* Reference windows (the labelled training population: benign and
   known malicious behavior) are split **by entity** into an index set and a
   calibration set, so calibration distances measure "a new device showing known
   behavior", not "the next hop of a device already in the index" (24 h windows
   hopping hourly are near-duplicates of each other).
3. *Score.* The novelty score is the mean Euclidean distance to the ``k`` nearest
   index windows.
4. *Calibrated threshold.* The conformal p-value of a test window is
   ``(1 + #{calibration scores >= score}) / (n_calibration + 1)``; it is novel when
   ``p <= alpha``. For in-distribution windows exchangeable with the calibration
   entities, the false-novelty rate is at most ``alpha``.

Baselines are kept per device class (Mondrian) with a pooled fallback when a class
has too few entities. The device class selects the comparison baseline only; it is
never evidence of anything.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np

from aegis.assurance._common import (
    POOLED,
    UNKNOWN_CLASS,
    AssuranceError,
    check_alpha,
    content_id,
    feature_matrix,
    finite_or_none,
)
from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import MODEL_FEATURES

NOVELTY_FORMAT = "aegis.assurance.novelty/1"
_CLIP = 1e3


@dataclass(frozen=True)
class FeatureScaler:
    """Robust per-feature scaling (median / IQR) with signed log compression."""
    median: tuple[float, ...]
    scale: tuple[float, ...]
    missing_weight: float = 2.0

    @classmethod
    def fit(cls, X: np.ndarray, missing_weight: float = 2.0) -> "FeatureScaler":
        med, scale = [], []
        for j in range(X.shape[1]):
            col = X[:, j]
            col = col[np.isfinite(col)]
            if col.size == 0:
                med.append(0.0)
                scale.append(1.0)
                continue
            m = float(np.median(col))
            q75, q25 = np.percentile(col, [75, 25])
            s = float(q75 - q25) / 1.349
            if not s > 1e-9:
                s = 1.4826 * float(np.median(np.abs(col - m)))
            if not s > 1e-9:
                s = float(np.std(col))
            if not s > 1e-9:
                s = max(abs(m), 1.0) * 0.1
            med.append(m)
            scale.append(s)
        return cls(tuple(med), tuple(scale), float(missing_weight))

    def z(self, X: np.ndarray) -> np.ndarray:
        """Signed-log robust z of the values (0 where missing)."""
        z = (X - np.asarray(self.median)) / np.asarray(self.scale)
        z = np.clip(np.nan_to_num(z, nan=0.0, posinf=_CLIP, neginf=-_CLIP), -_CLIP, _CLIP)
        return np.sign(z) * np.log1p(np.abs(z))

    def transform(self, X: np.ndarray) -> np.ndarray:
        miss = (~np.isfinite(X)).astype(float) * self.missing_weight
        return np.hstack([self.z(X), miss])

    def to_dict(self) -> dict[str, Any]:
        return {"median": [float(v) for v in self.median], "scale": [float(v) for v in self.scale],
                "missing_weight": self.missing_weight}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FeatureScaler":
        med, sc = tuple(float(v) for v in d["median"]), tuple(float(v) for v in d["scale"])
        if len(med) != len(sc) or any(s <= 0 for s in sc):
            raise AssuranceError("invalid feature scaler")
        return cls(med, sc, float(d.get("missing_weight", 2.0)))


@dataclass(frozen=True)
class Deviation:
    feature: str
    value: float | None              # None = missing in the window
    nearest_reference: float | None  # value of the closest reference window (None = missing there)
    contribution: float              # share of the squared distance to that window

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "value": finite_or_none(self.value),
                "nearest_reference": finite_or_none(self.nearest_reference),
                "contribution": round(self.contribution, 4)}


@dataclass(frozen=True)
class NoveltyResult:
    novel: bool
    p_value: float
    score: float                     # mean distance to the k nearest reference windows
    threshold: float                 # score above which p <= alpha (for display)
    alpha: float
    stratum: str                     # device class baseline used, or "*" (pooled)
    top_deviations: tuple[Deviation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"novel": self.novel, "p_value": round(self.p_value, 6), "score": round(self.score, 6),
                "threshold": finite_or_none(self.threshold), "alpha": self.alpha, "stratum": self.stratum,
                "top_deviations": [d.to_dict() for d in self.top_deviations]}


@dataclass
class _Baseline:
    index: np.ndarray                # transformed index windows
    raw: np.ndarray                  # raw feature values of index windows (for explanations)
    calibration: np.ndarray          # sorted novelty scores of calibration windows
    entities: int

    def to_dict(self) -> dict[str, Any]:
        return {"index": np.round(self.index, 5).tolist(),
                "raw": [[finite_or_none(v) for v in row] for row in self.raw],
                "calibration": [round(float(v), 6) for v in self.calibration], "entities": self.entities}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any], n_features: int) -> "_Baseline":
        idx = np.asarray(d["index"], dtype=float)
        raw = np.asarray([[np.nan if v is None else v for v in row] for row in d["raw"]], dtype=float)
        cal = np.sort(np.asarray(d["calibration"], dtype=float))
        if idx.ndim != 2 or idx.shape[1] != 2 * n_features or raw.shape != (idx.shape[0], n_features):
            raise AssuranceError("invalid novelty baseline")
        return cls(idx, raw, cal, int(d["entities"]))


def _knn_dist(index: np.ndarray, Q: np.ndarray, k: int, chunk: int = 512) -> tuple[np.ndarray, np.ndarray]:
    """Mean distance to the k nearest index rows, and the index of the nearest row."""
    kk = min(k, len(index))
    sq_i = np.einsum("ij,ij->i", index, index)
    means = np.empty(len(Q))
    nearest = np.empty(len(Q), dtype=int)
    for a in range(0, len(Q), chunk):
        q = Q[a:a + chunk]
        d2 = np.einsum("ij,ij->i", q, q)[:, None] + sq_i[None, :] - 2.0 * q @ index.T
        np.maximum(d2, 0.0, out=d2)
        part = np.argpartition(d2, kk - 1, axis=1)[:, :kk]
        dk = np.sqrt(np.take_along_axis(d2, part, axis=1))
        means[a:a + chunk] = dk.mean(axis=1)
        nearest[a:a + chunk] = part[np.arange(len(q)), np.argmin(dk, axis=1)]
    return means, nearest


class NoveltyDetector:
    """Distance-to-manifold open-set detector with a conformally calibrated threshold."""

    def __init__(self, scaler: FeatureScaler, baselines: Mapping[str, _Baseline], *, alpha: float = 0.01,
                 k: int = 5, info: Mapping[str, Any] | None = None):
        if POOLED not in baselines:
            raise AssuranceError("a pooled baseline is required")
        self.scaler = scaler
        self.baselines = dict(baselines)
        self.alpha = check_alpha(alpha)
        if k < 1:
            raise AssuranceError("k must be >= 1")
        self.k = int(k)
        self.info = dict(info or {})

    # ------------------------------------------------------------------ construction
    @classmethod
    def fit(cls, features: Sequence[FeatureVector], *, alpha: float = 0.01, k: int = 5,
            calibration_fraction: float = 0.3, max_index: int = 3000, min_entities: int = 20,
            missing_weight: float = 2.0, seed: int = 7, info: Mapping[str, Any] | None = None
            ) -> "NoveltyDetector":
        """Fit on reference windows (typically the model's training population).

        Entities are split into index / calibration sets (``calibration_fraction``);
        each device class with at least ``min_entities`` entities on both sides gets
        its own baseline, and a pooled baseline is always built.
        """
        if k < 1:
            raise AssuranceError("k must be >= 1")
        check_alpha(alpha)
        if not 0.05 <= calibration_fraction <= 0.8:
            raise AssuranceError("calibration_fraction must be in [0.05, 0.8]")
        fvs = list(features)
        if len(fvs) < 20:
            raise AssuranceError("at least 20 reference windows are required")
        X = feature_matrix(fvs)
        scaler = FeatureScaler.fit(X, missing_weight)
        T = scaler.transform(X)
        rng = np.random.default_rng(seed)
        ents = sorted({fv.entity_pseudonym for fv in fvs})
        rng.shuffle(ents)  # type: ignore[arg-type]
        n_cal = max(1, int(round(len(ents) * calibration_fraction)))
        cal_ents = set(ents[:n_cal])
        if n_cal >= len(ents):
            raise AssuranceError("need at least two distinct entities in the reference set")
        is_cal = np.array([fv.entity_pseudonym in cal_ents for fv in fvs])
        dcs = np.array([fv.device_class or UNKNOWN_CLASS for fv in fvs])
        baselines: dict[str, _Baseline] = {}
        strata = [POOLED] + sorted(set(dcs.tolist()))
        for st in strata:
            m = np.ones(len(fvs), dtype=bool) if st == POOLED else dcs == st
            idx_rows, cal_rows = np.flatnonzero(m & ~is_cal), np.flatnonzero(m & is_cal)
            n_idx_ents = len({fvs[i].entity_pseudonym for i in idx_rows})
            n_cal_ents = len({fvs[i].entity_pseudonym for i in cal_rows})
            if st != POOLED and (n_idx_ents < min_entities or n_cal_ents < max(5, min_entities // 4)):
                continue
            if len(idx_rows) == 0 or len(cal_rows) == 0:
                raise AssuranceError("reference set too small for an index/calibration split")
            if len(idx_rows) > max_index:
                idx_rows = np.sort(rng.choice(idx_rows, size=max_index, replace=False))
            # round exactly as persisted, so a loaded detector scores identically
            index = np.round(T[idx_rows], 5)
            cal_scores, _ = _knn_dist(index, T[cal_rows], k)
            baselines[st] = _Baseline(index=index, raw=np.round(X[idx_rows], 6),
                                      calibration=np.sort(np.round(cal_scores, 6)),
                                      entities=n_idx_ents + n_cal_ents)
        meta = {"reference_windows": len(fvs), "reference_entities": len(ents),
                "calibration_entities": n_cal, "features": list(MODEL_FEATURES)}
        meta.update(info or {})
        return cls(scaler, baselines, alpha=alpha, k=k, info=meta)

    # ------------------------------------------------------------------ scoring
    def stratum_for(self, device_class: str | None) -> str:
        dc = device_class or UNKNOWN_CLASS
        return dc if dc in self.baselines else POOLED

    def threshold(self, stratum: str, alpha: float | None = None) -> float:
        """Smallest score whose conformal p-value is <= alpha (inf if unattainable)."""
        a = self.alpha if alpha is None else check_alpha(alpha)
        cal = self.baselines[stratum].calibration
        n = len(cal)
        # p <= a  <=>  #{cal >= s} <= a (n+1) - 1
        m = int(np.floor(a * (n + 1) - 1 + 1e-9))
        if m < 0:
            return float("inf")
        if m >= n:
            return float("-inf")
        return float(np.nextafter(cal[n - m - 1], np.inf))

    def score_many(self, features: Sequence[FeatureVector], *, alpha: float | None = None,
                   top: int = 3) -> list[NoveltyResult]:
        a = self.alpha if alpha is None else check_alpha(alpha)
        fvs = list(features)
        if not fvs:
            return []
        X = feature_matrix(fvs)
        T = self.scaler.transform(X)
        results: list[NoveltyResult | None] = [None] * len(fvs)
        by: dict[str, list[int]] = defaultdict(list)
        for i, fv in enumerate(fvs):
            by[self.stratum_for(fv.device_class)].append(i)
        nf = len(MODEL_FEATURES)
        for st, rows in by.items():
            b = self.baselines[st]
            ii = np.asarray(rows)
            scores, nearest = _knn_dist(b.index, T[ii], self.k)
            n = len(b.calibration)
            ge = n - np.searchsorted(b.calibration, scores, side="left")
            pv = (1.0 + ge) / (n + 1.0)
            thr = self.threshold(st, a)
            for j, i in enumerate(ii):
                diff2 = (T[i] - b.index[nearest[j]]) ** 2
                per_feat = diff2[:nf] + diff2[nf:]
                tot = float(per_feat.sum())
                order = np.argsort(-per_feat)[:top]
                devs = tuple(
                    Deviation(feature=MODEL_FEATURES[f],
                              value=None if not np.isfinite(X[i, f]) else float(X[i, f]),
                              nearest_reference=None if not np.isfinite(b.raw[nearest[j], f])
                              else float(b.raw[nearest[j], f]),
                              contribution=float(per_feat[f] / tot) if tot > 0 else 0.0)
                    for f in order if per_feat[f] > 0)
                results[i] = NoveltyResult(novel=bool(pv[j] <= a), p_value=float(pv[j]), score=float(scores[j]),
                                           threshold=thr, alpha=a, stratum=st, top_deviations=devs)
        return [r for r in results if r is not None]

    def score(self, fv: FeatureVector, *, alpha: float | None = None) -> NoveltyResult:
        return self.score_many([fv], alpha=alpha)[0]

    def novelty_rate(self, features: Sequence[FeatureVector], *, alpha: float | None = None) -> float | None:
        """Share of windows flagged novel (a drift signal on recent production data)."""
        res = self.score_many(features, alpha=alpha, top=0)
        return sum(r.novel for r in res) / len(res) if res else None

    # ------------------------------------------------------------------ persistence
    def to_dict(self) -> dict[str, Any]:
        return {"format": NOVELTY_FORMAT, "alpha": self.alpha, "k": self.k, "info": self.info,
                "features": list(MODEL_FEATURES), "scaler": self.scaler.to_dict(),
                "baselines": {st: b.to_dict() for st, b in sorted(self.baselines.items())}}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "NoveltyDetector":
        if d.get("format") != NOVELTY_FORMAT:
            raise AssuranceError(f"unsupported novelty format {d.get('format')!r}")
        if list(d.get("features", [])) != list(MODEL_FEATURES):
            raise AssuranceError("novelty detector feature schema differs from this Sentinel version")
        nf = len(MODEL_FEATURES)
        baselines = {st: _Baseline.from_dict(b, nf) for st, b in d["baselines"].items()}
        return cls(FeatureScaler.from_dict(d["scaler"]), baselines, alpha=float(d["alpha"]), k=int(d["k"]),
                   info=d.get("info"))

    @property
    def novelty_id(self) -> str:
        body = self.to_dict()
        body["baselines"] = {st: {"calibration": b["calibration"], "entities": b["entities"],
                                  "index_sha": content_id("ix", b["index"])}
                             for st, b in body["baselines"].items()}
        return content_id("nov", body)


__all__ = ["Deviation", "FeatureScaler", "NOVELTY_FORMAT", "NoveltyDetector", "NoveltyResult"]
