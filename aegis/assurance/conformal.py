"""Mondrian (label- and device-class-conditional) split conformal prediction.

Given a calibrated SENTINEL score ``p`` (probability that a window is malicious)
the nonconformity of a candidate label is ``1 - p_label`` with
``p_malicious = p`` and ``p_benign = 1 - p``. On a held-out, labelled calibration
set the scores are grouped into *strata* ``(device_class, true_label)``; for a new
window the conformal p-value of a label is::

    p_label = (1 + #{calibration windows in the stratum with nonconformity >= s}) / (n_stratum + 1)

and the prediction set is ``{label : p_label > alpha}``.

**Guarantee.** If calibration and test windows of a stratum are exchangeable,
``P(true label in set | device class, true label) >= 1 - alpha`` (label-conditional
validity per device class). Label conditioning matters: positives are rare, so a
marginal guarantee could be met by never including "malicious".

**Small strata.** A stratum with fewer than ``min_stratum`` calibration windows
falls back to the pooled stratum of that label (all device classes), which keeps
label-conditional coverage marginally over device classes; the stratum actually
used is reported. A label with no usable calibration data at all gets
``p = 1`` (always included), so the set becomes ambiguous and the outcome abstains:
missing calibration never yields a confident answer.

**Outcomes.** ``{malicious}`` -> ``malicious``, ``{benign}`` -> ``benign``,
both -> ``ambiguous`` (abstain), none -> ``empty`` (the score conforms to neither
label's calibration; abstain). Abstain is a first-class outcome.

The device class only selects the calibration stratum. It never changes the
score, and on its own it can never place "malicious" in a set.

The calibration windows must not have been used to train the model (use the
model's test split or a separate labelled corpus), otherwise the guarantee does
not hold.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Mapping, Sequence

import numpy as np

from aegis.assurance._common import (
    BENIGN,
    LABELS,
    MALICIOUS,
    POOLED,
    UNKNOWN_CLASS,
    AssuranceError,
    check_alpha,
    check_scores,
    content_id,
    finite_or_none,
    label_array,
)

CONFORMAL_FORMAT = "aegis.assurance.conformal/1"
Outcome = Literal["benign", "malicious", "ambiguous", "empty"]


def nonconformity(score: np.ndarray | float, label: int) -> np.ndarray:
    """Nonconformity of ``label`` (0 benign / 1 malicious) given calibrated malicious probability."""
    s = np.asarray(score, dtype=float)
    return 1.0 - s if label == 1 else s


@dataclass
class _Stratum:
    """Sorted unique nonconformity values with counts (compact, exact)."""
    values: np.ndarray
    counts: np.ndarray
    n: int
    _ge: np.ndarray = field(init=False, repr=False)   # count of calibration scores >= values[i]

    def __post_init__(self) -> None:
        self._ge = np.cumsum(self.counts[::-1])[::-1] if self.n else np.zeros(0, dtype=int)

    @classmethod
    def from_scores(cls, s: np.ndarray) -> "_Stratum":
        # round to 12 decimals so float noise does not split ties
        vals, counts = np.unique(np.round(s.astype(float), 12), return_counts=True)
        return cls(vals, counts.astype(int), int(counts.sum()))

    def p_values(self, s: np.ndarray) -> np.ndarray:
        if self.n == 0:
            return np.ones_like(s, dtype=float)
        idx = np.searchsorted(self.values, np.round(s, 12) - 1e-12, side="left")
        ge = np.where(idx < len(self.values), self._ge[np.minimum(idx, len(self.values) - 1)], 0)
        return (1.0 + ge) / (self.n + 1.0)

    def to_dict(self) -> dict[str, Any]:
        return {"values": [float(v) for v in self.values], "counts": [int(c) for c in self.counts]}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "_Stratum":
        vals = np.asarray(d["values"], dtype=float)
        counts = np.asarray(d["counts"], dtype=int)
        if vals.shape != counts.shape or (len(vals) > 1 and np.any(np.diff(vals) <= 0)) or np.any(counts <= 0):
            raise AssuranceError("invalid conformal stratum")
        return cls(vals, counts, int(counts.sum()))


@dataclass(frozen=True)
class ConformalPrediction:
    """Conformal prediction set for one window."""
    prediction_set: tuple[str, ...]
    outcome: Outcome
    abstain: bool
    p_values: dict[str, float]
    strata: dict[str, str]           # label -> stratum used ("<device_class>" or "*")
    alpha: float
    credibility: float               # largest p-value
    confidence: float                # 1 - second largest p-value
    device_class: str
    score: float

    def to_dict(self) -> dict[str, Any]:
        return {"prediction_set": list(self.prediction_set), "outcome": self.outcome, "abstain": self.abstain,
                "p_values": {k: round(v, 6) for k, v in self.p_values.items()}, "strata": dict(self.strata),
                "alpha": self.alpha, "credibility": round(self.credibility, 6),
                "confidence": round(self.confidence, 6), "device_class": self.device_class,
                "score": round(self.score, 6)}


def _outcome(pset: tuple[str, ...]) -> Outcome:
    if len(pset) == 2:
        return "ambiguous"
    if not pset:
        return "empty"
    return "malicious" if pset[0] == MALICIOUS else "benign"


class MondrianConformal:
    """Label- and device-class-conditional split conformal predictor over calibrated scores."""

    def __init__(self, strata: Mapping[tuple[str, int], _Stratum], *, alpha: float = 0.1,
                 min_stratum: int = 50, model_id: str | None = None, calibration_id: str | None = None,
                 info: Mapping[str, Any] | None = None):
        self.alpha = check_alpha(alpha)
        if min_stratum < 1:
            raise AssuranceError("min_stratum must be >= 1")
        self.min_stratum = int(min_stratum)
        self._strata: dict[tuple[str, int], _Stratum] = dict(strata)
        self.model_id = model_id
        self.calibration_id = calibration_id
        self.info = dict(info or {})
        empty = _Stratum.from_scores(np.empty(0))
        for y in (0, 1):
            self._strata.setdefault((POOLED, y), empty)

    # ------------------------------------------------------------------ construction
    @classmethod
    def fit(cls, scores: Iterable[float], labels: Iterable[Any], device_classes: Sequence[str | None], *,
            alpha: float = 0.1, min_stratum: int = 50, model_id: str | None = None,
            calibration_id: str | None = None, info: Mapping[str, Any] | None = None) -> "MondrianConformal":
        """Calibrate on held-out labelled windows (unlabelled entries are ignored)."""
        s = check_scores(scores)
        y = label_array(labels)
        dcs = [d or UNKNOWN_CLASS for d in device_classes]
        if not (len(s) == len(y) == len(dcs)):
            raise AssuranceError("scores, labels and device_classes must have the same length")
        keep = y >= 0
        if not keep.any():
            raise AssuranceError("no labelled calibration windows")
        groups: dict[tuple[str, int], list[float]] = defaultdict(list)
        for si, yi, dc, k in zip(s, y, dcs, keep):
            if not k:
                continue
            nc = float(nonconformity(si, int(yi)))
            groups[(dc, int(yi))].append(nc)
            groups[(POOLED, int(yi))].append(nc)
        strata = {key: _Stratum.from_scores(np.asarray(v)) for key, v in groups.items()}
        meta = {"calibration_windows": int(keep.sum()),
                "positives": int((y == 1).sum()), "negatives": int((y == 0).sum())}
        meta.update(info or {})
        return cls(strata, alpha=alpha, min_stratum=min_stratum, model_id=model_id,
                   calibration_id=calibration_id, info=meta)

    @classmethod
    def fit_model(cls, model: Any, features: Sequence[Any], labels: Iterable[Any], **kwargs: Any
                  ) -> "MondrianConformal":
        """Calibrate on a :class:`~aegis.sentinel.model.TrainedModel`'s scores of held-out windows."""
        scores = model.predict_many(features)
        return cls.fit(scores, labels, [fv.device_class for fv in features], model_id=model.model_id,
                       calibration_id=model.calibration_id, **kwargs)

    # ------------------------------------------------------------------ prediction
    def stratum_for(self, device_class: str | None, label: int) -> str:
        dc = device_class or UNKNOWN_CLASS
        st = self._strata.get((dc, label))
        return dc if st is not None and st.n >= self.min_stratum else POOLED

    def _p(self, s: np.ndarray, dcs: Sequence[str], label: int) -> tuple[np.ndarray, list[str]]:
        nc = nonconformity(s, label)
        out = np.empty(len(s), dtype=float)
        used: list[str] = []
        by_key: dict[str, list[int]] = defaultdict(list)
        for i, dc in enumerate(dcs):
            key = self.stratum_for(dc, label)
            used.append(key)
            by_key[key].append(i)
        for key, idx in by_key.items():
            ii = np.asarray(idx)
            out[ii] = self._strata[(key, label)].p_values(nc[ii])
        return out, used

    def predict_many(self, scores: Iterable[float], device_classes: Sequence[str | None], *,
                     alpha: float | None = None) -> list[ConformalPrediction]:
        a = self.alpha if alpha is None else check_alpha(alpha)
        s = check_scores(scores)
        dcs = [d or UNKNOWN_CLASS for d in device_classes]
        if len(dcs) != len(s):
            raise AssuranceError("scores and device_classes must have the same length")
        p0, u0 = self._p(s, dcs, 0)
        p1, u1 = self._p(s, dcs, 1)
        out: list[ConformalPrediction] = []
        for i in range(len(s)):
            pv = {BENIGN: float(p0[i]), MALICIOUS: float(p1[i])}
            pset = tuple(lab for lab in LABELS if pv[lab] > a)
            hi, lo = max(pv.values()), min(pv.values())
            oc = _outcome(pset)
            out.append(ConformalPrediction(
                prediction_set=pset, outcome=oc, abstain=oc in ("ambiguous", "empty"), p_values=pv,
                strata={BENIGN: u0[i], MALICIOUS: u1[i]}, alpha=a, credibility=hi, confidence=1.0 - lo,
                device_class=dcs[i], score=float(s[i])))
        return out

    def predict(self, score: float, device_class: str | None, *, alpha: float | None = None
                ) -> ConformalPrediction:
        return self.predict_many([score], [device_class], alpha=alpha)[0]

    # ------------------------------------------------------------------ evaluation
    def coverage_report(self, scores: Iterable[float], labels: Iterable[Any],
                        device_classes: Sequence[str | None], *, alpha: float | None = None) -> dict[str, Any]:
        """Empirical coverage, set sizes and abstain rate on labelled windows not used for calibration."""
        a = self.alpha if alpha is None else check_alpha(alpha)
        s = check_scores(scores)
        y = label_array(labels)
        dcs = [d or UNKNOWN_CLASS for d in device_classes]
        if not (len(s) == len(y) == len(dcs)):
            raise AssuranceError("scores, labels and device_classes must have the same length")
        keep = np.flatnonzero(y >= 0)
        preds = self.predict_many(s[keep], [dcs[i] for i in keep], alpha=a)
        cells: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])  # (dc, label) -> [n, covered]
        outcomes: dict[str, int] = defaultdict(int)
        sizes: dict[int, int] = defaultdict(int)
        for j, pr in zip(keep, preds):
            lab = LABELS[int(y[j])]
            covered = int(lab in pr.prediction_set)
            for key in ((dcs[j], lab), (POOLED, lab)):
                cells[key][0] += 1
                cells[key][1] += covered
            outcomes[pr.outcome] += 1
            sizes[len(pr.prediction_set)] += 1
        n = len(preds)

        def cov(key: tuple[str, str]) -> dict[str, Any]:
            c = cells.get(key, [0, 0])
            return {"n": c[0], "covered": c[1], "coverage": finite_or_none(c[1] / c[0]) if c[0] else None}

        per_class = {dc: {lab: cov((dc, lab)) for lab in LABELS}
                     for dc in sorted({d for d, _ in cells if d != POOLED})}
        total_cov = sum(c[1] for (d, _), c in cells.items() if d == POOLED)
        return {
            "alpha": a, "target_coverage": 1.0 - a, "windows": n,
            "coverage": finite_or_none(total_cov / n) if n else None,
            "label_conditional": {lab: cov((POOLED, lab)) for lab in LABELS},
            "per_device_class": per_class,
            "outcomes": dict(outcomes),
            "abstain_rate": finite_or_none((outcomes["ambiguous"] + outcomes["empty"]) / n) if n else None,
            "set_size": {str(k): v for k, v in sorted(sizes.items())},
        }

    # ------------------------------------------------------------------ persistence
    def strata_summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = defaultdict(dict)
        for (dc, y), st in sorted(self._strata.items()):
            out[dc][LABELS[y]] = st.n
        return dict(out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": CONFORMAL_FORMAT, "alpha": self.alpha, "min_stratum": self.min_stratum,
            "model_id": self.model_id, "calibration_id": self.calibration_id, "info": self.info,
            "strata": [{"device_class": dc, "label": LABELS[y], **st.to_dict()}
                       for (dc, y), st in sorted(self._strata.items()) if st.n > 0],
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "MondrianConformal":
        if d.get("format") != CONFORMAL_FORMAT:
            raise AssuranceError(f"unsupported conformal format {d.get('format')!r}")
        strata: dict[tuple[str, int], _Stratum] = {}
        for row in d.get("strata", []):
            lab = row["label"]
            if lab not in LABELS:
                raise AssuranceError(f"unknown label {lab!r}")
            strata[(str(row["device_class"]), LABELS.index(lab))] = _Stratum.from_dict(row)
        return cls(strata, alpha=float(d["alpha"]), min_stratum=int(d["min_stratum"]),
                   model_id=d.get("model_id"), calibration_id=d.get("calibration_id"), info=d.get("info"))

    @property
    def conformal_id(self) -> str:
        return content_id("cp", self.to_dict())


__all__ = ["CONFORMAL_FORMAT", "ConformalPrediction", "MondrianConformal", "Outcome", "nonconformity"]
