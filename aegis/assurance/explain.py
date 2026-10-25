"""Per-finding explanations: TreeSHAP attributions, readable reasons, counterfactuals.

* **Attributions** come from LightGBM's built-in TreeSHAP (``pred_contrib=True``),
  in raw-score (log-odds) space. A feature's value column and its missingness
  indicator are merged into one attribution, so "``nxdomain_rate`` was missing"
  and "``nxdomain_rate`` was 0.4" are explained under one name. The attributions
  plus the expected value sum exactly to the raw score (checked).
* **Reasons** turn the top-k attributions into sentences using the feature
  documentation and, when a :class:`FeatureProfile` is available, the typical
  value among benign reference windows.
* **Counterfactuals** answer "what is the smallest change in behavior that would
  make the model call this window benign?" with a bounded beam search over
  *actionable* features (observed behavioral features; sensor coverage is not
  behavior). Candidate values are benign reference quantiles, so every proposed
  value is one that benign devices actually show. The search is bounded by the
  number of changes and an evaluation budget; when nothing is found within
  them the result says so (``found=False``), it never invents one.

These are explanations of the *model*, not evidence and not remediation advice:
features are changed independently, which real traffic may not allow.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from aegis.assurance._common import AssuranceError, content_id, feature_matrix, finite_or_none, label_array
from aegis.assurance.display import display_score
from aegis.contracts.models import FeatureVector
from aegis.sentinel.features import FEATURE_DOCS
from aegis.sentinel.model import INPUT_NAMES, MODEL_FEATURES, vectorize

PROFILE_FORMAT = "aegis.assurance.profile/1"
#: features that are not behavior of the device and are never changed by a counterfactual
NON_ACTIONABLE: dict[str, str] = {
    "coverage_h": "sensor coverage of the window, not device behavior",
}
DEFAULT_ACTIONABLE: tuple[str, ...] = tuple(f for f in MODEL_FEATURES if f not in NON_ACTIONABLE)
_QUANTS = ("p10", "p25", "p50", "p75", "p90")
_N = len(MODEL_FEATURES)


# ----------------------------------------------------------------------------- benign profile


@dataclass
class FeatureProfile:
    """Quantiles of observed feature values among benign reference windows."""
    quantiles: dict[str, dict[str, float]]      # feature -> p10..p90 (features never observed are absent)
    scale: dict[str, float]                     # feature -> robust scale (IQR/1.349, fallback std)
    windows: int
    info: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(cls, features: Sequence[FeatureVector], labels: Iterable[Any] | None = None, *,
              info: Mapping[str, Any] | None = None) -> "FeatureProfile":
        """Benign profile from reference windows; with ``labels`` only benign (0) windows are used."""
        fvs = list(features)
        if labels is not None:
            y = label_array(labels)
            if len(y) != len(fvs):
                raise AssuranceError("labels and features must have the same length")
            fvs = [fv for fv, yi in zip(fvs, y) if yi == 0]
        if not fvs:
            raise AssuranceError("no benign reference windows for the profile")
        X = feature_matrix(fvs)
        q: dict[str, dict[str, float]] = {}
        sc: dict[str, float] = {}
        for j, name in enumerate(MODEL_FEATURES):
            col = X[:, j]
            col = col[np.isfinite(col)]
            if col.size == 0:
                continue
            vals = np.quantile(col, [0.1, 0.25, 0.5, 0.75, 0.9])
            q[name] = {k: float(v) for k, v in zip(_QUANTS, vals)}
            s = float(vals[3] - vals[1]) / 1.349
            if not s > 1e-9:
                s = float(np.std(col))
            sc[name] = s if s > 1e-9 else max(abs(float(vals[2])), 1.0) * 0.1
        return cls(q, sc, len(fvs), dict(info or {}))

    def typical(self, feature: str) -> float | None:
        return self.quantiles.get(feature, {}).get("p50")

    def to_dict(self) -> dict[str, Any]:
        return {"format": PROFILE_FORMAT, "quantiles": self.quantiles, "scale": self.scale,
                "windows": self.windows, "info": self.info}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "FeatureProfile":
        if d.get("format") != PROFILE_FORMAT:
            raise AssuranceError(f"unsupported profile format {d.get('format')!r}")
        q = {k: {qk: float(qv) for qk, qv in v.items()} for k, v in d["quantiles"].items()}
        sc = {k: float(v) for k, v in d["scale"].items()}
        if any(v <= 0 for v in sc.values()):
            raise AssuranceError("invalid profile scale")
        return cls(q, sc, int(d["windows"]), dict(d.get("info") or {}))

    @property
    def profile_id(self) -> str:
        return content_id("prof", self.to_dict())


# ----------------------------------------------------------------------------- results


@dataclass(frozen=True)
class Attribution:
    feature: str
    contribution: float              # log-odds; value + missingness indicator merged
    value: float | None              # None = missing in the window
    missing: bool

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "contribution": round(self.contribution, 6),
                "value": finite_or_none(self.value), "missing": self.missing}


@dataclass(frozen=True)
class Attributions:
    items: tuple[Attribution, ...]   # sorted by |contribution|, zero contributions dropped
    expected_value: float            # model's expected raw score (SHAP base value)
    raw_score: float                 # booster raw score of this window

    def top(self, k: int) -> tuple[Attribution, ...]:
        return self.items[:k]

    def to_dict(self, k: int | None = None) -> dict[str, Any]:
        items = self.items if k is None else self.items[:k]
        return {"expected_value": round(self.expected_value, 6), "raw_score": round(self.raw_score, 6),
                "space": "log-odds (raw booster score)", "items": [a.to_dict() for a in items]}


@dataclass(frozen=True)
class Reason:
    feature: str
    direction: str                   # "raised" | "lowered"
    contribution: float
    text: str

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "direction": self.direction,
                "contribution": round(self.contribution, 6), "text": self.text}


@dataclass(frozen=True)
class FeatureChange:
    feature: str
    from_value: float
    to_value: float
    benign_quantile: str             # which benign quantile the new value is

    def to_dict(self) -> dict[str, Any]:
        return {"feature": self.feature, "from": finite_or_none(self.from_value),
                "to": finite_or_none(self.to_value), "benign_quantile": self.benign_quantile}


@dataclass(frozen=True)
class Counterfactual:
    found: bool
    changes: tuple[FeatureChange, ...]
    original_score: float
    new_score: float | None
    target: float
    evaluations: int
    max_changes: int
    reason: str                      # why not found / summary
    text: str
    calibration_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"found": self.found, "changes": [c.to_dict() for c in self.changes],
                "original_score": round(self.original_score, 6),
                "new_score": None if self.new_score is None else round(self.new_score, 6),
                "target": self.target, "evaluations": self.evaluations, "max_changes": self.max_changes,
                "reason": self.reason, "text": self.text, "calibration_id": self.calibration_id,
                "caveat": "model-level what-if with independently changed features; not evidence and not a "
                          "remediation instruction"}


def _fmt(v: float) -> str:
    if not math.isfinite(v):
        return str(v)
    if abs(v) >= 1000:
        return f"{v:,.0f}"
    return f"{v:.3g}"


# ----------------------------------------------------------------------------- explainer


class Explainer:
    """Explanations for one :class:`~aegis.sentinel.model.TrainedModel`."""

    def __init__(self, model: Any, profile: FeatureProfile | None = None, *,
                 actionable: Sequence[str] = DEFAULT_ACTIONABLE):
        self.model = model
        self.profile = profile
        bad = [f for f in actionable if f not in MODEL_FEATURES or f in NON_ACTIONABLE]
        if bad:
            raise AssuranceError(f"not actionable model features: {bad}")
        self.actionable = tuple(actionable)

    # ------------------------------------------------------------------ attributions
    def attributions(self, fv: FeatureVector) -> Attributions:
        return self.attributions_many([fv])[0]

    def attributions_many(self, fvs: Sequence[FeatureVector]) -> list[Attributions]:
        """TreeSHAP attributions for many windows (one booster call)."""
        if not fvs:
            return []
        rows = np.vstack([vectorize(fv) for fv in fvs])
        contrib = np.asarray(self.model.booster.predict(rows, pred_contrib=True), dtype=float)
        raw = np.asarray(self.model.booster.predict(rows, raw_score=True), dtype=float)
        merged = contrib[:, :_N].copy()
        for j, name in enumerate(INPUT_NAMES[_N:]):
            merged[:, MODEL_FEATURES.index(name.removeprefix("missing__"))] += contrib[:, _N + j]
        out: list[Attributions] = []
        for r in range(len(fvs)):
            base, rs = float(contrib[r, -1]), float(raw[r])
            if abs(base + float(merged[r].sum()) - rs) > 1e-6 * max(1.0, abs(rs)):
                raise AssuranceError("TreeSHAP attributions do not sum to the raw score")
            items = [Attribution(name, float(merged[r, j]),
                                 None if np.isnan(rows[r, j]) else float(rows[r, j]), bool(np.isnan(rows[r, j])))
                     for j, name in enumerate(MODEL_FEATURES) if merged[r, j] != 0.0]
            items.sort(key=lambda a: -abs(a.contribution))
            out.append(Attributions(tuple(items), base, rs))
        return out

    # ------------------------------------------------------------------ reasons
    def reasons(self, fv: FeatureVector, k: int = 3, attributions: Attributions | None = None) -> list[Reason]:
        """Top-k attributions as sentences (both directions, largest effect first)."""
        attr = attributions or self.attributions(fv)
        out: list[Reason] = []
        for a in attr.top(k):
            doc = FEATURE_DOCS.get(a.feature, a.feature)
            direction = "raised" if a.contribution > 0 else "lowered"
            if a.missing:
                obs = f"{doc} could not be measured in this window"
            else:
                obs = f"{doc} was {_fmt(a.value)}" if a.value is not None else doc
                typ = self.profile.typical(a.feature) if self.profile else None
                if typ is not None:
                    obs += f" (typical for benign windows: {_fmt(typ)})"
            text = f"{obs[0].upper()}{obs[1:]}; this {direction} the model's risk score ({a.contribution:+.2f} log-odds)."
            out.append(Reason(a.feature, direction, a.contribution, text))
        return out

    # ------------------------------------------------------------------ counterfactuals
    def counterfactual(self, fv: FeatureVector, *, target: float = 0.5, max_changes: int = 3, beam_width: int = 8,
                       max_evaluations: int = 4000) -> Counterfactual:
        """Fewest (then smallest) changes to actionable features that bring the calibrated score below ``target``."""
        if not 0.0 < target < 1.0:
            raise AssuranceError("target must be in (0, 1)")
        if max_changes < 1 or beam_width < 1 or max_evaluations < 1:
            raise AssuranceError("max_changes, beam_width and max_evaluations must be >= 1")
        cal_id = str(self.model.calibration_id)
        row0 = vectorize(fv)
        p0 = float(self.model.calibrator(self.model.booster.predict(row0[None, :], raw_score=True))[0])

        def result(found: bool, changes: tuple[FeatureChange, ...], new: float | None, evals: int,
                   reason: str) -> Counterfactual:
            if found:
                parts = [f"{c.feature} ({FEATURE_DOCS.get(c.feature, c.feature)}) were {_fmt(c.to_value)} "
                         f"instead of {_fmt(c.from_value)}" for c in changes]
                frm = display_score(p0, cal_id).text
                to = display_score(new if new is not None else 0.0, cal_id).text
                text = (f"The calibrated model probability would fall from {frm} to {to} "
                        f"(calibration {cal_id}) if " + "; and ".join(parts) + ".")
            else:
                text = f"No counterfactual found: {reason}."
            return Counterfactual(found, changes, p0, new, target, evals, max_changes, reason, text, cal_id)

        if p0 < target:
            return result(False, (), p0, 0, f"score already below the target {target}")
        if self.profile is None:
            return result(False, (), None, 0, "no benign feature profile is configured")
        cands: list[tuple[int, float, str, float]] = []      # (column, value, quantile, normalized cost)
        for name in self.actionable:
            j = MODEL_FEATURES.index(name)
            cur = row0[j]
            q = self.profile.quantiles.get(name)
            if q is None or not math.isfinite(cur):
                continue  # missing stays missing; never invent an observation
            scale = self.profile.scale[name]
            seen: set[float] = set()
            for qn in _QUANTS:
                v = q[qn]
                if v in seen or abs(v - cur) <= 1e-12:
                    continue
                seen.add(v)
                cands.append((j, v, qn, abs(v - cur) / scale))
        if not cands:
            return result(False, (), None, 0, "no actionable observed feature has benign reference values")
        # beam state: (changes as tuple of candidate indices, cost)
        beam: list[tuple[tuple[int, ...], float]] = [((), 0.0)]
        evals = 0
        for _depth in range(max_changes):
            states: list[tuple[tuple[int, ...], float]] = []
            seen_states: set[frozenset[int]] = set()
            for changes, cost in beam:
                used_cols = {cands[c][0] for c in changes}
                for ci, (col, _v, _q, cc) in enumerate(cands):
                    if col in used_cols:
                        continue
                    key = frozenset(changes + (ci,))
                    if key in seen_states:
                        continue
                    seen_states.add(key)
                    states.append((changes + (ci,), cost + cc))
            if not states:
                break
            budget_left = max_evaluations - evals
            truncated = len(states) > budget_left
            if truncated:
                states.sort(key=lambda s: s[1])
                states = states[:budget_left]
            if not states:
                break
            X = np.repeat(row0[None, :], len(states), axis=0)
            for i, (changes, _c) in enumerate(states):
                for ci in changes:
                    X[i, cands[ci][0]] = cands[ci][1]
            raw = np.asarray(self.model.booster.predict(X, raw_score=True), dtype=float)
            prob = np.asarray(self.model.calibrator(raw), dtype=float)
            evals += len(states)
            ok = np.flatnonzero(prob < target)
            if ok.size:
                best = min(ok, key=lambda i: (states[i][1], raw[i]))
                best_changes = tuple(FeatureChange(MODEL_FEATURES[cands[ci][0]], float(row0[cands[ci][0]]),
                                                   float(cands[ci][1]), cands[ci][2]) for ci in states[best][0])
                return result(True, best_changes, float(prob[best]), evals,
                              f"{len(best_changes)} change(s) to actionable features")
            if evals >= max_evaluations:
                return result(False, (), None, evals, f"evaluation budget of {max_evaluations} exhausted")
            order = sorted(range(len(states)), key=lambda i: (raw[i], states[i][1]))[:beam_width]
            beam = [states[i] for i in order]
        return result(False, (), None, evals, f"no change of at most {max_changes} actionable feature(s) "
                                              f"reaches a score below {target}")


__all__ = ["Attribution", "Attributions", "Counterfactual", "DEFAULT_ACTIONABLE", "Explainer", "FeatureChange",
           "FeatureProfile", "NON_ACTIONABLE", "PROFILE_FORMAT", "Reason"]
