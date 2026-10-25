"""Statistics for the independent evaluation protocol (spec section 14).

All metrics are computed at the **device-day** level. Confidence intervals come from a
cluster bootstrap that resamples *devices* (all device-days of a device move together,
so correlated days do not shrink the intervals), paired across systems so differences
between systems have their own intervals. Exact Clopper-Pearson intervals are given
for recall and the false-positive rate, which stay meaningful when a count is zero.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

import numpy as np

#: metrics bootstrapped per system
BOOT_METRICS = ("precision", "recall", "false_alerts_per_10k", "pr_auc", "fpr")
#: metrics where a lower value is an improvement
LOWER_IS_BETTER = frozenset({"false_alerts_per_10k", "fpr"})


@dataclass
class SystemScores:
    """Per device-day outputs of one system, aligned with :class:`DeviceDayTable` rows."""
    name: str
    alert: np.ndarray            # bool
    score: np.ndarray            # float in [0, 1], ranking score for PR curves
    abstain: np.ndarray | None = None
    first_alert_h: dict[str, float] = field(default_factory=dict)   # device -> hours since infection


@dataclass
class DeviceDayTable:
    keys: list[tuple[str, Any]]        # (entity, date)
    y: np.ndarray                      # 1 = compromised device-day
    device_class: list[str]
    label: list[str]
    hard_negative: np.ndarray          # bool

    def __post_init__(self) -> None:
        n = len(self.keys)
        if not (len(self.y) == len(self.device_class) == len(self.label) == len(self.hard_negative) == n):
            raise ValueError("device-day table columns must align")

    @property
    def devices(self) -> list[str]:
        return sorted({k[0] for k in self.keys})

    def device_index(self) -> dict[str, np.ndarray]:
        idx: dict[str, list[int]] = defaultdict(list)
        for i, (ent, _d) in enumerate(self.keys):
            idx[ent].append(i)
        return {k: np.array(v, dtype=np.int64) for k, v in idx.items()}

    @staticmethod
    def concat(tables: Sequence["DeviceDayTable"], prefixes: Sequence[str]) -> "DeviceDayTable":
        keys: list[tuple[str, Any]] = []
        for t, p in zip(tables, prefixes):
            keys.extend((f"{p}:{e}", d) for e, d in t.keys)
        return DeviceDayTable(keys=keys, y=np.concatenate([t.y for t in tables]),
                              device_class=[c for t in tables for c in t.device_class],
                              label=[lab for t in tables for lab in t.label],
                              hard_negative=np.concatenate([t.hard_negative for t in tables]))


# ---------------------------------------------------------------------------- point metrics

def confusion(y: np.ndarray, alert: np.ndarray) -> dict[str, int]:
    a = alert.astype(bool)
    yy = y.astype(bool)
    return {"tp": int((a & yy).sum()), "fp": int((a & ~yy).sum()), "fn": int((~a & yy).sum()),
            "tn": int((~a & ~yy).sum())}


def _div(a: float, b: float) -> float | None:
    return None if b == 0 else a / b


def rates(c: Mapping[str, int]) -> dict[str, float | None]:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    n = tp + fp + fn + tn
    p, r = _div(tp, tp + fp), _div(tp, tp + fn)
    f1 = None if p is None or r is None or p + r == 0 else 2 * p * r / (p + r)
    return {"precision": p, "recall": r, "f1": f1, "fpr": _div(fp, fp + tn),
            "false_alerts_per_10k": _div(1e4 * fp, n), "alerts_per_10k": _div(1e4 * (tp + fp), n)}


def average_precision(y: np.ndarray, score: np.ndarray) -> float | None:
    """Step-wise average precision (area under the PR curve), ties handled as one threshold."""
    pos = int(y.sum())
    if pos == 0 or pos == len(y):
        return None
    order = np.argsort(-score, kind="mergesort")
    s, yy = score[order], y[order].astype(float)
    tp = np.cumsum(yy)
    fp = np.cumsum(1.0 - yy)
    last = np.r_[np.where(np.diff(s) != 0)[0], len(s) - 1]   # last index of each distinct score
    tp_t, fp_t = tp[last], fp[last]
    precision = tp_t / (tp_t + fp_t)
    recall = tp_t / pos
    prev_recall = np.r_[0.0, recall[:-1]]
    return float(np.sum((recall - prev_recall) * precision))


def pr_curve(y: np.ndarray, score: np.ndarray, max_points: int = 120) -> list[tuple[float, float]]:
    """(recall, precision) points from the highest threshold down, thinned to ``max_points``."""
    pos = int(y.sum())
    if pos == 0:
        return []
    order = np.argsort(-score, kind="mergesort")
    s, yy = score[order], y[order].astype(float)
    tp, fp = np.cumsum(yy), np.cumsum(1.0 - yy)
    last = np.r_[np.where(np.diff(s) != 0)[0], len(s) - 1]
    pts = [(0.0, float(tp[last[0]] / (tp[last[0]] + fp[last[0]])))]
    pts += [(float(tp[i] / pos), float(tp[i] / (tp[i] + fp[i]))) for i in last]
    if len(pts) > max_points:
        step = len(pts) / max_points
        keep = sorted({int(i * step) for i in range(max_points)} | {len(pts) - 1})
        pts = [pts[i] for i in keep]
    return [(round(r, 4), round(p, 4)) for r, p in pts]


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float] | None:
    """Exact binomial confidence interval for k successes in n trials."""
    if n <= 0:
        return None
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def system_metrics(t: DeviceDayTable, s: SystemScores, *, malicious_devices: int | None = None) -> dict[str, Any]:
    c = confusion(t.y, s.alert)
    out: dict[str, Any] = {**c, **rates(c), "device_days": len(t.keys), "pr_auc": average_precision(t.y, s.score)}
    out["recall_ci95_exact"] = clopper_pearson(c["tp"], c["tp"] + c["fn"])
    out["fpr_ci95_exact"] = clopper_pearson(c["fp"], c["fp"] + c["tn"])
    per_class: dict[str, Any] = {}
    classes = np.array(t.device_class)
    for klass in sorted(set(t.device_class)):
        m = classes == klass
        cc = confusion(t.y[m], s.alert[m])
        per_class[klass] = {**cc, **{k: v for k, v in rates(cc).items() if k in
                                     ("precision", "recall", "false_alerts_per_10k")},
                            "device_days": int(m.sum())}
    out["per_device_class"] = per_class
    labels = np.array(t.label)
    per_label: dict[str, Any] = {}
    for lab in sorted(set(t.label) - {"benign"}):
        m = labels == lab
        per_label[lab] = {"device_days": int(m.sum()), "detected": int(s.alert[m].sum()),
                          "recall": _div(float(s.alert[m].sum()), float(m.sum()))}
    out["per_label"] = per_label
    hn = t.hard_negative.astype(bool)
    out["hard_negative_device_days"] = int(hn.sum())
    out["hard_negative_device_days_alerted"] = int((s.alert.astype(bool) & hn).sum())
    if s.abstain is not None:
        ab = s.abstain.astype(bool) & ~s.alert.astype(bool)
        out["abstain_only_device_days"] = int(ab.sum())
        out["abstain_only_positive_device_days"] = int((ab & t.y.astype(bool)).sum())
    delays = sorted(s.first_alert_h.values())
    out["detection_delay_hours_median"] = float(np.median(delays)) if delays else None
    out["detection_delay_hours_p90"] = float(np.percentile(delays, 90)) if delays else None
    out["malicious_devices"] = malicious_devices
    out["malicious_devices_detected"] = len(delays)
    out["pr_curve"] = pr_curve(t.y, s.score)
    return out


# ---------------------------------------------------------------------------- bootstrap

@dataclass
class BootstrapResult:
    ci: dict[str, dict[str, tuple[float, float] | None]]           # system -> metric -> CI
    diff_ci: dict[str, dict[str, tuple[float, float] | None]]      # "a - b" -> metric -> CI
    samples: dict[str, dict[str, np.ndarray]]                      # system -> metric -> samples (may hold NaN)
    resamples: int


def _metric_vector(y: np.ndarray, alert: np.ndarray, score: np.ndarray) -> dict[str, float]:
    c = confusion(y, alert)
    r = rates(c)
    ap = average_precision(y, score)
    nan = float("nan")
    return {"precision": r["precision"] if r["precision"] is not None else nan,
            "recall": r["recall"] if r["recall"] is not None else nan,
            "false_alerts_per_10k": r["false_alerts_per_10k"] if r["false_alerts_per_10k"] is not None else nan,
            "fpr": r["fpr"] if r["fpr"] is not None else nan,
            "pr_auc": ap if ap is not None else nan}


def _ci(v: np.ndarray, min_valid: int) -> tuple[float, float] | None:
    v = v[~np.isnan(v)]
    if len(v) < min_valid:
        return None
    return float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))


def cluster_bootstrap(t: DeviceDayTable, systems: Sequence[SystemScores], *, resamples: int = 1000,
                      seed: int = 7, reference: str | None = None) -> BootstrapResult:
    """Paired device-cluster bootstrap of :data:`BOOT_METRICS` for every system.

    With ``reference``, differences ``reference - other`` are bootstrapped on the same
    resamples (paired), giving intervals for improvements and regressions.
    """
    if resamples <= 0:
        raise ValueError("resamples must be positive")
    groups = list(t.device_index().values())
    rng = np.random.default_rng(seed)
    samples: dict[str, dict[str, np.ndarray]] = {
        s.name: {m: np.full(resamples, np.nan) for m in BOOT_METRICS} for s in systems}
    for b in range(resamples):
        pick = rng.integers(0, len(groups), len(groups))
        idx = np.concatenate([groups[j] for j in pick])
        y = t.y[idx]
        for s in systems:
            vec = _metric_vector(y, s.alert[idx], s.score[idx])
            for m in BOOT_METRICS:
                samples[s.name][m][b] = vec[m]
    min_valid = max(10, resamples // 4)
    ci = {s.name: {m: _ci(samples[s.name][m], min_valid) for m in BOOT_METRICS} for s in systems}
    diff_ci: dict[str, dict[str, tuple[float, float] | None]] = {}
    if reference is not None:
        ref = samples[reference]
        for s in systems:
            if s.name == reference:
                continue
            diff_ci[f"{reference} - {s.name}"] = {m: _ci(ref[m] - samples[s.name][m], min_valid)
                                                  for m in BOOT_METRICS}
    return BootstrapResult(ci=ci, diff_ci=diff_ci, samples=samples, resamples=resamples)


# ---------------------------------------------------------------------------- prevalence

def project_prevalence(recall: float | None, fpr: float | None, prevalence: float, *,
                       minutes_per_alert: float) -> dict[str, float | None]:
    """Expected operating figures of a system at another base rate (per 10k device-days)."""
    if recall is None or fpr is None:
        return {"prevalence": prevalence, "ppv": None, "alerts_per_10k": None, "false_alerts_per_10k": None,
                "true_alerts_per_10k": None, "analyst_hours_per_10k": None}
    tp = prevalence * recall
    fp = (1.0 - prevalence) * fpr
    alerts = tp + fp
    return {"prevalence": prevalence, "ppv": (tp / alerts) if alerts > 0 else None,
            "alerts_per_10k": 1e4 * alerts, "false_alerts_per_10k": 1e4 * fp, "true_alerts_per_10k": 1e4 * tp,
            "analyst_hours_per_10k": 1e4 * alerts * minutes_per_alert / 60.0}


def ppv_interval(recall_samples: np.ndarray, fpr_samples: np.ndarray, prevalence: float
                 ) -> tuple[float, float] | None:
    ok = ~(np.isnan(recall_samples) | np.isnan(fpr_samples))
    r, f = recall_samples[ok], fpr_samples[ok]
    if len(r) < 10:
        return None
    tp = prevalence * r
    alerts = tp + (1.0 - prevalence) * f
    with np.errstate(invalid="ignore", divide="ignore"):
        ppv = np.where(alerts > 0, tp / np.where(alerts > 0, alerts, 1.0), np.nan)
    return _ci(ppv, 10)


# ---------------------------------------------------------------------------- release gate

@dataclass(frozen=True)
class GateConfig:
    """Pre-registered release gate (spec section 14)."""
    candidate: str = "ensemble"
    comparators: tuple[str, ...] = ("rules_only", "static_blocklist")
    improvement_metrics: tuple[str, ...] = ("recall", "pr_auc", "precision", "false_alerts_per_10k")
    max_false_alert_regression_per_10k: float = 5.0


def release_gate(boot: BootstrapResult, cfg: GateConfig) -> dict[str, Any]:
    """Statistically supported improvement on >= 1 prioritized metric, and no false-alert
    regression beyond the predefined limit, against every comparator."""
    results: list[dict[str, Any]] = []
    for comp in cfg.comparators:
        key = f"{cfg.candidate} - {comp}"
        diffs = boot.diff_ci.get(key)
        if diffs is None:
            results.append({"comparator": comp, "passed": False, "reasons": ["comparator not evaluated"]})
            continue
        improved = []
        for m in cfg.improvement_metrics:
            ci = diffs.get(m)
            if ci is None:
                continue
            if (m in LOWER_IS_BETTER and ci[1] < 0) or (m not in LOWER_IS_BETTER and ci[0] > 0):
                improved.append(m)
        fa = diffs.get("false_alerts_per_10k")
        fa_ok = fa is not None and fa[1] <= cfg.max_false_alert_regression_per_10k
        reasons = []
        if improved:
            reasons.append("statistically supported improvement in " + ", ".join(improved))
        else:
            reasons.append("no metric improved with a 95% interval excluding zero")
        if fa is None:
            reasons.append("false-alert difference not estimable")
        elif fa_ok:
            reasons.append(f"false-alert difference upper bound {fa[1]:+.2f}/10k within limit "
                           f"{cfg.max_false_alert_regression_per_10k:+.2f}")
        else:
            reasons.append(f"false-alert difference upper bound {fa[1]:+.2f}/10k exceeds limit "
                           f"{cfg.max_false_alert_regression_per_10k:+.2f}")
        results.append({"comparator": comp, "passed": bool(improved) and fa_ok, "improved_metrics": improved,
                        "false_alert_diff_ci95": fa, "reasons": reasons})
    return {"candidate": cfg.candidate, "config": {"comparators": list(cfg.comparators),
                                                    "improvement_metrics": list(cfg.improvement_metrics),
                                                    "max_false_alert_regression_per_10k":
                                                        cfg.max_false_alert_regression_per_10k},
            "passed": bool(results) and all(r["passed"] for r in results), "comparisons": results,
            "not_assessed": ["privacy", "availability", "cost"],
            "note": ("Only detection metrics are assessed by this harness; privacy, availability and cost gates "
                     "are verified separately (spec sections 12 and 13).")}


def finite_or_none(v: float | None) -> float | None:
    return None if v is None or (isinstance(v, float) and not math.isfinite(v)) else v


__all__ = ["BOOT_METRICS", "LOWER_IS_BETTER", "BootstrapResult", "DeviceDayTable", "GateConfig", "SystemScores", "average_precision",
           "clopper_pearson", "cluster_bootstrap", "confusion", "finite_or_none", "ppv_interval", "pr_curve",
           "project_prevalence", "rates", "release_gate", "system_metrics"]
