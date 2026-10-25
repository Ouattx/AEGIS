"""Supervised detector (B): LightGBM + isotonic calibration (spec sections 4 and 14).

Training protocol (:func:`train`):

1. **Time-forward split.** Windows ending before the cutoff (``time_split``
   quantile of window end times) are eligible for training; the test set only
   contains windows ending at or after the cutoff.
2. **Group isolation.** Groups (device by default; campaign / infrastructure when
   ``groups`` maps entities to a campaign id) are partitioned into train and test
   groups, stratified by whether the group contains positives. No device or
   campaign appears on both sides.
3. **Calibration without leakage.** Raw scores for calibration are out-of-fold
   predictions from a group k-fold over the training set; isotonic regression is
   fit on them and the final booster is refit on the whole training set.
4. **Model card.** Precision, recall, PR-AUC, ROC-AUC, expected calibration error,
   Brier score, false alerts per 10k device-days, per-device-class breakdowns and
   cluster-bootstrap confidence intervals, all on the held-out test split. The card
   also records ``data.validated_min_population``: the smallest tenant population
   (active devices in one tenant window) in the training data. The fusion policy
   abstains from model-only verdicts below it.

Feature policy: ``ioc_contacts`` is excluded (indicator knowledge enters through
the signed rules path only; training on it would leak threat-feed copies into the
model) and the device class is never a model input (compromise is never inferred
from device class). Missing values stay NaN (LightGBM routes them natively) and
every feature that can be missing gets an explicit missingness indicator.

Artifacts are plain text/JSON (no pickle): ``booster.txt``, ``calibration.json``,
``anomaly.json``, ``model_card.json`` and a ``manifest.json`` with the SHA-256 of
every file, optionally Ed25519-signed. :func:`load` verifies the manifest.
"""
from __future__ import annotations

import json
import math
import os
import random
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import numpy as np

from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.contracts.models import FeatureVector
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.anomaly import RobustAnomalyModel
from aegis.sentinel.features import FEATURE_NAMES

MODEL_FORMAT = "aegis.sentinel.model/1"
EXCLUDED_FEATURES: dict[str, str] = {
    "ioc_contacts": "threat-feed knowledge enters through the signed rules path only (no feed contamination)",
}
MODEL_FEATURES: tuple[str, ...] = tuple(f for f in FEATURE_NAMES if f not in EXCLUDED_FEATURES)
#: features that are always computable when the window exists get no missingness flag
_NEVER_MISSING = {"coverage_h"}
MISSING_FLAGS: tuple[str, ...] = tuple(f for f in MODEL_FEATURES if f not in _NEVER_MISSING)
INPUT_NAMES: tuple[str, ...] = MODEL_FEATURES + tuple(f"missing__{f}" for f in MISSING_FLAGS)
_FLAG_SOURCE = tuple(MODEL_FEATURES.index(f) for f in MISSING_FLAGS)

DEFAULT_PARAMS: dict[str, Any] = {
    "objective": "binary",
    "learning_rate": 0.03,
    "num_leaves": 15,
    "min_data_in_leaf": 50,
    "feature_fraction": 0.7,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 5.0,
    "max_bin": 255,
    "verbose": -1,
    "deterministic": True,
    "force_row_wise": True,
    "num_threads": 1,
}
DEFAULT_ROUNDS = 300
OPERATING_THRESHOLDS = (0.5, 0.6, 0.9)


class InsufficientTrainingData(ValueError):
    """Not enough labeled windows/groups to train and calibrate honestly."""


class ModelIntegrityError(RuntimeError):
    """A saved model's files do not match their manifest (or its signature)."""


# ---------------------------------------------------------------------------- vectorization

def vectorize(fv: FeatureVector) -> np.ndarray:
    """Model input row: feature values (NaN when missing) then missingness indicators."""
    row = np.empty(len(INPUT_NAMES), dtype=np.float64)
    n = len(MODEL_FEATURES)
    for i, name in enumerate(MODEL_FEATURES):
        v = fv.values.get(name)
        miss = v is None or fv.missing.get(name, False) or not math.isfinite(v)
        row[i] = np.nan if miss else float(v)  # type: ignore[arg-type]
    for j, src in enumerate(_FLAG_SOURCE):
        row[n + j] = 1.0 if math.isnan(row[src]) else 0.0
    return row


def vectorize_many(fvs: Sequence[FeatureVector]) -> np.ndarray:
    if not fvs:
        return np.empty((0, len(INPUT_NAMES)))
    return np.vstack([vectorize(fv) for fv in fvs])


# ---------------------------------------------------------------------------- calibration

#: Ceiling applied when a calibration map carries no sample counts (artifacts trained
#: before ceilings were recorded): finite calibration data never supports more than
#: two nines, so a probability is never reported as certain.
DEFAULT_PROBABILITY_CEILING = 0.99


@dataclass
class IsotonicCalibrator:
    """Monotone piecewise-linear map from raw score to probability (JSON-serializable).

    Isotonic regression saturates at exactly 1.0 on the top block of calibration
    samples. ``ceiling`` caps the output at the posterior mean of that block under a
    uniform prior (rule of succession, ``(k + 1) / (n + 2)``), so a calibrated
    probability is never higher than the calibration evidence supports.
    """
    x: list[float]
    y: list[float]
    ceiling: float | None = None

    @classmethod
    def fit(cls, raw: np.ndarray, y: np.ndarray) -> "IsotonicCalibrator":
        from sklearn.isotonic import IsotonicRegression
        iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip", increasing=True)
        iso.fit(raw, y)
        xs = [float(v) for v in iso.X_thresholds_]
        ys = [float(v) for v in iso.y_thresholds_]
        raw_a, y_a = np.asarray(raw, dtype=float), np.asarray(y, dtype=float)
        top = max(ys) if ys else 1.0
        start = next((xv for xv, yv in zip(xs, ys) if yv >= top), xs[-1] if xs else 0.0)
        block = raw_a >= start
        n, k = int(block.sum()), float(y_a[block].sum())
        ceiling = round((k + 1.0) / (n + 2.0), 6) if n else DEFAULT_PROBABILITY_CEILING
        return cls(xs, ys, ceiling)

    @property
    def effective_ceiling(self) -> float:
        return self.ceiling if self.ceiling is not None else DEFAULT_PROBABILITY_CEILING

    def __call__(self, raw: np.ndarray | float) -> np.ndarray:
        return np.clip(np.interp(raw, self.x, self.y), 0.0, self.effective_ceiling)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"method": "isotonic", "x": self.x, "y": self.y}
        if self.ceiling is not None:
            d["ceiling"] = self.ceiling
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "IsotonicCalibrator":
        if d.get("method") != "isotonic":
            raise ValueError("unsupported calibration method")
        x, y = [float(v) for v in d["x"]], [float(v) for v in d["y"]]
        if len(x) != len(y) or not x or any(b < a for a, b in zip(x, x[1:])) \
                or any(b < a for a, b in zip(y, y[1:])):
            raise ValueError("calibration map must be non-empty and monotone")
        ceiling = d.get("ceiling")
        if ceiling is not None and not 0.5 <= float(ceiling) <= 1.0:
            raise ValueError("calibration ceiling must be in [0.5, 1]")
        return cls(x, y, float(ceiling) if ceiling is not None else None)

    @property
    def calibration_id(self) -> str:
        return "iso-" + sha256_hex(self.to_dict())[:16]


# ---------------------------------------------------------------------------- metrics

def device_day(fv: FeatureVector) -> tuple[str, date]:
    """Device-day a window is attributed to: the UTC date of its last instant."""
    return fv.entity_pseudonym, (fv.window_end - timedelta(microseconds=1)).date()


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    if len(y) == 0:
        return float("nan")
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1], right=False), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(ece)


def _safe_div(a: float, b: float) -> float | None:
    return None if b == 0 else a / b


def _binary_stats(y: np.ndarray, flag: np.ndarray) -> dict[str, Any]:
    tp = int(((flag == 1) & (y == 1)).sum())
    fp = int(((flag == 1) & (y == 0)).sum())
    fn = int(((flag == 0) & (y == 1)).sum())
    tn = int(((flag == 0) & (y == 0)).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": _safe_div(tp, tp + fp),
            "recall": _safe_div(tp, tp + fn)}


def _pr_auc(y: np.ndarray, p: np.ndarray) -> float | None:
    if y.sum() == 0 or y.sum() == len(y):
        return None
    from sklearn.metrics import average_precision_score
    return float(average_precision_score(y, p))


def _roc_auc(y: np.ndarray, p: np.ndarray) -> float | None:
    if y.sum() == 0 or y.sum() == len(y):
        return None
    from sklearn.metrics import roc_auc_score
    return float(roc_auc_score(y, p))


def device_day_table(fvs: Sequence[FeatureVector], y: np.ndarray, p: np.ndarray
                     ) -> tuple[list[tuple[str, date]], np.ndarray, np.ndarray, list[str]]:
    """Collapse windows to device-days: label = any positive window, score = max probability."""
    agg: dict[tuple[str, date], list[float]] = {}
    klass: dict[tuple[str, date], str] = {}
    for fv, yy, pp in zip(fvs, y, p):
        k = device_day(fv)
        cur = agg.get(k)
        if cur is None:
            agg[k] = [float(yy), float(pp)]
            klass[k] = fv.device_class
        else:
            cur[0] = max(cur[0], float(yy))
            cur[1] = max(cur[1], float(pp))
    keys = sorted(agg)
    return (keys, np.array([agg[k][0] for k in keys]), np.array([agg[k][1] for k in keys]),
            [klass[k] for k in keys])


def compute_metrics(fvs: Sequence[FeatureVector], y: Sequence[int] | np.ndarray,
                    p: Sequence[float] | np.ndarray, *,
                    thresholds: Sequence[float] = OPERATING_THRESHOLDS, bootstrap: int = 200,
                    seed: int = 7) -> dict[str, Any]:
    """Window- and device-day-level metrics of calibrated probabilities ``p``.

    False alerts per 10k device-days = benign device-days whose max probability
    reaches the threshold, per 10,000 observed device-days.
    """
    ya, pa = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    out: dict[str, Any] = {
        "windows": int(len(ya)), "positive_windows": int(ya.sum()),
        "base_rate_windows": float(ya.mean()) if len(ya) else None,
        "pr_auc": _pr_auc(ya, pa), "roc_auc": _roc_auc(ya, pa),
        "ece": expected_calibration_error(ya, pa) if len(ya) else None,
        "brier": float(np.mean((pa - ya) ** 2)) if len(ya) else None,
    }
    keys, dy, dp, dclass = device_day_table(fvs, ya, pa)
    out["device_days"] = len(keys)
    out["positive_device_days"] = int(dy.sum())
    out["base_rate_device_days"] = float(dy.mean()) if len(dy) else None
    out["device_day_pr_auc"] = _pr_auc(dy, dp)
    ops: dict[str, Any] = {}
    for thr in thresholds:
        w = _binary_stats(ya.astype(int), (pa >= thr).astype(int))
        d = _binary_stats(dy.astype(int), (dp >= thr).astype(int))
        per_class: dict[str, Any] = {}
        for c in sorted(set(dclass)):
            m = np.array([k == c for k in dclass])
            s = _binary_stats(dy[m].astype(int), (dp[m] >= thr).astype(int))
            s["device_days"] = int(m.sum())
            s["positive_device_days"] = int(dy[m].sum())
            s["false_alerts_per_10k_device_days"] = 1e4 * s["fp"] / max(1, int(m.sum()))
            per_class[c] = s
        ops[f"{thr:.2f}"] = {
            "window": w, "device_day": d,
            "false_alerts_per_10k_device_days": 1e4 * d["fp"] / max(1, len(keys)),
            "per_device_class": per_class,
        }
    out["operating_points"] = ops
    if bootstrap and len(keys) and 0 < dy.sum() < len(dy):
        out["bootstrap_ci95"] = _cluster_bootstrap(keys, dy, dp, thresholds, bootstrap, seed)
    return out


def _cluster_bootstrap(keys: list[tuple[str, date]], dy: np.ndarray, dp: np.ndarray,
                       thresholds: Sequence[float], n: int, seed: int) -> dict[str, Any]:
    """95% percentile CIs resampling *devices* (device-days of one device move together)."""
    by_dev: dict[str, list[int]] = defaultdict(list)
    for i, (ent, _) in enumerate(keys):
        by_dev[ent].append(i)
    devs = sorted(by_dev)
    rng = np.random.default_rng(seed)
    samples: dict[str, list[float]] = defaultdict(list)
    for _ in range(n):
        pick = rng.integers(0, len(devs), len(devs))
        idx = np.concatenate([np.array(by_dev[devs[j]]) for j in pick])
        y, p = dy[idx], dp[idx]
        pr = _pr_auc(y, p)
        if pr is not None:
            samples["device_day_pr_auc"].append(pr)
        for thr in thresholds:
            s = _binary_stats(y.astype(int), (p >= thr).astype(int))
            if s["precision"] is not None:
                samples[f"precision@{thr:.2f}"].append(s["precision"])
            if s["recall"] is not None:
                samples[f"recall@{thr:.2f}"].append(s["recall"])
            samples[f"false_alerts_per_10k@{thr:.2f}"].append(1e4 * s["fp"] / len(idx))
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]
            for k, v in sorted(samples.items()) if len(v) >= max(10, n // 4)}


# ---------------------------------------------------------------------------- split

@dataclass(frozen=True)
class SplitConfig:
    time_split: float = 0.6           # quantile of window_end used as train/test cutoff
    test_group_fraction: float = 0.3
    calibration_folds: int = 5
    min_train_positives: int = 20
    min_train_negatives: int = 50
    min_positive_groups: int = 3


Labels = Sequence[int | str | None] | Mapping[tuple[str, date], str] | Callable[[FeatureVector], int | None]


def _to_target(v: int | str | bool | None) -> int | None:
    if v is None:
        return None
    if isinstance(v, str):
        return 0 if v == "benign" else 1
    return 1 if int(v) else 0


def resolve_labels(features: Sequence[FeatureVector], labels: Labels) -> list[int | None]:
    """Normalize label input to one 0/1/None target per window.

    Accepts an aligned sequence (``"benign"``/other label strings, 0/1, ``None`` =
    excluded), a device-day mapping ``{(entity, date): label}`` (window attributed by
    :func:`device_day`), or a callable ``fv -> 0/1/None``.
    """
    if callable(labels):
        return [_to_target(labels(fv)) for fv in features]
    if isinstance(labels, Mapping):
        return [_to_target(labels.get(device_day(fv))) for fv in features]
    if len(labels) != len(features):
        raise ValueError("labels must align with features")
    return [_to_target(v) for v in labels]


def split_indices(features: Sequence[FeatureVector], y: Sequence[int | None], groups: Mapping[str, str] | None,
                  cfg: SplitConfig, seed: int) -> tuple[list[int], list[int], dict[str, Any]]:
    """Time-forward + group-isolated (train, test) indices and a description."""
    labeled = [i for i, v in enumerate(y) if v is not None]
    if not labeled:
        raise InsufficientTrainingData("no labeled windows")
    ends = sorted(features[i].window_end for i in labeled)
    cutoff = ends[min(len(ends) - 1, int(cfg.time_split * len(ends)))]
    gmap = groups or {}
    group_of = {i: gmap.get(features[i].entity_pseudonym, features[i].entity_pseudonym) for i in labeled}
    pos_groups = sorted({group_of[i] for i in labeled if y[i] == 1})
    neg_groups = sorted({group_of[i] for i in labeled} - set(pos_groups))
    rng = random.Random(f"split:{seed}")
    rng.shuffle(pos_groups)
    rng.shuffle(neg_groups)

    def take(gs: list[str]) -> set[str]:
        k = int(round(cfg.test_group_fraction * len(gs)))
        if len(gs) >= 2:
            k = min(max(k, 1), len(gs) - 1)
        return set(gs[:k])

    test_groups = take(pos_groups) | take(neg_groups)
    train = [i for i in labeled if group_of[i] not in test_groups and features[i].window_end < cutoff]
    test = [i for i in labeled if group_of[i] in test_groups and features[i].window_end >= cutoff]
    desc = {
        "method": "time_forward_group_isolated", "cutoff": cutoff.isoformat(), "time_split_quantile": cfg.time_split,
        "group_key": "campaign" if groups else "device", "groups_total": len(set(group_of.values())),
        "test_groups": len(test_groups), "positive_groups": len(pos_groups),
        "train_windows": len(train), "test_windows": len(test),
        "train_positive_windows": sum(1 for i in train if y[i] == 1),
        "test_positive_windows": sum(1 for i in test if y[i] == 1),
        "train_entities": len({features[i].entity_pseudonym for i in train}),
        "test_entities": len({features[i].entity_pseudonym for i in test}),
        "shared_entities": len({features[i].entity_pseudonym for i in train}
                               & {features[i].entity_pseudonym for i in test}),
        "shared_groups": len({group_of[i] for i in train} & {group_of[i] for i in test}),
    }
    return train, test, desc


def _group_folds(groups: list[str], y: np.ndarray, k: int, seed: int) -> list[np.ndarray]:
    """Group k-fold with positive groups spread across folds."""
    pos = sorted({g for g, t in zip(groups, y) if t == 1})
    neg = sorted(set(groups) - set(pos))
    rng = random.Random(f"folds:{seed}")
    rng.shuffle(pos)
    rng.shuffle(neg)
    fold_of: dict[str, int] = {}
    for j, g in enumerate(pos + neg):
        fold_of[g] = j % k if j < len(pos) else (j - len(pos)) % k
    arr = np.array([fold_of[g] for g in groups])
    return [np.where(arr == f)[0] for f in range(k)]


# ---------------------------------------------------------------------------- model

@dataclass
class TrainedModel:
    booster: Any                      # lightgbm.Booster
    calibrator: IsotonicCalibrator
    card: dict[str, Any]
    anomaly: RobustAnomalyModel | None = None
    model_id: str = ""
    _booster_text: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if not self._booster_text:
            self._booster_text = self.booster.model_to_string()
        if not self.model_id:
            self.model_id = "sentinel-lgbm-" + sha256_hex(
                self._booster_text.encode() + canonical_bytes(self.calibrator.to_dict()))[:16]

    @property
    def calibration_id(self) -> str:
        return self.calibrator.calibration_id

    @property
    def version(self) -> str:
        return str(self.card.get("version", self.model_id))

    @property
    def validated_min_population(self) -> int | None:
        """Smallest tenant population (active devices per window) the model was validated on.

        Read from ``data.validated_min_population``. Cards that predate that field fall back
        to the smallest training corpus (``data.corpora[].devices``), an upper bound (warm-up
        windows of a corpus have fewer active devices), so the guard errs strict. None when
        the card records neither.
        """
        data = self.card.get("data") or {}
        explicit = data.get("validated_min_population")
        if explicit is not None:
            return int(explicit)
        sizes = [int(c["devices"]) for c in data.get("corpora") or [] if c.get("devices") is not None]
        return min(sizes) if sizes else None

    def raw_scores(self, fvs: Sequence[FeatureVector]) -> np.ndarray:
        if not fvs:
            return np.empty(0)
        return np.asarray(self.booster.predict(vectorize_many(fvs), raw_score=True), dtype=float)

    def predict_many(self, fvs: Sequence[FeatureVector]) -> np.ndarray:
        """Calibrated probabilities for many windows."""
        if not fvs:
            return np.empty(0)
        return self.calibrator(self.raw_scores(fvs))

    def predict(self, fv: FeatureVector) -> tuple[float, str]:
        """Calibrated probability that the window is malicious, and the calibration id."""
        return float(self.predict_many([fv])[0]), self.calibration_id

    def explain(self, fv: FeatureVector, top: int = 5) -> list[dict[str, Any]]:
        """Top SHAP contributions (raw-score space) for one window, largest |contribution| first."""
        contrib = np.asarray(self.booster.predict(vectorize_many([fv]), pred_contrib=True))[0]
        pairs: list[dict[str, Any]] = []
        for name, c in zip(INPUT_NAMES, contrib[:-1]):
            if c == 0.0:
                continue
            base = name.removeprefix("missing__")
            value = fv.values.get(base)
            pairs.append({"feature": name, "contribution": round(float(c), 4),
                          "value": None if name.startswith("missing__") else value,
                          "missing": bool(name.startswith("missing__") and value is None)})
        pairs.sort(key=lambda d: -abs(float(d["contribution"])))
        return pairs[:top]

    def population_stability(self, fvs: Sequence[FeatureVector]) -> float | None:
        """PSI of the calibrated score distribution vs the training reference (drift signal)."""
        ref = self.card.get("score_reference", {}).get("fractions")
        edges = self.card.get("score_reference", {}).get("edges")
        if not ref or not edges or not fvs:
            return None
        p = self.predict_many(fvs)
        counts, _ = np.histogram(p, bins=np.asarray(edges))
        cur = counts / max(1, counts.sum())
        eps = 1e-4
        r = np.clip(np.asarray(ref), eps, None)
        c = np.clip(cur, eps, None)
        return float(np.sum((c - r) * np.log(c / r)))

    # ------------------------------------------------------------------ persistence
    def save(self, directory: str | Path, *, signer: Signer | None = None) -> Path:
        """Write the artifact (text/JSON only) plus a SHA-256 manifest, optionally signed."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        files = {
            "booster.txt": self._booster_text.encode(),
            "calibration.json": _json_bytes(self.calibrator.to_dict()),
            "model_card.json": _json_bytes(self.card),
        }
        if self.anomaly is not None:
            files["anomaly.json"] = _json_bytes(self.anomaly.to_dict())
        for name, data in files.items():
            (d / name).write_bytes(data)
        manifest: dict[str, Any] = {
            "format": MODEL_FORMAT, "model_id": self.model_id, "calibration_id": self.calibration_id,
            "files": {name: sha256_hex(data) for name, data in sorted(files.items())},
        }
        if signer is not None:
            manifest["signer_key_id"] = signer.key_id
            manifest["signature"] = signer.sign(canonical_bytes(manifest))
        (d / "manifest.json").write_bytes(_json_bytes(manifest))
        return d


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n").encode()


def load(directory: str | Path, *, keyring: KeyRing | None = None, require_signature: bool = False
         ) -> TrainedModel:
    """Load and integrity-check a saved model.

    Every file listed in the manifest must match its SHA-256. When the manifest is
    signed and a ``keyring`` is given the signature must verify; with
    ``require_signature`` an unsigned or unverifiable manifest is refused.
    """
    import lightgbm as lgb
    d = Path(directory)
    try:
        manifest = json.loads((d / "manifest.json").read_text())
    except FileNotFoundError as exc:
        raise ModelIntegrityError(f"no manifest in {d}") from exc
    if manifest.get("format") != MODEL_FORMAT:
        raise ModelIntegrityError(f"unsupported model format {manifest.get('format')!r}")
    sig = manifest.get("signature")
    if sig is not None or require_signature:
        unsigned = {k: v for k, v in manifest.items() if k != "signature"}
        ok = (sig is not None and keyring is not None
              and keyring.verify(str(manifest.get("signer_key_id")), canonical_bytes(unsigned), sig))
        if require_signature and not ok:
            raise ModelIntegrityError("model manifest signature missing or not trusted")
        if sig is not None and keyring is not None and not ok:
            raise ModelIntegrityError("model manifest signature does not verify")
    contents: dict[str, bytes] = {}
    for name, digest in manifest.get("files", {}).items():
        if "/" in name or "\\" in name or name.startswith("."):
            raise ModelIntegrityError(f"invalid file name in manifest: {name!r}")
        data = (d / name).read_bytes()
        if sha256_hex(data) != digest:
            raise ModelIntegrityError(f"{name} does not match the manifest")
        contents[name] = data
    for required in ("booster.txt", "calibration.json", "model_card.json"):
        if required not in contents:
            raise ModelIntegrityError(f"{required} missing from manifest")
    text = contents["booster.txt"].decode()
    booster = lgb.Booster(model_str=text)
    if list(booster.feature_name()) != list(INPUT_NAMES):
        raise ModelIntegrityError("model feature schema differs from this Sentinel version")
    cal = IsotonicCalibrator.from_dict(json.loads(contents["calibration.json"]))
    card = json.loads(contents["model_card.json"])
    anomaly = (RobustAnomalyModel.from_dict(json.loads(contents["anomaly.json"]))
               if "anomaly.json" in contents else None)
    model = TrainedModel(booster=booster, calibrator=cal, card=card, anomaly=anomaly,
                         model_id=str(manifest.get("model_id") or ""), _booster_text=text)
    return model


def default_model_dir() -> Path:
    """Shipped default model: ``$AEGIS_MODEL_DIR`` or ``<repo>/models/sentinel-default``."""
    env = os.environ.get("AEGIS_MODEL_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "models" / "sentinel-default"


def load_default(**kwargs: Any) -> TrainedModel:
    return load(default_model_dir(), **kwargs)


# ---------------------------------------------------------------------------- training

def min_window_population(fvs: Sequence[FeatureVector]) -> int | None:
    """Smallest number of active devices in one tenant window (the population-relative
    features of every training window were computed over at least this many devices).

    ``fvs`` must come from one corpus: windows are grouped by (tenant, window end).
    """
    counts: dict[tuple[str, datetime], int] = defaultdict(int)
    for fv in fvs:
        counts[(fv.tenant_id, fv.window_end)] += 1
    return min(counts.values()) if counts else None


def _fit_booster(X: np.ndarray, y: np.ndarray, params: dict[str, Any], rounds: int, seed: int) -> Any:
    import lightgbm as lgb
    p = dict(params)
    p.setdefault("seed", seed)
    p["seed"] = seed
    p["bagging_seed"] = seed
    p["feature_fraction_seed"] = seed
    p["data_random_seed"] = seed
    ds = lgb.Dataset(X, label=y, feature_name=list(INPUT_NAMES), free_raw_data=True)
    return lgb.train(p, ds, num_boost_round=rounds)


def train(features: Sequence[FeatureVector], labels: Labels, seed: int = 7, *,
          groups: Mapping[str, str] | None = None, params: Mapping[str, Any] | None = None,
          rounds: int = DEFAULT_ROUNDS, split: SplitConfig = SplitConfig(), fit_anomaly: bool = True,
          dataset_info: Mapping[str, Any] | None = None, version: str | None = None,
          now: datetime | None = None) -> TrainedModel:
    """Train, calibrate and evaluate the supervised detector. See module docstring."""
    feats = list(features)
    y_all = resolve_labels(feats, labels)
    train_idx, test_idx, split_desc = split_indices(feats, y_all, groups, split, seed)
    y_tr = np.array([y_all[i] for i in train_idx], dtype=float)
    n_pos, n_neg = int(y_tr.sum()), int(len(y_tr) - y_tr.sum())
    gmap = groups or {}
    tr_groups = [gmap.get(feats[i].entity_pseudonym, feats[i].entity_pseudonym) for i in train_idx]
    pos_groups = len({g for g, t in zip(tr_groups, y_tr) if t == 1})
    if n_pos < split.min_train_positives or n_neg < split.min_train_negatives \
            or pos_groups < split.min_positive_groups:
        raise InsufficientTrainingData(
            f"training split has {n_pos} positive / {n_neg} negative windows in {pos_groups} positive "
            f"groups (need {split.min_train_positives}/{split.min_train_negatives}/{split.min_positive_groups})")
    p = dict(DEFAULT_PARAMS)
    p.update(params or {})
    X_tr = vectorize_many([feats[i] for i in train_idx])

    # out-of-fold raw scores for calibration (group k-fold inside the training set)
    k = max(2, min(split.calibration_folds, pos_groups))
    oof = np.full(len(train_idx), np.nan)
    for fold in _group_folds(tr_groups, y_tr, k, seed):
        if len(fold) == 0:
            continue
        mask = np.ones(len(train_idx), dtype=bool)
        mask[fold] = False
        if y_tr[mask].sum() == 0 or y_tr[mask].sum() == mask.sum():
            continue
        b = _fit_booster(X_tr[mask], y_tr[mask], p, rounds, seed)
        oof[fold] = b.predict(X_tr[fold], raw_score=True)
    ok = ~np.isnan(oof)
    if y_tr[ok].sum() < 5:
        raise InsufficientTrainingData("not enough out-of-fold positives to calibrate")
    calibrator = IsotonicCalibrator.fit(oof[ok], y_tr[ok])
    booster = _fit_booster(X_tr, y_tr, p, rounds, seed)

    anomaly = None
    if fit_anomaly:
        benign_train = [feats[i] for i, t in zip(train_idx, y_tr) if t == 0]
        anomaly = RobustAnomalyModel.fit(benign_train)

    oof_p = calibrator(oof[ok])
    edges = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.0 + 1e-9]
    counts, _ = np.histogram(oof_p, bins=np.asarray(edges))
    model = TrainedModel(booster=booster, calibrator=calibrator, card={}, anomaly=anomaly)
    corpora = list((dataset_info or {}).get("corpora") or [])
    if corpora and all(c.get("min_window_population") is not None for c in corpora):
        validated_population = min(int(c["min_window_population"]) for c in corpora)
    else:
        validated_population = min_window_population(feats)

    test_fvs = [feats[i] for i in test_idx]
    y_te = [int(y_all[i]) for i in test_idx]  # type: ignore[arg-type]
    test_metrics = compute_metrics(test_fvs, y_te, model.predict_many(test_fvs), seed=seed) if test_fvs else None
    oof_fvs = [feats[i] for i, m in zip(train_idx, ok) if m]
    gain = booster.feature_importance(importance_type="gain")
    importance = sorted(((n, float(g)) for n, g in zip(INPUT_NAMES, gain) if g > 0), key=lambda t: -t[1])
    created = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    model.card = {
        "schema": "aegis.model_card/1",
        "model_id": model.model_id,
        "version": version or model.model_id,
        "created_at": created.isoformat(),
        "task": "binary: malicious vs benign device-window (24h context)",
        "algorithm": {"name": "lightgbm", "rounds": rounds, "params": {k2: v for k2, v in sorted(p.items())}},
        "calibration": {"method": "isotonic", "calibration_id": calibrator.calibration_id,
                        "fit_on": "out-of-fold predictions, group k-fold within the training split",
                        "folds": k, "points": len(calibrator.x)},
        "features": {"inputs": list(INPUT_NAMES), "model_features": list(MODEL_FEATURES),
                     "missingness_indicators": list(MISSING_FLAGS),
                     "excluded": {**EXCLUDED_FEATURES,
                                  "device_class": "never a model input: compromise is not inferred from device class"},
                     "top_importance_gain": importance[:15]},
        "data": {**dict(dataset_info or {}), "windows_total": len(feats),
                 "windows_labeled": sum(1 for v in y_all if v is not None),
                 "train_positive_windows": n_pos, "train_negative_windows": n_neg,
                 "train_positive_groups": pos_groups, "validated_min_population": validated_population},
        "split": split_desc,
        "metrics": {"test": test_metrics,
                    "train_out_of_fold": compute_metrics(oof_fvs, [int(v) for v in y_tr[ok]], oof_p,
                                                         bootstrap=0)},
        "score_reference": {"edges": edges, "fractions": (counts / max(1, counts.sum())).tolist()},
        "intended_use": ("Shadow-mode detection of compromised household devices from flow/DNS metadata. "
                         "Scores corroborate signed IOC rules and anomaly signals inside a pre-registered "
                         "fusion policy; a model score alone never triggers enforcement."),
        "limitations": [
            "Trained on the AEGIS synthetic lab corpus unless stated otherwise in data.source; "
            "re-validate on operator shadow data before trusting operating points.",
            "Label is device-window maliciousness; behavior type is assigned by deterministic rules.",
            "Prevalence features need at least 20 active devices per tenant window (missing otherwise).",
            f"Validated for tenant windows of at least {validated_population} active devices; the fusion "
            "policy abstains from model-only verdicts on smaller populations.",
        ],
    }
    return model


__all__ = [
    "DEFAULT_PARAMS", "EXCLUDED_FEATURES", "INPUT_NAMES", "MISSING_FLAGS", "MODEL_FEATURES", "MODEL_FORMAT",
    "InsufficientTrainingData", "IsotonicCalibrator", "ModelIntegrityError", "SplitConfig", "TrainedModel",
    "compute_metrics", "default_model_dir", "device_day", "expected_calibration_error", "load", "load_default",
    "min_window_population", "resolve_labels", "split_indices", "train", "vectorize", "vectorize_many",
]
