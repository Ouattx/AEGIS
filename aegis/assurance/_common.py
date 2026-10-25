"""Shared helpers for the assurance package (feature matrices, labels, JSON-safe floats)."""
from __future__ import annotations

import math
from typing import Any, Iterable, Sequence

import numpy as np

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import MODEL_FEATURES, vectorize_many

BENIGN = "benign"
MALICIOUS = "malicious"
#: label order used everywhere in the package (index 0 = benign, 1 = malicious)
LABELS: tuple[str, str] = (BENIGN, MALICIOUS)
#: stratum key of the pooled (all device classes) calibration set
POOLED = "*"
#: device class used when a window carries none
UNKNOWN_CLASS = "unknown"


class AssuranceError(ValueError):
    """Invalid input to an assurance component (bad shapes, labels, parameters)."""


class AssuranceMismatch(RuntimeError):
    """An assurance artifact was applied to a model or calibration it was not built for."""


def feature_matrix(fvs: Sequence[FeatureVector]) -> np.ndarray:
    """Model feature values (one row per window, columns = ``MODEL_FEATURES``), NaN when missing."""
    if not fvs:
        return np.empty((0, len(MODEL_FEATURES)))
    return np.asarray(vectorize_many(fvs)[:, : len(MODEL_FEATURES)], dtype=float)


def device_classes(fvs: Sequence[FeatureVector]) -> list[str]:
    return [fv.device_class or UNKNOWN_CLASS for fv in fvs]


def to_target(v: Any) -> int | None:
    """0 = benign, 1 = malicious, None = unlabelled. Accepts ints, bools and label strings."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("", "none", "unknown", "abstain"):
            return None
        return 0 if s in ("benign", "0", "false") else 1
    if isinstance(v, float) and math.isnan(v):
        return None
    iv = int(v)
    if iv not in (0, 1):
        raise AssuranceError(f"label must be 0/1 (got {v!r})")
    return iv


def label_array(labels: Iterable[Any]) -> np.ndarray:
    """Integer label array, -1 = unlabelled."""
    return np.array([-1 if (t := to_target(v)) is None else t for v in labels], dtype=int)


def check_scores(scores: Iterable[float]) -> np.ndarray:
    arr = np.asarray(list(scores) if not isinstance(scores, np.ndarray) else scores, dtype=float)
    if arr.ndim != 1:
        raise AssuranceError("scores must be one-dimensional")
    if arr.size and (not np.all(np.isfinite(arr)) or arr.min() < 0.0 or arr.max() > 1.0):
        raise AssuranceError("scores must be finite and within [0, 1]")
    return arr


def finite_or_none(x: float | None, digits: int | None = 6) -> float | None:
    """JSON-safe float: ``None`` for missing / non-finite values."""
    if x is None:
        return None
    f = float(x)
    if not math.isfinite(f):
        return None
    return round(f, digits) if digits is not None else f


def content_id(prefix: str, body: Any) -> str:
    return f"{prefix}-{sha256_hex(body)[:16]}"


def check_alpha(alpha: float, name: str = "alpha") -> float:
    a = float(alpha)
    if not 0.0 < a < 1.0:
        raise AssuranceError(f"{name} must be in (0, 1) (got {alpha!r})")
    return a
