"""Safe display of detector scores.

Rules (spec section 14 and the "no false witness" principle):

* a score is shown as a *probability* only when it carries a ``calibration_id``;
  otherwise it is labelled an uncalibrated score that is not a probability;
* a calibrated probability is never displayed as exactly 1 or 0: no finite
  calibration set can support certainty, so values beyond the display precision
  are clamped to ``">0.99"`` / ``"<0.01"`` (for two digits);
* the calibration id is always stated next to a probability.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from aegis.assurance._common import AssuranceError


@dataclass(frozen=True)
class ScoreDisplay:
    """How a score must be presented to a person."""
    text: str                    # ">0.99", "0.87", "<0.01"
    kind: str                    # "calibrated probability" | "uncalibrated score (not a probability)"
    calibration_id: str | None
    is_probability: bool
    clamped: bool                # True when the value was beyond the display bounds

    def __str__(self) -> str:
        if self.is_probability:
            return f"{self.text} ({self.kind}, calibration {self.calibration_id})"
        return f"{self.text} ({self.kind})"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["display"] = str(self)
        return d


def display_score(score: float, calibration_id: str | None, *, digits: int = 2) -> ScoreDisplay:
    """Display form of a detector score in [0, 1].

    ``digits`` (2 or 3) sets the precision; the clamp bounds follow it
    (``>0.99``/``<0.01`` for 2 digits, ``>0.999``/``<0.001`` for 3).
    """
    if digits not in (2, 3):
        raise AssuranceError("digits must be 2 or 3")
    try:
        s = float(score)
    except (TypeError, ValueError) as exc:
        raise AssuranceError(f"score must be a number (got {score!r})") from exc
    if not math.isfinite(s) or s < 0.0 or s > 1.0:
        raise AssuranceError(f"score must be finite and within [0, 1] (got {score!r})")
    step = 10.0 ** -digits
    hi, lo = 1.0 - step, step
    calibrated = bool(calibration_id)
    if s > hi:
        text, clamped = f">{hi:.{digits}f}", True
    elif s < lo:
        text, clamped = f"<{lo:.{digits}f}", True
    else:
        text, clamped = f"{s:.{digits}f}", False
        # rounding can never produce the bounds themselves as "1.00"/"0.00" here, because
        # hi/lo are representable at this precision and s lies within [lo, hi]
    kind = "calibrated probability" if calibrated else "uncalibrated score (not a probability)"
    return ScoreDisplay(text=text, kind=kind, calibration_id=calibration_id if calibrated else None,
                        is_probability=calibrated, clamped=clamped)


def format_score(score: float, calibration_id: str | None, *, digits: int = 2) -> str:
    """One-line display string, e.g. ``">0.99 (calibrated probability, calibration iso-...)"``."""
    return str(display_score(score, calibration_id, digits=digits))


__all__ = ["ScoreDisplay", "display_score", "format_score"]
