"""Assurance promotion gate: blocks model promotion on drift, regression or broken guarantees.

This gate complements :class:`aegis.sentinel.registry.PromotionGate` (which checks
signatures, model cards, device-day metrics and score PSI). It adds the assurance
checks, all deterministic and pre-registered:

* **holdout size** - enough labelled windows and positives (``holdout_too_small``);
* **regression vs champion** on the same holdout at the operating threshold -
  window recall may not drop by more than ``max_recall_drop``
  (``recall_regression``), the false-positive rate may not rise by more than
  ``max_false_positive_rate_increase`` (``false_positive_regression``) and the
  calibration error may not rise by more than ``max_ece_increase``
  (``calibration_error_regression``);
* **calibration** - ECE at most ``max_ece`` (``calibration_error_exceeds_limit``);
* **conformal guarantee** - on the holdout, label-conditional empirical coverage
  of the candidate's conformal predictor must reach ``1 - alpha - coverage_tolerance``
  (``conformal_coverage_below_target:<label>``) and its abstain rate may not exceed
  ``max_abstain_rate`` (``conformal_abstain_rate_exceeds_limit``). The conformal
  predictor must be calibrated on data disjoint from this holdout;
* **artifact binding** - assurance artifacts must belong to the candidate model
  (``assurance_artifact_mismatch``);
* **drift** - every alert of the candidate's :class:`DriftReport` on recent
  production data becomes ``drift_detected:<alert>``; a missing report, too few
  recent windows or an unmeasured score distribution becomes ``drift_unknown:*``
  (fail closed); a recent novelty rate above ``max_novelty_rate_factor x alpha``
  becomes ``drift_detected:novelty_rate``.

As in the registry, only ``drift_detected:*`` / ``drift_unknown:*`` are
acknowledgeable (by a second human, through the registry's ``acknowledge_drift``
flow); every other failure is a hard block. No language model and no agent can
pass this gate on anyone's behalf.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

import numpy as np

from aegis.assurance._common import (
    BENIGN,
    MALICIOUS,
    AssuranceError,
    check_scores,
    content_id,
    finite_or_none,
    label_array,
)
from aegis.assurance.conformal import MondrianConformal
from aegis.assurance.drift import DriftMonitor, DriftReference, DriftReport, DriftThresholds
from aegis.assurance.novelty import NoveltyDetector
from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import expected_calibration_error

ACKNOWLEDGEABLE_PREFIXES = ("drift_detected:", "drift_unknown:")


def acknowledgeable(check: str) -> bool:
    return check.startswith(ACKNOWLEDGEABLE_PREFIXES)


class PromotionBlocked(PermissionError):
    """The assurance gate refused a promotion; ``failed`` lists machine-readable reasons."""

    def __init__(self, message: str, failed: Sequence[str]):
        super().__init__(message)
        self.failed = list(failed)


@dataclass(frozen=True)
class AssuranceGateConfig:
    """Pre-registered assurance gate. Change it only by issuing a new config (new ``gate_id``)."""
    threshold: float = 0.6
    min_holdout: int = 200
    min_holdout_positives: int = 20
    max_recall_drop: float = 0.02
    max_false_positive_rate_increase: float = 0.0005
    max_ece: float = 0.05
    max_ece_increase: float = 0.01
    coverage_tolerance: float = 0.02
    max_abstain_rate: float = 0.25
    max_novelty_rate_factor: float = 3.0
    block_on_drift_warn: bool = False

    @property
    def gate_id(self) -> str:
        return content_id("agate", asdict(self))

    def describe(self) -> dict[str, Any]:
        return asdict(self) | {"gate_id": self.gate_id}


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    failed_checks: tuple[str, ...]
    blocking_checks: tuple[str, ...]          # cannot be lifted by any acknowledgement
    acknowledgeable_checks: tuple[str, ...]
    metrics: dict[str, Any]
    gate_id: str
    gate: dict[str, Any]
    candidate_model_id: str | None
    champion_model_id: str | None
    evaluated_at: datetime
    inputs_sha256: str

    def allowed_with_acknowledgement(self) -> bool:
        """True when only acknowledgeable (drift) checks failed."""
        return not self.blocking_checks

    def raise_if_blocked(self, *, acknowledge_drift: bool = False) -> None:
        if self.allowed:
            return
        if acknowledge_drift and not self.blocking_checks:
            return
        failed = list(self.blocking_checks) if acknowledge_drift else list(self.failed_checks)
        raise PromotionBlocked("assurance gate refused promotion: " + ", ".join(failed), failed)

    def to_dict(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "failed_checks": list(self.failed_checks),
                "blocking_checks": list(self.blocking_checks),
                "acknowledgeable_checks": list(self.acknowledgeable_checks), "metrics": self.metrics,
                "gate_id": self.gate_id, "gate": self.gate, "candidate_model_id": self.candidate_model_id,
                "champion_model_id": self.champion_model_id, "evaluated_at": self.evaluated_at.isoformat(),
                "inputs_sha256": self.inputs_sha256}


@dataclass
class PromotionInputs:
    """Everything the gate needs, as plain arrays and reports (model-agnostic)."""
    holdout_labels: Sequence[Any]
    candidate_scores: Sequence[float]
    candidate_model_id: str | None = None
    candidate_calibration_id: str | None = None
    champion_scores: Sequence[float] | None = None
    champion_model_id: str | None = None
    holdout_device_classes: Sequence[str | None] | None = None
    drift: DriftReport | None = None
    conformal: MondrianConformal | None = None
    recent_novelty_rate: float | None = None
    novelty_alpha: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _rates(y: np.ndarray, p: np.ndarray, thr: float) -> dict[str, Any]:
    flag = p >= thr
    pos, neg = y == 1, y == 0
    tp, fp = int((flag & pos).sum()), int((flag & neg).sum())
    return {"recall": tp / int(pos.sum()) if pos.any() else None,
            "false_positive_rate": fp / int(neg.sum()) if neg.any() else None,
            "precision": tp / (tp + fp) if tp + fp else None,
            "ece": float(expected_calibration_error(y.astype(float), p)) if len(y) else None,
            "brier": float(np.mean((p - y) ** 2)) if len(y) else None}


class AssuranceGate:
    """Deterministic assurance checks before a model can be promoted."""

    def __init__(self, config: AssuranceGateConfig | None = None, *, clock: Any = None):
        self.config = config or AssuranceGateConfig()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def evaluate(self, inputs: PromotionInputs) -> GateDecision:
        cfg = self.config
        y_all = label_array(inputs.holdout_labels)
        cand_all = check_scores(inputs.candidate_scores)
        if len(cand_all) != len(y_all):
            raise AssuranceError("candidate_scores and holdout_labels must have the same length")
        keep = y_all >= 0
        y, cand = y_all[keep], cand_all[keep]
        failed: list[str] = []
        metrics: dict[str, Any] = {"holdout_windows": int(keep.sum()), "holdout_positives": int((y == 1).sum())}
        if keep.sum() < cfg.min_holdout or (y == 1).sum() < cfg.min_holdout_positives:
            failed.append("holdout_too_small")
        cm = _rates(y, cand, cfg.threshold)
        metrics["candidate"] = {k: finite_or_none(v) for k, v in cm.items()}
        if cm["ece"] is not None and cm["ece"] > cfg.max_ece:
            failed.append("calibration_error_exceeds_limit")
        if inputs.champion_scores is not None:
            champ = check_scores(inputs.champion_scores)
            if len(champ) != len(y_all):
                raise AssuranceError("champion_scores and holdout_labels must have the same length")
            hm = _rates(y, champ[keep], cfg.threshold)
            metrics["champion"] = {k: finite_or_none(v) for k, v in hm.items()}
            if cm["recall"] is not None and hm["recall"] is not None \
                    and hm["recall"] - cm["recall"] > cfg.max_recall_drop:
                failed.append("recall_regression")
            if cm["false_positive_rate"] is not None and hm["false_positive_rate"] is not None \
                    and cm["false_positive_rate"] - hm["false_positive_rate"] > cfg.max_false_positive_rate_increase:
                failed.append("false_positive_regression")
            if cm["ece"] is not None and hm["ece"] is not None and cm["ece"] - hm["ece"] > cfg.max_ece_increase:
                failed.append("calibration_error_regression")
        if inputs.conformal is not None:
            cp = inputs.conformal
            if (inputs.candidate_model_id and cp.model_id and cp.model_id != inputs.candidate_model_id) or \
                    (inputs.candidate_calibration_id and cp.calibration_id
                     and cp.calibration_id != inputs.candidate_calibration_id):
                failed.append("assurance_artifact_mismatch")
            if inputs.holdout_device_classes is None or len(inputs.holdout_device_classes) != len(y_all):
                raise AssuranceError("holdout_device_classes are required for the conformal check")
            dcs = [d for d, k in zip(inputs.holdout_device_classes, keep) if k]
            rep = cp.coverage_report(cand, y, dcs)
            metrics["conformal"] = rep
            target = 1.0 - cp.alpha - cfg.coverage_tolerance
            for lab in (BENIGN, MALICIOUS):
                c = rep["label_conditional"][lab]
                if c["n"] and c["coverage"] is not None and c["coverage"] < target:
                    failed.append(f"conformal_coverage_below_target:{lab}")
            if rep["abstain_rate"] is not None and rep["abstain_rate"] > cfg.max_abstain_rate:
                failed.append("conformal_abstain_rate_exceeds_limit")
        # ---- drift (acknowledgeable)
        if inputs.drift is None:
            failed.append("drift_unknown:report_missing")
        else:
            d = inputs.drift
            metrics["drift"] = {"status": d.status, "alerts": list(d.alerts), "warnings": list(d.warnings),
                                "windows": d.windows, "unmeasured": list(d.unmeasured),
                                "reference_id": d.reference_id}
            for a in d.alerts:
                failed.append(("drift_unknown:" if a.startswith("insufficient_windows") else "drift_detected:") + a)
            if "score" in d.unmeasured:
                failed.append("drift_unknown:score")
            if cfg.block_on_drift_warn:
                failed.extend(f"drift_detected:{w}" for w in d.warnings if w != "calibration_unmeasured")
        if inputs.novelty_alpha is not None:
            rate = inputs.recent_novelty_rate
            metrics["novelty"] = {"recent_rate": finite_or_none(rate), "alpha": inputs.novelty_alpha,
                                  "limit": inputs.novelty_alpha * cfg.max_novelty_rate_factor}
            if rate is None:
                failed.append("drift_unknown:novelty")
            elif rate > inputs.novelty_alpha * cfg.max_novelty_rate_factor:
                failed.append("drift_detected:novelty_rate")
        failed = list(dict.fromkeys(failed))
        blocking = tuple(f for f in failed if not acknowledgeable(f))
        ack = tuple(f for f in failed if acknowledgeable(f))
        digest = sha256_hex({
            "labels": [int(v) for v in y_all], "candidate": [round(float(v), 9) for v in cand_all],
            "champion": None if inputs.champion_scores is None
            else [round(float(v), 9) for v in inputs.champion_scores],
            "drift": None if inputs.drift is None else inputs.drift.to_dict(),
            "conformal": None if inputs.conformal is None else inputs.conformal.conformal_id,
            "novelty": [finite_or_none(inputs.recent_novelty_rate), inputs.novelty_alpha],
        })
        return GateDecision(allowed=not failed, failed_checks=tuple(failed), blocking_checks=blocking,
                            acknowledgeable_checks=ack, metrics=metrics, gate_id=cfg.gate_id, gate=cfg.describe(),
                            candidate_model_id=inputs.candidate_model_id,
                            champion_model_id=inputs.champion_model_id, evaluated_at=self.clock(),
                            inputs_sha256=digest)

    def evaluate_models(self, candidate: Any, champion: Any | None, holdout: Sequence[FeatureVector],
                        holdout_labels: Iterable[Any], recent: Sequence[FeatureVector], *,
                        reference: DriftReference | None, conformal: MondrianConformal | None = None,
                        novelty: NoveltyDetector | None = None,
                        thresholds: DriftThresholds | None = None,
                        recent_labels: Iterable[Any] | None = None) -> GateDecision:
        """Convenience wrapper scoring :class:`TrainedModel` objects.

        ``reference`` is the candidate's drift reference (built from its training
        windows); without it the drift check is ``drift_unknown:report_missing``.
        """
        labels = list(holdout_labels)
        cand_scores = candidate.predict_many(holdout)
        drift = None
        if reference is not None:
            if reference.model_id and reference.model_id != candidate.model_id:
                raise AssuranceError("drift reference belongs to a different model")
            drift = DriftMonitor(reference, thresholds).evaluate(
                recent, scores=candidate.predict_many(recent) if recent else [], labels=recent_labels)
        return self.evaluate(PromotionInputs(
            holdout_labels=labels, candidate_scores=cand_scores, candidate_model_id=candidate.model_id,
            candidate_calibration_id=candidate.calibration_id,
            champion_scores=None if champion is None else champion.predict_many(holdout),
            champion_model_id=None if champion is None else champion.model_id,
            holdout_device_classes=[fv.device_class for fv in holdout], drift=drift, conformal=conformal,
            recent_novelty_rate=novelty.novelty_rate(recent) if novelty is not None else None,
            novelty_alpha=novelty.alpha if novelty is not None else None))


__all__ = ["ACKNOWLEDGEABLE_PREFIXES", "AssuranceGate", "AssuranceGateConfig", "GateDecision", "PromotionBlocked",
           "PromotionInputs", "acknowledgeable"]
