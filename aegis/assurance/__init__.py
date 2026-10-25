"""Model assurance for SENTINEL: honest uncertainty, novelty, drift and explanations.

- :mod:`.conformal`: Mondrian (device class x label) split conformal prediction sets
  with a finite-sample coverage guarantee and abstain on ambiguous / empty sets
- :mod:`.novelty`: open-set detection (distance to the training manifold with a
  conformally calibrated threshold); never-seen behavior is ``novel``, not a known label
- :mod:`.drift`: feature PSI / KS / missingness, score shift and calibration (ECE) drift
- :mod:`.gate`: deterministic promotion gate that blocks promotion on drift or regression
- :mod:`.explain`: TreeSHAP attributions (LightGBM ``pred_contrib``), readable reasons,
  bounded counterfactuals over actionable features
- :mod:`.display`: safe score display (never exactly 1 or 0; calibration id stated)
- :mod:`.assess`: :class:`ModelAssurance` facade bound to one model, with signed artifacts

Nothing here calls a language model, and nothing here changes policy, models or
enforcement: assurance outputs are advisory and can only route work to a human.
"""
from aegis.assurance._common import BENIGN, LABELS, MALICIOUS, POOLED, AssuranceError, AssuranceMismatch
from aegis.assurance.assess import (
    ASSURANCE_FORMAT,
    ENTRY_TYPE_ASSURANCE,
    AssuranceIntegrityError,
    AssuranceOutcome,
    AssuranceReport,
    ModelAssurance,
)
from aegis.assurance.conformal import ConformalPrediction, MondrianConformal, nonconformity
from aegis.assurance.display import ScoreDisplay, display_score, format_score
from aegis.assurance.drift import (
    DriftMonitor,
    DriftReference,
    DriftReport,
    DriftThresholds,
    FeatureDrift,
    psi,
)
from aegis.assurance.explain import (
    DEFAULT_ACTIONABLE,
    NON_ACTIONABLE,
    Attribution,
    Attributions,
    Counterfactual,
    Explainer,
    FeatureChange,
    FeatureProfile,
    Reason,
)
from aegis.assurance.gate import (
    AssuranceGate,
    AssuranceGateConfig,
    GateDecision,
    PromotionBlocked,
    PromotionInputs,
    acknowledgeable,
)
from aegis.assurance.novelty import Deviation, NoveltyDetector, NoveltyResult

__all__ = [
    "ASSURANCE_FORMAT", "AssuranceError", "AssuranceGate", "AssuranceGateConfig", "AssuranceIntegrityError",
    "AssuranceMismatch", "AssuranceOutcome", "AssuranceReport", "Attribution", "Attributions", "BENIGN",
    "ConformalPrediction", "Counterfactual", "DEFAULT_ACTIONABLE", "Deviation", "DriftMonitor", "DriftReference",
    "DriftReport", "DriftThresholds", "ENTRY_TYPE_ASSURANCE", "Explainer", "FeatureChange", "FeatureDrift",
    "FeatureProfile", "GateDecision", "LABELS", "MALICIOUS", "ModelAssurance", "MondrianConformal",
    "NON_ACTIONABLE", "NoveltyDetector", "NoveltyResult", "POOLED", "PromotionBlocked", "PromotionInputs",
    "Reason", "ScoreDisplay", "acknowledgeable", "display_score", "format_score", "nonconformity", "psi",
]
