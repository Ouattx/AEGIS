"""SENTINEL: network detection (spec section 4) and compromised-device detection (section 7).

- :mod:`.features`: :class:`WindowStore` (hopping per-device windows, missingness-aware features)
- :mod:`.rules`: signed :class:`IOCBundle`, :func:`load_bundle`, :func:`ioc_match`
- :mod:`.model`: LightGBM + isotonic calibration, time-forward group-isolated :func:`train`, model card
- :mod:`.anomaly`: per-device-class :class:`RobustAnomalyModel`, CUSUM :class:`ChangePointMonitor`
- :mod:`.fusion`: pre-registered :func:`fusion_policy` with mandatory ABSTAIN
- :mod:`.detector`: streaming :class:`Sentinel` producing evidence-backed findings (no LLM)
- :mod:`.training`: lab-corpus datasets, default model build and end-to-end evaluation
"""
from aegis.sentinel.anomaly import AnomalyScore, ChangePoint, ChangePointMonitor, CusumDetector, RobustAnomalyModel
from aegis.sentinel.detector import SENTINEL_VERSION, Decision, DecisionRecord, EventRejected, Sentinel
from aegis.sentinel.features import FEATURE_DOCS, FEATURE_NAMES, ContactSummary, WindowStore
from aegis.sentinel.fusion import DEFAULT_FUSION_POLICY, FusionPolicy, FusionResult, MLScore, fusion_policy
from aegis.sentinel.model import (
    InsufficientTrainingData,
    ModelIntegrityError,
    SplitConfig,
    TrainedModel,
    compute_metrics,
    default_model_dir,
    load,
    load_default,
    train,
)
from aegis.sentinel.rules import BundleError, BundleSignatureError, Indicator, IOCBundle, ioc_match, load_bundle

__all__ = [
    "AnomalyScore", "BundleError", "BundleSignatureError", "ChangePoint", "ChangePointMonitor", "ContactSummary",
    "CusumDetector", "DEFAULT_FUSION_POLICY", "Decision", "DecisionRecord", "EventRejected", "FEATURE_DOCS",
    "FEATURE_NAMES", "FusionPolicy", "FusionResult", "IOCBundle", "Indicator", "InsufficientTrainingData",
    "MLScore", "ModelIntegrityError", "RobustAnomalyModel", "SENTINEL_VERSION", "Sentinel", "SplitConfig",
    "TrainedModel", "WindowStore", "compute_metrics", "default_model_dir", "fusion_policy", "ioc_match", "load",
    "load_bundle", "load_default", "train",
]
