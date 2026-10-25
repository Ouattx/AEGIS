"""Pre-registered fusion policy with mandatory ABSTAIN (spec section 4).

Heterogeneous scores are never averaged. Each component answers a different
question and the policy is an ordered list of rules over them, fixed *before*
evaluation and identified by :attr:`FusionPolicy.policy_hash` (recorded on every
finding so a decision can be replayed against the exact policy):

==== ==================================================================== ===========
rule condition                                                              verdict
==== ==================================================================== ===========
F0   insufficient context (too few events / coverage / features)            ABSTAIN
F1   strong IOC hit and (>= 2 independent origins, or model >= suspicious,  MALICIOUS
     or anomaly/change-point corroboration)
F2   strong IOC hit alone                                                   SUSPICIOUS
F2b  model >= suspicious, not yet persistent, no weak IOC hit               ABSTAIN
F2c  model >= suspicious, no weak IOC hit, tenant population below the      ABSTAIN
     model's validated minimum
F3   model >= malicious and anomaly corroboration                           SUSPICIOUS
F4   model >= malicious                                                     SUSPICIOUS
F5   weak (contradicted / lookup-only / low-confidence) IOC + model >= sus. SUSPICIOUS
F6   model >= suspicious and anomaly/change-point corroboration             SUSPICIOUS
F7   weak IOC hit without behavioral corroboration                          ABSTAIN
F8   model >= suspicious alone                                              ABSTAIN
F9   no supervised model available and no IOC hit                           ABSTAIN
F10  model < benign threshold and no IOC hit                                BENIGN
F11  anything else (model between benign and suspicious)                    ABSTAIN
==== ==================================================================== ===========

Model-driven rules (F3, F4, F6) additionally need the model to stay above the
suspicious threshold for ``min_model_persistence`` consecutive windows of the entity:
malware is persistent, a device being switched on is a one-window spike.

They also need the window's tenant population (active devices of the tenant in that
window) to be at least ``min_model_population``, the smallest population the model was
trained and validated on (from its model card). Population-relative features
(destination prevalence, rarity) do not transfer to smaller tenants, so a model-only
verdict there is outside the model's validated envelope and abstains (F2c) instead.
Rules where an indicator carries the evidence (F1, F2, F5) are unaffected. With
``min_model_population`` set and the population unknown, the guard fails closed.

A *strong* IOC hit is a verified contact (traffic actually sent to the indicator)
with a fresh, uncontradicted indicator of effective confidence >= ``strong_ioc``.
Any counter-evidence (a contradicting feed) downgrades MALICIOUS to SUSPICIOUS.
Anomaly and change-point never produce a positive verdict on their own: they only
corroborate. A change point (e.g. a device being switched on) is weak context, so it
can corroborate an indicator hit (F1) or support SUSPICIOUS (F6), but a model-only
escalation (F3) needs the behavior to be unusual for its device class. The device
class itself is not an input of this function.

MALICIOUS is reserved for outcomes that already meet the case verification rule
(a verified signed-indicator contact, F1): the model, the anomaly detector and the
change-point monitor all read the same operator telemetry, a single origin, so their
agreement (F3) is capped at SUSPICIOUS. No one is judged on a single source.

Every MALICIOUS / SUSPICIOUS / ABSTAIN outcome ``requires_review`` (shadow mode).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Sequence

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import Evidence, EvidenceKind, FeatureVector, Verdict
from aegis.provenance.evidence import independent_origins
from aegis.sentinel.anomaly import AnomalyScore, ChangePoint

#: features whose availability defines "enough behavioral context"
CONTEXT_FEATURES = ("flow_rate_h", "bytes_out_rate_log", "unique_dst_ip", "dst_entropy", "tcp_frac",
                    "small_flow_frac", "dns_rate_h", "nxdomain_rate", "interval_p50_log", "active_bin_frac")


@dataclass(frozen=True)
class FusionPolicy:
    policy_id: str = "sentinel-fusion/3"
    min_events: int = 20
    min_coverage_h: float = 1.0
    min_context_features: int = 4
    strong_ioc: float = 0.7
    ml_malicious: float = 0.9
    ml_suspicious: float = 0.6
    ml_benign: float = 0.3
    anomaly_corroborate: float = 0.95
    min_model_persistence: int = 2
    #: smallest tenant population (active devices per window) model-only rules may act on;
    #: None = no population guard (the detector fills it in from the model card)
    min_model_population: int | None = None

    @property
    def policy_hash(self) -> str:
        return sha256_hex(asdict(self))

    def __post_init__(self) -> None:
        if not 0.0 <= self.ml_benign <= self.ml_suspicious <= self.ml_malicious <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= benign <= suspicious <= malicious <= 1")
        if self.min_model_population is not None and self.min_model_population < 1:
            raise ValueError("min_model_population must be >= 1")

    def population_validated(self, population: int | None) -> bool:
        """Is the model validated for a tenant window with ``population`` active devices?"""
        if self.min_model_population is None:
            return True
        return population is not None and population >= self.min_model_population


DEFAULT_FUSION_POLICY = FusionPolicy()


@dataclass(frozen=True)
class MLScore:
    probability: float
    calibration_id: str | None
    model_id: str
    #: consecutive windows (including this one) of the entity at or above the suspicious
    #: threshold; 1 when not tracked (a bare score is treated as a single window)
    persistence: int = 1

    def __post_init__(self) -> None:
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError("probability must be in [0, 1]")


@dataclass
class FusionResult:
    verdict: Verdict
    score: float
    calibration_id: str | None        # set only when ``score`` is a calibrated probability
    requires_review: bool
    rule: str
    reasons: list[str]
    signal: bool                      # some component carries a malicious signal
    component_scores: dict[str, float | None]
    policy_id: str
    policy_hash: str
    strong_hits: list[Evidence] = field(default_factory=list)
    weak_hits: list[Evidence] = field(default_factory=list)
    counter: list[Evidence] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "score": self.score, "calibration_id": self.calibration_id,
                "requires_review": self.requires_review, "rule": self.rule, "reasons": list(self.reasons),
                "signal": self.signal, "component_scores": dict(self.component_scores),
                "policy_id": self.policy_id, "policy_hash": self.policy_hash}


def format_probability(p: float) -> str:
    """Human-facing calibrated probability: never "1.00" (see the calibration ceiling)."""
    return ">0.99" if p >= 0.99 else (f"{p:.2f}" if p >= 0.01 else "<0.01")


def _eff(e: Evidence) -> float:
    return float(e.payload.get("effective_confidence", 0.0))


def is_strong_hit(e: Evidence, policy: FusionPolicy = DEFAULT_FUSION_POLICY) -> bool:
    return (e.supports and e.kind == EvidenceKind.IOC_MATCH and bool(e.payload.get("verified_contact"))
            and not e.payload.get("contradicted") and _eff(e) >= policy.strong_ioc)


def fusion_policy(rule_hits: Sequence[Evidence], ml: MLScore | float | None, anomaly: AnomalyScore | None,
                  changepoint: Sequence[ChangePoint] | ChangePoint | None, fv: FeatureVector,
                  policy: FusionPolicy = DEFAULT_FUSION_POLICY, *, population: int | None = None) -> FusionResult:
    """Apply the pre-registered rules (module docstring) to one window.

    ``population`` is the number of active devices of the tenant in this window.
    """
    if isinstance(ml, (int, float)):
        ml = MLScore(float(ml), None, "unknown")
    cps: list[ChangePoint] = ([changepoint] if isinstance(changepoint, ChangePoint)
                              else list(changepoint or []))
    supporting = [e for e in rule_hits if e.supports and e.kind == EvidenceKind.IOC_MATCH]
    counter = [e for e in rule_hits if not e.supports]
    strong = [e for e in supporting if is_strong_hit(e, policy)]
    weak = [e for e in supporting if e not in strong]
    origins = independent_origins(strong, supporting_only=True)
    ml_p = ml.probability if ml is not None else None
    anomaly_hi = anomaly is not None and anomaly.percentile >= policy.anomaly_corroborate
    corroborated = anomaly_hi or bool(cps)
    components: dict[str, float | None] = {
        "ioc": max((_eff(e) for e in supporting), default=0.0),
        "ioc_independent_origins": float(origins),
        "ioc_counter_evidence": float(len(counter)),
        "ml": ml_p,
        "anomaly": anomaly.percentile if anomaly is not None else None,
        "changepoint": 1.0 if cps else 0.0,
    }
    reasons: list[str] = []
    if strong:
        reasons.append(f"verified contact with fresh indicator(s) from {origins} independent origin(s)")
    if weak:
        reasons.append(f"{len(weak)} weak indicator match(es) (contradicted, lookup-only or low confidence)")
    if counter:
        reasons.append(f"{len(counter)} contradicting feed assertion(s)")
    if ml_p is not None:
        reasons.append(f"calibrated model probability {format_probability(ml_p)}")
    if anomaly_hi and anomaly is not None:
        reasons.append(f"behavior more unusual than {anomaly.percentile:.1%} of {anomaly.baseline} baseline windows")
    if cps:
        reasons.append("change point in " + ", ".join(sorted({c.metric for c in cps})))

    def result(verdict: Verdict, rule: str, score: float, calibrated: bool, why: str,
               signal: bool | None = None) -> FusionResult:
        if verdict == Verdict.MALICIOUS and counter:
            verdict = Verdict.SUSPICIOUS
            why += "; downgraded from MALICIOUS because a feed contradicts an indicator"
        sig = signal if signal is not None else verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        return FusionResult(
            verdict=verdict, score=float(min(1.0, max(0.0, score))),
            calibration_id=ml.calibration_id if (calibrated and ml is not None) else None,
            requires_review=verdict != Verdict.BENIGN, rule=rule, reasons=[why] + reasons, signal=sig,
            component_scores=components, policy_id=policy.policy_id, policy_hash=policy.policy_hash,
            strong_hits=strong, weak_hits=weak, counter=counter)

    ioc_score = max((_eff(e) for e in supporting), default=0.0)
    available = sum(1 for f in CONTEXT_FEATURES if fv.values.get(f) is not None and not fv.missing.get(f, False))
    coverage = fv.values.get("coverage_h")
    if fv.event_count < policy.min_events or (coverage is not None and coverage < policy.min_coverage_h) \
            or available < policy.min_context_features:
        signal = bool(supporting) or (ml_p is not None and ml_p >= policy.ml_suspicious)
        return result(Verdict.ABSTAIN, "F0_insufficient_context", max(ioc_score, ml_p or 0.0), False,
                      f"insufficient context ({fv.event_count} events, {available} context features)", signal)
    ml_sus = ml_p is not None and ml_p >= policy.ml_suspicious
    ml_mal = ml_p is not None and ml_p >= policy.ml_malicious
    persistent = ml is not None and ml.persistence >= policy.min_model_persistence
    population_ok = policy.population_validated(population)
    if strong:
        if origins >= 2 or ml_sus or corroborated:
            if ml_sus:
                return result(Verdict.MALICIOUS, "F1_ioc_corroborated", ml_p or 0.0, True,
                              "fresh indicator contact corroborated by the supervised model")
            return result(Verdict.MALICIOUS, "F1_ioc_corroborated", ioc_score, False,
                          "fresh indicator contact corroborated by independent evidence")
        return result(Verdict.SUSPICIOUS, "F2_ioc_only", ioc_score, False,
                      "fresh indicator contact without behavioral corroboration")
    if ml_sus and not persistent and not weak:
        return result(Verdict.ABSTAIN, "F2b_model_not_persistent", ml_p or 0.0, True,
                      f"elevated model probability in {ml.persistence if ml else 0} consecutive window(s) only "
                      f"(needs {policy.min_model_persistence})", True)
    if ml_sus and not population_ok and not weak:
        seen = f"{population} active devices" if population is not None else "an unknown population"
        return result(Verdict.ABSTAIN, "F2c_population_unvalidated", ml_p or 0.0, True,
                      f"elevated model probability, but the tenant window has {seen} and the model is "
                      f"validated for {policy.min_model_population} or more", True)
    if ml_mal and anomaly_hi and population_ok:
        # model and anomaly both derive from the operator's own telemetry (one origin):
        # never MALICIOUS on that alone
        return result(Verdict.SUSPICIOUS, "F3_model_corroborated", ml_p or 0.0, True,
                      "high model probability corroborated by per-class anomaly (single telemetry origin)")
    if ml_mal and population_ok:
        return result(Verdict.SUSPICIOUS, "F4_model_only", ml_p or 0.0, True, "high model probability")
    if weak and ml_sus:
        return result(Verdict.SUSPICIOUS, "F5_weak_ioc_and_model", ml_p or 0.0, True,
                      "weak indicator match with elevated model probability")
    if ml_sus and corroborated and population_ok:
        return result(Verdict.SUSPICIOUS, "F6_model_and_anomaly", ml_p or 0.0, True,
                      "elevated model probability corroborated by anomaly/change-point")
    if weak:
        return result(Verdict.ABSTAIN, "F7_weak_ioc_only", ioc_score, False,
                      "indicator match is contradicted or unverified and behavior does not corroborate it",
                      True)
    if ml_sus:
        return result(Verdict.ABSTAIN, "F8_model_uncorroborated", ml_p or 0.0, True,
                      "elevated model probability without corroboration", True)
    if ml_p is None:
        return result(Verdict.ABSTAIN, "F9_no_model", 0.0, False,
                      "no supervised model loaded and no indicator matched", False)
    if ml_p < policy.ml_benign:
        return result(Verdict.BENIGN, "F10_benign", ml_p, True, "low model probability and no indicator match",
                      False)
    return result(Verdict.ABSTAIN, "F11_uncertain", ml_p, True, "model probability in the uncertain band",
                  False)


__all__ = ["CONTEXT_FEATURES", "DEFAULT_FUSION_POLICY", "FusionPolicy", "FusionResult", "MLScore",
           "format_probability", "fusion_policy", "is_strong_hit"]
