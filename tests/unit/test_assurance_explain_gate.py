from __future__ import annotations

import json
from datetime import datetime, timezone

import numpy as np
import pytest

from aegis.assurance import (
    AssuranceError,
    AssuranceGate,
    AssuranceGateConfig,
    DriftMonitor,
    DriftReference,
    Explainer,
    FeatureProfile,
    MondrianConformal,
    PromotionBlocked,
    PromotionInputs,
    acknowledgeable,
)
from aegis.sentinel.model import MODEL_FEATURES
from test_assurance_helpers import population, small_model
from test_sentinel_helpers import make_fv


@pytest.fixture(scope="module")
def ref():
    return population(n_benign=100, n_mal=20, hours=24, seed=31)


@pytest.fixture(scope="module")
def explainer(ref):
    fvs, labels, _ = ref
    return Explainer(small_model(), FeatureProfile.build(fvs, labels))


def malicious_fv():
    return make_fv({"rare_dst_frac": 0.8, "beacon_dst_prevalence": 0.01, "flow_rate_h": 30.0,
                    "unique_dst_ip": 20.0, "dst_entropy": 2.0, "nxdomain_rate": None})


# ----------------------------------------------------------------------------- explanations


def test_attributions_sum_to_raw_score_and_merge_missing(explainer):
    fv = malicious_fv()
    attr = explainer.attributions(fv)
    assert attr.expected_value + sum(a.contribution for a in attr.items) == pytest.approx(attr.raw_score, abs=1e-6)
    names = [a.feature for a in attr.items]
    assert all(n in MODEL_FEATURES for n in names) and len(names) == len(set(names))
    assert not any(n.startswith("missing__") for n in names)
    assert names[0] in ("rare_dst_frac", "beacon_dst_prevalence")
    nx = [a for a in attr.items if a.feature == "nxdomain_rate"]
    if nx:
        assert nx[0].missing and nx[0].value is None
    assert abs(attr.items[0].contribution) >= abs(attr.items[-1].contribution)
    many = explainer.attributions_many([fv, fv])
    assert many[0] == many[1] == attr


def test_reasons_are_readable(explainer):
    reasons = explainer.reasons(malicious_fv(), k=2)
    assert len(reasons) == 2
    top = reasons[0]
    assert top.direction == "raised" and "typical for benign windows" in top.text and "log-odds" in top.text
    assert top.text[0].isupper()
    assert "probability" not in top.text


def test_counterfactual_flips_to_benign_with_benign_values(explainer):
    m = small_model()
    fv = malicious_fv()
    p0, _ = m.predict(fv)
    assert p0 >= 0.5
    cf = explainer.counterfactual(fv, target=0.5)
    assert cf.found and 1 <= len(cf.changes) <= 3
    assert cf.new_score is not None and cf.new_score < 0.5
    prof = explainer.profile
    assert prof is not None
    for ch in cf.changes:
        assert ch.feature != "coverage_h"
        assert ch.to_value == prof.quantiles[ch.feature][ch.benign_quantile]
    # applying the changes really flips the model
    vals = dict(fv.values)
    for ch in cf.changes:
        vals[ch.feature] = ch.to_value
    p1, _ = m.predict(fv.model_copy(update={"values": vals}))
    assert p1 == pytest.approx(cf.new_score)
    assert "1.00" not in cf.text and "calibration" in cf.text
    d = cf.to_dict()
    assert "not evidence" in d["caveat"]
    json.dumps(d)


def test_counterfactual_bounded_and_honest(explainer):
    fv = malicious_fv()
    cf = explainer.counterfactual(fv, target=0.5, max_evaluations=1)
    assert not cf.found and cf.evaluations <= 1 and "budget" in cf.reason
    benign = make_fv({"rare_dst_frac": 0.0, "beacon_dst_prevalence": 0.4})
    cf2 = explainer.counterfactual(benign)
    assert not cf2.found and "already below" in cf2.reason
    none = Explainer(small_model(), None).counterfactual(fv)
    assert not none.found and "profile" in none.reason
    only_cov = Explainer(small_model(), explainer.profile, actionable=("unique_dst_ip",))
    cf3 = only_cov.counterfactual(fv, max_changes=1)
    assert not cf3.found  # unique_dst_ip alone does not explain the synthetic beaconing
    with pytest.raises(AssuranceError):
        Explainer(small_model(), None, actionable=("coverage_h",))
    with pytest.raises(AssuranceError):
        explainer.counterfactual(fv, target=1.5)


def test_profile_round_trip(ref):
    fvs, labels, _ = ref
    prof = FeatureProfile.build(fvs, labels)
    assert prof.windows == sum(1 for y in labels if y == 0)
    p2 = FeatureProfile.from_dict(json.loads(json.dumps(prof.to_dict())))
    assert p2.profile_id == prof.profile_id
    with pytest.raises(AssuranceError):
        FeatureProfile.build(fvs, [1] * len(fvs))
    with pytest.raises(AssuranceError):
        FeatureProfile.from_dict(dict(prof.to_dict(), format="x"))


# ----------------------------------------------------------------------------- promotion gate


def _inputs(ref, **kw):
    fvs, labels, _ = ref
    m = small_model()
    scores = m.predict_many(fvs)
    base = dict(holdout_labels=labels, candidate_scores=scores, candidate_model_id=m.model_id,
                candidate_calibration_id=m.calibration_id, champion_scores=scores, champion_model_id="champ")
    base.update(kw)
    return PromotionInputs(**base)


def _clean_drift(ref):
    fvs, labels, _ = ref
    m = small_model()
    reference = DriftReference.from_model(m, fvs, labels)
    return DriftMonitor(reference).evaluate(fvs, scores=m.predict_many(fvs))


def test_gate_passes_identical_candidate_without_drift(ref):
    gate = AssuranceGate(clock=lambda: datetime(2026, 10, 1, tzinfo=timezone.utc))
    dec = gate.evaluate(_inputs(ref, drift=_clean_drift(ref)))
    assert dec.allowed, dec.failed_checks
    dec.raise_if_blocked()
    assert dec.gate_id == AssuranceGateConfig().gate_id
    assert dec.to_dict()["evaluated_at"].startswith("2026-10-01")
    again = gate.evaluate(_inputs(ref, drift=_clean_drift(ref)))
    assert again.inputs_sha256 == dec.inputs_sha256


def test_gate_fails_closed_without_drift_report(ref):
    dec = AssuranceGate().evaluate(_inputs(ref))
    assert not dec.allowed and "drift_unknown:report_missing" in dec.failed_checks
    assert dec.blocking_checks == () and dec.allowed_with_acknowledgement()
    with pytest.raises(PromotionBlocked):
        dec.raise_if_blocked()
    dec.raise_if_blocked(acknowledge_drift=True)


def test_gate_blocks_regressions(ref):
    fvs, labels, _ = ref
    y = np.array(labels)
    m = small_model()
    good = m.predict_many(fvs)
    worse = np.where(y == 1, np.minimum(good, 0.3), good)              # loses recall
    noisy = np.where(y == 0, np.maximum(good, 0.7 * (np.arange(len(y)) % 7 == 0)), good)  # adds false alerts
    dec = AssuranceGate().evaluate(_inputs(ref, candidate_scores=worse, drift=_clean_drift(ref)))
    assert "recall_regression" in dec.blocking_checks
    dec2 = AssuranceGate().evaluate(_inputs(ref, candidate_scores=noisy, drift=_clean_drift(ref)))
    assert "false_positive_regression" in dec2.blocking_checks
    assert "calibration_error_exceeds_limit" in dec2.blocking_checks
    with pytest.raises(PromotionBlocked) as exc:
        dec2.raise_if_blocked(acknowledge_drift=True)
    assert "false_positive_regression" in exc.value.failed


def test_gate_drift_is_acknowledgeable_only(ref):
    fvs, labels, _ = ref
    m = small_model()
    reference = DriftReference.from_model(m, fvs, labels)
    shifted, _, _ = population(n_benign=100, n_mal=20, hours=24, seed=32, prefix="z", shift=300.0)
    drift = DriftMonitor(reference).evaluate(shifted, scores=m.predict_many(shifted))
    dec = AssuranceGate().evaluate(_inputs(ref, drift=drift))
    assert "drift_detected:feature_drift:flow_rate_h" in dec.acknowledgeable_checks
    assert not dec.blocking_checks
    assert all(acknowledgeable(c) for c in dec.acknowledgeable_checks)


def test_gate_conformal_and_binding_checks(ref):
    fvs, labels, _ = ref
    m = small_model()
    scores = m.predict_many(fvs)
    dcs = [fv.device_class for fv in fvs]
    other = MondrianConformal.fit(scores, labels, dcs, alpha=0.1, min_stratum=20, model_id="someone-else",
                                  calibration_id=m.calibration_id)
    dec = AssuranceGate().evaluate(_inputs(ref, drift=_clean_drift(ref), conformal=other,
                                           holdout_device_classes=dcs))
    assert "assurance_artifact_mismatch" in dec.blocking_checks
    assert "conformal" in dec.metrics
    # a predictor calibrated on over-confident (perfect) scores under-covers the real holdout
    rng = np.random.default_rng(0)
    wrong = MondrianConformal.fit(np.clip(np.array(labels, float) + rng.normal(0, 0.001, len(labels)), 0, 1),
                                  labels, dcs, alpha=0.1, min_stratum=20, model_id=m.model_id,
                                  calibration_id=m.calibration_id)
    softer = np.where(np.array(labels) == 1, 0.7, scores)       # candidate less sure than calibrated for
    dec2 = AssuranceGate().evaluate(_inputs(ref, drift=_clean_drift(ref), conformal=wrong, candidate_scores=softer,
                                            holdout_device_classes=dcs))
    assert any(c.startswith("conformal_coverage_below_target") for c in dec2.blocking_checks)
    with pytest.raises(AssuranceError):
        AssuranceGate().evaluate(_inputs(ref, conformal=wrong))


def test_gate_small_holdout_and_novelty(ref):
    fvs, labels, _ = ref
    m = small_model()
    s = m.predict_many(fvs[:50])
    dec = AssuranceGate().evaluate(PromotionInputs(holdout_labels=labels[:50], candidate_scores=s,
                                                   drift=_clean_drift(ref), recent_novelty_rate=0.2,
                                                   novelty_alpha=0.01))
    assert "holdout_too_small" in dec.blocking_checks
    assert "drift_detected:novelty_rate" in dec.acknowledgeable_checks
    dec2 = AssuranceGate().evaluate(PromotionInputs(holdout_labels=labels, candidate_scores=m.predict_many(fvs),
                                                    drift=_clean_drift(ref), recent_novelty_rate=None,
                                                    novelty_alpha=0.01))
    assert "drift_unknown:novelty" in dec2.failed_checks
    with pytest.raises(AssuranceError):
        AssuranceGate().evaluate(PromotionInputs(holdout_labels=labels, candidate_scores=s))
