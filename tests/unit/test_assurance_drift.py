from __future__ import annotations

import json

import numpy as np
import pytest

from aegis.assurance import AssuranceError, DriftMonitor, DriftReference, DriftThresholds, psi
from test_assurance_helpers import population, small_model


@pytest.fixture(scope="module")
def data():
    return population(n_benign=100, n_mal=20, hours=24, seed=21)


@pytest.fixture(scope="module")
def reference(data):
    fvs, labels, _ = data
    return DriftReference.from_model(small_model(), fvs, labels)


def test_psi_basics():
    assert psi([0.5, 0.5], [0.5, 0.5]) == pytest.approx(0.0)
    assert psi([0.9, 0.1], [0.1, 0.9]) > 1.0
    assert psi([1.0, 0.0], [1.0, 0.0]) == pytest.approx(0.0, abs=1e-6)


def test_same_distribution_is_ok(reference):
    fresh, labels, _ = population(n_benign=100, n_mal=20, hours=24, seed=22, prefix="n")
    m = small_model()
    rep = DriftMonitor(reference).evaluate(fresh, scores=m.predict_many(fresh), labels=labels)
    assert rep.status in ("ok", "warn"), rep.alerts
    assert not rep.alerts
    assert rep.score["status"] == "ok"
    assert rep.calibration["status"] in ("ok", "alert")   # tiny synthetic model, reported either way
    assert rep.reference_id == reference.reference_id
    json.dumps(rep.to_dict())


def test_feature_shift_alerts(reference):
    shifted, _, _ = population(n_benign=100, n_mal=20, hours=24, seed=23, prefix="s", shift=200.0)
    rep = DriftMonitor(reference).evaluate(shifted, scores=small_model().predict_many(shifted))
    assert rep.status == "alert"
    assert "feature_drift:flow_rate_h" in rep.alerts
    assert "flow_rate_h" in rep.drifted_features()
    fd = next(f for f in rep.features if f.feature == "flow_rate_h")
    assert fd.psi is not None and fd.psi > 0.25 and fd.ks_d is not None and fd.ks_d > 0.5


def test_missingness_shift_alerts(reference, data):
    fvs = data[0]
    hollow = [fv.model_copy(update={"values": {**fv.values, "nxdomain_rate": None},
                                    "missing": {**fv.missing, "nxdomain_rate": True}}) for fv in fvs]
    rep = DriftMonitor(reference).evaluate(hollow)
    assert "feature_drift:nxdomain_rate" in rep.alerts
    fd = next(f for f in rep.features if f.feature == "nxdomain_rate")
    assert fd.missing_rate_cur == pytest.approx(1.0) and any("missing rate" in r for r in fd.reasons)


def test_score_and_calibration_drift(reference, data):
    fvs, labels, _ = data
    n = len(fvs)
    bad_scores = np.full(n, 0.95)
    rep = DriftMonitor(reference).evaluate(fvs, scores=bad_scores, labels=labels)
    assert "score_drift" in rep.alerts
    assert "calibration_drift" in rep.alerts
    assert rep.calibration["ece"] > 0.5


def test_insufficient_data_is_unknown_not_ok(reference, data):
    rep = DriftMonitor(reference).evaluate(data[0][:50])
    assert rep.status == "unknown"
    assert any(a.startswith("insufficient_windows") for a in rep.alerts)
    assert set(rep.unmeasured) == {"score", "calibration"}


def test_unlabelled_calibration_is_unmeasured(reference, data):
    fvs, labels, _ = data
    m = small_model()
    rep = DriftMonitor(reference).evaluate(fvs, scores=m.predict_many(fvs), labels=[None] * len(fvs))
    assert rep.calibration["status"] == "unknown" and "calibration" in rep.unmeasured
    assert "calibration_unmeasured" in rep.warnings


def test_thresholds_are_identified():
    assert DriftThresholds().thresholds_id == DriftThresholds().thresholds_id
    assert DriftThresholds(psi_alert=0.3).thresholds_id != DriftThresholds().thresholds_id


def test_reference_round_trip_and_validation(reference, data):
    d = json.loads(json.dumps(reference.to_dict()))
    r2 = DriftReference.from_dict(d)
    assert r2.reference_id == reference.reference_id
    rep1 = DriftMonitor(reference).evaluate(data[0])
    rep2 = DriftMonitor(r2).evaluate(data[0])
    assert rep1.to_dict() == rep2.to_dict()
    with pytest.raises(AssuranceError):
        DriftReference.from_dict(dict(d, format="nope"))
    with pytest.raises(AssuranceError):
        DriftReference.build([])
    with pytest.raises(AssuranceError):
        DriftReference.build(data[0], scores=[0.5])
    with pytest.raises(AssuranceError):
        DriftMonitor(reference).evaluate(data[0], scores=[0.5])
