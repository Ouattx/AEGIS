from __future__ import annotations

import json
import random
from datetime import date, timedelta

import numpy as np
import pytest

from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.model import (
    INPUT_NAMES,
    MODEL_FEATURES,
    InsufficientTrainingData,
    IsotonicCalibrator,
    ModelIntegrityError,
    SplitConfig,
    compute_metrics,
    expected_calibration_error,
    load,
    resolve_labels,
    split_indices,
    train,
    vectorize,
)
from test_sentinel_helpers import T0, make_fv

FAST = {"num_leaves": 7, "min_data_in_leaf": 10}


def synthetic(n_benign=90, n_mal=24, hours=48, seed=3):
    rng = random.Random(seed)
    fvs, labels, groups = [], [], {}
    classes = ["android_tv", "smart_tv", "phone", "camera"]
    for i in range(n_benign + n_mal):
        mal = i >= n_benign
        ent = f"p_{'m' if mal else 'b'}{i:03d}"
        if mal:
            groups[ent] = f"campaign-{i % 8}"
        infected_h = rng.randint(0, hours // 2) if mal else None
        for h in range(1, hours + 1):
            on = mal and h > infected_h
            vals = {
                "rare_dst_frac": rng.uniform(0.2, 0.9) if on else max(0.0, rng.gauss(0.02, 0.05)),
                "beacon_dst_prevalence": rng.uniform(0.0, 0.05) if on else rng.uniform(0.03, 0.6),
                "flow_rate_h": rng.uniform(5, 80),
                "unique_dst_ip": rng.uniform(3, 50),
                "nxdomain_rate": None if rng.random() < 0.2 else rng.uniform(0, 0.05),
            }
            fvs.append(make_fv(vals, entity=ent, device_class=classes[i % 4], window_end=T0 + timedelta(hours=h)))
            labels.append(1 if on else 0)
    return fvs, labels, groups


@pytest.fixture(scope="module")
def data():
    return synthetic()


@pytest.fixture(scope="module")
def model(data):
    fvs, labels, groups = data
    return train(fvs, labels, seed=7, groups=groups, params=FAST, rounds=60, dataset_info={"source": "synthetic"})


def test_vectorize_nan_and_missing_flags():
    fv = make_fv({"nxdomain_rate": None, "flow_rate_h": 3.0})
    row = vectorize(fv)
    assert row.shape == (len(INPUT_NAMES),)
    i = MODEL_FEATURES.index("nxdomain_rate")
    assert np.isnan(row[i])
    assert row[INPUT_NAMES.index("missing__nxdomain_rate")] == 1.0
    assert row[INPUT_NAMES.index("missing__flow_rate_h")] == 0.0
    assert "ioc_contacts" not in INPUT_NAMES and "device_class" not in INPUT_NAMES


def test_split_is_time_forward_and_group_isolated(data):
    fvs, labels, groups = data
    tr, te, desc = split_indices(fvs, labels, groups, SplitConfig(), seed=7)
    cutoff = max(fvs[i].window_end for i in tr)
    assert all(fvs[i].window_end >= cutoff for i in te)
    g = lambda i: groups.get(fvs[i].entity_pseudonym, fvs[i].entity_pseudonym)  # noqa: E731
    assert not ({g(i) for i in tr} & {g(i) for i in te})
    assert not ({fvs[i].entity_pseudonym for i in tr} & {fvs[i].entity_pseudonym for i in te})
    assert desc["shared_entities"] == 0 and desc["shared_groups"] == 0 and desc["group_key"] == "campaign"
    assert desc["test_positive_windows"] > 0 and desc["train_positive_windows"] > 0


def test_train_produces_calibrated_model_and_card(model, data):
    card = model.card
    assert card["schema"] == "aegis.model_card/1" and card["model_id"] == model.model_id
    assert card["calibration"]["calibration_id"] == model.calibration_id.__str__()
    assert model.calibration_id.startswith("iso-")
    test = card["metrics"]["test"]
    for key in ("pr_auc", "roc_auc", "ece", "brier", "device_days", "base_rate_device_days", "operating_points"):
        assert key in test
    op = test["operating_points"]["0.60"]
    for key in ("window", "device_day", "false_alerts_per_10k_device_days", "per_device_class"):
        assert key in op
    assert set(op["per_device_class"]) <= {"android_tv", "smart_tv", "phone", "camera"}
    assert op["device_day"]["precision"] is not None and op["device_day"]["recall"] is not None
    assert test["pr_auc"] > 0.9
    assert test["ece"] < 0.1
    assert "bootstrap_ci95" in test
    assert card["features"]["excluded"]["device_class"]
    assert "ioc_contacts" in card["features"]["excluded"]
    assert card["split"]["shared_entities"] == 0
    assert card["data"]["source"] == "synthetic"
    assert model.anomaly is not None


def test_predict_is_probability_and_separates(model):
    p_mal, cal = model.predict(make_fv({"rare_dst_frac": 0.8, "beacon_dst_prevalence": 0.01}))
    p_ben, _ = model.predict(make_fv({"rare_dst_frac": 0.0, "beacon_dst_prevalence": 0.4}))
    assert 0.0 <= p_ben < 0.2 < 0.8 < p_mal <= 1.0
    assert cal == model.calibration_id


def test_device_class_does_not_change_model_score(model):
    vals = {"rare_dst_frac": 0.5, "beacon_dst_prevalence": 0.04}
    scores = {model.predict(make_fv(vals, device_class=c))[0] for c in ("android_tv", "phone", "unknown", "x")}
    assert len(scores) == 1


def test_explain_returns_top_contributions(model):
    ex = model.explain(make_fv({"rare_dst_frac": 0.8}), top=3)
    assert len(ex) <= 3 and ex[0]["feature"] in INPUT_NAMES
    assert abs(ex[0]["contribution"]) >= abs(ex[-1]["contribution"])


def test_save_load_roundtrip_identical_predictions(model, data, tmp_path):
    fvs = data[0][:200]
    model.save(tmp_path / "m")
    clone = load(tmp_path / "m")
    assert clone.model_id == model.model_id and clone.calibration_id == model.calibration_id
    assert np.allclose(clone.predict_many(fvs), model.predict_many(fvs))
    assert clone.card["model_id"] == model.model_id
    assert clone.anomaly is not None
    manifest = json.loads((tmp_path / "m" / "manifest.json").read_text())
    assert set(manifest["files"]) == {"booster.txt", "calibration.json", "model_card.json", "anomaly.json"}
    assert not list((tmp_path / "m").glob("*.pkl"))


def test_tampered_artifact_rejected(model, tmp_path):
    d = model.save(tmp_path / "m")
    cal = json.loads((d / "calibration.json").read_text())
    cal["y"] = [1.0 for _ in cal["y"]]
    (d / "calibration.json").write_text(json.dumps(cal))
    with pytest.raises(ModelIntegrityError):
        load(d)


def test_missing_manifest_and_bad_format(model, tmp_path):
    with pytest.raises(ModelIntegrityError):
        load(tmp_path)
    d = model.save(tmp_path / "m")
    m = json.loads((d / "manifest.json").read_text())
    m["format"] = "other"
    (d / "manifest.json").write_text(json.dumps(m))
    with pytest.raises(ModelIntegrityError):
        load(d)


def test_signed_manifest(model, tmp_path):
    signer = Signer.generate("model-k1")
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    d = model.save(tmp_path / "signed", signer=signer)
    assert load(d, keyring=ring, require_signature=True).model_id == model.model_id
    with pytest.raises(ModelIntegrityError):
        load(d, keyring=KeyRing(), require_signature=True)
    other = KeyRing()
    other.add(signer.key_id, Signer.generate("model-k1").public_pem())
    with pytest.raises(ModelIntegrityError):
        load(d, keyring=other)
    unsigned = model.save(tmp_path / "unsigned")
    with pytest.raises(ModelIntegrityError):
        load(unsigned, keyring=ring, require_signature=True)


def test_training_is_deterministic(data):
    fvs, labels, groups = data
    a = train(fvs, labels, seed=11, groups=groups, params=FAST, rounds=30, fit_anomaly=False)
    b = train(fvs, labels, seed=11, groups=groups, params=FAST, rounds=30, fit_anomaly=False)
    assert a.model_id == b.model_id


def test_insufficient_data_raises():
    fvs, labels, groups = synthetic(n_benign=30, n_mal=2, hours=10)
    with pytest.raises(InsufficientTrainingData):
        train(fvs, labels, groups=groups, params=FAST, rounds=10)
    with pytest.raises(InsufficientTrainingData):
        train(fvs, [None] * len(fvs), params=FAST, rounds=10)


def test_resolve_labels_variants():
    fvs = [make_fv(entity="p_a", window_end=T0 + timedelta(hours=1)),
           make_fv(entity="p_b", window_end=T0 + timedelta(days=1))]
    assert resolve_labels(fvs, ["benign", "c2_beaconing"]) == [0, 1]
    assert resolve_labels(fvs, [0, None]) == [0, None]
    mapping = {("p_a", date(2026, 10, 1)): "benign", ("p_b", date(2026, 10, 1)): "ddos_bot"}
    assert resolve_labels(fvs, mapping) == [0, 1]      # window ending at midnight belongs to the previous day
    assert resolve_labels(fvs, lambda fv: 1 if fv.entity_pseudonym == "p_b" else 0) == [0, 1]
    with pytest.raises(ValueError):
        resolve_labels(fvs, [0])


def test_ece_and_metrics_on_known_values():
    y = np.array([0, 0, 1, 1])
    assert expected_calibration_error(y, np.array([0.0, 0.0, 1.0, 1.0])) == pytest.approx(0.0)
    assert expected_calibration_error(y, np.array([1.0, 1.0, 0.0, 0.0])) == pytest.approx(1.0)
    fvs = [make_fv(entity=f"p_{i}", device_class="phone" if i < 2 else "android_tv") for i in range(4)]
    m = compute_metrics(fvs, [0, 0, 1, 1], [0.1, 0.7, 0.95, 0.4], bootstrap=0)
    op = m["operating_points"]["0.60"]
    assert op["device_day"]["tp"] == 1 and op["device_day"]["fp"] == 1 and op["device_day"]["fn"] == 1
    assert op["false_alerts_per_10k_device_days"] == pytest.approx(2500.0)
    assert op["per_device_class"]["phone"]["false_alerts_per_10k_device_days"] == pytest.approx(5000.0)
    assert m["pr_auc"] is not None and m["device_days"] == 4


def test_isotonic_calibrator_roundtrip_and_validation():
    cal = IsotonicCalibrator.fit(np.array([-2.0, -1.0, 0.0, 1.0, 2.0]), np.array([0, 0, 1, 1, 1]))
    clone = IsotonicCalibrator.from_dict(cal.to_dict())
    assert clone.calibration_id == cal.calibration_id
    # three positives in the saturated top block: rule of succession (3 + 1) / (3 + 2) = 0.8
    assert cal.ceiling == pytest.approx(0.8)
    assert float(clone(5.0)) == pytest.approx(0.8) and float(clone(-5.0)) == pytest.approx(0.0)
    # artifacts without a recorded ceiling are capped at the default, never at certainty
    legacy = IsotonicCalibrator.from_dict({"method": "isotonic", "x": [0.0, 1.0], "y": [0.0, 1.0]})
    assert legacy.ceiling is None and float(legacy(9.0)) == pytest.approx(0.99)
    assert "ceiling" not in legacy.to_dict()
    with pytest.raises(ValueError):
        IsotonicCalibrator.from_dict({"method": "isotonic", "x": [0.0], "y": [0.0], "ceiling": 0.1})
    with pytest.raises(ValueError):
        IsotonicCalibrator.from_dict({"method": "isotonic", "x": [1.0, 0.0], "y": [0.0, 1.0]})
    with pytest.raises(ValueError):
        IsotonicCalibrator.from_dict({"method": "platt", "x": [0.0], "y": [0.0]})


def test_population_stability(model, data):
    fvs = data[0][:500]
    psi = model.population_stability(fvs)
    assert psi is not None and psi >= 0.0
    shifted = [make_fv({"rare_dst_frac": 0.9, "beacon_dst_prevalence": 0.01}, entity=f"p_s{i}") for i in range(200)]
    assert model.population_stability(shifted) > psi
