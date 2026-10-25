from __future__ import annotations

import json

import numpy as np
import pytest

from aegis.assurance import POOLED, AssuranceError, MondrianConformal, nonconformity


def synth(n: int, seed: int, pos_rate: float = 0.1, classes=("a", "b", "c")):
    """Scores from a noisy but informative detector, with class-dependent behavior."""
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < pos_rate).astype(int)
    dc = rng.choice(classes, size=n)
    shift = np.where(dc == "b", 0.15, 0.0)
    s = np.where(y == 1, rng.beta(5, 2, n), rng.beta(1.5, 6, n) + shift)
    return np.clip(s, 0, 1), y, list(dc)


def test_nonconformity():
    assert nonconformity(0.9, 1) == pytest.approx(0.1)
    assert nonconformity(0.9, 0) == pytest.approx(0.9)


@pytest.mark.parametrize("alpha", [0.05, 0.1, 0.2])
def test_label_conditional_coverage_guarantee_over_random_splits(alpha):
    s, y, dc = synth(6000, seed=1)
    rng = np.random.default_rng(2)
    covs = {("a", 0): [], ("a", 1): [], ("b", 0): [], ("b", 1): [], ("*", 0): [], ("*", 1): []}
    for _ in range(30):
        idx = rng.permutation(len(s))
        c, t = idx[:3000], idx[3000:]
        cp = MondrianConformal.fit(s[c], y[c], [dc[i] for i in c], alpha=alpha, min_stratum=30)
        rep = cp.coverage_report(s[t], y[t], [dc[i] for i in t])
        for (cls, lab) in covs:
            cell = (rep["label_conditional"] if cls == "*" else rep["per_device_class"][cls])
            covs[(cls, lab)].append(cell[("benign", "malicious")[lab]]["coverage"])
    for key, vals in covs.items():
        # the guarantee holds in expectation over calibration draws
        assert np.mean(vals) >= 1 - alpha - 0.01, (key, np.mean(vals))


def test_outcomes_and_abstain():
    s, y, dc = synth(4000, seed=3)
    cp = MondrianConformal.fit(s, y, dc, alpha=0.1, min_stratum=30, model_id="m", calibration_id="c")
    hi, lo = cp.predict(0.999, "a"), cp.predict(0.001, "a")
    assert hi.prediction_set == ("malicious",) and hi.outcome == "malicious" and not hi.abstain
    assert lo.prediction_set == ("benign",) and lo.outcome == "benign"
    mid = cp.predict(0.55, "a", alpha=0.01)
    assert mid.outcome == "ambiguous" and mid.abstain and set(mid.prediction_set) == {"benign", "malicious"}
    assert 0 < mid.confidence <= 1 and mid.credibility == max(mid.p_values.values())
    d = hi.to_dict()
    assert d["prediction_set"] == ["malicious"] and d["alpha"] == 0.1


def test_empty_set_abstains():
    # benign calibration all ~0, malicious all ~1 => 0.5 conforms to neither
    s = np.r_[np.zeros(500), np.ones(500)]
    y = np.r_[np.zeros(500, int), np.ones(500, int)]
    cp = MondrianConformal.fit(s, y, ["a"] * 1000, alpha=0.1)
    p = cp.predict(0.5, "a")
    assert p.prediction_set == () and p.outcome == "empty" and p.abstain


def test_small_strata_fall_back_to_pooled_and_unknown_class():
    s, y, dc = synth(3000, seed=4, classes=("a", "b"))
    s = np.r_[s, [0.9, 0.1]]
    y = np.r_[y, [1, 0]]
    dc = dc + ["rare", "rare"]
    cp = MondrianConformal.fit(s, y, dc, alpha=0.1, min_stratum=50)
    assert cp.predict(0.9, "rare").strata == {"benign": POOLED, "malicious": POOLED}
    assert cp.predict(0.9, "never-seen").strata == {"benign": POOLED, "malicious": POOLED}
    assert cp.predict(0.9, None).strata["benign"] == POOLED
    assert cp.predict(0.9, "a").strata == {"benign": "a", "malicious": "a"}


def test_label_without_calibration_data_is_always_included():
    # no malicious calibration windows at all => malicious is never excluded => abstain, never "benign"
    s = np.random.default_rng(0).beta(1, 8, 500)
    cp = MondrianConformal.fit(s, np.zeros(500, int), ["a"] * 500, alpha=0.1)
    p = cp.predict(0.0, "a")
    assert "malicious" in p.prediction_set and p.p_values["malicious"] == 1.0
    assert p.abstain


def test_device_class_alone_never_yields_malicious():
    s, y, dc = synth(5000, seed=5)
    cp = MondrianConformal.fit(s, y, dc, alpha=0.1, min_stratum=30)
    for cls in ("a", "b", "c", "x"):
        assert cp.predict(0.0, cls).outcome == "benign"


def test_unlabelled_entries_ignored_and_validation():
    cp = MondrianConformal.fit([0.1, 0.9, 0.5], [0, 1, None], ["a", "a", "a"], alpha=0.5, min_stratum=1)
    assert cp.info["calibration_windows"] == 2
    with pytest.raises(AssuranceError):
        MondrianConformal.fit([0.1], [None], ["a"])
    with pytest.raises(AssuranceError):
        MondrianConformal.fit([0.1, 0.2], [0], ["a", "a"])
    with pytest.raises(AssuranceError):
        MondrianConformal.fit([1.5], [0], ["a"])
    with pytest.raises(AssuranceError):
        MondrianConformal.fit([0.5], [0], ["a"], alpha=0.0)
    with pytest.raises(AssuranceError):
        MondrianConformal.fit([0.5], [2], ["a"])
    with pytest.raises(AssuranceError):
        cp.predict_many([0.1, 0.2], ["a"])


def test_round_trip_and_id_stability():
    s, y, dc = synth(2000, seed=6)
    cp = MondrianConformal.fit(s, y, dc, alpha=0.1, min_stratum=20, model_id="m1", calibration_id="iso-1")
    d = json.loads(json.dumps(cp.to_dict()))
    cp2 = MondrianConformal.from_dict(d)
    assert cp2.conformal_id == cp.conformal_id
    probe = np.linspace(0, 1, 101)
    for a, b in zip(cp.predict_many(probe, ["b"] * 101), cp2.predict_many(probe, ["b"] * 101)):
        assert a == b
    bad = dict(d, format="other")
    with pytest.raises(AssuranceError):
        MondrianConformal.from_dict(bad)
    bad2 = json.loads(json.dumps(d))
    bad2["strata"][0]["counts"][0] = 0
    with pytest.raises(AssuranceError):
        MondrianConformal.from_dict(bad2)


def test_ties_are_handled_conservatively():
    # heavily discretized scores (like isotonic outputs) keep coverage
    rng = np.random.default_rng(9)
    levels = np.array([0.0, 0.001, 0.02, 0.4, 0.9, 1.0])
    y = (rng.random(8000) < 0.08).astype(int)
    s = np.where(y == 1, rng.choice(levels, 8000, p=[0.01, 0.01, 0.03, 0.05, 0.2, 0.7]),
                 rng.choice(levels, 8000, p=[0.85, 0.08, 0.04, 0.02, 0.01, 0.0]))
    cp = MondrianConformal.fit(s[:4000], y[:4000], ["a"] * 4000, alpha=0.1)
    rep = cp.coverage_report(s[4000:], y[4000:], ["a"] * 4000)
    assert rep["label_conditional"]["benign"]["coverage"] >= 0.88
    assert rep["label_conditional"]["malicious"]["coverage"] >= 0.85
