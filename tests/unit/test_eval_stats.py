from __future__ import annotations

from datetime import date

import numpy as np
import pytest
from sklearn.metrics import average_precision_score

from eval.stats import (
    DeviceDayTable,
    GateConfig,
    SystemScores,
    average_precision,
    clopper_pearson,
    cluster_bootstrap,
    confusion,
    ppv_interval,
    pr_curve,
    project_prevalence,
    rates,
    release_gate,
    system_metrics,
)


def table(n_dev: int = 40, days: int = 2, pos_devices: int = 8) -> DeviceDayTable:
    keys, y, cls, lab, hn = [], [], [], [], []
    for i in range(n_dev):
        for d in range(days):
            keys.append((f"dev{i:03d}", date(2026, 10, 1 + d)))
            pos = i < pos_devices
            y.append(1 if pos else 0)
            cls.append("android_tv" if i % 2 else "phone")
            lab.append("c2_beaconing" if pos else "benign")
            hn.append(i == n_dev - 1)
    return DeviceDayTable(keys=keys, y=np.array(y), device_class=cls, label=lab, hard_negative=np.array(hn))


def test_confusion_and_rates():
    y = np.array([1, 1, 0, 0, 0])
    a = np.array([1, 0, 1, 0, 0], dtype=bool)
    c = confusion(y, a)
    assert c == {"tp": 1, "fp": 1, "fn": 1, "tn": 2}
    r = rates(c)
    assert r["precision"] == 0.5 and r["recall"] == 0.5 and r["f1"] == 0.5
    assert r["fpr"] == pytest.approx(1 / 3)
    assert r["false_alerts_per_10k"] == pytest.approx(2000.0)
    assert rates({"tp": 0, "fp": 0, "fn": 0, "tn": 0})["precision"] is None


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_average_precision_matches_sklearn_with_ties(seed):
    rng = np.random.default_rng(seed)
    y = rng.integers(0, 2, 300)
    s = np.round(rng.random(300), 1)  # many ties
    assert average_precision(y, s) == pytest.approx(average_precision_score(y, s))


def test_average_precision_degenerate():
    assert average_precision(np.zeros(5), np.ones(5)) is None
    assert average_precision(np.ones(5), np.ones(5)) is None


def test_pr_curve_shape():
    y = np.array([1, 0, 1, 0, 0, 1])
    s = np.array([0.9, 0.8, 0.7, 0.3, 0.2, 0.1])
    pts = pr_curve(y, s)
    assert pts[0][0] == 0.0 and pts[-1][0] == 1.0
    assert all(0 <= r <= 1 and 0 <= p <= 1 for r, p in pts)
    assert len(pr_curve(np.r_[y, y, y, y], np.r_[s, s + 1, s + 2, s + 3], max_points=5)) <= 6
    assert pr_curve(np.zeros(3), np.ones(3)) == []


def test_clopper_pearson():
    lo, hi = clopper_pearson(0, 100)
    assert lo == 0.0 and hi == pytest.approx(0.0362, abs=1e-3)
    lo, hi = clopper_pearson(10, 10)
    assert hi == 1.0 and lo == pytest.approx(0.6915, abs=1e-3)
    assert clopper_pearson(0, 0) is None


def test_system_metrics_breakdowns():
    t = table()
    alert = t.y.astype(bool).copy()
    alert[-1] = True  # hard-negative device-day alerted (false positive)
    first = {"dev000": 1.0, "dev001": 3.0}
    s = SystemScores("x", alert=alert, score=alert.astype(float), abstain=np.zeros(len(alert), bool),
                     first_alert_h=first)
    m = system_metrics(t, s, malicious_devices=8)
    assert (m["tp"], m["fp"], m["fn"]) == (16, 1, 0)
    assert m["hard_negative_device_days_alerted"] == 1
    assert m["per_device_class"]["android_tv"]["fp"] == 1
    assert m["per_label"]["c2_beaconing"]["recall"] == 1.0
    assert m["detection_delay_hours_median"] == 2.0
    assert m["malicious_devices_detected"] == 2
    assert m["abstain_only_device_days"] == 0
    assert m["recall_ci95_exact"][1] == 1.0


def test_cluster_bootstrap_and_paired_differences():
    t = table()
    perfect = SystemScores("good", alert=t.y.astype(bool), score=t.y.astype(float))
    half = t.y.astype(bool).copy()
    half[: 8] = False  # misses 4 devices (both days)
    worse = SystemScores("bad", alert=half, score=half.astype(float))
    boot = cluster_bootstrap(t, [perfect, worse], resamples=300, seed=3, reference="good")
    assert boot.ci["good"]["recall"] == (1.0, 1.0)
    lo, hi = boot.diff_ci["good - bad"]["recall"]
    assert lo > 0 and hi <= 1
    assert boot.diff_ci["good - bad"]["false_alerts_per_10k"] == (0.0, 0.0)
    again = cluster_bootstrap(t, [perfect, worse], resamples=300, seed=3, reference="good")
    assert again.diff_ci == boot.diff_ci
    with pytest.raises(ValueError):
        cluster_bootstrap(t, [perfect], resamples=0)


def test_release_gate_logic():
    t = table()
    good = SystemScores("ensemble", alert=t.y.astype(bool), score=t.y.astype(float))
    noisy_alert = np.ones(len(t.y), dtype=bool)
    noisy = SystemScores("static_blocklist", alert=noisy_alert, score=noisy_alert.astype(float))
    same = SystemScores("rules_only", alert=t.y.astype(bool), score=t.y.astype(float))
    boot = cluster_bootstrap(t, [good, noisy, same], resamples=200, seed=1, reference="ensemble")
    gate = release_gate(boot, GateConfig())
    by = {c["comparator"]: c for c in gate["comparisons"]}
    assert by["static_blocklist"]["passed"] and "false_alerts_per_10k" in by["static_blocklist"]["improved_metrics"]
    assert not by["rules_only"]["passed"]  # identical systems: no supported improvement
    assert gate["passed"] is False
    assert "privacy" in gate["not_assessed"]
    missing = release_gate(boot, GateConfig(comparators=("nonexistent",)))
    assert missing["comparisons"][0]["reasons"] == ["comparator not evaluated"]


def test_release_gate_rejects_false_alert_regression():
    t = table()
    noisy_alert = np.ones(len(t.y), dtype=bool)
    cand = SystemScores("ensemble", alert=noisy_alert, score=np.where(t.y == 1, 1.0, 0.5))
    base = SystemScores("rules_only", alert=t.y.astype(bool) & (np.arange(len(t.y)) % 4 == 0),
                        score=t.y.astype(float) * 0.5)
    boot = cluster_bootstrap(t, [cand, base], resamples=200, seed=1, reference="ensemble")
    gate = release_gate(boot, GateConfig(comparators=("rules_only",)))
    comp = gate["comparisons"][0]
    assert "recall" in comp["improved_metrics"]
    assert comp["passed"] is False and "exceeds limit" in comp["reasons"][1]


def test_prevalence_projection():
    p = project_prevalence(0.9, 0.001, 0.01, minutes_per_alert=30)
    assert p["ppv"] == pytest.approx(0.009 / (0.009 + 0.99 * 0.001))
    assert p["false_alerts_per_10k"] == pytest.approx(9.9)
    assert p["analyst_hours_per_10k"] == pytest.approx(1e4 * (0.009 + 0.00099) * 0.5)
    assert project_prevalence(None, 0.1, 0.01, minutes_per_alert=1)["ppv"] is None
    assert project_prevalence(0.0, 0.0, 0.01, minutes_per_alert=1)["ppv"] is None
    ci = ppv_interval(np.full(50, 0.9), np.full(50, 0.01), 0.05)
    assert ci is not None and ci[0] == pytest.approx(ci[1])
    assert ppv_interval(np.full(5, np.nan), np.full(5, 0.1), 0.05) is None


def test_table_validation_and_concat():
    t = table(4, 1, 1)
    both = DeviceDayTable.concat([t, t], ["a", "b"])
    assert len(both.keys) == 8 and len(both.devices) == 8
    with pytest.raises(ValueError):
        DeviceDayTable(keys=[("a", date(2026, 1, 1))], y=np.array([1, 0]), device_class=["x"], label=["b"],
                       hard_negative=np.array([False]))
