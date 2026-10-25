from __future__ import annotations

import json
from datetime import timedelta

import numpy as np
import pytest

from aegis.assurance import POOLED, AssuranceError, NoveltyDetector
from aegis.assurance.novelty import FeatureScaler
from test_assurance_helpers import population
from test_sentinel_helpers import T0, make_fv


@pytest.fixture(scope="module")
def ref():
    fvs, labels, _ = population(n_benign=120, n_mal=30, hours=24, seed=11)
    return fvs, labels


@pytest.fixture(scope="module")
def det(ref):
    return NoveltyDetector.fit(ref[0], alpha=0.02, min_entities=20, seed=3)


def test_in_distribution_false_novelty_rate_is_bounded(det):
    fresh, _, _ = population(n_benign=120, n_mal=30, hours=24, seed=99, prefix="x")
    rate = det.novelty_rate(fresh)
    # conformal guarantee: <= alpha for exchangeable new entities (small slack for finite samples)
    assert rate is not None and rate <= 0.02 + 0.02


def test_never_seen_behavior_is_novel(det):
    weird = [make_fv({"flow_rate_h": 5000.0, "unique_dst_ip": 4000.0, "zero_reply_frac": 0.95,
                      "nxdomain_rate": 0.9, "dst_entropy": 11.0, "rare_dst_frac": 0.5},
                     entity=f"p_new{i}", window_end=T0 + timedelta(hours=i)) for i in range(20)]
    res = det.score_many(weird)
    assert all(r.novel for r in res)
    r = res[0]
    assert r.p_value <= det.alpha and r.score >= r.threshold
    feats = {d.feature for d in r.top_deviations}
    assert feats & {"flow_rate_h", "unique_dst_ip", "zero_reply_frac", "nxdomain_rate", "dst_entropy"}
    assert sum(d.contribution for d in r.top_deviations) <= 1.0 + 1e-9
    d = r.to_dict()
    assert d["novel"] is True and len(d["top_deviations"]) <= 3


def test_missingness_pattern_counts(det):
    base = make_fv({"flow_rate_h": 30.0, "unique_dst_ip": 20.0, "dst_entropy": 2.0, "rare_dst_frac": 0.02,
                    "beacon_dst_prevalence": 0.2, "nxdomain_rate": 0.01})
    vals = {k: None for k in base.values}
    vals["coverage_h"] = 24.0
    hollow = make_fv(vals)
    assert det.score(hollow).score > det.score(base).score


def test_strata_and_fallback(det):
    assert POOLED in det.baselines
    assert det.stratum_for("never-seen") == POOLED
    assert det.stratum_for(None) == POOLED
    for st in det.baselines:
        assert np.all(np.diff(det.baselines[st].calibration) >= 0)


def test_threshold_matches_p_values(det):
    st = POOLED
    thr = det.threshold(st)
    cal = det.baselines[st].calibration
    n = len(cal)

    def p(s):
        return (1 + (cal >= s).sum()) / (n + 1)
    assert p(thr) <= det.alpha
    assert p(np.nextafter(thr, -np.inf)) > det.alpha or thr == cal.min()
    assert det.threshold(st, alpha=1e-9) == float("inf")


def test_round_trip_scores_identically(det, ref):
    d = json.loads(json.dumps(det.to_dict()))
    det2 = NoveltyDetector.from_dict(d)
    assert det2.novelty_id == det.novelty_id
    probe = ref[0][:50]
    assert [r.to_dict() for r in det.score_many(probe)] == [r.to_dict() for r in det2.score_many(probe)]
    with pytest.raises(AssuranceError):
        NoveltyDetector.from_dict(dict(d, format="x"))
    with pytest.raises(AssuranceError):
        NoveltyDetector.from_dict(dict(d, features=["a"]))


def test_fit_validation(ref):
    with pytest.raises(AssuranceError):
        NoveltyDetector.fit(ref[0][:5])
    with pytest.raises(AssuranceError):
        NoveltyDetector.fit(ref[0], calibration_fraction=0.95)
    one_entity = [make_fv({"flow_rate_h": float(i)}, entity="p_only", window_end=T0 + timedelta(hours=i))
                  for i in range(30)]
    with pytest.raises(AssuranceError):
        NoveltyDetector.fit(one_entity)
    with pytest.raises(AssuranceError):
        NoveltyDetector.fit(ref[0], k=0)
    assert NoveltyDetector.fit(ref[0], alpha=0.05).score_many([]) == []


def test_scaler_handles_constant_and_empty_columns():
    X = np.array([[1.0, np.nan, 5.0], [1.0, np.nan, 7.0], [1.0, np.nan, 9.0]])
    sc = FeatureScaler.fit(X)
    assert all(s > 0 for s in sc.scale)
    T = sc.transform(X)
    assert T.shape == (3, 6) and np.all(np.isfinite(T))
    assert np.all(T[:, 4] == sc.missing_weight)
    with pytest.raises(AssuranceError):
        FeatureScaler.from_dict({"median": [0.0], "scale": [0.0]})
