from __future__ import annotations

import random
from datetime import timedelta

import pytest

from aegis.sentinel.anomaly import (
    GLOBAL_BASELINE,
    ChangePointMonitor,
    CusumDetector,
    RobustAnomalyModel,
)
from test_sentinel_helpers import T0, make_fv


def population(device_class: str, n: int, seed: int = 1, **shift):
    rng = random.Random(seed)
    out = []
    for i in range(n):
        vals = {"flow_rate_h": rng.uniform(10, 30), "unique_dst_ip": rng.uniform(8, 16),
                "bytes_out_rate_log": rng.gauss(4.5, 0.2), "dst_entropy": rng.gauss(2.5, 0.2),
                "small_flow_frac": rng.uniform(0.1, 0.3), "rare_dst_frac": 0.0, "nxdomain_rate": 0.0}
        vals.update(shift)
        out.append(make_fv(vals, entity=f"p_{device_class}_{i}", device_class=device_class))
    return out


def test_typical_window_low_percentile_and_outlier_high():
    model = RobustAnomalyModel.fit(population("android_tv", 200))
    typical = model.score(make_fv({"flow_rate_h": 20, "unique_dst_ip": 12}, device_class="android_tv"))
    weird = model.score(make_fv({"rare_dst_frac": 0.9, "nxdomain_rate": 0.8, "unique_dst_ip": 400},
                                device_class="android_tv"))
    assert typical is not None and weird is not None
    assert typical.percentile < 0.9
    assert weird.percentile == 1.0
    assert {d.feature for d in weird.top} >= {"rare_dst_frac", "nxdomain_rate"}
    assert weird.baseline == "android_tv" and not weird.fallback
    assert weird.top[0].z == pytest.approx(20.0)        # clipped


def test_per_class_normalization():
    """A busy box is compared with boxes, not with phones."""
    boxes = population("android_tv", 100, flow_rate_h=150.0)
    phones = population("phone", 100, flow_rate_h=5.0)
    model = RobustAnomalyModel.fit(boxes + phones)
    busy_box = model.score(make_fv({"flow_rate_h": 150.0}, device_class="android_tv"))
    same_on_phone = model.score(make_fv({"flow_rate_h": 150.0}, device_class="phone"))
    assert busy_box.percentile < same_on_phone.percentile


def test_unknown_class_falls_back_to_global_baseline():
    model = RobustAnomalyModel.fit(population("android_tv", 50))
    s = model.score(make_fv(device_class="toaster"))
    assert s is not None and s.baseline == GLOBAL_BASELINE and s.fallback


def test_small_class_has_no_own_baseline():
    model = RobustAnomalyModel.fit(population("android_tv", 50) + population("camera", 5))
    assert "camera" not in model.baselines
    assert model.score(make_fv(device_class="camera")).baseline == GLOBAL_BASELINE


def test_no_baseline_or_no_features_is_missing_not_zero():
    assert RobustAnomalyModel().score(make_fv()) is None
    model = RobustAnomalyModel.fit(population("android_tv", 50))
    empty = make_fv({k: None for k in ("flow_rate_h", "dns_rate_h", "bytes_out_rate_log", "bytes_in_rate_log",
                                       "out_ratio", "unique_dst_ip", "dst_entropy", "small_flow_frac",
                                       "zero_reply_frac", "peak_out_pps_log", "nxdomain_rate", "nx_unique",
                                       "active_bin_frac", "out_heavy_bin_frac", "rare_dst_frac",
                                       "rare_qname_frac")})
    assert model.score(empty) is None


def test_roundtrip_serialization():
    model = RobustAnomalyModel.fit(population("android_tv", 80) + population("phone", 80, seed=3))
    clone = RobustAnomalyModel.from_dict(model.to_dict())
    fv = make_fv({"rare_dst_frac": 0.4}, device_class="phone")
    assert clone.score(fv) == model.score(fv)
    with pytest.raises(ValueError):
        RobustAnomalyModel.from_dict({"kind": "other"})


def test_reference_is_subsampled():
    model = RobustAnomalyModel.fit(population("android_tv", 300), reference_points=101)
    assert len(model.baselines["android_tv"].reference) == 101


# ------------------------------------------------------------------ CUSUM

def test_cusum_detects_step_up_once_then_rebaselines():
    rng = random.Random(4)
    det = CusumDetector(k=0.5, h=6.0, warmup=12)
    alarms = []
    for i in range(80):
        x = rng.gauss(1.0, 0.1) + (2.0 if i >= 40 else 0.0)
        a = det.update(x)
        if a:
            alarms.append((i, a))
    assert len(alarms) == 1
    i, (direction, stat, mean, scale) = alarms[0]
    assert direction == "up" and 40 <= i <= 45 and stat > 6.0 and mean == pytest.approx(1.0, abs=0.1)


def test_cusum_detects_step_down():
    det = CusumDetector(warmup=10, min_scale=0.1)
    res = [det.update(5.0) for _ in range(10)] + [det.update(3.0) for _ in range(10)]
    assert [r[0] for r in res if r] == ["down"]


def test_cusum_quiet_on_stationary_noise():
    rng = random.Random(9)
    det = CusumDetector()
    assert not any(det.update(rng.gauss(2.0, 0.3)) for _ in range(500))


def test_cusum_needs_warmup():
    det = CusumDetector(warmup=12)
    for _ in range(11):
        assert det.update(1.0) is None
    assert not det.ready
    det.update(1.0)
    assert det.ready


def _fv_at(h: int, flows: float, entity: str = "p_dev1"):
    return make_fv({"recent_flows_log": flows, "recent_bytes_out_log": 4.0, "recent_unique_dst": 5.0},
                   entity=entity, window_end=T0 + timedelta(hours=h))


def test_monitor_reports_change_and_recent_horizon():
    mon = ChangePointMonitor(warmup=12, horizon=timedelta(hours=6))
    found = []
    for h in range(1, 40):
        found += mon.update(_fv_at(h, 1.0 if h < 20 else 3.0))
    assert len(found) == 1
    cp = found[0]
    assert cp.metric == "recent_flows_log" and cp.direction == "up" and cp.entity_pseudonym == "p_dev1"
    assert cp.as_dict()["direction"] == "up"
    assert mon.recent("t1", "p_dev1", cp.detected_at + timedelta(hours=1)) == [cp]
    assert mon.recent("t1", "p_dev1", cp.detected_at + timedelta(hours=7)) == []


def test_monitor_ignores_replayed_windows_and_missing_metrics():
    mon = ChangePointMonitor(warmup=3)
    mon.update(_fv_at(5, 1.0))
    assert mon.update(_fv_at(5, 9.0)) == [] and mon.update(_fv_at(4, 9.0)) == []
    fv = make_fv({"recent_flows_log": None, "recent_bytes_out_log": None, "recent_unique_dst": None},
                 window_end=T0 + timedelta(hours=6))
    assert mon.update(fv) == []


def test_monitor_prunes_idle_entities():
    mon = ChangePointMonitor()
    mon.update(_fv_at(1, 1.0, entity="p_a"))
    mon.update(_fv_at(200, 1.0, entity="p_b"))
    assert mon.prune(T0 + timedelta(hours=200)) == 1
