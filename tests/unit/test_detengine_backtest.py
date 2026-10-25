"""Backtesting: time-forward held-out device-day metrics, confidence intervals, overlap."""
from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.contracts.models import Finding, Verdict
from aegis.detengine import (
    BacktestConfig,
    Backtester,
    RuleSpec,
    alerts_from_findings,
    alerts_from_predicate,
    alerts_from_rules,
)
from aegis.detengine.backtest import clopper_pearson, summarize_reports, window_day
from test_detengine_support import T0, fv, synthetic_dataset

SPEC = RuleSpec.from_dict({"rule_id": "dga-nx", "title": "NX storm", "label": "dga_activity",
                           "conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}]})


@pytest.fixture(scope="module")
def ds():
    return synthetic_dataset()


def run(ds, **cfg):
    return Backtester().run(SPEC, ds, tenant_id="acme", actor="system:test", config=BacktestConfig(**cfg))


def test_time_forward_holdout_metrics(ds):
    r = run(ds)
    m = r.metrics
    assert r.holdout_start == T0 + timedelta(days=1)           # first third is reference data
    assert m.device_days == 46 * 2 and m.positive_device_days == 12 and m.negative_device_days == 80
    assert (m.tp, m.fp, m.fn, m.tn) == (12, 2, 0, 78)
    assert m.precision == pytest.approx(12 / 14)
    assert m.recall == 1.0
    assert m.false_alerts_per_10k == pytest.approx(2 / 80 * 10_000)
    assert m.hard_negative_device_days == 2 and m.hard_negative_alerts == 2
    assert m.abstain_only_device_days == 2                    # the device whose rate is missing
    assert m.windows_evaluated == 92 and m.windows_fired == 14 and m.windows_abstained == 2
    assert m.per_label["dga_activity"]["recall"] == 1.0
    assert set(m.per_device_class) == {"android_tv", "phone"}
    assert r.synthetic and any("synthetic" in n for n in r.notes)
    assert not r.sufficient and any("holdout too small" in n for n in r.notes)
    assert r.false_alert_examples[0]["hard_negative"] is True
    assert r.spec_sha256 == SPEC.sha256


def test_confidence_intervals(ds):
    m = run(ds, bootstrap=300, seed=3).metrics
    for point, iv in ((m.precision, m.precision_ci_exact), (m.recall, m.recall_ci_exact),
                      (m.false_alerts_per_10k, m.false_alerts_per_10k_ci_exact),
                      (m.precision, m.precision_ci_bootstrap), (m.false_alerts_per_10k,
                                                                m.false_alerts_per_10k_ci_bootstrap)):
        assert iv is not None and iv.low <= point <= iv.high
    assert m.recall_ci_exact.high == 1.0 and m.recall_ci_exact.low < 1.0
    # deterministic for a fixed seed
    assert run(ds, bootstrap=300, seed=3).metrics.precision_ci_bootstrap == m.precision_ci_bootstrap


def test_clopper_pearson_edges():
    assert clopper_pearson(0, 0) is None
    lo, hi = clopper_pearson(0, 50)
    assert lo == 0.0 and 0.0 < hi < 0.1
    lo, hi = clopper_pearson(50, 50)
    assert hi == 1.0 and 0.9 < lo < 1.0


def test_whole_dataset_and_exclusion(ds):
    full = run(ds, time_forward=False).metrics
    assert full.device_days == 46 * 3 and full.fp == 3 and full.tp == 12
    excl = run(ds, exclude_entities=frozenset({"p_m045"})).metrics
    assert excl.positive_device_days == 10 and excl.device_days == 90


def test_strict_windows_drop_windows_straddling_the_split(ds):
    shifted = synthetic_dataset()
    r = Backtester().run(SPEC, shifted, tenant_id="acme", actor="system:test",
                         config=BacktestConfig(split_at=T0 + timedelta(days=1, hours=6)))
    # day 1 starts before the split: excluded; only day 2 remains and its windows start after the split
    assert r.metrics.device_days == 46 and r.metrics.tp == 6


def test_overlap_with_existing_detectors(ds):
    day1 = (T0 + timedelta(days=1)).date()
    existing = {"sentinel": {("p_m040", day1), ("p_b005", day1)}, "empty": set()}
    r = Backtester().run(SPEC, ds, tenant_id="acme", actor="system:test", existing=existing)
    by = {o.detector: o for o in r.overlap}
    s = by["sentinel"]
    assert (s.detector_alerts, s.rule_alerts, s.shared_alerts) == (2, 14, 1)
    assert s.jaccard == pytest.approx(1 / 15)
    assert (s.rule_tp, s.rule_tp_also_detected, s.novel_tp) == (12, 1, 11)
    assert by["empty"].novel_tp == 12 and r.novel_tp_vs_all_existing == 11


def test_alert_set_helpers(ds):
    other = RuleSpec.from_dict({"rule_id": "nx-unique", "title": "t", "label": "dga_activity",
                                "conditions": [{"feature": "nx_unique", "op": "ge", "value": 100}]})
    assert len(alerts_from_rules(ds, [other])) == 6 * 2
    assert alerts_from_predicate(ds, lambda f, c: False) == set()
    f = Finding(tenant_id="bench", entity_pseudonym="p_m040", device_class="phone", detector_version="x",
                label="dga_activity", verdict=Verdict.SUSPICIOUS, score=0.5,
                observed_window_start=T0, observed_window_end=T0 + timedelta(days=1), created_at=T0,
                expires_at=T0 + timedelta(days=3))
    benign = f.model_copy(update={"verdict": Verdict.BENIGN})
    assert alerts_from_findings([f, benign]) == {("p_m040", T0.date())}
    assert window_day(fv(end=T0 + timedelta(days=1))) == T0.date()


def test_rule_window_mismatch_is_reported(ds):
    five = RuleSpec.from_dict({**SPEC.to_dict(), "window": "5m"})
    r = Backtester().run(five, ds, tenant_id="acme", actor="system:test")
    assert r.metrics.windows_evaluated == 0 and any("no window" in n for n in r.notes)


def test_summarize_reports(ds):
    a, b = run(ds), run(ds, time_forward=False)
    s = summarize_reports([a, b])
    assert s["tp"] == 24 and s["fp"] == 5 and s["synthetic_only"] is True
    assert summarize_reports([])["precision"] is None


def test_dataset_rejects_cross_tenant_windows():
    ds = synthetic_dataset()
    with pytest.raises(ValueError):
        type(ds)(**{**ds.__dict__, "windows": ds.windows[:-1] + [fv(tenant_id="other")]})
