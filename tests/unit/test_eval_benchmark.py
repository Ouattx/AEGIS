"""End-to-end tests of the benchmark harness on tiny frozen scenarios."""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone

import numpy as np
import pytest

from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import load_default
from eval import datasets as D
from eval.render import render_benchmark_html
from eval.run_benchmark import (
    DEFAULT_SCENARIOS,
    BenchmarkConfig,
    ProtocolViolation,
    isolation_checks,
    main,
    run_benchmark,
)
from eval.stats import GateConfig
from eval.systems import SYSTEMS, blocklist_hits, corpus_bundle, heuristic_score, run_systems

TINY = (
    D.ScenarioSpec(name="tiny_high", seed=9101, n_devices=40, days=2, malicious_fraction=0.15,
                   start="2026-10-15T00:00:00+00:00", tenant_id="t-high", description="tiny high"),
    D.ScenarioSpec(name="tiny_low", seed=9102, n_devices=50, days=2, malicious_fraction=0.04,
                   start="2026-10-20T00:00:00+00:00", tenant_id="t-low", description="tiny low"),
)


@pytest.fixture(scope="module")
def model():
    return load_default()


@pytest.fixture(scope="module")
def tiny_corpus():
    return D.generate(TINY[0])


def cfg(tmp_path, **kw) -> BenchmarkConfig:
    base = dict(scenarios=TINY, bootstrap=60, manifest_path=str(tmp_path / "manifest.json"),
                projected_prevalences=(0.01, 0.1))
    base.update(kw)
    return BenchmarkConfig(**base)


# ---------------------------------------------------------------------------- datasets

def test_digest_is_deterministic_and_content_bound(tiny_corpus):
    again = D.generate(TINY[0])
    assert D.corpus_digest(again) == D.corpus_digest(tiny_corpus)
    other = D.generate(replace(TINY[0], seed=9103))
    assert D.corpus_digest(other) != D.corpus_digest(tiny_corpus)
    s = D.dataset_summary(tiny_corpus)
    assert s["A_malicious_device_days"] + s["B_legitimate_device_days"] == s["device_days"]
    assert s["hard_negative_devices"] >= 1


def test_frozen_manifest_check(tmp_path, tiny_corpus):
    path = tmp_path / "m.json"
    spec = TINY[0]
    digest = D.corpus_digest(tiny_corpus)
    assert D.check_frozen(spec, digest, D.load_manifest(path)) == "unfrozen"
    D.freeze({spec.name: (spec, digest, D.dataset_summary(tiny_corpus))}, path)
    m = D.load_manifest(path)
    assert D.check_frozen(spec, digest, m) == "verified"
    with pytest.raises(D.FrozenDatasetMismatch):
        D.check_frozen(spec, "0" * 64, m)
    assert D.check_frozen(replace(spec, n_devices=41), digest, m) == "unfrozen"
    path.write_text(json.dumps({"schema": "other"}))
    with pytest.raises(D.FrozenDatasetMismatch):
        D.load_manifest(path)


def test_shipped_manifest_freezes_default_scenarios():
    m = D.load_manifest()
    for spec in DEFAULT_SCENARIOS:
        entry = m["datasets"][spec.name]
        assert entry["spec"] == spec.identity()
        assert len(entry["digest"]) == 64


def test_scenario_requires_utc_offset():
    with pytest.raises(ValueError):
        _ = replace(TINY[0], start="2026-10-15T00:00:00").start_dt


# ---------------------------------------------------------------------------- systems

def test_heuristic_and_blocklist_baselines(tiny_corpus):
    fv = FeatureVector(tenant_id="t", entity_pseudonym="p", device_class="phone", window="24h",
                       window_end=datetime(2026, 10, 2, tzinfo=timezone.utc),
                       values={"nxdomain_rate": 0.6, "nx_unique": 90.0, "unique_dst_ip": None},
                       missing={"unique_dst_ip": True}, event_count=100)
    alert, score = heuristic_score(fv)
    assert alert and score == pytest.approx(1.0)
    quiet = fv.model_copy(update={"values": {"nxdomain_rate": 0.01, "nx_unique": 1.0}})
    assert heuristic_score(quiet) == (False, pytest.approx(0.0, abs=0.02))
    bundle = corpus_bundle(tiny_corpus)
    listed = next(i for i in bundle.indicators if i.verdict == "malicious" and i.type == "ip")
    assert blocklist_hits(bundle, {listed.value}, set()) >= 1
    assert blocklist_hits(bundle, {"192.0.2.250"}, {"nothing.example"}) == 0


def test_run_systems_outputs_align(tiny_corpus, model):
    run = run_systems(tiny_corpus, model)
    names = [s.name for s in run.systems]
    assert names == list(SYSTEMS)
    n = len(tiny_corpus.labels)
    assert len(run.table.keys) == n
    for s in run.systems:
        assert s.alert.shape == (n,) and s.score.shape == (n,)
        assert np.all((s.score >= 0) & (s.score <= 1))
    ens = next(s for s in run.systems if s.name == "ensemble")
    assert ens.abstain is not None
    assert run.windows > 0 and run.rejected_events == 0
    assert sum(run.ensemble_rules.values()) == run.windows
    no_model = run_systems(tiny_corpus, None)
    assert "supervised" not in [s.name for s in no_model.systems]


# ---------------------------------------------------------------------------- protocol

def test_isolation_rejects_leakage(tmp_path):
    info = {"train_seeds": [9101, 1], "train_days": 3, "train_start": "2026-10-01T00:00:00+00:00"}
    with pytest.raises(ProtocolViolation, match="used for training"):
        isolation_checks(cfg(tmp_path), info)
    info = {"train_seeds": [1], "train_days": 20, "train_start": "2026-10-01T00:00:00+00:00"}
    with pytest.raises(ProtocolViolation, match="time-forward"):
        isolation_checks(cfg(tmp_path), info)
    with pytest.raises(ProtocolViolation, match="unknown"):
        isolation_checks(cfg(tmp_path), {"train_seeds": [], "train_days": 3, "train_start": "2026-10-01T00:00:00+00:00"})
    ok = isolation_checks(cfg(tmp_path), {"train_seeds": [1, 2], "train_days": 3,
                                          "train_start": "2026-10-01T00:00:00+00:00"})
    assert ok["time_forward"]["ok"] and ok["seeds"]["shared"] == []
    assert isinstance(ok["c2_ips_shared"], int)


def test_unfrozen_datasets_are_refused(tmp_path):
    with pytest.raises(D.FrozenDatasetMismatch, match="not in the frozen manifest"):
        run_benchmark(cfg(tmp_path))


def test_unknown_model_source(tmp_path):
    with pytest.raises(ValueError):
        run_benchmark(cfg(tmp_path, model_source="magic"))


# ---------------------------------------------------------------------------- end to end

@pytest.fixture(scope="module")
def results(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("bench")
    c = BenchmarkConfig(scenarios=TINY, bootstrap=60, manifest_path=str(tmp / "manifest.json"),
                        projected_prevalences=(0.01, 0.1))
    first = run_benchmark(c, freeze_datasets=True)
    second = run_benchmark(c)  # verifies against the digests just frozen
    return first, second


def test_benchmark_results_structure(results):
    first, r = results
    assert r["schema"] == "aegis.benchmark/1"
    assert {d["frozen_status"] for d in first["datasets"].values()} == {"frozen_now"}
    assert {d["frozen_status"] for d in r["datasets"].values()} == {"verified"}
    assert set(r["scenarios"]) == {"tiny_high", "tiny_low"}
    for block in [r["pooled"], *r["scenarios"].values()]:
        assert set(block["systems"]) == set(SYSTEMS)
        for m in block["systems"].values():
            assert {"precision", "recall", "pr_auc", "false_alerts_per_10k", "ci95", "per_device_class",
                    "pr_curve", "fpr_ci95_exact"} <= set(m)
        assert "ensemble - static_blocklist" in block["paired_differences_ci95"]
    pooled = r["pooled"]
    assert pooled["device_days"] == sum(s["device_days"] for s in r["scenarios"].values())
    assert len(pooled["projections"]["ensemble"]) == 2
    assert r["isolation"]["seeds"]["shared"] == []
    assert r["model"]["excluded_features"]
    assert "graph_plus_agents" in r["systems_not_evaluated"]
    assert isinstance(r["release_gate"]["passed"], bool)
    json.dumps(r)  # fully JSON-serializable


def test_benchmark_is_reproducible(results):
    first, second = results
    for name in first["scenarios"]:
        a, b = first["scenarios"][name]["systems"], second["scenarios"][name]["systems"]
        for sys_name in a:
            assert a[sys_name]["ci95"] == b[sys_name]["ci95"]
            assert a[sys_name]["tp"] == b[sys_name]["tp"]


def test_static_blocklist_pays_for_ignoring_freshness(results):
    _, r = results
    p = r["pooled"]["systems"]
    assert p["static_blocklist"]["false_alerts_per_10k"] > p["rules_only"]["false_alerts_per_10k"]


def test_benchmark_html_is_self_contained(results):
    _, r = results
    html = render_benchmark_html(r)
    assert html.startswith("<!doctype html>")
    assert "<script" not in html.lower() and "<link" not in html.lower()
    assert "http://" not in html and "https://" not in html
    for s in ("Release gate", "Frozen datasets", "Time-forward split", "Precision-recall curves",
              "Per-device-class confusion matrices", "What changes at other prevalences", "Limitations"):
        assert s in html
    assert html.count("<svg") >= 5 * (1 + len(r["scenarios"]))


def test_cli_quick_smoke(tmp_path, monkeypatch):
    import eval.run_benchmark as rb
    monkeypatch.setattr(rb, "DEFAULT_SCENARIOS", (replace(TINY[0], name="cli_tiny"),))
    out = tmp_path / "out"
    assert main(["--quick", "--bootstrap", "30", "--out", str(out), "--manifest", str(tmp_path / "m.json")]) == 0
    data = json.loads((out / "results.json").read_text())
    assert "cli_tiny_quick" in data["scenarios"]
    assert (out / "report.html").read_text().startswith("<!doctype html>")


def test_gate_config_flows_into_results(tmp_path):
    c = cfg(tmp_path, gate=GateConfig(comparators=("threshold_heuristic",),
                                      max_false_alert_regression_per_10k=0.0))
    r = run_benchmark(c, freeze_datasets=True)
    assert [x["comparator"] for x in r["release_gate"]["comparisons"]] == ["threshold_heuristic"]
    assert r["release_gate"]["config"]["max_false_alert_regression_per_10k"] == 0.0
