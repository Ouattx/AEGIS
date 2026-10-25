"""eval/load: synthetic generator, cost model and a miniature end-to-end run of the harness."""
from __future__ import annotations

import json

from aegis.ingest import parsers
from eval.load.run_load import LoadConfig, Prices, chunk_payload, cost_model, main, pct
from eval.load.synth import SynthSpec, generate


def test_synth_is_deterministic_and_parseable():
    spec = SynthSpec(n_lines=200, duration_s=600, seed=3)
    a, b = generate(spec), generate(spec)
    assert a.netflow_csv == b.netflow_csv and a.dns_jsonl == b.dns_jsonl
    flows = list(parsers.parse_netflow_csv(a.netflow_csv))
    dns = list(parsers.parse_dns_jsonl(a.dns_jsonl))
    assert len(flows) == a.n_flows and len(dns) == a.n_dns
    assert not any(r.get("_error") for r in flows + dns)
    expected = 200 * 600 / 3600 * (spec.flows_per_line_hour + spec.dns_per_line_hour)
    assert 0.8 * expected < a.n_events < 1.3 * expected
    assert 60 < a.flow_bytes_per_event < 200 and 100 < a.dns_bytes_per_event < 300
    assert a.t_min >= spec.start.timestamp() and a.t_max <= spec.start.timestamp() + 600 + 1


def test_helpers():
    assert pct([]) == {}
    p = pct(list(range(101)))
    assert p["p50"] == 50 and p["max"] == 100
    chunks = chunk_payload(b"h\na\nb\nc\n", 2, True)
    assert chunks == [b"h\na\nb\n", b"h\nc\n"]


def test_cost_model_arithmetic():
    cfg = LoadConfig(scales=[1000], flows_per_line_hour=100, dns_per_line_hour=0,
                     prices=Prices(eur_per_vcpu_hour=3.6, eur_per_ram_gb_month=1.0, eur_per_storage_gb_month=1.0,
                                   target_utilization=1.0, raw_retention_days=30))
    scale = {"lines": 1000,
             "ingest": {"cpu_us_per_event": 10.0, "bytes_per_event": {"netflow_csv": 100.0, "dns_jsonl": 200.0}},
             "windows": {"cpu_us_per_event": 5.0},
             "scoring": {"close_score_emit": {"cpu_us_per_vector": 500.0}}}
    memory = {"bytes_per_line_24h_window": 1e6}
    res = {"projections": {"1000": {"cpu_s_per_hourly_run": 0.36, "peak_memory_gb": 2.0, "basis": "measured"}}}
    out = cost_model(cfg, [scale], memory, res)["scales"]["1000"]
    # line path: 10 + 5 + 500/100 = 20 us/event; RESONANCE: 0.36 s / (1000 lines * 100 ev) = 3.6 us/event
    assert abs(out["cpu_us_per_event_line_path"] - 20.0) < 1e-9
    assert abs(out["cpu_us_per_event_resonance"] - 3.6) < 1e-9
    # 23.6 CPU-s per million events at 3.6 EUR/vCPU-h = 0.0236 EUR
    assert abs(out["eur_per_million_events"] - 0.0236) < 1e-9
    assert abs(out["eur_per_line_month"]["window_ram"] - 1e-3) < 1e-12
    assert abs(out["eur_per_line_month"]["raw_storage"] - 100 * 730 * 100 / 1e9) < 1e-12
    assert abs(out["eur_per_line_month"]["resonance_ram"] - 2.0 / 1000) < 1e-12


def test_miniature_run_writes_json_and_html(tmp_path):
    rc = main(["--out", str(tmp_path), "--quick", "--scales", "500,2000", "--events-per-scale", "4000",
               "--workers", "2", "--resonance-lines", "200,300", "--memory-lines", "30", "--memory-hours", "1",
               "--paced-seconds", "1"])
    assert rc == 0
    report = json.loads((tmp_path / "load_report.json").read_text())
    assert report["synthetic"] is True and [s["lines"] for s in report["scales"]] == [500, 2000]
    for s in report["scales"]:
        assert s["ingest"]["events_per_s_wall"] > 0 and s["sharded"]["published"] == s["ingest"]["accepted"]
        assert s["sharded"]["feature_vectors"] == s["windows"]["window_close"]["feature_vectors"]
    assert set(report["cost"]["scales"]) == {"500", "2000"}
    assert report["resonance"]["projections"]["2000"]["basis"].startswith("extrapolated")
    html = (tmp_path / "load_report.html").read_text()
    assert "Synthetic traffic" in html and "<script" not in html and "http" not in html.split("<body>")[1]
