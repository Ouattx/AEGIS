"""AEGIS load test: throughput, latency, memory and cost at 10k / 100k / 1M subscriber lines.

    python -m eval.load.run_load --out eval/load/report            # full run (about 10 minutes, 4 cores)
    python -m eval.load.run_load --out /tmp/load --quick        # smoke run (about 1 minute)

All traffic is SYNTHETIC (``eval.load.synth``; RESONANCE stages use ``aegis.resonance.sim``).
Every stage is measured, never estimated, at the line count it names, with one exception
that the report states in each row: each scale processes a fixed *event budget*, so the
simulated duration shrinks as the line count grows (at 1M lines and the default budget,
about 6 s of traffic, under one event per line). Quantities that need a full day of history
(window memory per line, RESONANCE at 100k / 1M lines, the 24 h CPU bill) are extrapolated
from measured per-unit costs, and the report says so next to every such number.

Outputs ``load_report.json`` and a self-contained ``load_report.html`` in ``--out``.
"""
from __future__ import annotations

import argparse
import gc
import json
import math
import os
import platform
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import numpy as np

from aegis.contracts.models import FeatureVector, ObservationEvent, SourceKind, Vantage
from aegis.ingest import IngestPipeline, Pseudonymizer, SourceConfig, Validator
from aegis.scale import (
    CollectingBus,
    FixedClock,
    LineShardConfig,
    ProcessCluster,
    ResonanceShardConfig,
    ShardedLinePipeline,
    sharded_resonance_prep,
)
from aegis.scale.streaming import rss_bytes
from eval.load.synth import SynthBatch, SynthSpec, generate

TENANT = "load-isp"
TENANT_KEY = b"aegis-load-test-tenant-key-32by!"
AUTH = "auth-load-test"
SOURCES = {
    "nf": SourceConfig(tenant_id=TENANT, source_id="nf", source_kind=SourceKind.NETFLOW,
                       vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id=AUTH),
    "dns": SourceConfig(tenant_id=TENANT, source_id="dns", source_kind=SourceKind.DNS,
                        vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id=AUTH),
}


# ----------------------------------------------------------------------------- config

@dataclass
class Prices:
    eur_per_vcpu_hour: float = 0.04
    eur_per_ram_gb_month: float = 2.50
    eur_per_storage_gb_month: float = 0.10
    target_utilization: float = 0.6        # plan capacity so CPUs run at most this busy
    raw_retention_days: float = 30.0       # raw collector files kept for replay / quarantine review
    retain_raw: bool = True


@dataclass
class LoadConfig:
    scales: list[int] = field(default_factory=lambda: [10_000, 100_000, 1_000_000])
    events_per_scale: int = 300_000
    flows_per_line_hour: float = 120.0
    dns_per_line_hour: float = 60.0
    workers: int = 4
    chunk_records: int = 1_000
    score_sample: int = 20_000
    resonance_lines: list[int] = field(default_factory=lambda: [1_000, 2_500, 5_000, 10_000])
    resonance_prep_lines: int = 10_000
    memory_lines: int = 300
    memory_hours: float = 6.0
    paced_seconds: float = 15.0
    paced_fractions: list[float] = field(default_factory=lambda: [0.5, 0.9])
    seed: int = 7
    prices: Prices = field(default_factory=Prices)

    @property
    def events_per_line_hour(self) -> float:
        return self.flows_per_line_hour + self.dns_per_line_hour


QUICK = dict(scales=[10_000, 100_000, 1_000_000], events_per_scale=30_000, score_sample=2_000,
             resonance_lines=[500, 1_000], resonance_prep_lines=1_000, memory_lines=100, memory_hours=2.0,
             paced_seconds=4.0)


# ----------------------------------------------------------------------------- measurement helpers

def pct(values: list[float] | np.ndarray, qs: tuple[float, ...] = (50, 95, 99, 99.9)) -> dict[str, float]:
    a = np.asarray(values, dtype=np.float64)
    if a.size == 0:
        return {}
    out = {f"p{q:g}": float(np.percentile(a, q)) for q in qs}
    out["max"] = float(a.max())
    out["mean"] = float(a.mean())
    return out


class Meter:
    """Wall time, CPU time and RSS around a block (CPU time is robust to other tenants of the host)."""

    def __enter__(self) -> "Meter":
        gc.collect()
        self.rss0 = rss_bytes()
        self.c0 = time.process_time()
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self.wall = time.perf_counter() - self.t0
        self.cpu = time.process_time() - self.c0
        self.rss1 = rss_bytes()

    @property
    def rss_delta(self) -> int:
        return self.rss1 - self.rss0


def chunk_payload(payload: bytes, n_records: int, header: bool) -> list[bytes]:
    lines = payload.split(b"\n")
    head = lines[0] + b"\n" if header else b""
    body = [ln for ln in (lines[1:] if header else lines) if ln]
    return [head + b"\n".join(body[i:i + n_records]) + b"\n" for i in range(0, len(body), n_records)]


def hour_ceil(ts: float) -> datetime:
    return datetime.fromtimestamp(math.ceil(ts / 3600.0) * 3600.0, tz=timezone.utc)


def make_pipeline(now: datetime, sink: Callable[[ObservationEvent], None]) -> IngestPipeline:
    bus = CollectingBus()
    bus.subscribe("observations", sink)
    return IngestPipeline(bus, Validator(clock=FixedClock(now)), SOURCES,
                          pseudonymizers={TENANT: Pseudonymizer(TENANT_KEY)}, clock=FixedClock(now))


# ----------------------------------------------------------------------------- stages

def stage_ingest(batch: SynthBatch, now: datetime, chunk: int) -> tuple[list[ObservationEvent], dict[str, Any]]:
    events: list[ObservationEvent] = []
    pipe = make_pipeline(now, events.append)
    chunks = [("nf", c) for c in chunk_payload(batch.netflow_csv, chunk, True)] + \
             [("dns", c) for c in chunk_payload(batch.dns_jsonl, chunk, False)]
    lat_ms: list[float] = []
    quarantined = 0
    with Meter() as m:
        for sid, data in chunks:
            t = time.perf_counter()
            st = pipe.ingest_text(data, sid)
            lat_ms.append((time.perf_counter() - t) * 1000)
            quarantined += st.quarantined
    n = batch.n_events
    return events, {
        "events": n, "accepted": len(events), "quarantined": quarantined, "wall_s": m.wall, "cpu_s": m.cpu,
        "events_per_s_wall": n / m.wall, "events_per_s_cpu": n / m.cpu, "cpu_us_per_event": 1e6 * m.cpu / n,
        "batch_records": chunk, "batch_latency_ms": pct(lat_ms),
        "bytes_per_event": {"netflow_csv": batch.flow_bytes_per_event, "dns_jsonl": batch.dns_bytes_per_event},
        "input_mb": (len(batch.netflow_csv) + len(batch.dns_jsonl)) / 1e6,
    }


def stage_windows(events: list[ObservationEvent], flush_at: datetime
                  ) -> tuple[list[FeatureVector], Any, dict[str, Any]]:
    from aegis.sentinel import WindowStore
    events.sort(key=lambda e: e.observed_at)
    ws = WindowStore("24h")
    lat_us = np.empty(len(events))
    pc = time.perf_counter_ns
    with Meter() as m:
        for i, ev in enumerate(events):
            t = pc()
            ws.update(ev)
            lat_us[i] = (pc() - t) / 1000
    with Meter() as mf:
        fvs = ws.flush(flush_at)
    n = len(events)
    return fvs, ws, {
        "events": n, "wall_s": m.wall, "cpu_s": m.cpu, "events_per_s_wall": n / m.wall,
        "events_per_s_cpu": n / m.cpu, "cpu_us_per_event": 1e6 * m.cpu / n, "update_latency_us": pct(lat_us),
        "active_lines": ws.entity_count(TENANT), "window_close": {
            "feature_vectors": len(fvs), "wall_s": mf.wall, "cpu_s": mf.cpu,
            "cpu_us_per_vector": 1e6 * mf.cpu / max(1, len(fvs))},
        "state_rss_mb": m.rss_delta / 1e6,
    }


def stage_scoring(events: list[ObservationEvent], fvs: list[FeatureVector], ws: Any, sample: int,
                  flush_at: datetime) -> dict[str, Any]:
    """SENTINEL detectors + fusion per window (``evaluate``), and the full public path
    (``process`` + ``flush``: window close, scoring and finding emission) on a subset of lines."""
    from aegis.sentinel import Sentinel, WindowStore, load_default
    model = load_default()
    sen = Sentinel(model, None, None, window_store=ws)
    sub = fvs[:sample]
    lat_ms: list[float] = []
    with Meter() as m:
        for i in range(0, len(sub), 1000):
            t = time.perf_counter()
            sen.evaluate(sub[i:i + 1000])
            lat_ms.append((time.perf_counter() - t) * 1000)
    n = len(sub)
    lines = {fv.entity_pseudonym for fv in sub}
    full = Sentinel(model, None, None, window_store=WindowStore("24h"))
    for ev in events:
        if ev.entity_pseudonym in lines:
            full.process(ev)
    with Meter() as mf:
        found = full.flush(flush_at)
    return {"feature_vectors_scored": n, "feature_vectors_available": len(fvs), "wall_s": m.wall, "cpu_s": m.cpu,
            "vectors_per_s_wall": n / m.wall if m.wall else None, "cpu_us_per_vector": 1e6 * m.cpu / max(1, n),
            "batch_vectors": 1000, "batch_latency_ms": pct(lat_ms), "model_id": model.model_id,
            "close_score_emit": {"lines": len(lines), "findings": len(found), "wall_s": mf.wall, "cpu_s": mf.cpu,
                                 "cpu_us_per_vector": 1e6 * mf.cpu / max(1, len(lines)),
                                 "findings_per_vector": len(found) / max(1, len(lines))},
            "note": None if n == len(fvs) else f"scored a sample of {n} of {len(fvs)} vectors; "
                                               "per-vector cost is independent of the sample size"}


def stage_sharded(batch: SynthBatch, now: datetime, flush_at: datetime, workers: int, mode: str) -> dict[str, Any]:
    from aegis.sentinel.model import default_model_dir
    cfg = LineShardConfig(sources=SOURCES, tenant_keys={TENANT: TENANT_KEY}, mode=mode,  # type: ignore[arg-type]
                          collect="count", clock=FixedClock(now),
                          model_dir=str(default_model_dir()) if mode == "sentinel" else None)
    t_spawn = time.perf_counter()
    cluster = ProcessCluster(cfg, n_shards=workers * 2, n_workers=workers)
    spawn_s = time.perf_counter() - t_spawn
    try:
        cpu_w0 = sum(cluster.worker_cpu_seconds())
        pipe = ShardedLinePipeline(cluster, cfg, batch_size=20_000)
        with Meter() as m:
            pipe.ingest_text(batch.netflow_csv, "nf")
            pipe.ingest_text(batch.dns_jsonl, "dns")
        with Meter() as mf:
            pipe.flush(flush_at)
            res = pipe.finish()
        cpu_w = sum(cluster.worker_cpu_seconds()) - cpu_w0
    finally:
        cluster.close()
    n = batch.n_events
    total_cpu = m.cpu + mf.cpu + cpu_w
    shard_events = list(res.per_shard_events.values())
    return {
        "mode": mode, "workers": workers, "shards": workers * 2, "events": n, "published": res.n_events,
        "ingest_wall_s": m.wall, "events_per_s_wall": n / m.wall, "close_wall_s": mf.wall,
        "feature_vectors": res.n_features, "findings": res.n_findings, "coordinator_cpu_s": m.cpu + mf.cpu,
        "worker_cpu_s": cpu_w, "total_cpu_us_per_event": 1e6 * total_cpu / n, "spawn_s": spawn_s,
        "barriers": res.barriers,
        "shard_balance": {"min": min(shard_events), "max": max(shard_events),
                          "max_over_mean": max(shard_events) / (sum(shard_events) / len(shard_events))},
    }


def stage_window_memory(cfg: LoadConfig) -> dict[str, Any]:
    """Steady-state window memory: bytes retained per buffered event, from a run with full history."""
    from aegis.sentinel import WindowStore
    spec = SynthSpec(n_lines=cfg.memory_lines, duration_s=cfg.memory_hours * 3600,
                     flows_per_line_hour=cfg.flows_per_line_hour, dns_per_line_hour=cfg.dns_per_line_hour,
                     seed=cfg.seed + 1)
    batch = generate(spec)
    now = hour_ceil(batch.t_max)
    events: list[ObservationEvent] = []
    pipe = make_pipeline(now, events.append)
    pipe.ingest_text(batch.netflow_csv, "nf")
    pipe.ingest_text(batch.dns_jsonl, "dns")
    events.sort(key=lambda e: e.observed_at)
    out = {}
    for ids in (10_000, 0):
        gc.collect()
        r0 = rss_bytes()
        ws = WindowStore("24h", max_source_event_ids=ids)
        for ev in events:
            ws.update(ev)
        gc.collect()
        delta = rss_bytes() - r0
        out[f"max_source_event_ids={ids}"] = {"bytes_per_buffered_event": delta / len(events),
                                              "bytes_per_line": delta / cfg.memory_lines}
        del ws
    per_event = out["max_source_event_ids=10000"]["bytes_per_buffered_event"]
    per_line_24h = per_event * cfg.events_per_line_hour * 24
    return {"lines": cfg.memory_lines, "simulated_hours": cfg.memory_hours, "buffered_events": len(events),
            "measured": out, "bytes_per_line_24h_window": per_line_24h,
            "method": (f"RSS growth of one WindowStore holding {cfg.memory_hours:g} h of history for "
                       f"{cfg.memory_lines} lines, divided by buffered events; a 24 h window buffers 24 h of "
                       f"events per line, so bytes/line = bytes/event x {cfg.events_per_line_hour:g} x 24 "
                       "(extrapolated in time, linear: the store keeps per-event timestamps for periodicity)")}


def stage_paced(cfg: LoadConfig, capacity_eps: float) -> list[dict[str, Any]]:
    """Offer events at fixed rates (fractions of the measured single-core capacity) for a fixed time;
    report end-to-end latency (arrival to features updated) per 100 ms tick and whether the pipeline kept up."""
    from aegis.sentinel import WindowStore
    out = []
    for frac in cfg.paced_fractions:
        rate = frac * capacity_eps
        n_total = int(rate * cfg.paced_seconds)
        spec = SynthSpec(n_lines=10_000, duration_s=max(60.0, 1.1 * n_total / (10_000 * cfg.flows_per_line_hour / 3600)),
                         flows_per_line_hour=cfg.flows_per_line_hour, dns_per_line_hour=0.0, seed=cfg.seed + 2)
        batch = generate(spec)
        lines = [ln for ln in batch.netflow_csv.split(b"\n")[1:] if ln][:n_total]
        header = batch.netflow_csv.split(b"\n", 1)[0] + b"\n"
        ws = WindowStore("24h")
        pipe = make_pipeline(hour_ceil(batch.t_max), ws.update)
        tick = 0.1
        lat: list[float] = []
        sent = 0
        t0 = time.perf_counter()
        while sent < len(lines):
            now = time.perf_counter() - t0
            due = min(len(lines), int(now * rate) + 1)
            if due <= sent:
                time.sleep(min(tick, (sent + 1) / rate - now))
                continue
            first_arrival = sent / rate
            pipe.ingest_text(header + b"\n".join(lines[sent:due]) + b"\n", "nf")
            done = time.perf_counter() - t0
            lat.append((done - first_arrival) * 1000)
            sent = due
        elapsed = time.perf_counter() - t0
        lag = elapsed - len(lines) / rate
        out.append({"offered_fraction_of_capacity": frac, "offered_events_per_s": rate, "events": len(lines),
                    "elapsed_s": elapsed, "achieved_events_per_s": len(lines) / elapsed, "final_lag_s": lag,
                    "kept_up": lag < 0.5, "latency_ms": pct(lat),
                    "stage": "ingest+validate+feature windows (NetFlow only), single process"})
    return out


class PeakSampler:
    """Samples this process's RSS every ``interval_s`` (``ru_maxrss`` cannot be used in a child:
    on Linux it carries the parent's high-water mark across fork + exec)."""

    def __init__(self, interval_s: float = 0.02):
        import threading
        self.interval_s = interval_s
        self.base = rss_bytes()
        self.peak = self.base
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            self.peak = max(self.peak, rss_bytes())

    def stop(self) -> int:
        self._stop.set()
        self._t.join()
        self.peak = max(self.peak, rss_bytes())
        return self.peak


def resonance_worker(n_lines: int, seed: int) -> dict[str, Any]:
    """Run in a fresh subprocess so peak memory belongs to this job alone."""
    from aegis.resonance import DestinationContext, Resonance, ResonanceConfig
    from aegis.resonance.sim import ScenarioSpec, generate_scenario, standard_campaigns
    sampler = PeakSampler()          # base = interpreter + libraries, before any job data exists
    sc = generate_scenario(ScenarioSpec(n_lines=n_lines, days=1.0, campaigns=standard_campaigns(0.01), seed=seed),
                           sampling=100)
    cfg = ResonanceConfig()
    c0, t0 = time.process_time(), time.perf_counter()
    tb = sc.table(cfg)
    build_s = time.perf_counter() - t0
    rep = Resonance(cfg, context=DestinationContext(sc.topology), tenant_id=TENANT).detect(tb)
    peak = sampler.stop()
    return {"lines": n_lines, "events": len(tb), "events_per_line_day": len(tb) / n_lines,
            "table_build_s": build_s, "detect_wall_s": time.perf_counter() - t0 - build_s,
            "cpu_s": time.process_time() - c0, "peak_rss_mb": peak / 1e6,
            "peak_rss_growth_mb": (peak - sampler.base) / 1e6,
            "memory_note": "includes the simulated input frames (the job's input)", "campaigns": len(rep.campaigns),
            "tested": rep.n_tested, "timings_s": rep.timings_s}


def stage_resonance(cfg: LoadConfig) -> dict[str, Any]:
    runs = []
    for n in cfg.resonance_lines:
        proc = subprocess.run([sys.executable, "-m", "eval.load.run_load", "--resonance-worker", str(n),
                               "--seed", str(cfg.seed)], capture_output=True, text=True, check=True,
                              cwd=Path(__file__).resolve().parents[2])
        runs.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    xs = np.log([r["lines"] for r in runs])
    fit_cpu = np.polyfit(xs, np.log([r["cpu_s"] for r in runs]), 1)
    fit_mem = np.polyfit(xs, np.log([max(1.0, r["peak_rss_growth_mb"]) for r in runs]), 1)

    def cpu_at(n: float) -> float:
        return float(math.exp(np.polyval(fit_cpu, math.log(n))))

    def mem_at(n: float) -> float:
        return float(math.exp(np.polyval(fit_mem, math.log(n))))

    projections = {}
    for n in cfg.scales:
        measured = next((r for r in runs if r["lines"] == n), None)
        projections[str(n)] = {
            "cpu_s_per_hourly_run": measured["cpu_s"] if measured else cpu_at(n),
            "peak_memory_gb": (measured["peak_rss_growth_mb"] if measured else mem_at(n)) / 1e3,
            "basis": "measured" if measured else (f"extrapolated (power law fitted on {len(runs)} measured line "
                                                  f"counts {[r['lines'] for r in runs]})"),
            "fits_in_one_hour_on_one_core": (measured["cpu_s"] if measured else cpu_at(n)) < 3600,
        }
    return {"runs": runs, "cpu_power_law": {"exponent": float(fit_cpu[0]), "coef": float(math.exp(fit_cpu[1]))},
            "memory_power_law": {"exponent": float(fit_mem[0]), "coef_mb": float(math.exp(fit_mem[1]))},
            "projections": projections,
            "traffic": "aegis.resonance.sim, 24 h, NetFlow sampled 1:100 + unsampled resolver DNS, 1 % infected lines"}


def stage_resonance_prep(cfg: LoadConfig, workers: int) -> dict[str, Any]:
    from aegis.resonance import ResonanceConfig, build_event_table
    from aegis.resonance.population import key_stats
    from aegis.resonance.sim import ScenarioSpec, generate_scenario, standard_campaigns
    sc = generate_scenario(ScenarioSpec(n_lines=cfg.resonance_prep_lines, days=1.0,
                                        campaigns=standard_campaigns(0.01), seed=cfg.seed), sampling=100)
    rcfg = ResonanceConfig()
    with Meter() as m1:
        tb = build_event_table(sc.flows, sc.dns, dns_join_ttl_s=rcfg.dns_join_ttl_s)
        key_stats(tb, rcfg)
    cluster = ProcessCluster(ResonanceShardConfig(rcfg), n_shards=workers, n_workers=workers)
    try:
        w0 = sum(cluster.worker_cpu_seconds())
        with Meter() as m2:
            res = sharded_resonance_prep(cluster, sc.flows, sc.dns)
        w = sum(cluster.worker_cpu_seconds()) - w0
    finally:
        cluster.close()
    return {"lines": cfg.resonance_prep_lines, "events": len(tb), "single_wall_s": m1.wall, "single_cpu_s": m1.cpu,
            "sharded_wall_s": m2.wall, "sharded_total_cpu_s": m2.cpu + w, "workers": workers,
            "active_lines": res.population.active_lines, "destination_keys": len(res.population.keys),
            "note": "stages 1-2 only (DNS join, destination population statistics); detection runs once on the "
                    "coordinator (see aegis/scale/population.py for why it does not shard by destination)"}


# ----------------------------------------------------------------------------- scale run + cost model

def run_scale(cfg: LoadConfig, n_lines: int) -> dict[str, Any]:
    rate_per_line = cfg.events_per_line_hour / 3600.0
    duration = cfg.events_per_scale / (n_lines * rate_per_line)
    spec = SynthSpec(n_lines=n_lines, duration_s=duration, flows_per_line_hour=cfg.flows_per_line_hour,
                     dns_per_line_hour=cfg.dns_per_line_hour, seed=cfg.seed)
    t = time.perf_counter()
    batch = generate(spec)
    gen_s = time.perf_counter() - t
    now = hour_ceil(batch.t_max)
    events, ingest = stage_ingest(batch, now, cfg.chunk_records)
    fvs, ws, windows = stage_windows(events, now)
    scoring = stage_scoring(events, fvs, ws, cfg.score_sample, now)
    del fvs, ws, events
    gc.collect()
    sharded = stage_sharded(batch, now, now, cfg.workers, "sentinel")
    single_line_path_cpu_us = ingest["cpu_us_per_event"] + windows["cpu_us_per_event"]
    return {
        "lines": n_lines, "simulated_seconds": duration, "events": batch.n_events,
        "events_per_line": batch.n_events / n_lines, "generation_s": gen_s,
        "required_events_per_s": n_lines * rate_per_line,
        "duration_note": (f"event budget {cfg.events_per_scale:,}: {duration:,.0f} s of simulated traffic "
                          f"({batch.n_events / n_lines:.2f} events per line)"),
        "ingest": ingest, "windows": windows, "scoring": scoring, "sharded": sharded,
        "single_core_line_path_events_per_s_cpu": 1e6 / single_line_path_cpu_us,
    }


def cost_model(cfg: LoadConfig, scales: list[dict[str, Any]], memory: dict[str, Any],
               resonance: dict[str, Any]) -> dict[str, Any]:
    p = cfg.prices
    eph = cfg.events_per_line_hour
    line_hours_month = 730.0
    out = {}
    bytes_per_event = None
    for s in scales:
        n = s["lines"]
        ing, win, sco = s["ingest"], s["windows"], s["scoring"]
        bytes_per_event = (ing["bytes_per_event"]["netflow_csv"] * cfg.flows_per_line_hour
                           + ing["bytes_per_event"]["dns_jsonl"] * cfg.dns_per_line_hour) / eph
        # per-line path CPU per event: ingest + window updates + (window close + scoring + finding emission)
        # once per line per hour (one 24 h window vector per active line per hop)
        cpu_us_event = ing["cpu_us_per_event"] + win["cpu_us_per_event"] + \
            sco["close_score_emit"]["cpu_us_per_vector"] / eph
        res_cpu_run = resonance["projections"][str(n)]["cpu_s_per_hourly_run"]
        res_cpu_us_event = res_cpu_run * 1e6 / (n * eph)        # hourly job amortized over one hour of events
        total_us = cpu_us_event + res_cpu_us_event
        eur_per_m = total_us * 1e6 / 1e6 / 3600 * p.eur_per_vcpu_hour / p.target_utilization
        events_month = eph * line_hours_month
        cpu_eur_line_month = events_month * total_us / 1e6 / 3600 * p.eur_per_vcpu_hour / p.target_utilization
        ram_gb_line = memory["bytes_per_line_24h_window"] / 1e9
        ram_eur_line_month = ram_gb_line * p.eur_per_ram_gb_month
        res_mem_gb = resonance["projections"][str(n)]["peak_memory_gb"]
        res_ram_eur_line_month = res_mem_gb / n * p.eur_per_ram_gb_month
        storage_gb_line = events_month * bytes_per_event / 1e9 * (p.raw_retention_days / 30.0) if p.retain_raw else 0.0
        storage_eur_line_month = storage_gb_line * p.eur_per_storage_gb_month
        required_eps = n * eph / 3600
        vcpus = required_eps * cpu_us_event / 1e6 / p.target_utilization + res_cpu_run / 3600 / p.target_utilization
        out[str(n)] = {
            "cpu_us_per_event_line_path": cpu_us_event, "cpu_us_per_event_resonance": res_cpu_us_event,
            "eur_per_million_events": eur_per_m,
            "eur_per_line_month": {"cpu": cpu_eur_line_month, "window_ram": ram_eur_line_month,
                                   "resonance_ram": res_ram_eur_line_month, "raw_storage": storage_eur_line_month,
                                   "total": cpu_eur_line_month + ram_eur_line_month + res_ram_eur_line_month
                                   + storage_eur_line_month},
            "required_events_per_s": required_eps, "vcpus_needed": vcpus,
            "window_ram_gb_total": ram_gb_line * n, "resonance_peak_ram_gb": res_mem_gb,
            "resonance_basis": resonance["projections"][str(n)]["basis"],
        }
    return {"prices": asdict(p), "events_per_line_hour": eph, "bytes_per_event": bytes_per_event,
            "assumptions": [
                f"{cfg.flows_per_line_hour:g} flow records + {cfg.dns_per_line_hour:g} DNS queries per line-hour "
                "(configurable; sampled NetFlow at 1:1000 would be far lower)",
                "CPU = measured CPU seconds per event (process_time, robust to other load on the host) divided by "
                f"target utilization {p.target_utilization:g}",
                "window RAM per line = measured bytes per buffered event x 24 h of events (see memory section)",
                "RESONANCE CPU/RAM per hourly run from measured runs (10k) and a fitted power law beyond",
                f"raw collector files retained {p.raw_retention_days:g} days" if p.retain_raw
                else "raw collector files not retained",
                "no evidence/ledger storage, network egress, or operations staff in this model"],
            "scales": out}


# ----------------------------------------------------------------------------- HTML

def render_html(report: dict[str, Any]) -> str:
    from html import escape

    from aegis.reports.charts import BarRow, Segment, hbar_chart
    from aegis.reports.theme import BASE_CSS, SERIES

    def f(v: Any, d: int = 1) -> str:
        if v is None:
            return "n/a"
        if isinstance(v, bool):
            return "yes" if v else "no"
        if isinstance(v, int):
            return f"{v:,}"
        if isinstance(v, float):
            if v != 0 and abs(v) < 0.01:
                return f"{v:.2e}"
            return f"{v:,.{d}f}"
        return escape(str(v))

    def table(head: list[str], rows: list[list[Any]]) -> str:
        h = "".join(f"<th>{escape(x)}</th>" for x in head)
        b = "".join("<tr>" + "".join(f"<td>{c if isinstance(c, str) and c.startswith('<') else f(c)}</td>"
                                     for c in r) + "</tr>" for r in rows)
        return f'<table class="tbl"><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table>'

    sc = report["scales"]
    bars = []
    for s in sc:
        bars.append(BarRow(f"{s['lines']:,} lines, 1 core", (Segment("ingest+validate", s["ingest"]["events_per_s_cpu"],
                                                                     SERIES[0]),)))
        bars.append(BarRow(f"{s['lines']:,} lines, sharded x{s['sharded']['workers']}",
                           (Segment("ingest+windows+SENTINEL", s["sharded"]["events_per_s_wall"], SERIES[1]),)))
    chart = hbar_chart(bars, value_suffix=" ev/s", aria_label="throughput by scale", label_width=230)
    env = report["environment"]
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AEGIS load test</title>
<style>{BASE_CSS}
body{{max-width:1100px;margin:0 auto;padding:24px 16px;font-family:system-ui,sans-serif;background:var(--page);color:var(--ink)}}
.tbl{{border-collapse:collapse;width:100%;margin:8px 0 20px;font-size:13px;background:var(--surface)}}
.tbl th,.tbl td{{border:1px solid var(--grid);padding:5px 8px;text-align:right}}
.tbl th:first-child,.tbl td:first-child{{text-align:left}}
.banner{{background:var(--warning-soft);border:1px solid var(--warning);padding:10px 14px;border-radius:6px}}
.note{{color:var(--ink-2);font-size:13px}} h2{{margin-top:28px}}
.wrap{{overflow-x:auto}}</style></head><body>
<h1>AEGIS SHIELD load test</h1>
<p class="banner"><strong>Synthetic traffic.</strong> Every number below was measured on generated telemetry on the
host described here, not on operator data. Rows marked <em>extrapolated</em> are computed from measured per-unit costs;
the method is stated next to them.</p>
<p class="note">Run {escape(report['generated_at'])} on {escape(env['cpu_model'])}, {env['cpu_count']} logical CPUs,
Python {escape(env['python'])}. Host load average at start / end: {f(env['loadavg_start'][0], 2)} /
{f(env['loadavg_end'][0], 2)} (other processes were running on this host; wall-clock throughput is affected,
CPU-time figures much less).</p>
<h2>Throughput</h2><div class="wrap">{chart}</div>
<div class="wrap">"""]
    parts.append(table(
        ["lines", "events", "simulated", "ingest+validate ev/s (wall)", "ingest CPU µs/ev", "windows ev/s (wall)",
         "windows CPU µs/ev", "SENTINEL evaluate vectors/s", "close+score+emit CPU µs/vector (findings/vector)",
         "sharded x4 ev/s (wall)", "sharded CPU µs/ev", "required ev/s"],
        [[s["lines"], s["events"], f"{s['simulated_seconds']:,.0f} s", s["ingest"]["events_per_s_wall"],
          s["ingest"]["cpu_us_per_event"], s["windows"]["events_per_s_wall"], s["windows"]["cpu_us_per_event"],
          s["scoring"]["vectors_per_s_wall"],
          f"{f(s['scoring']['close_score_emit']['cpu_us_per_vector'])} "
          f"({f(s['scoring']['close_score_emit']['findings_per_vector'], 2)})",
          s["sharded"]["events_per_s_wall"],
          s["sharded"]["total_cpu_us_per_event"], s["required_events_per_s"]] for s in sc]))
    parts.append("</div><p class='note'>" + " ".join(escape(s["duration_note"]) + "." for s in sc) + "</p>")
    parts.append("<h2>Latency</h2><div class='wrap'>")
    parts.append(table(
        ["lines", "ingest batch (1,000 records) p50 / p95 / p99 ms", "window update p50 / p99 / p99.9 µs",
         "window close (all lines) s", "scoring batch (1,000 vectors) p50 / p99 ms"],
        [[s["lines"],
          f"{f(s['ingest']['batch_latency_ms']['p50'])} / {f(s['ingest']['batch_latency_ms']['p95'])} / "
          f"{f(s['ingest']['batch_latency_ms']['p99'])}",
          f"{f(s['windows']['update_latency_us']['p50'])} / {f(s['windows']['update_latency_us']['p99'])} / "
          f"{f(s['windows']['update_latency_us']['p99.9'])}",
          s["windows"]["window_close"]["wall_s"],
          f"{f(s['scoring']['batch_latency_ms'].get('p50'))} / {f(s['scoring']['batch_latency_ms'].get('p99'))}"]
         for s in sc]))
    pc = report["paced"]
    parts.append("</div><h3>Controlled-rate runs</h3><div class='wrap'>")
    parts.append(table(["offered ev/s", "share of capacity", "achieved ev/s", "kept up", "latency p50 / p99 / max ms"],
                       [[p["offered_events_per_s"], p["offered_fraction_of_capacity"], p["achieved_events_per_s"],
                         p["kept_up"], f"{f(p['latency_ms']['p50'])} / {f(p['latency_ms']['p99'])} / "
                                       f"{f(p['latency_ms']['max'])}"] for p in pc]))
    mem = report["window_memory"]
    parts.append(f"</div><h2>Memory</h2><p>Feature-window state: <strong>{f(mem['bytes_per_line_24h_window'] / 1e3, 0)}"
                 f" KB per line</strong> with a full 24 h window (<em>extrapolated in time</em>: "
                 f"{escape(mem['method'])}).</p>")
    parts.append(table(["setting", "bytes per buffered event", "bytes per line (measured history)"],
                       [[k, v["bytes_per_buffered_event"], v["bytes_per_line"]] for k, v in mem["measured"].items()]))
    rs = report["resonance"]
    parts.append("<h2>RESONANCE hourly job</h2><div class='wrap'>")
    parts.append(table(["lines", "events (24 h)", "table build s", "detect s (wall)", "CPU s", "peak RAM growth MB",
                        "campaigns"],
                       [[r["lines"], r["events"], r["table_build_s"], r["detect_wall_s"], r["cpu_s"],
                         r["peak_rss_growth_mb"], r["campaigns"]] for r in rs["runs"]]))
    parts.append(table(["lines", "CPU s per hourly run", "peak RAM GB", "fits in 1 h on 1 core", "basis"],
                       [[k, v["cpu_s_per_hourly_run"], v["peak_memory_gb"], v["fits_in_one_hour_on_one_core"],
                         v["basis"]] for k, v in rs["projections"].items()]))
    rp = report["resonance_prep"]
    parts.append(f"</div><p class='note'>Sharded RESONANCE preparation ({rp['lines']:,} lines, {rp['events']:,} events, "
                 f"{rp['workers']} workers): {f(rp['sharded_wall_s'], 2)} s wall vs {f(rp['single_wall_s'], 2)} s "
                 f"single-node. {escape(rp['note'])}.</p>")
    cm = report["cost"]
    parts.append("<h2>Cost model</h2><p class='note'>Prices: " + escape(json.dumps(cm["prices"])) + "</p><ul>" +
                 "".join(f"<li>{escape(a)}</li>" for a in cm["assumptions"]) + "</ul><div class='wrap'>")
    parts.append(table(["lines", "€ per million events", "€ per line-month (total)", "of which CPU", "window RAM",
                        "RESONANCE RAM", "raw storage", "vCPUs needed", "window RAM total GB", "RESONANCE basis"],
                       [[k, v["eur_per_million_events"], v["eur_per_line_month"]["total"],
                         v["eur_per_line_month"]["cpu"], v["eur_per_line_month"]["window_ram"],
                         v["eur_per_line_month"]["resonance_ram"], v["eur_per_line_month"]["raw_storage"],
                         v["vcpus_needed"], v["window_ram_gb_total"], v["resonance_basis"]]
                        for k, v in cm["scales"].items()]))
    parts.append("</div><h2>Findings and limits</h2><ul>" +
                 "".join(f"<li>{escape(x)}</li>" for x in report["findings"]) + "</ul></body></html>")
    return "".join(parts)


# ----------------------------------------------------------------------------- driver

def environment() -> dict[str, Any]:
    model = platform.processor() or platform.machine()
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"cpu_model": model, "cpu_count": os.cpu_count(), "python": platform.python_version(),
            "platform": platform.platform(), "loadavg_start": list(os.getloadavg())}


def findings(report: dict[str, Any]) -> list[str]:
    out = []
    sc = report["scales"]
    big = sc[-1]
    out.append(f"Single-core ingest+validate: {sc[0]['ingest']['events_per_s_cpu']:,.0f} events per CPU-second at "
               f"{sc[0]['lines']:,} lines; feature windows {sc[0]['windows']['events_per_s_cpu']:,.0f}.")
    sp = [s["sharded"]["events_per_s_wall"] / (1e6 / (s["ingest"]["cpu_us_per_event"] + s["windows"]["cpu_us_per_event"]))
          for s in sc]
    out.append("Sharded x{} (ingest + windows + SENTINEL, wall clock) vs one core doing ingest + windows (CPU time): "
               "{} (speed-up is limited by the single coordinator, which reads, identifies and routes every record, "
               "and by other processes sharing this host).".format(
                   sc[0]["sharded"]["workers"], ", ".join(f"{s['lines']:,} lines {x:.2f}x" for s, x in zip(sc, sp))))
    need = report["cost"]["scales"][str(big["lines"])]
    out.append(f"At {big['lines']:,} lines the configured traffic needs {need['required_events_per_s']:,.0f} events/s; "
               f"one coordinator handled {big['sharded']['events_per_s_wall']:,.0f} events/s here, so a deployment at "
               "that size runs several coordinators fed by collector-side partitioning (Kafka partitions keyed with "
               "aegis.scale.kafka_partition_for_line).")
    mem = report["window_memory"]["bytes_per_line_24h_window"]
    out.append(f"Feature-window memory dominates at scale: about {mem / 1e3:,.0f} KB per line for a 24 h window "
               f"({mem * big['lines'] / 1e9:,.0f} GB at {big['lines']:,} lines). The store keeps per-event timestamps "
               "for periodicity features; bounding them (reservoirs) in aegis.sentinel.features is the main lever.")
    proj = report["resonance"]["projections"]
    for k, v in proj.items():
        if not v["fits_in_one_hour_on_one_core"] or v["peak_memory_gb"] > 64:
            out.append(f"RESONANCE at {int(k):,} lines ({v['basis']}): {v['cpu_s_per_hourly_run']:,.0f} CPU s and "
                       f"{v['peak_memory_gb']:,.0f} GB per hourly run. Detection is not sharded by destination "
                       "(the permutation null needs every destination of each line), so at this size the population "
                       "must be split into independent sub-populations (e.g. per region / BNG), each tested on its own.")
    rp = report["resonance_prep"]
    out.append(f"Sharded RESONANCE preparation ({rp['lines']:,} lines, {rp['workers']} workers) took "
               f"{rp['sharded_wall_s']:.1f} s vs {rp['single_wall_s']:.1f} s single-node: at this size shipping the "
               "frames to worker processes costs more than the join saves; it pays off only when the line shards "
               "already hold their data (Kafka / Kubernetes executors), not with the local executor.")
    out.append("1M-line rows process the same event budget as smaller scales over a shorter simulated window; "
               "throughput and per-line state lookups are measured with 1M distinct lines, full-day quantities are "
               "extrapolated as stated.")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="eval/load/report")
    ap.add_argument("--quick", action="store_true", help="small event budgets (smoke run)")
    ap.add_argument("--scales", default=None, help="comma-separated line counts (default 10000,100000,1000000)")
    ap.add_argument("--events-per-scale", type=int, default=None)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--flows-per-line-hour", type=float, default=None)
    ap.add_argument("--dns-per-line-hour", type=float, default=None)
    ap.add_argument("--eur-per-vcpu-hour", type=float, default=None)
    ap.add_argument("--eur-per-gb-month", type=float, default=None, help="storage price, € per GB-month")
    ap.add_argument("--eur-per-ram-gb-month", type=float, default=None)
    ap.add_argument("--target-utilization", type=float, default=None)
    ap.add_argument("--raw-retention-days", type=float, default=None)
    ap.add_argument("--no-raw-retention", action="store_true")
    ap.add_argument("--resonance-lines", default=None, help="comma-separated line counts for the RESONANCE series")
    ap.add_argument("--memory-lines", type=int, default=None)
    ap.add_argument("--memory-hours", type=float, default=None)
    ap.add_argument("--paced-seconds", type=float, default=None)
    ap.add_argument("--reuse", default=None, help="report JSON whose line-path stages are kept; only the "
                    "RESONANCE stages, cost model and findings are recomputed")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--resonance-worker", type=int, default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.resonance_worker is not None:
        print(json.dumps(resonance_worker(a.resonance_worker, a.seed)))
        return 0
    cfg = LoadConfig(**(QUICK if a.quick else {}), seed=a.seed)
    if a.scales:
        cfg.scales = [int(x) for x in a.scales.split(",")]
    if a.resonance_lines:
        cfg.resonance_lines = [int(x) for x in a.resonance_lines.split(",")]
        cfg.resonance_prep_lines = cfg.resonance_lines[-1]
    for name in ("events_per_scale", "workers", "flows_per_line_hour", "dns_per_line_hour", "memory_lines",
                 "memory_hours", "paced_seconds"):
        if getattr(a, name) is not None:
            setattr(cfg, name, getattr(a, name))
    if a.eur_per_vcpu_hour is not None:
        cfg.prices.eur_per_vcpu_hour = a.eur_per_vcpu_hour
    if a.eur_per_gb_month is not None:
        cfg.prices.eur_per_storage_gb_month = a.eur_per_gb_month
    if a.eur_per_ram_gb_month is not None:
        cfg.prices.eur_per_ram_gb_month = a.eur_per_ram_gb_month
    if a.target_utilization is not None:
        cfg.prices.target_utilization = a.target_utilization
    if a.raw_retention_days is not None:
        cfg.prices.raw_retention_days = a.raw_retention_days
    if a.no_raw_retention:
        cfg.prices.retain_raw = False

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    env = environment()
    t0 = time.perf_counter()
    if a.reuse:
        old = json.loads(Path(a.reuse).read_text())
        scales, memory, paced = old["scales"], old["window_memory"], old["paced"]
        cfg.scales = [s["lines"] for s in scales]
        env = old["environment"] | {"reused_line_path_stages_from": old["generated_at"]}
    else:
        scales = []
        for n in cfg.scales:
            print(f"[load] scale {n:,} lines", file=sys.stderr, flush=True)
            scales.append(run_scale(cfg, n))
        print("[load] window memory", file=sys.stderr, flush=True)
        memory = stage_window_memory(cfg)
        print("[load] controlled-rate runs", file=sys.stderr, flush=True)
        capacity = 1e6 / (scales[0]["ingest"]["cpu_us_per_event"] + scales[0]["windows"]["cpu_us_per_event"])
        paced = stage_paced(cfg, capacity)
    print("[load] RESONANCE", file=sys.stderr, flush=True)
    resonance = stage_resonance(cfg)
    resonance_prep = stage_resonance_prep(cfg, cfg.workers)
    env["loadavg_end"] = list(os.getloadavg())
    report: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "synthetic": True, "config": {k: v for k, v in asdict(cfg).items()}, "environment": env,
        "scales": scales, "window_memory": memory, "paced": paced, "resonance": resonance,
        "resonance_prep": resonance_prep, "runtime_s": None,
    }
    report["cost"] = cost_model(cfg, scales, memory, resonance)
    report["findings"] = findings(report)
    report["runtime_s"] = time.perf_counter() - t0
    (out / "load_report.json").write_text(json.dumps(report, indent=2, default=str))
    (out / "load_report.html").write_text(render_html(report))
    print(json.dumps({"out": str(out), "runtime_s": round(report["runtime_s"], 1),
                      "throughput_events_per_s": {s["lines"]: round(s["sharded"]["events_per_s_wall"])
                                                  for s in scales}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
