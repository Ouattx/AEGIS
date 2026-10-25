"""RESONANCE benchmark: cross-subscriber resonance vs per-line periodicity vs static blocklist.

Usage::

    python -m eval.resonance_benchmark                 # default grid (about 10 minutes on 4 cores)
    python -m eval.resonance_benchmark --quick         # small smoke grid
    python -m eval.resonance_benchmark --lines 3000 --seeds 3 --out eval/out/resonance

Outputs ``resonance_benchmark.json`` and a self-contained ``resonance_benchmark.html``.

Scenarios (aegis.resonance.sim): home-NAT lines (1 + Poisson devices each) with benign
browsing, streaming/IPTV, busy always-on IPTV boxes, NTP, push, OS/TV telemetry, console
presence, cameras and niche benign widget timers; four campaigns at the given line
prevalence: ``standard`` (600 s +-15 %, fresh domain, cached DNS), ``slow`` (2400 s +-40 %,
fresh domain), ``evasive`` (per-bot period 15-60 min, +-30 %, 8 rotating domains on 4 IPs,
half the bots with hard-coded IPs, staggered onset) and ``known`` (900 s, C2 published in
the lab IOC feed - the case static blocklists are built for). NetFlow is packet-sampled 1:N; resolver
logs are unsampled. RESONANCE gets a warm-up history (one campaign-free day of the same
population, treated as 30 days of memory) unless stated otherwise.

Metrics (line level unless noted): precision, recall, false alerts per 10k line-days
(benign lines flagged / benign line-days), campaign-level achieved FDR (RESONANCE only),
per-campaign recall, detection delay (streaming, 1 h steps). 95 % CIs: percentile
bootstrap (1000 resamples) over runs, then lines within each resampled run.
"""
from __future__ import annotations

import argparse
import html
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.resonance import DestinationContext, Resonance, ResonanceConfig, ResonanceStream  # noqa: E402
from aegis.resonance.baselines import per_line_periodicity, static_blocklist  # noqa: E402
from aegis.resonance.sim import (  # noqa: E402
    ScenarioSpec,
    baseline_history,
    generate_scenario,
    merge_lines,
    standard_campaigns,
)

METHODS = ("resonance", "per_line_periodicity", "static_blocklist")
IPTV_CDN_MARKERS = ("iptv-operator", "streamcdn", "edgefabric")


# ---------------------------------------------------------------------------- one run

def _flagged_resonance(report) -> tuple[set[str], list[dict[str, Any]]]:
    lines: set[str] = set()
    camps = []
    for c in report.campaigns:
        lines.update(c.member_lines)
        camps.append({"destinations": c.destinations, "n_lines": c.n_lines, "q": c.q_value, "p": c.p_value,
                      "period_s": c.period_s, "statistic": c.statistic})
    return lines, camps


def run_once(spec: ScenarioSpec, sampling: int, cfg: ResonanceConfig, history, *, cgnat: int = 1,
             baselines: bool = True) -> dict[str, Any]:
    t0 = time.perf_counter()
    sc = generate_scenario(spec, sampling=sampling)
    if cgnat > 1:
        sc = merge_lines(sc, cgnat, seed=spec.seed)
    tb = sc.table(cfg)
    t_gen = time.perf_counter() - t0
    det = Resonance(cfg, context=DestinationContext(sc.topology), history=history, tenant_id="bench")
    t1 = time.perf_counter()
    rep = det.detect(tb)
    t_det = time.perf_counter() - t1
    mal = sc.malicious_keys()
    res_lines, camps = _flagged_resonance(rep)
    for c in camps:
        c["true"] = bool(set(c["destinations"]) & mal)
        c["iptv_or_cdn"] = any(any(m in d for m in IPTV_CDN_MARKERS) for d in c["destinations"])
    flagged = {"resonance": res_lines}
    if baselines:
        flagged["per_line_periodicity"] = set(per_line_periodicity(tb, cfg, q=cfg.q))
        flagged["static_blocklist"] = set(static_blocklist(tb, sc.blocklist))
    lines_all = sorted(set(tb.lines.items))
    infected = {ln for ln in lines_all if sc.infected.get(ln)}
    by_campaign = {c: {ln for ln, v in sc.infected.items() if c in v} for c in sc.campaign_keys}
    out = {"lines": lines_all, "infected": sorted(infected), "days": spec.days, "flagged": {k: sorted(v) for k, v in flagged.items()},
           "campaigns": camps, "by_campaign": {k: sorted(v) for k, v in by_campaign.items()},
           "detected_campaign_types": sorted(k for k, keys in sc.campaign_keys.items()
                                             if any(set(c["destinations"]) & keys for c in camps)),
           "status": rep.status, "n_tested": rep.n_tested, "timing_s": {"generate": round(t_gen, 2),
                                                                        "detect": round(t_det, 3)}}
    return out


# ---------------------------------------------------------------------------- metrics

def _line_metrics(run: dict[str, Any], method: str, idx: np.ndarray | None = None) -> tuple[int, int, int, int]:
    lines = np.array(run["lines"])
    if idx is not None:
        lines = lines[idx]
    inf = set(run["infected"])
    fl = set(run["flagged"].get(method, []))
    is_inf = np.fromiter((ln in inf for ln in lines), bool, len(lines))
    is_fl = np.fromiter((ln in fl for ln in lines), bool, len(lines))
    tp = int((is_inf & is_fl).sum())
    fp = int((~is_inf & is_fl).sum())
    fn = int((is_inf & ~is_fl).sum())
    neg = int((~is_inf).sum())
    return tp, fp, fn, neg


def _agg(counts: list[tuple[int, int, int, int]], days: float) -> dict[str, float | None]:
    tp, fp, fn, neg = (sum(c[i] for c in counts) for i in range(4))
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    fa = 1e4 * fp / (neg * days) if neg else None
    return {"precision": prec, "recall": rec, "false_alerts_per_10k_line_days": fa, "tp": tp, "fp": fp, "fn": fn}


def metrics_with_ci(runs: list[dict[str, Any]], method: str, n_boot: int = 1000, seed: int = 0) -> dict[str, Any]:
    days = runs[0]["days"] if runs else 1.0
    point = _agg([_line_metrics(r, method) for r in runs], days)
    rng = np.random.default_rng(seed)
    boots: dict[str, list[float]] = {"precision": [], "recall": [], "false_alerts_per_10k_line_days": []}
    for _ in range(n_boot):
        pick = rng.integers(0, len(runs), len(runs))
        cs = []
        for i in pick:
            n = len(runs[i]["lines"])
            cs.append(_line_metrics(runs[i], method, rng.integers(0, n, n)))
        a = _agg(cs, days)
        for k in boots:
            if a[k] is not None:
                boots[k].append(a[k])
    ci = {k: ([float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None) for k, v in boots.items()}
    return {**point, "ci95": ci}


def campaign_fdr(runs: list[dict[str, Any]], n_boot: int = 1000, seed: int = 0) -> dict[str, Any]:
    per_run = []
    for r in runs:
        n = len(r["campaigns"])
        f = sum(1 for c in r["campaigns"] if not c["true"])
        per_run.append((f, n))
    fdp = [f / n if n else 0.0 for f, n in per_run]
    rng = np.random.default_rng(seed)
    boots = [float(np.mean([fdp[i] for i in rng.integers(0, len(fdp), len(fdp))])) for _ in range(n_boot)] if fdp else []
    return {"achieved_fdr": float(np.mean(fdp)) if fdp else None,
            "ci95": [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))] if boots else None,
            "false_campaigns": sum(f for f, _ in per_run), "campaigns": sum(n for _, n in per_run),
            "runs_with_false_campaign": sum(1 for f, _ in per_run if f > 0), "runs": len(per_run)}


def per_campaign_recall(runs: list[dict[str, Any]]) -> dict[str, dict[str, float | None]]:
    out: dict[str, dict[str, float | None]] = {}
    for method in METHODS:
        acc: dict[str, list[int]] = {}
        for r in runs:
            fl = set(r["flagged"].get(method, []))
            for c, ls in r["by_campaign"].items():
                a = acc.setdefault(c, [0, 0])
                a[0] += sum(1 for ln in ls if ln in fl)
                a[1] += len(ls)
        out[method] = {c: (v[0] / v[1] if v[1] else None) for c, v in acc.items()}
    return out


# ---------------------------------------------------------------------------- detection delay (streaming)

def detection_delay(spec: ScenarioSpec, sampling: int, cfg: ResonanceConfig, history, step_s: float = 3600.0
                    ) -> dict[str, float | None]:
    sc = generate_scenario(spec, sampling=sampling)
    st = ResonanceStream(cfg, context=DestinationContext(sc.topology), history=history, tenant_id="bench",
                         step_s=step_s, update_history=False)
    first: dict[str, float] = {}
    t0 = sc.start
    n_steps = int(spec.days * 86400 / step_s)
    for h in range(1, n_steps + 1):
        a, b = t0 + (h - 1) * step_s, t0 + h * step_s
        st.ingest_frames(sc.flows[(sc.flows.t >= a) & (sc.flows.t < b)], sc.dns[(sc.dns.t >= a) & (sc.dns.t < b)])
        up = st.advance(b)
        if up is None:
            continue
        for c in up.report.campaigns:
            for name, keys in sc.campaign_keys.items():
                if name not in first and set(c.destinations) & keys:
                    first[name] = b
    return {name: (None if name not in first else round((first[name] - sc.campaign_onset[name]) / 3600.0, 2))
            for name in sc.campaign_keys}


# ---------------------------------------------------------------------------- driver

def run_benchmark(lines: int = 3000, seeds: int = 3, samplings=(1, 100, 1000), prevalences=(0.005, 0.02),
                  q: float = 0.01, out_dir: str | Path = "eval/out/resonance", delay: bool = True,
                  log=print) -> dict[str, Any]:
    cfg = ResonanceConfig(q=q)
    t_start = time.perf_counter()
    results: dict[str, Any] = {"config": cfg.as_dict(), "lines": lines, "seeds": seeds, "grid": [], "benign": {},
                               "hard_cases": {}, "delay": {}, "environment": {
                                   "python": platform.python_version(), "machine": platform.machine(),
                                   "processor_count": __import__("os").cpu_count()}}
    hist_cache: dict[tuple[int, int], Any] = {}

    def history(seed: int, sampling: int):
        key = (seed, sampling)
        if key not in hist_cache:
            hist_cache[key] = baseline_history(ScenarioSpec(n_lines=lines, seed=seed), cfg, sampling=sampling)
        return hist_cache[key]

    # main grid
    for sampling in samplings:
        for prev in prevalences:
            runs = []
            for s in range(seeds):
                seed = 1000 + s
                spec = ScenarioSpec(n_lines=lines, campaigns=standard_campaigns(prev), seed=seed)
                runs.append(run_once(spec, sampling, cfg, history(seed, sampling)))
                log(f"  sampling 1:{sampling} prevalence {prev} seed {seed}: "
                    f"{len(runs[-1]['campaigns'])} campaigns, detect {runs[-1]['timing_s']['detect']} s")
            entry = {"sampling": sampling, "prevalence": prev,
                     "infected_lines_per_campaign": int(round(prev * lines)),
                     "methods": {m: metrics_with_ci(runs, m) for m in METHODS},
                     "campaign_fdr": campaign_fdr(runs), "per_campaign_recall": per_campaign_recall(runs),
                     "detected_campaign_types": [r["detected_campaign_types"] for r in runs],
                     "detect_seconds": [r["timing_s"]["detect"] for r in runs]}
            results["grid"].append(entry)

    # benign-only: FDR control (with history) and cold start (no history)
    for sampling in samplings:
        runs = []
        for s in range(seeds):
            seed = 2000 + s
            spec = ScenarioSpec(n_lines=lines, campaigns=[], seed=seed)
            runs.append(run_once(spec, sampling, cfg, history(seed, sampling)))
        results["benign"][f"1:{sampling}"] = {
            "campaign_fdr": campaign_fdr(runs),
            "methods": {m: metrics_with_ci(runs, m) for m in METHODS},
            "iptv_or_cdn_campaigns": sum(1 for r in runs for c in r["campaigns"] if c["iptv_or_cdn"])}
        log(f"  benign 1:{sampling}: {results['benign'][f'1:{sampling}']['campaign_fdr']}")
    cold = []
    for s in range(seeds):
        spec = ScenarioSpec(n_lines=lines, campaigns=[], seed=3000 + s)
        cold.append(run_once(spec, 100, cfg, None, baselines=False))
    results["hard_cases"]["cold_start_no_history_benign_1:100"] = {
        "campaign_fdr": campaign_fdr(cold), "false_campaigns": [c for r in cold for c in r["campaigns"]],
        "iptv_or_cdn_campaigns": sum(1 for r in cold for c in r["campaigns"] if c["iptv_or_cdn"])}
    log(f"  cold start: {results['hard_cases']['cold_start_no_history_benign_1:100']['campaign_fdr']}")
    newapp = []
    for s in range(seeds):
        spec = ScenarioSpec(n_lines=lines, campaigns=[], seed=4000 + s, benign_new_app=True)
        newapp.append(run_once(spec, 100, cfg, history(4000 + s, 100), baselines=False))
    results["hard_cases"]["benign_new_app_rollout_1:100"] = {
        "campaign_fdr": campaign_fdr(newapp),
        "new_app_flagged_runs": sum(1 for r in newapp if any("newwidget" in d for c in r["campaigns"]
                                                             for d in c["destinations"]))}
    log(f"  new app rollout: {results['hard_cases']['benign_new_app_rollout_1:100']}")
    cg = []
    for s in range(seeds):
        seed = 5000 + s
        spec = ScenarioSpec(n_lines=lines, campaigns=standard_campaigns(0.02), seed=seed)
        cg.append(run_once(spec, 100, cfg, history(seed, 100), cgnat=4))
    results["hard_cases"]["cgnat_merge4_1:100_prev0.02"] = {
        "methods": {m: metrics_with_ci(cg, m) for m in METHODS}, "campaign_fdr": campaign_fdr(cg),
        "per_campaign_recall": per_campaign_recall(cg)}
    log("  cgnat done")
    if delay:
        for sampling in (100, 1000):
            ds = []
            for s in range(seeds):
                seed = 6000 + s
                spec = ScenarioSpec(n_lines=lines, campaigns=standard_campaigns(0.02), seed=seed)
                ds.append(detection_delay(spec, sampling, cfg, history(seed, sampling)))
            agg = {}
            for name in ds[0]:
                vals = [d[name] for d in ds if d[name] is not None]
                agg[name] = {"median_hours": float(np.median(vals)) if vals else None,
                             "detected_runs": len(vals), "runs": len(ds), "per_run_hours": [d[name] for d in ds]}
            results["delay"][f"1:{sampling}"] = agg
            log(f"  delay 1:{sampling}: {agg}")
    results["wall_seconds"] = round(time.perf_counter() - t_start, 1)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "resonance_benchmark.json").write_text(json.dumps(results, indent=2, default=float))
    (out / "resonance_benchmark.html").write_text(render_html(results))
    return results


# ---------------------------------------------------------------------------- HTML

def _f(x: Any, nd: int = 3) -> str:
    if x is None:
        return "&ndash;"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return html.escape(str(x))


def _ci(m: dict[str, Any], k: str, nd: int = 3) -> str:
    ci = (m.get("ci95") or {}).get(k)
    return f"{_f(m.get(k), nd)} <span class=ci>[{_f(ci[0], nd)}, {_f(ci[1], nd)}]</span>" if ci else _f(m.get(k), nd)


def render_html(r: dict[str, Any]) -> str:
    rows = []
    for e in r["grid"]:
        for m in METHODS:
            mm = e["methods"][m]
            fdr = e["campaign_fdr"] if m == "resonance" else None
            rows.append(
                f"<tr class='{m}'><td>1:{e['sampling']}</td><td>{e['prevalence']} ({e['infected_lines_per_campaign']}/campaign)</td>"
                f"<td>{m}</td><td>{_ci(mm, 'precision')}</td><td>{_ci(mm, 'recall')}</td>"
                f"<td>{_ci(mm, 'false_alerts_per_10k_line_days', 1)}</td>"
                f"<td>{_f(fdr['achieved_fdr']) if fdr else '&ndash;'}</td>"
                f"<td>{', '.join(f'{k}:{_f(v, 2)}' for k, v in e['per_campaign_recall'][m].items())}</td></tr>")
    brow = []
    for k, b in r["benign"].items():
        brow.append(f"<tr><td>{k}</td><td>{b['campaign_fdr']['false_campaigns']}</td>"
                    f"<td>{b['campaign_fdr']['runs_with_false_campaign']}/{b['campaign_fdr']['runs']}</td>"
                    f"<td>{b['iptv_or_cdn_campaigns']}</td>"
                    f"<td>{_ci(b['methods']['per_line_periodicity'], 'false_alerts_per_10k_line_days', 1)}</td>"
                    f"<td>{_ci(b['methods']['static_blocklist'], 'false_alerts_per_10k_line_days', 1)}</td></tr>")
    drow = []
    for k, d in r.get("delay", {}).items():
        for name, v in d.items():
            drow.append(f"<tr><td>{k}</td><td>{name}</td><td>{_f(v['median_hours'], 1)}</td>"
                        f"<td>{v['detected_runs']}/{v['runs']}</td></tr>")
    hc = r["hard_cases"]
    cold = hc.get("cold_start_no_history_benign_1:100", {})
    na = hc.get("benign_new_app_rollout_1:100", {})
    cg = hc.get("cgnat_merge4_1:100_prev0.02", {})
    cg_rows = "".join(f"<tr><td>{m}</td><td>{_ci(cg['methods'][m], 'precision')}</td><td>{_ci(cg['methods'][m], 'recall')}</td>"
                      f"<td>{_ci(cg['methods'][m], 'false_alerts_per_10k_line_days', 1)}</td></tr>" for m in METHODS) if cg else ""
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>RESONANCE benchmark</title><style>
:root{{--bg:#fff;--fg:#1d1d1f;--mut:#666;--line:#ddd;--acc:#2456c7}}
@media (prefers-color-scheme:dark){{:root{{--bg:#16171a;--fg:#e8e8ea;--mut:#9a9aa2;--line:#33343a;--acc:#7aa2ff}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px}}
table{{border-collapse:collapse;width:100%;margin:8px 0 24px;font-variant-numeric:tabular-nums}}
td,th{{border-bottom:1px solid var(--line);padding:4px 6px;text-align:left;vertical-align:top}}
th{{color:var(--mut);font-weight:600}} tr.resonance td{{font-weight:600}} .ci{{color:var(--mut);font-size:12px}}
.wrap{{overflow-x:auto}} code{{font-size:12px}} h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px}}
</style></head><body>
<h1>RESONANCE benchmark</h1>
<p>{r['lines']} subscriber lines (home NAT, several devices per line), 24 h, {r['seeds']} seeds per cell, target q = {r['config']['q']}.
Four campaigns per scenario (standard 600 s, slow 2400 s &plusmn;40 %, evasive desynchronized/rotating, known C2 listed in the IOC feed). CIs: 95 % bootstrap over runs then lines.
Synthetic data only; see docs/RESONANCE.md for what these numbers do and do not show. Wall time {r.get('wall_seconds')} s.</p>
<h2>Detection grid</h2><div class=wrap><table><tr><th>sampling</th><th>prevalence</th><th>method</th><th>precision</th><th>recall</th>
<th>false alerts / 10k line-days</th><th>campaign FDR</th><th>recall by campaign</th></tr>{''.join(rows)}</table></div>
<h2>Benign-only populations (FDR control, with warm-up history)</h2><div class=wrap><table><tr><th>sampling</th><th>false campaigns</th>
<th>runs with any false campaign</th><th>IPTV/CDN campaigns</th><th>per-line periodicity FA/10k</th><th>blocklist FA/10k</th></tr>{''.join(brow)}</table></div>
<h2>Hard cases (where it fails)</h2>
<p><b>Cold start, no history (benign only, 1:100):</b> {cold.get('campaign_fdr', {}).get('false_campaigns')} false campaigns in
{cold.get('campaign_fdr', {}).get('runs')} runs ({cold.get('iptv_or_cdn_campaigns')} on IPTV/CDN). Niche benign shared timers are genuine resonances; without history or an allowlist they are reported.</p>
<p><b>New benign app rollout (shared 900 s timer to a new destination on ~1.5 % of lines):</b> flagged in {na.get('new_app_flagged_runs')} of {na.get('campaign_fdr', {}).get('runs')} runs. Timing alone cannot separate a new benign timer from a new botnet.</p>
<p><b>CGNAT-style merging (4 lines per entity, 1:100, prevalence 0.02):</b></p>
<div class=wrap><table><tr><th>method</th><th>precision</th><th>recall</th><th>FA/10k</th></tr>{cg_rows}</table></div>
<h2>Detection delay (streaming, 1 h steps, 6 h minimum window)</h2><div class=wrap><table><tr><th>sampling</th><th>campaign</th>
<th>median hours after onset</th><th>detected</th></tr>{''.join(drow)}</table></div>
<details><summary>Raw JSON</summary><pre>{html.escape(json.dumps({k: v for k, v in r.items() if k != 'config'}, indent=1, default=float)[:200000])}</pre></details>
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lines", type=int, default=3000)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--q", type=float, default=0.01)
    ap.add_argument("--out", default="eval/out/resonance")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--no-delay", action="store_true")
    a = ap.parse_args(argv)
    if a.quick:
        res = run_benchmark(lines=800, seeds=1, samplings=(100,), prevalences=(0.02,), q=a.q, out_dir=a.out,
                            delay=not a.no_delay)
    else:
        res = run_benchmark(lines=a.lines, seeds=a.seeds, q=a.q, out_dir=a.out, delay=not a.no_delay)
    print(json.dumps({"wall_seconds": res["wall_seconds"], "out": a.out}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
