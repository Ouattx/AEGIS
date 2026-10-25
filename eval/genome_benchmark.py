"""GENOME benchmark: genome matched filter vs generic RESONANCE vs per-line periodicity.

Usage::

    python -m eval.genome_benchmark              # default grid (roughly 15-25 minutes on 4 cores)
    python -m eval.genome_benchmark --quick      # smoke grid (a few minutes)

Outputs ``genome_benchmark.json`` and a self-contained ``genome_benchmark.html`` in ``--out``.

Setup (all synthetic, see aegis.genome.sim): four families with distinct genomes are run on
lab boxes (3 days each, plus clean reference boxes of the same models); genomes are
extracted, signed and loaded through the verifying registry. ISP populations come from
aegis.resonance.sim (home NAT, browsing, streaming/IPTV, busy IPTV boxes, NTP, push,
telemetry, consoles, cameras, niche benign timers) with each family injected on N lines
at NetFlow packet sampling 1:1, 1:100, 1:1000 (resolver logs unsampled). All detectors get
the same warm-up history and the same minimum-lines gate.

Metrics:
* minimum infected lines for detection (smallest N in the grid detected in every seed),
  per family / sampling / method, plus detection rate per N with bootstrap CIs;
* line recall vs sampling at a fixed N;
* achieved campaign-level FDR vs target q (benign-only and infected runs);
* family attribution confusion matrix (GENOME only);
* time to detect (hours of data after onset) on growing windows;
* failure modes: shifted timer, genome drift, adversarial timer randomization, new
  infrastructure, cold start (no history).
95 % CIs: percentile bootstrap (1000 resamples) over runs.
"""
from __future__ import annotations

import argparse
import html
import json
import platform
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.genome import GenomeConfig, GenomeDetector, extract_genome, sign_genome  # noqa: E402
from aegis.genome.sim import DEFAULT_START, FamilySpec, isp_population, lab_capture, standard_families  # noqa: E402
from aegis.provenance.signing import KeyRing, Signer  # noqa: E402
from aegis.resonance import DestinationContext, Resonance, ResonanceConfig  # noqa: E402
from aegis.resonance.baselines import per_line_periodicity  # noqa: E402
from aegis.resonance.sim import ScenarioSpec, baseline_history, generate_scenario  # noqa: E402

METHODS = ("genome", "resonance", "per_line")
BENIGN_MARKERS = ("streamcdn", "edgefabric", "licensed-iptv", "iptv-operator", "iptv")


# ---------------------------------------------------------------------------- lab
def build_genomes(families: list[FamilySpec], seed: int, signer: Signer) -> tuple[list, dict[str, Any]]:
    models = sorted({m for f in families for m in f.box_models})
    clean = [lab_capture(None, box_model=m, seed=seed + 1000) for m in models]
    out, info = [], {}
    for f in families:
        res = extract_genome([lab_capture(f, box_model=m, seed=seed) for m in f.box_models], clean_reference=clean,
                             now=DEFAULT_START)
        if res.genome is None:
            info[f.name] = {"error": res.reason}
            continue
        g = sign_genome(res.genome, signer)
        out.append(g)
        info[f.name] = {"genome_id": g.genome_id, "period_s": g.timer.period_s, "true_period_s": f.period_s,
                        "jitter": f"{g.timer.jitter_family} {g.timer.jitter_scale:.3f}",
                        "true_jitter": f"{f.jitter} {f.jitter_scale:.3f}", "confidence": g.confidence,
                        "c2_keys": len(g.c2_keys)}
    return out, info


# ---------------------------------------------------------------------------- one run
def _family_of_campaign(members: list[str], infected: dict[str, str]) -> str | None:
    fams = [infected[m] for m in members if m in infected]
    if not fams:
        return None
    vals, cnt = np.unique(fams, return_counts=True)
    return str(vals[int(np.argmax(cnt))]) if cnt.max() >= 0.5 * len(members) else None


def run_detectors(sc, genomes, keyring, hist, *, q: float, min_lines: int, methods=METHODS,
                  until: float | None = None) -> dict[str, Any]:
    rc = ResonanceConfig(q=q, min_lines=min_lines)
    tb = sc.table(rc, until=until)
    ctx = DestinationContext(sc.topology)
    fam_keys = sc.family_keys
    out: dict[str, Any] = {"n_infected": {f: sum(1 for v in sc.infected.values() if v == f) for f in fam_keys}}
    now = DEFAULT_START + timedelta(seconds=(until or sc.end) - sc.start)
    if "genome" in methods:
        t0 = time.perf_counter()
        gcfg = GenomeConfig(q=q, resonance=ResonanceConfig(q=q, min_lines=min_lines, series_cap=600))
        rep = GenomeDetector(genomes, keyring, gcfg, context=ctx, history=hist, tenant_id="bench").detect(tb, now=now)
        camps = []
        for c in rep.campaigns:
            true = next((f for f, ks in fam_keys.items() if set(c.destinations) & ks), None)
            camps.append({"dest": c.destinations[:3], "n_lines": c.n_lines, "q": c.q_value, "family": c.family,
                          "true_family": true, "members": c.member_lines,
                          "benign_marker": any(m in d for d in c.destinations for m in BENIGN_MARKERS)})
        out["genome"] = {"campaigns": camps, "t": time.perf_counter() - t0, "status": rep.status,
                         "abstentions": len(rep.abstentions)}
    if "resonance" in methods:
        t0 = time.perf_counter()
        rr = Resonance(rc, context=ctx, history=hist, tenant_id="bench").detect(tb)
        camps = []
        for c in rr.campaigns:
            true = next((f for f, ks in fam_keys.items() if set(c.destinations) & ks), None)
            camps.append({"dest": c.destinations[:3], "n_lines": c.n_lines, "q": c.q_value, "true_family": true,
                          "members": c.member_lines,
                          "benign_marker": any(m in d for d in c.destinations for m in BENIGN_MARKERS)})
        out["resonance"] = {"campaigns": camps, "t": time.perf_counter() - t0, "status": rr.status}
    if "per_line" in methods:
        t0 = time.perf_counter()
        flagged = per_line_periodicity(tb, rc, q=q)
        fam_lines: dict[str, int] = {}
        benign_flag = 0
        for ln, keys in flagged.items():
            hit = [f for f, ks in fam_keys.items() if keys & ks and sc.infected.get(ln) == f]
            for f in hit:
                fam_lines[f] = fam_lines.get(f, 0) + 1
            if ln not in sc.infected:
                benign_flag += 1
        out["per_line"] = {"lines_by_family": fam_lines, "benign_lines_flagged": benign_flag,
                           "t": time.perf_counter() - t0}
    return out


def detected(run: dict[str, Any], method: str, fam: str) -> bool:
    if method == "per_line":
        n = run["n_infected"].get(fam, 0)
        return n > 0 and run["per_line"]["lines_by_family"].get(fam, 0) >= max(1, int(np.ceil(0.5 * n)))
    return any(c["true_family"] == fam for c in run[method]["campaigns"])


def line_recall(run: dict[str, Any], method: str, sc_infected: dict[str, str]) -> tuple[int, int]:
    tot = len(sc_infected)
    if method == "per_line":
        return sum(run["per_line"]["lines_by_family"].values()), tot
    hit = set()
    for c in run[method]["campaigns"]:
        if c["true_family"]:
            hit |= {m for m in c["members"] if sc_infected.get(m) == c["true_family"]}
    return len(hit), tot


def false_discoveries(run: dict[str, Any], method: str) -> tuple[int, int]:
    camps = run[method]["campaigns"]
    return sum(1 for c in camps if c["true_family"] is None), len(camps)


def boot_mean(x: list[float], n_boot: int = 1000, seed: int = 0) -> dict[str, Any]:
    a = np.asarray(x, dtype=float)
    if len(a) == 0:
        return {"mean": None, "ci": None, "n": 0}
    rng = np.random.default_rng(seed)
    bs = rng.choice(a, size=(n_boot, len(a)), replace=True).mean(axis=1)
    return {"mean": float(a.mean()), "ci": [float(np.quantile(bs, 0.025)), float(np.quantile(bs, 0.975))],
            "n": int(len(a))}


# ---------------------------------------------------------------------------- driver
def run_benchmark(*, lines: int = 2000, seeds: int = 3, samplings=(1, 100, 1000), n_grid=(3, 4, 5, 6, 8, 12, 16),
                  q: float = 0.01, qs=(0.01, 0.05, 0.1), min_lines: int = 3, recall_n: int = 8,
                  out_dir: str | Path = "eval/out/genome", ttd: bool = True, variants: bool = True,
                  verbose: bool = True) -> dict[str, Any]:
    t_all = time.perf_counter()
    signer = Signer.generate("genome-bench")
    kr = KeyRing()
    kr.add_signer(signer)
    fams = standard_families()
    genomes, ginfo = build_genomes(fams, 7, signer)
    log = (lambda *a: print(*a, flush=True)) if verbose else (lambda *a: None)
    log("genomes:", json.dumps(ginfo))
    runs: list[dict[str, Any]] = []
    fdr_runs: list[dict[str, Any]] = []
    for s in range(seeds):
        seed = 101 + s
        for samp in samplings:
            base = generate_scenario(ScenarioSpec(n_lines=lines, days=1.0, seed=seed, campaigns=[]), samp)
            hist = baseline_history(ScenarioSpec(n_lines=lines, days=1.0, seed=seed), sampling=samp)
            for n in (0, *n_grid):
                sc = isp_population([(f, n) for f in fams] if n else [], seed=seed, sampling=samp, base=base)
                qlist = qs if n in (0, recall_n) else (q,)
                for qq in qlist:
                    r = run_detectors(sc, genomes, kr, hist, q=qq, min_lines=min_lines,
                                      methods=METHODS if qq == q else ("genome", "resonance"))
                    r.update({"seed": seed, "sampling": samp, "n": n, "q": qq})
                    if qq == q and n:
                        r["recall"] = {m: line_recall(r, m, sc.infected) for m in METHODS}
                        runs.append(r)
                    fdr_runs.append({k: r[k] for k in ("seed", "sampling", "n", "q")} |
                                    {m: false_discoveries(r, m) for m in ("genome", "resonance")} |
                                    {"benign_marker_campaigns": {m: sum(c["benign_marker"] for c in r[m]["campaigns"])
                                                                 for m in ("genome", "resonance")},
                                     "per_line_benign_lines": r.get("per_line", {}).get("benign_lines_flagged")})
                log(f"seed={seed} 1:{samp} n={n} genome={[c['family'] for c in r['genome']['campaigns']]} "
                    f"resonance={[c['true_family'] for c in r['resonance']['campaigns']]}")

    # -------------------------------------------------- minimum lines + detection-rate curves
    min_lines_tab: dict[str, Any] = {}
    curves: dict[str, Any] = {}
    for samp in samplings:
        for m in METHODS:
            for f in fams:
                rates = {}
                ok_n = None
                for n in n_grid:
                    d = [float(detected(r, m, f.name)) for r in runs if r["sampling"] == samp and r["n"] == n]
                    rates[n] = boot_mean(d)
                    if ok_n is None and d and all(d):
                        ok_n = n
                min_lines_tab.setdefault(f"1:{samp}", {}).setdefault(m, {})[f.name] = ok_n
                curves.setdefault(f"1:{samp}", {}).setdefault(m, {})[f.name] = {str(k): v for k, v in rates.items()}
    # -------------------------------------------------- recall vs sampling
    recall: dict[str, Any] = {}
    for samp in samplings:
        for m in METHODS:
            per = [r["recall"][m][0] / max(1, r["recall"][m][1]) for r in runs
                   if r["sampling"] == samp and r["n"] == recall_n]
            recall.setdefault(f"1:{samp}", {})[m] = boot_mean(per)
    # -------------------------------------------------- achieved FDR vs q
    fdr: dict[str, Any] = {}
    for qq in qs:
        for m in ("genome", "resonance"):
            vals = [fr[m][0] / max(1, fr[m][1]) for fr in fdr_runs if fr["q"] == qq]
            benign_only = [fr[m][1] for fr in fdr_runs if fr["q"] == qq and fr["n"] == 0]
            fdr.setdefault(str(qq), {})[m] = {"achieved": boot_mean(vals),
                                              "benign_only_campaigns_total": int(sum(benign_only)),
                                              "benign_only_runs": len(benign_only),
                                              "iptv_cdn_campaigns": int(sum(fr["benign_marker_campaigns"][m]
                                                                            for fr in fdr_runs if fr["q"] == qq))}
    # -------------------------------------------------- attribution confusion
    names = [f.name for f in fams]
    conf = {t: {p: 0 for p in names + ["unlabeled"]} for t in names}
    for r in runs:
        for c in r["genome"]["campaigns"]:
            if c["true_family"]:
                conf[c["true_family"]][c["family"] or "unlabeled"] += 1
    tot = sum(sum(v.values()) for v in conf.values())
    acc = sum(conf[t][t] for t in names) / tot if tot else None
    correct = [float(c["family"] == c["true_family"]) for r in runs for c in r["genome"]["campaigns"]
               if c["true_family"]]
    attribution = {"confusion": conf, "accuracy": acc, "accuracy_ci": boot_mean(correct)["ci"], "n": tot}

    result: dict[str, Any] = {
        "config": {"lines": lines, "seeds": seeds, "samplings": list(samplings), "n_grid": list(n_grid), "q": q,
                   "qs": list(qs), "min_lines": min_lines, "recall_n": recall_n},
        "genomes": ginfo, "min_lines_needed": min_lines_tab, "detection_curves": curves, "recall": recall,
        "fdr": fdr, "attribution": attribution,
        "timing_s": {m: float(np.mean([r[m]["t"] for r in runs])) for m in METHODS},
        "per_line_false_alerts": {f"1:{samp}": boot_mean([float(fr["per_line_benign_lines"]) for fr in fdr_runs
                                                          if fr["sampling"] == samp and fr["q"] == q
                                                          and fr["per_line_benign_lines"] is not None])
                                  for samp in samplings},
    }
    # -------------------------------------------------- time to detect
    if ttd:
        seed = 101
        out_ttd: dict[str, Any] = {}
        for samp in samplings:
            base = generate_scenario(ScenarioSpec(n_lines=lines, days=1.0, seed=seed, campaigns=[]), samp)
            hist = baseline_history(ScenarioSpec(n_lines=lines, days=1.0, seed=seed), sampling=samp)
            sc = isp_population([(f, recall_n) for f in fams], seed=seed, sampling=samp, base=base)
            first: dict[str, dict[str, float | None]] = {m: {f.name: None for f in fams} for m in ("genome", "resonance")}
            for h in range(6, 25, 2):
                r = run_detectors(sc, genomes, kr, hist, q=q, min_lines=min_lines, methods=("genome", "resonance"),
                                  until=sc.start + h * 3600)
                for m in ("genome", "resonance"):
                    for f in fams:
                        if first[m][f.name] is None and detected(r, m, f.name):
                            first[m][f.name] = float(h)
            out_ttd[f"1:{samp}"] = first
            log(f"ttd 1:{samp}: {first}")
        result["time_to_detect_h"] = out_ttd
    # -------------------------------------------------- failure modes
    if variants:
        seed, samp, n = 101, 100, recall_n
        base = generate_scenario(ScenarioSpec(n_lines=lines, days=1.0, seed=seed, campaigns=[]), samp)
        hist = baseline_history(ScenarioSpec(n_lines=lines, days=1.0, seed=seed), sampling=samp)
        a = fams[0]
        cases = {
            "baseline_alpha": a,
            "shifted_timer_+15pct": a.variant(period_scale=1.15),
            "shifted_timer_+4pct": a.variant(period_scale=1.04),
            "drift_+10pct_over_day": a.variant(drift_frac=0.10),
            "adversarial_jitter_uniform_0.6": a.variant(jitter_scale=0.6),
        }
        var: dict[str, Any] = {}
        for name, f in cases.items():
            sc = isp_population([(f, n)], seed=seed, sampling=samp, base=base)
            r = run_detectors(sc, genomes, kr, hist, q=q, min_lines=min_lines, methods=("genome", "resonance"))
            g_c = [c for c in r["genome"]["campaigns"] if c["true_family"]]
            var[name] = {"genome_detected": bool(g_c), "genome_family": g_c[0]["family"] if g_c else None,
                         "resonance_detected": detected(r, "resonance", f.name)}
            log(f"variant {name}: {var[name]}")
        # new infrastructure (generation 1): matched by timing, not by indicators
        sc = isp_population([(a, n)], seed=seed, sampling=samp, base=base, generation=1)
        r = run_detectors(sc, genomes, kr, hist, q=q, min_lines=min_lines, methods=("genome", "resonance"))
        g_c = [c for c in r["genome"]["campaigns"] if c["true_family"]]
        var["new_infrastructure_gen1"] = {"genome_detected": bool(g_c),
                                          "genome_family": g_c[0]["family"] if g_c else None,
                                          "resonance_detected": detected(r, "resonance", a.name)}
        # cold start: no history
        sc = isp_population([(f, n) for f in fams], seed=seed, sampling=samp, base=base)
        r = run_detectors(sc, genomes, kr, None, q=q, min_lines=min_lines, methods=("genome", "resonance"))
        var["cold_start_no_history"] = {m: {"false_campaigns": false_discoveries(r, m)[0],
                                            "campaigns": false_discoveries(r, m)[1],
                                            "families_detected": sorted({c["true_family"] for c in r[m]["campaigns"]
                                                                         if c["true_family"]})}
                                        for m in ("genome", "resonance")}
        log(f"cold start: {var['cold_start_no_history']}")
        result["failure_modes"] = var
    result["meta"] = {"python": platform.python_version(), "platform": platform.platform(),
                      "wall_s": round(time.perf_counter() - t_all, 1)}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "genome_benchmark.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    (out / "genome_benchmark.html").write_text(render_html(result), encoding="utf-8")
    return result


# ---------------------------------------------------------------------------- HTML
def _f(x: Any, nd: int = 3) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return html.escape(str(x))


def _ci(b: dict[str, Any]) -> str:
    if not b or b.get("mean") is None:
        return "n/a"
    ci = b.get("ci")
    return f"{b['mean']:.3f}" + (f" <span class=ci>[{ci[0]:.3f}, {ci[1]:.3f}]</span>" if ci else "")


def render_html(r: dict[str, Any]) -> str:
    rows = []
    fams = list(r["genomes"])
    for samp, by_m in r["min_lines_needed"].items():
        for m, by_f in by_m.items():
            rows.append(f"<tr><td>{samp}</td><td>{m}</td>" + "".join(
                f"<td>{_f(by_f.get(f)) if by_f.get(f) is not None else '&gt; grid'}</td>" for f in fams) + "</tr>")
    min_tab = ("<table><tr><th>sampling</th><th>method</th>" + "".join(f"<th>{html.escape(f)}</th>" for f in fams)
               + "</tr>" + "".join(rows) + "</table>")
    rec = "".join(f"<tr><td>{s}</td>" + "".join(f"<td>{_ci(v[m])}</td>" for m in METHODS) + "</tr>"
                  for s, v in r["recall"].items())
    fdr = "".join(f"<tr><td>{q}</td>" + "".join(
        f"<td>{_ci(v[m]['achieved'])}</td><td>{v[m]['benign_only_campaigns_total']} / {v[m]['benign_only_runs']}</td>"
        f"<td>{v[m]['iptv_cdn_campaigns']}</td>" for m in ("genome", "resonance")) + "</tr>"
                  for q, v in r["fdr"].items())
    conf = r["attribution"]["confusion"]
    cols = list(next(iter(conf.values())).keys()) if conf else []
    cm = ("<table><tr><th>true \\ attributed</th>" + "".join(f"<th>{html.escape(c)}</th>" for c in cols) + "</tr>"
          + "".join(f"<tr><td>{html.escape(t)}</td>" + "".join(f"<td>{v[c]}</td>" for c in cols) + "</tr>"
                    for t, v in conf.items()) + "</table>")
    ttd = ""
    if "time_to_detect_h" in r:
        ttd = "<h2>Time to detect (hours of data, 2 h steps from 6 h)</h2><table><tr><th>sampling</th><th>method</th>" + \
              "".join(f"<th>{html.escape(f)}</th>" for f in fams) + "</tr>" + "".join(
                  f"<tr><td>{s}</td><td>{m}</td>" + "".join(f"<td>{_f(v[m].get(f), 0)}</td>" for f in fams) + "</tr>"
                  for s, v in r["time_to_detect_h"].items() for m in v) + "</table>"
    fm = ""
    if "failure_modes" in r:
        fm = "<h2>Failure modes and stress cases (1:100)</h2><pre>" + html.escape(
            json.dumps(r["failure_modes"], indent=2)) + "</pre>"
    curves = "<h2>Detection rate per infected-line count</h2><pre>" + html.escape(
        json.dumps(r["detection_curves"], indent=1)) + "</pre>"
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1"><title>GENOME Benchmark</title>
<style>
:root{{--bg:#fff;--fg:#1b1f24;--mut:#5b6470;--line:#d8dde3;--acc:#2456a6}}
@media (prefers-color-scheme: dark){{:root:not([data-theme="light"]){{--bg:#14171b;--fg:#e6e9ed;--mut:#9aa4af;--line:#2c333b;--acc:#7aa7f0}}}}
:root[data-theme="dark"]{{--bg:#14171b;--fg:#e6e9ed;--mut:#9aa4af;--line:#2c333b;--acc:#7aa7f0}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px}}
table{{border-collapse:collapse;margin:8px 0 20px;display:block;overflow-x:auto}}
td,th{{border:1px solid var(--line);padding:4px 8px;text-align:left;white-space:nowrap}}
th{{color:var(--mut)}} .ci{{color:var(--mut);font-size:12px}} pre{{overflow-x:auto;font-size:12px}}
h1,h2{{color:var(--acc)}}
</style></head><body>
<h1>GENOME benchmark</h1>
<p>Synthetic evaluation: {r['config']['lines']} lines, {r['config']['seeds']} seeds, target q={r['config']['q']},
minimum lines gate {r['config']['min_lines']} for every method. Numbers include failures. Lab genomes:</p>
<pre>{html.escape(json.dumps(r['genomes'], indent=1))}</pre>
<h2>Minimum infected lines needed (detected in every seed)</h2>{min_tab}
<h2>Line recall at N={r['config']['recall_n']} infected lines per family</h2>
<table><tr><th>sampling</th>{''.join(f'<th>{m}</th>' for m in METHODS)}</tr>{rec}</table>
<p>Per-line baseline: benign lines flagged per run (no population FDR control):
{html.escape(json.dumps({k: (round(v["mean"], 1) if v["mean"] is not None else None) for k, v in r["per_line_false_alerts"].items()}))}.
Its low minimum-lines numbers come with these false alerts.</p>
<h2>Achieved campaign FDR vs target q</h2>
<table><tr><th>q</th><th>GENOME FDR</th><th>GENOME benign-only campaigns / runs</th><th>GENOME IPTV/CDN campaigns</th>
<th>RESONANCE FDR</th><th>RESONANCE benign-only campaigns / runs</th><th>RESONANCE IPTV/CDN campaigns</th></tr>{fdr}</table>
<h2>Family attribution (GENOME)</h2><p>accuracy {_f(r['attribution']['accuracy'])}
95 % CI {_f(r['attribution']['accuracy_ci'])} over {r['attribution']['n']} detected campaigns</p>{cm}
{ttd}{fm}{curves}
<p>Mean detector time per run (s): {html.escape(json.dumps({k: round(v, 2) for k, v in r['timing_s'].items()}))}.
Wall time {r['meta']['wall_s']} s.</p>
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--lines", type=int, default=2000)
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--out", default="eval/out/genome")
    a = ap.parse_args(argv)
    if a.quick:
        r = run_benchmark(lines=1000, seeds=1, samplings=(1, 1000), n_grid=(3, 5, 8), qs=(0.01, 0.1), recall_n=8,
                          out_dir=a.out, ttd=False, variants=False)
    else:
        r = run_benchmark(lines=a.lines, seeds=a.seeds, out_dir=a.out)
    print(json.dumps({"min_lines_needed": r["min_lines_needed"], "recall": r["recall"],
                      "attribution_accuracy": r["attribution"]["accuracy"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
