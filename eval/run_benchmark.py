"""AEGIS SHIELD independent benchmark harness (spec section 14).

Protocol:

1. **Frozen datasets.** Each scenario is a deterministic lab corpus whose content digest
   must match ``eval/frozen/manifest.json`` (dataset A = malicious device-days,
   B = legitimate device-days including hard negatives).
2. **Time-forward split.** The supervised model is trained only on corpora that end
   before the first evaluation corpus starts.
3. **Group isolation.** Training and evaluation corpora share no seed, device, tenant
   pseudonymization key or campaign; C2 infrastructure overlap is measured and reported.
   Threat-feed knowledge never enters the model (``ioc_contacts`` is excluded).
4. **Systems.** ensemble vs supervised vs rules-only (deterministic baseline) vs two
   external-style baselines (static blocklist, threshold IDS); see :mod:`eval.systems`.
5. **Statistics.** Device-day precision / recall / PR-AUC / false alerts per 10k
   device-days with paired device-cluster bootstrap 95% CIs, exact binomial intervals,
   PR curves, per-device-class confusion matrices, detection delay, high- and
   low-prevalence scenarios plus projections to other base rates, and a pre-registered
   release gate.

Outputs ``results.json`` and a self-contained ``report.html``.

Usage::

    python -m eval.run_benchmark --out eval/results            # shipped model, default scenarios
    python -m eval.run_benchmark --train --out eval/results    # retrain the model in-harness
    python -m eval.run_benchmark --freeze                      # record digests (after review)
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np

if __package__ in (None, ""):  # executed as a script: make the repository root importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis.lab.corpus import DEFAULT_START
from aegis.lab.topology import generate_topology
from aegis.sentinel.fusion import DEFAULT_FUSION_POLICY
from aegis.sentinel.model import TrainedModel, default_model_dir, load
from aegis.sentinel.training import DEFAULT_TRAIN_SEEDS, DEFAULT_TRAIN_SIZES, train_lab_model

from eval import datasets as D
from eval.stats import (
    BootstrapResult,
    DeviceDayTable,
    GateConfig,
    SystemScores,
    cluster_bootstrap,
    finite_or_none,
    ppv_interval,
    project_prevalence,
    release_gate,
    system_metrics,
)
from eval.systems import SYSTEM_DESCRIPTIONS, CorpusRun, run_systems

RESULTS_SCHEMA = "aegis.benchmark/1"

DEFAULT_SCENARIOS: tuple[D.ScenarioSpec, ...] = (
    D.ScenarioSpec(name="high_prevalence", seed=4242, n_devices=200, days=3, malicious_fraction=0.08,
                   start="2026-10-15T00:00:00+00:00", tenant_id="bench-high",
                   description="infection-heavy segment (about 8% of devices compromised during the window)"),
    D.ScenarioSpec(name="low_prevalence", seed=4343, n_devices=400, days=3, malicious_fraction=0.01,
                   start="2026-10-22T00:00:00+00:00", tenant_id="bench-low",
                   description="typical residential segment (about 1% of devices compromised)"),
)


@dataclass
class BenchmarkConfig:
    scenarios: tuple[D.ScenarioSpec, ...] = DEFAULT_SCENARIOS
    model_source: str = "default"                 # "default" (shipped model) or "train"
    model_dir: str | None = None
    train_seeds: tuple[int, ...] = DEFAULT_TRAIN_SEEDS
    train_sizes: tuple[int, ...] = DEFAULT_TRAIN_SIZES
    train_days: int = 3
    train_start: str = DEFAULT_START.isoformat()
    supervised_threshold: float = DEFAULT_FUSION_POLICY.ml_suspicious
    bootstrap: int = 1000
    seed: int = 7
    projected_prevalences: tuple[float, ...] = (0.001, 0.005, 0.01, 0.05)
    analyst_minutes_per_alert: float = 20.0
    gate: GateConfig = field(default_factory=GateConfig)
    manifest_path: str = str(D.FROZEN_MANIFEST)
    require_frozen: bool = True
    workers: int = 1


class ProtocolViolation(RuntimeError):
    """The configured run would break the evaluation protocol (leakage, time order)."""


# ---------------------------------------------------------------------------- model + isolation

def resolve_model(cfg: BenchmarkConfig, log: Callable[[str], None]) -> tuple[TrainedModel, dict[str, Any]]:
    if cfg.model_source == "train":
        log(f"training model on seeds {list(cfg.train_seeds)}")
        model = train_lab_model(cfg.train_seeds, n_devices=list(cfg.train_sizes), days=cfg.train_days,
                                seed=cfg.seed, workers=cfg.workers)
        info = {"source": "trained in harness", "train_seeds": list(cfg.train_seeds),
                "train_sizes": list(cfg.train_sizes), "train_days": cfg.train_days, "train_start": cfg.train_start}
    elif cfg.model_source == "default":
        mdir = Path(cfg.model_dir) if cfg.model_dir else default_model_dir()
        model = load(mdir)
        corpora = model.card.get("data", {}).get("corpora") or []
        seeds = [int(c["seed"]) for c in corpora if "seed" in c] or list(model.card.get("data", {}).get("seeds", []))
        days = max((int(c.get("days", cfg.train_days)) for c in corpora), default=cfg.train_days)
        info = {"source": f"shipped model ({mdir.name})", "train_seeds": seeds, "train_days": days,
                "train_start": DEFAULT_START.isoformat()}
    else:
        raise ValueError("model_source must be 'default' or 'train'")
    info.update({"model_id": model.model_id, "calibration_id": model.calibration_id,
                 "excluded_features": model.card.get("features", {}).get("excluded", {}),
                 "internal_split": model.card.get("split", {})})
    return model, info


def isolation_checks(cfg: BenchmarkConfig, model_info: dict[str, Any]) -> dict[str, Any]:
    """Verify time-forward ordering and group isolation between training and evaluation."""
    train_seeds = set(int(s) for s in model_info.get("train_seeds", []))
    if not train_seeds:
        raise ProtocolViolation("training seeds of the model are unknown; cannot verify isolation")
    eval_seeds = {s.seed for s in cfg.scenarios}
    shared = sorted(train_seeds & eval_seeds)
    if shared:
        raise ProtocolViolation(f"evaluation seeds {shared} were used for training")
    train_end = datetime.fromisoformat(model_info["train_start"]) + timedelta(days=int(model_info["train_days"]))
    first_eval = min(s.start_dt for s in cfg.scenarios)
    if first_eval < train_end:
        raise ProtocolViolation(f"evaluation starts {first_eval.isoformat()} before training data ends "
                                f"{train_end.isoformat()} (time-forward split violated)")
    train_c2_ips: set[str] = set()
    train_c2_domains: set[str] = set()
    for s in sorted(train_seeds):
        for fam in generate_topology(s).malicious.values():
            train_c2_ips.update(fam.c2_ips)
            train_c2_domains.update(fam.c2_domains)
    eval_c2_ips: set[str] = set()
    eval_c2_domains: set[str] = set()
    for sc in cfg.scenarios:
        for fam in generate_topology(sc.seed).malicious.values():
            eval_c2_ips.update(fam.c2_ips)
            eval_c2_domains.update(fam.c2_domains)
    return {
        "time_forward": {"train_end": train_end.isoformat(), "first_eval_start": first_eval.isoformat(), "ok": True},
        "seeds": {"train": sorted(train_seeds), "eval": sorted(eval_seeds), "shared": shared},
        "devices_shared": 0,
        "devices_note": ("device pseudonyms are keyed per (tenant, seed); disjoint seeds give disjoint devices and "
                         "pseudonymization keys"),
        "campaign_groups_shared": 0,
        "c2_ips_shared": len(train_c2_ips & eval_c2_ips),
        "c2_domain_names_shared": len(train_c2_domains & eval_c2_domains),
        "c2_note": ("emulated malware families reuse C2 domain names across lab seeds; the supervised model never "
                    "sees names or addresses (behavioral features only, ioc_contacts excluded), and indicator "
                    "knowledge enters only through each evaluation corpus' own signed bundle"),
        "feed_contamination": "none: ioc_contacts excluded from model inputs",
    }


# ---------------------------------------------------------------------------- evaluation

def _jsonable(v: Any) -> Any:
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, np.generic):
        return v.item()
    if isinstance(v, float):
        return finite_or_none(v)
    return v


def evaluate_tables(table: DeviceDayTable, systems: Sequence[SystemScores], cfg: BenchmarkConfig, *,
                    malicious_devices: int | None) -> tuple[dict[str, Any], BootstrapResult]:
    names = [s.name for s in systems]
    boot = cluster_bootstrap(table, systems, resamples=cfg.bootstrap, seed=cfg.seed,
                             reference=cfg.gate.candidate if cfg.gate.candidate in names else None)
    metrics = {}
    for s in systems:
        m = system_metrics(table, s, malicious_devices=malicious_devices)
        m["ci95"] = boot.ci[s.name]
        metrics[s.name] = m
    projections: dict[str, list[dict[str, Any]]] = {}
    for s in systems:
        m = metrics[s.name]
        rows = []
        for prev in cfg.projected_prevalences:
            row: dict[str, Any] = dict(project_prevalence(m["recall"], m["fpr"], prev,
                                                          minutes_per_alert=cfg.analyst_minutes_per_alert))
            row["ppv_ci95"] = ppv_interval(boot.samples[s.name]["recall"], boot.samples[s.name]["fpr"], prev)
            fpr_hi = m["fpr_ci95_exact"][1] if m["fpr_ci95_exact"] else None
            worst = project_prevalence(m["recall"], fpr_hi, prev, minutes_per_alert=cfg.analyst_minutes_per_alert)
            row["ppv_at_fpr_upper_exact"] = worst["ppv"]
            row["false_alerts_per_10k_at_fpr_upper_exact"] = worst["false_alerts_per_10k"]
            rows.append(row)
        projections[s.name] = rows
    base = float(table.y.mean()) if len(table.y) else None
    return {"device_days": len(table.keys), "positive_device_days": int(table.y.sum()), "base_rate": base,
            "devices": len(table.devices), "systems": metrics, "paired_differences_ci95": boot.diff_ci,
            "bootstrap_resamples": boot.resamples, "projections": projections}, boot


def run_benchmark(cfg: BenchmarkConfig, *, log: Callable[[str], None] = lambda m: None,
                  freeze_datasets: bool = False) -> dict[str, Any]:
    t0 = time.time()
    model, model_info = resolve_model(cfg, log)
    isolation = isolation_checks(cfg, model_info)
    manifest_path = Path(cfg.manifest_path)
    manifest = D.load_manifest(manifest_path)
    scenario_results: dict[str, Any] = {}
    dataset_info: dict[str, Any] = {}
    runs: list[tuple[D.ScenarioSpec, CorpusRun, int]] = []
    to_freeze: dict[str, tuple[D.ScenarioSpec, str, dict[str, Any]]] = {}
    for spec in cfg.scenarios:
        log(f"[{spec.name}] generating corpus (seed {spec.seed}, {spec.n_devices} devices, {spec.days} days)")
        corpus = D.generate(spec)
        digest = D.corpus_digest(corpus)
        summary = D.dataset_summary(corpus)
        status = "frozen_now" if freeze_datasets else D.check_frozen(spec, digest, manifest)
        if status == "unfrozen" and cfg.require_frozen:
            raise D.FrozenDatasetMismatch(
                f"dataset {spec.name!r} is not in the frozen manifest {manifest_path}; run with --freeze to record it")
        if freeze_datasets:
            to_freeze[spec.name] = (spec, digest, summary)
        dataset_info[spec.name] = {"spec": asdict(spec), "digest": digest, "frozen_status": status, **summary}
        log(f"[{spec.name}] running systems over {len(corpus.events):,} events")
        run = run_systems(corpus, model, supervised_threshold=cfg.supervised_threshold, progress=log)
        mal = len(corpus.malicious_devices())
        res, _boot = evaluate_tables(run.table, run.systems, cfg, malicious_devices=mal)
        res.update({"windows": run.windows, "rejected_events": run.rejected_events,
                    "ensemble_fusion_rules": run.ensemble_rules, "detector_version": run.detector_version,
                    "description": spec.description})
        scenario_results[spec.name] = res
        runs.append((spec, run, mal))
        del corpus
    if to_freeze:
        D.freeze(to_freeze, manifest_path)

    # pooled over scenarios (devices stay distinct: each scenario is its own tenant)
    names = [s.name for s in runs[0][1].systems]
    pooled_table = DeviceDayTable.concat([r.table for _, r, _ in runs], [s.name for s, _, _ in runs])
    pooled_systems = []
    for n in names:
        parts = [next(x for x in r.systems if x.name == n) for _, r, _ in runs]
        pooled_systems.append(SystemScores(
            name=n, alert=np.concatenate([p.alert for p in parts]), score=np.concatenate([p.score for p in parts]),
            abstain=(np.concatenate([p.abstain for p in parts]) if all(p.abstain is not None for p in parts)
                     else None),
            first_alert_h={f"{s.name}:{k}": v for (s, _, _), p in zip(runs, parts) for k, v in p.first_alert_h.items()}))
    pooled, boot_pooled = evaluate_tables(pooled_table, pooled_systems, cfg,
                                          malicious_devices=sum(m for _, _, m in runs))
    gate = release_gate(boot_pooled, cfg.gate)

    cfg_dict = asdict(cfg)
    cfg_dict["scenarios"] = [asdict(s) for s in cfg.scenarios]
    results = {
        "schema": RESULTS_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runtime_s": round(time.time() - t0, 1),
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "config": cfg_dict,
        "systems": {n: SYSTEM_DESCRIPTIONS[n] for n in names},
        "systems_not_evaluated": {
            "graph_plus_agents": ("ATLAS graph and ORACLE agents verify and explain alerts in the case workflow; "
                                  "they do not emit device-day detections, so they are assessed through case "
                                  "outcomes in the shadow PoV report, not in this detection benchmark"),
            "dataset_C": "legally verified infringement cases belong to RIGHTS, out of scope for SHIELD v1",
        },
        "model": model_info,
        "isolation": isolation,
        "datasets": dataset_info,
        "scenarios": scenario_results,
        "pooled": pooled,
        "release_gate": gate,
        "limitations": LIMITATIONS,
    }
    return _jsonable(results)


LIMITATIONS: list[str] = [
    "All datasets are synthetic lab corpora with emulated malware behaviour. They test the pipeline, the protocol "
    "and relative behaviour of systems; they do not estimate field accuracy on a real operator network.",
    "Emulated families are cleaner than real-world compromise, so absolute figures (especially near-perfect ones) "
    "will be lower on real traffic. Re-run this harness on operator shadow data with independent labels before "
    "quoting any figure externally.",
    "The external-style baselines are representative re-implementations (static blocklist, threshold IDS), not "
    "named commercial products; no claim is made about any specific vendor.",
    "Superiority claims are limited to the metrics and scenarios reported here, with the confidence intervals shown.",
    "Projected prevalence figures assume the measured recall and false-positive rate transfer to the new base rate; "
    "the exact-interval column shows the worst case consistent with the observed false-positive count.",
]


# ---------------------------------------------------------------------------- CLI

def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m eval.run_benchmark", description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default="eval/results", help="output directory for results.json and report.html")
    ap.add_argument("--train", action="store_true", help="retrain the supervised model in the harness")
    ap.add_argument("--model-dir", default=None, help="model directory (default: shipped model)")
    ap.add_argument("--bootstrap", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--minutes-per-alert", type=float, default=20.0)
    ap.add_argument("--fa-limit", type=float, default=5.0, help="max false-alert regression per 10k (gate)")
    ap.add_argument("--manifest", default=str(D.FROZEN_MANIFEST))
    ap.add_argument("--freeze", action="store_true", help="record dataset digests in the frozen manifest")
    ap.add_argument("--allow-unfrozen", action="store_true", help="evaluate datasets missing from the manifest")
    ap.add_argument("--quick", action="store_true", help="small scenarios for a smoke run (not frozen)")
    ap.add_argument("--workers", type=int, default=1)
    args = ap.parse_args(argv)

    scenarios = DEFAULT_SCENARIOS
    if args.quick:
        scenarios = tuple(replace(s, name=f"{s.name}_quick", n_devices=max(60, s.n_devices // 4), days=2)
                          for s in DEFAULT_SCENARIOS)
    cfg = BenchmarkConfig(scenarios=scenarios, model_source="train" if args.train else "default",
                          model_dir=args.model_dir, bootstrap=args.bootstrap, seed=args.seed,
                          analyst_minutes_per_alert=args.minutes_per_alert,
                          gate=GateConfig(max_false_alert_regression_per_10k=args.fa_limit),
                          manifest_path=args.manifest, require_frozen=not (args.allow_unfrozen or args.quick),
                          workers=args.workers)

    def log(msg: str) -> None:
        print(f"[benchmark] {msg}", file=sys.stderr, flush=True)

    results = run_benchmark(cfg, log=log, freeze_datasets=args.freeze)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    from eval.render import render_benchmark_html
    (out / "report.html").write_text(render_benchmark_html(results), encoding="utf-8")
    brief = {n: {k: results["pooled"]["systems"][n][k] for k in ("precision", "recall", "pr_auc",
                                                                  "false_alerts_per_10k")}
             for n in results["pooled"]["systems"]}
    print(json.dumps({"out": str(out), "release_gate_passed": results["release_gate"]["passed"], "pooled": brief},
                     indent=1))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
