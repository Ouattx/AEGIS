"""Training and evaluation on the AEGIS lab corpus (spec sections 7 and 14).

- :func:`extract_windows` runs the production :class:`WindowStore` over events;
- :func:`lab_window_labels` derives window labels from the corpus' independent
  ground truth (a window is malicious once the device has been infected for at
  least ``min_exposure`` inside it; windows straddling the infection are excluded);
- :func:`lab_campaign_groups` maps infected devices to campaign/infrastructure
  groups so no campaign is shared between train and test;
- :func:`build_lab_dataset` / :func:`train_lab_model` build the shipped default
  model from corpora whose seeds differ from the evaluation corpus;
- :func:`evaluate_detector` runs the full :class:`Sentinel` over a corpus and
  reports device-day metrics of the *fused* detector (not only the model).

Command line::

    python -m aegis.sentinel.training --out models/sentinel-default
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from statistics import median
from typing import Any, Iterable, Sequence

from aegis.contracts.models import FeatureVector, ObservationEvent, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.provenance.signing import KeyRing
from aegis.sentinel.features import WindowName, WindowStore
from aegis.sentinel.model import TrainedModel, min_window_population, train
from aegis.sentinel.rules import IOCBundle, load_bundle

DEFAULT_TRAIN_SEEDS = (101, 202, 303, 404, 505, 606, 808, 909)
DEFAULT_TRAIN_SIZES = (200, 120, 260, 90)
DEFAULT_EVAL_SEED = 7


def extract_windows(events: Iterable[ObservationEvent], *, window: WindowName = "24h",
                    hop: timedelta | None = None, flush_at: datetime | None = None,
                    min_population: int | None = None) -> list[FeatureVector]:
    """Feature vectors for every window of ``events`` (event-id lists omitted to save memory)."""
    kwargs: dict[str, Any] = {"max_source_event_ids": 0}
    if min_population is not None:
        kwargs["min_population"] = min_population
    store = WindowStore(window, hop, **kwargs)
    out: list[FeatureVector] = []
    last: datetime | None = None
    for ev in events:
        out.extend(store.update(ev))
        if last is None or ev.observed_at > last:
            last = ev.observed_at
    end = flush_at or last
    if end is not None:
        out.extend(store.flush(end))
    return out


def lab_window_labels(corpus: Corpus, fvs: Sequence[FeatureVector], *,
                      min_exposure: timedelta = timedelta(hours=1)) -> list[int | None]:
    """1 = infected for >= ``min_exposure`` within the window, 0 = clean, None = ambiguous."""
    infected = {d.entity_pseudonym: d.infected_at for d in corpus.devices if d.malicious}
    out: list[int | None] = []
    for fv in fvs:
        t = infected.get(fv.entity_pseudonym)
        if t is None or t >= fv.window_end:
            out.append(0)
        elif t <= fv.window_end - min_exposure:
            out.append(1)
        else:
            out.append(None)
    return out


def lab_campaign_groups(corpus: Corpus) -> dict[str, str]:
    """Infected device -> campaign group (seed, family, C2 infrastructure)."""
    return {d.entity_pseudonym: f"campaign:{corpus.seed}:{d.malware_family}:{d.c2_ip}"
            for d in corpus.devices if d.malicious}


def lab_bundle(corpus: Corpus) -> IOCBundle:
    """The corpus' signed IOC bundle, verified like a production bundle."""
    from aegis.lab.iocs import lab_signer
    signer = lab_signer(corpus.seed)
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    return load_bundle(corpus.ioc_bundle(signer), ring)


@dataclass
class LabDataset:
    features: list[FeatureVector] = field(default_factory=list)
    labels: list[int | None] = field(default_factory=list)
    groups: dict[str, str] = field(default_factory=dict)
    info: dict[str, Any] = field(default_factory=dict)


def _seed_windows(args: tuple[int, int, int, float, str]) -> tuple[list[FeatureVector], list[int | None],
                                                                   dict[str, str], dict[str, Any]]:
    seed, n_devices, days, malicious_fraction, tenant_id = args
    corpus = generate_corpus(seed=seed, days=days, n_devices=n_devices, malicious_fraction=malicious_fraction,
                             tenant_id=tenant_id)
    fvs = extract_windows(corpus.events, flush_at=corpus.end)
    info = {"seed": seed, "devices": n_devices, "days": days, "events": len(corpus.events), "windows": len(fvs),
            "malicious_devices": len(corpus.malicious_devices()),
            "hard_negative_devices": len(corpus.hard_negatives()),
            "min_window_population": min_window_population(fvs)}
    return fvs, lab_window_labels(corpus, fvs), lab_campaign_groups(corpus), info


def build_lab_dataset(seeds: Sequence[int] = DEFAULT_TRAIN_SEEDS, *,
                      n_devices: int | Sequence[int] = DEFAULT_TRAIN_SIZES, days: int = 3,
                      malicious_fraction: float = 0.08, tenant_id: str = "lab", workers: int = 1) -> LabDataset:
    """Windows + labels + campaign groups from one lab corpus per seed.

    ``n_devices`` may be a sequence cycled over the seeds, so prevalence features are
    learned across tenant sizes. ``workers`` > 1 builds corpora in parallel processes.
    """
    sizes = [n_devices] if isinstance(n_devices, int) else list(n_devices)
    jobs = [(seed, sizes[i % len(sizes)], days, malicious_fraction, tenant_id) for i, seed in enumerate(seeds)]
    if workers > 1 and len(jobs) > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=min(workers, len(jobs))) as pool:
            results = list(pool.map(_seed_windows, jobs))
    else:
        results = [_seed_windows(j) for j in jobs]
    ds = LabDataset()
    per_seed = []
    for fvs, labels, groups, info in results:
        ds.features.extend(fvs)
        ds.labels.extend(labels)
        ds.groups.update(groups)
        per_seed.append(info)
    ds.info = {"source": "aegis.lab synthetic corpus", "seeds": list(seeds), "malicious_fraction": malicious_fraction,
               "window": "24h", "hop": "1h", "label_rule": "infected >= 1h inside the window; straddling excluded",
               "corpora": per_seed}
    return ds


def train_lab_model(seeds: Sequence[int] = DEFAULT_TRAIN_SEEDS, *,
                    n_devices: int | Sequence[int] = DEFAULT_TRAIN_SIZES, days: int = 3,
                    seed: int = 7, version: str | None = None, workers: int = 1) -> TrainedModel:
    ds = build_lab_dataset(seeds, n_devices=n_devices, days=days, workers=workers)
    return train(ds.features, ds.labels, seed, groups=ds.groups, dataset_info=ds.info, version=version)


# ---------------------------------------------------------------------------- end-to-end evaluation

def evaluate_detector(corpus: Corpus, model: TrainedModel | None, bundle: IOCBundle | None = None, *,
                      use_bundle: bool = True) -> dict[str, Any]:
    """Run the fused :class:`Sentinel` over ``corpus`` and score it per device-day.

    A device-day is *alerted* when any window attributed to it (by window end) gets a
    MALICIOUS or SUSPICIOUS verdict. Returns precision/recall, false alerts per 10k
    device-days, per-class and per-label breakdowns, hard-negative outcomes and
    detection delay. Also returns the emitted findings count and verdict mix.
    """
    from aegis.sentinel.detector import Sentinel
    if bundle is None and use_bundle:
        bundle = lab_bundle(corpus)
    sentinel = Sentinel(model, bundle if use_bundle else None, record_decisions=True)
    findings = sentinel.process_batch(corpus.events)
    findings += sentinel.flush(corpus.end)
    alerted: dict[tuple[str, date], set[str]] = defaultdict(set)
    first_alert: dict[str, datetime] = {}
    for r in sentinel.decisions:
        if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            day = (r.window_end - timedelta(microseconds=1)).date()
            alerted[(r.entity_pseudonym, day)].add(r.verdict.value)
            if r.entity_pseudonym not in first_alert or r.window_end < first_alert[r.entity_pseudonym]:
                first_alert[r.entity_pseudonym] = r.window_end
    devices = {d.entity_pseudonym: d for d in corpus.devices}
    tp = fp = fn = tn = 0
    per_class: dict[str, Counter[str]] = defaultdict(Counter)
    per_label: dict[str, Counter[str]] = defaultdict(Counter)
    for (ent, day), label in corpus.labels.items():
        dev = devices[ent]
        positive = label != "benign"
        flagged = (ent, day) in alerted
        key = ("tp" if flagged else "fn") if positive else ("fp" if flagged else "tn")
        tp, fp, fn, tn = tp + (key == "tp"), fp + (key == "fp"), fn + (key == "fn"), tn + (key == "tn")
        per_class[dev.device_class][key] += 1
        per_label[label][key] += 1
    total = tp + fp + fn + tn
    mal_devices = corpus.malicious_devices()
    detected_devices = [d for d in mal_devices if d.entity_pseudonym in first_alert]
    delays = [(first_alert[d.entity_pseudonym] - d.infected_at).total_seconds() / 3600.0
              for d in detected_devices if d.infected_at is not None
              and first_alert[d.entity_pseudonym] >= d.infected_at]
    hard = corpus.hard_negatives()
    hard_alerted = sorted({ent for (ent, _), _v in alerted.items() if devices[ent].hard_negative})

    def stats(c: Counter[str]) -> dict[str, Any]:
        n = sum(c.values())
        return {"device_days": n, "tp": c["tp"], "fp": c["fp"], "fn": c["fn"], "tn": c["tn"],
                "precision": c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else None,
                "recall": c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None,
                "false_alerts_per_10k_device_days": 1e4 * c["fp"] / n if n else None}

    by_label_detection: Counter[str] = Counter()
    for d in detected_devices:
        by_label_detection[d.malicious_label or "?"] += 1
    return {
        "corpus": corpus.summary() | {"start": corpus.start.isoformat()},
        "detector_version": sentinel.detector_version,
        "device_days": total, "positive_device_days": tp + fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_alerts_per_10k_device_days": 1e4 * fp / total if total else None,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "per_device_class": {k: stats(v) for k, v in sorted(per_class.items())},
        "per_label": {k: stats(v) for k, v in sorted(per_label.items())},
        "malicious_devices": len(mal_devices), "malicious_devices_detected": len(detected_devices),
        "detected_by_label": dict(by_label_detection),
        "malicious_by_label": dict(Counter(d.malicious_label or "?" for d in mal_devices)),
        "detection_delay_hours_median": median(delays) if delays else None,
        "hard_negative_devices": len(hard), "hard_negative_devices_alerted": len(hard_alerted),
        "findings_emitted": len(findings),
        "findings_by_verdict": dict(Counter(f.verdict.value for f in findings)),
        "windows": sentinel.stats.windows, "verdicts": dict(sentinel.stats.verdicts),
        "rules": dict(sentinel.stats.rules),
    }


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train the Sentinel model on the lab corpus and evaluate it")
    ap.add_argument("--out", default="models/sentinel-default")
    ap.add_argument("--seeds", default=",".join(str(s) for s in DEFAULT_TRAIN_SEEDS))
    ap.add_argument("--devices", default=",".join(str(n) for n in DEFAULT_TRAIN_SIZES),
                    help="device count per corpus, cycled over the seeds")
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--eval-seed", type=int, default=DEFAULT_EVAL_SEED)
    ap.add_argument("--version", default=None)
    ap.add_argument("--workers", type=int, default=1)
    args = ap.parse_args(argv)
    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    if args.eval_seed in seeds:
        ap.error("the evaluation seed must not be a training seed")
    sizes = [int(n) for n in str(args.devices).split(",") if n.strip()]
    model = train_lab_model(seeds, n_devices=sizes, days=args.days, version=args.version,
                            workers=args.workers)
    corpus = generate_corpus(seed=args.eval_seed, days=3, n_devices=200, tenant_id="lab-eval")
    model.card["metrics"]["external_holdout_detector"] = evaluate_detector(corpus, model)
    model.card["metrics"]["external_holdout_detector_no_iocs"] = evaluate_detector(corpus, model, use_bundle=False)
    model.card["metrics"]["external_holdout_note"] = (
        f"full Sentinel (rules + model + anomaly + change-point + fusion) on an unseen corpus "
        f"(seed {args.eval_seed}: unseen devices, topology and campaigns), device-day level")
    model.card["evaluated_at"] = datetime.now(timezone.utc).isoformat()
    out = model.save(args.out)
    print(json.dumps({"out": str(out), "model_id": model.model_id,
                      "test": _brief(model.card["metrics"]["test"]),
                      "holdout": {k: model.card["metrics"]["external_holdout_detector"][k]
                                  for k in ("precision", "recall", "false_alerts_per_10k_device_days",
                                            "malicious_devices", "malicious_devices_detected",
                                            "hard_negative_devices_alerted")}}, indent=1, default=str))
    return 0


def _brief(m: dict[str, Any] | None) -> dict[str, Any] | None:
    if m is None:
        return None
    op = m["operating_points"]["0.60"]
    return {"pr_auc": m["pr_auc"], "ece": m["ece"], "precision@0.6": op["device_day"]["precision"],
            "recall@0.6": op["device_day"]["recall"],
            "false_alerts_per_10k@0.6": op["false_alerts_per_10k_device_days"]}


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
