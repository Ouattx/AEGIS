"""Backtesting of detection rules on frozen, labelled lab datasets.

Protocol (the same device-day protocol as ``eval/``, spec section 14):

* **Frozen data.** A :class:`BacktestDataset` is built from a deterministic lab corpus
  and carries a content digest (the same formula as ``eval.datasets.corpus_digest``).
  :func:`load_frozen_lab_dataset` regenerates a dataset listed in
  ``eval/frozen/manifest.json`` and refuses it when the digest differs.
* **Time-forward, held out.** The dataset is split at ``split_at``. Windows before the
  split are the only data a drafter may use as an (unlabelled) population baseline
  (:meth:`BacktestDataset.reference_windows`); metrics are computed only on device-days
  after the split, from windows lying entirely after it (``strict_windows``). Entities
  the rule was derived from are excluded (``exclude_entities``).
* **Device-day metrics.** A device-day alerts when any window ending that day fires.
  Precision, recall and false alerts per 10k device-days are reported with exact
  Clopper-Pearson intervals and with a device-cluster bootstrap (all days of a device
  are resampled together, so correlated days do not shrink the interval).
* **Overlap.** For each existing detector (device-day alert sets) the report gives
  shared alerts, Jaccard overlap and the rule's *novel* true positives: what the rule
  adds over the existing detection.

Synthetic results are labelled ``synthetic`` in every report.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, AbstractSet, Any, Callable, Iterable, Mapping, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict

from aegis.contracts.models import FeatureVector, Finding
from aegis.detengine.language import Contacts, RuleSpec, evaluate_rule, spec_sha256
from aegis.sentinel.features import WINDOW_SECONDS, WindowName, WindowStore

if TYPE_CHECKING:  # pragma: no cover
    from aegis.lab.corpus import Corpus

DeviceDay = tuple[str, date]
FROZEN_SCHEMA = "aegis.eval.frozen/1"
BENIGN = "benign"


class FrozenDatasetMismatch(RuntimeError):
    """A dataset's content differs from its frozen digest."""


def window_day(fv: FeatureVector) -> date:
    """The device-day a window is attributed to (a window ending at midnight belongs to the day before)."""
    return (fv.window_end - timedelta(microseconds=1)).date()


def _midnight(d: date) -> datetime:
    return datetime.combine(d, time(0), tzinfo=timezone.utc)


# ----------------------------------------------------------------------------- datasets


@dataclass
class BacktestDataset:
    """Feature windows (+ contacts) with independent device-day ground truth."""
    name: str
    tenant_id: str
    windows: list[FeatureVector]
    contacts: list[Contacts | None]
    labels: dict[DeviceDay, str]
    device_classes: dict[str, str]
    hard_negatives: frozenset[str]
    start: datetime
    end: datetime
    digest: str
    synthetic: bool = True
    frozen: bool = False
    source: str = "aegis.lab synthetic corpus"

    def __post_init__(self) -> None:
        if len(self.windows) != len(self.contacts):
            raise ValueError("windows and contacts must align")
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("dataset bounds must be timezone-aware")
        if any(fv.tenant_id != self.tenant_id for fv in self.windows):
            raise ValueError("every window must belong to the dataset tenant")

    def default_split(self) -> datetime:
        """Midnight after the first third of the span (at least one day of reference data)."""
        days = max(1, (self.end - self.start).days // 3)
        return _midnight((self.start + timedelta(days=days)).date())

    def reference_windows(self, before: datetime) -> list[FeatureVector]:
        """Unlabelled population windows ending at or before ``before`` (drafter baseline)."""
        return [fv for fv in self.windows if fv.window_end <= before]

    def descriptor(self) -> dict[str, Any]:
        return {"name": self.name, "tenant_id": self.tenant_id, "digest": self.digest, "frozen": self.frozen,
                "synthetic": self.synthetic, "source": self.source, "start": self.start.isoformat(),
                "end": self.end.isoformat(), "windows": len(self.windows), "device_days": len(self.labels),
                "positive_device_days": sum(1 for v in self.labels.values() if v != BENIGN)}


def corpus_digest(corpus: "Corpus") -> str:
    """SHA-256 over every event and label (identical to ``eval.datasets.corpus_digest``)."""
    h = hashlib.sha256()
    for ev in corpus.events:
        h.update(f"{ev.event_id}|{ev.integrity_sha256}|{ev.observed_at.isoformat()}\n".encode())
    for (ent, day), label in sorted(corpus.labels.items()):
        h.update(f"L|{ent}|{day.isoformat()}|{label}\n".encode())
    return h.hexdigest()


def dataset_from_corpus(corpus: "Corpus", *, name: str, expected_digest: str | None = None,
                        window: WindowName = "24h", hop: timedelta | None = None) -> BacktestDataset:
    """Run the production window store over a lab corpus, keeping each window's contacts.

    With ``expected_digest`` the corpus must match it (the dataset is then ``frozen``).
    """
    digest = corpus_digest(corpus)
    if expected_digest is not None and digest != expected_digest:
        raise FrozenDatasetMismatch(f"dataset {name!r}: digest {digest} != frozen {expected_digest}")
    store = WindowStore(window, hop, max_source_event_ids=0)
    windows: list[FeatureVector] = []
    contacts: list[Contacts | None] = []

    def take(fvs: list[FeatureVector]) -> None:
        for fv in fvs:
            cs = store.contacts_for(fv)
            windows.append(fv)
            contacts.append(Contacts.from_summary(cs) if cs is not None else None)

    for ev in corpus.events:
        take(store.update(ev))
    take(store.flush(corpus.end))
    return BacktestDataset(
        name=name, tenant_id=corpus.tenant_id, windows=windows, contacts=contacts, labels=dict(corpus.labels),
        device_classes={d.entity_pseudonym: d.device_class for d in corpus.devices},
        hard_negatives=frozenset(d.entity_pseudonym for d in corpus.hard_negatives()),
        start=corpus.start, end=corpus.end, digest=digest, synthetic=True, frozen=expected_digest is not None,
        source=f"aegis.lab synthetic corpus (seed {corpus.seed})")


def load_frozen_lab_dataset(name: str, manifest_path: str | Path) -> BacktestDataset:
    """Regenerate a dataset listed in a frozen manifest and verify its digest."""
    from aegis.lab.corpus import generate_corpus

    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema") != FROZEN_SCHEMA:
        raise FrozenDatasetMismatch(f"unsupported manifest schema {manifest.get('schema')!r}")
    entry = (manifest.get("datasets") or {}).get(name)
    if not isinstance(entry, dict):
        raise KeyError(f"dataset {name!r} is not in the frozen manifest")
    spec = entry["spec"]
    start = datetime.fromisoformat(spec["start"])
    if start.tzinfo is None:
        raise FrozenDatasetMismatch(f"dataset {name!r}: start must carry a UTC offset")
    corpus = generate_corpus(seed=int(spec["seed"]), days=int(spec["days"]), n_devices=int(spec["n_devices"]),
                             malicious_fraction=float(spec["malicious_fraction"]), tenant_id=spec["tenant_id"],
                             start=start.astimezone(timezone.utc))
    return dataset_from_corpus(corpus, name=name, expected_digest=entry["digest"])


# ----------------------------------------------------------------------------- statistics


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float] | None:
    """Exact binomial interval for ``k`` successes in ``n`` trials (None when ``n == 0``)."""
    if n <= 0:
        return None
    from scipy.stats import beta
    lo = 0.0 if k == 0 else float(beta.ppf(alpha / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - alpha / 2, k + 1, n - k))
    return lo, hi


def _div(a: float, b: float) -> float | None:
    return a / b if b > 0 else None


class Interval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    low: float
    high: float


def _iv(t: tuple[float, float] | None, scale: float = 1.0) -> Interval | None:
    return None if t is None else Interval(low=t[0] * scale, high=t[1] * scale)


class BacktestMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")
    device_days: int
    positive_device_days: int
    negative_device_days: int
    tp: int
    fp: int
    fn: int
    tn: int
    abstain_only_device_days: int
    precision: float | None
    recall: float | None
    false_alerts_per_10k: float | None
    precision_ci_exact: Interval | None
    recall_ci_exact: Interval | None
    false_alerts_per_10k_ci_exact: Interval | None
    precision_ci_bootstrap: Interval | None
    recall_ci_bootstrap: Interval | None
    false_alerts_per_10k_ci_bootstrap: Interval | None
    hard_negative_device_days: int
    hard_negative_alerts: int
    windows_evaluated: int
    windows_fired: int
    windows_abstained: int
    devices: int
    per_device_class: dict[str, dict[str, Any]]
    per_label: dict[str, dict[str, Any]]


class OverlapStats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detector: str
    detector_alerts: int
    rule_alerts: int
    shared_alerts: int
    jaccard: float | None
    rule_tp: int
    rule_tp_also_detected: int
    novel_tp: int


class RuleBacktestReport(BaseModel):
    """One backtest of one rule version on one dataset (DocStore kind ``RuleBacktestReport``)."""
    model_config = ConfigDict(extra="forbid")
    doc_id: str
    tenant_id: str
    rule_id: str
    rule_ref: str | None
    spec_sha256: str
    dataset: dict[str, Any]
    config: dict[str, Any]
    holdout_start: datetime | None
    excluded_entities: int
    metrics: BacktestMetrics
    overlap: list[OverlapStats]
    novel_tp_vs_all_existing: int | None
    false_alert_examples: list[dict[str, Any]]
    missed_examples: list[dict[str, Any]]
    sufficient: bool
    notes: list[str]
    synthetic: bool
    created_at: datetime
    created_by: str

    def summary(self) -> dict[str, Any]:
        m = self.metrics
        return {"backtest_id": self.doc_id, "dataset": self.dataset.get("name"), "synthetic": self.synthetic,
                "precision": m.precision, "recall": m.recall, "false_alerts_per_10k": m.false_alerts_per_10k,
                "precision_ci": m.precision_ci_exact.model_dump() if m.precision_ci_exact else None,
                "recall_ci": m.recall_ci_exact.model_dump() if m.recall_ci_exact else None,
                "false_alerts_per_10k_ci": (m.false_alerts_per_10k_ci_exact.model_dump()
                                            if m.false_alerts_per_10k_ci_exact else None),
                "device_days": m.device_days, "sufficient": self.sufficient}


@dataclass(frozen=True)
class BacktestConfig:
    split_at: datetime | None = None          # None: dataset.default_split()
    time_forward: bool = True                  # False: evaluate the whole dataset (fully held-out data only)
    strict_windows: bool = True                # windows must start at or after the split
    exclude_entities: frozenset[str] = frozenset()
    alpha: float = 0.05
    bootstrap: int = 500
    seed: int = 0
    min_holdout_device_days: int = 100
    min_holdout_positive_device_days: int = 5
    max_examples: int = 10

    def describe(self) -> dict[str, Any]:
        return {"split_at": self.split_at.isoformat() if self.split_at else None, "time_forward": self.time_forward,
                "strict_windows": self.strict_windows, "alpha": self.alpha, "bootstrap": self.bootstrap,
                "seed": self.seed, "min_holdout_device_days": self.min_holdout_device_days,
                "min_holdout_positive_device_days": self.min_holdout_positive_device_days}


def _bootstrap(per_device: np.ndarray, resamples: int, seed: int, alpha: float
               ) -> dict[str, tuple[float, float] | None]:
    """Cluster bootstrap over devices. ``per_device`` columns: tp, fp, fn, tn."""
    out: dict[str, tuple[float, float] | None] = {"precision": None, "recall": None, "fa10k": None}
    n = per_device.shape[0]
    if n == 0 or resamples <= 0:
        return out
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(resamples, n))
    sums = per_device[idx].sum(axis=1)                       # (resamples, 4)
    tp, fp, fn, tn = sums[:, 0], sums[:, 1], sums[:, 2], sums[:, 3]
    q = (100 * alpha / 2, 100 * (1 - alpha / 2))
    min_valid = max(10, resamples // 2)
    with np.errstate(divide="ignore", invalid="ignore"):
        for key, num, den, scale in (("precision", tp, tp + fp, 1.0), ("recall", tp, tp + fn, 1.0),
                                     ("fa10k", fp, fp + tn, 10_000.0)):
            valid = den > 0
            if int(valid.sum()) >= min_valid:
                v = num[valid] / den[valid] * scale
                lo, hi = np.percentile(v, q)
                out[key] = (float(lo), float(hi))
    return out


# ----------------------------------------------------------------------------- backtester


def alerts_from_findings(findings: Iterable[Finding]) -> set[DeviceDay]:
    """Device-days alerted by existing findings (verdict suspicious or malicious)."""
    out: set[DeviceDay] = set()
    for f in findings:
        if f.verdict.value in ("suspicious", "malicious"):
            out.add((f.entity_pseudonym, (f.observed_window_end - timedelta(microseconds=1)).date()))
    return out


def alerts_from_predicate(dataset: BacktestDataset,
                          predicate: Callable[[FeatureVector, Contacts | None], bool]) -> set[DeviceDay]:
    """Device-days on which ``predicate`` (an existing detector) fires on any window."""
    return {(fv.entity_pseudonym, window_day(fv)) for fv, c in zip(dataset.windows, dataset.contacts)
            if predicate(fv, c)}


def alerts_from_rules(dataset: BacktestDataset, specs: Sequence[RuleSpec]) -> set[DeviceDay]:
    """Device-days on which any of ``specs`` (e.g. already promoted rules) fires."""
    return alerts_from_predicate(dataset, lambda fv, c: any(evaluate_rule(s, fv, c).fired for s in specs))


class Backtester:
    """Runs rules over datasets and produces :class:`RuleBacktestReport` objects (not persisted here)."""

    def __init__(self, clock: Callable[[], datetime] | None = None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, spec: RuleSpec, dataset: BacktestDataset, *, tenant_id: str, actor: str,
            config: BacktestConfig | None = None, existing: Mapping[str, AbstractSet[DeviceDay]] | None = None,
            rule_ref: str | None = None) -> RuleBacktestReport:
        cfg = config or BacktestConfig()
        notes: list[str] = []
        split = (cfg.split_at or dataset.default_split()) if cfg.time_forward else None
        if split is not None and split.tzinfo is None:
            raise ValueError("split_at must be timezone-aware")
        excluded = cfg.exclude_entities

        def day_in_holdout(d: date) -> bool:
            return split is None or _midnight(d) >= split

        # ---- device-day universe
        keys = sorted(k for k in dataset.labels if k[0] not in excluded and day_in_holdout(k[1]))
        key_set = set(keys)
        fired: set[DeviceDay] = set()
        abstained: set[DeviceDay] = set()
        n_eval = n_fired = n_abstain = 0
        span = timedelta(seconds=WINDOW_SECONDS[spec.window])
        for fv, c in zip(dataset.windows, dataset.contacts):
            if fv.window != spec.window or fv.entity_pseudonym in excluded:
                continue
            if split is not None and (fv.window_end <= split or (cfg.strict_windows and fv.window_end - span < split)):
                continue
            k = (fv.entity_pseudonym, window_day(fv))
            if k not in key_set:
                continue
            n_eval += 1
            ev = evaluate_rule(spec, fv, c)
            if ev.outcome == "fired":
                n_fired += 1
                fired.add(k)
            elif ev.outcome == "abstain":
                n_abstain += 1
                abstained.add(k)

        y = np.array([dataset.labels[k] != BENIGN for k in keys], dtype=bool)
        alert = np.array([k in fired for k in keys], dtype=bool)
        tp = int((y & alert).sum())
        fp = int((~y & alert).sum())
        fn = int((y & ~alert).sum())
        tn = int((~y & ~alert).sum())
        pos, neg = tp + fn, fp + tn

        # ---- bootstrap (device clusters)
        dev_index: dict[str, int] = {}
        for ent, _ in keys:
            dev_index.setdefault(ent, len(dev_index))
        per_dev = np.zeros((len(dev_index), 4), dtype=np.int64)
        for i, (ent, _) in enumerate(keys):
            col = 0 if (y[i] and alert[i]) else 1 if alert[i] else 2 if y[i] else 3
            per_dev[dev_index[ent], col] += 1
        boot = _bootstrap(per_dev, cfg.bootstrap, cfg.seed, cfg.alpha)

        hn = np.array([k[0] in dataset.hard_negatives for k in keys], dtype=bool)
        per_class: dict[str, dict[str, Any]] = {}
        classes = [dataset.device_classes.get(k[0], "unknown") for k in keys]
        for klass in sorted(set(classes)):
            m = np.array([c == klass for c in classes], dtype=bool)
            ctp, cfp = int((y & alert & m).sum()), int((~y & alert & m).sum())
            cfn, ctn = int((y & ~alert & m).sum()), int((~y & ~alert & m).sum())
            per_class[klass] = {"device_days": int(m.sum()), "tp": ctp, "fp": cfp, "fn": cfn, "tn": ctn,
                                "precision": _div(ctp, ctp + cfp), "recall": _div(ctp, ctp + cfn),
                                "false_alerts_per_10k": (None if cfp + ctn == 0 else cfp / (cfp + ctn) * 10_000)}
        per_label: dict[str, dict[str, Any]] = {}
        labels = [dataset.labels[k] for k in keys]
        for lab in sorted(set(labels) - {BENIGN}):
            m = np.array([x == lab for x in labels], dtype=bool)
            per_label[lab] = {"device_days": int(m.sum()), "detected": int((alert & m).sum()),
                              "recall": _div(float((alert & m).sum()), float(m.sum()))}
        abstain_only = sum(1 for k in abstained if k not in fired)
        metrics = BacktestMetrics(
            device_days=len(keys), positive_device_days=pos, negative_device_days=neg, tp=tp, fp=fp, fn=fn, tn=tn,
            abstain_only_device_days=abstain_only, precision=_div(tp, tp + fp), recall=_div(tp, pos),
            false_alerts_per_10k=None if neg == 0 else fp / neg * 10_000,
            precision_ci_exact=_iv(clopper_pearson(tp, tp + fp, cfg.alpha)),
            recall_ci_exact=_iv(clopper_pearson(tp, pos, cfg.alpha)),
            false_alerts_per_10k_ci_exact=_iv(clopper_pearson(fp, neg, cfg.alpha), 10_000.0),
            precision_ci_bootstrap=_iv(boot["precision"]), recall_ci_bootstrap=_iv(boot["recall"]),
            false_alerts_per_10k_ci_bootstrap=_iv(boot["fa10k"]),
            hard_negative_device_days=int(hn.sum()), hard_negative_alerts=int((hn & alert).sum()),
            windows_evaluated=n_eval, windows_fired=n_fired, windows_abstained=n_abstain, devices=len(dev_index),
            per_device_class=per_class, per_label=per_label)

        # ---- overlap with existing detectors
        overlap: list[OverlapStats] = []
        rule_alerts = {k for k in keys if k in fired}
        rule_tp = {k for k in rule_alerts if dataset.labels[k] != BENIGN}
        caught_any: set[DeviceDay] = set()
        for name, raw in sorted((existing or {}).items()):
            det = {k for k in raw if k in key_set}
            caught_any |= det
            shared = rule_alerts & det
            union = rule_alerts | det
            overlap.append(OverlapStats(
                detector=name, detector_alerts=len(det), rule_alerts=len(rule_alerts), shared_alerts=len(shared),
                jaccard=_div(len(shared), len(union)), rule_tp=len(rule_tp),
                rule_tp_also_detected=len(rule_tp & det), novel_tp=len(rule_tp - det)))
        novel_all = len(rule_tp - caught_any) if existing else None

        # ---- examples (failure cases are part of an honest report)
        fa = [k for k in keys if k in fired and dataset.labels[k] == BENIGN]
        missed = [k for k in keys if k not in fired and dataset.labels[k] != BENIGN]
        fa_ex = [{"entity_pseudonym": e, "date": d.isoformat(), "device_class": dataset.device_classes.get(e, "unknown"),
                  "hard_negative": e in dataset.hard_negatives} for e, d in fa[:cfg.max_examples]]
        miss_ex = [{"entity_pseudonym": e, "date": d.isoformat(), "label": dataset.labels[(e, d)],
                    "device_class": dataset.device_classes.get(e, "unknown"), "abstained": (e, d) in abstained}
                   for e, d in missed[:cfg.max_examples]]

        sufficient = len(keys) >= cfg.min_holdout_device_days and pos >= cfg.min_holdout_positive_device_days
        if len(keys) < cfg.min_holdout_device_days:
            notes.append(f"holdout too small: {len(keys)} device-days < {cfg.min_holdout_device_days}")
        if pos < cfg.min_holdout_positive_device_days:
            notes.append(f"too few positive device-days: {pos} < {cfg.min_holdout_positive_device_days}")
        if dataset.synthetic:
            notes.append("synthetic lab data: rates do not transfer to production without shadow validation")
        if not dataset.frozen:
            notes.append("dataset digest not checked against a frozen manifest")
        if n_eval == 0:
            notes.append("no window was evaluated (window size or split excludes all data)")
        return RuleBacktestReport(
            doc_id=str(uuid.uuid4()), tenant_id=tenant_id, rule_id=spec.rule_id, rule_ref=rule_ref,
            spec_sha256=spec_sha256(spec), dataset=dataset.descriptor(), config=cfg.describe(), holdout_start=split,
            excluded_entities=len(excluded), metrics=metrics, overlap=overlap, novel_tp_vs_all_existing=novel_all,
            false_alert_examples=fa_ex, missed_examples=miss_ex, sufficient=sufficient, notes=notes,
            synthetic=dataset.synthetic, created_at=self.clock(), created_by=actor)


def summarize_reports(reports: Sequence[RuleBacktestReport]) -> dict[str, Any]:
    """Pooled counts over several reports (for display; the gate checks each report)."""
    c: Counter[str] = Counter()
    for r in reports:
        m = r.metrics
        c.update({"tp": m.tp, "fp": m.fp, "fn": m.fn, "tn": m.tn})
    neg = c["fp"] + c["tn"]
    return {"reports": len(reports), **dict(c), "precision": _div(c["tp"], c["tp"] + c["fp"]),
            "recall": _div(c["tp"], c["tp"] + c["fn"]),
            "false_alerts_per_10k": None if neg == 0 else c["fp"] / neg * 10_000,
            "synthetic_only": all(r.synthetic for r in reports) if reports else None}


__all__ = [
    "BacktestConfig", "BacktestDataset", "BacktestMetrics", "RuleBacktestReport", "Backtester", "DeviceDay",
    "FrozenDatasetMismatch", "Interval", "OverlapStats", "alerts_from_findings", "alerts_from_predicate",
    "alerts_from_rules", "clopper_pearson", "corpus_digest", "dataset_from_corpus", "load_frozen_lab_dataset",
    "summarize_reports", "window_day",
]
