"""Systems under comparison, all run over the same frozen corpus in one streaming pass.

* ``ensemble`` - the production :class:`~aegis.sentinel.Sentinel`: signed IOC rules +
  calibrated LightGBM + per-class anomaly + CUSUM change point, pre-registered fusion.
  Alert = MALICIOUS or SUSPICIOUS verdict (ABSTAIN is not an alert).
* ``supervised`` - the calibrated model alone: alert when the probability reaches the
  operating threshold (no rules, no persistence, no fusion).
* ``rules_only`` - the deterministic baseline: a Sentinel with the signed bundle and no
  model (fusion rules F0-F2 / F9), i.e. fresh, verified indicator contacts only.
* ``static_blocklist`` - external-style baseline modelled on a commodity DNS/IP
  blocklist: any contact with any indicator ever listed as malicious, ignoring
  freshness, expiry, confidence, contradiction and verification.
* ``threshold_heuristic`` - external-style baseline modelled on a threshold IDS: fixed,
  pre-registered volume/NXDOMAIN/fan-out thresholds per device window.

The windows are computed once by a shared :class:`~aegis.sentinel.WindowStore`; each
Sentinel keeps its own persistence and change-point state. A window is attributed to
the device-day of its last instant (same rule as the model card and the PoV report).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Callable

import numpy as np

from aegis.contracts.models import FeatureVector, Verdict
from aegis.lab.corpus import Corpus
from aegis.lab.iocs import lab_signer
from aegis.provenance.signing import KeyRing
from aegis.sentinel.detector import EventRejected, Sentinel
from aegis.sentinel.features import WindowStore
from aegis.sentinel.model import TrainedModel
from aegis.sentinel.rules import IOCBundle, load_bundle

from eval.stats import DeviceDayTable, SystemScores

SYSTEMS: tuple[str, ...] = ("ensemble", "supervised", "rules_only", "static_blocklist", "threshold_heuristic")
SYSTEM_DESCRIPTIONS: dict[str, str] = {
    "ensemble": "AEGIS Sentinel: signed IOC rules + calibrated model + anomaly + change point, pre-registered fusion",
    "supervised": "calibrated LightGBM alone at the operating threshold",
    "rules_only": "deterministic baseline: fresh, verified, signed indicator contacts (Sentinel without a model)",
    "static_blocklist": "external-style baseline: static blocklist, any listed indicator ever contacted",
    "threshold_heuristic": "external-style baseline: fixed volume / NXDOMAIN / fan-out thresholds",
}

#: pre-registered thresholds of the threshold_heuristic baseline: (feature conditions, name)
HEURISTIC_RULES: tuple[tuple[tuple[tuple[str, float], ...], str], ...] = (
    ((("nxdomain_rate", 0.30), ("nx_unique", 30.0)), "nxdomain_storm"),
    ((("zero_reply_frac", 0.50), ("flow_rate_h", 300.0)), "unanswered_flood"),
    ((("unique_dst_ip", 400.0),), "destination_fan_out"),
    ((("out_ratio", 0.70), ("bytes_out_rate_log", 7.0)), "sustained_egress"),
)


def _day(fv: FeatureVector) -> date:
    return (fv.window_end - timedelta(microseconds=1)).date()


def heuristic_score(fv: FeatureVector) -> tuple[bool, float]:
    """(alert, score in [0, 1]) of the threshold baseline for one window."""
    best = 0.0
    alert = False
    for conds, _name in HEURISTIC_RULES:
        ratios: list[float] = []
        for feat, thr in conds:
            v = fv.values.get(feat)
            if v is None or fv.missing.get(feat, False):
                ratios = []
                break
            ratios.append(float(v) / thr if thr else 0.0)
        if not ratios:
            continue
        r = min(ratios)
        alert = alert or r >= 1.0
        best = max(best, min(1.0, r / 2.0))
    return alert, best


def blocklist_hits(bundle: IOCBundle, dst_ips: set[str], qnames: set[str]) -> int:
    hit: set[str] = set()
    for ip in dst_ips:
        hit.update(i.indicator_id for i in bundle.for_ip(ip) if i.verdict == "malicious")
    for q in qnames:
        hit.update(i.indicator_id for i in bundle.for_domain(q) if i.verdict == "malicious")
    return len(hit)


def corpus_bundle(corpus: Corpus) -> IOCBundle:
    """The corpus' signed IOC bundle, signature-verified like a production bundle."""
    signer = lab_signer(corpus.seed)
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    return load_bundle(corpus.ioc_bundle(signer), ring)


@dataclass
class _Acc:
    alert: dict[tuple[str, date], bool] = field(default_factory=dict)
    score: dict[tuple[str, date], float] = field(default_factory=dict)
    abstain: dict[tuple[str, date], bool] = field(default_factory=dict)
    alert_times: dict[str, list[datetime]] = field(default_factory=dict)

    def add(self, key: tuple[str, date], alert: bool, score: float, when: datetime, abstain: bool = False) -> None:
        self.alert[key] = self.alert.get(key, False) or alert
        self.score[key] = max(self.score.get(key, 0.0), score)
        if abstain:
            self.abstain[key] = True
        if alert:
            self.alert_times.setdefault(key[0], []).append(when)

    def first_after(self, entity: str, t0: datetime) -> datetime | None:
        after = [t for t in self.alert_times.get(entity, ()) if t >= t0]
        return min(after) if after else None


@dataclass
class CorpusRun:
    table: DeviceDayTable
    systems: list[SystemScores]
    windows: int
    rejected_events: int
    ensemble_rules: dict[str, int]
    detector_version: str


def run_systems(corpus: Corpus, model: TrainedModel | None, *, supervised_threshold: float = 0.6,
                progress: Callable[[str], None] | None = None) -> CorpusRun:
    """Stream ``corpus`` once through every system and collect device-day outputs."""
    bundle = corpus_bundle(corpus)
    ws = WindowStore("24h", max_source_event_ids=0)
    ens = Sentinel(model, bundle, window_store=ws, tenant_id=corpus.tenant_id)
    rules = Sentinel(None, bundle, window_store=ws, tenant_id=corpus.tenant_id)
    acc = {name: _Acc() for name in SYSTEMS}
    rule_counts: dict[str, int] = {}
    windows = rejected = 0

    def handle(fvs: list[FeatureVector]) -> None:
        nonlocal windows
        if not fvs:
            return
        de = ens.evaluate(fvs)
        dr = rules.evaluate(fvs)
        for fv, e, r in zip(fvs, de, dr):
            windows += 1
            key = (fv.entity_pseudonym, _day(fv))
            when = fv.window_end
            v = e.result.verdict
            rule_counts[e.result.rule] = rule_counts.get(e.result.rule, 0) + 1
            rank = {Verdict.MALICIOUS: 2.0, Verdict.SUSPICIOUS: 1.0}.get(v, 0.0)
            acc["ensemble"].add(key, v in (Verdict.MALICIOUS, Verdict.SUSPICIOUS), (rank + e.result.score) / 3.0,
                                when, abstain=v == Verdict.ABSTAIN)
            if e.ml is not None:
                p = e.ml.probability
                acc["supervised"].add(key, p >= supervised_threshold, p, when)
            rv = r.result.verdict
            r_alert = rv in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
            ioc = float(r.result.component_scores.get("ioc") or 0.0)
            acc["rules_only"].add(key, r_alert, 0.5 * float(r_alert) + 0.5 * ioc, when)
            contacts = ws.contacts_for(fv)
            hits = blocklist_hits(bundle, set(contacts.dst_ips), set(contacts.qnames)) if contacts else 0
            acc["static_blocklist"].add(key, hits >= 1, min(1.0, hits / 3.0), when)
            h_alert, h_score = heuristic_score(fv)
            acc["threshold_heuristic"].add(key, h_alert, h_score, when)

    for n, ev in enumerate(corpus.events):
        try:
            ens.validate(ev)
        except EventRejected:
            rejected += 1
            continue
        handle(ws.update(ev))
        if progress is not None and n and n % 100_000 == 0:
            progress(f"{n:,} events")
    handle(ws.flush(corpus.end, corpus.tenant_id))

    devices = {d.entity_pseudonym: d for d in corpus.devices}
    keys = sorted(corpus.labels)
    table = DeviceDayTable(
        keys=keys, y=np.array([corpus.labels[k] != "benign" for k in keys], dtype=np.int8),
        device_class=[devices[k[0]].device_class for k in keys], label=[corpus.labels[k] for k in keys],
        hard_negative=np.array([devices[k[0]].hard_negative for k in keys], dtype=bool))
    infected = {d.entity_pseudonym: d.infected_at for d in corpus.devices if d.malicious and d.infected_at}
    out: list[SystemScores] = []
    for name in SYSTEMS:
        if name == "supervised" and model is None:
            continue
        a = acc[name]
        first_h: dict[str, float] = {}
        for ent, t0 in infected.items():
            t1 = a.first_after(ent, t0)
            if t1 is not None:
                first_h[ent] = (t1 - t0).total_seconds() / 3600.0
        out.append(SystemScores(
            name=name, alert=np.array([a.alert.get(k, False) for k in keys], dtype=bool),
            score=np.array([a.score.get(k, 0.0) for k in keys], dtype=float),
            abstain=(np.array([a.abstain.get(k, False) for k in keys], dtype=bool) if name == "ensemble" else None),
            first_alert_h=first_h))
    return CorpusRun(table=table, systems=out, windows=windows, rejected_events=rejected,
                     ensemble_rules=dict(sorted(rule_counts.items())), detector_version=ens.detector_version)


__all__ = ["CorpusRun", "HEURISTIC_RULES", "SYSTEMS", "SYSTEM_DESCRIPTIONS", "blocklist_hits", "corpus_bundle",
           "heuristic_score", "run_systems"]
