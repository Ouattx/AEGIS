"""Single-home analysis mode.

Runs, per lab device:

1. **SENTINEL** (the production per-device detectors: indicator rules, calibrated model,
   anomaly, change points, fusion with mandatory ABSTAIN) over the imported events;
2. **timer / heartbeat analysis** with periodograms (:mod:`.timers`), split into active
   and idle behavior when the owner provided usage windows;
3. **contacted infrastructure** with signed-feed matches (:mod:`.infra`);
4. the pre-registered **Box Lab verdict** (:mod:`.verdict`).

Every input file hash, timer, feed match, counter-evidence item and verdict is written
as evidence through the provenance layer (sha256 + signed hash-chained ledger), so the
report's evidence trail can be re-verified. Nothing here calls an LLM, and nothing
changes any policy, model or enforcement point.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Sequence

import numpy as np

from aegis.contracts.models import Evidence, EvidenceKind, Finding, ObservationEvent
from aegis.homelab.importer import CaptureImport
from aegis.homelab.infra import FeedMatch, InfraSummary, analyze_infrastructure
from aegis.homelab.store import LabStore
from aegis.homelab.timers import TimerAnalysis, analyze_timers
from aegis.homelab.usage import ResolvedUsage, UsageWindows
from aegis.homelab.verdict import CAPTURE_ORIGIN, BoxVerdict, decide
from aegis.resonance.config import ResonanceConfig
from aegis.sentinel.detector import Sentinel
from aegis.sentinel.model import TrainedModel, load_default
from aegis.sentinel.rules import IOCBundle

HOMELAB_VERSION = "1.0.0"
VERDICT_ENTRY = "homelab_verdict"
SENTINEL_OOD_NOTE = ("SENTINEL's shipped model was trained and calibrated on the synthetic lab corpus at operator "
                     "vantage; one home device is outside that distribution, so its scores are indicative only.")


@dataclass(frozen=True)
class HourBin:
    hour: datetime
    flows: int
    dns: int
    bytes_total: int | None
    active_share: float | None            # share of the hour inside active usage windows (None = no usage)

    def to_dict(self) -> dict[str, Any]:
        return {"hour": self.hour.isoformat(), "flows": self.flows, "dns": self.dns,
                "bytes_total": self.bytes_total, "active_share": self.active_share}


@dataclass
class DeviceAnalysis:
    entity_pseudonym: str
    label: str
    n_events: int
    n_flows: int
    n_dns: int
    timers: TimerAnalysis
    infra: InfraSummary
    sentinel_findings: list[Finding]
    sentinel_windows: dict[str, int]
    sentinel_rules: dict[str, str]
    hourly: list[HourBin]
    verdict: BoxVerdict
    evidence: list[Evidence] = field(default_factory=list)
    local_chatter: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"entity_pseudonym": self.entity_pseudonym, "label": self.label, "events": self.n_events,
                "flows": self.n_flows, "dns": self.n_dns, "timers": self.timers.to_dict(),
                "infrastructure": self.infra.to_dict(),
                "sentinel": {"windows": self.sentinel_windows, "rules": self.sentinel_rules,
                             "findings": [f.model_dump(mode="json") for f in self.sentinel_findings]},
                "hourly": [h.to_dict() for h in self.hourly], "verdict": self.verdict.to_dict(),
                "evidence": [{"evidence_id": e.evidence_id, "kind": e.kind.value, "sha256": e.sha256,
                              "summary": e.summary, "supports": e.supports,
                              "source_independence_group": e.source_independence_group} for e in self.evidence],
                "local_chatter": self.local_chatter}


@dataclass
class HomeLabAnalysis:
    capture: CaptureImport
    usage: UsageWindows | None
    devices: list[DeviceAnalysis]
    sentinel: dict[str, Any]
    ledger: dict[str, Any] | None
    generated_at: datetime
    capture_evidence: list[Evidence] = field(default_factory=list)
    crowd: Any = None                      # aegis.homelab.crowd.CrowdMixResult, attached by the caller
    version: str = HOMELAB_VERSION

    @property
    def synthetic(self) -> bool:
        return self.capture.synthetic

    def device(self, pseudonym_or_label: str) -> DeviceAnalysis:
        for d in self.devices:
            if pseudonym_or_label in (d.entity_pseudonym, d.label):
                return d
        raise KeyError(pseudonym_or_label)

    def to_dict(self) -> dict[str, Any]:
        return {"homelab_version": self.version, "generated_at": self.generated_at.isoformat(),
                "data_class": "synthetic" if self.synthetic else "home_lab_capture",
                "capture": self.capture.summary(), "usage": self.usage.to_dict() if self.usage else None,
                "sentinel": self.sentinel, "ledger": self.ledger,
                "capture_evidence": [{"evidence_id": e.evidence_id, "sha256": e.sha256, "summary": e.summary}
                                     for e in self.capture_evidence],
                "devices": [d.to_dict() for d in self.devices],
                "crowd_mix": self.crowd.to_dict() if self.crowd is not None else None}


# ---------------------------------------------------------------------------- helpers

def _hourly(events: Sequence[ObservationEvent], start: datetime, end: datetime,
            usage: ResolvedUsage | None) -> list[HourBin]:
    h0 = int(start.timestamp() // 3600)
    h1 = int(np.ceil(end.timestamp() / 3600))
    n = max(1, h1 - h0)
    flows = np.zeros(n, dtype=np.int64)
    dns = np.zeros(n, dtype=np.int64)
    byts = np.zeros(n, dtype=np.int64)
    known = np.zeros(n, dtype=bool)
    for e in events:
        i = int(e.observed_at.timestamp() // 3600) - h0
        if not 0 <= i < n:
            continue
        if e.flow is not None:
            flows[i] += 1
            for b in (e.flow.bytes_out, e.flow.bytes_in):
                if b is not None:
                    byts[i] += b
                    known[i] = True
        elif e.dns is not None:
            dns[i] += 1
    out = []
    for i in range(n):
        hs = (h0 + i) * 3600.0
        share = None
        if usage is not None:
            cov = sum(max(0.0, min(e, hs + 3600) - max(s, hs)) for s, e in usage.active)
            share = round(cov / 3600.0, 3)
        out.append(HourBin(datetime.fromtimestamp(hs, timezone.utc), int(flows[i]), int(dns[i]),
                           int(byts[i]) if known[i] else None, share))
    return out


class _Writer:
    """Evidence factory bound to one tenant / authorization / store."""

    def __init__(self, store: LabStore | None, tenant_id: str, auth: str, now: datetime):
        self.store = store
        self.tenant_id = tenant_id
        self.auth = auth
        self.now = now

    def add(self, kind: EvidenceKind, summary: str, payload: dict[str, Any], *, origin: str,
            group: str = CAPTURE_ORIGIN, supports: bool = True, artifact_ref: str | None = None) -> Evidence:
        ev = Evidence(tenant_id=self.tenant_id, kind=kind, origin_source=origin, source_independence_group=group,
                      collected_at=self.now, summary=summary, payload=payload, authorization_id=self.auth,
                      supports=supports, artifact_ref=artifact_ref)
        return self.store.evidence.append(ev) if self.store is not None else ev


def _match_evidence(w: _Writer, m: FeedMatch, entity: str) -> list[Evidence]:
    if m.feed_kind != "signed_bundle" or m.state != "active":
        return []
    out = [w.add(EvidenceKind.IOC_MATCH,
                 f"{m.matched_on} {m.value} listed as {m.threat_label or m.verdict} by {m.source} "
                 f"({'verified contact' if m.verified_contact else 'lookup only'})",
                 {"entity_pseudonym": entity, **m.to_dict()}, origin=m.source, group=m.source_group,
                 supports=not m.contradicted)]
    if m.contradicted:
        out.append(w.add(EvidenceKind.COUNTER_HYPOTHESIS,
                         f"indicator on {m.value} is contradicted by {len(m.contradicted_by)} benign indicator(s) "
                         "from another source group", {"entity_pseudonym": entity, "indicator_id": m.indicator_id,
                                                       "contradicted_by": list(m.contradicted_by)},
                         origin="aegis:homelab/feed-match", supports=False))
    return out


# ---------------------------------------------------------------------------- entry point

def analyze_single_home(capture: CaptureImport, *, usage: UsageWindows | None = None,
                        bundle: IOCBundle | None = None, local_list: Sequence[str] = (),
                        store: LabStore | None = None,
                        model: TrainedModel | None | Literal["default"] = "default",
                        resonance_cfg: ResonanceConfig | None = None,
                        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> HomeLabAnalysis:
    """Single-home analysis of an imported capture (see module docstring).

    ``store`` receives every evidence record and ledger entry (pass
    :func:`aegis.homelab.store.open_lab_store` output); without it, evidence objects are
    built but not persisted and the report says the trail is unverified.
    """
    cfg = capture.cfg
    now = clock()
    start, end = capture.start, capture.end
    resolved = usage.resolved(start.timestamp(), end.timestamp()) if usage is not None else None
    trained = load_default() if model == "default" else model
    w = _Writer(store, cfg.tenant_id, cfg.collection_authorization_id, now)

    capture_ev = [w.add(EvidenceKind.OBSERVATION,
                        f"home-lab capture {capture.manifest.capture_id or ''}: {len(capture.events)} events from "
                        f"{len(capture.files)} file(s), {capture.span_s / 3600:.1f} h"
                        + (" (SYNTHETIC)" if capture.synthetic else ""),
                        {"files": [f.to_dict() for f in capture.files], "ingest": capture.ingest,
                         "prefilter": capture.prefilter, "quarantined": capture.quarantined,
                         "manifest": capture.manifest.to_dict(), "start": start.isoformat(), "end": end.isoformat(),
                         "pseudonym_key_fingerprint": capture.pseudonym_key_fingerprint},
                        origin="sensor:homelab-capture", artifact_ref="file://capture")]
    if usage is not None:
        capture_ev.append(w.add(EvidenceKind.ANALYST_NOTE,
                                f"owner-provided usage windows: {len(usage.active)} active window(s)",
                                usage.to_dict(), origin="user:usage-windows", group="homelab-owner"))

    sentinel = Sentinel(trained, bundle, store.evidence if store is not None else None, tenant_id=cfg.tenant_id,
                        authorized_collections={cfg.collection_authorization_id}, record_decisions=True)
    findings = sentinel.process_batch(capture.events)
    findings += sentinel.flush(end + timedelta(seconds=1))
    rule_of = {(r.entity_pseudonym, r.window_end, r.label): r.rule for r in sentinel.decisions}
    finding_rules = {f.finding_id: rule_of.get((f.entity_pseudonym, f.observed_window_end, f.label), "unknown")
                     for f in findings}
    windows: dict[str, dict[str, int]] = {}
    for rec in sentinel.decisions:
        windows.setdefault(rec.entity_pseudonym, {}).setdefault(rec.verdict.value, 0)
        windows[rec.entity_pseudonym][rec.verdict.value] += 1

    devices: list[DeviceAnalysis] = []
    for pseudo, label in capture.devices.items():
        dev_events = capture.events_for(pseudo)
        timers = analyze_timers(dev_events, pseudo, start=start, end=end, usage=resolved, cfg=resonance_cfg)
        infra = analyze_infrastructure(dev_events, pseudo, as_of=end, gateway_ip=cfg.gateway_ip, bundle=bundle,
                                       local_list=local_list, usage=resolved)
        dev_findings = [f for f in findings if f.entity_pseudonym == pseudo]
        verdict = decide(entity_pseudonym=pseudo, span_s=capture.span_s, n_events=len(dev_events), timers=timers,
                         infra=infra, sentinel_findings=dev_findings, sentinel_rules=finding_rules,
                         sentinel_model_note=SENTINEL_OOD_NOTE if trained is not None else
                         "SENTINEL ran without a model (rules and anomaly only).", synthetic=capture.synthetic)

        ev: list[Evidence] = list(capture_ev)
        counter: list[Evidence] = []
        for c in timers.timers:
            act = c.activity
            ev.append(w.add(EvidenceKind.OBSERVATION,
                            f"timer to {c.display}: ~{c.period_s:.0f} s, z={c.z:.1f} (nominal), {c.n_events} contacts"
                            + (f", {act.pattern.replace('_', ' ')}" if act else ""),
                            {"entity_pseudonym": pseudo, **c.to_dict()}, origin="aegis:homelab/timers"))
            if act is not None and act.pattern == "active_only":
                counter.append(w.add(EvidenceKind.BENIGN_BASELINE,
                                     f"timer to {c.display} follows the owner's usage (active only): consistent "
                                     "with a player or app heartbeat", {"entity_pseudonym": pseudo, "key": c.key,
                                                                         "activity": act.to_dict()},
                                     origin="aegis:homelab/timers", supports=False))
        for d in infra.destinations:
            for m in d.matches:
                for e in _match_evidence(w, m, pseudo):
                    (ev if e.supports else counter).append(e)
        if bundle is not None and not any(m.feed_kind == "signed_bundle" and m.state == "active"
                                          for d in infra.destinations for m in d.matches):
            counter.append(w.add(EvidenceKind.BENIGN_BASELINE,
                                 f"no active indicator of feed bundle {bundle.bundle_id} matched any contacted "
                                 "destination", {"entity_pseudonym": pseudo, "bundle": bundle.provenance()},
                                 origin="aegis:homelab/feed-match", supports=False))
        for f in dev_findings:
            ev_ids = set(f.evidence_ids)
            if store is not None:
                for e in store.evidence.list_for(cfg.tenant_id, sorted(ev_ids)):
                    ev.append(e)
                for e in store.evidence.list_for(cfg.tenant_id, sorted(f.counterevidence_ids)):
                    counter.append(e)
        verdict.evidence_ids = [e.evidence_id for e in ev]
        verdict.counterevidence_ids = [e.evidence_id for e in counter]
        if store is not None:
            store.ledger.append(cfg.tenant_id, VERDICT_ENTRY, pseudo, {
                "entity_pseudonym": pseudo, "label": label, **verdict.to_dict(),
                "capture_id": capture.manifest.capture_id, "synthetic": capture.synthetic,
                "sentinel_detector_version": sentinel.detector_version, "homelab_version": HOMELAB_VERSION})
        n_flows = sum(1 for e in dev_events if e.flow is not None)
        chatter = capture.local_chatter.get(pseudo)
        devices.append(DeviceAnalysis(
            entity_pseudonym=pseudo, label=label, n_events=len(dev_events), n_flows=n_flows,
            n_dns=len(dev_events) - n_flows, timers=timers, infra=infra, sentinel_findings=dev_findings,
            sentinel_windows=windows.get(pseudo, {}),
            sentinel_rules={f.finding_id: finding_rules[f.finding_id] for f in dev_findings}, hourly=_hourly(dev_events, start, end, resolved),
            verdict=verdict, evidence=ev + counter, local_chatter=chatter.to_dict() if chatter else None))

    sentinel_info = {"detector_version": sentinel.detector_version,
                     "model_id": trained.model_id if trained is not None else None,
                     "bundle": bundle.provenance() if bundle is not None else None,
                     "windows": sentinel.stats.windows, "findings": len(findings),
                     "verdict_counts": dict(sentinel.stats.verdicts),
                     "note": SENTINEL_OOD_NOTE if trained is not None else None}
    return HomeLabAnalysis(capture=capture, usage=usage, devices=devices, sentinel=sentinel_info,
                           ledger=store.verify(cfg.tenant_id) if store is not None else None, generated_at=now,
                           capture_evidence=capture_ev)


__all__ = ["DeviceAnalysis", "HOMELAB_VERSION", "HomeLabAnalysis", "HourBin", "SENTINEL_OOD_NOTE", "VERDICT_ENTRY",
           "analyze_single_home"]
