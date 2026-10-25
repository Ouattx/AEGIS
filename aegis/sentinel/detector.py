"""SENTINEL detector: observation stream -> evidence-backed findings (spec section 4).

Per event::

    validate authorization and schema         (fail closed: unauthorized events are dropped)
    windows = window_store.update(event)      (feature vectors of windows that just closed)
    for each window:
        rules   = ioc_match(window contacts, fresh signed indicators)      (A)
        ml      = calibrated_model.predict(window)                          (B)
        anomaly = per-device-class robust anomaly(window)                   (C)
        change  = CUSUM change points of the entity                         (D)
        result  = fusion_policy(rules, ml, anomaly, change, window)         (ABSTAIN when context is short)
        emit a Finding for MALICIOUS / SUSPICIOUS (and signal-bearing ABSTAIN)

Findings cite evidence ids (observation summary, indicator matches, model score with
feature attributions, anomaly, change points) and contradicting feeds as
counter-evidence. When an :class:`EvidenceStore` is configured every evidence record
is appended (hash + ledger entry) and every finding gets a ``finding`` ledger entry.

Repeated windows of an ongoing incident do not flood analysts: a finding for the
same (entity, label) is re-emitted only after ``suppress_for`` or when the verdict
escalates. Findings are stamped with event time (the window end) so lab runs and
replays are reproducible; pass ``clock`` for wall-clock ``created_at`` (the
production service always does). ``Finding.ingested_at`` records when the telemetry
that closed the window was received, so alert latency can be measured as
``created_at - max(window end, ingested_at)`` even for late (backfilled) exports.

Nothing here imports or calls an LLM.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, Sequence

from aegis.contracts.models import (
    Evidence,
    EvidenceKind,
    FeatureVector,
    Finding,
    ObservationEvent,
    Verdict,
)
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType
from aegis.sentinel.anomaly import AnomalyScore, ChangePoint, ChangePointMonitor, RobustAnomalyModel
from aegis.sentinel.explain import behavior_label, render_explanation
from aegis.sentinel.features import WINDOW_SECONDS, ContactSummary, WindowStore
from aegis.sentinel.fusion import (
    DEFAULT_FUSION_POLICY,
    FusionPolicy,
    FusionResult,
    MLScore,
    format_probability,
    fusion_policy,
)
from aegis.sentinel.model import TrainedModel
from aegis.sentinel.rules import IOCBundle, ioc_match

SENTINEL_VERSION = "1.0.0"
TELEMETRY_GROUP = "operator-telemetry"
_RANK = {Verdict.ABSTAIN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}
_SUMMARY_FEATURES = ("flow_rate_h", "dns_rate_h", "unique_dst_ip", "dst_entropy", "nxdomain_rate", "nx_unique",
                     "zero_reply_frac", "beacon_robust_cv", "beacon_period_log", "beacon_dst_prevalence",
                     "rare_dst_frac", "rare_qname_frac", "active_bin_frac", "out_ratio", "coverage_h")


@dataclass
class Decision:
    """Fusion outcome for one window (emitted or not)."""
    fv: FeatureVector
    result: FusionResult
    label: str
    label_reasons: list[str]
    hits: list[Evidence]
    ml: MLScore | None
    anomaly: AnomalyScore | None
    changepoints: list[ChangePoint]
    contacts: ContactSummary | None


@dataclass(frozen=True)
class DecisionRecord:
    tenant_id: str
    entity_pseudonym: str
    device_class: str
    window_end: datetime
    verdict: Verdict
    label: str
    score: float
    rule: str


@dataclass
class SentinelStats:
    events: int = 0
    rejected_events: int = 0
    windows: int = 0
    verdicts: Counter[str] = field(default_factory=Counter)
    rules: Counter[str] = field(default_factory=Counter)
    findings: int = 0
    suppressed: int = 0
    evidence_written: int = 0


class EventRejected(ValueError):
    """Raised by :meth:`Sentinel.validate` for an event that must not be processed."""


class Sentinel:
    """Streaming detector producing :class:`Finding` objects. Works without any LLM.

    ``model`` and ``bundle`` are both optional: without a model, fusion relies on
    rules (and abstains rather than calling anything benign); without a bundle no
    indicator evidence exists. ``authorized_collections``, when given, is the set of
    collection authorization ids this deployment accepts (others are rejected).
    """

    def __init__(self, model: TrainedModel | None, bundle: IOCBundle | None,
                 evidence_store: EvidenceStore | None = None, *,
                 anomaly: RobustAnomalyModel | None = None,
                 window_store: WindowStore | None = None,
                 changepoints: ChangePointMonitor | None = None,
                 policy: FusionPolicy = DEFAULT_FUSION_POLICY,
                 tenant_id: str | None = None,
                 authorized_collections: Iterable[str] | None = None,
                 finding_ttl: timedelta = timedelta(days=3),
                 suppress_for: timedelta = timedelta(hours=24),
                 emit_abstain: bool = True,
                 record_decisions: bool = False,
                 clock: Callable[[], datetime] | None = None):
        self.model = model
        self.bundle = bundle
        self.evidence_store = evidence_store
        self.anomaly = anomaly if anomaly is not None else (model.anomaly if model is not None else None)
        self.windows = window_store or WindowStore("24h")
        self.changepoints = changepoints or ChangePointMonitor()
        self.policy = policy
        self.tenant_id = tenant_id
        self.authorized = frozenset(authorized_collections) if authorized_collections is not None else None
        self.finding_ttl = finding_ttl
        self.suppress_for = suppress_for
        self.emit_abstain = emit_abstain
        self.record_decisions = record_decisions
        self.clock = clock
        self.stats = SentinelStats()
        self.decisions: list[DecisionRecord] = []
        self._last_emit: dict[tuple[str, str, str], tuple[datetime, Verdict]] = {}
        self._streak: dict[tuple[str, str], tuple[datetime, int]] = {}
        self._last_prune: datetime | None = None
        self._closing_ingested_at: datetime | None = None
        self.state_ttl = max(timedelta(days=7), suppress_for)

    # ------------------------------------------------------------------ identity
    @property
    def detector_version(self) -> str:
        model = self.model.model_id if self.model is not None else "nomodel"
        bundle = self.bundle.version if self.bundle is not None else "nobundle"
        return f"sentinel/{SENTINEL_VERSION}+{model}+ioc:{bundle}+{self.policy.policy_hash[:12]}"

    # ------------------------------------------------------------------ input validation
    def validate(self, event: ObservationEvent) -> None:
        """Fail closed on events this deployment may not process."""
        if event.schema_version != "3.0":
            raise EventRejected(f"unsupported schema_version {event.schema_version!r}")
        if self.tenant_id is not None and event.tenant_id != self.tenant_id:
            raise EventRejected("event belongs to another tenant")
        auth = (event.collection_authorization_id or "").strip()
        if not auth:
            raise EventRejected("event has no collection authorization")
        if self.authorized is not None and auth not in self.authorized:
            raise EventRejected(f"collection authorization {auth!r} is not accepted")
        if event.entity_pseudonym is None:
            raise EventRejected("event has no entity pseudonym")
        if event.flow is None and event.dns is None:
            raise EventRejected("event carries no flow or DNS observation")

    # ------------------------------------------------------------------ processing
    def process(self, event: ObservationEvent) -> list[Finding]:
        self.stats.events += 1
        try:
            self.validate(event)
        except EventRejected:
            self.stats.rejected_events += 1
            return []
        fvs = self.windows.update(event)
        if not fvs:
            return []
        self._closing_ingested_at = event.ingested_at
        return self._handle(fvs)

    def process_batch(self, events: Iterable[ObservationEvent]) -> list[Finding]:
        out: list[Finding] = []
        for ev in events:
            out.extend(self.process(ev))
        return out

    def flush(self, now: datetime) -> list[Finding]:
        """Close all windows up to ``now`` (end of a replay, or an idle sensor)."""
        fvs = self.windows.flush(now, self.tenant_id)
        if not fvs:
            return []
        self._closing_ingested_at = self.clock() if self.clock is not None else now
        return self._handle(fvs)

    # ------------------------------------------------------------------ restart recovery
    def warm(self, items: Iterable[ObservationEvent | datetime], *, complete_after: datetime | None = None) -> int:
        """Rebuild in-memory detection context from telemetry that was already processed
        before a restart, emitting nothing (no evidence, no findings, no ledger writes).

        ``items`` replays the original order: events, and ``datetime`` flush markers
        (the times :meth:`flush` was called). Window bins and watermarks are rebuilt
        exactly; model persistence and change-point baselines learn only from windows
        that lie entirely after ``complete_after`` (the start of the replayed span), so
        partial windows never bias them. Returns the number of windows replayed.
        """
        span = timedelta(seconds=self.windows.window_s)
        n = 0
        for item in items:
            if isinstance(item, datetime):
                fvs = self.windows.flush(item, self.tenant_id)
            else:
                try:
                    self.validate(item)
                except EventRejected:
                    continue
                fvs = self.windows.update(item)
            if not fvs:
                continue
            n += len(fvs)
            ready = [fv for fv in fvs if complete_after is None or fv.window_end - span >= complete_after]
            if ready:
                self.evaluate(ready)
        return n

    def seed_suppression(self, findings: Iterable[Finding]) -> int:
        """Restore repeat suppression from findings already emitted (e.g. read back from storage)."""
        n = 0
        for f in findings:
            if f.verdict not in _RANK:
                continue
            key = (f.tenant_id, f.entity_pseudonym, f.label)
            end = f.observed_window_end
            prev = self._last_emit.get(key)
            if prev is None or end > prev[0] or (end == prev[0] and _RANK[f.verdict] > _RANK[prev[1]]):
                self._last_emit[key] = (end, f.verdict)
                n += 1
        return n

    def evaluate(self, fvs: Sequence[FeatureVector]) -> list[Decision]:
        """Run detectors A-D and fusion on windows (no emission, no persistence)."""
        if not fvs:
            return []
        probs = self.model.predict_many(fvs) if self.model is not None else None
        out: list[Decision] = []
        for i, fv in enumerate(fvs):
            contacts = self.windows.contacts_for(fv)
            hits: list[Evidence] = []
            if self.bundle is not None and contacts is not None:
                hits = ioc_match(fv, contacts, self.bundle, fv.window_end)
            ml = None
            if probs is not None and self.model is not None:
                p = float(probs[i])
                ml = MLScore(p, self.model.calibration_id, self.model.model_id, self._persistence(fv, p))
            anomaly = self.anomaly.score(fv) if self.anomaly is not None else None
            self.changepoints.update(fv)
            cps = self.changepoints.recent(fv.tenant_id, fv.entity_pseudonym, fv.window_end)
            result = fusion_policy(hits, ml, anomaly, cps, fv, self.policy)
            label, why = behavior_label(fv, result.strong_hits + result.weak_hits)
            out.append(Decision(fv, result, label, why, hits, ml, anomaly, cps, contacts))
        return out

    def _persistence(self, fv: FeatureVector, p: float) -> int:
        """Consecutive windows (hop apart) of this entity at or above the suspicious threshold."""
        key = (fv.tenant_id, fv.entity_pseudonym)
        prev = self._streak.get(key)
        if prev is not None and fv.window_end <= prev[0]:
            return prev[1]                                     # replayed window: no state change
        if p < self.policy.ml_suspicious:
            n = 0
        elif prev is not None and prev[1] > 0 and fv.window_end - prev[0] == timedelta(seconds=self.windows.hop_s):
            n = prev[1] + 1
        else:
            n = 1
        self._streak[key] = (fv.window_end, n)
        return n

    def prune(self, now: datetime) -> int:
        """Forget per-entity state (suppression, persistence, change points) idle for ``state_ttl``."""
        cutoff = now - self.state_ttl
        before = len(self._last_emit) + len(self._streak)
        self._last_emit = {k: v for k, v in self._last_emit.items() if v[0] >= cutoff}
        self._streak = {k: v for k, v in self._streak.items() if v[0] >= cutoff}
        dropped = before - len(self._last_emit) - len(self._streak)
        return dropped + self.changepoints.prune(now)

    def _handle(self, fvs: list[FeatureVector]) -> list[Finding]:
        latest = max(fv.window_end for fv in fvs)
        if self._last_prune is None or latest - self._last_prune >= timedelta(days=1):
            self.prune(latest)
            self._last_prune = latest
        findings: list[Finding] = []
        for d in self.evaluate(fvs):
            self.stats.windows += 1
            self.stats.verdicts[d.result.verdict.value] += 1
            self.stats.rules[d.result.rule] += 1
            if self.record_decisions:
                self.decisions.append(DecisionRecord(d.fv.tenant_id, d.fv.entity_pseudonym, d.fv.device_class,
                                                     d.fv.window_end, d.result.verdict, d.label, d.result.score,
                                                     d.result.rule))
            if not self._should_emit(d):
                continue
            findings.append(self._emit(d))
        return findings

    def _should_emit(self, d: Decision) -> bool:
        v = d.result.verdict
        if v == Verdict.BENIGN:
            return False
        if v == Verdict.ABSTAIN and not (self.emit_abstain and d.result.signal):
            return False
        key = (d.fv.tenant_id, d.fv.entity_pseudonym, d.label)
        last = self._last_emit.get(key)
        if last is not None:
            t, lv = last
            if d.fv.window_end - t < self.suppress_for and _RANK[v] <= _RANK[lv]:
                self.stats.suppressed += 1
                return False
        self._last_emit[key] = (d.fv.window_end, v)
        return True

    # ------------------------------------------------------------------ evidence + finding
    def _emit(self, d: Decision) -> Finding:
        fv, res = d.fv, d.result
        now = self.clock() if self.clock is not None else fv.window_end
        if now.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        now = now.astimezone(timezone.utc)
        auth = (sorted(d.contacts.authorization_ids)[0] if d.contacts is not None and d.contacts.authorization_ids
                else "unknown")
        sources = sorted(d.contacts.source_ids) if d.contacts is not None else []
        window_start = fv.window_end - timedelta(seconds=WINDOW_SECONDS[fv.window])
        supporting: list[Evidence] = []
        counter: list[Evidence] = list(res.counter)

        obs_payload = {
            "entity_pseudonym": fv.entity_pseudonym, "device_class": fv.device_class, "window": fv.window,
            "window_start": window_start.isoformat(), "window_end": fv.window_end.isoformat(),
            "event_count": fv.event_count, "source_ids": sources,
            "features": {k: fv.values.get(k) for k in _SUMMARY_FEATURES},
            "missing": sorted(k for k, m in fv.missing.items() if m),
            "source_event_ids": fv.source_event_ids[:200],
            "source_event_ids_total": len(fv.source_event_ids),
        }
        if d.contacts is not None:
            top = d.contacts.dst_ips.most_common(10)
            obs_payload["top_destinations"] = [{"dst_ip": ip, "flows": n} for ip, n in top]
        supporting.append(Evidence(
            tenant_id=fv.tenant_id, kind=EvidenceKind.OBSERVATION,
            origin_source="sensor:" + (",".join(sources) or "unknown"), source_independence_group=TELEMETRY_GROUP,
            collected_at=now, authorization_id=auth, payload=obs_payload,
            summary=(f"{fv.event_count} flow/DNS events from {fv.entity_pseudonym} in the {fv.window} window "
                     f"ending {fv.window_end.isoformat()}")))
        supporting.extend(res.strong_hits + res.weak_hits)
        if d.ml is not None and self.model is not None:
            contrib = self.model.explain(fv, top=6)
            supporting.append(Evidence(
                tenant_id=fv.tenant_id, kind=EvidenceKind.MODEL_SCORE,
                origin_source=f"aegis:sentinel/model:{self.model.model_id}", source_independence_group=TELEMETRY_GROUP,
                collected_at=now, authorization_id=auth,
                summary=f"calibrated probability {format_probability(d.ml.probability)} ({self.model.model_id})",
                payload={"entity_pseudonym": fv.entity_pseudonym, "window_end": fv.window_end.isoformat(),
                         "probability": d.ml.probability, "calibration_id": d.ml.calibration_id,
                         "model_id": self.model.model_id, "model_version": self.model.version,
                         "top_contributions": contrib}))
        else:
            contrib = []
        if d.anomaly is not None and d.anomaly.percentile >= self.policy.anomaly_corroborate:
            supporting.append(Evidence(
                tenant_id=fv.tenant_id, kind=EvidenceKind.ANOMALY, origin_source="aegis:sentinel/anomaly",
                source_independence_group=TELEMETRY_GROUP, collected_at=now, authorization_id=auth,
                summary=f"anomaly percentile {d.anomaly.percentile:.3f} vs {d.anomaly.baseline} baseline",
                payload={"entity_pseudonym": fv.entity_pseudonym, "window_end": fv.window_end.isoformat(),
                         **d.anomaly.as_dict()}))
        for cp in d.changepoints:
            supporting.append(Evidence(
                tenant_id=fv.tenant_id, kind=EvidenceKind.CHANGE_POINT, origin_source="aegis:sentinel/cusum",
                source_independence_group=TELEMETRY_GROUP, collected_at=now, authorization_id=auth,
                summary=f"{cp.metric} shifted {cp.direction} at {cp.detected_at.isoformat()}",
                payload={"entity_pseudonym": fv.entity_pseudonym, **cp.as_dict()}))

        if self.evidence_store is not None:
            supporting = [self.evidence_store.append(e) for e in supporting]
            counter = [self.evidence_store.append(e) for e in counter]
            self.stats.evidence_written += len(supporting) + len(counter)

        explanation = render_explanation(fv=fv, result=res, label=d.label, label_reasons=d.label_reasons,
                                         model_contrib=contrib, anomaly=d.anomaly, changepoints=d.changepoints)
        finding = Finding(
            tenant_id=fv.tenant_id, entity_pseudonym=fv.entity_pseudonym, device_class=fv.device_class,
            detector_version=self.detector_version, label=d.label, verdict=res.verdict, score=res.score,
            calibration_id=res.calibration_id, component_scores=dict(res.component_scores),
            observed_window_start=window_start, observed_window_end=fv.window_end,
            evidence_ids=[e.evidence_id for e in supporting], counterevidence_ids=[e.evidence_id for e in counter],
            requires_review=res.requires_review, explanation=explanation, created_at=now,
            expires_at=now + self.finding_ttl,
            ingested_at=(self._closing_ingested_at.astimezone(timezone.utc)
                         if self._closing_ingested_at is not None and self._closing_ingested_at.tzinfo is not None
                         else None))
        if self.evidence_store is not None:
            self.evidence_store.ledger.append(fv.tenant_id, EntryType.FINDING, finding.finding_id, {
                "finding_id": finding.finding_id, "entity_pseudonym": finding.entity_pseudonym,
                "label": finding.label, "verdict": finding.verdict.value, "score": finding.score,
                "calibration_id": finding.calibration_id, "detector_version": finding.detector_version,
                "model_id": self.model.model_id if self.model is not None else None,
                "rule_bundle": self.bundle.provenance() if self.bundle is not None else None,
                "fusion": res.as_dict(), "evidence_ids": finding.evidence_ids,
                "counterevidence_ids": finding.counterevidence_ids,
                "observed_window_end": finding.observed_window_end,
            })
        self.stats.findings += 1
        return finding


__all__ = ["SENTINEL_VERSION", "Decision", "DecisionRecord", "EventRejected", "Sentinel", "SentinelStats"]
