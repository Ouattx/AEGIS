"""EGRESS verdicts -> Findings, with evidence written through the provenance layer.

Per verdict:

* one ``OBSERVATION`` evidence record per line signal (metrics are the full rule inputs, so
  the verdict can be recomputed by hand);
* one ``ANOMALY`` evidence record per cross-line campaign (shared by member findings,
  written once, ledgered as ``egress_campaign``);
* ``COUNTER_HYPOTHESIS`` evidence (``supports=False``) listing the benign explanations a
  reviewer must rule out, and ``BENIGN_BASELINE`` counter-evidence when a concrete fact
  argues against the reading (popular or residential proxy sink, web-port-only stuffing,
  spam rate near the threshold, an amplifier that is a misconfigured CPE).

All EGRESS evidence derives from the operator's own telemetry and shares the
``operator-telemetry`` independence group with SENTINEL and RESONANCE: several EGRESS
signals are *not* independent corroboration in the sense of the case state machine. Only
the anti-spoofing counters (a different collector) carry their own group
``operator-urpf``. Every finding has ``requires_review=True`` and ``calibration_id=None``.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from aegis.contracts.models import Evidence, EvidenceKind, Finding, Verdict
from aegis.egress.config import EgressConfig
from aegis.egress.models import EgressCampaign, EgressReport, LineVerdict
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType

ORIGIN = "aegis:egress"
INDEPENDENCE_GROUP = "operator-telemetry"
SPOOF_INDEPENDENCE_GROUP = "operator-urpf"
CAMPAIGN_ENTRY = "egress_campaign"

_VERDICTS = {"malicious": Verdict.MALICIOUS, "suspicious": Verdict.SUSPICIOUS, "abstain": Verdict.ABSTAIN}


def _campaign_evidence(c: EgressCampaign, now: datetime, auth: str) -> Evidence:
    return Evidence(
        tenant_id=c.tenant_id, kind=EvidenceKind.ANOMALY, origin_source=ORIGIN,
        source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
        summary=f"cross-line {c.kind} ({c.label}): {c.explanation}",
        payload={"campaign_id": c.campaign_id, "label": c.label, "kind": c.kind, "n_lines": c.n_lines,
                 "member_lines": c.member_lines[:200], "targets": c.targets[:200],
                 "start": c.start.isoformat(), "end": c.end.isoformat(), "metrics": c.metrics})


def to_findings(report: EgressReport, *, cfg: EgressConfig | None = None,
                evidence_store: EvidenceStore | None = None, now: datetime | None = None,
                authorization_id: str | None = None) -> list[Finding]:
    """Findings for every verdict in ``report`` (evidence persisted when a store is given).

    A report-level abstention produces no findings (there is no line to attach one to);
    the caller records ``report.abstain_reason`` in its coverage statistics.
    """
    cfg = cfg or EgressConfig()
    now = now or report.window_end
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    auth = authorization_id or cfg.authorization_id
    ttl = timedelta(hours=cfg.finding_ttl_hours)
    if report.status == "abstain":
        return []

    camp_ev: dict[str, Evidence] = {}
    for c in report.campaigns:
        ev = _campaign_evidence(c, now, auth)
        if evidence_store is not None:
            ev = evidence_store.append(ev)
            evidence_store.ledger.append(report.tenant_id, CAMPAIGN_ENTRY, c.campaign_id, {
                "campaign_id": c.campaign_id, "evidence_id": ev.evidence_id, "label": c.label, "kind": c.kind,
                "n_lines": c.n_lines, "targets": c.targets[:50], "detector_version": report.detector_version,
                "config_hash": report.config_hash})
        camp_ev[c.campaign_id] = ev

    out: list[Finding] = []
    for v in report.verdicts:
        out.append(_finding(report, v, camp_ev, evidence_store, now, auth, ttl))
    return out


def _finding(report: EgressReport, v: LineVerdict, camp_ev: dict[str, Evidence],
             store: EvidenceStore | None, now: datetime, auth: str, ttl: timedelta) -> Finding:
    def persist(ev: Evidence) -> Evidence:
        return store.append(ev) if store is not None else ev

    support: list[Evidence] = []
    for s in v.signals:
        group = SPOOF_INDEPENDENCE_GROUP if s.kind == "spoofing" else INDEPENDENCE_GROUP
        origin = f"{ORIGIN}:{s.metrics.get('sources', ['urpf'])[0]}" if s.kind == "spoofing" else ORIGIN
        support.append(persist(Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.OBSERVATION, origin_source=origin,
            source_independence_group=group, collected_at=now, authorization_id=auth, summary=s.summary,
            payload={"entity_pseudonym": v.entity_pseudonym, "signal": s.kind, "label": s.label,
                     "strong": s.strong, "start": s.start.isoformat(), "end": s.end.isoformat(),
                     "targets": s.targets[:200], "metrics": s.metrics,
                     "detector_version": report.detector_version, "config_hash": report.config_hash})))
    if v.verdict == "abstain":
        # the abstention itself is the observation: which candidate, which counters are missing
        support.append(persist(Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.OBSERVATION, origin_source=ORIGIN,
            source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
            summary=f"EGRESS abstained on {v.label}: {v.counter_facts.get('abstain_reason', 'insufficient data')}",
            payload={"entity_pseudonym": v.entity_pseudonym, "label": v.label, "abstention": v.counter_facts,
                     "detector_version": report.detector_version, "config_hash": report.config_hash})))
    counter: list[Evidence] = []
    if v.alternatives:
        counter.append(persist(Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.COUNTER_HYPOTHESIS, origin_source=ORIGIN,
            source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
            supports=False, summary=f"benign explanations to rule out for {v.label}",
            payload={"entity_pseudonym": v.entity_pseudonym, "label": v.label, "alternatives": v.alternatives})))
    facts = {k: val for k, val in v.counter_facts.items() if k != "abstain_reason"}
    if facts and v.verdict != "abstain":
        counter.append(persist(Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.BENIGN_BASELINE, origin_source=ORIGIN,
            source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
            supports=False, summary=f"facts limiting the {v.label} reading: " + ", ".join(sorted(facts)),
            payload={"entity_pseudonym": v.entity_pseudonym, "label": v.label, "facts": facts})))
    evidence_ids = [e.evidence_id for e in support] + [camp_ev[c].evidence_id for c in v.campaign_ids
                                                        if c in camp_ev]
    components: dict[str, float | None] = {"signals": float(len(v.signals)),
                                           "corroborations": float(len(v.corroboration)),
                                           "strong_signals": float(sum(1 for s in v.signals if s.strong))}
    components.update(_headline_metrics(v))
    f = Finding(
        tenant_id=report.tenant_id, entity_pseudonym=v.entity_pseudonym, device_class=v.device_class,
        detector_version=report.detector_version, label=v.label, verdict=_VERDICTS[v.verdict], score=v.score,
        calibration_id=None, component_scores=components,
        observed_window_start=min(v.start, report.window_end) if v.verdict != "abstain" else report.window_start,
        observed_window_end=v.end if v.verdict != "abstain" else report.window_end,
        evidence_ids=evidence_ids, counterevidence_ids=[e.evidence_id for e in counter],
        requires_review=True, explanation=v.explanation, created_at=now, expires_at=now + ttl)
    if store is not None:
        store.ledger.append(report.tenant_id, EntryType.FINDING, f.finding_id, {
            "finding_id": f.finding_id, "entity_pseudonym": f.entity_pseudonym, "label": f.label,
            "verdict": f.verdict.value, "score": f.score, "calibration_id": None,
            "detector_version": f.detector_version, "config_hash": report.config_hash,
            "campaign_ids": v.campaign_ids, "corroboration": v.corroboration,
            "evidence_ids": f.evidence_ids, "counterevidence_ids": f.counterevidence_ids,
            "observed_window_end": f.observed_window_end})
    return f


def _headline_metrics(v: LineVerdict) -> dict[str, float | None]:
    keys = ("peak_pps", "response_ratio", "distinct_reflectors", "relay_correlation", "byte_balance",
            "mx_per_hour", "sessions_per_hour", "distinct_hosts", "median_amplification", "fraction")
    out: dict[str, float | None] = {}
    for s in v.signals:
        for k in keys:
            val: Any = s.metrics.get(k)
            if isinstance(val, (int, float)) and not isinstance(val, bool) and k not in out:
                out[k] = float(val)
    return out


__all__ = ["CAMPAIGN_ENTRY", "INDEPENDENCE_GROUP", "ORIGIN", "SPOOF_INDEPENDENCE_GROUP", "to_findings"]
