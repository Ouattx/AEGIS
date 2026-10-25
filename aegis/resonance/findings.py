"""Campaigns -> per-line Findings with evidence written through the provenance layer.

Verdict policy (pre-registered, deterministic):

* campaign q <= ``q_malicious`` and the line individually supports the campaign timer
  (one-sided z >= ``support_z`` at the campaign period) -> ``MALICIOUS``;
* otherwise (campaign q <= ``q``) -> ``SUSPICIOUS``;
* report abstained -> optional ``ABSTAIN`` findings for lines the caller asks about.

Every finding has ``requires_review=True`` (shadow mode; enforcement is MIRROR's job), a
score that is a *ranking* in [0, 1] (``calibration_id=None``: not a probability), and cites a
campaign-level evidence record plus a line-level one. RESONANCE derives from the same
operator telemetry as SENTINEL, so its evidence shares the ``operator-telemetry``
independence group: it is not independent corroboration of a SENTINEL finding.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable

import numpy as np

from aegis.contracts.models import Evidence, EvidenceKind, Finding, Verdict
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import EntryType
from aegis.resonance.config import FINDING_LABEL, ResonanceConfig
from aegis.resonance.models import Campaign, ResonanceReport

ORIGIN = "aegis:resonance"
INDEPENDENCE_GROUP = "operator-telemetry"
CAMPAIGN_ENTRY = "resonance_campaign"


def campaign_score(c: Campaign, line_supports: bool) -> float:
    """Ranking score in [0, 1]: -log10(q) scaled to 12 decades, discounted without line support."""
    s = min(1.0, -np.log10(max(c.q_value, 1e-12)) / 12.0)
    return float(round(s * (1.0 if line_supports else 0.6), 6))


def _campaign_payload(c: Campaign, cfg: ResonanceConfig) -> dict:
    d = c.model_dump(mode="json", exclude={"lines"})
    d["config"] = cfg.as_dict()
    d["lines_preview"] = [s.model_dump(mode="json") for s in c.lines[:25]]
    d["detector_version"] = c.detector_version
    return d


def to_findings(report: ResonanceReport, *, cfg: ResonanceConfig | None = None,
                evidence_store: EvidenceStore | None = None, now: datetime | None = None,
                authorization_id: str | None = None, device_class: str = "unknown",
                emit_abstain_for: Iterable[str] = ()) -> list[Finding]:
    """Per-line findings for every campaign in ``report`` (evidence persisted when a store is given)."""
    cfg = cfg or ResonanceConfig()
    now = now or report.window_end
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    auth = authorization_id or cfg.authorization_id
    ttl = timedelta(hours=cfg.finding_ttl_hours)
    out: list[Finding] = []

    if report.status == "abstain":
        for line in emit_abstain_for:
            out.append(Finding(
                tenant_id=report.tenant_id, entity_pseudonym=line, device_class=device_class,
                detector_version=report.detector_version, label=FINDING_LABEL, verdict=Verdict.ABSTAIN, score=0.0,
                observed_window_start=report.window_start, observed_window_end=report.window_end,
                requires_review=True, created_at=now, expires_at=now + ttl,
                explanation=f"RESONANCE abstained: {report.abstain_reason}. No inference was made."))
        return out

    for c in report.campaigns:
        camp_ev = Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.ANOMALY, origin_source=ORIGIN,
            source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
            summary=(f"cross-subscriber resonance: {c.n_lines} lines -> {', '.join(c.destinations[:3])}"
                     f"{' ...' if len(c.destinations) > 3 else ''}; p={c.p_value:.2e}, q={c.q_value:.2e}"),
            payload=_campaign_payload(c, cfg))
        counter: list[Evidence] = []
        if c.shared_hosting_domain or c.topology_unknown or c.evidence_summary.get("infrastructure", {}).get(
                "cohosted_ips"):
            counter.append(Evidence(
                tenant_id=report.tenant_id, kind=EvidenceKind.BENIGN_BASELINE, origin_source=ORIGIN,
                source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
                supports=False,
                summary="destination infrastructure is shared or not fully known: IP-level action unsafe",
                payload={"campaign_id": c.campaign_id, "shared_hosting_domain": c.shared_hosting_domain,
                         "topology_unknown": c.topology_unknown,
                         "cohosted_ips": c.evidence_summary.get("infrastructure", {}).get("cohosted_ips", []),
                         "destination_ips": c.destination_ips[:50]}))
        if evidence_store is not None:
            camp_ev = evidence_store.append(camp_ev)
            counter = [evidence_store.append(e) for e in counter]
            evidence_store.ledger.append(report.tenant_id, CAMPAIGN_ENTRY, c.campaign_id, {
                "campaign_id": c.campaign_id, "evidence_id": camp_ev.evidence_id,
                "counterevidence_ids": [e.evidence_id for e in counter], "detector_version": c.detector_version,
                "config_hash": c.config_hash, "destinations": c.destinations, "n_lines": c.n_lines,
                "p_value": c.p_value, "q_value": c.q_value, "q_target": c.q_target})
        for s in c.lines:
            line_ev = Evidence(
                tenant_id=report.tenant_id, kind=EvidenceKind.OBSERVATION, origin_source=ORIGIN,
                source_independence_group=INDEPENDENCE_GROUP, collected_at=now, authorization_id=auth,
                summary=(f"line timer toward campaign destinations: {s.n_events} events, own period "
                         f"{'n/a' if s.period_s is None else f'{s.period_s:.0f} s'}, z at campaign period "
                         f"{s.z_at_campaign_period if s.z_at_campaign_period is not None else 'n/a'}"),
                payload={"campaign_id": c.campaign_id, "destinations": c.destinations, **s.model_dump(mode="json")})
            if evidence_store is not None:
                line_ev = evidence_store.append(line_ev)
            malicious = c.q_value <= cfg.q_malicious and s.supports
            verdict = Verdict.MALICIOUS if malicious else Verdict.SUSPICIOUS
            score = campaign_score(c, s.supports)
            per = "n/a" if c.period_s is None else f"~{c.period_s:.0f} s"
            explanation = (f"Line {s.line} is one of {c.n_lines} unrelated lines in RESONANCE campaign "
                           f"{c.campaign_id} ({per} timer toward {', '.join(d.split(':', 1)[1] for d in c.destinations[:3])}). "
                           + ("Its own traffic supports the shared timer. " if s.supports else
                              "Its own traffic is too sparse to confirm the timer individually (membership by "
                              "destination only). ")
                           + c.explanation)
            f = Finding(
                tenant_id=report.tenant_id, entity_pseudonym=s.line, device_class=device_class,
                detector_version=c.detector_version, label=FINDING_LABEL, verdict=verdict, score=score,
                calibration_id=None,
                component_scores={"p_value": c.p_value, "q_value": c.q_value,
                                  "resonance_statistic": float(min(c.resonance_statistic, 1e6)),
                                  "line_z_at_period": s.z_at_campaign_period, "weight": c.weight,
                                  "persistence": s.persistence},
                observed_window_start=c.window_start, observed_window_end=c.window_end,
                evidence_ids=[camp_ev.evidence_id, line_ev.evidence_id],
                counterevidence_ids=[e.evidence_id for e in counter], requires_review=True,
                explanation=explanation, created_at=now, expires_at=now + ttl)
            if evidence_store is not None:
                evidence_store.ledger.append(report.tenant_id, EntryType.FINDING, f.finding_id, {
                    "finding_id": f.finding_id, "entity_pseudonym": f.entity_pseudonym, "label": f.label,
                    "verdict": f.verdict.value, "score": f.score, "calibration_id": None,
                    "detector_version": f.detector_version, "campaign_id": c.campaign_id,
                    "evidence_ids": f.evidence_ids, "counterevidence_ids": f.counterevidence_ids,
                    "observed_window_end": f.observed_window_end})
            out.append(f)
    return out


def utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)
