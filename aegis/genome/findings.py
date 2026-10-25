"""Genome campaigns -> per-line Findings with evidence through the provenance layer.

Verdict policy (pre-registered, deterministic): a member line whose own series supports
the genome timer (matched-filter z >= ``support_z``) in a campaign with q <= ``q_malicious``
is ``MALICIOUS``; every other member line is ``SUSPICIOUS``. Every finding requires review
(shadow mode). Scores are rankings (``calibration_id=None``), not probabilities.

Two evidence records per campaign: the matched-filter result on operator telemetry
(independence group ``operator-telemetry``, shared with SENTINEL/RESONANCE) and the genome's
lab provenance (group ``boxfarm-lab``: lab captures are a separate origin from the tenant's
own telemetry). ``device_class`` is never read; device-model hypotheses stay hypotheses.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable

import numpy as np

from aegis.contracts.models import Evidence, EvidenceKind, Finding, Verdict
from aegis.genome.models import Genome, GenomeReport

ORIGIN = "aegis:genome"
TELEMETRY_GROUP = "operator-telemetry"
LAB_GROUP = "boxfarm-lab"
FINDING_LABEL = "c2_beaconing_genome_match"
CAMPAIGN_ENTRY = "genome_campaign"


def to_findings(report: GenomeReport, genomes: Iterable[Genome], *, evidence_store=None, now: datetime | None = None,
                authorization_id: str = "auth-genome-unset", q_malicious: float = 0.001,
                ttl_hours: float = 72.0) -> list[Finding]:
    now = now or report.window_end
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    by_id = {g.genome_id: g for g in genomes}
    hyp = {h.line: h for h in report.device_hypotheses}
    out: list[Finding] = []
    if report.status != "ok":
        return out
    for c in report.campaigns:
        g = by_id.get(c.genome_id)
        camp_ev = Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.MODEL_SCORE, origin_source=ORIGIN,
            source_independence_group=TELEMETRY_GROUP, collected_at=now, authorization_id=authorization_id,
            summary=(f"genome matched filter: {c.n_lines} lines -> {', '.join(c.destinations[:3])}; "
                     f"p={c.p_value:.2e}, q={c.q_value:.2e}; family {c.family or 'unlabeled'}"),
            payload=c.model_dump(mode="json"))
        lab_ev = Evidence(
            tenant_id=report.tenant_id, kind=EvidenceKind.THREAT_FEED, origin_source="lab:boxfarm",
            source_independence_group=LAB_GROUP, collected_at=now, authorization_id=authorization_id,
            license=g.provenance.licence if g else "operator-internal",
            summary=(f"genome {c.genome_id} extracted from lab captures "
                     f"{', '.join(g.provenance.capture_ids[:3]) if g else 'n/a'}"),
            payload={"genome_id": c.genome_id, "content_sha256": g.content_sha256 if g else None,
                     "signer_key_id": g.signer_key_id if g else None,
                     "provenance": g.provenance.model_dump(mode="json") if g else None,
                     "expires_at": g.expires_at.isoformat() if g else None})
        if evidence_store is not None:
            camp_ev = evidence_store.append(camp_ev)
            lab_ev = evidence_store.append(lab_ev)
            evidence_store.ledger.append(report.tenant_id, CAMPAIGN_ENTRY, c.genome_id + ":" + c.destinations[0][:80], {
                "genome_id": c.genome_id, "evidence_ids": [camp_ev.evidence_id, lab_ev.evidence_id],
                "detector_version": report.detector_version, "destinations": c.destinations, "n_lines": c.n_lines,
                "p_value": c.p_value, "q_value": c.q_value, "q_target": c.q_target})
        supp = set(c.evidence.get("supporting_lines", []))
        base = min(1.0, -np.log10(max(c.q_value, 1e-12)) / 12.0)
        for line in c.member_lines:
            s = line in supp
            verdict = Verdict.MALICIOUS if (s and c.q_value <= q_malicious) else Verdict.SUSPICIOUS
            h = hyp.get(line)
            expl = (f"Line {line} is one of {c.n_lines} lines whose timing toward "
                    f"{', '.join(d.split(':', 1)[1] for d in c.destinations[:3])} matches lab genome "
                    f"{c.genome_id} ({c.family or 'unlabeled'}). "
                    + ("Its own traffic matches the genome timer. " if s else
                       "Its own traffic is too sparse to confirm the timer individually. ")
                    + (f"Likely device model (ranked hypothesis, behavioral evidence only): "
                       f"{h.ranked[0]['box_model']}. " if h and h.ranked else "")
                    + "Requires analyst review.")
            f = Finding(
                tenant_id=report.tenant_id, entity_pseudonym=line, device_class="unknown",
                detector_version=report.detector_version, label=FINDING_LABEL, verdict=verdict,
                score=float(round(base * (1.0 if s else 0.6), 6)), calibration_id=None,
                component_scores={"p_value": c.p_value, "q_value": c.q_value,
                                  "attribution_confidence": c.attribution_confidence},
                observed_window_start=report.window_start, observed_window_end=report.window_end,
                evidence_ids=[camp_ev.evidence_id, lab_ev.evidence_id], requires_review=True,
                explanation=expl, created_at=now, expires_at=now + timedelta(hours=ttl_hours))
            if evidence_store is not None:
                evidence_store.ledger.append(report.tenant_id, "finding", f.finding_id, {
                    "finding_id": f.finding_id, "entity_pseudonym": line, "label": f.label,
                    "verdict": f.verdict.value, "evidence_ids": f.evidence_ids,
                    "detector_version": f.detector_version, "genome_id": c.genome_id})
            out.append(f)
    return out
