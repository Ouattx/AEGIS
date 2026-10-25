"""Typed, JSON-serializable content of the shadow proof-of-value report.

:func:`aegis.reports.pov.collect_pov_report` fills a :class:`PovReport` from the
tenant's stores; :func:`aegis.reports.pov.render_pov_html` renders it. The API can
return the same object as JSON, so the HTML and machine-readable report never
disagree. ``None`` always means *not measurable from the supplied data*, never zero.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

REPORT_SCHEMA = "aegis.pov_report/1"


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AlertSummary(_M):
    findings_total: int
    alerts: int                      # MALICIOUS + SUSPICIOUS findings
    malicious: int
    suspicious: int
    abstain_for_review: int          # signal-bearing ABSTAIN findings routed to analysts
    alerted_devices: int
    alerted_device_days: int


class Dispositions(_M):
    """Analyst outcomes of alerting device-days (from the case ledger)."""
    verified: int
    rejected: int
    inconclusive: int
    pending: int


class FalseAlertRates(_M):
    device_days: int | None
    rejected_device_days: int
    unresolved_device_days: int      # pending + inconclusive
    per_10k: float | None            # analyst-rejected alerts (measured)
    per_10k_upper: float | None      # if every unresolved alert proved false
    per_device_class: dict[str, float | None] = Field(default_factory=dict)
    budget_per_10k: float | None = None
    within_budget: bool | None = None


class ThreatClassRow(_M):
    label: str
    malicious: int
    suspicious: int
    abstain: int
    devices: int
    evidence_items: int
    max_independent_origins: int
    verified: int
    rejected: int
    pending: int
    median_score: float | None


class DeviceClassRow(_M):
    device_class: str
    devices_observed: int | None
    alerted_devices: int
    alert_rate: float | None         # alerted / observed devices of the class


class DailyRow(_M):
    day: date
    malicious: int
    suspicious: int
    abstain: int


class EvidenceView(_M):
    evidence_id: str
    kind: str
    summary: str
    origin_source: str
    independence_group: str
    collected_at: datetime | None
    supports: bool
    sha256: str
    integrity: Literal["verified", "tampered", "missing"]


class DecisionView(_M):
    from_state: str
    to_state: str
    actor: str
    reason: str
    at: datetime
    ledger_entry_hash: str | None


class CaseView(_M):
    case_id: str
    title: str
    state: str
    severity: str
    created_at: datetime
    label: str
    verdict: str
    score: float
    calibrated: bool
    entity_pseudonym: str
    device_class: str
    window_start: datetime
    window_end: datetime
    explanation: str
    independent_origins: int
    counter_evidence: int
    evidence: list[EvidenceView]
    evidence_total: int
    decisions: list[DecisionView]
    snapshot_hash: str | None


class EvidenceCoverage(_M):
    alerts_with_evidence: int
    alerts_with_two_origins: int
    evidence_items_checked: int
    evidence_integrity_failures: int
    evidence_missing: int


class DetectionTiming(_M):
    alert_latency_p50_s: float | None
    alert_latency_p95_s: float | None
    onsets_supplied: int
    onsets_detected: int
    detection_delay_median_h: float | None
    detection_delay_p90_h: float | None


class EffortSummary(_M):
    cases: int
    dispositioned_cases: int
    est_minutes_per_case: float | None
    est_minutes_per_dispositioned_case: float | None
    est_total_hours: float
    measured_elapsed_median_h: float | None   # wall-clock from first to last human decision (not effort)
    model: dict[str, float]


class CostLine(_M):
    item: str
    monthly: float
    basis: str


class CostSummary(_M):
    currency: str
    protected_devices: int | None
    lines: list[CostLine]
    monthly_total: float
    per_device_month: float | None
    operator_inputs_configured: bool


class Attestation(_M):
    status: Literal["attested", "enforcement_recorded", "unverifiable"]
    statement: str
    scope: str
    live_executions: int
    dry_run_executions: int
    refused_or_failed_executions: int
    rollbacks: int
    actions_proposed: int
    authorization_decisions: int
    executed_case_transitions: int
    active_policies: list[str]
    shadow_policies: int


class LedgerVerification(_M):
    ok: bool
    entries_checked: int
    signed_entries: int
    signatures_verified: bool
    head_hash: str
    first_bad_seq: int | None
    reason: str | None
    snapshot_id: str | None
    snapshot_hash: str | None
    snapshot_as_of: datetime | None


class Validation(_M):
    """Optional comparison against independent ground truth (lab or red-team injection)."""
    source: str
    device_days: int
    positive_device_days: int
    tp: int
    fp: int
    fn: int
    tn: int
    precision: float | None
    recall: float | None
    false_alerts_per_10k: float | None


class PovReport(_M):
    schema_: str = Field(default=REPORT_SCHEMA, alias="schema")
    tenant_id: str
    operator_name: str
    period_start: datetime
    period_end: datetime
    period_days: float
    generated_at: datetime
    headline: str
    summary: list[str]
    coverage: dict[str, object] | None
    alerts: AlertSummary
    dispositions: Dispositions
    false_alerts: FalseAlertRates
    threat_classes: list[ThreatClassRow]
    device_classes: list[DeviceClassRow]
    daily: list[DailyRow]
    top_cases: list[CaseView]
    evidence: EvidenceCoverage
    timing: DetectionTiming
    effort: EffortSummary
    cost: CostSummary
    attestation: Attestation
    ledger: LedgerVerification
    validation: Validation | None
    detector_versions: list[str]
    methodology: list[str]
    limitations: list[str]
    fingerprint: str = ""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


__all__ = [
    "AlertSummary", "Attestation", "CaseView", "CostLine", "CostSummary", "DailyRow", "DecisionView",
    "DetectionTiming", "DeviceClassRow", "Dispositions", "EffortSummary", "EvidenceCoverage", "EvidenceView",
    "FalseAlertRates", "LedgerVerification", "PovReport", "REPORT_SCHEMA", "ThreatClassRow", "Validation",
]
