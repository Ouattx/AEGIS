"""Canonical data contracts (spec section 3), schema_version 3.0.

These models are the single source of truth shared by every module. Change them
only with a schema_version bump and a compatibility test in tests/unit.

Design rules carried from the spec:
- Raw observations and derived features are separate types (ObservationEvent vs
  FeatureVector). Collectors never pre-compute windowed features.
- Missing values are None plus an explicit missingness flag, never zero.
- Scores are not probabilities unless ``calibration_id`` is set.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "3.0"


def new_id() -> str:
    return str(uuid.uuid4())


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


# ---------------------------------------------------------------- observations

class SourceKind(str, Enum):
    NETFLOW = "netflow"        # NetFlow v5/v9 / IPFIX flow records
    DNS = "dns"                # resolver query logs (dnstap / JSON)
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    CPE = "cpe"                # gateway / CPE agent telemetry (per-device)


class Vantage(str, Enum):
    """What the operator can actually see. Determines which detections apply."""
    SUBSCRIBER_LINE = "subscriber_line"   # ISP core: one identity per line/NAT
    DEVICE = "device"                     # CPE/gateway: per-device identity


class FlowObservation(Strict):
    src_ip: str | None = None
    dst_ip: str
    dst_port: int | None = None
    protocol: Literal["tcp", "udp", "icmp", "other"] = "other"
    bytes_out: int | None = None
    bytes_in: int | None = None
    packets_out: int | None = None
    packets_in: int | None = None
    duration_ms: int | None = None


class DnsObservation(Strict):
    qname: str
    qtype: str = "A"
    rcode: str = "NOERROR"            # NOERROR / NXDOMAIN / SERVFAIL ...
    answers: list[str] = Field(default_factory=list)


class ObservationEvent(Strict):
    """One raw telemetry record, after collector normalization."""
    event_id: str = Field(default_factory=new_id)
    schema_version: Literal["3.0"] = SCHEMA_VERSION
    tenant_id: str
    observed_at: datetime
    ingested_at: datetime
    source_id: str
    source_kind: SourceKind
    vantage: Vantage
    collection_authorization_id: str
    entity_pseudonym: str | None = None   # device or line pseudonym (never raw subscriber id)
    device_class: str | None = None       # e.g. android_tv, smart_tv, console, phone, unknown
    flow: FlowObservation | None = None
    dns: DnsObservation | None = None
    raw_artifact_ref: str | None = None
    data_class: Literal["security_metadata"] = "security_metadata"
    retention_until: datetime
    integrity_sha256: str                 # sha256 of canonical original record bytes


# ---------------------------------------------------------------- features

class FeatureVector(Strict):
    tenant_id: str
    entity_pseudonym: str
    device_class: str
    window: Literal["5m", "15m", "24h"]
    window_end: datetime
    values: dict[str, float | None]       # None = missing
    missing: dict[str, bool]              # explicit missingness indicators
    event_count: int
    source_event_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------- evidence & findings

class EvidenceKind(str, Enum):
    OBSERVATION = "observation"
    IOC_MATCH = "ioc_match"
    MODEL_SCORE = "model_score"
    ANOMALY = "anomaly"
    CHANGE_POINT = "change_point"
    GRAPH_LINK = "graph_link"
    THREAT_FEED = "threat_feed"
    ANALYST_NOTE = "analyst_note"
    COUNTER_HYPOTHESIS = "counter_hypothesis"
    BENIGN_BASELINE = "benign_baseline"


class Evidence(Strict):
    evidence_id: str = Field(default_factory=new_id)
    tenant_id: str
    kind: EvidenceKind
    origin_source: str                    # e.g. "feed:abuse_ch", "sensor:netflow-par1"
    source_independence_group: str        # feeds syndicating one report share a group
    collected_at: datetime
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    sha256: str = ""                      # filled by provenance on append
    artifact_ref: str | None = None
    license: str = "operator-internal"
    authorization_id: str
    supports: bool = True                 # False = counter-evidence


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    TRIAGE = "triage"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    ABSTAIN = "abstain"                   # mandatory unknown outcome


class Finding(Strict):
    finding_id: str = Field(default_factory=new_id)
    tenant_id: str
    entity_pseudonym: str
    device_class: str
    detector_version: str
    label: str                            # e.g. "c2_beaconing", "dga_activity", "residential_proxy"
    verdict: Verdict
    score: float                          # in [0,1]; probability only if calibration_id set
    calibration_id: str | None = None
    component_scores: dict[str, float | None] = Field(default_factory=dict)
    observed_window_start: datetime
    observed_window_end: datetime
    evidence_ids: list[str] = Field(default_factory=list)
    counterevidence_ids: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.CANDIDATE
    requires_review: bool = True
    explanation: str = ""
    created_at: datetime
    expires_at: datetime
    #: wall-clock time the telemetry that closed the window was received (ingest time);
    #: alert latency = created_at - max(observed_window_end, ingested_at)
    ingested_at: datetime | None = None


# ---------------------------------------------------------------- cases

class CaseState(str, Enum):
    NEW = "NEW"
    TRIAGE = "TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PROPOSED = "PROPOSED"
    CLOSED = "CLOSED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXECUTED = "EXECUTED"
    ROLLED_BACK = "ROLLED_BACK"
    EXPIRED = "EXPIRED"


class CaseDecision(Strict):
    decision_id: str = Field(default_factory=new_id)
    from_state: CaseState
    to_state: CaseState
    actor: str                            # user id or "agent:<name>" or "system"
    reason: str
    at: datetime
    ledger_entry_hash: str | None = None
    #: the proposed action this decision is about (PROPOSED / APPROVED / DENIED / EXECUTED);
    #: an approval authorizes exactly this action and nothing else
    action_id: str | None = None
    #: sha256 of the authorization assessment the decision relied on
    authorization_sha256: str | None = None


class Case(Strict):
    case_id: str = Field(default_factory=new_id)
    tenant_id: str
    product: Literal["shield"] = "shield"
    title: str
    hypothesis: str
    alternative_hypotheses: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    decisions: list[CaseDecision] = Field(default_factory=list)
    state: CaseState = CaseState.NEW
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    reviewer: str | None = None
    counter_hypothesis_reviewed: bool = False
    snapshot_hash: str | None = None
    model_versions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------- enforcement

class ActionType(str, Enum):
    DNS_SINKHOLE = "dns_sinkhole"         # RPZ entry
    IP_BLOCK = "ip_block"
    DEVICE_QUARANTINE = "device_quarantine"   # walled garden for a pseudonymous device/line
    NOTIFY_SUBSCRIBER = "notify_subscriber"


class ProposedAction(Strict):
    action_id: str = Field(default_factory=new_id)
    tenant_id: str
    case_id: str
    action_type: ActionType
    targets: list[str]                    # domains / IPs / pseudonyms
    scope: dict[str, Any] = Field(default_factory=dict)   # e.g. {"max_entities": 1, "regions": [...]}
    legal_basis: str | None = None        # e.g. "operator_tos_security_clause"
    authorization_id: str | None = None
    expires_at: datetime | None = None
    rollback_plan: str | None = None
    rollback_verified: bool = False
    created_by: str
    created_at: datetime


class MirrorVerdict(str, Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    UNKNOWN = "UNKNOWN"                   # treated as UNSAFE (fail closed)


class MirrorResult(Strict):
    action_id: str
    verdict: MirrorVerdict
    affected_entities: int | None
    legitimate_cotenants: list[str] = Field(default_factory=list)
    shared_infrastructure: bool = False
    historic_daily_legit_flows: int | None = None
    reversibility: Literal["instant", "minutes", "manual", "unknown"] = "unknown"
    unknowns: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    rationale: str
    computed_at: datetime


class OperatorPolicy(Strict):
    """Signed operator policy granting bounded enforcement authority."""
    policy_id: str
    tenant_id: str
    mode: Literal["shadow", "active"] = "shadow"
    allowed_actions: list[ActionType] = Field(default_factory=list)
    max_targets_per_action: int = 1
    max_ttl_hours: int = 24
    approved_scope: dict[str, Any] = Field(default_factory=dict)
    legal_signoff_ref: str | None = None
    valid_from: datetime
    valid_until: datetime
    signer_key_id: str
    signature: str                        # Ed25519 over canonical policy minus signature


class AuthorizationDecision(Strict):
    action_id: str
    allowed: bool
    failed_checks: list[str] = Field(default_factory=list)
    requires_human_approval: bool = True
    evaluated_at: datetime
    policy_id: str | None = None


# ---------------------------------------------------------------- ledger

class LedgerEntry(Strict):
    seq: int
    tenant_id: str
    entry_type: str                       # "evidence", "finding", "case_transition", "action", "model", "correction", ...
    subject_id: str
    payload_sha256: str
    payload: dict[str, Any]
    prev_hash: str
    entry_hash: str
    recorded_at: datetime
    signer_key_id: str | None = None
    signature: str | None = None
