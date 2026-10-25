/**
 * TypeScript mirror of the AEGIS API payloads (aegis/contracts/models.py and the
 * dict shapes returned by aegis/service.py). Timestamps are ISO-8601 UTC strings.
 */

export type Role = "viewer" | "analyst" | "approver" | "admin" | "integration";

export type Permission =
  | "read"
  | "read_audit"
  | "ingest"
  | "case_work"
  | "investigate"
  | "propose"
  | "approve"
  | "execute"
  | "configure";

export type CaseState =
  | "NEW"
  | "TRIAGE"
  | "INVESTIGATING"
  | "VERIFIED"
  | "REJECTED"
  | "INCONCLUSIVE"
  | "PROPOSED"
  | "CLOSED"
  | "APPROVED"
  | "DENIED"
  | "EXECUTED"
  | "ROLLED_BACK"
  | "EXPIRED";

export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "malicious" | "suspicious" | "benign" | "abstain";
export type FindingStatus = "candidate" | "triage" | "verified" | "rejected" | "expired";
export type ActionType = "dns_sinkhole" | "ip_block" | "device_quarantine" | "notify_subscriber";
export type MirrorVerdict = "SAFE" | "UNSAFE" | "UNKNOWN";
export type ExecutionStatus = "applied" | "dry_run" | "refused" | "failed" | "rolled_back" | "rollback_failed";

export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface ListOf<T> {
  items: T[];
  total: number;
}

export interface AuthConfig {
  auth_mode: "dev" | "oidc";
  oidc_issuer: string | null;
  oidc_audience: string | null;
  demo: boolean;
  roles: Role[];
}

export interface DemoToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  role: Role;
  tenant_id: string;
  sub: string;
}

export interface Me {
  sub: string;
  tenant_id: string;
  roles: Role[];
  auth_mode: string;
  permissions: Permission[];
}

export interface Finding {
  finding_id: string;
  tenant_id: string;
  entity_pseudonym: string;
  device_class: string;
  detector_version: string;
  label: string;
  verdict: Verdict;
  score: number | null;
  calibration_id: string | null;
  component_scores: Record<string, number | null>;
  observed_window_start: string;
  observed_window_end: string;
  evidence_ids: string[];
  counterevidence_ids: string[];
  status: FindingStatus;
  requires_review: boolean;
  explanation: string;
  created_at: string;
  expires_at: string | null;
}

export interface CaseDecision {
  decision_id: string;
  from_state: CaseState;
  to_state: CaseState;
  actor: string;
  reason: string;
  at: string;
  ledger_entry_hash: string | null;
}

export interface Case {
  case_id: string;
  tenant_id: string;
  product: string;
  title: string;
  hypothesis: string;
  alternative_hypotheses: string[];
  finding_ids: string[];
  evidence_ids: string[];
  decisions: CaseDecision[];
  state: CaseState;
  severity: Severity;
  reviewer: string | null;
  counter_hypothesis_reviewed: boolean;
  snapshot_hash: string | null;
  model_versions: string[];
  created_at: string;
  updated_at: string;
}

export interface EvidenceAssessment {
  qualifying_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  signed_ioc_hit_ids: string[];
  supporting_origins: string[];
  contradicting_origins: string[];
  rejected: Record<string, string>;
  contested: boolean;
  verification_blockers: string[];
}

export interface ProposedAction {
  action_id: string;
  tenant_id: string;
  case_id: string;
  action_type: ActionType;
  targets: string[];
  scope: Record<string, unknown>;
  legal_basis: string | null;
  authorization_id: string | null;
  expires_at: string | null;
  rollback_plan: string | null;
  rollback_verified: boolean;
  created_by: string;
  created_at: string;
}

export interface CaseDetail {
  case: Case;
  findings: Finding[];
  evidence_assessment: EvidenceAssessment;
  allowed_transitions: CaseState[];
  actions: ProposedAction[];
  investigation: {
    report_id: string;
    finished_at: string;
    recommendation: string;
    escalate: boolean;
  } | null;
}

export interface Evidence {
  evidence_id: string;
  tenant_id: string;
  kind: string;
  origin_source: string;
  source_independence_group: string;
  collected_at: string;
  summary: string;
  payload: Record<string, unknown>;
  sha256: string;
  artifact_ref: string | null;
  license: string;
  authorization_id: string;
  supports: boolean;
}

export interface EvidenceView {
  evidence: Evidence;
  integrity_verified: boolean;
  superseded_by: string | null;
}

export interface HistoryEntry {
  seq: number;
  entry_type: string;
  recorded_at: string;
  entry_hash: string;
  payload: Record<string, unknown>;
  subject_id?: string;
}

export interface AlternativeHypothesis {
  title: string;
  rationale: string;
  plausibility: string;
  discriminating_tests: string[];
  source: string;
}

export interface ToolCall {
  agent: string;
  tool: string;
  ok: boolean;
  attempts: number;
  duration_ms: number;
  error: string | null;
  injection_flags: string[];
}

export interface InvestigationReport {
  report_id: string;
  case_id: string;
  tenant_id: string;
  started_at: string;
  finished_at: string;
  mode: string;
  llm_status: string;
  llm_model: string | null;
  hypothesis: string;
  narrative: string;
  evidence_summary: string;
  evidence: Array<{
    evidence_id: string;
    kind: string;
    origin_source: string;
    source_group: string;
    supports: boolean;
    integrity_verified: boolean;
    agent_appended: boolean;
    summary: string;
  }>;
  supporting_origins: string[];
  contradicting_origins: string[];
  signed_ioc_hit_ids: string[];
  counter_evidence_ids: string[];
  alternative_hypotheses: AlternativeHypothesis[];
  graph_findings: string[];
  policy: { enforcement_possible: boolean; active_policy_ids: string[]; notes: string[] };
  verification: {
    recommendation: string;
    suggested_state: string | null;
    evidence_sufficient_for_verified: boolean;
    blockers: string[];
    rationale: string;
  };
  proposal_action_id: string | null;
  proposal_notes: string[];
  escalate: boolean;
  escalation_reasons: string[];
  tool_calls: ToolCall[];
  refused_tool_requests: unknown[];
  untrusted_content_flags: unknown[];
  llm_discrepancies: unknown[];
  appended_evidence_ids: string[];
  candidate_edge_ids: string[];
  budget: Record<string, unknown>;
  report_sha256: string | null;
}

export interface Snapshot {
  snapshot_id: string;
  snapshot_hash: string;
  tenant_id: string;
  as_of: string;
  entry_count: number;
  head_seq: number;
  head_hash: string;
}

export interface Replay {
  tenant_id: string;
  subject_id: string;
  as_of: string;
  snapshot: Snapshot;
  evidence_ids: string[];
  superseded_evidence_ids: Record<string, string>;
  non_contemporaneous_evidence_ids: string[];
  model_versions: string[];
  rule_bundle_versions: string[];
  decisions: HistoryEntry[];
  entries: HistoryEntry[];
}

export interface GraphNode {
  tenant_id: string;
  node_id: string;
  node_type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  attrs: Record<string, unknown>;
  provenance_ids: string[];
}

export interface GraphEdge {
  edge_id: string;
  src: string;
  dst: string;
  edge_type: string;
  first_seen: string;
  last_seen: string;
  evidence_grade: string;
  independent_source_count: number;
  source_groups: string[];
  observation_count: number;
  active: boolean;
  candidate: boolean;
  investigative_only: boolean;
  enforcement_eligible: boolean;
  eligibility_reasons: string[];
  attrs: Record<string, unknown>;
}

export interface GraphNeighbor {
  node_id: string;
  node_type: string;
  direction: "in" | "out";
  edge: GraphEdge;
}

export interface CandidateLink {
  src: string;
  dst: string;
  score: number;
  method: string;
  shared_neighbors: string[];
  rationale: string;
  investigative_only: boolean;
  enforcement_eligible: boolean;
}

export interface GraphView {
  node: GraphNode;
  shared_hosting: boolean;
  degree: number;
  neighbors: GraphNeighbor[];
  truncated: boolean;
  candidate_links: CandidateLink[];
  as_of: string | null;
}

export interface MirrorResult {
  action_id: string;
  verdict: MirrorVerdict;
  affected_entities: number | null;
  legitimate_cotenants: string[];
  shared_infrastructure: boolean;
  historic_daily_legit_flows: number | null;
  reversibility: "instant" | "minutes" | "manual" | "unknown";
  unknowns: string[];
  requires_human_approval: boolean;
  rationale: string;
  computed_at: string;
}

export interface AuthorizationDecision {
  action_id: string;
  allowed: boolean;
  failed_checks: string[];
  requires_human_approval: boolean;
  evaluated_at: string;
  policy_id: string | null;
}

export interface ExecutionRecord {
  execution_id: string;
  tenant_id: string;
  action_id: string;
  case_id: string;
  operation: "execute" | "rollback";
  status: ExecutionStatus;
  adapter: string;
  dry_run: boolean;
  actor: string;
  reason: string;
  refusal_reasons: string[];
  policy_id: string | null;
  prior_state: Record<string, unknown>;
  details: Record<string, unknown>;
  at: string;
  ledger_entry_hash: string | null;
}

export interface ActionDetail {
  action: ProposedAction;
  mirror: MirrorResult | null;
  authorization: AuthorizationDecision | null;
  evidence_quality_ok: boolean | null;
  executions: ExecutionRecord[];
  live: boolean;
}

export interface AuthorizeResult {
  decision: AuthorizationDecision;
  case_state: CaseState;
  evidence_quality_ok: boolean;
}

export interface LedgerVerify {
  ok: boolean;
  first_bad_seq: number | null;
  reason: string | null;
  entries_checked: number;
  head_hash: string | null;
  signed_entries: number;
  entry_count: number;
  trusted_ledger_keys: string[];
}

export interface LedgerEntry {
  seq: number;
  tenant_id: string;
  entry_type: string;
  subject_id: string;
  payload_sha256: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
  recorded_at: string;
  signer_key_id: string | null;
  signature: string | null;
}

export interface MetricsSummary {
  tenant_id: string;
  findings: { total: number; by_verdict: Record<string, number>; by_label: Record<string, number> };
  cases: {
    total: number;
    open: number;
    by_state: Record<string, number>;
    by_severity: Record<string, number>;
  };
  actions: {
    total: number;
    executions_by_status: Record<string, number>;
    live_enforcements: number;
    enforcement_applied: number;
  };
  coverage: {
    period_start: string;
    period_end: string;
    devices_observed: number;
    device_days: number;
    events: number;
    devices_by_class: Record<string, number>;
  };
  ingest: { quarantined: number; quarantine_reasons: Record<string, number>; sources: string[] };
  detector_version: string;
  model_loaded: boolean;
  ioc_bundle: IocBundleStatus | null;
  topology: TopologyStatus | null;
  llm: boolean;
  enforcement_adapter: string;
  ledger: { entries: number; head: string | null };
}

export interface IocBundleStatus {
  bundle_id: string;
  version: string;
  issuer: string;
  sha256: string;
  signer_key_id: string;
  issued_at: string;
  indicators: number;
  indicator_states: Record<string, number>;
}

export interface TopologyStatus {
  topology_id: string;
  complete: boolean;
  prefixes: number;
  hosts: number;
  shared_hosts: number;
  domains: number;
}

export interface OperatorPolicy {
  policy_id: string;
  tenant_id: string;
  mode: "shadow" | "active";
  allowed_actions: ActionType[];
  max_targets_per_action: number;
  max_ttl_hours: number;
  approved_scope: Record<string, unknown>;
  legal_signoff_ref: string | null;
  valid_from: string;
  valid_until: string;
  signer_key_id: string;
  signature: string;
}

export interface PolicyItem {
  policy: OperatorPolicy;
  signature_valid: boolean;
  valid_now: boolean;
}

export interface SourceConfig {
  tenant_id: string;
  source_id: string;
  source_kind: string;
  vantage: string;
  collection_authorization_id: string;
  retention_days: number;
  format: string | null;
  entity_field: string;
  assume_utc_for_naive: boolean;
  max_clock_skew_s: number;
}

/** The JSON form of the shadow proof-of-value report (schema ``aegis.pov_report/1``). */
export interface PovReport {
  schema: string;
  tenant_id: string;
  operator_name: string;
  period_start: string;
  period_end: string;
  period_days: number;
  generated_at: string;
  headline: string;
  summary: string[];
  coverage: {
    devices_observed: number;
    device_days: number;
    events: number;
    devices_by_class: Record<string, number>;
    device_days_by_class: Record<string, number>;
    sources: string[];
  };
  alerts: {
    findings_total: number;
    alerts: number;
    malicious: number;
    suspicious: number;
    abstain_for_review: number;
    alerted_devices: number;
    alerted_device_days: number;
  };
  dispositions: { verified: number; rejected: number; inconclusive: number; pending: number };
  false_alerts: {
    device_days: number;
    rejected_device_days: number;
    unresolved_device_days: number;
    per_10k: number | null;
    per_10k_upper: number | null;
    per_device_class: Record<string, number | null>;
    budget_per_10k: number | null;
    within_budget: boolean | null;
  };
  threat_classes: Array<{
    label: string;
    malicious: number;
    suspicious: number;
    abstain: number;
    devices: number;
    verified: number;
    rejected: number;
    pending: number;
  }>;
  device_classes: Array<{
    device_class: string;
    devices_observed: number;
    alerted_devices: number;
    alert_rate: number | null;
  }>;
  daily: Array<{ day: string; malicious: number; suspicious: number; abstain: number }>;
  evidence: {
    alerts_with_evidence: number;
    alerts_with_two_origins: number;
    evidence_items_checked: number;
    evidence_integrity_failures: number;
    evidence_missing: number;
  };
  timing: {
    detection_delay_median_h: number | null;
    detection_delay_p90_h: number | null;
    onsets_supplied: number;
    onsets_detected: number;
  };
  effort: { cases: number; est_total_hours: number | null; est_minutes_per_case: number | null };
  attestation: {
    status: string;
    statement: string;
    scope: string;
    live_executions: number;
    dry_run_executions: number;
    actions_proposed: number;
    shadow_policies: number;
  };
  ledger: {
    ok: boolean;
    entries_checked: number;
    head_hash: string | null;
    snapshot_hash: string | null;
  };
  validation: {
    source: string;
    precision: number | null;
    recall: number | null;
    tp: number;
    fp: number;
    fn: number;
    tn: number;
  } | null;
  fingerprint: string;
  limitations: string[];
}

export interface ApiErrorBody {
  error: string;
  detail: string;
  failed_checks: string[];
  request_id: string | null;
  errors?: Array<{ loc: string[]; msg: string; type: string }>;
}
