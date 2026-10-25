import type { ActionDetail, CaseDetail, EvidenceView, Finding, InvestigationReport, LedgerVerify, MetricsSummary, PolicyItem, PovReport, Role } from "../api/types";

export const NOW = "2026-10-25T10:00:00Z";

export function token(role: Role): string {
  const b64 = (o: unknown) => btoa(JSON.stringify(o)).replace(/=+$/, "");
  return `${b64({ alg: "HS256" })}.${b64({ sub: `demo-${role}`, roles: [role], exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;
}

const PERMS: Record<Role, string[]> = {
  viewer: ["read"],
  analyst: ["case_work", "investigate", "propose", "read"],
  approver: ["approve", "execute", "read"],
  admin: ["configure", "read", "read_audit"],
  integration: ["ingest"],
};

export function me(role: Role) {
  return { sub: `demo-${role}`, tenant_id: "demo", roles: [role], auth_mode: "dev", permissions: PERMS[role] };
}

export const metrics: MetricsSummary = {
  tenant_id: "demo",
  findings: { total: 27, by_verdict: { malicious: 23, abstain: 4 }, by_label: { c2_beaconing: 9, ddos_bot: 4 } },
  cases: { total: 23, open: 4, by_state: { VERIFIED: 15, INVESTIGATING: 4, INCONCLUSIVE: 4 }, by_severity: { critical: 22, high: 1 } },
  actions: { total: 0, executions_by_status: {}, live_enforcements: 0, enforcement_applied: 0 },
  coverage: { period_start: "2026-10-22T00:00:00Z", period_end: "2026-10-25T00:00:00Z", devices_observed: 120, device_days: 360, events: 248877, devices_by_class: { android_tv: 33 } },
  ingest: { quarantined: 0, quarantine_reasons: {}, sources: ["lab-dns", "lab-netflow"] },
  detector_version: "sentinel/1.0.0+m+ioc:x+abc",
  model_loaded: true,
  ioc_bundle: null,
  topology: { topology_id: "t", complete: true, prefixes: 13, hosts: 502, shared_hosts: 48, domains: 2600 },
  llm: false,
  enforcement_adapter: "dry_run",
  ledger: { entries: 462, head: "f".repeat(64) },
};

export const ledger: LedgerVerify = { ok: true, first_bad_seq: null, reason: null, entries_checked: 462, head_hash: "f".repeat(64), signed_entries: 462, entry_count: 462, trusted_ledger_keys: ["aegis-ledger"] };

export const shadowPolicy: PolicyItem = {
  policy: {
    policy_id: "demo-shadow",
    tenant_id: "demo",
    mode: "shadow",
    allowed_actions: ["dns_sinkhole", "notify_subscriber"],
    max_targets_per_action: 5,
    max_ttl_hours: 72,
    approved_scope: { legal_bases: ["operator_tos_security_clause"] },
    legal_signoff_ref: null,
    valid_from: "2026-10-24T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
    signer_key_id: "demo-operator",
    signature: "sig",
  },
  signature_valid: true,
  valid_now: true,
};

export const finding: Finding = {
  finding_id: "f-1",
  tenant_id: "demo",
  entity_pseudonym: "p_e8d81a05b8b803811a6a7cadaac16df5",
  device_class: "android_tv",
  detector_version: "sentinel/1.0.0+m",
  label: "c2_beaconing",
  verdict: "malicious",
  score: 1,
  calibration_id: "iso-1",
  component_scores: { ioc: 0.9, ml: 1, anomaly: 1, changepoint: 0 },
  observed_window_start: "2026-10-21T03:00:00Z",
  observed_window_end: "2026-10-22T03:00:00Z",
  evidence_ids: ["ev-1", "ev-2"],
  counterevidence_ids: [],
  status: "candidate",
  requires_review: true,
  explanation: "MALICIOUS: command-and-control beaconing",
  created_at: "2026-10-22T03:00:00Z",
  expires_at: null,
};

export function caseDetail(state: CaseDetail["case"]["state"] = "INVESTIGATING", reviewed = false): CaseDetail {
  return {
    case: {
      case_id: "case-1",
      tenant_id: "demo",
      product: "shield",
      title: "c2_beaconing on android_tv device p_e8d81a05b8b803811a6a7cadaac16df5",
      hypothesis: "Device p_e8d8 exhibits c2 beaconing",
      alternative_hypotheses: ["Legitimate push heartbeat", "IPTV licence polling"],
      finding_ids: ["f-1"],
      evidence_ids: ["ev-1", "ev-2"],
      decisions: [],
      state,
      severity: "critical",
      reviewer: reviewed ? "demo-analyst" : null,
      counter_hypothesis_reviewed: reviewed,
      snapshot_hash: null,
      model_versions: ["sentinel/1.0.0+m"],
      created_at: NOW,
      updated_at: NOW,
    },
    findings: [finding],
    evidence_assessment: {
      qualifying_evidence_ids: ["ev-1", "ev-2"],
      contradicting_evidence_ids: [],
      signed_ioc_hit_ids: ["ev-2"],
      supporting_origins: ["grp:alpha", "operator-telemetry"],
      contradicting_origins: [],
      rejected: {},
      contested: false,
      verification_blockers: [],
    },
    allowed_transitions: state === "INVESTIGATING" ? ["INCONCLUSIVE", "REJECTED", "VERIFIED"] : state === "VERIFIED" ? ["CLOSED", "PROPOSED"] : [],
    actions: [],
    investigation: null,
  };
}

export const evidence: EvidenceView[] = [
  {
    evidence: { evidence_id: "ev-1", tenant_id: "demo", kind: "observation", origin_source: "sensor:lab-dns", source_independence_group: "operator-telemetry", collected_at: NOW, summary: "26 flow/DNS events", payload: { top_destinations: [{ dst_ip: "203.0.113.53", flows: 12 }] }, sha256: "a".repeat(64), artifact_ref: null, license: "operator-internal", authorization_id: "auth-1", supports: true },
    integrity_verified: true,
    superseded_by: null,
  },
  {
    evidence: { evidence_id: "ev-2", tenant_id: "demo", kind: "ioc_match", origin_source: "feed:alpha", source_independence_group: "grp:alpha", collected_at: NOW, summary: "contacted cfg.boxhelper.example", payload: { indicator_type: "domain", indicator_value: "cfg.boxhelper.example" }, sha256: "b".repeat(64), artifact_ref: null, license: "feed", authorization_id: "auth-1", supports: true },
    integrity_verified: false,
    superseded_by: null,
  },
];

export const action: ActionDetail = {
  action: { action_id: "act-1", tenant_id: "demo", case_id: "case-1", action_type: "dns_sinkhole", targets: ["cfg.boxhelper.example"], scope: {}, legal_basis: "operator_tos_security_clause", authorization_id: null, expires_at: "2026-10-26T10:00:00Z", rollback_plan: "remove entry", rollback_verified: true, created_by: "demo-analyst", created_at: NOW },
  mirror: { action_id: "act-1", verdict: "SAFE", affected_entities: 2, legitimate_cotenants: [], shared_infrastructure: false, historic_daily_legit_flows: 0, reversibility: "minutes", unknowns: [], requires_human_approval: true, rationale: "SAFE: dns_sinkhole on 1 target(s).", computed_at: NOW },
  authorization: { action_id: "act-1", allowed: false, failed_checks: ["policy_not_active_mode", "policy_missing_legal_signoff"], requires_human_approval: true, evaluated_at: NOW, policy_id: "demo-shadow" },
  evidence_quality_ok: true,
  executions: [],
  live: false,
};

export const pov = {
  false_alerts: { device_days: 360, rejected_device_days: 0, unresolved_device_days: 7, per_10k: 0, per_10k_upper: 194.4, per_device_class: {}, budget_per_10k: null, within_budget: null },
  device_classes: [{ device_class: "android_tv", devices_observed: 33, alerted_devices: 6, alert_rate: 0.18 }],
  evidence: { alerts_with_evidence: 23, alerts_with_two_origins: 18, evidence_items_checked: 171, evidence_integrity_failures: 0, evidence_missing: 0 },
  timing: { detection_delay_median_h: 0.83, detection_delay_p90_h: 2, onsets_supplied: 10, onsets_detected: 10 },
  dispositions: { verified: 14, rejected: 0, inconclusive: 3, pending: 4 },
  validation: null,
  attestation: { status: "attested", statement: "none", scope: "", live_executions: 0, dry_run_executions: 0, actions_proposed: 0, shadow_policies: 1 },
} as unknown as PovReport;

export const report = {
  report_id: "r1", case_id: "case-1", tenant_id: "demo", started_at: NOW, finished_at: NOW, mode: "deterministic", llm_status: "disabled", llm_model: null,
  hypothesis: "h", narrative: "narrative text", evidence_summary: "", evidence: [], supporting_origins: ["grp:alpha"], contradicting_origins: [], signed_ioc_hit_ids: [], counter_evidence_ids: [],
  alternative_hypotheses: [{ title: "Legitimate push heartbeat", rationale: "keep-alives look periodic", plausibility: "low", discriminating_tests: ["Check destination"], source: "deterministic" }],
  graph_findings: [], policy: { enforcement_possible: false, active_policy_ids: [], notes: [] },
  verification: { recommendation: "verify", suggested_state: "VERIFIED", evidence_sufficient_for_verified: true, blockers: [], rationale: "two origins" },
  proposal_action_id: null, proposal_notes: [], escalate: false, escalation_reasons: [], tool_calls: [], refused_tool_requests: [], untrusted_content_flags: [], llm_discrepancies: [], appended_evidence_ids: [], candidate_edge_ids: [], budget: {}, report_sha256: "c".repeat(64),
} as InvestigationReport;
