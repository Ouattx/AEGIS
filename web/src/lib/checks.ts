/**
 * The deterministic authorization formula of aegis.mirror.authorize, grouped by conjunct
 * so the console can show every check as pass / fail (spec sections 9 and 12):
 *
 *   authorize(action) = signed_operator_policy AND legal_basis_valid AND evidence_quality_pass
 *                       AND mirror_result == SAFE AND scope <= approved_scope
 *                       AND expires_at set AND rollback_plan_verified
 *
 * The check identifiers are the stable names listed in ``CHECK_NAMES`` on the server.
 */
export interface CheckGroup {
  id: string;
  title: string;
  description: string;
  checks: Array<{ id: string; label: string }>;
}

export const AUTHORIZATION_GROUPS: CheckGroup[] = [
  {
    id: "policy",
    title: "Signed operator policy",
    description: "A valid Ed25519-signed policy for this tenant, in active mode, with legal signoff, allowing this action type.",
    checks: [
      { id: "policy_missing", label: "Policy present" },
      { id: "policy_signature_invalid", label: "Signature verifies against operator key ring" },
      { id: "policy_tenant_mismatch", label: "Policy belongs to this tenant" },
      { id: "policy_not_yet_valid", label: "Policy validity window has started" },
      { id: "policy_expired", label: "Policy not expired" },
      { id: "policy_not_active_mode", label: "Policy mode is active (shadow never enforces)" },
      { id: "policy_missing_legal_signoff", label: "Legal signoff reference recorded" },
      { id: "action_type_not_allowed", label: "Action type allowed by policy" },
    ],
  },
  {
    id: "legal",
    title: "Legal basis",
    description: "The proposal names a legal basis the policy approves.",
    checks: [
      { id: "legal_basis_missing", label: "Legal basis given" },
      { id: "legal_basis_not_approved", label: "Legal basis approved by policy" },
    ],
  },
  {
    id: "evidence",
    title: "Evidence quality",
    description: "The case is VERIFIED with no verification blockers (two independent origins or a signed IOC hit).",
    checks: [{ id: "evidence_quality_failed", label: "Evidence quality passes verification guard" }],
  },
  {
    id: "mirror",
    title: "MIRROR simulation is SAFE",
    description: "A fresh impact simulation of this exact action returned SAFE (UNKNOWN fails closed).",
    checks: [
      { id: "mirror_missing", label: "Simulation recorded" },
      { id: "mirror_action_mismatch", label: "Simulation matches this action" },
      { id: "mirror_not_safe", label: "Verdict is SAFE" },
      { id: "mirror_stale", label: "Simulation is fresh (< 1 h)" },
      { id: "mirror_from_future", label: "Simulation timestamp is sane" },
    ],
  },
  {
    id: "scope",
    title: "Scope within approved scope",
    description: "Targets and scope stay inside the policy's limits, including collateral impact.",
    checks: [
      { id: "targets_empty", label: "At least one target" },
      { id: "targets_invalid", label: "Targets are valid for the action type" },
      { id: "targets_exceed_max", label: "Target count within policy maximum" },
      { id: "scope_reserved_key", label: "No reserved scope keys" },
      { id: "scope_key_not_approved", label: "Every scope key approved" },
      { id: "scope_exceeds_approved", label: "Scope values within approved bounds" },
      { id: "affected_entities_unknown", label: "Affected entity count known" },
      { id: "affected_entities_exceed_approved", label: "Affected entities within approved ceiling" },
    ],
  },
  {
    id: "expiry",
    title: "Bounded expiry",
    description: "The action expires, in the future and within the policy's maximum TTL.",
    checks: [
      { id: "expires_at_missing", label: "Expiry set" },
      { id: "expires_at_not_in_future", label: "Expiry in the future" },
      { id: "expires_at_exceeds_max_ttl", label: "Expiry within policy max TTL" },
    ],
  },
  {
    id: "rollback",
    title: "Rollback plan verified",
    description: "A rollback plan exists and has been verified.",
    checks: [
      { id: "rollback_plan_missing", label: "Rollback plan written" },
      { id: "rollback_not_verified", label: "Rollback plan verified" },
    ],
  },
];

const KNOWN = new Set(AUTHORIZATION_GROUPS.flatMap((g) => g.checks.map((c) => c.id)));

export interface EvaluatedGroup extends CheckGroup {
  passed: boolean;
  results: Array<{ id: string; label: string; passed: boolean }>;
}

/** Expand a decision's ``failed_checks`` into every check with pass / fail. */
export function evaluateChecks(failed: string[]): { groups: EvaluatedGroup[]; unknown: string[] } {
  const f = new Set(failed);
  const groups = AUTHORIZATION_GROUPS.map((g) => {
    const results = g.checks.map((c) => ({ ...c, passed: !f.has(c.id) }));
    return { ...g, results, passed: results.every((r) => r.passed) };
  });
  return { groups, unknown: failed.filter((x) => !KNOWN.has(x)) };
}

/** Human labels for case guard failures returned by the state machine and execution gate. */
export const GUARD_LABELS: Record<string, string> = {
  needs_two_independent_origins_or_signed_ioc_hit: "Needs two independent evidence origins or a signed IOC hit",
  contested_requires_two_independent_supporting_origins: "Contested evidence: two independent supporting origins required",
  contradicting_origins_not_outweighed: "Independent contradicting origins are not outweighed",
  counter_hypothesis_review_missing: "Counter-hypothesis review must be recorded first",
  contested_case_requires_human_verifier: "Contested case requires a human verifier",
  approval_requires_human_approver: "Approval requires a human approver",
  no_human_approval_recorded: "No human approval recorded",
  signed_policy_missing: "No signed operator policy",
  policy_not_valid_now: "Policy is not valid now",
  authorization_not_bound_to_policy: "Authorization is not bound to the policy",
  action_type_not_allowed_by_policy: "Action type not allowed by policy",
  action_without_expiry: "Action has no expiry",
  action_expired: "Action expired",
  mirror_result_missing: "No MIRROR simulation recorded",
  proposed_action_not_found: "Proposed action not found",
  authorization_not_allowed: "Deterministic authorization did not allow this action",
  approver_is_proposer: "Four-eyes: the proposer cannot approve or execute",
  terminal_state: "Case is in a terminal state",
  no_live_execution: "No live execution to roll back",
};

export function labelCheck(id: string): string {
  if (GUARD_LABELS[id]) return GUARD_LABELS[id];
  for (const g of AUTHORIZATION_GROUPS) {
    const c = g.checks.find((x) => x.id === id);
    if (c) return `${c.label} — failed`;
  }
  if (id.startsWith("case_state:")) return `Case is ${id.slice("case_state:".length)}`;
  return id.replace(/_/g, " ");
}
