import { describe, expect, it } from "vitest";
import { AUTHORIZATION_GROUPS, evaluateChecks, labelCheck } from "./checks";

describe("authorization checklist", () => {
  it("covers every check name the server can emit, once", () => {
    const ids = AUTHORIZATION_GROUPS.flatMap((g) => g.checks.map((c) => c.id));
    // mirror of aegis.mirror.authorize.CHECK_NAMES
    const server = [
      "policy_missing", "policy_signature_invalid", "policy_tenant_mismatch", "policy_not_yet_valid", "policy_expired",
      "policy_not_active_mode", "policy_missing_legal_signoff", "action_type_not_allowed", "legal_basis_missing",
      "legal_basis_not_approved", "evidence_quality_failed", "mirror_missing", "mirror_action_mismatch", "mirror_not_safe",
      "mirror_stale", "mirror_from_future", "targets_empty", "targets_invalid", "targets_exceed_max", "scope_reserved_key",
      "scope_key_not_approved", "scope_exceeds_approved", "affected_entities_unknown", "affected_entities_exceed_approved",
      "expires_at_missing", "expires_at_not_in_future", "expires_at_exceeds_max_ttl", "rollback_plan_missing", "rollback_not_verified",
    ];
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual([...server].sort());
  });

  it("marks only the conjuncts with failed checks as failed", () => {
    const { groups, unknown } = evaluateChecks(["policy_not_active_mode", "policy_missing_legal_signoff"]);
    const failed = groups.filter((g) => !g.passed).map((g) => g.id);
    expect(failed).toEqual(["policy"]);
    const policy = groups.find((g) => g.id === "policy")!;
    expect(policy.results.filter((r) => !r.passed).map((r) => r.id)).toEqual(["policy_not_active_mode", "policy_missing_legal_signoff"]);
    expect(unknown).toEqual([]);
  });

  it("passes everything for an allowed decision and reports unknown checks", () => {
    expect(evaluateChecks([]).groups.every((g) => g.passed)).toBe(true);
    expect(evaluateChecks(["something_new"]).unknown).toEqual(["something_new"]);
  });

  it("labels guard and state failures", () => {
    expect(labelCheck("approver_is_proposer")).toMatch(/four-eyes/i);
    expect(labelCheck("case_state:PROPOSED")).toBe("Case is PROPOSED");
    expect(labelCheck("mirror_not_safe")).toMatch(/SAFE/);
    expect(labelCheck("brand_new_check")).toBe("brand new check");
  });
});
