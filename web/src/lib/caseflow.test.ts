import { describe, expect, it } from "vitest";
import { transitionButtons } from "./caseflow";

const ok = { counterHypothesisReviewed: true, verificationBlockers: [] as string[] };

describe("transition gating", () => {
  it("lets an analyst move an investigating case", () => {
    const b = transitionButtons(["INCONCLUSIVE", "REJECTED", "VERIFIED"], ["read", "case_work"], ok);
    expect(b.map((x) => [x.to, x.enabled])).toEqual([
      ["INCONCLUSIVE", true],
      ["REJECTED", true],
      ["VERIFIED", true],
    ]);
  });

  it("disables analyst transitions for viewers and approvers", () => {
    const b = transitionButtons(["REJECTED", "VERIFIED"], ["read", "approve", "execute"], ok);
    expect(b.every((x) => !x.enabled)).toBe(true);
    expect(b[0].hint).toMatch(/analyst/);
  });

  it("blocks VERIFIED until review is recorded and blockers are clear", () => {
    expect(transitionButtons(["VERIFIED"], ["case_work"], { counterHypothesisReviewed: false, verificationBlockers: [] })[0]).toMatchObject({ enabled: false });
    const blocked = transitionButtons(["VERIFIED"], ["case_work"], { counterHypothesisReviewed: true, verificationBlockers: ["needs_two_independent_origins_or_signed_ioc_hit"] })[0];
    expect(blocked.enabled).toBe(false);
    expect(blocked.hint).toMatch(/needs_two_independent/);
  });

  it("hides workflow-only states and gates approver states", () => {
    const b = transitionButtons(["APPROVED", "DENIED"], new Set(["read", "case_work"] as const), ok);
    expect(b.map((x) => x.to)).toEqual(["DENIED"]);
    expect(b[0].enabled).toBe(false);
    expect(transitionButtons(["DENIED"], ["approve"], ok)[0].enabled).toBe(true);
  });
});
