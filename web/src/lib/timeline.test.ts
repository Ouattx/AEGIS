import { describe, expect, it } from "vitest";
import type { HistoryEntry } from "../api/types";
import { actorKind, stateAsOf, toTimeline } from "./timeline";

const e = (seq: number, entry_type: string, payload: Record<string, unknown>): HistoryEntry => ({ seq, entry_type, payload, recorded_at: `2026-10-25T10:00:${String(seq).padStart(2, "0")}Z`, entry_hash: `h${seq}` });

describe("timeline", () => {
  const history = [
    e(3, "case_transition", { actor: "system:demo", event: "transition", from_state: "NEW", to_state: "TRIAGE", reason: "queued" }),
    e(1, "case_transition", { actor: "system", event: "case_opened", to_state: "NEW", severity: "critical", reason: "opened", finding_ids: ["f1"] }),
    e(5, "case_transition_refused", { actor: "demo-approver", from_state: "PROPOSED", to_state: "APPROVED", failed_checks: ["authorization_not_allowed"], reason: "ok" }),
    e(4, "oracle_investigation", { mode: "deterministic", recommendation: "verify", escalate: true, escalation_reasons: ["x"], report_sha256: "abc" }),
    e(6, "case_counter_hypothesis_review", { reviewer: "alice", notes: "ruled out", alternatives: ["CDN", "NAT"] }),
    e(7, "oracle_recommendation", { agent: "agent:verifier", recommendation: { recommendation: "verify", rationale: "two origins", blockers: [] } }),
    e(8, "some_new_type", { actor: "bob", reason: "why" }),
  ];

  it("orders by sequence and renders each entry type", () => {
    const items = toTimeline(history);
    expect(items.map((i) => i.seq)).toEqual([1, 3, 4, 5, 6, 7, 8]);
    expect(items[0].title).toBe("Case opened (Critical severity)");
    expect(items[0].details).toEqual(["finding f1"]);
    expect(items[1].title).toBe("NEW → TRIAGE");
    expect(items[2].title).toMatch(/Bounded investigation \(deterministic\) → Verify/);
    expect(items[2].body).toBe("Escalated: x");
    expect(items[3]).toMatchObject({ title: "Refused: PROPOSED → APPROVED", tone: "warn", details: ["authorization_not_allowed"] });
    expect(items[4]).toMatchObject({ actor: "alice", details: ["CDN", "NAT"] });
    expect(items[5]).toMatchObject({ actor: "agent:verifier", body: "two origins" });
    expect(items[6]).toMatchObject({ title: "Some new type", actor: "bob", body: "why" });
  });

  it("derives the state as of a replay", () => {
    expect(stateAsOf(history)).toBe("TRIAGE");
    expect(stateAsOf([])).toBeNull();
  });

  it("classifies actors", () => {
    expect(actorKind("agent:verifier")).toBe("agent");
    expect(actorKind("system:demo-orchestrator")).toBe("system");
    expect(actorKind("analyst:lab-simulated")).toBe("simulated");
    expect(actorKind("demo-analyst")).toBe("human");
    expect(actorKind(null)).toBe("system");
  });
});
