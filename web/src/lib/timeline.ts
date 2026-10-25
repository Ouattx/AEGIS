import type { HistoryEntry } from "../api/types";
import { humanize } from "./format";

export type TimelineTone = "ok" | "bad" | "warn" | "violet" | "info" | "dim";

export interface TimelineItem {
  seq: number;
  at: string;
  entryType: string;
  title: string;
  body: string | null;
  actor: string | null;
  tone: TimelineTone;
  hash: string;
  details: string[];
}

const s = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

const STATE_TONE: Record<string, TimelineTone> = {
  VERIFIED: "bad",
  REJECTED: "ok",
  INCONCLUSIVE: "dim",
  PROPOSED: "violet",
  APPROVED: "violet",
  DENIED: "dim",
  EXECUTED: "bad",
  ROLLED_BACK: "ok",
  CLOSED: "dim",
  EXPIRED: "dim",
};

/** Actor kind for display: humans, AI agents (advisory only) and the system. */
export function actorKind(actor: string | null): "human" | "agent" | "system" | "simulated" {
  if (!actor) return "system";
  if (actor.startsWith("agent:")) return "agent";
  if (actor.startsWith("system")) return "system";
  if (actor.includes("simulated")) return "simulated";
  return "human";
}

/** Turn ledger entries about a case into readable timeline items (oldest first). */
export function toTimeline(entries: HistoryEntry[]): TimelineItem[] {
  return [...entries]
    .sort((a, b) => a.seq - b.seq)
    .map((e) => {
      const p = e.payload ?? {};
      const base = { seq: e.seq, at: e.recorded_at, entryType: e.entry_type, hash: e.entry_hash };
      switch (e.entry_type) {
        case "case_transition": {
          const to = s(p.to_state) ?? "?";
          if (p.event === "case_opened") {
            return { ...base, title: `Case opened (${humanize(s(p.severity) ?? "")} severity)`, body: s(p.reason), actor: s(p.actor), tone: "info" as const, details: arr(p.finding_ids).map((f) => `finding ${f}`) };
          }
          return { ...base, title: `${s(p.from_state) ?? "?"} → ${to}`, body: s(p.reason), actor: s(p.actor), tone: STATE_TONE[to] ?? "info", details: [] };
        }
        case "case_transition_refused":
          return { ...base, title: `Refused: ${s(p.from_state) ?? "?"} → ${s(p.to_state) ?? "?"}`, body: s(p.reason), actor: s(p.actor), tone: "warn" as const, details: arr(p.failed_checks) };
        case "case_counter_hypothesis_review":
          return { ...base, title: "Counter-hypothesis review recorded", body: s(p.notes), actor: s(p.reviewer) ?? s(p.actor), tone: "ok" as const, details: arr(p.alternatives) };
        case "case_evidence_attached":
          return { ...base, title: `Evidence attached (${arr(p.evidence_ids).length})`, body: null, actor: s(p.actor), tone: "info" as const, details: arr(p.evidence_ids) };
        case "oracle_investigation":
          return {
            ...base,
            title: `Bounded investigation (${s(p.mode) ?? "deterministic"}) → ${humanize(s(p.recommendation) ?? "")}`,
            body: p.escalate ? `Escalated: ${arr(p.escalation_reasons).join(", ") || "yes"}` : null,
            actor: "agent:investigator",
            tone: "violet" as const,
            details: s(p.report_sha256) ? [`report sha256 ${s(p.report_sha256)}`] : [],
          };
        case "oracle_recommendation": {
          const r = (p.recommendation ?? {}) as Record<string, unknown>;
          return { ...base, title: `Verifier recommends: ${humanize(s(r.recommendation) ?? "")}`, body: s(r.rationale), actor: s(p.agent), tone: "violet" as const, details: arr(r.blockers) };
        }
        case "oracle_advisory": {
          const a = (p.advisory ?? {}) as Record<string, unknown>;
          return { ...base, title: "Policy advisory", body: arr(a.notes).join(" ") || null, actor: s(p.agent), tone: "violet" as const, details: [] };
        }
        case "evidence":
          return { ...base, title: `Evidence recorded: ${humanize(s(p.kind) ?? "item")}`, body: s(p.origin_source), actor: null, tone: "info" as const, details: [s(p.source_independence_group) ? `group ${s(p.source_independence_group)}` : "", s(p.sha256) ? `sha256 ${s(p.sha256)}` : ""].filter(Boolean) };
        case "finding":
          return { ...base, title: `Finding: ${humanize(s(p.label) ?? "")} (${s(p.verdict) ?? "?"})`, body: s(p.detector_version), actor: "system:sentinel", tone: p.verdict === "malicious" ? ("bad" as const) : ("warn" as const), details: [] };
        case "investigation_requested":
          return { ...base, title: "Investigation re-run requested", body: null, actor: s(p.actor), tone: "info" as const, details: [] };
        case "snapshot":
        case "constellation_snapshot":
          return { ...base, title: e.entry_type === "snapshot" ? "Ledger snapshot anchored" : "Graph snapshot anchored", body: s(p.reason), actor: null, tone: "dim" as const, details: s(p.snapshot_hash) ? [`snapshot ${s(p.snapshot_hash)}`] : [] };
        default:
          return { ...base, title: humanize(e.entry_type), body: s(p.reason) ?? s(p.note) ?? null, actor: s(p.actor) ?? s(p.agent), tone: "info" as const, details: [] };
      }
    });
}

/** Case state as of a replay: the last recorded transition's target state. */
export function stateAsOf(entries: HistoryEntry[]): string | null {
  let state: string | null = null;
  for (const e of [...entries].sort((a, b) => a.seq - b.seq)) {
    if (e.entry_type === "case_transition" && typeof e.payload?.to_state === "string") state = e.payload.to_state as string;
  }
  return state;
}
