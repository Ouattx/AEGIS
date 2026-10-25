import type { CaseState, Permission } from "../api/types";

/** States an analyst sets through ``/cases/{id}/transition`` (``case_work``); mirrors routes.ANALYST_STATES. */
export const ANALYST_STATES: ReadonlySet<CaseState> = new Set<CaseState>([
  "TRIAGE",
  "INVESTIGATING",
  "VERIFIED",
  "REJECTED",
  "INCONCLUSIVE",
  "CLOSED",
]);

/** States reserved to approvers on the transition route; mirrors routes.APPROVER_STATES. */
export const APPROVER_STATES: ReadonlySet<CaseState> = new Set<CaseState>(["DENIED", "EXPIRED"]);

/** States reached only through the MIRROR actions workflow. */
export const WORKFLOW_STATES: ReadonlySet<CaseState> = new Set<CaseState>([
  "PROPOSED",
  "APPROVED",
  "EXECUTED",
  "ROLLED_BACK",
]);

export const TERMINAL_STATES: ReadonlySet<CaseState> = new Set<CaseState>([
  "CLOSED",
  "DENIED",
  "ROLLED_BACK",
  "EXPIRED",
]);

export const OPEN_STATES: ReadonlySet<CaseState> = new Set<CaseState>(["NEW", "TRIAGE", "INVESTIGATING"]);

export interface TransitionButton {
  to: CaseState;
  enabled: boolean;
  /** why the button is disabled, or the hint shown on hover */
  hint: string;
  tone: "primary" | "danger" | "neutral" | "success";
}

const TONE: Partial<Record<CaseState, TransitionButton["tone"]>> = {
  VERIFIED: "success",
  REJECTED: "danger",
  DENIED: "danger",
  INCONCLUSIVE: "neutral",
  CLOSED: "neutral",
  TRIAGE: "primary",
  INVESTIGATING: "primary",
  EXPIRED: "neutral",
};

/**
 * Buttons for the transitions the server allows from the current state, gated by the
 * caller's permissions exactly as the API gates them (the server re-checks every call).
 */
export function transitionButtons(
  allowed: CaseState[],
  perms: ReadonlySet<Permission> | Permission[],
  opts: { counterHypothesisReviewed: boolean; verificationBlockers: string[] },
): TransitionButton[] {
  const p = perms instanceof Set ? perms : new Set(perms);
  const out: TransitionButton[] = [];
  for (const to of allowed) {
    if (WORKFLOW_STATES.has(to)) continue;
    let enabled = true;
    let hint = `Move case to ${to}`;
    if (ANALYST_STATES.has(to) && !p.has("case_work")) {
      enabled = false;
      hint = "Requires the analyst role (case_work)";
    } else if (APPROVER_STATES.has(to) && !p.has("approve")) {
      enabled = false;
      hint = "Requires the approver role (approve)";
    } else if (to === "VERIFIED") {
      if (opts.verificationBlockers.length) {
        enabled = false;
        hint = `Blocked: ${opts.verificationBlockers.join(", ")}`;
      } else if (!opts.counterHypothesisReviewed) {
        enabled = false;
        hint = "Record the counter-hypothesis review first";
      }
    }
    out.push({ to, enabled, hint, tone: TONE[to] ?? "neutral" });
  }
  return out;
}

/** Ordered lifecycle used for the case progress rail. */
export const LIFECYCLE: CaseState[] = ["NEW", "TRIAGE", "INVESTIGATING", "VERIFIED", "PROPOSED", "APPROVED", "EXECUTED"];
