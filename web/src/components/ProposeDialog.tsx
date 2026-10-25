import { useMemo, useState } from "react";
import type { ActionType, PolicyItem } from "../api/types";
import { useClient } from "../auth/AuthContext";
import { ErrorBox, Modal } from "./ui";
import { humanize } from "../lib/format";

const ACTIONS: Array<{ id: ActionType; text: string; targetHint: string }> = [
  { id: "dns_sinkhole", text: "RPZ sinkhole for a malicious domain", targetHint: "domain" },
  { id: "ip_block", text: "Block traffic to a malicious IP", targetHint: "IP address" },
  { id: "device_quarantine", text: "Walled garden for a pseudonymous device/line", targetHint: "device pseudonym" },
  { id: "notify_subscriber", text: "Notify the subscriber (no blocking)", targetHint: "device pseudonym" },
];

export interface TargetSuggestions {
  domains: string[];
  ips: string[];
  entities: string[];
}

function suggestionsFor(t: ActionType, s: TargetSuggestions): string[] {
  if (t === "dns_sinkhole") return s.domains;
  if (t === "ip_block") return s.ips;
  return s.entities;
}

/**
 * Proposal form. It only records a proposal: nothing is enforced until MIRROR reports
 * SAFE, the deterministic authorization allows it, a different human approves it and an
 * approver executes it, all under a signed active-mode policy.
 */
export function ProposeDialog({
  caseId,
  suggestions,
  policies,
  onClose,
  onProposed,
}: {
  caseId: string;
  suggestions: TargetSuggestions;
  policies: PolicyItem[] | undefined;
  onClose: () => void;
  onProposed: (actionId: string) => void;
}) {
  const client = useClient();
  const policy = useMemo(() => policies?.find((p) => p.signature_valid && p.valid_now)?.policy, [policies]);
  const legalBases = useMemo(() => {
    const lb = policy?.approved_scope?.legal_bases;
    return Array.isArray(lb) ? lb.filter((x): x is string => typeof x === "string") : [];
  }, [policy]);
  const [type, setType] = useState<ActionType>(() => (suggestions.domains.length ? "dns_sinkhole" : suggestions.ips.length ? "ip_block" : "notify_subscriber"));
  const [targets, setTargets] = useState<string>(() => (suggestionsFor(type, suggestions)[0] ?? ""));
  const [legal, setLegal] = useState<string>(legalBases[0] ?? "");
  const [hours, setHours] = useState<number>(Math.min(24, policy?.max_ttl_hours ?? 24));
  const [plan, setPlan] = useState<string>("Remove the enforcement entry; the adapter restores the recorded prior state.");
  const [verified, setVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const targetList = targets
    .split(/[\n,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  const sugg = suggestionsFor(type, suggestions);

  const changeType = (t: ActionType) => {
    setType(t);
    setTargets(suggestionsFor(t, suggestions)[0] ?? "");
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const a = await client.propose({
        case_id: caseId,
        action_type: type,
        targets: targetList,
        legal_basis: legal.trim() || null,
        expires_in_hours: hours > 0 ? hours : undefined,
        rollback_plan: plan.trim() || null,
        rollback_verified: verified,
      });
      onProposed(a.action_id);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Propose response action"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy || targetList.length === 0} onClick={submit} data-testid="propose-submit">
            {busy && <span className="spinner" />} Record proposal
          </button>
        </>
      }
    >
      <div className="callout violet small">
        A proposal changes nothing on the network. Next: MIRROR impact simulation → deterministic authorization → four-eyes approval → execution by an approver.
        {policy?.mode === "shadow" && <b> The loaded policy is shadow-mode, so authorization will refuse enforcement by design.</b>}
      </div>
      <div className="field">
        <label>Action type</label>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
          {ACTIONS.map((a) => {
            const allowed = !policy || policy.allowed_actions.includes(a.id);
            return (
              <label key={a.id} className="check" style={{ border: `1px solid ${type === a.id ? "var(--accent)" : "var(--line-2)"}`, borderRadius: 6, padding: "7px 9px", background: type === a.id ? "var(--accent-dim)" : "var(--bg-2)" }}>
                <input type="radio" name="atype" checked={type === a.id} onChange={() => changeType(a.id)} />
                <span>
                  <b>{humanize(a.id)}</b>
                  <div className="small dim">{a.text}</div>
                  {!allowed && <div className="small" style={{ color: "#fbbf24" }}>not in policy allowed actions</div>}
                </span>
              </label>
            );
          })}
        </div>
      </div>
      <div className="field">
        <label htmlFor="targets">Targets ({ACTIONS.find((a) => a.id === type)?.targetHint}, one per line)</label>
        <textarea id="targets" className="input mono" rows={2} value={targets} onChange={(e) => setTargets(e.target.value)} data-testid="propose-targets" />
        {sugg.length > 0 && (
          <div className="row" style={{ gap: 4 }}>
            <span className="small dim">From case evidence:</span>
            {sugg.slice(0, 6).map((s) => (
              <button key={s} type="button" className="chip mono" style={{ cursor: "pointer" }} onClick={() => setTargets((t) => (t.split(/\n/).map((x) => x.trim()).includes(s) ? t : t.trim() ? `${t.trim()}\n${s}` : s))}>
                + {s}
              </button>
            ))}
          </div>
        )}
        {policy && <span className="help">Policy allows at most {policy.max_targets_per_action} target(s) per action.</span>}
      </div>
      <div className="grid g-2" style={{ gap: 10 }}>
        <div className="field">
          <label htmlFor="legal">Legal basis</label>
          <input id="legal" className="input" list="legal-bases" value={legal} onChange={(e) => setLegal(e.target.value)} placeholder="e.g. operator_tos_security_clause" />
          <datalist id="legal-bases">
            {legalBases.map((l) => (
              <option key={l} value={l} />
            ))}
          </datalist>
        </div>
        <div className="field">
          <label htmlFor="ttl">Expires in (hours)</label>
          <input id="ttl" type="number" min={1} max={24 * 365} className="input" value={hours} onChange={(e) => setHours(Number(e.target.value))} />
          {policy && <span className="help">Policy max TTL {policy.max_ttl_hours} h</span>}
        </div>
      </div>
      <div className="field">
        <label htmlFor="plan">Rollback plan</label>
        <textarea id="plan" className="input" rows={2} value={plan} onChange={(e) => setPlan(e.target.value)} maxLength={4000} />
      </div>
      <label className="check">
        <input type="checkbox" checked={verified} onChange={(e) => setVerified(e.target.checked)} data-testid="propose-rollback-verified" />
        <span>Rollback plan has been verified (tested on the enforcement point)</span>
      </label>
      {error !== null && <ErrorBox error={error} />}
    </Modal>
  );
}
