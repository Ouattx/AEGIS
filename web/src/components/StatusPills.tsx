import { Link } from "react-router-dom";
import { fmtNumber, shortHash } from "../lib/format";
import { IconAlert, IconChain, IconEye, IconLock } from "./icons";
import { useTenantStatus } from "./status";

export function ModePill() {
  const { mode, activePolicy } = useTenantStatus();
  if (mode === "active")
    return (
      <span className="status-pill active" data-testid="mode-pill" title={`Active enforcement authorized by signed policy ${activePolicy?.policy.policy_id} (legal signoff ${activePolicy?.policy.legal_signoff_ref}). Every action still needs a SAFE simulation, deterministic authorization and a human approver.`}>
        <IconAlert /> Active enforcement
      </span>
    );
  if (mode === "shadow")
    return (
      <span className="status-pill shadow" data-testid="mode-pill" title="Shadow mode: read-only alerts and reports. The signed operator policy refuses every enforcement action by design.">
        <IconEye /> Shadow mode
      </span>
    );
  if (mode === "none")
    return (
      <span className="status-pill shadow" data-testid="mode-pill" title="No valid signed operator policy: enforcement is refused (fail closed).">
        <IconLock /> No policy · read-only
      </span>
    );
  return (
    <span className="status-pill unknown" data-testid="mode-pill">
      <IconEye /> Mode …
    </span>
  );
}

export function LedgerPill() {
  const { ledger, ledgerError } = useTenantStatus();
  if (ledgerError)
    return (
      <Link to="/ledger" className="status-pill unknown" data-testid="ledger-pill">
        <IconChain /> Ledger unavailable
      </Link>
    );
  if (!ledger)
    return (
      <span className="status-pill unknown" data-testid="ledger-pill">
        <IconChain /> Ledger …
      </span>
    );
  return ledger.ok ? (
    <Link to="/ledger" className="status-pill ok" data-testid="ledger-pill" title={`Hash chain and Ed25519 signatures verified over ${ledger.entries_checked} entries. Head ${shortHash(ledger.head_hash, 12)}`} style={{ textDecoration: "none" }}>
      <IconChain /> Ledger verified · {fmtNumber(ledger.entries_checked)}
    </Link>
  ) : (
    <Link to="/ledger" className="status-pill bad" data-testid="ledger-pill" title={ledger.reason ?? "verification failed"} style={{ textDecoration: "none" }}>
      <IconAlert /> Ledger integrity failure at #{ledger.first_bad_seq}
    </Link>
  );
}
