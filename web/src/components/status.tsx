import { createContext, useContext, type ReactNode } from "react";
import { useAsync } from "../api/hooks";
import type { LedgerVerify, PolicyItem } from "../api/types";
import { useClient } from "../auth/AuthContext";

export type EnforcementMode = "shadow" | "active" | "none" | "unknown";

export interface TenantStatus {
  ledger: LedgerVerify | undefined;
  ledgerError: unknown;
  policies: PolicyItem[] | undefined;
  mode: EnforcementMode;
  activePolicy: PolicyItem | undefined;
  reload: () => void;
}

/**
 * The tenant's enforcement mode as the console must show it. Only a policy that is
 * signature-valid, inside its validity window, in ``active`` mode and carrying a legal
 * signoff reference can authorize a live change; anything else is shadow (or none).
 */
export function enforcementMode(policies: PolicyItem[] | undefined): { mode: EnforcementMode; active?: PolicyItem } {
  if (!policies) return { mode: "unknown" };
  const usable = policies.filter((p) => p.signature_valid && p.valid_now);
  const active = usable.find((p) => p.policy.mode === "active" && !!p.policy.legal_signoff_ref);
  if (active) return { mode: "active", active };
  if (usable.length) return { mode: "shadow" };
  return { mode: "none" };
}

const Ctx = createContext<TenantStatus | null>(null);

export function TenantStatusProvider({ children }: { children: ReactNode }) {
  const client = useClient();
  const ledger = useAsync(() => client.ledgerVerify(), [client], 30_000);
  const policies = useAsync(() => client.policies().then((r) => r.items), [client], 60_000);
  const { mode, active } = enforcementMode(policies.data);
  const value: TenantStatus = {
    ledger: ledger.data,
    ledgerError: ledger.error,
    policies: policies.data,
    mode,
    activePolicy: active,
    reload: () => {
      ledger.reload();
      policies.reload();
    },
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTenantStatus(): TenantStatus {
  const v = useContext(Ctx);
  if (!v) throw new Error("useTenantStatus must be used inside <TenantStatusProvider>");
  return v;
}
