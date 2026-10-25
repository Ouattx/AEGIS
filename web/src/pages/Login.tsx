import { useState, type ReactNode } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { describeError } from "../api/client";
import { useAsync } from "../api/hooks";
import type { Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AegisMark, IconEye, IconGavel, IconKey, IconSearch, IconCog } from "../components/icons";
import { Badge, ErrorBox, Loading } from "../components/ui";

export const ROLE_INFO: Record<Exclude<Role, "integration">, { title: string; text: string; perms: string[]; icon: ReactNode }> = {
  analyst: {
    title: "Analyst",
    text: "Triage and investigate cases, review counter-hypotheses, verify or reject, propose actions and run MIRROR simulations.",
    perms: ["read", "case_work", "investigate", "propose"],
    icon: <IconSearch />,
  },
  approver: {
    title: "Approver",
    text: "Approve or deny authorized proposals (four-eyes) and execute or roll back. Cannot approve their own proposals.",
    perms: ["read", "approve", "execute"],
    icon: <IconGavel />,
  },
  viewer: {
    title: "Viewer",
    text: "Read-only access to findings, cases, evidence, graph, reports and ledger status. Ideal for executives and auditors.",
    perms: ["read"],
    icon: <IconEye />,
  },
  admin: {
    title: "Admin",
    text: "Tenant configuration (sources, signed IOC bundles, signed policies, topology) and the raw audit ledger. Not an approver.",
    perms: ["read", "read_audit", "configure"],
    icon: <IconCog />,
  },
};

const ORDER: Array<keyof typeof ROLE_INFO> = ["analyst", "approver", "viewer", "admin"];

export function LoginPage() {
  const { client, loginDemo, loginWithToken, notice } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const cfg = useAsync(() => client.authConfig(), [client]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [token, setToken] = useState("");
  const next = (loc.state as { from?: string } | null)?.from ?? "/";

  const pick = async (role: Role) => {
    setBusy(role);
    setError(null);
    try {
      await loginDemo(role);
      nav(next, { replace: true });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  const useToken = async () => {
    setBusy("token");
    setError(null);
    try {
      await loginWithToken(token.trim());
      nav(next, { replace: true });
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="login">
      <div className="login-card">
        <div className="login-hero">
          <AegisMark />
          <div>
            <h1>AEGIS OMEGA · SHIELD</h1>
            <p>Evidence-first network and device security intelligence for operators.</p>
          </div>
        </div>
        {notice && <div className="callout warn" style={{ marginBottom: 14 }}>{notice}</div>}
        {cfg.loading && !cfg.data && <Loading label="Contacting AEGIS API" />}
        {cfg.error !== undefined && <ErrorBox error={cfg.error} onRetry={cfg.reload} />}
        {cfg.data?.demo && (
          <div className="panel" style={{ padding: 18 }}>
            <div className="row" style={{ marginBottom: 14 }}>
              <h2>Choose a role</h2>
              <Badge tone="violet">Demo tenant</Badge>
              <span className="muted small" style={{ marginLeft: "auto" }}>
                Development sign-in: short-lived tokens for the seeded lab tenant. Disabled in production.
              </span>
            </div>
            <div className="role-grid">
              {ORDER.map((r) => (
                <button key={r} className="role-card" onClick={() => pick(r)} disabled={busy !== null} data-testid={`role-${r}`}>
                  <span className="ri">{busy === r ? <span className="spinner" /> : ROLE_INFO[r].icon}</span>
                  <span>
                    <b>{ROLE_INFO[r].title}</b>
                    <p>{ROLE_INFO[r].text}</p>
                    <span className="perm">
                      {ROLE_INFO[r].perms.map((p) => (
                        <span key={p} className="chip mono">
                          {p}
                        </span>
                      ))}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
        {cfg.data && !cfg.data.demo && (
          <div className="panel" style={{ padding: 18 }}>
            <div className="row" style={{ marginBottom: 10 }}>
              <IconKey width={18} height={18} />
              <h2>Sign in with your identity provider token</h2>
            </div>
            <p className="muted" style={{ marginTop: 0 }}>
              This deployment uses {cfg.data.auth_mode === "oidc" ? "OIDC" : "bearer"} authentication
              {cfg.data.oidc_issuer ? (
                <>
                  {" "}issued by <span className="mono">{cfg.data.oidc_issuer}</span>
                </>
              ) : null}
              . Paste an access token for audience <span className="mono">{cfg.data.oidc_audience ?? "aegis-api"}</span>; your tenant and roles come from its claims only.
            </p>
            <div className="field">
              <label htmlFor="tok">Access token</label>
              <textarea id="tok" className="input mono" rows={4} value={token} onChange={(e) => setToken(e.target.value)} spellCheck={false} />
            </div>
            <div className="row" style={{ marginTop: 12 }}>
              <button className="btn primary" disabled={!token.trim() || busy !== null} onClick={useToken}>
                {busy === "token" && <span className="spinner" />} Sign in
              </button>
            </div>
          </div>
        )}
        {error !== null && (
          <div className="callout bad" style={{ marginTop: 14 }} role="alert">
            Sign-in failed: {describeError(error)}
          </div>
        )}
        <div className="login-foot">
          <span>Shadow-mode pilots are read-only: no blocking, no DPI payloads, pseudonymous device identifiers only.</span>
          <span>Every state change is written to a signed, hash-chained ledger.</span>
        </div>
      </div>
    </div>
  );
}
