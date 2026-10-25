import type { ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import {
  AegisMark,
  IconBolt,
  IconChain,
  IconCog,
  IconDoc,
  IconFolder,
  IconGrid,
  IconLogout,
  IconRadar,
} from "./icons";
import { LedgerPill, ModePill } from "./StatusPills";

const NAV: Array<{ to: string; label: string; icon: ReactNode; section?: string }> = [
  { to: "/", label: "Overview", icon: <IconGrid />, section: "Monitor" },
  { to: "/findings", label: "Findings", icon: <IconRadar /> },
  { to: "/cases", label: "Cases", icon: <IconFolder /> },
  { to: "/actions", label: "Actions", icon: <IconBolt />, section: "Respond" },
  { to: "/ledger", label: "Ledger", icon: <IconChain />, section: "Assure" },
  { to: "/reports", label: "Reports", icon: <IconDoc /> },
  { to: "/settings", label: "Settings", icon: <IconCog />, section: "Configure" },
];

const TITLES: Record<string, string> = {
  "": "Overview",
  findings: "Findings",
  cases: "Cases",
  actions: "Actions",
  ledger: "Provenance ledger",
  reports: "Reports",
  settings: "Settings",
};

export function Layout() {
  const { session, logout } = useAuth();
  const loc = useLocation();
  const seg = loc.pathname.split("/").filter(Boolean);
  const title = TITLES[seg[0] ?? ""] ?? "AEGIS";
  const me = session?.me;
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <AegisMark className="brand-mark" />
          <div className="brand-text">
            <div className="brand-name">AEGIS OMEGA</div>
            <div className="brand-sub">SHIELD</div>
          </div>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <div key={n.to}>
              {n.section && <div className="nav-section">{n.section}</div>}
              <NavLink to={n.to} end={n.to === "/"} className={({ isActive }) => (isActive ? "active" : "")} data-testid={`nav-${n.label.toLowerCase()}`}>
                {n.icon}
                <span>{n.label}</span>
              </NavLink>
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div>Tenant <b className="mono" style={{ color: "var(--text-2)" }}>{me?.tenant_id}</b></div>
          <div style={{ marginTop: 4 }}>Evidence-first · AI proposes, code authorizes</div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="crumbs">
            <b>{title}</b>
            {seg[1] && <span className="mono dim">/ {seg[1].slice(0, 13)}</span>}
          </div>
          <div className="spacer" />
          <div className="status-strip">
            <ModePill />
            <LedgerPill />
          </div>
          {me && (
            <div className="user-chip" data-testid="user-chip">
              <div className="who">
                <b>{me.sub}</b>
                <span>{me.roles.join(", ")}</span>
              </div>
              <button className="btn ghost sm" onClick={() => logout()} title="Sign out" aria-label="Sign out" data-testid="logout">
                <IconLogout />
              </button>
            </div>
          )}
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
