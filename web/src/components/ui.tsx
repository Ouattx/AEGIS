import { useEffect, useState, type ReactNode } from "react";
import { describeError, ApiError } from "../api/client";
import type { CaseState, Severity, Verdict } from "../api/types";
import { labelCheck } from "../lib/checks";
import { fmtTime, humanize, shortHash } from "../lib/format";
import { IconAlert, IconCheck, IconRefresh, IconX } from "./icons";

export function Panel({
  title,
  right,
  children,
  flush,
  className,
  testId,
}: {
  title?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
  flush?: boolean;
  className?: string;
  testId?: string;
}) {
  return (
    <section className={`panel ${className ?? ""}`} data-testid={testId}>
      {(title || right) && (
        <div className="panel-head">
          {typeof title === "string" ? <h3>{title}</h3> : title}
          {right && <div className="right">{right}</div>}
        </div>
      )}
      <div className={`panel-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}

export type Tone = "ok" | "warn" | "bad" | "info" | "violet" | "neutral";

export function Badge({ tone = "neutral", children, dot, title, lg }: { tone?: Tone; children: ReactNode; dot?: boolean; title?: string; lg?: boolean }) {
  return (
    <span className={`badge ${tone} ${lg ? "lg" : ""}`} title={title}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

const STATE_TONE: Record<CaseState, Tone> = {
  NEW: "info",
  TRIAGE: "info",
  INVESTIGATING: "warn",
  VERIFIED: "bad",
  REJECTED: "neutral",
  INCONCLUSIVE: "neutral",
  PROPOSED: "violet",
  CLOSED: "neutral",
  APPROVED: "violet",
  DENIED: "neutral",
  EXECUTED: "bad",
  ROLLED_BACK: "ok",
  EXPIRED: "neutral",
};

export function StateBadge({ state }: { state: CaseState }) {
  return (
    <Badge tone={STATE_TONE[state] ?? "neutral"} dot>
      {state.replace("_", " ")}
    </Badge>
  );
}

const SEV_TONE: Record<Severity, Tone> = { critical: "bad", high: "warn", medium: "info", low: "neutral" };

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEV_TONE[severity] ?? "neutral"}>{severity}</Badge>;
}

const VERDICT_TONE: Record<Verdict, Tone> = { malicious: "bad", suspicious: "warn", benign: "ok", abstain: "neutral" };

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <Badge tone={VERDICT_TONE[verdict] ?? "neutral"} title={verdict === "abstain" ? "Detector abstained: evidence insufficient, routed for review" : undefined}>
      {verdict}
    </Badge>
  );
}

/** A hash or id shown short; click copies the full value. */
export function Hash({ value, n = 8, label }: { value: string | null | undefined; n?: number; label?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="dim">—</span>;
  const copy = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable (insecure context): the title still shows the full value */
    }
  };
  return (
    <span className={`hash ${copied ? "copied" : ""}`} title={`${label ? `${label}: ` : ""}${value} (click to copy)`} onClick={copy}>
      {copied ? "copied" : shortHash(value, n)}
    </span>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading-block" role="status">
      <span className="spinner" /> {label}…
    </div>
  );
}

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const forbidden = error instanceof ApiError && error.status === 403;
  return (
    <div className={`callout ${forbidden ? "warn" : "bad"}`} role="alert">
      <div className="row">
        <IconAlert width={16} height={16} />
        <b>{forbidden ? "Not permitted for your role" : "Request failed"}</b>
        {onRetry && (
          <button className="btn sm ghost" onClick={onRetry} style={{ marginLeft: "auto" }}>
            <IconRefresh /> Retry
          </button>
        )}
      </div>
      <div style={{ marginTop: 4 }}>{describeError(error)}</div>
      {error instanceof ApiError && error.failedChecks.length > 0 && (
        <ul>
          {error.failedChecks.map((c) => (
            <li key={c}>
              {labelCheck(c)} <code className="dim">{c}</code>
            </li>
          ))}
        </ul>
      )}
      {error instanceof ApiError && error.requestId && <div className="small dim" style={{ marginTop: 4 }}>request id {error.requestId}</div>}
    </div>
  );
}

export function Empty({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return (
    <div className="empty">
      {icon}
      <div>{children}</div>
    </div>
  );
}

export function Kpi({
  label,
  value,
  unit,
  foot,
  accent,
  spark,
  testId,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  foot?: ReactNode;
  accent?: string;
  spark?: ReactNode;
  testId?: string;
}) {
  return (
    <div className="panel kpi" style={{ ["--kpi-accent" as string]: accent }} data-testid={testId}>
      <div className="k-label">{label}</div>
      <div className="k-value">
        {value}
        {unit && <small>{unit}</small>}
      </div>
      {foot && <div className="k-foot">{foot}</div>}
      {spark && <div className="k-spark">{spark}</div>}
    </div>
  );
}

export function ScoreBar({ value, color }: { value: number | null | undefined; color?: string }) {
  if (value === null || value === undefined) return <span className="dim mono">n/a</span>;
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const c = color ?? (value >= 0.85 ? "var(--bad)" : value >= 0.5 ? "var(--warn)" : "var(--accent)");
  return (
    <span className="score">
      <span className="bar" style={{ width: 70 }}>
        <i style={{ width: `${pct}%`, background: c }} />
      </span>
      {value.toFixed(2)}
    </span>
  );
}

export function Pager({ total, limit, offset, onChange }: { total: number; limit: number; offset: number; onChange: (offset: number) => void }) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="pager">
      <span>
        {from}–{to} of {total}
      </span>
      <span className="spacer" />
      <button className="btn sm" disabled={offset <= 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        Previous
      </button>
      <button className="btn sm" disabled={to >= total} onClick={() => onChange(offset + limit)}>
        Next
      </button>
    </div>
  );
}

export function Modal({ title, children, footer, onClose, wide }: { title: ReactNode; children: ReactNode; footer?: ReactNode; onClose: () => void; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true">
        <div className="modal-head">
          {typeof title === "string" ? <h2>{title}</h2> : title}
          <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close">
            <IconX />
          </button>
        </div>
        {wide ? children : <div className="modal-body">{children}</div>}
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/**
 * Collects the mandatory reason for a state change or decision, runs ``onSubmit`` and
 * keeps the dialog open with the server's refusal (failed checks) when it is refused.
 */
export function ReasonDialog({
  title,
  description,
  confirmLabel,
  tone = "primary",
  defaultReason = "",
  onSubmit,
  onClose,
  requireReason = true,
}: {
  title: string;
  description?: ReactNode;
  confirmLabel: string;
  tone?: "primary" | "danger" | "success";
  defaultReason?: string;
  onSubmit: (reason: string) => Promise<void>;
  onClose: () => void;
  requireReason?: boolean;
}) {
  const [reason, setReason] = useState(defaultReason);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(reason.trim());
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button className={`btn ${tone}`} disabled={busy || (requireReason && !reason.trim())} onClick={submit} data-testid="reason-confirm">
            {busy && <span className="spinner" />} {confirmLabel}
          </button>
        </>
      }
    >
      {description && <div className="muted">{description}</div>}
      <div className="field">
        <label htmlFor="reason">Reason {requireReason ? "(recorded in the signed ledger)" : "(optional)"}</label>
        <textarea id="reason" className="input" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} autoFocus data-testid="reason-input" />
      </div>
      {error !== null && <ErrorBox error={error} />}
    </Modal>
  );
}

export function Drawer({ title, children, onClose }: { title: ReactNode; children: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        <div className="drawer-head">
          {title}
          <button className="btn ghost sm" style={{ marginLeft: "auto" }} onClick={onClose} aria-label="Close">
            <IconX />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
      </aside>
    </>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: Array<{ id: T; label: string; count?: number }>; value: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={`tab ${value === t.id ? "active" : ""}`} onClick={() => onChange(t.id)} data-testid={`tab-${t.id}`}>
          {t.label}
          {t.count !== undefined && <span className="n">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function PassIcon({ state }: { state: "pass" | "fail" | "pending" }) {
  return <span className={`ic ${state}`}>{state === "pass" ? <IconCheck /> : state === "fail" ? <IconX /> : null}</span>;
}

export function Time({ ts, seconds }: { ts: string | null | undefined; seconds?: boolean }) {
  return (
    <span className="mono nowrap" title={ts ?? undefined}>
      {fmtTime(ts, seconds)}
    </span>
  );
}

export function Label({ value }: { value: string }) {
  return <span>{humanize(value)}</span>;
}
