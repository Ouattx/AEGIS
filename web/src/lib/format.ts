import { displayLabel } from "./labels";
/** Formatting helpers. All timestamps are rendered in UTC: SOC teams across regions share one clock. */

export function fmtNumber(n: number | null | undefined, digits = 0): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  return n.toLocaleString("en-US", { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

export function fmtCompact(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "—";
  const abs = Math.abs(n);
  if (abs >= 1e9) return `${(n / 1e9).toFixed(abs >= 1e10 ? 0 : 1)}B`;
  if (abs >= 1e6) return `${(n / 1e6).toFixed(abs >= 1e7 ? 0 : 1)}M`;
  if (abs >= 1e4) return `${(n / 1e3).toFixed(abs >= 1e5 ? 0 : 1)}k`;
  return fmtNumber(n);
}

export function fmtPct(x: number | null | undefined, digits = 0): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return `${(x * 100).toFixed(digits)}%`;
}

function parse(ts: string | Date | null | undefined): Date | null {
  if (!ts) return null;
  const d = ts instanceof Date ? ts : new Date(ts);
  return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n: number) => String(n).padStart(2, "0");

/** ``2026-10-24 19:00:00Z`` */
export function fmtTime(ts: string | Date | null | undefined, seconds = true): string {
  const d = parse(ts);
  if (!d) return "—";
  const base = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  return `${base}${seconds ? `:${pad(d.getUTCSeconds())}` : ""}Z`;
}

export function fmtDate(ts: string | Date | null | undefined): string {
  const d = parse(ts);
  if (!d) return "—";
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

/** ``3m ago`` / ``in 2h`` relative to ``now``. */
export function fmtRelative(ts: string | Date | null | undefined, now: number = Date.now()): string {
  const d = parse(ts);
  if (!d) return "—";
  const diff = Math.round((now - d.getTime()) / 1000);
  const future = diff < 0;
  const s = Math.abs(diff);
  let v: string;
  if (s < 45) v = `${s}s`;
  else if (s < 3600) v = `${Math.round(s / 60)}m`;
  else if (s < 86400 * 2) v = `${Math.round(s / 3600)}h`;
  else v = `${Math.round(s / 86400)}d`;
  return future ? `in ${v}` : `${v} ago`;
}

/** First and last characters of a hash/id for dense tables. */
export function shortHash(h: string | null | undefined, n = 8): string {
  if (!h) return "—";
  if (h.length <= n * 2 + 1) return h;
  return `${h.slice(0, n)}…${h.slice(-4)}`;
}

/** ``c2_beaconing`` -> ``C2 beaconing``; ``INVESTIGATING`` -> ``Investigating``. */
export function humanize(s: string | null | undefined): string {
  return displayLabel(s);
}

export function shortPseudonym(p: string | null | undefined): string {
  if (!p) return "—";
  return p.length > 14 ? `${p.slice(0, 10)}…${p.slice(-4)}` : p;
}

/** Short form of a detector version string such as ``sentinel/1.0.0+sentinel-lgbm-…+ioc:…+…``. */
export function shortDetector(v: string | null | undefined): string {
  if (!v) return "—";
  return v.split("+")[0];
}

export function clamp(x: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, x));
}

/** ISO string for a ``datetime-local`` input value interpreted as UTC. */
export function localInputToIso(v: string): string | undefined {
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})(:\d{2}(\.\d+)?)?$/.exec(v);
  if (!m) return undefined;
  const d = new Date(`${m[1]}${m[2] ?? ":00"}Z`);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** Split an ORACLE case title (``<label> on <class> device <pseudonym>``); null when it has another shape. */
export function parseCaseTitle(title: string): { label: string; deviceClass: string; entity: string } | null {
  const m = /^(\S+) on (\S+) device (\S+)$/.exec(title.trim());
  return m ? { label: m[1], deviceClass: m[2], entity: m[3] } : null;
}
