import { useMemo, useState } from "react";
import { fmtNumber } from "../lib/format";

/** Lightweight SVG charts (no charting library: small bundle, CSP-safe, crisp at any DPI). */

export const PALETTE = ["#38bdf8", "#a78bfa", "#f472b6", "#f59e0b", "#2dd4bf", "#ef4444", "#22c55e", "#818cf8", "#fb923c"];

export function Sparkline({ values, width = 90, height = 28, color = "#38bdf8" }: { values: number[]; width?: number; height?: number; color?: string }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 1);
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)] as const);
  const d = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  const id = `sp-${color.replace("#", "")}`;
  return (
    <svg width={width} height={height} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.35" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${d}L${width},${height}L0,${height}Z`} fill={`url(#${id})`} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}

export interface Series {
  name: string;
  color: string;
  values: number[];
}

/** Stacked bar time series with hover readout. */
export function StackedBars({ labels, series, height = 200 }: { labels: string[]; series: Series[]; height?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const width = 640;
  const padL = 34;
  const padB = 22;
  const padT = 8;
  const totals = labels.map((_, i) => series.reduce((s, x) => s + (x.values[i] ?? 0), 0));
  const max = Math.max(1, ...totals);
  const niceMax = niceCeil(max);
  const innerH = height - padB - padT;
  const bw = (width - padL - 8) / Math.max(1, labels.length);
  const ticks = axisTicks(niceMax);
  const every = Math.max(1, Math.ceil(labels.length / 8));
  return (
    <div style={{ position: "relative" }}>
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none" role="img" aria-label="time series">
        {ticks.map((t) => {
          const y = padT + innerH - (t / niceMax) * innerH;
          return (
            <g key={t}>
              <line className="grid-line" x1={padL} x2={width} y1={y} y2={y} />
              <text x={padL - 6} y={y + 3} textAnchor="end">
                {t}
              </text>
            </g>
          );
        })}
        {labels.map((l, i) => {
          let acc = 0;
          const x = padL + i * bw + bw * 0.15;
          const w = Math.max(1, bw * 0.7);
          return (
            <g key={l} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={padL + i * bw} y={padT} width={bw} height={innerH} fill={hover === i ? "rgba(56,189,248,0.06)" : "transparent"} />
              {series.map((s) => {
                const v = s.values[i] ?? 0;
                const h = (v / niceMax) * innerH;
                const y = padT + innerH - acc - h;
                acc += h;
                return v > 0 ? <rect key={s.name} x={x} y={y} width={w} height={h} fill={s.color} rx={1.5} opacity={0.92} /> : null;
              })}
              {i % every === 0 && (
                <text x={padL + i * bw + bw / 2} y={height - 6} textAnchor="middle">
                  {l}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {hover !== null && (
        <div className="graph-tip" style={{ left: `${Math.min(80, ((padL + hover * bw) / width) * 100)}%`, top: 4 }}>
          <b>{labels[hover]}</b>
          {series.map((s) => (
            <div key={s.name} className="row" style={{ gap: 6 }}>
              <i style={{ width: 8, height: 8, background: s.color, display: "inline-block", borderRadius: 2 }} />
              {s.name}: <b>{s.values[hover] ?? 0}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Integer ticks for a count axis: quarters when they are whole numbers, else halves, else the ends. */
export function axisTicks(max: number): number[] {
  for (const parts of [4, 2]) {
    if (max % parts === 0) return Array.from({ length: parts + 1 }, (_, i) => (max / parts) * i);
  }
  return [0, max];
}

export function niceCeil(x: number): number {
  if (x <= 4) return 4;
  if (x <= 40) return Math.ceil(x / 4) * 4;
  const p = Math.pow(10, Math.floor(Math.log10(x)));
  const m = x / p;
  const n = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
  return n * p;
}

/** Horizontal bars, sorted, with value labels. */
export function HBars({ data, color = "#38bdf8", format = (v: number) => fmtNumber(v), onClick }: { data: Array<{ label: string; value: number; color?: string; hint?: string }>; color?: string; format?: (v: number) => string; onClick?: (label: string) => void }) {
  const max = Math.max(1, ...data.map((d) => d.value));
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
      {data.map((d) => (
        <div key={d.label} style={{ display: "grid", gridTemplateColumns: "120px 1fr 48px", gap: 10, alignItems: "center", cursor: onClick ? "pointer" : undefined }} onClick={() => onClick?.(d.label)} title={d.hint}>
          <span className="ellipsis muted" style={{ fontSize: 12 }}>
            {d.label}
          </span>
          <span className="bar" style={{ height: 8 }}>
            <i style={{ width: `${(d.value / max) * 100}%`, background: d.color ?? color }} />
          </span>
          <span className="mono right-align" style={{ fontSize: 12 }}>
            {format(d.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Donut with centre label. */
export function Donut({ data, size = 132, thickness = 16, center }: { data: Array<{ label: string; value: number; color: string }>; size?: number; thickness?: number; center?: React.ReactNode }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const arcs = useMemo(() => {
    let acc = 0;
    return data
      .filter((d) => d.value > 0)
      .map((d) => {
        const len = total ? (d.value / total) * c : 0;
        const a = { ...d, dash: `${Math.max(0, len - 2)} ${c - Math.max(0, len - 2)}`, offset: -acc };
        acc += len;
        return a;
      });
  }, [data, total, c]);
  return (
    <div style={{ position: "relative", width: size, height: size, flex: "none" }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label="distribution">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#17223a" strokeWidth={thickness} />
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {arcs.map((a) => (
            <circle key={a.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={a.color} strokeWidth={thickness} strokeDasharray={a.dash} strokeDashoffset={a.offset}>
              <title>
                {a.label}: {a.value}
              </title>
            </circle>
          ))}
        </g>
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>{center}</div>
    </div>
  );
}

export function Legend({ items }: { items: Array<{ label: string; color: string; value?: number | string }> }) {
  return (
    <div className="legend">
      {items.map((i) => (
        <span key={i.label}>
          <i style={{ background: i.color }} />
          {i.label}
          {i.value !== undefined && <b style={{ color: "var(--text)" }}>{i.value}</b>}
        </span>
      ))}
    </div>
  );
}
