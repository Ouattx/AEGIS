import { useMemo, useRef, useState } from "react";
import type { VEdge, VGraph, VNode } from "../lib/graph";

export const NODE_COLORS: Record<string, string> = {
  domain: "#38bdf8",
  ip: "#a78bfa",
  device: "#f59e0b",
  malware_family: "#ef4444",
  asn: "#2dd4bf",
  prefix: "#2dd4bf",
  certificate: "#f472b6",
  campaign: "#fb7185",
};

export function nodeColor(type: string): string {
  return NODE_COLORS[type] ?? "#94a3b8";
}

function trim(s: string, n = 26): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/**
 * SVG neighbourhood view with wheel zoom and drag pan. Candidate (inferred) links are
 * dashed and labelled investigative-only; they never qualify as evidence.
 */
export function GraphCanvas({ graph, width, height, onSelect, selected }: { graph: VGraph; width: number; height: number; onSelect?: (n: VNode) => void; selected?: string | null }) {
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hover, setHover] = useState<{ node?: VNode; edge?: VEdge; x: number; y: number } | null>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const pos = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);

  const onWheel = (e: React.WheelEvent) => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = ((e.clientX - rect.left) / rect.width) * width;
    const my = ((e.clientY - rect.top) / rect.height) * height;
    const k = Math.min(4, Math.max(0.4, view.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12)));
    setView({ k, x: mx - ((mx - view.x) * k) / view.k, y: my - ((my - view.y) * k) / view.k });
  };

  return (
    <div className="graph-wrap" style={{ height }}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        height={height}
        onWheel={onWheel}
        onMouseDown={(e) => (drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y })}
        onMouseMove={(e) => {
          if (!drag.current) return;
          const rect = svgRef.current?.getBoundingClientRect();
          const scale = rect ? width / rect.width : 1;
          setView((v) => ({ ...v, x: drag.current!.vx + (e.clientX - drag.current!.x) * scale, y: drag.current!.vy + (e.clientY - drag.current!.y) * scale }));
        }}
        onMouseUp={() => (drag.current = null)}
        onMouseLeave={() => {
          drag.current = null;
          setHover(null);
        }}
        style={{ cursor: drag.current ? "grabbing" : "grab" }}
        role="img"
        aria-label="infrastructure graph neighbourhood"
        data-testid="graph-canvas"
      >
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="18" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#3a4d72" />
          </marker>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {graph.edges.map((e) => {
            const a = pos.get(e.source);
            const b = pos.get(e.target);
            if (!a || !b) return null;
            const stroke = e.candidate ? "#64748b" : e.enforcementEligible ? "#3b82f6" : "#334766";
            return (
              <g key={e.id} onMouseEnter={(ev) => setHover({ edge: e, x: ev.nativeEvent.offsetX, y: ev.nativeEvent.offsetY })} onMouseLeave={() => setHover(null)}>
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="transparent" strokeWidth={10} />
                <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={stroke} strokeWidth={e.candidate ? 1.2 : 1.6} strokeDasharray={e.candidate ? "4 4" : undefined} markerEnd={e.candidate ? undefined : "url(#arrow)"} opacity={0.9} />
              </g>
            );
          })}
          {graph.nodes.map((n) => {
            const c = nodeColor(n.type);
            const r = n.seed ? 11 : 7;
            const isSel = selected === n.id;
            return (
              <g
                key={n.id}
                transform={`translate(${n.x},${n.y})`}
                onMouseEnter={(ev) => setHover({ node: n, x: ev.nativeEvent.offsetX, y: ev.nativeEvent.offsetY })}
                onMouseLeave={() => setHover(null)}
                onClick={(ev) => {
                  ev.stopPropagation();
                  onSelect?.(n);
                }}
                style={{ cursor: onSelect ? "pointer" : "default" }}
              >
                {n.seed && <circle r={r + 7} fill={c} opacity={0.12} filter="url(#glow)" />}
                <circle r={r} fill="#0b1220" stroke={c} strokeWidth={isSel ? 3.5 : n.seed ? 2.5 : 1.8} />
                <circle r={r * 0.45} fill={c} opacity={n.type === "malware_family" ? 1 : 0.8} />
                {n.shared && <circle r={r + 3} fill="none" stroke="#f59e0b" strokeDasharray="2 2" strokeWidth={1.2} />}
                <text y={r + 12} textAnchor="middle" style={{ fill: n.seed ? "#dbe4f3" : undefined, fontWeight: n.seed ? 600 : 400 }}>
                  {trim(n.label)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      {hover && (
        <div className="graph-tip" style={{ left: Math.min(hover.x + 14, width - 330), top: hover.y + 14 }}>
          {hover.node && (
            <>
              <div className="row" style={{ gap: 6 }}>
                <i style={{ width: 8, height: 8, borderRadius: 4, background: nodeColor(hover.node.type), display: "inline-block" }} />
                <b className="mono">{hover.node.label}</b>
              </div>
              <div className="dim">{hover.node.type.replace("_", " ")}{hover.node.seed ? " · cited by case evidence" : ""}{hover.node.shared ? " · shared hosting" : ""}</div>
              {onSelect && <div className="dim small" style={{ marginTop: 4 }}>click to expand its neighbourhood</div>}
            </>
          )}
          {hover.edge && (
            <>
              <b>{hover.edge.type.replace(/_/g, " ")}</b>
              <div className="dim mono small">
                {trim(hover.edge.source, 32)} → {trim(hover.edge.target, 32)}
              </div>
              {hover.edge.candidate ? (
                <div style={{ color: "#fbbf24" }}>Candidate link{hover.edge.score !== undefined ? ` (score ${hover.edge.score.toFixed(2)})` : ""} — investigative only, never evidence</div>
              ) : (
                <div>
                  grade <b>{hover.edge.grade ?? "?"}</b> · {hover.edge.sources} independent source(s) · {hover.edge.enforcementEligible ? <span style={{ color: "#86efac" }}>enforcement-eligible</span> : <span className="dim">not enforcement-eligible</span>}
                </div>
              )}
            </>
          )}
        </div>
      )}
      <div style={{ position: "absolute", left: 10, top: 8, display: "flex", gap: 6 }}>
        <button className="btn sm" onClick={() => setView({ x: 0, y: 0, k: 1 })}>
          Reset view
        </button>
      </div>
    </div>
  );
}
