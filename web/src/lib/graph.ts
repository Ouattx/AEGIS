import type { GraphView } from "../api/types";

export interface VNode {
  id: string;
  type: string;
  label: string;
  /** a seed node (an indicator or destination cited by the case evidence) */
  seed: boolean;
  shared: boolean;
  x: number;
  y: number;
}

export interface VEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  grade: string | null;
  candidate: boolean;
  investigativeOnly: boolean;
  enforcementEligible: boolean;
  sources: number;
  score?: number;
}

export interface VGraph {
  nodes: VNode[];
  edges: VEdge[];
}

function nodeLabel(id: string): string {
  const i = id.indexOf(":");
  return i >= 0 ? id.slice(i + 1) : id;
}

function nodeType(id: string): string {
  const i = id.indexOf(":");
  return i >= 0 ? id.slice(0, i) : "unknown";
}

/** Merge several ``/graph/{node}`` neighbourhoods into one de-duplicated graph. */
export function mergeViews(views: GraphView[], maxNodes = 80): VGraph {
  const nodes = new Map<string, VNode>();
  const edges = new Map<string, VEdge>();
  const add = (id: string, type?: string, seed = false, shared = false) => {
    const cur = nodes.get(id);
    if (cur) {
      cur.seed = cur.seed || seed;
      cur.shared = cur.shared || shared;
      return true;
    }
    if (nodes.size >= maxNodes) return false;
    nodes.set(id, { id, type: type ?? nodeType(id), label: nodeLabel(id), seed, shared, x: 0, y: 0 });
    return true;
  };
  for (const v of views) add(v.node.node_id, v.node.node_type, true, v.shared_hosting);
  for (const v of views) {
    for (const n of v.neighbors) {
      if (!add(n.node_id, n.node_type)) continue;
      const e = n.edge;
      edges.set(e.edge_id, {
        id: e.edge_id,
        source: e.src,
        target: e.dst,
        type: e.edge_type,
        grade: e.evidence_grade ?? null,
        candidate: e.candidate,
        investigativeOnly: e.investigative_only,
        enforcementEligible: e.enforcement_eligible,
        sources: e.independent_source_count,
      });
    }
    for (const c of v.candidate_links) {
      if (!add(c.src) || !add(c.dst)) continue;
      const id = `cand:${[c.src, c.dst].sort().join("|")}`;
      if (!edges.has(id)) {
        edges.set(id, {
          id,
          source: c.src,
          target: c.dst,
          type: `candidate (${c.method})`,
          grade: null,
          candidate: true,
          investigativeOnly: true,
          enforcementEligible: false,
          sources: 0,
          score: c.score,
        });
      }
    }
  }
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()].filter((e) => nodes.has(e.source) && nodes.has(e.target)),
  };
}

/** Small deterministic PRNG so the same neighbourhood always renders the same way. */
function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function hashString(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const GRAVITY = 0.06;
const REPULSION_RANGE = 2.5;

/**
 * Fruchterman–Reingold style force layout inside a ``width`` x ``height`` box.
 * Deterministic for a given graph. Mutates and returns ``g``.
 */
export function layout(g: VGraph, width: number, height: number, iterations = 300): VGraph {
  const n = g.nodes.length;
  if (n === 0) return g;
  const rand = mulberry32(hashString(g.nodes.map((x) => x.id).sort().join(",")));
  const cx = width / 2;
  const cy = height / 2;
  const pad = 40;
  if (n === 1) {
    g.nodes[0].x = cx;
    g.nodes[0].y = cy;
    return g;
  }
  g.nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n + rand() * 0.3;
    const r = (node.seed ? 0.2 : 0.42) * Math.min(width, height);
    node.x = cx + r * Math.cos(angle);
    node.y = cy + r * Math.sin(angle);
  });
  const idx = new Map(g.nodes.map((x, i) => [x.id, i]));
  const area = (width - 2 * pad) * (height - 2 * pad);
  const k = Math.sqrt(area / n) * 0.75;
  let temp = Math.min(width, height) / 8;
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);
  for (let it = 0; it < iterations; it++) {
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ddx = g.nodes[i].x - g.nodes[j].x;
        let ddy = g.nodes[i].y - g.nodes[j].y;
        let d2 = ddx * ddx + ddy * ddy;
        if (d2 < 0.01) {
          ddx = rand() - 0.5;
          ddy = rand() - 0.5;
          d2 = ddx * ddx + ddy * ddy;
        }
        const d = Math.sqrt(d2);
        if (d > REPULSION_RANGE * k) continue; // bounded repulsion lets gravity gather components
        const f = (k * k) / d;
        dx[i] += (ddx / d) * f;
        dy[i] += (ddy / d) * f;
        dx[j] -= (ddx / d) * f;
        dy[j] -= (ddy / d) * f;
      }
    }
    for (const e of g.edges) {
      const a = idx.get(e.source);
      const b = idx.get(e.target);
      if (a === undefined || b === undefined || a === b) continue;
      const ddx = g.nodes[a].x - g.nodes[b].x;
      const ddy = g.nodes[a].y - g.nodes[b].y;
      const d = Math.max(0.1, Math.sqrt(ddx * ddx + ddy * ddy));
      const f = ((d * d) / k) * (e.candidate ? 0.5 : 1);
      dx[a] -= (ddx / d) * f;
      dy[a] -= (ddy / d) * f;
      dx[b] += (ddx / d) * f;
      dy[b] += (ddy / d) * f;
    }
    for (let i = 0; i < n; i++) {
      // gravity keeps disconnected components close to the centre
      dx[i] += (cx - g.nodes[i].x) * GRAVITY;
      dy[i] += (cy - g.nodes[i].y) * GRAVITY;
      const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]);
      if (d > 0) {
        const step = Math.min(d, temp);
        g.nodes[i].x += (dx[i] / d) * step;
        g.nodes[i].y += (dy[i] / d) * step;
      }
      g.nodes[i].x = Math.min(width - pad, Math.max(pad, g.nodes[i].x));
      g.nodes[i].y = Math.min(height - pad, Math.max(pad, g.nodes[i].y));
    }
    temp = Math.max(0.5, temp * 0.985);
  }
  return g;
}

/** Graph seeds for a case: indicators matched, resolved IPs and top destinations in its evidence. */
export function seedsFromEvidence(payloads: Array<{ kind: string; payload: Record<string, unknown> }>, max = 6): string[] {
  const out: string[] = [];
  const push = (type: string, v: unknown) => {
    if (typeof v !== "string" || !v) return;
    const id = `${type}:${v.toLowerCase()}`;
    if (!out.includes(id)) out.push(id);
  };
  for (const e of payloads) {
    if (e.kind !== "ioc_match") continue;
    const t = e.payload.indicator_type;
    push(t === "ip" ? "ip" : "domain", e.payload.indicator_value);
    const ips = e.payload.resolved_ips;
    if (Array.isArray(ips)) ips.forEach((ip) => push("ip", ip));
  }
  for (const e of payloads) {
    const dests = e.payload.top_destinations;
    if (Array.isArray(dests)) {
      for (const d of dests.slice(0, 3)) {
        if (d && typeof d === "object") push("ip", (d as { dst_ip?: unknown }).dst_ip);
      }
    }
  }
  return out.slice(0, max);
}
