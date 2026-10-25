import { useEffect, useMemo, useState } from "react";
import type { GraphView } from "../../api/types";
import { useClient } from "../../auth/AuthContext";
import { GraphCanvas, NODE_COLORS } from "../../components/GraphCanvas";
import { Badge, Empty, Loading, Panel } from "../../components/ui";
import { layout, mergeViews, type VNode } from "../../lib/graph";

const W = 900;
const H = 520;

/** CONSTELLATION neighbourhood of the indicators and destinations cited by the case evidence. */
export function GraphTab({ seeds }: { seeds: string[] }) {
  const client = useClient();
  const [views, setViews] = useState<GraphView[] | null>(null);
  const [missing, setMissing] = useState<string[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [expanding, setExpanding] = useState(false);

  useEffect(() => {
    let live = true;
    setViews(null);
    Promise.allSettled(seeds.map((s) => client.graph(s))).then((rs) => {
      if (!live) return;
      setViews(rs.flatMap((r) => (r.status === "fulfilled" ? [r.value] : [])));
      setMissing(seeds.filter((_, i) => rs[i].status === "rejected"));
    });
    return () => {
      live = false;
    };
  }, [client, seeds]);

  const graph = useMemo(() => (views && views.length ? layout(mergeViews(views), W, H) : null), [views]);
  const selView = views?.find((v) => v.node.node_id === selected);

  const expand = async (n: VNode) => {
    setSelected(n.id);
    if (views?.some((v) => v.node.node_id === n.id)) return;
    setExpanding(true);
    try {
      const v = await client.graph(n.id);
      setViews((vs) => [...(vs ?? []), v]);
    } catch {
      /* node without a stored neighbourhood (e.g. outside the as-of window) */
    } finally {
      setExpanding(false);
    }
  };

  if (!seeds.length) return <Empty>This case cites no indicators or destinations to place in the infrastructure graph.</Empty>;
  if (!views) return <Loading label="Querying CONSTELLATION neighbourhood" />;
  if (!graph) return <Empty>None of the cited indicators ({seeds.join(", ")}) are in the tenant graph yet.</Empty>;

  return (
    <div className="grid g-main">
      <Panel
        title="Infrastructure neighbourhood"
        right={
          <div className="legend">
            {["domain", "ip", "malware_family"].map((t) => (
              <span key={t}>
                <i style={{ background: NODE_COLORS[t], borderRadius: 5 }} />
                {t.replace("_", " ")}
              </span>
            ))}
            <span>
              <i style={{ background: "transparent", borderTop: "2px dashed #64748b", height: 0, width: 14 }} /> candidate link
            </span>
            {expanding && <span className="spinner" />}
          </div>
        }
        flush
        testId="graph-panel"
      >
        <GraphCanvas graph={graph} width={W} height={H} onSelect={expand} selected={selected} />
      </Panel>
      <div className="stack">
        <Panel title="Graph semantics">
          <div className="muted small" style={{ lineHeight: 1.6 }}>
            Solid edges are observed or attributed relationships with an evidence grade; blue edges are enforcement-eligible. Dashed edges are candidate links inferred by link prediction: investigative only, never evidence and never enforcement-eligible. A dotted amber ring marks shared hosting (blocking it would hit legitimate co-tenants).
          </div>
          <div className="divider" />
          <dl className="kv">
            <dt>Nodes</dt>
            <dd>{graph.nodes.length}</dd>
            <dt>Edges</dt>
            <dd>
              {graph.edges.filter((e) => !e.candidate).length} observed · {graph.edges.filter((e) => e.candidate).length} candidate
            </dd>
            <dt>Seeds</dt>
            <dd className="mono small">{seeds.join(", ")}</dd>
            {missing.length > 0 && (
              <>
                <dt>Not in graph</dt>
                <dd className="mono small dim">{missing.join(", ")}</dd>
              </>
            )}
          </dl>
        </Panel>
        {selView && (
          <Panel title={<span className="mono">{selView.node.value}</span>} right={selView.shared_hosting ? <Badge tone="warn">shared hosting</Badge> : null}>
            <dl className="kv">
              <dt>Type</dt>
              <dd>{selView.node.node_type}</dd>
              <dt>Degree</dt>
              <dd>
                {selView.degree}
                {selView.truncated ? " (truncated)" : ""}
              </dd>
              <dt>First seen</dt>
              <dd className="mono small">{selView.node.first_seen}</dd>
              <dt>Last seen</dt>
              <dd className="mono small">{selView.node.last_seen}</dd>
            </dl>
            <div className="divider" />
            {selView.neighbors.slice(0, 12).map((n) => (
              <div key={n.edge.edge_id} className="row small" style={{ justifyContent: "space-between", flexWrap: "nowrap", marginBottom: 4 }}>
                <span className="ellipsis mono">
                  {n.direction === "out" ? "→" : "←"} {n.node_id}
                </span>
                <span className="nowrap">
                  <Badge tone="neutral">{n.edge.edge_type.replace(/_/g, " ")}</Badge> <Badge tone={n.edge.evidence_grade === "A" ? "ok" : n.edge.evidence_grade === "B" ? "info" : "neutral"}>{n.edge.evidence_grade}</Badge>
                </span>
              </div>
            ))}
          </Panel>
        )}
      </div>
    </div>
  );
}
