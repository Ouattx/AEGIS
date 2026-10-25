import { humanize, parseCaseTitle } from "../lib/format";

/** Readable case title: threat label and device class, pseudonym shown separately. */
export function CaseTitle({ title }: { title: string }) {
  const t = parseCaseTitle(title);
  if (!t) return <span>{title}</span>;
  return (
    <span>
      {humanize(t.label)} <span className="dim">· {humanize(t.deviceClass)}</span>
    </span>
  );
}

/** Stable colour per source-independence group so the evidence trail shows syndication at a glance. */
const GROUP_COLORS = ["#38bdf8", "#a78bfa", "#f472b6", "#f59e0b", "#2dd4bf", "#818cf8", "#fb923c", "#22c55e"];

export function groupColor(group: string): string {
  let h = 0;
  for (let i = 0; i < group.length; i++) h = (h * 31 + group.charCodeAt(i)) >>> 0;
  return GROUP_COLORS[h % GROUP_COLORS.length];
}

export function GroupChip({ group }: { group: string }) {
  return (
    <span className="chip" title={`source-independence group ${group}`}>
      <span className="sw" style={{ background: groupColor(group) }} />
      <span className="mono">{group}</span>
    </span>
  );
}

const KIND_LABEL: Record<string, string> = {
  observation: "Observation",
  ioc_match: "Signed IOC match",
  model_score: "Model score",
  anomaly: "Anomaly",
  change_point: "Change point",
  graph_link: "Graph link",
  threat_feed: "Threat feed",
  analyst_note: "Analyst note",
  counter_hypothesis: "Counter-hypothesis",
  benign_baseline: "Benign baseline",
};

export function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? humanize(kind);
}
