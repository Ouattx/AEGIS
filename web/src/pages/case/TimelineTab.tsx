import type { HistoryEntry } from "../../api/types";
import { Badge, Empty, Hash, Time } from "../../components/ui";
import { labelCheck } from "../../lib/checks";
import { actorKind, toTimeline } from "../../lib/timeline";

export function ActorBadge({ actor }: { actor: string | null }) {
  const k = actorKind(actor);
  if (!actor) return null;
  const tone = k === "human" ? "info" : k === "agent" ? "violet" : k === "simulated" ? "warn" : "neutral";
  return (
    <Badge tone={tone} title={k === "agent" ? "AI agent: advisory only, cannot change state or policy" : k === "simulated" ? "Simulated analyst used by the lab demo" : undefined}>
      {k === "agent" ? "AI " : ""}
      {actor}
    </Badge>
  );
}

/** Decision timeline of the case, built from its signed ledger entries. */
export function TimelineTab({ history }: { history: HistoryEntry[] }) {
  const items = toTimeline(history);
  if (!items.length) return <Empty>No ledger entries for this case.</Empty>;
  return (
    <div className="timeline" data-testid="timeline">
      {items.map((it) => (
        <div className="tl-item" key={it.seq}>
          <span className={`tl-dot ${it.tone}`} />
          <div className="tl-head">
            <b>{it.title}</b>
            <ActorBadge actor={it.actor} />
          </div>
          {it.body && <div className="tl-body">{it.body}</div>}
          {it.details.length > 0 && (
            <div className="row" style={{ marginTop: 4, gap: 4 }}>
              {it.details.slice(0, 8).map((d) => (
                <span key={d} className="chip" title={d}>
                  {it.entryType === "case_transition_refused" ? labelCheck(d) : d.length > 60 ? `${d.slice(0, 58)}…` : d}
                </span>
              ))}
              {it.details.length > 8 && <span className="dim small">+{it.details.length - 8} more</span>}
            </div>
          )}
          <div className="tl-meta">
            <Time ts={it.at} />
            <span className="mono">#{it.seq}</span>
            <span>{it.entryType}</span>
            <Hash value={it.hash} label="ledger entry hash" />
          </div>
        </div>
      ))}
    </div>
  );
}
