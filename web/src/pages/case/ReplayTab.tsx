import { useEffect, useMemo, useState } from "react";
import type { HistoryEntry, Replay } from "../../api/types";
import { useClient } from "../../auth/AuthContext";
import { Badge, ErrorBox, Hash, Panel, StateBadge, Time } from "../../components/ui";
import type { CaseState } from "../../api/types";
import { fmtTime } from "../../lib/format";
import { stateAsOf, toTimeline } from "../../lib/timeline";

/**
 * Replay-as-of: reconstructs what the ledger knew about this case at time T (evidence,
 * decisions, model versions) from a content-hashed snapshot. Nothing is recomputed.
 */
export function ReplayTab({ caseId, history }: { caseId: string; history: HistoryEntry[] }) {
  const client = useClient();
  const bounds = useMemo(() => {
    const times = history.map((h) => new Date(h.recorded_at).getTime()).filter((t) => !Number.isNaN(t));
    const min = times.length ? Math.min(...times) - 1000 : Date.now() - 3600_000;
    const max = Math.max(Date.now(), times.length ? Math.max(...times) + 1000 : Date.now());
    return { min, max, marks: [...new Set(times)].sort((a, b) => a - b) };
  }, [history]);
  const [t, setT] = useState<number>(bounds.max);
  const [replay, setReplay] = useState<Replay | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let live = true;
    const h = window.setTimeout(() => {
      setLoading(true);
      client
        .caseReplay(caseId, new Date(t).toISOString())
        .then((r) => {
          if (!live) return;
          setReplay(r);
          setError(null);
        })
        .catch((e) => live && setError(e))
        .finally(() => live && setLoading(false));
    }, 180);
    return () => {
      live = false;
      window.clearTimeout(h);
    };
  }, [client, caseId, t]);

  const state = replay ? stateAsOf(replay.decisions) : null;
  const items = replay ? toTimeline(replay.decisions).slice(-8).reverse() : [];

  return (
    <div className="stack" data-testid="replay">
      <Panel title="Replay as of" right={loading ? <span className="spinner" /> : <span className="mono">{fmtTime(new Date(t))}</span>}>
        <input
          type="range"
          className="slider"
          min={bounds.min}
          max={bounds.max}
          step={1000}
          value={t}
          onChange={(e) => setT(Number(e.target.value))}
          aria-label="Replay time"
          data-testid="replay-slider"
        />
        <div className="ticks">
          <span>{fmtTime(new Date(bounds.min))}</span>
          <span>now</span>
        </div>
        <div className="row" style={{ marginTop: 10, gap: 4 }}>
          <span className="small dim">Jump to ledger event:</span>
          {bounds.marks.slice(0, 14).map((m, i) => (
            <button key={m} className={`btn sm ${Math.abs(m - t) < 1500 ? "primary" : ""}`} onClick={() => setT(m + 500)} title={fmtTime(new Date(m))}>
              {i + 1}
            </button>
          ))}
          <button className="btn sm" onClick={() => setT(bounds.max)}>
            Now
          </button>
        </div>
      </Panel>
      {error !== null && <ErrorBox error={error} />}
      {replay && (
        <div className="grid g-3">
          <Panel title="Case at T">
            <dl className="kv">
              <dt>State</dt>
              <dd>{state ? <StateBadge state={state as CaseState} /> : <Badge tone="neutral">did not exist yet</Badge>}</dd>
              <dt>Evidence known</dt>
              <dd>{replay.evidence_ids.length}</dd>
              <dt>Superseded</dt>
              <dd>{Object.keys(replay.superseded_evidence_ids).length}</dd>
              <dt>Non-contemporaneous</dt>
              <dd>
                {replay.non_contemporaneous_evidence_ids.length}
                {replay.non_contemporaneous_evidence_ids.length > 0 && <span className="small dim"> (collected after T)</span>}
              </dd>
              <dt>Model versions</dt>
              <dd className="mono small">{replay.model_versions.map((m) => m.split("+")[0]).join(", ") || "—"}</dd>
            </dl>
          </Panel>
          <Panel title="Snapshot anchor">
            <dl className="kv">
              <dt>Snapshot</dt>
              <dd>
                <Hash value={replay.snapshot.snapshot_hash} label="snapshot hash" />
              </dd>
              <dt>As of</dt>
              <dd>
                <Time ts={replay.snapshot.as_of} />
              </dd>
              <dt>Ledger head</dt>
              <dd>
                #{replay.snapshot.head_seq} <Hash value={replay.snapshot.head_hash} />
              </dd>
              <dt>Entries covered</dt>
              <dd>{replay.snapshot.entry_count}</dd>
            </dl>
            <div className="small dim" style={{ marginTop: 8 }}>Anyone holding the ledger can recompute this hash and get the same view.</div>
          </Panel>
          <Panel title="Decisions known at T">
            {items.length ? (
              <div className="timeline">
                {items.map((it) => (
                  <div className="tl-item" key={it.seq}>
                    <span className={`tl-dot ${it.tone}`} />
                    <div className="tl-head">
                      <b>{it.title}</b>
                    </div>
                    <div className="tl-meta">
                      <Time ts={it.at} /> <span className="mono">#{it.seq}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="dim">No decisions recorded yet at this time.</div>
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
