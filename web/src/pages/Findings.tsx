import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAsync } from "../api/hooks";
import type { Finding } from "../api/types";
import { useClient } from "../auth/AuthContext";
import { IconRefresh, IconSearch } from "../components/icons";
import { Badge, Drawer, Empty, ErrorBox, Hash, Loading, Pager, Panel, ScoreBar, Time, VerdictBadge } from "../components/ui";
import { fmtRelative, humanize, localInputToIso, shortDetector, shortPseudonym } from "../lib/format";

const PAGE = 50;
const VERDICTS = ["malicious", "suspicious", "abstain", "benign"];
const STATUSES = ["candidate", "triage", "verified", "rejected", "expired"];

export function FindingsPage() {
  const client = useClient();
  const [params, setParams] = useSearchParams();
  const verdict = params.get("verdict") ?? "";
  const label = params.get("label") ?? "";
  const status = params.get("status") ?? "";
  const entity = params.get("entity") ?? "";
  const since = params.get("since") ?? "";
  const until = params.get("until") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [entityDraft, setEntityDraft] = useState(entity);
  const [selected, setSelected] = useState<Finding | null>(null);

  const list = useAsync(
    () =>
      client.findings({
        verdict,
        label,
        status,
        entity,
        since: localInputToIso(since),
        until: localInputToIso(until),
        limit: PAGE,
        offset,
      }),
    [client, verdict, label, status, entity, since, until, offset],
    30_000,
  );
  const metrics = useAsync(() => client.metrics(), [client]);
  const cases = useAsync(() => client.cases({ limit: 500 }), [client]);
  const caseOf = useMemo(() => {
    const m = new Map<string, string>();
    for (const c of cases.data?.items ?? []) for (const f of c.finding_ids) m.set(f, c.case_id);
    return m;
  }, [cases.data]);
  const labels = Object.keys(metrics.data?.findings.by_label ?? {}).sort();

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };
  const anyFilter = verdict || label || status || entity || since || until;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Findings</h1>
          <div className="sub">Detector outputs with calibrated scores and cited evidence. Abstentions are first-class and routed for review.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={list.reload}>
            <IconRefresh /> Refresh
          </button>
        </div>
      </div>
      <Panel flush>
        <div className="row" style={{ padding: 12, borderBottom: "1px solid var(--line)", gap: 10 }}>
          <select className="input" value={verdict} onChange={(e) => set("verdict", e.target.value)} aria-label="Verdict" data-testid="filter-verdict">
            <option value="">All verdicts</option>
            {VERDICTS.map((v) => (
              <option key={v} value={v}>
                {humanize(v)}
              </option>
            ))}
          </select>
          <select className="input" value={label} onChange={(e) => set("label", e.target.value)} aria-label="Threat class">
            <option value="">All threat classes</option>
            {labels.map((v) => (
              <option key={v} value={v}>
                {humanize(v)}
              </option>
            ))}
          </select>
          <select className="input" value={status} onChange={(e) => set("status", e.target.value)} aria-label="Status">
            <option value="">All statuses</option>
            {STATUSES.map((v) => (
              <option key={v} value={v}>
                {humanize(v)}
              </option>
            ))}
          </select>
          <form
            className="row"
            style={{ gap: 6 }}
            onSubmit={(e) => {
              e.preventDefault();
              set("entity", entityDraft.trim());
            }}
          >
            <input className="input mono" placeholder="device pseudonym p_…" value={entityDraft} onChange={(e) => setEntityDraft(e.target.value)} style={{ width: 220 }} aria-label="Device pseudonym" />
            <button className="btn" type="submit">
              <IconSearch />
            </button>
          </form>
          <label className="row small muted" style={{ gap: 6 }}>
            since
            <input type="datetime-local" className="input" value={since} onChange={(e) => set("since", e.target.value)} />
          </label>
          <label className="row small muted" style={{ gap: 6 }}>
            until
            <input type="datetime-local" className="input" value={until} onChange={(e) => set("until", e.target.value)} />
          </label>
          {anyFilter && (
            <button
              className="btn ghost"
              onClick={() => {
                setEntityDraft("");
                setParams(new URLSearchParams(), { replace: true });
              }}
            >
              Clear filters
            </button>
          )}
          <span className="small dim" style={{ marginLeft: "auto" }}>times in UTC</span>
        </div>
        {list.error !== undefined && (
          <div style={{ padding: 12 }}>
            <ErrorBox error={list.error} onRetry={list.reload} />
          </div>
        )}
        {list.loading && !list.data ? (
          <Loading />
        ) : list.data && list.data.items.length === 0 ? (
          <Empty>No findings match these filters.</Empty>
        ) : list.data ? (
          <>
            <div className="table-wrap">
              <table className="t" data-testid="findings-table">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Threat class</th>
                    <th>Score</th>
                    <th>Device</th>
                    <th>Class</th>
                    <th className="num">Evidence</th>
                    <th>Status</th>
                    <th>Window end</th>
                    <th>Case</th>
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((f) => (
                    <tr key={f.finding_id} className={`clickable ${selected?.finding_id === f.finding_id ? "selected" : ""}`} onClick={() => setSelected(f)}>
                      <td>
                        <VerdictBadge verdict={f.verdict} />
                      </td>
                      <td>{humanize(f.label)}</td>
                      <td>
                        <ScoreBar value={f.score} />
                      </td>
                      <td className="mono">{shortPseudonym(f.entity_pseudonym)}</td>
                      <td className="muted">{humanize(f.device_class)}</td>
                      <td className="num mono">{f.evidence_ids.length}</td>
                      <td>
                        <Badge tone={f.status === "verified" ? "bad" : f.status === "rejected" ? "ok" : "neutral"}>{f.status}</Badge>
                      </td>
                      <td>
                        <Time ts={f.observed_window_end} seconds={false} />
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        {caseOf.get(f.finding_id) ? <Link to={`/cases/${caseOf.get(f.finding_id)}`}>open →</Link> : <span className="dim">—</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager total={list.data.total} limit={PAGE} offset={offset} onChange={(o) => set("offset", String(o))} />
          </>
        ) : null}
      </Panel>
      {selected && <FindingDrawer finding={selected} caseId={caseOf.get(selected.finding_id)} onClose={() => setSelected(null)} />}
    </div>
  );
}

const COMPONENTS: Array<[string, string]> = [
  ["ioc", "Signed IOC"],
  ["ioc_independent_origins", "IOC independent origins"],
  ["ioc_counter_evidence", "IOC counter-evidence"],
  ["ml", "Calibrated model"],
  ["anomaly", "Per-class anomaly"],
  ["changepoint", "Change point"],
];

function FindingDrawer({ finding: f, caseId, onClose }: { finding: Finding; caseId?: string; onClose: () => void }) {
  return (
    <Drawer
      onClose={onClose}
      title={
        <div className="row">
          <VerdictBadge verdict={f.verdict} />
          <h2>{humanize(f.label)}</h2>
        </div>
      }
    >
      <div className="stack">
        <dl className="kv">
          <dt>Finding</dt>
          <dd>
            <Hash value={f.finding_id} />
          </dd>
          <dt>Device</dt>
          <dd className="mono">
            {f.entity_pseudonym} <span className="dim">({humanize(f.device_class)})</span>
          </dd>
          <dt>Window</dt>
          <dd>
            <Time ts={f.observed_window_start} seconds={false} /> → <Time ts={f.observed_window_end} seconds={false} />
          </dd>
          <dt>Detector</dt>
          <dd className="mono" title={f.detector_version}>
            {shortDetector(f.detector_version)}
          </dd>
          <dt>Calibration</dt>
          <dd className="mono">{f.calibration_id ?? "uncalibrated"}</dd>
          <dt>Expires</dt>
          <dd>{f.expires_at ? `${fmtRelative(f.expires_at)}` : "—"}</dd>
          <dt>Case</dt>
          <dd>{caseId ? <Link to={`/cases/${caseId}`}>Open case →</Link> : <span className="dim">no case (abstain or below threshold)</span>}</dd>
        </dl>
        <div>
          <h3 style={{ marginBottom: 8 }}>Fusion components</h3>
          <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: "6px 12px", alignItems: "center" }}>
            {COMPONENTS.map(([k, l]) => (
              <FragmentRow key={k} label={l} value={f.component_scores[k]} />
            ))}
            <span className="muted">Fused score</span>
            <ScoreBar value={f.score} />
          </div>
        </div>
        <div>
          <h3 style={{ marginBottom: 8 }}>Explanation</h3>
          <div className="callout" style={{ whiteSpace: "pre-wrap" }}>
            {f.explanation}
          </div>
        </div>
        <div>
          <h3 style={{ marginBottom: 8 }}>Cited evidence ({f.evidence_ids.length})</h3>
          <div className="row">
            {f.evidence_ids.map((e) => (
              <Hash key={e} value={e} />
            ))}
          </div>
          {f.counterevidence_ids.length > 0 && (
            <>
              <h3 style={{ margin: "12px 0 8px" }}>Counter-evidence ({f.counterevidence_ids.length})</h3>
              <div className="row">
                {f.counterevidence_ids.map((e) => (
                  <Hash key={e} value={e} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </Drawer>
  );
}

function FragmentRow({ label, value }: { label: string; value: number | null | undefined }) {
  return (
    <>
      <span className="muted">{label}</span>
      <ScoreBar value={value ?? null} />
    </>
  );
}
