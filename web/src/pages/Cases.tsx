import { useNavigate, useSearchParams } from "react-router-dom";
import { useAsync } from "../api/hooks";
import type { CaseState } from "../api/types";
import { useClient } from "../auth/AuthContext";
import { CaseTitle } from "../components/domain";
import { IconRefresh } from "../components/icons";
import { Badge, Empty, ErrorBox, Loading, Pager, Panel, SeverityBadge, StateBadge, Time } from "../components/ui";
import { fmtRelative, humanize, parseCaseTitle, shortPseudonym } from "../lib/format";

const PAGE = 50;
const STATES: CaseState[] = ["NEW", "TRIAGE", "INVESTIGATING", "VERIFIED", "PROPOSED", "APPROVED", "EXECUTED", "INCONCLUSIVE", "REJECTED", "DENIED", "ROLLED_BACK", "EXPIRED", "CLOSED"];

export function CasesPage() {
  const client = useClient();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const state = (params.get("state") ?? "") as CaseState | "";
  const severity = params.get("severity") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const list = useAsync(() => client.cases({ state, severity, limit: PAGE, offset }), [client, state, severity, offset], 30_000);
  const metrics = useAsync(() => client.metrics(), [client], 30_000);
  const byState = metrics.data?.cases.by_state ?? {};

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Cases</h1>
          <div className="sub">Every state change is guarded by the case state machine and written to the signed ledger.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={list.reload}>
            <IconRefresh /> Refresh
          </button>
        </div>
      </div>
      <div className="row" style={{ gap: 6 }}>
        <button className={`btn sm ${state === "" ? "primary" : ""}`} onClick={() => set("state", "")}>
          All <span className="mono">{metrics.data?.cases.total ?? ""}</span>
        </button>
        {STATES.filter((s) => byState[s]).map((s) => (
          <button key={s} className={`btn sm ${state === s ? "primary" : ""}`} onClick={() => set("state", s)} data-testid={`state-${s}`}>
            {humanize(s)} <span className="mono">{byState[s]}</span>
          </button>
        ))}
        <select className="input" style={{ marginLeft: "auto" }} value={severity} onChange={(e) => set("severity", e.target.value)} aria-label="Severity">
          <option value="">All severities</option>
          {["critical", "high", "medium", "low"].map((s) => (
            <option key={s} value={s}>
              {humanize(s)}
            </option>
          ))}
        </select>
      </div>
      <Panel flush>
        {list.error !== undefined && (
          <div style={{ padding: 12 }}>
            <ErrorBox error={list.error} onRetry={list.reload} />
          </div>
        )}
        {list.loading && !list.data ? (
          <Loading />
        ) : list.data && list.data.items.length === 0 ? (
          <Empty>No cases match.</Empty>
        ) : list.data ? (
          <>
            <div className="table-wrap">
              <table className="t" data-testid="cases-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Case</th>
                    <th>Device</th>
                    <th>State</th>
                    <th className="num">Evidence</th>
                    <th>Review</th>
                    <th>Opened</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((c) => (
                    <tr key={c.case_id} className="clickable" onClick={() => nav(`/cases/${c.case_id}`)}>
                      <td>
                        <SeverityBadge severity={c.severity} />
                      </td>
                      <td>
                        <CaseTitle title={c.title} />
                      </td>
                      <td className="mono dim">{shortPseudonym(parseCaseTitle(c.title)?.entity)}</td>
                      <td>
                        <StateBadge state={c.state} />
                      </td>
                      <td className="num mono">{c.evidence_ids.length}</td>
                      <td>{c.counter_hypothesis_reviewed ? <Badge tone="ok">reviewed</Badge> : <Badge tone="neutral">pending</Badge>}</td>
                      <td>
                        <Time ts={c.created_at} seconds={false} />
                      </td>
                      <td className="dim nowrap">{fmtRelative(c.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager total={list.data.total} limit={PAGE} offset={offset} onChange={(o) => set("offset", String(o))} />
          </>
        ) : null}
      </Panel>
    </div>
  );
}
