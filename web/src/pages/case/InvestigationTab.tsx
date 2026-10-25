import type { InvestigationReport } from "../../api/types";
import { Badge, Hash, Panel, Time } from "../../components/ui";
import { humanize } from "../../lib/format";
import { GroupChip, kindLabel } from "../../components/domain";

/** The bounded investigation report: narrative, verification advice, tool calls and budget. */
export function InvestigationTab({ report }: { report: InvestigationReport }) {
  const v = report.verification;
  const b = report.budget as Record<string, number | string[] | undefined>;
  return (
    <div className="stack" data-testid="investigation">
      <div className="grid g-main">
        <Panel
          title="Investigation report"
          right={
            <div className="row">
              <Badge tone={report.mode === "deterministic" ? "neutral" : "info"}>{report.mode}</Badge>
              <Badge tone="neutral">LLM {report.llm_status}</Badge>
            </div>
          }
        >
          <p style={{ marginTop: 0, whiteSpace: "pre-wrap", lineHeight: 1.6 }}>{report.narrative}</p>
          {report.graph_findings.length > 0 && (
            <>
              <h3 style={{ margin: "14px 0 8px" }}>Infrastructure correlation</h3>
              <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)" }}>
                {report.graph_findings.map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
            </>
          )}
          {report.policy.notes.length > 0 && (
            <div className="callout violet" style={{ marginTop: 12 }}>
              <b>Policy:</b> {report.policy.notes.join(" ")} {report.policy.enforcement_possible ? "" : "Enforcement is not possible under the current policy."}
            </div>
          )}
        </Panel>
        <div className="stack">
          <Panel title="Verifier advice">
            <div className="row" style={{ marginBottom: 8 }}>
              <Badge tone={v.recommendation === "verify" ? "bad" : v.recommendation === "reject" ? "ok" : "warn"} lg>
                {humanize(v.recommendation)}
              </Badge>
              {v.suggested_state && <span className="muted">suggests {v.suggested_state}</span>}
            </div>
            <div className="muted">{v.rationale}</div>
            <div className="divider" />
            <dl className="kv">
              <dt>Evidence sufficient</dt>
              <dd>{v.evidence_sufficient_for_verified ? <Badge tone="ok">yes</Badge> : <Badge tone="warn">no</Badge>}</dd>
              <dt>Blockers</dt>
              <dd>{v.blockers.length ? v.blockers.join(", ") : "none"}</dd>
              <dt>Escalate</dt>
              <dd>{report.escalate ? <Badge tone="warn">{report.escalation_reasons.join(", ") || "yes"}</Badge> : "no"}</dd>
              <dt>Supporting origins</dt>
              <dd className="row" style={{ gap: 4 }}>
                {report.supporting_origins.map((o) => (
                  <GroupChip key={o} group={o} />
                ))}
              </dd>
            </dl>
            <div className="small dim" style={{ marginTop: 10 }}>Advisory only: agents cannot change case state, policy or enforcement.</div>
          </Panel>
          <Panel title="Provenance">
            <dl className="kv">
              <dt>Report</dt>
              <dd>
                <Hash value={report.report_id} />
              </dd>
              <dt>Report SHA-256</dt>
              <dd>
                <Hash value={report.report_sha256} />
              </dd>
              <dt>Started</dt>
              <dd>
                <Time ts={report.started_at} />
              </dd>
              <dt>Finished</dt>
              <dd>
                <Time ts={report.finished_at} />
              </dd>
              <dt>Budget</dt>
              <dd>
                {String(b.tool_calls ?? "?")}/{String(b.max_tool_calls ?? "?")} tool calls · {String(b.llm_calls ?? 0)} LLM calls · {String(b.elapsed_s ?? "?")} s
              </dd>
            </dl>
          </Panel>
        </div>
      </div>
      <div className="grid g-2">
        <Panel title="Evidence reviewed by agents" flush>
          <table className="t">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Summary</th>
                <th>Group</th>
              </tr>
            </thead>
            <tbody>
              {report.evidence.map((e) => (
                <tr key={e.evidence_id}>
                  <td className="nowrap">
                    {kindLabel(e.kind)} {e.agent_appended && <Badge tone="violet">agent</Badge>}
                  </td>
                  <td className="ellipsis" style={{ maxWidth: 360 }} title={e.summary}>
                    {e.summary}
                  </td>
                  <td>
                    <GroupChip group={e.source_group} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Agent tool calls" flush>
          <table className="t">
            <thead>
              <tr>
                <th>Agent</th>
                <th>Tool</th>
                <th>Result</th>
                <th className="num">ms</th>
              </tr>
            </thead>
            <tbody>
              {report.tool_calls.map((t, i) => (
                <tr key={`${t.agent}-${t.tool}-${i}`}>
                  <td className="mono">{t.agent}</td>
                  <td className="mono">{t.tool}</td>
                  <td>
                    {t.ok ? <Badge tone="ok">ok</Badge> : <Badge tone="bad">{t.error ?? "failed"}</Badge>}
                    {t.injection_flags.length > 0 && <Badge tone="warn">injection flagged</Badge>}
                  </td>
                  <td className="num mono">{t.duration_ms}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {report.refused_tool_requests.length > 0 && <div className="callout warn" style={{ margin: 12 }}>{report.refused_tool_requests.length} tool request(s) refused by the sandbox.</div>}
        </Panel>
      </div>
    </div>
  );
}
