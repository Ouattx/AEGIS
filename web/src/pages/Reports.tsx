import { useEffect, useState } from "react";
import type { PovReport } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { IconDoc, IconDownload, IconExternal, IconShieldCheck } from "../components/icons";
import { Badge, ErrorBox, Hash, Kpi, Modal, Panel } from "../components/ui";
import { fmtDate, fmtNumber, fmtPct, humanize, localInputToIso } from "../lib/format";

/** Shadow proof-of-value report: generate, preview the key numbers, open or download the full report. */
export function ReportsPage() {
  const { client, session } = useAuth();
  const [operator, setOperator] = useState("");
  const [budget, setBudget] = useState<string>("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [busy, setBusy] = useState<null | "json" | "html">(null);
  const [error, setError] = useState<unknown>(null);
  const [report, setReport] = useState<PovReport | null>(null);
  const [html, setHtml] = useState<string | null>(null);
  const [viewer, setViewer] = useState(false);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);

  useEffect(() => () => {
    if (blobUrl) URL.revokeObjectURL(blobUrl);
  }, [blobUrl]);

  const query = () => ({
    operator: operator.trim() || undefined,
    budget: budget.trim() ? Number(budget) : undefined,
    start: localInputToIso(start),
    end: localInputToIso(end),
  });

  const generate = async () => {
    setBusy("json");
    setError(null);
    setHtml(null);
    if (blobUrl) URL.revokeObjectURL(blobUrl);
    setBlobUrl(null);
    try {
      setReport(await client.povJson(query()));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  const loadHtml = async (): Promise<string | null> => {
    if (html) return html;
    setBusy("html");
    setError(null);
    try {
      const h = await client.povHtml(query());
      setHtml(h);
      const url = URL.createObjectURL(new Blob([h], { type: "text/html" }));
      setBlobUrl(url);
      return h;
    } catch (e) {
      setError(e);
      return null;
    } finally {
      setBusy(null);
    }
  };

  const open = async () => {
    if (await loadHtml()) setViewer(true);
  };
  const download = async () => {
    const h = await loadHtml();
    if (!h) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([h], { type: "text/html" }));
    a.download = `aegis-pov-${session?.me.tenant_id ?? "tenant"}-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };
  const partialPeriod = (start && !end) || (!start && end);

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Shadow proof-of-value report</h1>
          <div className="sub">The pilot deliverable: coverage, alerts with cited evidence, false-alert rate per 10k device-days, analyst effort, zero-enforcement attestation and ledger proof.</div>
        </div>
      </div>
      <Panel title="Generate">
        <div className="row" style={{ gap: 12, alignItems: "flex-end" }}>
          <div className="field">
            <label htmlFor="op">Operator name (cover page)</label>
            <input id="op" className="input" value={operator} onChange={(e) => setOperator(e.target.value)} placeholder={session?.me.tenant_id} maxLength={120} style={{ width: 220 }} />
          </div>
          <div className="field">
            <label htmlFor="budget">False-alert budget / 10k device-days</label>
            <input id="budget" className="input" type="number" min={0} max={10000} step="0.1" value={budget} onChange={(e) => setBudget(e.target.value)} placeholder="e.g. 5" style={{ width: 200 }} />
          </div>
          <div className="field">
            <label htmlFor="start">Period start (UTC, optional)</label>
            <input id="start" className="input" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="end">Period end (UTC, optional)</label>
            <input id="end" className="input" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
          </div>
          <button className="btn primary lg" onClick={generate} disabled={busy !== null || !!partialPeriod} data-testid="btn-generate">
            {busy === "json" ? <span className="spinner" /> : <IconDoc />} Generate report
          </button>
        </div>
        {partialPeriod && <div className="small" style={{ color: "#fbbf24", marginTop: 8 }}>Give both start and end, or neither (default: the full observation period).</div>}
      </Panel>
      {error !== null && <ErrorBox error={error} />}
      {report && (
        <div className="stack" data-testid="report-summary">
          <Panel
            title={
              <div className="row">
                <IconShieldCheck width={16} height={16} />
                <h3>{report.operator_name} · {fmtDate(report.period_start)} → {fmtDate(report.period_end)}</h3>
              </div>
            }
            right={
              <div className="row">
                <button className="btn primary" onClick={open} disabled={busy !== null} data-testid="btn-open-report">
                  {busy === "html" ? <span className="spinner" /> : <IconExternal />} Open full report
                </button>
                <button className="btn" onClick={download} disabled={busy !== null}>
                  <IconDownload /> Download HTML
                </button>
              </div>
            }
          >
            <div style={{ fontSize: 17, fontWeight: 600, marginBottom: 10 }}>{report.headline}</div>
            <ul style={{ margin: 0, paddingLeft: 18, color: "var(--text-2)", lineHeight: 1.7 }}>
              {report.summary.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </Panel>
          <div className="grid g-6">
            <Kpi label="Devices observed" value={fmtNumber(report.coverage.devices_observed)} foot={`${fmtNumber(report.coverage.device_days)} device-days`} />
            <Kpi label="Alerts" value={fmtNumber(report.alerts.alerts)} foot={`${report.alerts.alerted_devices} devices · ${report.alerts.abstain_for_review} abstain`} accent="#ef4444" />
            <Kpi label="False alerts / 10k dd" value={report.false_alerts.per_10k === null ? "n/a" : fmtNumber(report.false_alerts.per_10k, 1)} foot={report.false_alerts.within_budget === null ? `upper ${fmtNumber(report.false_alerts.per_10k_upper, 1)}` : report.false_alerts.within_budget ? "within budget" : "over budget"} accent="#22c55e" />
            <Kpi label="Verified by analysts" value={fmtNumber(report.dispositions.verified)} foot={`${report.dispositions.rejected} rejected · ${report.dispositions.pending} pending`} accent="#f59e0b" />
            <Kpi label="Analyst effort (est.)" value={report.effort.est_total_hours === null ? "n/a" : fmtNumber(report.effort.est_total_hours, 1)} unit="h" foot={`${report.effort.est_minutes_per_case ?? "?"} min / case`} accent="#a78bfa" />
            <Kpi label="Live enforcements" value={fmtNumber(report.attestation.live_executions)} foot={report.attestation.status === "attested" ? "zero-enforcement attested" : report.attestation.status} accent="#a78bfa" />
          </div>
          <div className="grid g-2">
            <Panel title="Threat classes" flush>
              <table className="t">
                <thead>
                  <tr>
                    <th>Class</th>
                    <th className="num">Alerts</th>
                    <th className="num">Devices</th>
                    <th className="num">Verified</th>
                    <th className="num">Rejected</th>
                    <th className="num">Pending</th>
                  </tr>
                </thead>
                <tbody>
                  {report.threat_classes.map((t) => (
                    <tr key={t.label}>
                      <td>{humanize(t.label)}</td>
                      <td className="num">{t.malicious + t.suspicious}</td>
                      <td className="num">{t.devices}</td>
                      <td className="num">{t.verified}</td>
                      <td className="num">{t.rejected}</td>
                      <td className="num">{t.pending}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
            <Panel title="Assurance">
              <dl className="kv">
                <dt>Attestation</dt>
                <dd>
                  <Badge tone={report.attestation.status === "attested" ? "ok" : "warn"}>{report.attestation.status}</Badge> <span className="muted">{report.attestation.statement}</span>
                </dd>
                <dt>Ledger</dt>
                <dd>
                  {report.ledger.ok ? <Badge tone="ok">verified</Badge> : <Badge tone="bad">failed</Badge>} {fmtNumber(report.ledger.entries_checked)} entries · head <Hash value={report.ledger.head_hash} />
                </dd>
                <dt>Snapshot</dt>
                <dd>
                  <Hash value={report.ledger.snapshot_hash} />
                </dd>
                {report.validation && (
                  <>
                    <dt>Validation</dt>
                    <dd>
                      precision {fmtPct(report.validation.precision, 1)} · recall {fmtPct(report.validation.recall, 1)} <span className="dim small">({report.validation.source})</span>
                    </dd>
                  </>
                )}
                <dt>Report fingerprint</dt>
                <dd>
                  <Hash value={report.fingerprint} n={12} />
                </dd>
              </dl>
              {report.limitations.length > 0 && (
                <details style={{ marginTop: 10 }}>
                  <summary className="small muted" style={{ cursor: "pointer" }}>
                    Limitations ({report.limitations.length})
                  </summary>
                  <ul className="small muted" style={{ paddingLeft: 18 }}>
                    {report.limitations.map((l) => (
                      <li key={l}>{l}</li>
                    ))}
                  </ul>
                </details>
              )}
            </Panel>
          </div>
        </div>
      )}
      {viewer && html && (
        <Modal
          wide
          onClose={() => setViewer(false)}
          title={
            <div className="row">
              <h2>Proof-of-value report</h2>
              {blobUrl && (
                <a className="btn sm" href={blobUrl} target="_blank" rel="noopener">
                  <IconExternal /> New tab (print to PDF)
                </a>
              )}
            </div>
          }
        >
          <iframe className="iframe-report" title="Proof-of-value report" sandbox="" srcDoc={html} data-testid="report-frame" />
        </Modal>
      )}
    </div>
  );
}
