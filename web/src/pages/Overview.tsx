import { useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAsync } from "../api/hooks";
import type { Case, CaseState, Finding } from "../api/types";
import { useClient } from "../auth/AuthContext";
import { Donut, HBars, Legend, PALETTE, Sparkline, StackedBars } from "../components/charts";
import { IconRefresh } from "../components/icons";
import { CaseTitle } from "../components/domain";
import { useTenantStatus } from "../components/status";
import { Badge, ErrorBox, Hash, Kpi, Loading, Panel, SeverityBadge, StateBadge } from "../components/ui";
import { fmtCompact, fmtDate, fmtNumber, fmtPct, fmtRelative, humanize, parseCaseTitle, shortDetector, shortPseudonym } from "../lib/format";
import { bucketize, chooseBucketHours } from "../lib/series";

const STATE_COLORS: Partial<Record<CaseState, string>> = {
  NEW: "#38bdf8",
  TRIAGE: "#60a5fa",
  INVESTIGATING: "#f59e0b",
  VERIFIED: "#ef4444",
  REJECTED: "#64748b",
  INCONCLUSIVE: "#94a3b8",
  PROPOSED: "#a78bfa",
  APPROVED: "#c084fc",
  DENIED: "#475569",
  EXECUTED: "#f472b6",
  ROLLED_BACK: "#22c55e",
  CLOSED: "#334155",
  EXPIRED: "#1e293b",
};

const VERDICT_COLORS = { malicious: "#ef4444", suspicious: "#f59e0b", abstain: "#64748b", benign: "#22c55e" };
const SEV_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };
/** States that need someone to act, most urgent first (PROPOSED waits for an approver). */
const ATTENTION_PRIORITY: Partial<Record<CaseState, number>> = { PROPOSED: 0, INVESTIGATING: 1, TRIAGE: 2, NEW: 3 };

/** Cases needing attention: actionable states only, by state priority, then severity, then oldest first. */
export function attentionQueue(items: Case[], limit = 8): Case[] {
  return items
    .filter((c) => ATTENTION_PRIORITY[c.state] !== undefined)
    .sort(
      (a, b) =>
        (ATTENTION_PRIORITY[a.state] ?? 9) - (ATTENTION_PRIORITY[b.state] ?? 9) ||
        (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) ||
        a.updated_at.localeCompare(b.updated_at),
    )
    .slice(0, limit);
}

function fmtCi(ci: [number, number] | null | undefined): string {
  return ci ? `${fmtPct(ci[0], 0)}–${fmtPct(ci[1], 0)}` : "n/a";
}

export function OverviewPage() {
  const client = useClient();
  const nav = useNavigate();
  const status = useTenantStatus();
  const metrics = useAsync(() => client.metrics(), [client], 30_000);
  const pov = useAsync(() => client.povJson({}), [client], 120_000);
  const findings = useAsync(() => client.findings({ limit: 500 }), [client], 60_000);
  const cases = useAsync(() => client.cases({ limit: 500 }), [client], 30_000);

  const m = metrics.data;
  const trend = useMemo(() => {
    if (!m || !findings.data) return null;
    const start = new Date(m.coverage.period_start);
    const end = new Date(m.coverage.period_end);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) return null;
    const hours = chooseBucketHours(start, end, 24);
    const b = bucketize<Finding>(findings.data.items, (f) => f.created_at, (f) => f.verdict, ["malicious", "suspicious", "abstain"], start, end, hours);
    return { ...b, hours };
  }, [m, findings.data]);

  const openCases = useMemo(() => attentionQueue(cases.data?.items ?? []), [cases.data]);

  if (metrics.error && !m) return <ErrorBox error={metrics.error} onRetry={metrics.reload} />;
  if (!m) return <Loading label="Loading tenant overview" />;

  const p = pov.data;
  const fa = p?.false_alerts;
  const verdictSpark = trend ? trend.labels.map((_, i) => (trend.counts.malicious[i] ?? 0) + (trend.counts.suspicious[i] ?? 0)) : [];
  const stateData = Object.entries(m.cases.by_state)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({ label: humanize(k), value: v, color: STATE_COLORS[k as CaseState] ?? "#64748b" }));
  const labelData = Object.entries(m.findings.by_label)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v], i) => ({ label: humanize(k), value: v, color: PALETTE[i % PALETTE.length] }));
  const live = m.actions.live_enforcements;

  return (
    <div className="stack" data-testid="overview">
      <div className="page-head">
        <div>
          <h1>Security posture</h1>
          <div className="sub">
            Tenant <span className="mono">{m.tenant_id}</span> · observation period {fmtDate(m.coverage.period_start)} → {fmtDate(m.coverage.period_end)} · {fmtCompact(m.coverage.events)} telemetry events
          </div>
        </div>
        <div className="actions">
          {status.mode === "shadow" && <Badge tone="violet" lg dot>Shadow pilot · zero blocking</Badge>}
          <button
            className="btn"
            onClick={() => {
              metrics.reload();
              pov.reload();
              findings.reload();
              cases.reload();
              status.reload();
            }}
          >
            <IconRefresh /> Refresh
          </button>
        </div>
      </div>

      {p?.synthetic && (
        <div className="callout bad" role="alert" data-testid="synthetic-banner">
          <b>Synthetic lab demo · simulated analyst.</b> {p.synthetic_notice}
        </div>
      )}

      <div className="grid g-6">
        <Kpi testId="kpi-devices" label="Devices monitored" value={fmtNumber(m.coverage.devices_observed)} accent="#38bdf8" foot={<>{fmtNumber(m.coverage.device_days)} device-days observed</>} />
        <Kpi
          testId="kpi-cases"
          label="Active cases"
          value={fmtNumber(m.cases.open)}
          accent="#f59e0b"
          foot={
            <>
              <span>{fmtNumber(m.cases.total)} total</span>
              {m.cases.by_severity.critical ? <Badge tone="bad">{m.cases.by_severity.critical} critical</Badge> : null}
            </>
          }
        />
        <Kpi
          testId="kpi-false-alerts"
          label="False alerts / 10k device-days"
          value={fa ? (fa.per_10k === null ? "n/a" : fmtNumber(fa.per_10k, 1)) : "…"}
          accent="#22c55e"
          foot={
            fa ? (
              <span title="95% exact upper confidence bound of the measured rate; n = observed device-days">
                <b>≤ {fa.per_10k_ci_upper == null ? "n/a" : fmtNumber(fa.per_10k_ci_upper, 1)}</b> (95% upper bound, n = {fmtNumber(fa.device_days)}) · {fa.rejected_device_days} rejected
              </span>
            ) : pov.error ? (
              <span className="dim">report unavailable</span>
            ) : (
              <span className="dim">computing…</span>
            )
          }
        />
        <Kpi
          testId="kpi-findings"
          label="Alerts raised"
          value={fmtNumber((m.findings.by_verdict.malicious ?? 0) + (m.findings.by_verdict.suspicious ?? 0))}
          accent="#ef4444"
          spark={<Sparkline values={verdictSpark} color="#ef4444" />}
          foot={<>{m.findings.by_verdict.abstain ?? 0} abstained for review</>}
        />
        <Kpi
          testId="kpi-ledger"
          label="Ledger integrity"
          value={status.ledger ? (status.ledger.ok ? "Verified" : "FAILED") : "…"}
          accent={status.ledger && !status.ledger.ok ? "#ef4444" : "#22c55e"}
          foot={status.ledger ? <>{fmtNumber(status.ledger.signed_entries)} signed entries · <Hash value={status.ledger.head_hash} n={6} label="head" /></> : null}
        />
        <Kpi
          testId="kpi-enforcement"
          label="Live enforcements"
          value={fmtNumber(live)}
          accent={live > 0 ? "#ef4444" : "#a78bfa"}
          foot={<>{status.mode === "shadow" ? "shadow policy refuses enforcement" : status.mode === "active" ? "active policy loaded" : "no valid policy"} · adapter {m.enforcement_adapter}</>}
        />
      </div>

      <div className="grid g-main">
        <Panel
          title="Detections over time"
          right={
            <Legend
              items={[
                { label: "Malicious", color: VERDICT_COLORS.malicious },
                { label: "Suspicious", color: VERDICT_COLORS.suspicious },
                { label: "Abstain", color: VERDICT_COLORS.abstain },
              ]}
            />
          }
          testId="trend"
        >
          {trend ? (
            <StackedBars
              labels={trend.labels}
              series={[
                { name: "Malicious", color: VERDICT_COLORS.malicious, values: trend.counts.malicious },
                { name: "Suspicious", color: VERDICT_COLORS.suspicious, values: trend.counts.suspicious },
                { name: "Abstain", color: VERDICT_COLORS.abstain, values: trend.counts.abstain },
              ]}
              height={210}
            />
          ) : findings.error ? (
            <ErrorBox error={findings.error} />
          ) : (
            <Loading />
          )}
          {trend && <div className="small dim" style={{ marginTop: 6 }}>{trend.hours}h buckets by detection window end (UTC)</div>}
        </Panel>
        <Panel title="Case pipeline (cases)" right={<Link to="/cases">All cases →</Link>}>
          <div className="row" style={{ gap: 18, alignItems: "center", flexWrap: "nowrap" }}>
            <Donut
              data={stateData}
              center={
                <div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{m.cases.total}</div>
                  <div className="small dim">cases</div>
                </div>
              }
            />
            <div style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 0, flex: 1 }}>
              {stateData.map((s) => (
                <div key={s.label} className="row" style={{ justifyContent: "space-between", flexWrap: "nowrap" }}>
                  <span className="row" style={{ gap: 6 }}>
                    <i style={{ width: 9, height: 9, borderRadius: 2, background: s.color, display: "inline-block" }} />
                    <span className="muted">{s.label}</span>
                  </span>
                  <b className="mono">{s.value}</b>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid g-3">
        <Panel title="Threat classes" right={<Link to="/findings">Findings →</Link>}>
          {labelData.length ? <HBars data={labelData} onClick={(l) => nav(`/findings?label=${encodeURIComponent(l.toLowerCase().replace(/ /g, "_"))}`)} /> : <div className="dim">No findings yet.</div>}
        </Panel>
        <Panel title="Alert rate by device class">
          {p ? (
            <HBars
              data={[...p.device_classes].sort((a, b) => (b.alert_rate ?? 0) - (a.alert_rate ?? 0)).map((d) => ({ label: humanize(d.device_class), value: (d.alert_rate ?? 0) * 100, hint: `${d.alerted_devices} of ${d.devices_observed} devices alerted` }))}
              color="#a78bfa"
              format={(v) => `${v.toFixed(0)}%`}
            />
          ) : pov.error ? (
            <ErrorBox error={pov.error} />
          ) : (
            <Loading />
          )}
          <div className="small dim" style={{ marginTop: 8 }}>Device class selects a comparison baseline only; it is never evidence of compromise.</div>
        </Panel>
        <Panel title="Evidence & validation">
          {p ? (
            <dl className="kv">
              <dt>Alerts with ≥2 independent origins</dt>
              <dd>
                <b>{p.evidence.alerts_with_two_origins}</b> / {p.evidence.alerts_with_evidence}
              </dd>
              <dt>Evidence items integrity-checked</dt>
              <dd>
                {fmtNumber(p.evidence.evidence_items_checked)}{" "}
                {p.evidence.evidence_integrity_failures === 0 ? <Badge tone="ok">0 failures</Badge> : <Badge tone="bad">{p.evidence.evidence_integrity_failures} failures</Badge>}
              </dd>
              <dt>Detection delay (median / p90)</dt>
              <dd>
                {p.timing.detection_delay_median_h ?? "n/a"} h / {p.timing.detection_delay_p90_h ?? "n/a"} h
              </dd>
              <dt>{p.synthetic ? "Simulated-analyst dispositions" : "Analyst dispositions"} (alerting device-days)</dt>
              <dd>
                {p.dispositions.verified} verified · {p.dispositions.rejected} rejected · {p.dispositions.inconclusive} inconclusive · {p.dispositions.pending} pending
              </dd>
              {p.validation && (
                <>
                  <dt>
                    Validation against independent labels {p.synthetic ? <Badge tone="warn">synthetic lab</Badge> : null}
                  </dt>
                  <dd data-testid="validation">
                    precision 95% CI {fmtCi(p.validation.precision_ci)} (n = {p.validation.tp + p.validation.fp}) · recall 95% CI {fmtCi(p.validation.recall_ci)} (n ={" "}
                    {p.validation.positive_device_days ?? p.validation.tp + p.validation.fn}) · base rate{" "}
                    {p.validation.device_days ? fmtPct((p.validation.positive_device_days ?? 0) / p.validation.device_days, 1) : "n/a"}
                    <div className="dim small">{p.validation.source}</div>
                  </dd>
                </>
              )}
              <dt>Zero-enforcement attestation</dt>
              <dd>{p.attestation.status === "attested" ? <Badge tone="ok">attested</Badge> : <Badge tone="warn">{p.attestation.status}</Badge>}</dd>
            </dl>
          ) : pov.error ? (
            <ErrorBox error={pov.error} />
          ) : (
            <Loading />
          )}
        </Panel>
      </div>

      <div className="grid g-main">
        <Panel title="Cases needing attention" right={<Link to="/cases">Queue →</Link>} flush testId="attention">
          {openCases.length ? (
            <div className="table-wrap">
              <table className="t">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Case</th>
                    <th>State</th>
                    <th>Device</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {openCases.map((c) => (
                    <tr key={c.case_id} className="clickable" onClick={() => nav(`/cases/${c.case_id}`)}>
                      <td>
                        <SeverityBadge severity={c.severity} />
                      </td>
                      <td className="ellipsis" style={{ maxWidth: 360 }}>
                        <CaseTitle title={c.title} />
                      </td>
                      <td>
                        <StateBadge state={c.state} />
                      </td>
                      <td className="mono dim">{shortPseudonym(parseCaseTitle(c.title)?.entity)}</td>
                      <td className="dim nowrap">{fmtRelative(c.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : cases.loading ? (
            <Loading />
          ) : (
            <div className="empty">No open cases. The queue is clear.</div>
          )}
        </Panel>
        <Panel title="Platform posture">
          <dl className="kv">
            <dt>Detector</dt>
            <dd className="mono" title={m.detector_version}>
              {shortDetector(m.detector_version)}
            </dd>
            <dt>Model</dt>
            <dd>{m.model_loaded ? <Badge tone="ok">calibrated model loaded</Badge> : <Badge tone="warn">rules + anomaly only</Badge>}</dd>
            <dt>IOC bundle</dt>
            <dd>
              {m.ioc_bundle ? (
                <>
                  <span className="mono">{m.ioc_bundle.version}</span> · {m.ioc_bundle.indicators} indicators <Badge tone="ok">signed</Badge>
                </>
              ) : (
                <Badge tone="warn">none loaded</Badge>
              )}
            </dd>
            <dt>Topology</dt>
            <dd>
              {m.topology ? (
                <>
                  {m.topology.prefixes} prefixes · {m.topology.hosts} hosts · {m.topology.shared_hosts} shared {m.topology.complete ? <Badge tone="ok">complete</Badge> : <Badge tone="warn">incomplete · fail closed</Badge>}
                </>
              ) : (
                <Badge tone="warn">unknown · enforcement fails closed</Badge>
              )}
            </dd>
            <dt>Sources</dt>
            <dd>{m.ingest.sources.join(", ") || "—"}</dd>
            <dt>Quarantined records</dt>
            <dd>{fmtNumber(m.ingest.quarantined)}</dd>
            <dt>LLM assistance</dt>
            <dd>{m.llm ? <Badge tone="info">enabled · advisory only</Badge> : <Badge tone="neutral">off · deterministic</Badge>}</dd>
          </dl>
        </Panel>
      </div>
    </div>
  );
}
