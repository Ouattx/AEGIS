import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useAsync } from "../api/hooks";
import type { ActionDetail, CaseDetail, ExecutionRecord } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CaseTitle } from "../components/domain";
import { IconBolt, IconCheck, IconFlask, IconGavel, IconPlay, IconRefresh, IconUndo, IconX } from "../components/icons";
import { ProposeDialog } from "../components/ProposeDialog";
import { useTenantStatus } from "../components/status";
import { useToast } from "../components/toast";
import { Badge, Empty, ErrorBox, Hash, Loading, Modal, Pager, Panel, PassIcon, ReasonDialog, StateBadge, Time } from "../components/ui";
import { evaluateChecks, labelCheck } from "../lib/checks";
import { fmtNumber, fmtRelative, humanize } from "../lib/format";

const PAGE = 50;

export function ActionsPage() {
  const { client, can } = useAuth();
  const nav = useNavigate();
  const status = useTenantStatus();
  const [params, setParams] = useSearchParams();
  const offset = Number(params.get("offset") ?? 0) || 0;
  const list = useAsync(() => client.actions({ limit: PAGE, offset }), [client, offset], 20_000);
  const verified = useAsync(() => client.cases({ state: "VERIFIED", limit: 200 }), [client]);
  const [pickCase, setPickCase] = useState(false);
  const [proposeFor, setProposeFor] = useState<string | null>(null);
  const caseFor = useAsync(() => (proposeFor ? client.caseEvidence(proposeFor) : Promise.resolve(null)), [client, proposeFor]);
  const suggestions = useMemo(() => {
    const domains: string[] = [];
    const ips: string[] = [];
    const entities: string[] = [];
    for (const it of caseFor.data?.items ?? []) {
      const p = it.evidence.payload;
      if (typeof p.entity_pseudonym === "string" && !entities.includes(p.entity_pseudonym)) entities.push(p.entity_pseudonym);
      if (it.evidence.kind === "ioc_match" && typeof p.indicator_value === "string") {
        (p.indicator_type === "ip" ? ips : domains).push(p.indicator_value);
      }
    }
    return { domains: [...new Set(domains)], ips: [...new Set(ips)], entities };
  }, [caseFor.data]);

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Response actions</h1>
          <div className="sub">Propose → MIRROR impact simulation → deterministic authorization → four-eyes approval → execute / roll back. AI never authorizes.</div>
        </div>
        <div className="actions">
          <button className="btn" onClick={list.reload}>
            <IconRefresh /> Refresh
          </button>
          {can("propose") && (
            <button className="btn primary" onClick={() => setPickCase(true)} data-testid="btn-new-action">
              <IconBolt /> New proposal
            </button>
          )}
        </div>
      </div>
      {status.mode === "shadow" && (
        <div className="callout violet">
          <b>Shadow mode.</b> The signed operator policy is in shadow mode: every proposal can be simulated and assessed, and the authorization checklist will show why enforcement is refused (<code>policy_not_active_mode</code>). Nothing is ever blocked during the pilot.
        </div>
      )}
      <Panel flush>
        {list.error !== undefined && (
          <div style={{ padding: 12 }}>
            <ErrorBox error={list.error} onRetry={list.reload} />
          </div>
        )}
        {list.loading && !list.data ? (
          <Loading />
        ) : list.data && list.data.items.length === 0 ? (
          <Empty icon={<IconBolt />}>No actions proposed yet. Actions start from a VERIFIED case.</Empty>
        ) : list.data ? (
          <>
            <table className="t" data-testid="actions-table">
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Targets</th>
                  <th>Case</th>
                  <th>Legal basis</th>
                  <th>Proposed by</th>
                  <th>Expires</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((a) => (
                  <tr key={a.action_id} className="clickable" onClick={() => nav(`/actions/${a.action_id}`)}>
                    <td>
                      <b>{humanize(a.action_type)}</b>
                    </td>
                    <td className="mono small">{a.targets.join(", ")}</td>
                    <td>
                      <Hash value={a.case_id} />
                    </td>
                    <td className="mono small">{a.legal_basis ?? <span className="dim">none</span>}</td>
                    <td>{a.created_by}</td>
                    <td className="dim">{a.expires_at ? fmtRelative(a.expires_at) : "never"}</td>
                    <td>
                      <Time ts={a.created_at} seconds={false} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager total={list.data.total} limit={PAGE} offset={offset} onChange={(o) => setParams(o ? { offset: String(o) } : {}, { replace: true })} />
          </>
        ) : null}
      </Panel>
      {pickCase && (
        <Modal title="Choose a VERIFIED case" onClose={() => setPickCase(false)}>
          {verified.loading && !verified.data ? (
            <Loading />
          ) : verified.data?.items.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 420, overflow: "auto" }}>
              {verified.data.items.map((c) => (
                <button
                  key={c.case_id}
                  className="role-card"
                  style={{ padding: 10 }}
                  onClick={() => {
                    setPickCase(false);
                    setProposeFor(c.case_id);
                  }}
                >
                  <span>
                    <b style={{ textTransform: "none" }}>
                      <CaseTitle title={c.title} />
                    </b>
                    <p className="mono small">{c.case_id}</p>
                  </span>
                </button>
              ))}
            </div>
          ) : (
            <div className="dim">No VERIFIED cases. Verify a case first.</div>
          )}
        </Modal>
      )}
      {proposeFor && caseFor.data && (
        <ProposeDialog
          caseId={proposeFor}
          suggestions={suggestions}
          policies={status.policies}
          onClose={() => setProposeFor(null)}
          onProposed={(id) => {
            setProposeFor(null);
            nav(`/actions/${id}`);
          }}
        />
      )}
    </div>
  );
}

type StepState = "done" | "current" | "blocked" | "todo";

export function ActionDetailPage() {
  const { actionId = "" } = useParams();
  const { client, can, session } = useAuth();
  const toast = useToast();
  const status = useTenantStatus();
  const [busy, setBusy] = useState<string | null>(null);
  const [dialog, setDialog] = useState<null | "approve" | "deny" | "execute" | "rollback">(null);
  const detail = useAsync<ActionDetail>(() => client.action(actionId), [client, actionId]);
  const caseDetail = useAsync<CaseDetail | null>(() => (detail.data ? client.caseDetail(detail.data.action.case_id) : Promise.resolve(null)), [client, detail.data?.action.case_id]);

  if (detail.error && !detail.data) return <ErrorBox error={detail.error} onRetry={detail.reload} />;
  if (!detail.data) return <Loading label="Loading action" />;
  const { action: a, mirror, authorization: authz, executions, live } = detail.data;
  const cs = caseDetail.data?.case.state;
  const reload = () => {
    detail.reload();
    caseDetail.reload();
    status.reload();
  };
  const run = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    try {
      await fn();
      toast(ok, "ok");
    } catch (e) {
      toast(<ErrorBox error={e} />, "bad");
    } finally {
      setBusy(null);
      reload();
    }
  };
  const isProposer = session?.me.sub === a.created_by;
  const lastExec = executions[executions.length - 1];
  const executed = executions.some((e) => e.operation === "execute" && (e.status === "applied" || e.status === "dry_run"));
  const rolledBack = executions.some((e) => e.operation === "rollback" && e.status === "rolled_back");
  const approvedStates = ["APPROVED", "EXECUTED", "ROLLED_BACK", "EXPIRED"];

  const steps: Array<{ n: string; t: string; s: string; st: StepState }> = [
    { n: "Step 1", t: "Proposed", s: `${a.created_by} · ${fmtRelative(a.created_at)}`, st: "done" },
    { n: "Step 2", t: "MIRROR simulation", s: mirror ? `${mirror.verdict} · ${mirror.affected_entities ?? "?"} affected` : "not run", st: mirror ? (mirror.verdict === "SAFE" ? "done" : "blocked") : "current" },
    { n: "Step 3", t: "Authorization", s: authz ? (authz.allowed ? "allowed" : `${authz.failed_checks.length} check(s) failed`) : "not assessed", st: authz ? (authz.allowed ? "done" : "blocked") : mirror ? "current" : "todo" },
    { n: "Step 4", t: "Human approval", s: cs === "DENIED" ? "denied" : cs && approvedStates.includes(cs) ? "approved" : cs === "PROPOSED" ? "awaiting approver" : "—", st: cs === "DENIED" ? "blocked" : cs && approvedStates.includes(cs) ? "done" : authz?.allowed ? "current" : "todo" },
    { n: "Step 5", t: "Execution", s: rolledBack ? "rolled back" : executed ? (live ? "live" : lastExec?.status ?? "executed") : "—", st: rolledBack ? "done" : executed ? "done" : cs === "APPROVED" ? "current" : "todo" },
  ];
  const { groups, unknown } = evaluateChecks(authz?.failed_checks ?? []);

  return (
    <div className="stack" data-testid="action-detail">
      <div className="page-head" style={{ alignItems: "flex-start" }}>
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <Link to="/actions" className="small">
              ← Actions
            </Link>
            <Hash value={a.action_id} label="action id" />
          </div>
          <div className="row" style={{ gap: 10 }}>
            <h1>{humanize(a.action_type)}</h1>
            <span className="mono">{a.targets.join(", ")}</span>
            {live && <Badge tone="bad" dot>live enforcement</Badge>}
          </div>
          <div className="sub">
            Case <Link to={`/cases/${a.case_id}`}>{caseDetail.data ? <CaseTitle title={caseDetail.data.case.title} /> : a.case_id}</Link> {cs && <StateBadge state={cs} />}
          </div>
        </div>
        <div className="actions">
          <button className="btn ghost" onClick={reload}>
            <IconRefresh />
          </button>
        </div>
      </div>

      <div className="stepper" data-testid="stepper">
        {steps.map((s) => (
          <div key={s.n} className={`step ${s.st}`}>
            <span className="s-n">{s.n}</span>
            <span className="s-t">{s.t}</span>
            <span className="s-s">{s.s}</span>
          </div>
        ))}
      </div>

      <div className="grid g-2">
        <Panel
          title="MIRROR impact simulation"
          right={
            can("propose") && (
              <button className="btn primary sm" disabled={busy !== null} onClick={() => run("sim", () => client.simulate(actionId), "MIRROR simulation recorded in the ledger.")} data-testid="btn-simulate">
                {busy === "sim" ? <span className="spinner" /> : <IconFlask />} {mirror ? "Re-run simulation" : "Run simulation"}
              </button>
            )
          }
          testId="mirror-panel"
        >
          {mirror ? (
            <div className="stack" style={{ gap: 10 }}>
              <div className="row">
                <Badge tone={mirror.verdict === "SAFE" ? "ok" : "bad"} lg dot>
                  {mirror.verdict}
                </Badge>
                <span className="muted">{mirror.rationale}</span>
              </div>
              <div className="grid g-4" style={{ gap: 8 }}>
                <Metric label="Affected entities" value={mirror.affected_entities === null ? "unknown" : fmtNumber(mirror.affected_entities)} bad={mirror.affected_entities === null} />
                <Metric label="Legit daily flows hit" value={mirror.historic_daily_legit_flows === null ? "unknown" : fmtNumber(mirror.historic_daily_legit_flows)} bad={!!mirror.historic_daily_legit_flows} />
                <Metric label="Shared infrastructure" value={mirror.shared_infrastructure ? "yes" : "no"} bad={mirror.shared_infrastructure} />
                <Metric label="Reversibility" value={mirror.reversibility} bad={mirror.reversibility === "unknown" || mirror.reversibility === "manual"} />
              </div>
              <dl className="kv">
                <dt>Legitimate co-tenants</dt>
                <dd>{mirror.legitimate_cotenants.length ? mirror.legitimate_cotenants.join(", ") : <span className="dim">none found</span>}</dd>
                <dt>Unknowns</dt>
                <dd>{mirror.unknowns.length ? mirror.unknowns.map((u) => <Badge key={u} tone="warn">{u}</Badge>) : <span className="dim">none</span>}</dd>
                <dt>Human approval</dt>
                <dd>{mirror.requires_human_approval ? "required" : "not required by MIRROR (policy still decides)"}</dd>
                <dt>Computed</dt>
                <dd>
                  <Time ts={mirror.computed_at} /> <span className="dim small">(stale after 1 h)</span>
                </dd>
              </dl>
            </div>
          ) : (
            <div className="dim">Not simulated yet. MIRROR estimates collateral impact from the topology and traffic history; UNKNOWN fails closed.</div>
          )}
        </Panel>

        <Panel
          title="Authorization checklist"
          right={
            <div className="row">
              {authz && <Badge tone={authz.allowed ? "ok" : "bad"} lg>{authz.allowed ? "allowed" : "not allowed"}</Badge>}
              {can("propose") && (
                <button className="btn primary sm" disabled={busy !== null || !(cs === "VERIFIED" || cs === "PROPOSED")} title={cs === "VERIFIED" || cs === "PROPOSED" ? "Run the deterministic assessment" : `Case is ${cs}`} onClick={() => run("auth", () => client.authorize(actionId), "Authorization assessed deterministically and recorded.")} data-testid="btn-authorize">
                  {busy === "auth" ? <span className="spinner" /> : <IconGavel />} {authz ? "Re-assess" : "Assess"}
                </button>
              )}
            </div>
          }
          testId="authz-panel"
        >
          <div className="small dim" style={{ marginBottom: 10 }}>
            authorize = signed policy ∧ legal basis ∧ evidence quality ∧ MIRROR SAFE ∧ scope ⊆ approved ∧ expiry ∧ rollback verified. Every conjunct is evaluated; no language model is consulted.
          </div>
          <div className="checklist">
            {groups.map((g) => (
              <details key={g.id} className="cg" open={!!authz && !g.passed}>
                <summary className="cg-head" style={{ listStyle: "none" }}>
                  <PassIcon state={!authz ? "pending" : g.passed ? "pass" : "fail"} />
                  <span style={{ flex: 1 }}>
                    <div className="cg-title">{g.title}</div>
                    <div className="cg-desc">{g.description}</div>
                  </span>
                </summary>
                <div className="cg-body">
                  {g.results.map((r) => (
                    <div key={r.id} className={`ci ${authz && !r.passed ? "fail" : ""}`}>
                      <PassIcon state={!authz ? "pending" : r.passed ? "pass" : "fail"} />
                      {r.label} <code>{r.id}</code>
                    </div>
                  ))}
                </div>
              </details>
            ))}
            {unknown.length > 0 && <div className="callout bad">Other failed checks: {unknown.join(", ")}</div>}
          </div>
          {authz && (
            <div className="small dim" style={{ marginTop: 10 }}>
              Policy <span className="mono">{authz.policy_id ?? "none"}</span> · evaluated <Time ts={authz.evaluated_at} /> · evidence quality {detail.data.evidence_quality_ok ? "ok" : "failed"}
            </div>
          )}
        </Panel>
      </div>

      <div className="grid g-2">
        <Panel title="Approval (four-eyes)" testId="approval-panel">
          <dl className="kv" style={{ marginBottom: 12 }}>
            <dt>Proposer</dt>
            <dd>{a.created_by}</dd>
            <dt>Legal basis</dt>
            <dd className="mono">{a.legal_basis ?? "—"}</dd>
            <dt>Expires</dt>
            <dd>{a.expires_at ? <Time ts={a.expires_at} /> : <Badge tone="warn">no expiry</Badge>}</dd>
            <dt>Rollback plan</dt>
            <dd>
              {a.rollback_plan ?? "—"} {a.rollback_verified ? <Badge tone="ok">rehearsed on adapter</Badge> : <Badge tone="warn">not rehearsed</Badge>}
            </dd>
          </dl>
          {can("approve") ? (
            <div className="row">
              <button className="btn success" disabled={cs !== "PROPOSED" || !authz?.allowed || isProposer} onClick={() => setDialog("approve")} title={isProposer ? "Four-eyes: you proposed this action" : !authz?.allowed ? "Authorization did not allow this action" : undefined} data-testid="btn-approve">
                <IconCheck /> Approve
              </button>
              <button className="btn danger" disabled={cs !== "PROPOSED"} onClick={() => setDialog("deny")} data-testid="btn-deny">
                <IconX /> Deny
              </button>
              {cs === "PROPOSED" && authz && !authz.allowed && <span className="small" style={{ color: "#fca5a5" }}>Approval is blocked: the deterministic authorization did not allow this action.</span>}
              {isProposer && <span className="small dim">You proposed this action and cannot approve it.</span>}
            </div>
          ) : (
            <div className="dim small">Approval requires the approver role. {cs === "PROPOSED" ? "Awaiting an approver." : ""}</div>
          )}
        </Panel>
        <Panel title="Execution" testId="execution-panel">
          {can("execute") ? (
            <div className="row" style={{ marginBottom: 12 }}>
              <button className="btn primary" disabled={cs !== "APPROVED" || isProposer} onClick={() => setDialog("execute")} data-testid="btn-execute">
                <IconPlay /> Execute
              </button>
              <button className="btn" disabled={!live} onClick={() => setDialog("rollback")} data-testid="btn-rollback">
                <IconUndo /> Roll back
              </button>
              <span className="small dim">Every gate is re-evaluated at execution time.</span>
            </div>
          ) : (
            <div className="dim small" style={{ marginBottom: 12 }}>Execution requires the approver role.</div>
          )}
          {executions.length ? <ExecutionTable records={executions} /> : <div className="dim">No execution records.</div>}
        </Panel>
      </div>

      {dialog === "approve" && (
        <ReasonDialog title="Approve action" confirmLabel="Approve" tone="success" onSubmit={async (r) => { await client.approve(actionId, r); toast("Action approved.", "ok"); reload(); }} onClose={() => setDialog(null)} />
      )}
      {dialog === "deny" && (
        <ReasonDialog title="Deny action" description="The case moves to DENIED (terminal)." confirmLabel="Deny" tone="danger" onSubmit={async (r) => { await client.deny(actionId, r); toast("Action denied.", "ok"); reload(); }} onClose={() => setDialog(null)} />
      )}
      {dialog === "execute" && (
        <ReasonDialog title="Execute action" description="Policy, authorization, approval and simulation are re-checked now; any failure refuses and is recorded." confirmLabel="Execute" requireReason={false} onSubmit={async (r) => { await client.execute(actionId, r); toast("Action executed.", "ok"); reload(); }} onClose={() => setDialog(null)} />
      )}
      {dialog === "rollback" && (
        <ReasonDialog title="Roll back action" description="Restores the recorded prior state at the enforcement point." confirmLabel="Roll back" tone="danger" onSubmit={async (r) => { await client.rollback(actionId, r); toast("Action rolled back.", "ok"); reload(); }} onClose={() => setDialog(null)} />
      )}
    </div>
  );
}

function Metric({ label, value, bad }: { label: string; value: string; bad?: boolean }) {
  return (
    <div style={{ border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px", background: "var(--bg-2)" }}>
      <div className="small dim">{label}</div>
      <div style={{ fontSize: 16, fontWeight: 700, color: bad ? "#fbbf24" : "var(--text)" }}>{value}</div>
    </div>
  );
}

function ExecutionTable({ records }: { records: ExecutionRecord[] }) {
  return (
    <table className="t">
      <thead>
        <tr>
          <th>Operation</th>
          <th>Status</th>
          <th>Adapter</th>
          <th>Actor</th>
          <th>At</th>
          <th>Ledger</th>
        </tr>
      </thead>
      <tbody>
        {records.map((r) => (
          <tr key={r.execution_id}>
            <td>{r.operation}</td>
            <td>
              <Badge tone={r.status === "applied" ? "bad" : r.status === "rolled_back" || r.status === "dry_run" ? "ok" : "warn"}>{r.status}</Badge>
              {r.refusal_reasons.length > 0 && <div className="small dim">{r.refusal_reasons.map(labelCheck).join("; ")}</div>}
            </td>
            <td className="mono">{r.adapter}</td>
            <td>{r.actor}</td>
            <td>
              <Time ts={r.at} />
            </td>
            <td>
              <Hash value={r.ledger_entry_hash} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
