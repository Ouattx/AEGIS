import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAsync } from "../api/hooks";
import type { CaseState, InvestigationReport } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { GroupChip } from "../components/domain";
import { IconBolt, IconFlask, IconRefresh } from "../components/icons";
import { ProposeDialog, type TargetSuggestions } from "../components/ProposeDialog";
import { useTenantStatus } from "../components/status";
import { useToast } from "../components/toast";
import { Badge, ErrorBox, Hash, Loading, Modal, Panel, ReasonDialog, ScoreBar, SeverityBadge, StateBadge, Tabs, Time, VerdictBadge } from "../components/ui";
import { LIFECYCLE, TERMINAL_STATES, transitionButtons } from "../lib/caseflow";
import { humanize, parseCaseTitle, shortDetector } from "../lib/format";
import { seedsFromEvidence } from "../lib/graph";
import { EvidenceTab } from "./case/EvidenceTab";
import { GraphTab } from "./case/GraphTab";
import { HypothesisPanel } from "./case/HypothesisPanel";
import { InvestigationTab } from "./case/InvestigationTab";
import { ReplayTab } from "./case/ReplayTab";
import { TimelineTab } from "./case/TimelineTab";

type TabId = "summary" | "evidence" | "timeline" | "investigation" | "graph" | "replay";

export function CaseDetailPage() {
  const { caseId = "" } = useParams();
  const { client, session, can } = useAuth();
  const toast = useToast();
  const nav = useNavigate();
  const status = useTenantStatus();
  const [tab, setTab] = useState<TabId>("summary");
  const [dialog, setDialog] = useState<null | { kind: "transition"; to: CaseState } | { kind: "review" } | { kind: "note" } | { kind: "propose" }>(null);
  const [investigating, setInvestigating] = useState(false);

  const detail = useAsync(() => client.caseDetail(caseId), [client, caseId]);
  const evidence = useAsync(() => client.caseEvidence(caseId), [client, caseId]);
  const history = useAsync(() => client.caseHistory(caseId), [client, caseId]);
  const report = useAsync<InvestigationReport | null>(
    () => client.caseInvestigation(caseId).catch((e) => (e instanceof ApiError && e.status === 404 ? null : Promise.reject(e))),
    [client, caseId],
  );
  const reloadAll = () => {
    detail.reload();
    evidence.reload();
    history.reload();
    report.reload();
    status.reload();
  };

  const seeds = useMemo(() => seedsFromEvidence((evidence.data?.items ?? []).map((e) => ({ kind: e.evidence.kind, payload: e.evidence.payload }))), [evidence.data]);
  const suggestions: TargetSuggestions = useMemo(() => {
    const entity = detail.data?.findings[0]?.entity_pseudonym ?? parseCaseTitle(detail.data?.case.title ?? "")?.entity;
    return {
      domains: seeds.filter((s) => s.startsWith("domain:")).map((s) => s.slice(7)),
      ips: seeds.filter((s) => s.startsWith("ip:")).map((s) => s.slice(3)),
      entities: entity ? [entity] : [],
    };
  }, [seeds, detail.data]);

  if (detail.error && !detail.data) return <ErrorBox error={detail.error} onRetry={detail.reload} />;
  if (!detail.data) return <Loading label="Loading case" />;
  const d = detail.data;
  const c = d.case;
  const perms = new Set(session?.me.permissions ?? []);
  const buttons = transitionButtons(d.allowed_transitions, perms, {
    counterHypothesisReviewed: c.counter_hypothesis_reviewed,
    verificationBlockers: d.evidence_assessment.verification_blockers,
  });
  const terminal = TERMINAL_STATES.has(c.state);
  const t = parseCaseTitle(c.title);
  const rep = report.data ?? undefined;

  const runInvestigation = async () => {
    setInvestigating(true);
    try {
      await client.investigate(caseId);
      toast("Bounded investigation completed and recorded in the ledger.", "ok");
      reloadAll();
    } catch (e) {
      toast(<ErrorBox error={e} />, "bad");
    } finally {
      setInvestigating(false);
    }
  };

  return (
    <div className="stack" data-testid="case-detail">
      <div className="page-head" style={{ alignItems: "flex-start" }}>
        <div style={{ minWidth: 0 }}>
          <div className="row" style={{ marginBottom: 6 }}>
            <Link to="/cases" className="small">
              ← Cases
            </Link>
            <Hash value={c.case_id} label="case id" />
          </div>
          <div className="row" style={{ gap: 10 }}>
            <h1>{t ? humanize(t.label) : c.title}</h1>
            <SeverityBadge severity={c.severity} />
            <StateBadge state={c.state} />
            {d.evidence_assessment.contested && <Badge tone="warn">contested</Badge>}
          </div>
          <div className="sub">
            {t ? (
              <>
                {humanize(t.deviceClass)} device <span className="mono">{t.entity}</span> ·{" "}
              </>
            ) : null}
            opened <Time ts={c.created_at} seconds={false} /> · {c.evidence_ids.length} evidence items · detector <span className="mono">{shortDetector(c.model_versions[0])}</span>
          </div>
        </div>
        <div className="actions">
          <button className="btn ghost" onClick={reloadAll} title="Reload">
            <IconRefresh />
          </button>
          {can("investigate") && !terminal && (
            <button className="btn" onClick={runInvestigation} disabled={investigating} data-testid="btn-investigate">
              {investigating ? <span className="spinner" /> : <IconFlask />} Re-run investigation
            </button>
          )}
          {can("case_work") && !terminal && (
            <>
              <button className="btn" onClick={() => setDialog({ kind: "note" })}>
                Add note
              </button>
              <button className="btn" onClick={() => setDialog({ kind: "review" })} data-testid="btn-review">
                {c.counter_hypothesis_reviewed ? "Update review" : "Record counter-hypothesis review"}
              </button>
            </>
          )}
          {can("propose") && c.state === "VERIFIED" && (
            <button className="btn primary" onClick={() => setDialog({ kind: "propose" })} data-testid="btn-propose">
              <IconBolt /> Propose action
            </button>
          )}
        </div>
      </div>

      <Panel>
        <div className="row" style={{ justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <Rail state={c.state} />
          <div className="row" data-testid="transition-buttons">
            {buttons.length === 0 && <span className="dim small">{terminal ? "Terminal state: no further transitions." : "Next steps run through the actions workflow."}</span>}
            {buttons.map((b) => (
              <button key={b.to} className={`btn ${b.enabled ? b.tone : ""}`} disabled={!b.enabled} title={b.hint} onClick={() => setDialog({ kind: "transition", to: b.to })} data-testid={`transition-${b.to}`}>
                {humanize(b.to)}
              </button>
            ))}
            {d.allowed_transitions.includes("PROPOSED") && !can("propose") && <span className="small dim">Proposing requires the analyst role.</span>}
            {d.actions.length > 0 && (
              <Link className="btn" to={`/actions/${d.actions[d.actions.length - 1].action_id}`}>
                <IconBolt /> Action workflow
              </Link>
            )}
          </div>
        </div>
        {!can("case_work") && !can("approve") && (
          <div className="small dim" style={{ marginTop: 8 }}>
            Signed in as {session?.me.roles.join(", ")}: read-only on this case.
          </div>
        )}
      </Panel>

      <Tabs<TabId>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "summary", label: "Summary" },
          { id: "evidence", label: "Evidence trail", count: evidence.data?.total },
          { id: "timeline", label: "Decision timeline", count: history.data?.total },
          { id: "investigation", label: "Investigation report" },
          { id: "graph", label: "Graph neighbourhood", count: seeds.length },
          { id: "replay", label: "Replay as of" },
        ]}
      />

      {tab === "summary" && (
        <div className="stack">
          <HypothesisPanel c={c} report={rep} />
          <div className="grid g-main">
            <Panel title={`Findings (${d.findings.length})`} flush>
              <table className="t">
                <thead>
                  <tr>
                    <th>Verdict</th>
                    <th>Class</th>
                    <th>Score</th>
                    <th>Window</th>
                    <th className="num">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {d.findings.map((f) => (
                    <tr key={f.finding_id}>
                      <td>
                        <VerdictBadge verdict={f.verdict} />
                      </td>
                      <td>{humanize(f.label)}</td>
                      <td>
                        <ScoreBar value={f.score} />
                      </td>
                      <td>
                        <Time ts={f.observed_window_end} seconds={false} />
                      </td>
                      <td className="num mono">{f.evidence_ids.length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {d.findings[0] && <div className="callout" style={{ margin: 12, whiteSpace: "pre-wrap" }}>{d.findings[0].explanation}</div>}
            </Panel>
            <div className="stack">
              <Panel title="Verification guard">
                <dl className="kv">
                  <dt>Independent origins</dt>
                  <dd className="row" style={{ gap: 4 }}>
                    {d.evidence_assessment.supporting_origins.length ? d.evidence_assessment.supporting_origins.map((o) => <GroupChip key={o} group={o} />) : <span className="dim">none</span>}
                  </dd>
                  <dt>Signed IOC hits</dt>
                  <dd>{d.evidence_assessment.signed_ioc_hit_ids.length}</dd>
                  <dt>Contradicting</dt>
                  <dd>{d.evidence_assessment.contradicting_origins.length ? d.evidence_assessment.contradicting_origins.join(", ") : "none"}</dd>
                  <dt>Counter-hypothesis</dt>
                  <dd>{c.counter_hypothesis_reviewed ? <Badge tone="ok">reviewed</Badge> : <Badge tone="warn">not reviewed</Badge>}</dd>
                  <dt>Blockers</dt>
                  <dd>{d.evidence_assessment.verification_blockers.length ? <Badge tone="warn">{d.evidence_assessment.verification_blockers.join(", ")}</Badge> : <Badge tone="ok">none</Badge>}</dd>
                </dl>
                <div className="small dim" style={{ marginTop: 8 }}>VERIFIED requires two independent origins or a signed IOC hit, no unresolved contradiction, and a recorded human counter-hypothesis review.</div>
              </Panel>
              <Panel title="Investigation">
                {d.investigation ? (
                  <dl className="kv">
                    <dt>Recommendation</dt>
                    <dd>
                      <Badge tone={d.investigation.recommendation === "verify" ? "bad" : "neutral"}>{d.investigation.recommendation}</Badge>
                    </dd>
                    <dt>Escalate</dt>
                    <dd>{d.investigation.escalate ? "yes" : "no"}</dd>
                    <dt>Finished</dt>
                    <dd>
                      <Time ts={d.investigation.finished_at} />
                    </dd>
                  </dl>
                ) : (
                  <span className="dim">Not investigated yet.</span>
                )}
                <button className="btn sm" style={{ marginTop: 10 }} onClick={() => setTab("investigation")}>
                  Open report
                </button>
              </Panel>
              <Panel title={`Actions (${d.actions.length})`}>
                {d.actions.length ? (
                  d.actions.map((a) => (
                    <div key={a.action_id} className="row" style={{ justifyContent: "space-between" }}>
                      <span>
                        <b>{humanize(a.action_type)}</b> <span className="mono small dim">{a.targets.join(", ")}</span>
                      </span>
                      <Link to={`/actions/${a.action_id}`}>open →</Link>
                    </div>
                  ))
                ) : (
                  <span className="dim">No actions proposed. Actions can be proposed once the case is VERIFIED.</span>
                )}
              </Panel>
            </div>
          </div>
        </div>
      )}
      {tab === "evidence" && (evidence.data ? <EvidenceTab items={evidence.data.items} assessment={d.evidence_assessment} /> : evidence.error ? <ErrorBox error={evidence.error} /> : <Loading />)}
      {tab === "timeline" && (history.data ? <TimelineTab history={history.data.items} /> : history.error ? <ErrorBox error={history.error} /> : <Loading />)}
      {tab === "investigation" &&
        (report.loading && report.data === undefined ? (
          <Loading />
        ) : report.error ? (
          <ErrorBox error={report.error} />
        ) : rep ? (
          <InvestigationTab report={rep} />
        ) : (
          <div className="empty">No investigation report yet. {can("investigate") && !terminal && "Run one with “Re-run investigation”."}</div>
        ))}
      {tab === "graph" && (evidence.data ? <GraphTab seeds={seeds} /> : <Loading />)}
      {tab === "replay" && (history.data ? <ReplayTab caseId={caseId} history={history.data.items} /> : <Loading />)}

      {dialog?.kind === "transition" && (
        <ReasonDialog
          title={`Move case to ${humanize(dialog.to)}`}
          description={
            dialog.to === "VERIFIED"
              ? "The state machine re-checks the evidence guard and the counter-hypothesis review; a refusal lists every failed check."
              : dialog.to === "REJECTED"
                ? "Marks this alert as a false alert. It counts toward the false-alert rate in the proof-of-value report."
                : undefined
          }
          confirmLabel={`Move to ${humanize(dialog.to)}`}
          tone={dialog.to === "REJECTED" || dialog.to === "DENIED" ? "danger" : dialog.to === "VERIFIED" ? "success" : "primary"}
          onSubmit={async (reason) => {
            await client.transition(caseId, dialog.to, reason);
            toast(`Case moved to ${dialog.to}. Ledger entry written.`, "ok");
            reloadAll();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "note" && (
        <ReasonDialog
          title="Add analyst note"
          description="Notes are attached as evidence for the record; they never qualify for verification."
          confirmLabel="Add note"
          onSubmit={async (note) => {
            await client.addNote(caseId, note);
            toast("Note attached.", "ok");
            reloadAll();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "review" && (
        <ReviewDialog
          alternatives={rep?.alternative_hypotheses.map((a) => a.title) ?? c.alternative_hypotheses}
          onSubmit={async (alts, notes) => {
            await client.review(caseId, alts, notes);
            toast("Counter-hypothesis review recorded.", "ok");
            reloadAll();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "propose" && (
        <ProposeDialog
          caseId={caseId}
          suggestions={suggestions}
          policies={status.policies}
          onClose={() => setDialog(null)}
          onProposed={(id) => {
            toast("Proposal recorded. Run the MIRROR simulation next.", "ok");
            nav(`/actions/${id}`);
          }}
        />
      )}
    </div>
  );
}

function Rail({ state }: { state: CaseState }) {
  const offPath: Partial<Record<CaseState, number>> = { REJECTED: 3, INCONCLUSIVE: 3, CLOSED: 3, DENIED: 5, ROLLED_BACK: 7, EXPIRED: 6 };
  const idx = LIFECYCLE.indexOf(state);
  const reached = idx >= 0 ? idx : (offPath[state] ?? 0) - 1;
  return (
    <div className="rail" aria-label="case lifecycle">
      {LIFECYCLE.map((s, i) => (
        <span key={s} style={{ display: "contents" }}>
          {i > 0 && <span className={`rail-line ${i <= reached ? "done" : ""}`} />}
          <span className={`rail-step ${i < reached || (i === reached && idx < 0) ? "done" : i === idx ? "current" : ""}`}>
            <span className="rs-dot">{i < reached || (i === reached && idx < 0) ? "✓" : ""}</span>
            {s.replace("_", " ")}
          </span>
        </span>
      ))}
      {idx < 0 && (
        <>
          <span className="rail-line" />
          <span className="rail-step current off">
            <span className="rs-dot" />
            {state.replace("_", " ")}
          </span>
        </>
      )}
    </div>
  );
}

function ReviewDialog({ alternatives, onSubmit, onClose }: { alternatives: string[]; onSubmit: (alts: string[], notes: string) => Promise<void>; onClose: () => void }) {
  const [checked, setChecked] = useState<Set<string>>(() => new Set(alternatives));
  const [extra, setExtra] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const alts = [...checked, ...extra.split("\n").map((s) => s.trim()).filter(Boolean)];
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit(alts, notes.trim());
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Counter-hypothesis review"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={busy || !alts.length || !notes.trim()} onClick={submit} data-testid="review-submit">
            {busy && <span className="spinner" />} Record review
          </button>
        </>
      }
    >
      <div className="muted">Confirm which benign explanations you considered and why they do not explain the activity. Required before VERIFIED; recorded with your identity in the ledger.</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {alternatives.map((a) => (
          <label key={a} className="check">
            <input
              type="checkbox"
              checked={checked.has(a)}
              onChange={(e) => {
                const n = new Set(checked);
                if (e.target.checked) n.add(a);
                else n.delete(a);
                setChecked(n);
              }}
            />
            <span>{a}</span>
          </label>
        ))}
      </div>
      <div className="field">
        <label htmlFor="extra">Other alternatives considered (one per line)</label>
        <textarea id="extra" className="input" rows={2} value={extra} onChange={(e) => setExtra(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="notes">Review notes</label>
        <textarea id="notes" className="input" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={4000} placeholder="e.g. destination is not a push/CDN provider; interval does not match class baseline; indicator signed by two feeds" data-testid="review-notes" />
      </div>
      {error !== null && <ErrorBox error={error} />}
    </Modal>
  );
}
