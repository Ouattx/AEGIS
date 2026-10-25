import { Fragment, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useAsync } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { IconChain, IconLock, IconRefresh, IconShieldCheck, IconAlert } from "../components/icons";
import { Badge, Empty, ErrorBox, Hash, Loading, Pager, Panel, Time } from "../components/ui";
import { fmtNumber } from "../lib/format";

const PAGE = 50;
const ENTRY_TYPES = [
  "evidence",
  "finding",
  "case_transition",
  "case_transition_refused",
  "case_counter_hypothesis_review",
  "case_evidence_attached",
  "oracle_investigation",
  "action",
  "mirror_simulation",
  "authorization",
  "execution",
  "execution_refused",
  "snapshot",
  "policy",
  "model",
  "rule_bundle",
  "correction",
  "api_audit",
];

export function LedgerPage() {
  const { client, can } = useAuth();
  const [params, setParams] = useSearchParams();
  const entryType = params.get("type") ?? "";
  const subject = params.get("subject") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [subjectDraft, setSubjectDraft] = useState(subject);
  const [open, setOpen] = useState<number | null>(null);
  const verify = useAsync(() => client.ledgerVerify(), [client]);
  const audit = can("read_audit");
  const entries = useAsync(
    () => (audit ? client.ledgerEntries({ entry_type: entryType, subject_id: subject, limit: PAGE, offset }) : Promise.resolve(null)),
    [client, audit, entryType, subject, offset],
  );
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    if (k !== "offset") next.delete("offset");
    setParams(next, { replace: true });
  };
  const v = verify.data;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Provenance ledger</h1>
          <div className="sub">Append-only, hash-chained and Ed25519-signed. Every finding, evidence item, decision, simulation, authorization and API mutation is recorded.</div>
        </div>
        <div className="actions">
          <button className="btn primary" onClick={verify.reload} disabled={verify.loading} data-testid="btn-verify">
            {verify.loading ? <span className="spinner" /> : <IconRefresh />} Verify chain now
          </button>
        </div>
      </div>
      {verify.error !== undefined && <ErrorBox error={verify.error} onRetry={verify.reload} />}
      {v && (
        <div className="grid g-main">
          <Panel testId="ledger-verify">
            <div className="row" style={{ gap: 16, alignItems: "center", flexWrap: "nowrap" }}>
              <div style={{ width: 64, height: 64, borderRadius: 14, display: "grid", placeItems: "center", background: v.ok ? "var(--ok-dim)" : "var(--bad-dim)", color: v.ok ? "var(--ok)" : "var(--bad)", border: `1px solid ${v.ok ? "rgba(34,197,94,.4)" : "rgba(239,68,68,.5)"}`, flex: "none" }}>
                {v.ok ? <IconShieldCheck width={34} height={34} /> : <IconAlert width={34} height={34} />}
              </div>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{v.ok ? "Chain verified" : "Integrity failure"}</div>
                <div className="muted">
                  {v.ok
                    ? `All ${fmtNumber(v.entries_checked)} entries re-hashed and every signature verified against the trusted ledger keys.`
                    : `Verification failed at entry #${v.first_bad_seq}: ${v.reason ?? "unknown reason"}. Treat everything after this point as untrusted.`}
                </div>
              </div>
            </div>
            <div className="divider" />
            <div className="grid g-4" style={{ gap: 10 }}>
              <Stat label="Entries" value={fmtNumber(v.entry_count)} />
              <Stat label="Checked" value={fmtNumber(v.entries_checked)} />
              <Stat label="Signed" value={fmtNumber(v.signed_entries)} />
              <Stat label="First bad entry" value={v.first_bad_seq === null ? "none" : `#${v.first_bad_seq}`} />
            </div>
          </Panel>
          <Panel title="Chain head">
            <dl className="kv">
              <dt>Head hash</dt>
              <dd className="mono small" style={{ wordBreak: "break-all" }}>
                {v.head_hash ?? "—"}
              </dd>
              <dt>Trusted keys</dt>
              <dd>
                {v.trusted_ledger_keys.map((k) => (
                  <Badge key={k} tone="info">
                    {k}
                  </Badge>
                ))}
              </dd>
            </dl>
            <div className="small dim" style={{ marginTop: 10 }}>Pin the head hash in your change-management system; any later rewrite of history changes it.</div>
          </Panel>
        </div>
      )}
      {!audit ? (
        <Panel>
          <Empty icon={<IconLock />}>Raw ledger entries require the admin role (permission read_audit). Case timelines show the entries for each case to every reader.</Empty>
        </Panel>
      ) : (
        <Panel
          flush
          title={
            <div className="row">
              <IconChain width={15} height={15} />
              <h3>Entries</h3>
            </div>
          }
          right={
            <div className="row">
              <select className="input" value={entryType} onChange={(e) => set("type", e.target.value)} aria-label="Entry type">
                <option value="">All entry types</option>
                {ENTRY_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  set("subject", subjectDraft.trim());
                }}
              >
                <input className="input mono" placeholder="subject id" value={subjectDraft} onChange={(e) => setSubjectDraft(e.target.value)} style={{ width: 260 }} aria-label="Subject id" />
              </form>
            </div>
          }
        >
          {entries.error !== undefined && (
            <div style={{ padding: 12 }}>
              <ErrorBox error={entries.error} />
            </div>
          )}
          {entries.loading && !entries.data ? (
            <Loading />
          ) : entries.data && entries.data.items.length === 0 ? (
            <Empty>No entries match.</Empty>
          ) : entries.data ? (
            <>
              <div className="table-wrap">
                <table className="t" data-testid="ledger-table">
                  <thead>
                    <tr>
                      <th className="num">Seq</th>
                      <th>Type</th>
                      <th>Subject</th>
                      <th>Recorded</th>
                      <th>Prev hash</th>
                      <th>Entry hash</th>
                      <th>Signer</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.data.items.map((e) => (
                      <Fragment key={e.seq}>
                        <tr className="clickable" onClick={() => setOpen(open === e.seq ? null : e.seq)}>
                          <td className="num mono">{e.seq}</td>
                          <td>
                            <Badge tone={e.entry_type.includes("refused") ? "warn" : e.entry_type === "api_audit" ? "neutral" : "info"}>{e.entry_type}</Badge>
                          </td>
                          <td>
                            <Hash value={e.subject_id} />
                          </td>
                          <td>
                            <Time ts={e.recorded_at} />
                          </td>
                          <td>
                            <Hash value={e.prev_hash} n={6} label="prev" />
                          </td>
                          <td>
                            <Hash value={e.entry_hash} n={6} label="entry" />
                          </td>
                          <td>{e.signature ? <Badge tone="ok">{e.signer_key_id}</Badge> : <Badge tone="warn">unsigned</Badge>}</td>
                        </tr>
                        {open === e.seq && (
                          <tr>
                            <td colSpan={7} style={{ background: "var(--bg-2)" }}>
                              <dl className="kv" style={{ marginBottom: 8 }}>
                                <dt>Payload SHA-256</dt>
                                <dd className="mono small">{e.payload_sha256}</dd>
                                <dt>Signature</dt>
                                <dd className="mono small" style={{ wordBreak: "break-all" }}>
                                  {e.signature ?? "—"}
                                </dd>
                              </dl>
                              <pre className="code">{JSON.stringify(e.payload, null, 2)}</pre>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={entries.data.total} limit={PAGE} offset={offset} onChange={(o) => set("offset", String(o))} />
            </>
          ) : null}
        </Panel>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="small dim">{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700 }} className="mono">
        {value}
      </div>
    </div>
  );
}
