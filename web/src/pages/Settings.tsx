import { useAsync } from "../api/hooks";
import type { Permission, Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { IconCheck } from "../components/icons";
import { useTenantStatus } from "../components/status";
import { ModePill } from "../components/StatusPills";
import { Badge, ErrorBox, Hash, Loading, Panel, Time } from "../components/ui";
import { humanize, shortDetector } from "../lib/format";

const MATRIX: Array<[Role, Permission[]]> = [
  ["viewer", ["read"]],
  ["analyst", ["read", "case_work", "investigate", "propose"]],
  ["approver", ["read", "approve", "execute"]],
  ["admin", ["read", "read_audit", "configure"]],
  ["integration", ["ingest"]],
];
const PERMS: Permission[] = ["read", "read_audit", "ingest", "case_work", "investigate", "propose", "approve", "execute", "configure"];

export function SettingsPage() {
  const { client, session } = useAuth();
  const status = useTenantStatus();
  const sources = useAsync(() => client.sources(), [client]);
  const iocs = useAsync(() => client.iocs(), [client]);
  const topo = useAsync(() => client.topology(), [client]);
  const metrics = useAsync(() => client.metrics(), [client]);
  const me = session?.me;

  return (
    <div className="stack">
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <div className="sub">Tenant policy, enforcement mode, data sources and trust anchors. Configuration is changed only through signed artifacts (policy, IOC bundle) loaded by an admin; the console shows what is in force.</div>
        </div>
        <div className="actions">
          <ModePill />
        </div>
      </div>

      <Panel title="Enforcement mode & operator policy" testId="policy-panel">
        {status.policies === undefined ? (
          <Loading />
        ) : status.policies.length === 0 ? (
          <div className="callout warn">No signed operator policy is loaded. Enforcement is refused (fail closed); detection, cases and reports work normally.</div>
        ) : (
          <div className="stack" style={{ gap: 12 }}>
            {status.mode === "shadow" && (
              <div className="callout violet">
                <b>Shadow mode is in force.</b> AEGIS observes, alerts and reports. Proposals can be simulated and assessed, but the deterministic authorization refuses every enforcement action (<code>policy_not_active_mode</code>). Switching to active mode requires a new policy signed by the operator key with <code>mode="active"</code> and a legal signoff reference.
              </div>
            )}
            {status.mode === "active" && (
              <div className="callout bad">
                <b>Active enforcement is authorized</b> by policy <span className="mono">{status.activePolicy?.policy.policy_id}</span> (legal signoff <span className="mono">{status.activePolicy?.policy.legal_signoff_ref}</span>). Each action still requires a SAFE simulation, an allowed authorization and a human approver.
              </div>
            )}
            {status.policies.map(({ policy: p, signature_valid, valid_now }) => (
              <div key={p.policy_id} className="panel" style={{ background: "var(--bg-2)", boxShadow: "none" }}>
                <div className="panel-head">
                  <b className="mono">{p.policy_id}</b>
                  <Badge tone={p.mode === "active" ? "bad" : "violet"} dot>
                    {p.mode}
                  </Badge>
                  {signature_valid ? <Badge tone="ok">signature valid</Badge> : <Badge tone="bad">signature invalid</Badge>}
                  {valid_now ? <Badge tone="ok">in validity window</Badge> : <Badge tone="warn">not valid now</Badge>}
                </div>
                <div className="panel-body">
                  <div className="grid g-3">
                    <dl className="kv">
                      <dt>Allowed actions</dt>
                      <dd>{p.allowed_actions.length ? p.allowed_actions.map((a) => <Badge key={a} tone="neutral">{humanize(a)}</Badge>) : "none"}</dd>
                      <dt>Max targets / action</dt>
                      <dd>{p.max_targets_per_action}</dd>
                      <dt>Max TTL</dt>
                      <dd>{p.max_ttl_hours} h</dd>
                    </dl>
                    <dl className="kv">
                      <dt>Legal signoff</dt>
                      <dd>{p.legal_signoff_ref ? <span className="mono">{p.legal_signoff_ref}</span> : <Badge tone="warn">none</Badge>}</dd>
                      <dt>Valid from</dt>
                      <dd>
                        <Time ts={p.valid_from} seconds={false} />
                      </dd>
                      <dt>Valid until</dt>
                      <dd>
                        <Time ts={p.valid_until} seconds={false} />
                      </dd>
                    </dl>
                    <dl className="kv">
                      <dt>Signer key</dt>
                      <dd className="mono">{p.signer_key_id}</dd>
                      <dt>Signature</dt>
                      <dd>
                        <Hash value={p.signature} n={10} />
                      </dd>
                    </dl>
                  </div>
                  <div className="divider" />
                  <div className="small dim" style={{ marginBottom: 6 }}>Approved scope</div>
                  <pre className="code">{JSON.stringify(p.approved_scope, null, 2)}</pre>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <div className="grid g-2">
        <Panel title="Your session">
          {me && (
            <dl className="kv">
              <dt>Subject</dt>
              <dd className="mono">{me.sub}</dd>
              <dt>Tenant</dt>
              <dd className="mono">{me.tenant_id}</dd>
              <dt>Roles</dt>
              <dd>{me.roles.map((r) => <Badge key={r} tone="info">{r}</Badge>)}</dd>
              <dt>Permissions</dt>
              <dd className="row" style={{ gap: 4 }}>
                {me.permissions.map((p) => (
                  <span key={p} className="chip mono">
                    {p}
                  </span>
                ))}
              </dd>
              <dt>Auth mode</dt>
              <dd>{me.auth_mode}</dd>
              <dt>Token expires</dt>
              <dd>{session?.expiresAt ? <Time ts={new Date(session.expiresAt).toISOString()} /> : "—"}</dd>
            </dl>
          )}
        </Panel>
        <Panel title="Role matrix (separation of duties)" flush>
          <table className="t">
            <thead>
              <tr>
                <th>Role</th>
                {PERMS.map((p) => (
                  <th key={p} style={{ textAlign: "center" }}>
                    {p.replace("_", " ")}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {MATRIX.map(([r, ps]) => (
                <tr key={r} className={me?.roles.includes(r) ? "selected" : ""}>
                  <td>
                    <b>{r}</b>
                  </td>
                  {PERMS.map((p) => (
                    <td key={p} style={{ textAlign: "center", color: "var(--ok)" }}>
                      {ps.includes(p) ? <IconCheck width={13} height={13} /> : <span className="dim">·</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <div className="small dim" style={{ padding: "8px 12px" }}>Approvers cannot approve their own proposals (four-eyes). Admins configure but cannot approve.</div>
        </Panel>
      </div>

      <div className="grid g-3">
        <Panel title="Signed IOC bundle">
          {iocs.error !== undefined ? (
            <ErrorBox error={iocs.error} />
          ) : !iocs.data ? (
            <Loading />
          ) : iocs.data.bundle ? (
            <dl className="kv">
              <dt>Bundle</dt>
              <dd className="mono">{iocs.data.bundle.bundle_id}</dd>
              <dt>Version</dt>
              <dd className="mono">{iocs.data.bundle.version}</dd>
              <dt>Issuer</dt>
              <dd>{iocs.data.bundle.issuer}</dd>
              <dt>Signer</dt>
              <dd className="mono">{iocs.data.bundle.signer_key_id}</dd>
              <dt>Issued</dt>
              <dd>
                <Time ts={iocs.data.bundle.issued_at} seconds={false} />
              </dd>
              <dt>Indicators</dt>
              <dd>
                {iocs.data.bundle.indicators}{" "}
                {Object.entries(iocs.data.bundle.indicator_states).map(([k, v]) => (
                  <Badge key={k} tone={k === "active" ? "ok" : "neutral"}>
                    {v} {k}
                  </Badge>
                ))}
              </dd>
              <dt>SHA-256</dt>
              <dd>
                <Hash value={iocs.data.bundle.sha256} />
              </dd>
            </dl>
          ) : (
            <div className="dim">No IOC bundle loaded: rules contribute nothing; model and anomaly still run.</div>
          )}
        </Panel>
        <Panel title="Operator topology">
          {topo.error !== undefined ? (
            <ErrorBox error={topo.error} />
          ) : !topo.data ? (
            <Loading />
          ) : topo.data.topology ? (
            <dl className="kv">
              <dt>Topology</dt>
              <dd className="mono">{topo.data.topology.topology_id}</dd>
              <dt>Complete</dt>
              <dd>{topo.data.topology.complete ? <Badge tone="ok">yes</Badge> : <Badge tone="warn">no · simulations fail closed</Badge>}</dd>
              <dt>Prefixes</dt>
              <dd>{topo.data.topology.prefixes}</dd>
              <dt>Hosts</dt>
              <dd>{topo.data.topology.hosts}</dd>
              <dt>Shared hosts</dt>
              <dd>{topo.data.topology.shared_hosts}</dd>
              <dt>Domains</dt>
              <dd>{topo.data.topology.domains}</dd>
            </dl>
          ) : (
            <div className="dim">No topology loaded: MIRROR reports UNKNOWN and enforcement is refused.</div>
          )}
        </Panel>
        <Panel title="Detection platform">
          {metrics.data ? (
            <dl className="kv">
              <dt>Detector</dt>
              <dd className="mono" title={metrics.data.detector_version}>
                {shortDetector(metrics.data.detector_version)}
              </dd>
              <dt>Model</dt>
              <dd>{metrics.data.model_loaded ? <Badge tone="ok">loaded</Badge> : <Badge tone="warn">not loaded</Badge>}</dd>
              <dt>LLM</dt>
              <dd>{metrics.data.llm ? <Badge tone="info">advisory</Badge> : <Badge tone="neutral">disabled</Badge>}</dd>
              <dt>Enforcement adapter</dt>
              <dd className="mono">{metrics.data.enforcement_adapter}</dd>
              <dt>Ledger entries</dt>
              <dd>{metrics.data.ledger.entries}</dd>
            </dl>
          ) : metrics.error ? (
            <ErrorBox error={metrics.error} />
          ) : (
            <Loading />
          )}
        </Panel>
      </div>

      <Panel title="Telemetry sources" flush>
        {sources.error !== undefined ? (
          <div style={{ padding: 12 }}>
            <ErrorBox error={sources.error} />
          </div>
        ) : !sources.data ? (
          <Loading />
        ) : (
          <table className="t">
            <thead>
              <tr>
                <th>Source</th>
                <th>Kind</th>
                <th>Vantage</th>
                <th>Entity field</th>
                <th>Collection authorization</th>
                <th className="num">Retention</th>
                <th className="num">Max skew</th>
              </tr>
            </thead>
            <tbody>
              {sources.data.items.map((s) => (
                <tr key={s.source_id}>
                  <td className="mono">{s.source_id}</td>
                  <td>{s.source_kind}</td>
                  <td>{humanize(s.vantage)}</td>
                  <td className="mono">{s.entity_field}</td>
                  <td className="mono">{s.collection_authorization_id}</td>
                  <td className="num">{s.retention_days} d</td>
                  <td className="num">{s.max_clock_skew_s} s</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
