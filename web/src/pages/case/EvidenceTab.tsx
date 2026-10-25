import { Fragment, useMemo, useState } from "react";
import type { EvidenceAssessment, EvidenceView } from "../../api/types";
import { GroupChip, groupColor, kindLabel } from "../../components/domain";
import { IconCheck, IconX } from "../../components/icons";
import { Badge, Empty, Hash, Panel, Time } from "../../components/ui";

/**
 * Evidence trail: every item with its content hash, integrity verification and its
 * source-independence group. Items in the same group are syndicated and count once.
 */
export function EvidenceTab({ items, assessment }: { items: EvidenceView[]; assessment: EvidenceAssessment }) {
  const [open, setOpen] = useState<string | null>(null);
  const qualifying = useMemo(() => new Set(assessment.qualifying_evidence_ids), [assessment]);
  const signed = useMemo(() => new Set(assessment.signed_ioc_hit_ids), [assessment]);
  const groups = useMemo(() => {
    const m = new Map<string, EvidenceView[]>();
    for (const it of items) {
      const g = it.evidence.source_independence_group;
      m.set(g, [...(m.get(g) ?? []), it]);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [items]);

  if (!items.length) return <Empty>No evidence attached.</Empty>;
  return (
    <div className="stack">
      <div className="grid g-4">
        <div className="panel kpi" style={{ ["--kpi-accent" as string]: "#22c55e" }}>
          <div className="k-label">Independent supporting origins</div>
          <div className="k-value">{assessment.supporting_origins.length}</div>
          <div className="k-foot">{assessment.supporting_origins.map((o) => <GroupChip key={o} group={o} />)}</div>
        </div>
        <div className="panel kpi" style={{ ["--kpi-accent" as string]: "#38bdf8" }}>
          <div className="k-label">Qualifying items</div>
          <div className="k-value">
            {assessment.qualifying_evidence_ids.length}
            <small>/ {items.length}</small>
          </div>
          <div className="k-foot">notes, graph links and agent arguments never qualify</div>
        </div>
        <div className="panel kpi" style={{ ["--kpi-accent" as string]: "#a78bfa" }}>
          <div className="k-label">Signed IOC hits</div>
          <div className="k-value">{assessment.signed_ioc_hit_ids.length}</div>
          <div className="k-foot">verified against trusted bundle signer</div>
        </div>
        <div className="panel kpi" style={{ ["--kpi-accent" as string]: assessment.contradicting_origins.length ? "#ef4444" : "#64748b" }}>
          <div className="k-label">Contradicting origins</div>
          <div className="k-value">{assessment.contradicting_origins.length}</div>
          <div className="k-foot">{assessment.contested ? <Badge tone="warn">contested</Badge> : "not contested"}</div>
        </div>
      </div>
      {assessment.verification_blockers.length > 0 && (
        <div className="callout warn">
          <b>Verification blockers:</b> {assessment.verification_blockers.join(", ")}
        </div>
      )}
      <Panel title="Source-independence groups" right={<span className="small dim">items sharing a group are syndicated and counted once</span>}>
        <div style={{ display: "flex", height: 10, borderRadius: 5, overflow: "hidden", marginBottom: 10 }}>
          {groups.map(([g, xs]) => (
            <div key={g} title={`${g}: ${xs.length}`} style={{ flex: xs.length, background: groupColor(g) }} />
          ))}
        </div>
        <div className="row">
          {groups.map(([g, xs]) => (
            <span key={g} className="row" style={{ gap: 4 }}>
              <GroupChip group={g} /> <span className="mono small dim">×{xs.length}</span>
            </span>
          ))}
        </div>
      </Panel>
      <Panel title="Evidence trail" flush>
        <div className="table-wrap">
          <table className="t" data-testid="evidence-table">
            <thead>
              <tr>
                <th>Kind</th>
                <th>Summary</th>
                <th>Group</th>
                <th>SHA-256</th>
                <th>Integrity</th>
                <th>Role</th>
                <th>Collected</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => {
                const e = it.evidence;
                const isOpen = open === e.evidence_id;
                return (
                  <Fragment key={e.evidence_id}>
                    <tr className="clickable" onClick={() => setOpen(isOpen ? null : e.evidence_id)}>
                      <td className="nowrap">
                        <b>{kindLabel(e.kind)}</b>
                        {signed.has(e.evidence_id) && (
                          <>
                            {" "}
                            <Badge tone="violet">signed</Badge>
                          </>
                        )}
                      </td>
                      <td style={{ maxWidth: 440 }}>
                        <div className="ellipsis" title={e.summary}>
                          {e.summary}
                        </div>
                        <div className="small dim mono ellipsis">{e.origin_source}</div>
                      </td>
                      <td>
                        <GroupChip group={e.source_independence_group} />
                      </td>
                      <td>
                        <Hash value={e.sha256} label="sha256" />
                      </td>
                      <td>
                        {it.integrity_verified ? (
                          <span className="row" style={{ gap: 4, color: "#4ade80" }}>
                            <IconCheck width={13} height={13} /> verified
                          </span>
                        ) : (
                          <span className="row" style={{ gap: 4, color: "#f87171" }}>
                            <IconX width={13} height={13} /> FAILED
                          </span>
                        )}
                        {it.superseded_by && <div className="small dim">superseded</div>}
                      </td>
                      <td>
                        {!e.supports ? <Badge tone="ok">contradicts</Badge> : qualifying.has(e.evidence_id) ? <Badge tone="info">qualifying</Badge> : <Badge tone="neutral">context</Badge>}
                      </td>
                      <td>
                        <Time ts={e.collected_at} seconds={false} />
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)" }}>
                          <div className="grid g-2" style={{ gap: 12 }}>
                            <dl className="kv">
                              <dt>Evidence id</dt>
                              <dd>
                                <Hash value={e.evidence_id} n={12} />
                              </dd>
                              <dt>SHA-256</dt>
                              <dd className="mono small">{e.sha256}</dd>
                              <dt>Origin</dt>
                              <dd className="mono">{e.origin_source}</dd>
                              <dt>License</dt>
                              <dd>{e.license}</dd>
                              <dt>Collection authorization</dt>
                              <dd className="mono">{e.authorization_id}</dd>
                              {e.artifact_ref && (
                                <>
                                  <dt>Artifact</dt>
                                  <dd className="mono">{e.artifact_ref}</dd>
                                </>
                              )}
                              {it.superseded_by && (
                                <>
                                  <dt>Superseded by</dt>
                                  <dd>
                                    <Hash value={it.superseded_by} />
                                  </dd>
                                </>
                              )}
                            </dl>
                            <pre className="code">{JSON.stringify(e.payload, null, 2)}</pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
