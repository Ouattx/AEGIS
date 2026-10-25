import type { Case, InvestigationReport } from "../../api/types";
import { Badge, Panel } from "../../components/ui";

/** Primary hypothesis against the alternatives the analyst must rule out. */
export function HypothesisPanel({ c, report }: { c: Case; report: InvestigationReport | undefined }) {
  const alts = report?.alternative_hypotheses.length
    ? report.alternative_hypotheses
    : c.alternative_hypotheses.map((t) => ({ title: t, rationale: "", plausibility: "", discriminating_tests: [], source: "case" }));
  return (
    <Panel title="Hypothesis vs alternatives" right={c.counter_hypothesis_reviewed ? <Badge tone="ok">review recorded{c.reviewer ? ` · ${c.reviewer}` : ""}</Badge> : <Badge tone="warn">review required</Badge>} testId="hypothesis">
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) minmax(0, 1.4fr)", gap: 14 }}>
        <div className="callout bad" style={{ color: "var(--text)" }}>
          <div className="small" style={{ color: "#fca5a5", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6 }}>
            Primary hypothesis
          </div>
          {c.hypothesis}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <div className="small" style={{ color: "var(--text-3)", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase" }}>
            Alternative (benign) explanations — {alts.length}
          </div>
          {alts.map((a) => (
            <details key={a.title} className="cg">
              <summary className="cg-head" style={{ listStyle: "none" }}>
                <span className="cg-title" style={{ flex: 1 }}>
                  {a.title}
                </span>
                {a.plausibility && <Badge tone={a.plausibility === "high" ? "warn" : a.plausibility === "medium" ? "info" : "neutral"}>{a.plausibility} plausibility</Badge>}
              </summary>
              {(a.rationale || a.discriminating_tests.length > 0) && (
                <div className="cg-body" style={{ paddingLeft: 12 }}>
                  {a.rationale && <div className="muted">{a.rationale}</div>}
                  {a.discriminating_tests.length > 0 && (
                    <>
                      <div className="small dim" style={{ marginTop: 6 }}>Discriminating tests</div>
                      <ul style={{ margin: "2px 0 0", paddingLeft: 18, color: "var(--text-2)" }}>
                        {a.discriminating_tests.map((t) => (
                          <li key={t}>{t}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
              )}
            </details>
          ))}
        </div>
      </div>
    </Panel>
  );
}
