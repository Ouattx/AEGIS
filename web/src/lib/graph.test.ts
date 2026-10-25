import { describe, expect, it } from "vitest";
import type { GraphView } from "../api/types";
import { layout, mergeViews, seedsFromEvidence } from "./graph";

const edge = (id: string, src: string, dst: string, extra: Partial<GraphView["neighbors"][0]["edge"]> = {}) => ({
  edge_id: id, src, dst, edge_type: "observed_resolves_to", first_seen: "", last_seen: "", evidence_grade: "B",
  independent_source_count: 1, source_groups: [], observation_count: 1, active: true, candidate: false,
  investigative_only: false, enforcement_eligible: true, eligibility_reasons: [], attrs: {}, ...extra,
});

const view = (id: string, type: string, neighbors: GraphView["neighbors"], candidates: GraphView["candidate_links"] = [], shared = false): GraphView => ({
  node: { tenant_id: "t", node_id: id, node_type: type, value: id.split(":")[1], first_seen: "", last_seen: "", attrs: {}, provenance_ids: [] },
  shared_hosting: shared, degree: neighbors.length, neighbors, truncated: false, candidate_links: candidates, as_of: null,
});

describe("graph", () => {
  const a = view("domain:evil.example", "domain", [
    { node_id: "ip:203.0.113.53", node_type: "ip", direction: "out", edge: edge("e1", "domain:evil.example", "ip:203.0.113.53") },
    { node_id: "malware_family:x", node_type: "malware_family", direction: "out", edge: edge("e2", "domain:evil.example", "malware_family:x", { edge_type: "attributed_to", enforcement_eligible: false }) },
  ], [{ src: "domain:evil.example", dst: "domain:other.example", score: 0.46, method: "adamic_adar", shared_neighbors: [], rationale: "", investigative_only: true, enforcement_eligible: false }]);
  const b = view("ip:203.0.113.53", "ip", [
    { node_id: "domain:evil.example", node_type: "domain", direction: "in", edge: edge("e1", "domain:evil.example", "ip:203.0.113.53") },
  ], [{ src: "domain:other.example", dst: "domain:evil.example", score: 0.46, method: "adamic_adar", shared_neighbors: [], rationale: "", investigative_only: true, enforcement_eligible: false }], true);

  it("merges neighbourhoods without duplicate nodes or edges", () => {
    const g = mergeViews([a, b]);
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["domain:evil.example", "domain:other.example", "ip:203.0.113.53", "malware_family:x"]);
    expect(g.edges.filter((e) => !e.candidate).map((e) => e.id).sort()).toEqual(["e1", "e2"]);
    const cand = g.edges.filter((e) => e.candidate);
    expect(cand).toHaveLength(1); // the same pair reported from both ends counts once
    expect(cand[0]).toMatchObject({ investigativeOnly: true, enforcementEligible: false });
    expect(g.nodes.find((n) => n.id === "ip:203.0.113.53")).toMatchObject({ seed: true, shared: true });
    expect(g.nodes.find((n) => n.id === "malware_family:x")).toMatchObject({ seed: false, type: "malware_family", label: "x" });
  });

  it("caps the node count", () => {
    const g = mergeViews([a, b], 2);
    expect(g.nodes).toHaveLength(2);
    expect(g.edges.every((e) => g.nodes.some((n) => n.id === e.source) && g.nodes.some((n) => n.id === e.target))).toBe(true);
  });

  it("lays out deterministically inside the box", () => {
    const g1 = layout(mergeViews([a, b]), 600, 400);
    const g2 = layout(mergeViews([a, b]), 600, 400);
    expect(g1.nodes.map((n) => [n.x, n.y])).toEqual(g2.nodes.map((n) => [n.x, n.y]));
    for (const n of g1.nodes) {
      expect(n.x).toBeGreaterThanOrEqual(40);
      expect(n.x).toBeLessThanOrEqual(560);
      expect(n.y).toBeGreaterThanOrEqual(40);
      expect(n.y).toBeLessThanOrEqual(360);
    }
    const single = layout(mergeViews([view("ip:1.2.3.4", "ip", [])]), 600, 400);
    expect(single.nodes[0]).toMatchObject({ x: 300, y: 200 });
  });

  it("derives seeds from IOC matches and top destinations", () => {
    const seeds = seedsFromEvidence([
      { kind: "observation", payload: { top_destinations: [{ dst_ip: "198.18.1.1", flows: 4 }, { dst_ip: "203.0.113.53" }] } },
      { kind: "ioc_match", payload: { indicator_type: "domain", indicator_value: "Evil.Example", resolved_ips: ["203.0.113.53"] } },
      { kind: "ioc_match", payload: { indicator_type: "ip", indicator_value: "203.0.113.53" } },
      { kind: "model_score", payload: {} },
    ]);
    expect(seeds).toEqual(["domain:evil.example", "ip:203.0.113.53", "ip:198.18.1.1"]);
  });
});
