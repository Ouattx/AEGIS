from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from aegis.atlas import (
    Atlas,
    AtlasConflictError,
    EdgeType,
    EvidenceGrade,
    NodeType,
    canonical_node_id,
    indicator_node_id,
    node_key,
    parse_node_id,
)
from aegis.contracts.models import DnsObservation, ObservationEvent, SourceKind, Vantage
from aegis.lab.iocs import build_ioc_bundle, lab_signer
from aegis.lab.topology import generate_topology
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import init_db, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
TEN = "isp-a"


class Clock:
    def __init__(self, t: datetime):
        self.t = t

    def __call__(self) -> datetime:
        return self.t


@pytest.fixture
def sf(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'atlas.db'}")
    init_db(eng)
    yield make_session_factory(eng)
    eng.dispose()


@pytest.fixture
def clock():
    return Clock(T0 + timedelta(hours=1))


@pytest.fixture
def atlas(sf, clock):
    return Atlas(sf, clock=clock, hub_degree_limit=5)


def resolves(atlas, dom, ip, at, prov, grade="B", group="sensor:dns-1", rec=None, ttl=None):
    return atlas.upsert_edge(TEN, node_key("domain", dom), node_key("ip", ip),
                             EdgeType.OBSERVED_RESOLVES_TO, at, prov, grade, group, ttl,
                             recorded_at=rec or at)


# ----------------------------------------------------------------------------- node ids

def test_node_key_normalization():
    assert node_key("domain", "C2.Example.") == "domain:c2.example"
    assert node_key(NodeType.IP, "2001:db8:0:0::1") == "ip:2001:db8::1"
    assert node_key("asn", "AS64500") == "asn:64500"
    assert parse_node_id("domain:A.example") == (NodeType.DOMAIN, "a.example")
    assert canonical_node_id("ip:192.0.2.001".replace("001", "1")) == "ip:192.0.2.1"
    assert indicator_node_id("198.51.100.7") == "ip:198.51.100.7"
    assert indicator_node_id("Bad.Test") == "domain:bad.test"


@pytest.mark.parametrize("bad", ["nocolon", "planet:x", "ip:999.1.1.1", "domain:has space.example",
                                 "asn:ASxyz", "domain:"])
def test_invalid_node_ids_rejected(bad):
    with pytest.raises(ValueError):
        canonical_node_id(bad)


# ----------------------------------------------------------------------------- upserts

def test_upsert_edge_derives_attributes(atlas):
    e = resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    assert e.first_seen == e.last_seen == T0
    assert e.provenance_ids == ["ev-1"]
    assert e.evidence_grade is EvidenceGrade.B
    assert e.independent_source_count == 1
    assert e.ttl_hours == 72 and e.expires_at == T0 + timedelta(hours=72)
    assert e.active and e.enforcement_eligible and e.eligibility_reasons == []

    e2 = resolves(atlas, "c2.example", "192.0.2.10", T0 + timedelta(hours=2), "ev-2",
                  grade="C", group="Feed:Alpha")
    assert e2.edge_id == e.edge_id
    assert e2.first_seen == T0 and e2.last_seen == T0 + timedelta(hours=2)
    assert e2.provenance_ids == ["ev-1", "ev-2"]
    assert e2.evidence_grade is EvidenceGrade.B  # best grade wins
    assert e2.independent_source_count == 2
    assert e2.source_groups == ["feed:alpha", "sensor:dns-1"]
    assert e2.expires_at == T0 + timedelta(hours=74)


def test_upsert_is_idempotent_per_provenance(atlas):
    a = resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    b = resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    assert a == b
    assert b.observation_count == 1
    assert len(atlas.edges(TEN)) == 1


def test_conflicting_redelivery_raises(atlas):
    resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    with pytest.raises(AtlasConflictError):
        resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1", grade="A")
    atlas.upsert_node(TEN, "domain", "x.example", T0, "n-1", attrs={"a": 1})
    with pytest.raises(AtlasConflictError):
        atlas.upsert_node(TEN, "domain", "x.example", T0, "n-1", attrs={"a": 2})


def test_input_validation(atlas):
    with pytest.raises(ValueError):
        resolves(atlas, "a.example", "192.0.2.1", T0, "p", grade="E")
    with pytest.raises(ValueError):
        resolves(atlas, "a.example", "192.0.2.1", T0, "p", ttl=0)
    with pytest.raises(ValueError):
        atlas.upsert_edge(TEN, "domain:a.example", "domain:a.example", "co_observed", T0, "p", "B", "g")
    with pytest.raises(ValueError):
        atlas.upsert_edge(TEN, "domain:a.example", "ip:192.0.2.1", "observed_resolves_to",
                          T0.replace(tzinfo=None), "p", "B", "g")
    with pytest.raises(ValueError):
        atlas.upsert_edge(TEN, "domain:a.example", "ip:192.0.2.1", "not_a_type", T0, "p", "B", "g")


def test_symmetric_co_observed_edges_share_identity(atlas):
    a = atlas.upsert_edge(TEN, "domain:b.example", "domain:a.example", "co_observed", T0, "p1", "B", "g")
    b = atlas.upsert_edge(TEN, "domain:a.example", "domain:b.example", "co_observed", T0, "p2", "B", "g")
    assert a.edge_id == b.edge_id and b.observation_count == 2


def test_tenant_isolation(atlas):
    resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    assert atlas.neighbors("other-tenant", "domain:c2.example") == []
    assert atlas.get_node("other-tenant", "domain:c2.example") is None
    assert atlas.edges("other-tenant") == []


# ----------------------------------------------------------------------------- temporal

def test_as_of_respects_knowledge_and_valid_time(atlas):
    resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1", rec=T0 + timedelta(minutes=5))
    # observed later and learned later
    resolves(atlas, "c2.example", "192.0.2.10", T0 + timedelta(hours=5), "ev-2",
             group="feed:beta", grade="C", rec=T0 + timedelta(hours=6))
    assert atlas.neighbors(TEN, "domain:c2.example", as_of=T0) == []          # not yet known
    early = atlas.neighbors(TEN, "domain:c2.example", as_of=T0 + timedelta(hours=1))
    assert len(early) == 1 and early[0].edge.provenance_ids == ["ev-1"]
    assert early[0].edge.independent_source_count == 1
    # observed at T0+5h but only recorded at T0+6h: invisible at T0+5h30
    mid = atlas.neighbors(TEN, "domain:c2.example", as_of=T0 + timedelta(hours=5, minutes=30))
    assert mid[0].edge.provenance_ids == ["ev-1"]
    late = atlas.neighbors(TEN, "domain:c2.example", as_of=T0 + timedelta(hours=7))
    assert late[0].edge.provenance_ids == ["ev-1", "ev-2"]
    assert late[0].edge.independent_source_count == 2
    node = atlas.get_node(TEN, "domain:c2.example", as_of=T0 + timedelta(hours=1))
    assert node is not None and node.last_seen == T0
    assert atlas.get_node(TEN, "domain:c2.example", as_of=T0 - timedelta(days=1)) is None


def test_ttl_expiry_hides_edges_unless_requested(atlas, clock):
    resolves(atlas, "old.example", "192.0.2.20", T0, "ev-1", ttl=2)
    clock.t = T0 + timedelta(hours=3)
    assert atlas.neighbors(TEN, "domain:old.example") == []
    exp = atlas.neighbors(TEN, "domain:old.example", include_expired=True)
    assert len(exp) == 1 and not exp[0].edge.active
    assert "expired" in exp[0].edge.eligibility_reasons and not exp[0].edge.enforcement_eligible
    # as-of inside the TTL window it was active
    assert atlas.neighbors(TEN, "domain:old.example", as_of=T0 + timedelta(hours=1))[0].edge.active
    # a fresh observation refreshes it
    resolves(atlas, "old.example", "192.0.2.20", T0 + timedelta(hours=3), "ev-2", ttl=2)
    assert atlas.neighbors(TEN, "domain:old.example")[0].edge.active


# ----------------------------------------------------------------------------- eligibility

def test_co_hosting_edges_never_enforcement_eligible(atlas):
    e = atlas.upsert_edge(TEN, "domain:a.example", "domain:b.example", EdgeType.CO_OBSERVED, T0,
                          "p1", "A", "operator:topology")
    e = atlas.upsert_edge(TEN, "domain:a.example", "domain:b.example", EdgeType.CO_OBSERVED, T0,
                          "p2", "A", "feed:other")
    assert e.independent_source_count == 2 and e.evidence_grade is EvidenceGrade.A
    assert e.enforcement_eligible is False
    assert "co_hosting_edge_never_enforcement_eligible" in e.eligibility_reasons


def test_weak_grade_needs_corroboration(atlas):
    att = atlas.upsert_edge(TEN, "domain:c2.example", "malware_family:badbox", "attributed_to", T0,
                            "f1", "C", "grp:alpha")
    assert not att.enforcement_eligible and "insufficient_evidence_grade" in att.eligibility_reasons
    att = atlas.upsert_edge(TEN, "domain:c2.example", "malware_family:badbox", "attributed_to", T0,
                            "f2", "C", "grp:alpha")  # syndicated copy, same group
    assert att.independent_source_count == 1 and not att.enforcement_eligible
    att = atlas.upsert_edge(TEN, "domain:c2.example", "malware_family:badbox", "attributed_to", T0,
                            "f3", "C", "grp:gamma")
    assert att.independent_source_count == 2 and att.enforcement_eligible
    d = atlas.upsert_edge(TEN, "domain:x.example", "malware_family:badbox", "attributed_to", T0,
                          "f4", "D", "grp:a")
    d = atlas.upsert_edge(TEN, "domain:x.example", "malware_family:badbox", "attributed_to", T0,
                          "f5", "D", "grp:b")
    assert not d.enforcement_eligible


def test_shared_hosting_destination_not_eligible(atlas):
    for i in range(3):
        resolves(atlas, f"tenant{i}.example", "198.51.100.50", T0, f"ev-{i}")
    assert atlas.is_shared_hosting(TEN, "ip:198.51.100.50")
    for n in atlas.neighbors(TEN, "ip:198.51.100.50"):
        assert not n.edge.enforcement_eligible
        assert "shared_hosting_destination" in n.edge.eligibility_reasons
    single = resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-x")
    assert single.enforcement_eligible
    assert not atlas.is_shared_hosting(TEN, "domain:c2.example")


def test_shared_hosting_flag_from_node_attrs(atlas):
    atlas.upsert_node(TEN, "ip", "203.0.113.9", T0, "topo-1", attrs={"shared_hosting": True})
    e = resolves(atlas, "only.example", "203.0.113.9", T0, "ev-1")
    assert "shared_hosting_destination" in e.eligibility_reasons


def test_case_reference_edges_not_eligible(atlas):
    e = atlas.link_case(TEN, "case-1", "domain:c2.example", T0, "case-1:c2")
    assert e.edge_type is EdgeType.MENTIONED_IN_CASE and not e.enforcement_eligible


def test_candidate_edges_flagged_investigative_only(atlas):
    c = atlas.add_candidate_edge(TEN, "domain:a.example", "domain:b.example", "co_observed", T0,
                                 "oracle:case-1", rationale="shared neighbour")
    assert c.candidate and c.investigative_only and not c.enforcement_eligible
    assert c.evidence_grade is EvidenceGrade.E
    assert "candidate_link_investigative_only" in c.eligibility_reasons
    assert atlas.neighbors(TEN, "domain:a.example") == []
    assert len(atlas.neighbors(TEN, "domain:a.example", include_candidates=True)) == 1
    with pytest.raises(ValueError):
        atlas.add_candidate_edge(TEN, "domain:a.example", "domain:c.example", "co_observed", T0,
                                 "p", rationale="  ")


# ----------------------------------------------------------------------------- overlinking

def _cdn_world(atlas):
    """One C2 domain fronted by a shared CDN IP with many legit co-tenants, plus dedicated C2."""
    for i in range(10):
        resolves(atlas, f"legit{i}.example", "198.51.100.80", T0, f"cdn-{i}")
    resolves(atlas, "c2-front.example", "198.51.100.80", T0, "c2-front")
    resolves(atlas, "c2-front.example", "192.0.2.66", T0, "c2-ded")
    resolves(atlas, "c2-backup.example", "192.0.2.66", T0, "c2-backup")


def test_related_does_not_expand_through_hubs(atlas):
    _cdn_world(atlas)
    rel = {r.node_id: r for r in atlas.related(TEN, "domain:c2-front.example", max_depth=3)}
    assert rel["ip:198.51.100.80"].hub is True
    assert not any(n.startswith("domain:legit") for n in rel)   # no overlinking via the CDN
    assert "domain:c2-backup.example" in rel                    # reached via dedicated IP
    assert rel["domain:c2-backup.example"].depth == 2
    assert rel["ip:198.51.100.80"].enforcement_eligible_path is False


def test_related_does_not_expand_weak_edges(atlas):
    atlas.upsert_edge(TEN, "domain:a.example", "domain:b.example", "co_observed", T0, "p1", "B", "g")
    resolves(atlas, "b.example", "192.0.2.1", T0, "p2")
    rel = {r.node_id: r for r in atlas.related(TEN, "domain:a.example", max_depth=3)}
    assert rel["domain:b.example"].via_weak_edge
    assert "ip:192.0.2.1" not in rel
    with pytest.raises(ValueError):
        atlas.related(TEN, "domain:a.example", max_depth=0)


def test_candidate_links_exclude_hubs_and_are_investigative(atlas):
    _cdn_world(atlas)
    links = atlas.candidate_links(TEN, "domain:c2-front.example")
    dsts = [c.dst for c in links]
    assert "domain:c2-backup.example" in dsts
    assert not any(d.startswith("domain:legit") for d in dsts)
    for c in links:
        assert c.investigative_only is True and c.enforcement_eligible is False
        assert c.score > 0


# ----------------------------------------------------------------------------- snapshots

def test_snapshot_is_deterministic_and_as_of(atlas, sf):
    resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    s1 = atlas.snapshot(TEN, T0 + timedelta(hours=1))
    assert s1["edge_count"] == 1 and s1["node_count"] == 2
    # later knowledge does not change the historical snapshot
    resolves(atlas, "c2.example", "192.0.2.11", T0 + timedelta(hours=2), "ev-2")
    s2 = atlas.snapshot(TEN, T0 + timedelta(hours=1))
    assert s1["snapshot_hash"] == s2["snapshot_hash"]
    s3 = atlas.snapshot(TEN, T0 + timedelta(hours=3))
    assert s3["snapshot_hash"] != s1["snapshot_hash"]
    # another Atlas instance over the same store computes the same hash
    assert Atlas(sf).snapshot_hash(TEN, T0 + timedelta(hours=1)) == s1["snapshot_hash"]
    assert atlas.verify_snapshot(TEN, s1)
    assert not atlas.verify_snapshot(TEN, {**s1, "snapshot_hash": "0" * 64})
    assert not atlas.verify_snapshot(TEN, {})


def test_record_snapshot_daily_and_ledger_anchor(sf, clock):
    ledger = Ledger(sf, Signer.generate("ledger-k"))
    atlas = Atlas(sf, ledger=ledger, clock=clock)
    resolves(atlas, "c2.example", "192.0.2.10", T0, "ev-1")
    snap = atlas.daily_snapshot(TEN, date(2026, 10, 1))
    again = atlas.daily_snapshot(TEN, date(2026, 10, 1))
    assert snap["snapshot_hash"] == again["snapshot_hash"]
    rows = atlas.snapshots(TEN)
    assert len(rows) == 1 and rows[0]["reason"] == "daily:2026-10-01"
    entries = ledger.entries(TEN, entry_type="atlas_snapshot")
    assert len(entries) == 1 and entries[0].payload["snapshot_hash"] == snap["snapshot_hash"]
    t = atlas.record_snapshot(TEN, reason="case_transition:VERIFIED", subject_id="case-9")
    assert ledger.entries(TEN, subject_id="case-9")[0].payload["snapshot_id"] == t["snapshot_id"]
    assert ledger.verify_chain(TEN)[0]


# ----------------------------------------------------------------------------- consumers

def _dns_event(qname, answers, rcode="NOERROR", eid="e1"):
    return ObservationEvent(event_id=eid, tenant_id=TEN, observed_at=T0, ingested_at=T0,
                            source_id="dns-par1", source_kind=SourceKind.DNS,
                            vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-1",
                            entity_pseudonym="p_x", dns=DnsObservation(qname=qname, rcode=rcode,
                                                                       answers=answers),
                            retention_until=T0 + timedelta(days=30), integrity_sha256="0" * 64)


def test_ingest_event_creates_resolution_edges_idempotently(atlas):
    ev = _dns_event("Cdn.Example.", ["192.0.2.5", "cname.example", "192.0.2.6"])
    out = atlas.ingest_event(ev, recorded_at=T0)
    assert {e.dst for e in out} == {"ip:192.0.2.5", "ip:192.0.2.6"}
    assert all(e.source_groups == ["sensor:dns-par1"] for e in out)
    atlas.ingest_event(ev, recorded_at=T0)
    assert len(atlas.edges(TEN)) == 2
    assert atlas.ingest_event(_dns_event("nx.example", [], rcode="NXDOMAIN", eid="e2")) == []


def test_ingest_signed_ioc_bundle(atlas):
    topo = generate_topology(7)
    signer = lab_signer(7)
    bundle = build_ioc_bundle(topo, start=T0, days=3, seed=7, signer=signer)
    ring = KeyRing()
    ring.add_signer(signer)
    n = atlas.ingest_ioc_bundle(TEN, bundle, ring, now=T0, recorded_at=T0)
    assert n > 0
    attributed = [e for e in atlas.edges(TEN, T0) if e.edge_type is EdgeType.ATTRIBUTED_TO]
    assert attributed
    fams = {e.dst for e in attributed}
    assert "malware_family:badbox2_emu" in fams
    assert "malware_family:legacy_family" not in fams      # expired indicators ignored
    # syndicated copies of alpha's report count once
    for e in attributed:
        assert e.independent_source_count == len(set(e.source_groups))
    benign = [nd for nd in atlas.nodes(TEN, T0) if nd.attrs.get("benign_claim")]
    assert benign
    # idempotent reload
    assert atlas.ingest_ioc_bundle(TEN, bundle, ring, now=T0, recorded_at=T0) == n
    tampered = dict(bundle, issuer="evil")
    with pytest.raises(ValueError):
        atlas.ingest_ioc_bundle(TEN, tampered, ring, now=T0)
    with pytest.raises(ValueError):
        atlas.ingest_ioc_bundle(TEN, bundle, KeyRing(), now=T0)
