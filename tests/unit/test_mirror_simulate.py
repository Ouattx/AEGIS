from __future__ import annotations

from datetime import timedelta

import pytest
from test_mirror_helpers import (
    C2_DOMAIN,
    C2_IP,
    CDN_IP,
    CDN_NAMES,
    LEGIT_API,
    RESOLVER_IP,
    T0,
    TENANT,
    VICTIM_IP,
    action,
    session_factory,
    topology,
)

from aegis.atlas.graph import Atlas
from aegis.contracts.models import (
    ActionType,
    DnsObservation,
    FlowObservation,
    MirrorVerdict,
    ObservationEvent,
    SourceKind,
    Vantage,
)
from aegis.lab.topology import generate_topology
from aegis.mirror import AggregateTrafficHistory, TopologyView, simulate


def history() -> AggregateTrafficHistory:
    h = AggregateTrafficHistory()
    h.set_window(TENANT, 2)
    for i in range(6):
        h.add(TENANT, C2_IP, flows=10, entity=f"p_dev{i:06d}")
        h.add(TENANT, C2_DOMAIN, flows=4, entity=f"p_dev{i:06d}")
    for i in range(40):
        h.add(TENANT, CDN_IP, flows=50, entity=f"p_viewer{i:05d}")
    h.add(TENANT, LEGIT_API, flows=300, entity="p_phone000001")
    h.add(TENANT, "fw.tvbox.example", flows=20, entity="p_tv0000001")
    return h


def test_lab_topology_satisfies_protocol():
    assert isinstance(topology(), TopologyView)
    assert isinstance(generate_topology(7), TopologyView)


# ------------------------------------------------------------------ IP block

def test_dedicated_c2_ip_block_is_safe_with_case_indicator():
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), None, history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.SAFE
    assert r.legitimate_cotenants == []
    assert r.shared_infrastructure is False
    assert r.affected_entities == 6
    assert r.historic_daily_legit_flows == 0
    assert r.reversibility == "minutes"
    assert r.computed_at == T0
    # graph not attached => advisory unknown => human approval
    assert "graph_unavailable" in r.unknowns
    assert r.requires_human_approval is True


def test_dedicated_ip_hostname_counts_as_collateral_without_case_link():
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE
    assert r.legitimate_cotenants == [C2_DOMAIN]


def test_shared_cdn_ip_block_is_unsafe_with_cotenants_and_flows():
    r = simulate(action(ActionType.IP_BLOCK, [CDN_IP]), topology(), None, history(), now=T0,
                 case_indicators=["img.bad.example"])
    assert r.verdict is MirrorVerdict.UNSAFE
    assert r.shared_infrastructure is True
    assert set(r.legitimate_cotenants) == set(CDN_NAMES) - {"img.bad.example"}
    assert "img.bad.example" not in r.legitimate_cotenants
    assert r.historic_daily_legit_flows == 1000      # 40*50 flows over 2 days
    assert r.affected_entities == 40
    assert r.requires_human_approval is True
    assert "legitimate co-tenant" in r.rationale


def test_lab_shared_cdn_never_safe():
    topo = generate_topology(7)
    bb = topo.malicious["badbox2_emu"]
    cdn = next(ip for ip, h in topo.hosts.items() if "img.tvsync-update.example" in h.hostnames)
    r = simulate(action(ActionType.IP_BLOCK, [cdn]), topo, None, None, now=T0,
                 case_indicators=bb.c2_domains + bb.cohosted_domains)
    assert r.verdict is MirrorVerdict.UNSAFE
    assert len(r.legitimate_cotenants) >= 20
    dedicated = simulate(action(ActionType.IP_BLOCK, [bb.c2_ips[0]]), topo, None, None, now=T0,
                         case_indicators=bb.c2_domains)
    assert dedicated.verdict is MirrorVerdict.SAFE


@pytest.mark.parametrize("ip,needle", [(RESOLVER_IP, "critical_infrastructure"),
                                       (VICTIM_IP, "attack_victim_not_a_target")])
def test_critical_and_victim_hosts_unsafe(ip, needle):
    r = simulate(action(ActionType.IP_BLOCK, [ip]), topology(), None, history(), now=T0,
                 case_indicators=["resolver.isp.example", "shop0.victim-hosting.example"])
    assert r.verdict is MirrorVerdict.UNSAFE
    assert needle in r.rationale


def test_ip_outside_topology_is_unknown():
    r = simulate(action(ActionType.IP_BLOCK, ["8.8.8.8"]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNKNOWN
    assert "ip_not_in_topology:8.8.8.8" in r.unknowns
    assert r.historic_daily_legit_flows is None


# ------------------------------------------------------------------ fail closed

def test_incomplete_topology_fails_closed():
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(complete=False), None, history(),
                 now=T0, case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.UNKNOWN
    assert "topology_incomplete" in r.unknowns
    assert r.requires_human_approval is True
    assert r.historic_daily_legit_flows is None


def test_missing_topology_fails_closed():
    r = simulate(action(), None, None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNKNOWN
    assert "topology_unavailable" in r.unknowns


def test_unknown_domain_fails_closed():
    r = simulate(action(targets=["never-seen.example"]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNKNOWN
    assert "domain_footprint_unknown:never-seen.example" in r.unknowns


def test_graph_failure_fails_closed():
    class Broken:
        def __getattr__(self, name):
            def boom(*a, **k):
                raise RuntimeError("db down")
            return boom

    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), Broken(), history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.UNKNOWN
    assert any(u.startswith("graph_query_failed") for u in r.unknowns)


@pytest.mark.parametrize("targets", [["not a domain"], ["bad.example; rm -rf"], ["*.x.example"],
                                     ["1.2.3.4"], []])
def test_invalid_or_empty_dns_targets_unsafe(targets):
    r = simulate(action(targets=targets), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE


def test_invalid_ip_target_unsafe():
    r = simulate(action(ActionType.IP_BLOCK, ["10.0.0.0/8"]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE


# ------------------------------------------------------------------ DNS sinkhole

def test_exact_sinkhole_of_cohosted_malicious_name_is_safe():
    r = simulate(action(targets=["img.bad.example"]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.SAFE
    assert r.legitimate_cotenants == []
    assert r.historic_daily_legit_flows == 0
    assert "shared infrastructure" in r.rationale


def test_sinkhole_of_known_legit_service_unsafe():
    r = simulate(action(targets=[LEGIT_API]), topology(), None, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE
    assert LEGIT_API in r.legitimate_cotenants
    assert r.historic_daily_legit_flows == 150


def test_wildcard_sinkhole_catches_legit_subdomain():
    act = action(targets=["tvbox.example"], scope={"include_subdomains": True})
    r = simulate(act, topology(), None, history(), now=T0, case_indicators=["api.tvbox.example"])
    assert r.verdict is MirrorVerdict.UNSAFE
    assert r.legitimate_cotenants == ["fw.tvbox.example"]
    assert r.shared_infrastructure is True
    assert r.historic_daily_legit_flows == 10


def test_affected_entities_from_history_and_missing_history():
    r = simulate(action(), topology(), None, history(), now=T0)
    assert r.affected_entities == 6
    r2 = simulate(action(), topology(), None, None, now=T0)
    assert r2.affected_entities is None
    assert "traffic_history_unavailable" in r2.unknowns
    assert r2.requires_human_approval is True
    other = AggregateTrafficHistory()
    other.set_window("other-tenant", 1)
    r3 = simulate(action(), topology(), None, other, now=T0)
    assert r3.affected_entities is None
    assert "traffic_history_does_not_cover_tenant" in r3.unknowns


def test_large_blast_radius_requires_human():
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), None, history(), now=T0,
                 case_indicators=[C2_DOMAIN], max_affected_entities=5)
    assert r.verdict is MirrorVerdict.SAFE
    assert any(u.startswith("large_blast_radius") for u in r.unknowns)
    assert r.requires_human_approval


def test_history_from_events():
    def ev(i, dst=None, q=None, ent="p_aaaaaaaa01"):
        return ObservationEvent(
            tenant_id=TENANT, observed_at=T0 + timedelta(hours=i), ingested_at=T0,
            source_id="s", source_kind=SourceKind.NETFLOW if dst else SourceKind.DNS,
            vantage=Vantage.DEVICE, collection_authorization_id="auth",
            entity_pseudonym=ent, device_class="android_tv",
            flow=FlowObservation(dst_ip=dst) if dst else None,
            dns=DnsObservation(qname=q) if q else None,
            retention_until=T0 + timedelta(days=30), integrity_sha256="0" * 64)

    events = [ev(0, dst=C2_IP), ev(1, dst=C2_IP, ent="p_aaaaaaaa02"), ev(2, q="C2.Bad.Example.")]
    h = AggregateTrafficHistory.from_events(events, start=T0, end=T0 + timedelta(days=2))
    assert h.daily_flows(TENANT, C2_IP) == 1.0
    assert h.distinct_entities(TENANT, C2_IP) == 2
    assert h.daily_flows(TENANT, C2_DOMAIN) == 0.5
    assert h.daily_flows(TENANT, "unseen.example") == 0
    assert h.daily_flows("nobody", C2_IP) is None


# ------------------------------------------------------------------ device controls

def test_device_quarantine_always_needs_human():
    act = action(ActionType.DEVICE_QUARANTINE, ["p_abcdef123456"])
    r = simulate(act, None, None, None, now=T0)
    assert r.verdict is MirrorVerdict.SAFE
    assert r.affected_entities == 1
    assert r.requires_human_approval is True
    assert "entities_behind_line_unknown" in r.unknowns
    assert r.historic_daily_legit_flows is None
    notify = simulate(action(ActionType.NOTIFY_SUBSCRIBER, ["p_abcdef123456"],
                             scope={"vantage": "device"}), None, None, None, now=T0)
    assert notify.reversibility == "manual"
    assert notify.requires_human_approval


def test_device_target_must_be_pseudonym():
    r = simulate(action(ActionType.DEVICE_QUARANTINE, ["subscriber-42@isp"]), None, None, None,
                 now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE


# ------------------------------------------------------------------ ATLAS integration

def _atlas(tmp_path) -> Atlas:
    return Atlas(session_factory(tmp_path), clock=lambda: T0)


def test_atlas_reveals_extra_cotenants_on_dedicated_ip(tmp_path):
    atlas = _atlas(tmp_path)
    for i, name in enumerate(["c2.bad.example", "blog.innocent.example"]):
        atlas.upsert_edge(TENANT, f"domain:{name}", f"ip:{C2_IP}", "observed_resolves_to",
                          T0 - timedelta(hours=2), f"prov-{i}", "B", "sensor:resolver",
                          recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), atlas, history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.UNSAFE
    assert r.legitimate_cotenants == ["blog.innocent.example"]
    assert "graph_unavailable" not in r.unknowns


def test_atlas_attributed_names_are_not_collateral(tmp_path):
    atlas = _atlas(tmp_path)
    atlas.upsert_edge(TENANT, "domain:c2.bad.example", "malware_family:badbox2_emu",
                      "attributed_to", T0 - timedelta(hours=2), "prov-attr", "A", "feed:x",
                      recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), atlas, history(), now=T0)
    assert r.verdict is MirrorVerdict.SAFE
    assert r.legitimate_cotenants == []


def test_atlas_shared_hosting_flag_marks_shared(tmp_path):
    atlas = _atlas(tmp_path)
    for i in range(3):
        atlas.upsert_edge(TENANT, f"domain:site{i}.example", f"ip:{C2_IP}",
                          "observed_resolves_to", T0 - timedelta(hours=2), f"p{i}", "B", "s",
                          recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), atlas, history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.shared_infrastructure is True
    assert r.verdict is MirrorVerdict.UNSAFE


def test_atlas_knowledge_after_now_is_ignored(tmp_path):
    atlas = _atlas(tmp_path)
    atlas.upsert_edge(TENANT, "domain:late.innocent.example", f"ip:{C2_IP}",
                      "observed_resolves_to", T0 + timedelta(hours=1), "late", "B", "s",
                      recorded_at=T0 + timedelta(hours=2))
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), atlas, history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.SAFE


def test_atlas_dependent_domain_blocks_sinkhole(tmp_path):
    atlas = _atlas(tmp_path)
    atlas.upsert_edge(TENANT, "domain:shop.customer.example", "domain:img.bad.example",
                      "observed_resolves_to", T0 - timedelta(hours=2), "cname", "B", "s",
                      recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(targets=["img.bad.example"]), topology(), atlas, history(), now=T0)
    assert r.verdict is MirrorVerdict.UNSAFE
    assert "shop.customer.example" in r.legitimate_cotenants


def test_atlas_known_domain_counts_as_footprint(tmp_path):
    atlas = _atlas(tmp_path)
    atlas.upsert_node(TENANT, "domain", "dga-abc.test", T0 - timedelta(hours=2), "n1",
                      recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(targets=["dga-abc.test"]), topology(), atlas, history(), now=T0)
    assert r.verdict is MirrorVerdict.SAFE


def test_simulation_is_tenant_scoped(tmp_path):
    atlas = _atlas(tmp_path)
    atlas.upsert_edge("other-tenant", "domain:blog.innocent.example", f"ip:{C2_IP}",
                      "observed_resolves_to", T0 - timedelta(hours=2), "x", "B", "s",
                      recorded_at=T0 - timedelta(hours=1))
    r = simulate(action(ActionType.IP_BLOCK, [C2_IP]), topology(), atlas, history(), now=T0,
                 case_indicators=[C2_DOMAIN])
    assert r.verdict is MirrorVerdict.SAFE
