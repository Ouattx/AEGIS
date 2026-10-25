"""FlowSpec proposals: RFC 8955 semantics, safe defaults, abstention and router renderings."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from test_egress_detector import CFG, TENANT, VICTIM, ev, flood, run

from aegis.connectors import PROPOSAL_NOTICE, FlowSpecConfig, flowspec_export, propose_flowspec, render
from aegis.connectors.flowspec import ComponentType, FlowSpecAction, FlowSpecMatch, Range
from aegis.egress import EgressDetector

SRC = FlowSpecConfig(source_prefixes=("100.64.0.0/10", "2001:db8::/32"))


def _campaign_report(port_per_bucket: bool = False):
    events = []
    for i in range(3):
        for e in flood(f"p_line0000{i}", range(i, i + 3), 1_500):
            if port_per_bucket:
                e = e.model_copy(update={"flow": e.flow.model_copy(update={"dst_port": 1000 + int(e.observed_at.minute)
                                                                           + 10 * i})})
            events.append(e)
    return run(events)


def _reasons(plan):
    return {s.reason for s in plan.skipped}


def test_corroborated_flood_campaign_gives_one_rate_limit_rule_per_family():
    plan = propose_flowspec(_campaign_report(), SRC)
    assert len(plan.proposals) == 1          # IPv4 victim: only the IPv4 subscriber aggregate applies
    p = plan.proposals[0]
    assert p.status == "proposed" and p.requires_operator_review is True
    assert p.verdict == "malicious" and p.lines_involved == 3 and len(p.campaign_ids) == 1
    assert p.action.kind == "rate_limit" and p.action.rate_bytes_per_s == 1_250_000
    assert p.match.destination == f"{VICTIM}/32" and p.match.source == "100.64.0.0/10"
    assert p.match.protocols == (17,) and [r.numeric_op() for r in p.match.destination_ports] == ["=80"]
    assert p.suggested_expiry - p.created_at == timedelta(hours=4)
    wire = p.rfc8955()
    assert [c["type"] for c in wire["nlri"]] == sorted(c["type"] for c in wire["nlri"])
    assert wire["nlri"][0]["type"] == ComponentType.DESTINATION_PREFIX
    assert wire["extended_communities"][0] == {"type": "0x8006", "name": "traffic-rate-bytes", "as": 0,
                                               "rate_bytes_per_s": 1_250_000.0}


def test_proposal_ids_are_deterministic():
    a = propose_flowspec(_campaign_report(), SRC).proposals[0]
    b = propose_flowspec(_campaign_report(), SRC).proposals[0]
    assert a.proposal_id == b.proposal_id and a.name == f"AEGIS-{a.proposal_id[4:12]}"


def test_randomized_ports_give_no_port_component():
    p = propose_flowspec(_campaign_report(port_per_bucket=True), SRC).proposals[0]
    assert p.match.destination_ports == ()
    assert any("No port component" in c for c in p.caveats)


def test_no_subscriber_prefix_means_no_rule():
    plan = propose_flowspec(_campaign_report(), FlowSpecConfig())
    assert plan.proposals == [] and "source_prefixes_not_configured" in _reasons(plan)


def test_uncorroborated_flood_is_not_proposed_by_default():
    rep = run(flood("p_line00001", range(2), 1_200))
    plan = propose_flowspec(rep, SRC)
    assert plan.proposals == [] and "not_corroborated" in _reasons(plan)
    plan = propose_flowspec(rep, SRC.model_copy(update={"include_suspicious": True}))
    assert len(plan.proposals) == 1 and plan.proposals[0].verdict == "suspicious"


def test_discard_only_when_allowed_and_corroborated():
    rep = _campaign_report()
    assert propose_flowspec(rep, SRC).proposals[0].action.kind == "rate_limit"
    p = propose_flowspec(rep, SRC.model_copy(update={"allow_discard": True})).proposals[0]
    assert p.action.kind == "discard" and p.action.rate_bytes_per_s == 0
    sus = run(flood("p_line00001", range(2), 1_200))
    cfg = SRC.model_copy(update={"allow_discard": True, "include_suspicious": True})
    assert propose_flowspec(sus, cfg).proposals[0].action.kind == "rate_limit"


def test_reflection_requests_are_never_a_flowspec_rule():
    events = [ev("p_line00001", b * 60 + i, f"198.51.100.{i + 1}", 123, bo=300 * 48, bi=0, po=300, pi=0, dur=100)
              for b in range(2) for i in range(12)]
    plan = propose_flowspec(run(events), SRC)
    assert plan.proposals == [] and "spoofed_source_not_matchable" in _reasons(plan)


def test_abused_reflector_gets_a_udp_rate_limit_with_victim_caveat():
    events = [ev("p_line00001", b * 60, VICTIM, 40_000, bo=18_000 * 1_400, bi=18_000 * 50, po=18_000, pi=18_000,
                 dur=60_000) for b in range(3)]
    p = propose_flowspec(run(events), SRC).proposals[0]
    assert p.label == "egress_abused_reflector" and p.match.protocols == (17,) and p.match.destination_ports == ()
    assert any("victim of an open service" in c for c in p.caveats)


def test_shared_infrastructure_target_is_skipped():
    class Ctx:
        def kind(self, ip):
            return "shared_cdn"

    plan = propose_flowspec(_campaign_report(), SRC, context=Ctx())
    assert plan.proposals == [] and "target_on_shared_infrastructure" in _reasons(plan)


def test_abstentions_propagate():
    rep = EgressDetector(tenant_id=TENANT).detect(flood("p_line00001", range(2), 1_200))
    assert _reasons(propose_flowspec(rep, SRC)) == {"report_abstained"}
    uni = [ev("p_line00001", b * 60, VICTIM, 80, bo=72_000 * 512, bi=None, po=72_000, pi=None, dur=60_000)
           for b in range(3)]
    plan = propose_flowspec(run(uni), SRC)
    assert plan.proposals == [] and "verdict_abstain" in _reasons(plan)


def test_max_rules_caps_the_plan():
    events = []
    for t, victim in enumerate(("192.0.2.10", "192.0.2.77")):
        events += [e for i in range(3) for e in flood(f"p_line{t}000{i}", range(3), 1_500, dst=victim)]
    rep = run(events)
    plan = propose_flowspec(rep, SRC.model_copy(update={"max_rules": 1}))
    assert len(plan.proposals) == 1 and "max_rules_exceeded" in _reasons(plan)


def test_models_refuse_unsafe_or_inconsistent_rules():
    with pytest.raises(ValidationError):
        FlowSpecMatch(afi="ipv4", destination="0.0.0.0/0", source="100.64.0.0/10")
    with pytest.raises(ValidationError):
        FlowSpecMatch(afi="ipv4", destination="2001:db8::1/128", source="100.64.0.0/10")
    with pytest.raises(ValidationError):
        FlowSpecMatch(afi="ipv4", destination="192.0.2.1/32", source="100.64.0.0/10", protocols=(1,),
                      destination_ports=(Range(lo=80, hi=80),))
    with pytest.raises(ValidationError):
        Range(lo=10, hi=5)
    with pytest.raises(ValidationError):
        FlowSpecAction(kind="rate_limit", rate_bytes_per_s=0)
    with pytest.raises(ValidationError):
        FlowSpecConfig(source_prefixes=("0.0.0.0/0",))
    assert Range(lo=1000, hi=2000).numeric_op() == ">=1000&<=2000"


@pytest.mark.parametrize("syntax,needles", [
    ("junos", ["set routing-options flow route AEGIS-", "match destination 192.0.2.10/32",
               "match source 100.64.0.0/10", "match protocol udp", "match destination-port 80",
               "then rate-limit 10000000"]),
    ("iosxr", ["class-map type traffic match-all AEGIS-", "match destination-address ipv4 192.0.2.10 255.255.255.255",
               "match source-address ipv4 100.64.0.0 255.192.0.0", "police rate 10000 kbps",
               "service-policy type pbr AEGIS-PROPOSALS"]),
    ("exabgp", ["flow {", "destination 192.0.2.10/32;", "source 100.64.0.0/10;", "destination-port [ =80 ];",
                "rate-limit 1250000;"]),
])
def test_renderings_are_labelled_proposals(syntax, needles):
    plan = propose_flowspec(_campaign_report(), SRC)
    text = render(plan.proposals, syntax)
    assert text.splitlines()[0].endswith(PROPOSAL_NOTICE)
    assert "caveat:" in text
    for n in needles:
        assert n in text, n


def test_ipv6_rendering_and_render_edge_cases():
    m = FlowSpecMatch(afi="ipv6", destination="2001:db8:1::5", source="2001:db8::/32", protocols=(6,))
    plan = propose_flowspec(_campaign_report(), SRC)
    p6 = plan.proposals[0].model_copy(update={"match": m})
    assert "set routing-options rib inet6.0 flow route" in render([p6], "junos")
    assert "match destination-address ipv6 2001:db8:1::5/128" in render([p6], "iosxr")
    assert p6.rfc8955()["rfc"] == "RFC 8956"
    assert render([], "junos") == ""
    with pytest.raises(ValueError):
        render(plan.proposals, "cisco-ios")  # type: ignore[arg-type]


def test_flowspec_export_payload_is_a_proposal():
    plan = propose_flowspec(_campaign_report(), SRC, now=datetime(2026, 10, 1, 1, tzinfo=timezone.utc))
    pl = flowspec_export(plan, "junos")
    assert pl.proposal is True and pl.connector == "flowspec.junos" and pl.records == 1
    assert pl.tenant_id == TENANT and len(pl.sha256) == 64
    assert CFG.min_flow_records == 1


def test_onset_only_evidence_has_no_rule_inputs():
    events = []
    for i in range(4):
        events += flood(f"p_line0000{i}", range(0, 6), 1) + flood(f"p_line0000{i}", range(6, 7), 800)
    plan = propose_flowspec(run(events), SRC.model_copy(update={"include_suspicious": True}))
    assert plan.proposals == [] and _reasons(plan) == {"no_rule_inputs"}
