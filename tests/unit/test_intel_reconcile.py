from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.intel import reconcile
from aegis.intel.reconcile import IndicatorIndex
from test_intel_helpers import NOW, campaign, dns, flow, loaded_store, pseudonymizer

T = NOW - timedelta(hours=3)


def _traffic():
    ps = pseudonymizer()
    infected = ps.pseudonym("198.18.10.21")       # same line Shadowserver reported (vo1d)
    return infected, [
        # verified domain contact: resolved, then contacted the answer
        dns(T, infected, "c2.vo1d-emu.example", ["192.0.2.44"]),
        flow(T + timedelta(seconds=2), infected, "192.0.2.44"),
        # lookup only (no contact to the answer)
        dns(T, "p_" + "b" * 32, "sub.c2.vo1d-emu.example", ["192.0.2.45"]),
        # IP hit on an active Feodo C2 from two lines
        flow(T, "p_" + "c" * 32, "192.0.2.15"),
        flow(T + timedelta(minutes=5), "p_" + "d" * 32, "192.0.2.15"),
        # CIDR hit (Spamhaus DROP 203.0.113.128/25)
        flow(T, "p_" + "e" * 32, "203.0.113.200"),
        # stale / expired indicators: offline Feodo C2 and the 2025 ThreatFox domain
        flow(T, "p_" + "f" * 32, "192.0.2.17"),
        dns(T, "p_" + "f" * 32, "old-c2.legacy.example"),
        # benign traffic
        flow(T, "p_" + "a" * 32, "198.51.99.1"),
    ]


def test_seen_stale_and_verified_contacts():
    st = loaded_store()
    infected, events = _traffic()
    rep = reconcile(st, events, now=NOW)
    seen = {(s.type, s.value, s.source_group): s for s in rep.seen}
    vo = seen[("domain", "c2.vo1d-emu.example", "grp:abuse.ch")]
    assert vo.lines == 2 and vo.verified_contact and vo.independent_groups == 2   # abuse.ch + shadowserver
    assert ("domain", "c2.vo1d-emu.example", "grp:shadowserver") in seen
    feodo = seen[("ip", "192.0.2.15", "grp:abuse.ch")]
    assert feodo.lines == 2 and feodo.contacts == 2 and feodo.verified_contact
    assert ("cidr", "203.0.113.128/25", "grp:spamhaus") in seen
    stale = {(s.value, s.state) for s in rep.seen_stale}
    assert ("192.0.2.17", "expired") in stale and ("old-c2.legacy.example", "expired") in stale
    assert all(s.line_pseudonyms is None for s in rep.seen + rep.seen_stale)   # no pseudonyms by default
    assert rep.n_lines == 7 and rep.active_not_seen > 0
    assert rep.summary["stale_indicators_seen"] == 2
    groups = {g.source_group: g for g in rep.groups}
    assert groups["grp:abuse.ch"].stale_seen == 2


def test_lookup_only_is_not_verified():
    st = loaded_store()
    events = [dns(T, "p_" + "b" * 32, "c2.vo1d-emu.example", ["192.0.2.45"])]
    rep = reconcile(st, events, now=NOW)
    assert rep.seen and not any(s.verified_contact for s in rep.seen)


def test_campaign_coverage_found_what_the_feeds_miss():
    st = loaded_store()
    lines = [f"p_{i:032x}" for i in range(12)]
    novel = campaign(["d:beacon.novel-c2.example"], lines, cid="rc-novel")
    covered = campaign(["d:c2.vo1d-emu.example"], lines, cid="rc-covered")
    # feed listed the domain only after AEGIS detected it (ThreatFox first_seen 10-15 00:00; detection 10-14 00:30)
    later = campaign(["d:c2.vo1d-emu.example"], lines, cid="rc-later",
                     window_end=NOW - timedelta(days=6, hours=12))
    stale = campaign(["d:old-c2.legacy.example"], lines, cid="rc-stale")
    shared = campaign(["d:cdn-fronted.novel.example"], lines, cid="rc-shared", shared_hosting_domain=True,
                      destination_ips=["198.51.100.40"])   # the CDN IP is in DROP: must NOT count as coverage
    rep = reconcile(st, [], now=NOW, campaigns=[novel, covered, later, stale, shared])
    cov = {c.campaign_id: c for c in rep.campaigns}
    assert cov["rc-novel"].status == "uncovered"
    assert cov["rc-covered"].status == "covered_before_detection"
    assert cov["rc-later"].status == "covered_after_detection"
    assert cov["rc-later"].lead_time_s == pytest.approx(timedelta(hours=23, minutes=30).total_seconds())
    assert cov["rc-stale"].status == "stale_only"
    assert cov["rc-shared"].status == "uncovered"
    assert set(rep.uncovered_campaigns) == {"rc-novel", "rc-stale", "rc-shared"}
    assert rep.summary["campaigns_without_feed_coverage"] == 3


def test_ip_campaign_covered_by_cidr():
    st = loaded_store()
    c = campaign(["ip:198.51.100.77"], [f"p_{i:032x}" for i in range(6)], cid="rc-ip")
    rep = reconcile(st, [], now=NOW, campaigns=[c])
    assert rep.campaigns[0].status == "covered_before_detection"
    assert rep.campaigns[0].matched[0]["type"] == "cidr"


def test_victim_agreement_counts_only_infections():
    st = loaded_store()
    infected, events = _traffic()
    ps = pseudonymizer()
    camp = campaign(["d:ping.badbox.example"], [ps.pseudonym("198.18.10.22"), "p_" + "9" * 32], cid="rc-bb")
    rep = reconcile(st, events, now=NOW, campaigns=[camp])
    v = rep.victims
    assert v is not None
    assert v.reported_infected_lines == 5                # 3 sinkhole + 2 drone lines
    assert v.reported_exposed_lines == 2                 # telnet scan: exposure, not compromise
    assert v.infected_in_aegis_campaign == 1
    assert v.infected_with_feed_contact == 1             # the vo1d line contacted the C2 domain
    assert v.infected_without_aegis_signal == 3
    assert v.by_family["vo1d"] == 2


def test_tenant_isolation_and_pseudonym_opt_in():
    st = loaded_store()
    with pytest.raises(ValueError):
        reconcile(st, [flow(T, "p_x", "192.0.2.15", tenant="other")], now=NOW)
    with pytest.raises(ValueError):
        reconcile(st, [], now=NOW, campaigns=[campaign(["d:x.example"], ["p_1"], tenant="other")])
    infected, events = _traffic()
    rep = reconcile(st, events, now=NOW, include_pseudonyms=True)
    vo = next(s for s in rep.seen if s.value == "c2.vo1d-emu.example")
    assert infected in (vo.line_pseudonyms or [])


def test_future_indicators_are_invisible():
    st = loaded_store()
    early = NOW - timedelta(days=60)
    rep = reconcile(st, [flow(early, "p_" + "c" * 32, "192.0.2.15")], now=early)
    assert rep.seen == []                                 # Feodo listed it only on 2026-09-01


def test_index_ipv6_and_parent_domains():
    st = loaded_store()
    idx = IndicatorIndex(st.indicators())
    assert any(i.value == "2001:db8:dead::/48" for i in idx.for_ip("2001:db8:dead:1::9"))
    assert idx.for_ip("not-an-ip") == []
    assert any(i.value == "c2.vo1d-emu.example" for i in idx.for_domain("a.b.C2.vo1d-emu.example."))
