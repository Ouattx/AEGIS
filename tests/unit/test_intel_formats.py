from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.intel import FeedParseError, get_spec, parse_feed
from aegis.intel.formats import (
    classify_host,
    is_shared_platform,
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    parse_feed_time,
)
from test_intel_helpers import FEEDS, NOW, pseudonymizer


def by_value(result):
    return {(i.type, i.value): i for i in result.indicators}


# ---------------------------------------------------------------------------- normalization

def test_normalization_refuses_unroutable_space_and_over_broad_prefixes():
    assert normalize_ip(" 192.0.2.7 ") == "192.0.2.7"
    assert normalize_ip("2001:DB8::1") == "2001:db8::1"
    for bad in ("10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "224.0.0.1",
                "fe80::1", "::1", "fd00::1"):
        with pytest.raises(ValueError):
            normalize_ip(bad)
    assert normalize_cidr("198.51.100.0/24") == ("cidr", "198.51.100.0/24")
    assert normalize_cidr("192.0.2.9/32") == ("ip", "192.0.2.9")
    with pytest.raises(ValueError):
        normalize_cidr("0.0.0.0/0")
    with pytest.raises(ValueError):
        normalize_cidr("64.0.0.0/4")
    with pytest.raises(ValueError):
        normalize_cidr("10.0.0.0/8")
    assert normalize_domain("C2.Example.") == "c2.example"
    for bad in ("localhost", "bad host.example", "-x.example", "1.2.3.4"):
        with pytest.raises(ValueError):
            normalize_domain(bad)
    assert classify_host("[2001:db8::5]") == ("ip", "2001:db8::5")
    with pytest.raises(ValueError):
        classify_host("10.0.0.1")
    assert is_shared_platform("raw.githubusercontent.com")
    assert is_shared_platform("bucket.s3.amazonaws.com")
    assert not is_shared_platform("update-cdn.badbox.example")
    assert is_shared_platform("files.myhost.example", extra=["myhost.example"])


def test_feed_time_spellings():
    assert parse_feed_time("2026-10-20 12:00:00").isoformat() == "2026-10-20T12:00:00+00:00"
    assert parse_feed_time("2026-10-20 12:00:00 UTC").hour == 12
    assert parse_feed_time("2026-10-20").hour == 0
    assert parse_feed_time("Tue, 20 Oct 2026 10:00:00 GMT").hour == 10
    assert parse_feed_time("1792490400").isoformat() == "2026-10-20T10:00:00+00:00"
    assert parse_feed_time("") is None and parse_feed_time(None) is None
    with pytest.raises(ValueError):
        parse_feed_time("yesterday")


# ---------------------------------------------------------------------------- URLhaus

def test_urlhaus_hosts_offline_shared_platform_and_bad_rows():
    r = parse_feed(FEEDS / "urlhaus_recent.csv", get_spec("feed:urlhaus"), NOW)
    v = by_value(r)
    assert set(v) == {("ip", "198.51.100.23"), ("domain", "update-cdn.badbox.example"),
                      ("domain", "files.payload.test")}
    ip = v[("ip", "198.51.100.23")]
    # two URLs on one host merge into one indicator with the widest lifecycle
    assert ip.first_seen.isoformat() == "2026-10-19T08:00:00+00:00"
    assert ip.last_seen.isoformat() == "2026-10-20T11:30:00+00:00"
    assert ip.expires_at == ip.last_seen + timedelta(days=30)
    assert ip.malware_family == "mirai" and ip.threat_label == "malware_distribution"
    assert ip.license == "CC0-1.0" and ip.redistributable and ip.source_group == "grp:abuse.ch"
    assert len(ip.references) == 2
    off = v[("domain", "files.payload.test")]
    assert "offline" in off.tags and off.confidence < ip.confidence
    assert r.skipped["shared_platform_url"] == 1           # raw.githubusercontent.com never listed
    assert len(r.errors) == 2                                # private IP and malformed host
    assert r.generated_at is not None and r.generated_at.hour == 12
    assert not any("github" in i.value for i in r.indicators)


def test_urlhaus_extra_shared_platform_and_wrong_format():
    r = parse_feed(FEEDS / "urlhaus_recent.csv", get_spec("feed:urlhaus"), NOW,
                   extra_shared_platforms=["badbox.example"])
    assert ("domain", "update-cdn.badbox.example") not in by_value(r)
    with pytest.raises(FeedParseError):
        parse_feed("a,b\n1,2\n", get_spec("feed:urlhaus"), NOW)


# ---------------------------------------------------------------------------- ThreatFox

def test_threatfox_types_confidence_and_skips():
    r = parse_feed(FEEDS / "threatfox_recent.json", get_spec("feed:threatfox"), NOW)
    v = by_value(r)
    ip = v[("ip", "203.0.113.50")]
    assert ip.confidence == 0.9 and ip.threat_label == "c2_beaconing" and "port:8443" in ip.tags
    dom = v[("domain", "c2.vo1d-emu.example")]
    assert dom.confidence == 0.75 and dom.last_seen == dom.first_seen   # last_seen null in feed
    assert v[("domain", "update-cdn.badbox.example")].threat_label == "malware_distribution"
    assert r.skipped["non_network_ioc"] == 1 and r.skipped["shared_platform_url"] == 1
    assert v[("domain", "old-c2.legacy.example")].state(NOW) == "expired"


def test_threatfox_api_format_and_errors():
    body = ('{"query_status": "ok", "data": [{"id": "5", "ioc": "gate.c2.example", "ioc_type": "domain", '
            '"threat_type": "botnet_cc", "malware_printable": "X", "confidence_level": 60, '
            '"first_seen": "2026-10-19 00:00:00 UTC", "last_seen": null, "tags": null},'
            '{"id": "6", "ioc": "10.0.0.1:80", "ioc_type": "ip:port"}, "junk"]}')
    r = parse_feed(body, get_spec("feed:threatfox"), NOW)
    assert [i.value for i in r.indicators] == ["gate.c2.example"]
    assert r.indicators[0].references == ("threatfox:5",)
    assert len(r.errors) == 2
    with pytest.raises(FeedParseError):
        parse_feed("not json", get_spec("feed:threatfox"), NOW)


# ---------------------------------------------------------------------------- Feodo

def test_feodo_csv_snapshot_semantics():
    r = parse_feed(FEEDS / "feodo_ipblocklist.csv", get_spec("feed:feodo"), NOW)
    v = by_value(r)
    online = v[("ip", "192.0.2.15")]
    assert online.last_seen == r.generated_at              # listed as online at generation time
    assert online.malware_family == "qakbot" and "port:443" in online.tags
    offline = v[("ip", "192.0.2.17")]
    assert "offline" in offline.tags and offline.state(NOW) == "expired"


def test_feodo_plain_text():
    r = parse_feed(FEEDS / "feodo_ipblocklist.txt", get_spec("feed:feodo_txt"), NOW)
    assert [i.value for i in r.indicators] == ["192.0.2.15", "192.0.2.16"]
    r2 = parse_feed("192.0.2.1\nnot-an-ip\n10.0.0.1\n", get_spec("feed:feodo_txt"), NOW)
    assert len(r2.indicators) == 1 and len(r2.errors) == 2


# ---------------------------------------------------------------------------- Spamhaus

def test_spamhaus_text_json_and_edrop():
    spec = get_spec("feed:spamhaus_drop")
    txt = parse_feed(FEEDS / "spamhaus_drop.txt", spec, NOW)
    v = by_value(txt)
    assert ("cidr", "198.51.100.0/24") in v and ("cidr", "2001:db8:dead::/48") in v
    assert ("ip", "192.0.2.200") in v                     # /32 collapsed to an IP indicator
    assert len(txt.errors) == 1                           # 10.0.0.0/8 refused
    assert txt.generated_at.isoformat() == "2026-10-20T10:00:00+00:00"
    assert v[("cidr", "198.51.100.0/24")].references == ("spamhaus:SBL900001",)
    assert not v[("cidr", "198.51.100.0/24")].redistributable
    js = parse_feed(FEEDS / "spamhaus_drop_v4.json", spec, NOW)
    assert {i.value for i in js.indicators} == {"198.51.100.0/24", "203.0.113.128/25"}
    assert js.generated_at == txt.generated_at
    ed = parse_feed(FEEDS / "spamhaus_edrop.txt", get_spec("feed:spamhaus_edrop"), NOW)
    assert [i.value for i in ed.indicators] == ["192.0.2.128/26"]


# ---------------------------------------------------------------------------- Shadowserver

def test_shadowserver_sinkhole_pseudonymizes_victims_and_never_keeps_raw_addresses():
    ps = pseudonymizer()
    r = parse_feed(FEEDS / "shadowserver_event4_sinkhole_http.csv", get_spec("feed:shadowserver"), NOW,
                   report_type="event4_sinkhole_http", pseudonymizer=ps)
    assert {i.value for i in r.indicators} == {"c2.vo1d-emu.example", "ping.badbox.example"}
    assert all("sinkholed" in i.tags for i in r.indicators)
    assert "192.0.2.99" not in {i.value for i in r.indicators}   # sinkhole IP is not malicious
    assert r.skipped["sinkhole_infrastructure"] == 4
    assert len(r.victims) == 4 and all(v.kind == "infection" for v in r.victims)
    assert {v.line_pseudonym for v in r.victims} == {ps.pseudonym("198.18.10.21"), ps.pseudonym("198.18.10.22"),
                                                       ps.pseudonym("198.18.10.23")}
    dumped = repr(r)
    assert "198.18.10." not in dumped                      # raw subscriber address never retained


def test_shadowserver_without_pseudonymizer_drops_victims():
    r = parse_feed(FEEDS / "shadowserver_event4_sinkhole_http.csv", get_spec("feed:shadowserver"), NOW,
                   report_type="event4_sinkhole_http", pseudonymizer=None)
    assert r.victims == [] and r.skipped["victim_dropped_no_pseudonymizer"] == 4
    assert "198.18.10." not in repr(r)


def test_shadowserver_drone_and_scan_reports():
    ps = pseudonymizer()
    drone = parse_feed(FEEDS / "shadowserver_botnet_drone.csv", get_spec("feed:shadowserver"), NOW,
                       report_type="botnet_drone", pseudonymizer=ps)
    assert {(i.type, i.value) for i in drone.indicators} == {("ip", "203.0.113.50"),
                                                             ("domain", "gate.drone-c2.test")}
    assert {v.malware_family for v in drone.victims} == {"mirai", "gafgyt"}
    scan = parse_feed(FEEDS / "shadowserver_scan_telnet.csv", get_spec("feed:shadowserver"), NOW,
                      report_type="scan_telnet", pseudonymizer=ps)
    assert scan.indicators == []                           # an open port is not an indicator
    assert all(v.kind == "exposure" for v in scan.victims) and len(scan.victims) == 2
    with pytest.raises(ValueError):
        parse_feed(FEEDS / "shadowserver_scan_telnet.csv", get_spec("feed:shadowserver"), NOW)


def test_parser_limits_and_naive_now():
    from datetime import datetime

    from aegis.intel.formats import parse_urlhaus_csv
    with pytest.raises(FeedParseError):
        parse_urlhaus_csv(b"\xff\xfe\x00bad", get_spec("feed:urlhaus"), NOW)
    with pytest.raises(ValueError):
        parse_feed("", get_spec("feed:urlhaus"), datetime(2026, 1, 1))  # noqa: DTZ001
