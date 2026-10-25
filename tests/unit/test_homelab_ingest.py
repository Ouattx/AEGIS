"""AEGIS home lab: dnsmasq parsing, single-home sources, capture import, usage windows.

Fixtures are synthetic: hand-written dnsmasq lines and Zeek/dnsmasq files from
``aegis.homelab.synthetic`` (reserved names and documentation address ranges only).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis.contracts.models import SourceKind, Vantage
from aegis.homelab import (
    CaptureError,
    HomeLabConfig,
    SyntheticBoxSpec,
    discover_capture,
    import_capture,
    load_usage_windows,
    parse_dnsmasq_log,
    single_home_sources,
    write_synthetic_capture,
)
from aegis.homelab.dnsmasq import DnsmasqLogParser, records_to_jsonl
from aegis.homelab.usage import UsageWindowError, UsageWindows
from aegis.ingest.normalize import normalize
from aegis.ingest.parsers import parse_dns_jsonl
from aegis.ingest.pseudonym import Pseudonymizer

START = datetime(2026, 10, 20, 6, tzinfo=timezone.utc)
KEY = b"homelab-test-key-0123456789abcdef"


@pytest.fixture(scope="module")
def capture_dir(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("cap")
    write_synthetic_capture(d, SyntheticBoxSpec(start=START, hours=8, nxdomain_burst=True,
                                                sessions=((1.0, 1.0), (5.0, 1.0))))
    return d


@pytest.fixture(scope="module")
def imported(capture_dir):
    return import_capture(capture_dir, HomeLabConfig(device_labels={"10.42.0.23": "test box"}),
                          pseudonymizer=Pseudonymizer(KEY))


# ============================================================================ dnsmasq

EXTRA_LOG = """\
Oct 20 06:00:01 dnsmasq[812]: 1 10.42.0.23/40001 query[A] sync.example-c2.test from 10.42.0.23
Oct 20 06:00:01 dnsmasq[812]: 1 10.42.0.23/40001 forwarded sync.example-c2.test to 192.0.2.53
Oct 20 06:00:01 dnsmasq[812]: 1 10.42.0.23/40001 reply sync.example-c2.test is 198.51.100.77
Oct 20 06:00:02 dnsmasq[812]: 2 10.42.0.23/40002 query[A] www.example from 10.42.0.23
Oct 20 06:00:02 dnsmasq[812]: 2 10.42.0.23/40002 reply www.example is <CNAME>
Oct 20 06:00:02 dnsmasq[812]: 2 10.42.0.23/40002 reply edge.cdn.example is 192.0.2.10
Oct 20 06:00:02 dnsmasq[812]: 2 10.42.0.23/40002 reply edge.cdn.example is 192.0.2.11
Oct 20 06:00:03 dnsmasq[812]: 3 10.42.0.23/40003 query[A] nope.test from 10.42.0.23
Oct 20 06:00:03 dnsmasq[812]: 3 10.42.0.23/40003 reply nope.test is NXDOMAIN
Oct 20 06:00:04 dnsmasq[812]: 4 10.42.0.23/40004 query[AAAA] v4only.example from 10.42.0.23
Oct 20 06:00:04 dnsmasq[812]: 4 10.42.0.23/40004 reply v4only.example is NODATA-IPv6
Oct 20 06:00:05 dnsmasq[812]: 5 10.42.0.23/40005 query[A] slow.example from 10.42.0.23
Oct 20 06:00:05 dnsmasq[812]: 5 10.42.0.23/40005 forwarded slow.example to 192.0.2.53
Oct 20 06:00:06 dnsmasq-dhcp[812]: DHCPACK(wlan0) 10.42.0.23 02:00:00:00:00:01 box
Oct 20 06:00:07 dnsmasq[812]: 6 127.0.0.1/50000 query[A] upstream.example from 127.0.0.1
this line is not dnsmasq output
"""


def test_dnsmasq_extra_format_ties_replies_to_queries():
    p = DnsmasqLogParser(year=2026)
    recs = list(p.parse(EXTRA_LOG))
    by = {r["qname"]: r for r in recs}
    assert by["sync.example-c2.test"]["answers"] == ["198.51.100.77"]
    assert by["sync.example-c2.test"]["rcode"] == "NOERROR"
    assert by["sync.example-c2.test"]["src_ip"] == "10.42.0.23"
    assert by["sync.example-c2.test"]["observed_at"] == "2026-10-20T06:00:01+00:00"
    assert by["www.example"]["answers"] == ["192.0.2.10", "192.0.2.11"]       # CNAME chain belongs to the query
    assert by["nope.test"]["rcode"] == "NXDOMAIN" and by["nope.test"]["answers"] == []
    assert by["v4only.example"]["rcode"] == "NOERROR" and by["v4only.example"]["qtype"] == "AAAA"
    assert by["slow.example"]["rcode"] is None                                # never invented
    assert p.stats.dhcp_lines == 1 and p.stats.unparsed_lines == 1 and p.stats.queries == 6
    assert p.stats.unanswered == 2
    # integrity covers every original line used
    assert by["www.example"]["_raw"].count(b"\n") == 3


def test_dnsmasq_plain_format_and_cname_fallback():
    log = ("Oct 20 06:00:01 dnsmasq[9]: query[A] a.example from 10.42.0.30\n"
           "Oct 20 06:00:01 dnsmasq[9]: forwarded a.example to 192.0.2.53\n"
           "Oct 20 06:00:01 dnsmasq[9]: reply a.example is <CNAME>\n"
           "Oct 20 06:00:01 dnsmasq[9]: reply b.cdn.example is 192.0.2.20\n"
           "Oct 20 06:00:09 dnsmasq[9]: query[A] c.example from 10.42.0.30\n"
           "Oct 20 06:00:09 dnsmasq[9]: cached c.example is 192.0.2.21\n")
    recs = parse_dnsmasq_log(log, year=2026)
    assert [r["answers"] for r in recs] == [["192.0.2.20"], ["192.0.2.21"]]


def test_dnsmasq_timezone_year_rollover_and_iso_prefix():
    log = ("Dec 31 23:59:59 dnsmasq[9]: query[A] x.example from 10.42.0.30\n"
           "Jan  1 00:00:01 dnsmasq[9]: query[A] y.example from 10.42.0.30\n"
           "2026-10-20T08:00:00+02:00 pi dnsmasq[9]: query[A] z.example from 10.42.0.30\n")
    recs = parse_dnsmasq_log(log, year=2025, tz="Europe/Paris")
    assert recs[0]["observed_at"] == "2025-12-31T22:59:59+00:00"
    assert recs[1]["observed_at"] == "2025-12-31T23:00:01+00:00"            # 2026-01-01 00:00:01 CET
    assert recs[2]["observed_at"] == "2026-10-20T06:00:00+00:00"


def test_dnsmasq_jsonl_roundtrip_through_ingest_normalization():
    recs = parse_dnsmasq_log(EXTRA_LOG, year=2026)
    text = records_to_jsonl(recs)
    raws = list(parse_dns_jsonl(text))
    assert len(raws) == len(recs)
    src = single_home_sources(HomeLabConfig())["homelab-dnsmasq"]
    now = datetime(2026, 10, 21, tzinfo=timezone.utc)
    events = [normalize(r, src, Pseudonymizer(KEY), now) for r in raws[:6]]
    assert events[0].dns.answers == ["198.51.100.77"]
    unanswered = [e for e in events if e.dns.qname == "slow.example"][0]
    assert unanswered.dns.rcode == "UNKNOWN"                                   # explicit, not NOERROR
    assert all(e.entity_pseudonym.startswith("p_") for e in events)


# ============================================================================ config / sources

def test_config_rejects_public_subnet_and_outside_gateway():
    with pytest.raises(ValueError):
        HomeLabConfig(lab_subnet="8.8.8.0/24", gateway_ip="8.8.8.1")
    with pytest.raises(ValueError):
        HomeLabConfig(lab_subnet="10.42.0.0/24", gateway_ip="10.43.0.1")
    cfg = HomeLabConfig()
    assert cfg.is_lab_client("10.42.0.23") and not cfg.is_lab_client("10.42.0.1")
    assert not cfg.is_lab_client("198.51.100.1") and not cfg.is_lab_client(None)
    for ip in ("10.42.0.1", "239.255.255.250", "224.0.0.251", "255.255.255.255", "169.254.1.1", "10.42.0.255"):
        assert cfg.is_local_destination(ip), ip
    assert not cfg.is_local_destination("198.51.100.77")


def test_single_home_sources_are_per_device_and_scoped_to_the_lab():
    srcs = single_home_sources(HomeLabConfig(tenant_id="lab-a", collection_authorization_id="consent-1"))
    assert set(srcs) == {"homelab-zeek-conn", "homelab-zeek-dns", "homelab-dnsmasq"}
    for s in srcs.values():
        assert s.tenant_id == "lab-a" and s.collection_authorization_id == "consent-1"
        assert s.vantage == Vantage.DEVICE and s.entity_field == "src_ip"
        assert s.subscriber_prefixes == ("10.42.0.0/24",)
    assert srcs["homelab-zeek-conn"].source_kind == SourceKind.ZEEK_CONN
    assert srcs["homelab-dnsmasq"].source_kind == SourceKind.DNS


# ============================================================================ import

def test_import_produces_pseudonymous_events_and_accounting(imported, capture_dir):
    imp = imported
    assert imp.events and imp.synthetic
    assert all(e.tenant_id == "homelab" and e.entity_pseudonym and e.entity_pseudonym.startswith("p_")
               for e in imp.events)
    assert all(e.flow is None or e.flow.src_ip is None for e in imp.events)       # no raw lab IP kept
    dumped = json.dumps([e.model_dump(mode="json") for e in imp.events])
    assert "10.42.0.23" not in dumped
    assert list(imp.devices.values()) == ["test box"]
    times = [e.observed_at for e in imp.events]
    assert times == sorted(times)
    assert imp.start == START and imp.end == START + timedelta(hours=8)
    assert imp.quarantined == 0
    # SSDP and DNS to the access point are lab-local chatter, not infrastructure
    assert imp.prefilter["local_chatter_flows"] > 0
    chatter = next(iter(imp.local_chatter.values())).to_dict()
    assert {p for p, _ in chatter["top_ports"]} == {53, 1900} and chatter["multicast_flows"] > 0
    assert not any(e.flow is not None and e.flow.dst_ip in ("10.42.0.1", "239.255.255.250") for e in imp.events)
    # every input file hashed; Zeek dns.log found but not used while the dnsmasq log feeds DNS
    kinds = {f.kind: f for f in imp.files}
    assert kinds["zeek_dns"].used is False and kinds["dnsmasq_log"].used
    conn = kinds["zeek_conn"]
    assert conn.sha256 == hashlib.sha256(Path(conn.path).read_bytes()).hexdigest()
    assert {f.kind for f in imp.files} >= {"capture_manifest", "usage_windows"}


def test_import_with_zeek_dns_instead_of_dnsmasq(capture_dir):
    imp = import_capture(capture_dir, HomeLabConfig(dns_source="zeek"), pseudonymizer=Pseudonymizer(KEY))
    kinds = {f.kind: f.used for f in imp.files}
    assert kinds["zeek_dns"] and not kinds["dnsmasq_log"]
    assert any(e.dns is not None and e.source_id == "homelab-zeek-dns" for e in imp.events)


def test_import_quarantines_bad_lines_skips_inbound_and_clips_window(tmp_path):
    write_synthetic_capture(tmp_path, SyntheticBoxSpec(start=START, hours=7, sessions=((1.0, 1.0),)))
    conn = tmp_path / "zeek" / "conn.log"
    lines = conn.read_text().splitlines()
    fields = next(line for line in lines if line.startswith("#fields")).split("\t")[1:]
    ok_row = next(line for line in lines if not line.startswith("#")
                  and line.split("\t")[4] not in ("10.42.0.1", "239.255.255.250"))
    inbound = ok_row.split("\t")
    inbound[2], inbound[4] = "198.51.100.9", "10.42.0.23"                     # remote -> lab client
    late = ok_row.split("\t")
    late[0] = f"{(START + timedelta(days=2)).timestamp():.6f}"                # outside capture.json window
    extra = ["garbage\twith\ttoo few columns", "\t".join(inbound), "\t".join(late)]
    conn.write_text("\n".join(lines[:-1] + extra + lines[-1:]) + "\n")
    assert len(fields) == len(inbound)
    imp = import_capture(tmp_path, HomeLabConfig(), pseudonymizer=Pseudonymizer(KEY))
    assert imp.quarantined == 1 and imp.quarantine_reasons == {"column_count": 1}
    assert imp.prefilter["inbound_to_lab_client"] == 1
    assert imp.prefilter["outside_capture_window"] == 1
    zeek_stats = next(s for s in imp.ingest if s["source_id"] == "homelab-zeek-conn")
    assert zeek_stats["skip_reasons"] == {"return_flow": 1}           # never attributed to the remote host
    assert all(e.observed_at <= imp.end + timedelta(minutes=1) for e in imp.events)


def test_discover_and_empty_capture(tmp_path, capture_dir):
    paths = discover_capture(capture_dir)
    assert paths.manifest and paths.usage and paths.zeek_conn and paths.zeek_dns and paths.dnsmasq
    assert all(p.name != "dnsmasq.log" for p in paths.zeek_dns)
    with pytest.raises(CaptureError):
        import_capture(tmp_path, pseudonymizer=Pseudonymizer(KEY))
    with pytest.raises(CaptureError):
        discover_capture(tmp_path / "missing")


def test_pseudonyms_are_stable_per_key_and_differ_across_keys(capture_dir):
    a = import_capture(capture_dir, pseudonymizer=Pseudonymizer(KEY))
    b = import_capture(capture_dir, pseudonymizer=Pseudonymizer(KEY))
    c = import_capture(capture_dir, pseudonymizer=Pseudonymizer(b"another-key-0123456789abcdef-xyz"))
    assert list(a.devices) == list(b.devices) != list(c.devices)


# ============================================================================ usage windows

def test_usage_windows_formats_and_complement(tmp_path):
    js = tmp_path / "usage.json"
    js.write_text(json.dumps({"active": [["2026-10-20T08:00:00+02:00", "2026-10-20T09:00:00+02:00"]]}))
    u = load_usage_windows(js)
    r = u.resolved(START.timestamp(), (START + timedelta(hours=4)).timestamp())
    assert r.active == ((START.timestamp(), START.timestamp() + 3600),)
    assert r.idle == ((START.timestamp() + 3600, START.timestamp() + 4 * 3600),)
    assert list(r.state_of([START.timestamp() + 10, START.timestamp() + 7200, START.timestamp() - 5])) == [1, 0, -1]
    csv_text = "start,end,state\n2026-10-20T06:00:00Z,2026-10-20T07:00:00Z,active\n" \
               "2026-10-20T08:00:00Z,2026-10-20T09:00:00Z,idle\n"
    u2 = load_usage_windows(csv_text)
    r2 = u2.resolved(START.timestamp(), (START + timedelta(hours=4)).timestamp())
    assert r2.idle_explicit and r2.idle_s == 3600 and r2.active_s == 3600
    listed = load_usage_windows([{"start": "2026-10-20T06:00:00Z", "end": "2026-10-20T06:30:00Z"}])
    assert len(listed.active) == 1 and listed.idle is None


@pytest.mark.parametrize("bad", [
    {"active": [["2026-10-20T06:00:00", "2026-10-20T07:00:00"]]},                    # no timezone
    {"active": [["2026-10-20T07:00:00Z", "2026-10-20T06:00:00Z"]]},                  # end before start
    {"active": [["2026-10-20T06:00:00Z", "2026-10-20T08:00:00Z"]],
     "idle": [["2026-10-20T07:00:00Z", "2026-10-20T09:00:00Z"]]},                    # overlap
    [{"start": "2026-10-20T06:00:00Z", "end": "2026-10-20T07:00:00Z", "state": "watching"}],
])
def test_usage_windows_refuse_ambiguous_input(bad):
    with pytest.raises(UsageWindowError):
        load_usage_windows(bad)


def test_usage_windows_roundtrip():
    u = UsageWindows(active=((START.timestamp(), START.timestamp() + 60),))
    assert load_usage_windows(u.to_dict() | {"idle": None}).active == u.active
