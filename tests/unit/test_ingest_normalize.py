from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import ObservationEvent, SourceKind, Vantage
from aegis.ingest.normalize import NormalizationError, SourceConfig, normalize, parse_timestamp
from aegis.ingest.pseudonym import Pseudonymizer

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
PSEUDO = Pseudonymizer(b"k" * 32)


def src(kind=SourceKind.NETFLOW, **kw):
    base = dict(tenant_id="t1", source_id="s1", source_kind=kind, vantage=Vantage.DEVICE,
                collection_authorization_id="auth-1")
    base.update(kw)
    return SourceConfig(**base)


def flow_raw(**kw):
    r = {"record_type": "flow", "observed_at": "2026-10-01T12:00:00.250Z", "device_id": "02:aa:bb:cc:dd:ee",
         "device_class": "Android-TV", "src_ip": "100.64.0.1", "src_port": "40000", "dst_ip": "198.18.0.5",
         "dst_port": "443", "protocol": "6", "bytes_out": "1000", "bytes_in": None, "packets_out": "3",
         "packets_in": "4", "duration_ms": "1500", "_raw": b"original,line", "_line_no": 2}
    r.update(kw)
    return r


def dns_raw(**kw):
    r = {"record_type": "dns", "observed_at": 1790856000.5, "device_id": "02:aa:bb:cc:dd:ee",
         "qname": "Foo.Example.", "qtype": 28, "rcode": "nxdomain", "answers": None, "_raw": b"{}"}
    r.update(kw)
    return r


def test_flow_normalization():
    ev = normalize(flow_raw(), src(), PSEUDO, NOW, event_id="e1", raw_artifact_ref="raw://s1/f#L2")
    assert ev.event_id == "e1" and ev.tenant_id == "t1" and ev.source_kind == SourceKind.NETFLOW
    assert ev.observed_at == datetime(2026, 10, 1, 12, 0, 0, 250000, tzinfo=timezone.utc)
    assert ev.ingested_at == NOW
    assert ev.entity_pseudonym == PSEUDO.pseudonym("02:aa:bb:cc:dd:ee")
    assert ev.device_class == "android_tv"
    f = ev.flow
    assert f is not None and f.src_ip is None  # subscriber IP is never carried
    assert (f.dst_ip, f.dst_port, f.protocol, f.bytes_out, f.bytes_in, f.duration_ms) == (
        "198.18.0.5", 443, "tcp", 1000, None, 1500)
    assert ev.integrity_sha256 == sha256_hex(b"original,line")
    assert ev.retention_until == ev.observed_at + timedelta(days=30)
    # the fast construction path yields a model identical to a fully validated one
    again = ObservationEvent.model_validate_json(ev.model_dump_json(), strict=True)
    assert again == ev and again.model_dump() == ev.model_dump()


def test_missing_values_stay_none():
    ev = normalize(flow_raw(bytes_out=None, packets_out=None, duration_ms=None, dst_port=None, protocol=None),
                   src(), PSEUDO, NOW)
    assert ev.flow.bytes_out is None and ev.flow.packets_out is None and ev.flow.duration_ms is None
    assert ev.flow.dst_port is None and ev.flow.protocol == "other"


def test_dns_normalization_and_explicit_unknowns():
    ev = normalize(dns_raw(), src(SourceKind.DNS), PSEUDO, NOW)
    assert ev.dns.qname == "foo.example" and ev.dns.qtype == "AAAA" and ev.dns.rcode == "NXDOMAIN"
    assert ev.dns.answers == [] and ev.flow is None
    ev2 = normalize(dns_raw(qtype=None, rcode=None, answers="1.2.3.4, 5.6.7.8"), src(SourceKind.DNS), PSEUDO, NOW)
    assert ev2.dns.qtype == "UNKNOWN" and ev2.dns.rcode == "UNKNOWN"  # never defaulted to A / NOERROR
    assert ev2.dns.answers == ["1.2.3.4", "5.6.7.8"]
    ev3 = normalize(dns_raw(rcode=3, qtype="65", answers=[{"data": "x.example"}]), src(SourceKind.DNS), PSEUDO, NOW)
    assert ev3.dns.rcode == "NXDOMAIN" and ev3.dns.qtype == "HTTPS" and ev3.dns.answers == ["x.example"]
    ev4 = normalize(dns_raw(qname="bücher.example", qtype=999, rcode=99), src(SourceKind.DNS), PSEUDO, NOW)
    assert ev4.dns.qname == "xn--bcher-kva.example" and ev4.dns.qtype == "TYPE999" and ev4.dns.rcode == "RCODE99"


def test_duration_seconds_and_epoch_ms():
    ev = normalize(flow_raw(duration_ms=None, duration_s="0.25", observed_at="1790856000250"), src(), PSEUDO, NOW)
    assert ev.flow.duration_ms == 250
    assert ev.observed_at == datetime.fromtimestamp(1790856000.25, tz=timezone.utc)


@pytest.mark.parametrize("field,value,code", [
    ("observed_at", None, "missing_timestamp"),
    ("observed_at", "yesterday", "bad_timestamp"),
    ("observed_at", "2026-10-01T00:00:00", "naive_timestamp"),
    ("observed_at", "2099-01-01T00:00:00Z", "future_timestamp"),
    ("observed_at", True, "bad_timestamp"),
    ("observed_at", "20261001", "bad_timestamp"),
    ("dst_ip", None, "missing_dst_ip"),
    ("dst_ip", "999.1.1.1", "bad_dst_ip"),
    ("dst_ip", 12, "bad_dst_ip"),
    ("src_ip", "nope", "bad_src_ip"),
    ("dst_port", "70000", "bad_dst_port"),
    ("src_port", "-1", "bad_src_port"),
    ("bytes_out", "-5", "bad_bytes_out"),
    ("bytes_out", "1e3", "bad_bytes_out"),
    ("bytes_out", "12.5", "bad_bytes_out"),
    ("bytes_out", True, "bad_bytes_out"),
    ("bytes_out", 1.5, "bad_bytes_out"),
    ("bytes_out", [1], "bad_bytes_out"),
    ("bytes_out", "9007199254740992", "bad_bytes_out"),
    ("bytes_out", 9007199254740992.0, "bad_bytes_out"),
    ("bytes_in", 2**53, "bad_bytes_in"),
    ("packets_out", 2**63 - 1, "bad_packets_out"),
    ("packets_in", "9007199254740992", "bad_packets_in"),
    ("duration_ms", 9007199254740992.0, "bad_duration_ms"),
    ("protocol", "300", "bad_protocol"),
    ("protocol", "t c p", "bad_protocol"),
    ("protocol", False, "bad_protocol"),
    ("device_class", "bad class!", "bad_device_class"),
    ("device_class", 7, "bad_device_class"),
    ("device_id", "  ", "bad_device_id"),
    ("record_type", "netflow", "unknown_record_type"),
    ("record_type", "dns", "record_type_mismatch"),
])
def test_strict_rejections(field, value, code):
    with pytest.raises(NormalizationError) as ei:
        normalize(flow_raw(**{field: value}), src(), PSEUDO, NOW)
    assert ei.value.code == code


def test_counters_at_json_safe_integer_limit_are_hashable_and_revalidate():
    from aegis.ingest.validator import Validator
    top = 2**53 - 1
    ev = normalize(flow_raw(bytes_out=str(top), bytes_in=float(top), packets_out=top, packets_in=top,
                            duration_ms=top), src(), PSEUDO, NOW)
    assert ev.flow.bytes_out == top and ev.flow.bytes_in == top
    sha256_hex(ev.model_dump(mode="json"))  # RFC 8785 accepts it
    assert isinstance(Validator(clock=lambda: NOW).validate(ev.model_dump(mode="json")), ObservationEvent)


@pytest.mark.parametrize("kw,code", [
    ({"qname": None}, "missing_qname"),
    ({"qname": "bad name.example"}, "bad_qname"),
    ({"qname": "a" * 64 + ".example"}, "bad_qname"),
    ({"qtype": "A A"}, "bad_qtype"),
    ({"rcode": True}, "bad_rcode"),
    ({"answers": [1]}, "bad_answers"),
    ({"answers": 5}, "bad_answers"),
])
def test_dns_rejections(kw, code):
    with pytest.raises(NormalizationError) as ei:
        normalize(dns_raw(**kw), src(SourceKind.DNS), PSEUDO, NOW)
    assert ei.value.code == code


def test_parser_errors_propagate_as_codes():
    with pytest.raises(NormalizationError) as ei:
        normalize({"_error": "column_count", "_error_detail": "x", "_raw": b"a"}, src(), PSEUDO, NOW)
    assert ei.value.code == "column_count"


def test_entity_selection():
    by_ip = src(entity_field="src_ip")
    ev = normalize(flow_raw(), by_ip, PSEUDO, NOW)
    assert ev.entity_pseudonym == PSEUDO.pseudonym("100.64.0.1")
    ev = normalize(flow_raw(device_id=None), src(), PSEUDO, NOW)
    assert ev.entity_pseudonym == PSEUDO.pseudonym("100.64.0.1")
    with pytest.raises(NormalizationError) as ei:
        normalize(flow_raw(device_id=None, src_ip=None), src(), PSEUDO, NOW)
    assert ei.value.code == "missing_entity"
    with pytest.raises(NormalizationError):
        normalize(flow_raw(device_id=None), src(entity_field="device_id"), PSEUDO, NOW)


def test_naive_allowed_when_configured_and_cpe_kinds():
    ev = normalize(flow_raw(observed_at="2026-10-01T00:00:00"), src(assume_utc_for_naive=True), PSEUDO, NOW)
    assert ev.observed_at.tzinfo is not None
    cpe = src(SourceKind.CPE)
    assert normalize(flow_raw(), cpe, PSEUDO, NOW).flow is not None
    assert normalize(dns_raw(), cpe, PSEUDO, NOW).dns is not None


def test_integrity_without_raw_bytes_is_canonical():
    a = flow_raw()
    a.pop("_raw")
    b = dict(reversed(list(a.items())))
    assert normalize(a, src(), PSEUDO, NOW).integrity_sha256 == normalize(b, src(), PSEUDO, NOW).integrity_sha256


def test_now_must_be_aware_and_source_config_validation():
    with pytest.raises(ValueError):
        normalize(flow_raw(), src(), PSEUDO, datetime(2026, 10, 2))
    with pytest.raises(ValidationError):
        src(format="bogus")
    with pytest.raises(ValidationError):
        src(retention_days=0)
    assert src().parser_format == "netflow_csv"
    assert src(SourceKind.ZEEK_DNS).parser_format == "zeek_dns"


def test_parse_timestamp_variants():
    assert parse_timestamp("2026-10-01T02:00:00+02:00") == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert parse_timestamp(1790812800) == datetime(2026, 10, 1, tzinfo=timezone.utc)
    with pytest.raises(NormalizationError):
        parse_timestamp([1])
    with pytest.raises(NormalizationError):
        parse_timestamp(10**15)


# ------------------------------------------------------------------ unidirectional NetFlow (nfdump v5/v9)

NFDUMP_UNIFLOW = (
    "ts,te,td,sa,da,sp,dp,pr,flg,ipkt,ibyt,opkt,obyt\n"
    # subscriber 100.64.1.7 -> server, and the server's reply as a separate (reverse) flow
    "2026-10-01T08:00:01Z,x,0.75,100.64.1.7,198.18.0.20,51000,443,6,.AP.SF,12,4210,0,0\n"
    "2026-10-01T08:00:01Z,x,0.74,198.18.0.20,100.64.1.7,443,51000,6,.AP.SF,15,18892,0,0\n"
    # transit between two outside hosts (e.g. mis-scoped export)
    "2026-10-01T08:00:02Z,x,0.10,203.0.113.5,198.18.0.21,1234,53,17,......,1,80,0,0\n"
)


def test_unidirectional_nfdump_export_is_modelled_per_subscriber(tmp_path):
    from aegis.ingest.bus import OBSERVATIONS_TOPIC, InMemoryBus
    from aegis.ingest.normalize import SourceConfig
    from aegis.ingest.pipeline import IngestPipeline
    from aegis.ingest.pseudonym import Pseudonymizer
    from aegis.ingest.validator import Validator

    bus = InMemoryBus()
    got = []
    bus.subscribe(OBSERVATIONS_TOPIC, got.append)
    src = SourceConfig(tenant_id="t1", source_id="nf", source_kind="netflow", vantage="subscriber_line",
                       collection_authorization_id="auth-1", subscriber_prefixes=("100.64.0.0/10",))
    p = IngestPipeline(bus, Validator(), {"nf": src}, pseudonymizers={"t1": Pseudonymizer(b"k" * 32)})
    stats = p.ingest_text(NFDUMP_UNIFLOW, "nf")
    bus.drain()
    assert stats.records_read == 3 and stats.published == 1 and stats.quarantined == 0
    assert stats.skipped == 2 and stats.skip_reasons == {"return_flow": 1, "outside_subscriber_prefixes": 1}
    assert stats.success_rate == 1.0
    (ev,) = got
    assert ev.flow.dst_ip == "198.18.0.20" and ev.flow.bytes_out == 4210
    # nfdump writes 0 (not empty) for counters a uniflow exporter does not have: missing, never "no reply"
    assert ev.flow.bytes_in is None and ev.flow.packets_in is None


def test_flow_direction_modes():
    from aegis.ingest.normalize import SourceConfig, normalize
    from aegis.ingest.parsers import parse_netflow_csv
    from aegis.ingest.pseudonym import Pseudonymizer

    (rec, *_rest) = list(parse_netflow_csv(NFDUMP_UNIFLOW))
    nonzero = dict(rec, bytes_in="900", packets_in="3")
    base = dict(tenant_id="t1", source_id="nf", source_kind="netflow", vantage="subscriber_line",
                collection_authorization_id="a")
    ps = Pseudonymizer(b"k" * 32)
    now = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
    assert normalize(nonzero, SourceConfig(**base), ps, now).flow.bytes_in == 900          # auto keeps real counters
    assert normalize(rec, SourceConfig(**base, flow_direction="biflow"), ps, now).flow.bytes_in == 0
    assert normalize(nonzero, SourceConfig(**base, flow_direction="uniflow"), ps, now).flow.bytes_in is None
    with pytest.raises(ValueError):
        SourceConfig(**base, subscriber_prefixes=("not-a-cidr",))
