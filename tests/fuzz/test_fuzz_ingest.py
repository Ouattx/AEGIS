"""Property-based fuzzing of every ingest parser and the validator.

Properties (spec section 3 / CLAUDE.md non-negotiables):

* hostile input never crashes the pipeline (no exception escapes ``ingest_text``);
* nothing is lost: every record is accepted, quarantined (with a stable reason), dropped as an
  exact duplicate, or skipped as out of scope, and the counters add up;
* nothing is accepted silently: every accepted event re-validates strictly, carries a pseudonym
  and never a subscriber IP; records with a known-invalid field are quarantined, records whose
  fields are all valid are accepted with exactly the values given.
"""
from __future__ import annotations

import ipaddress
import json
import string
from datetime import datetime, timedelta, timezone

from hypothesis import assume, given
from hypothesis import strategies as st

from aegis.contracts.models import ObservationEvent
from aegis.ingest import Quarantined, Validator
from aegis.scale.lines import FixedClock
from fuzz_support import NOW, Run, check_invariants, reasons_of

NETFLOW_HEADER = ("ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,"
                  "packets_in,bytes_in,duration_ms")
NASTY_TEXT = st.text(alphabet=st.characters(codec="utf-8", exclude_categories=("Cs",)), max_size=40)
JSON_SCALARS = st.one_of(st.none(), st.booleans(), st.integers(min_value=-(2**70), max_value=2**70),
                         st.floats(allow_nan=False, allow_infinity=False), NASTY_TEXT)
JSON_VALUES = st.recursive(JSON_SCALARS, lambda inner: st.one_of(
    st.lists(inner, max_size=4), st.dictionaries(NASTY_TEXT, inner, max_size=4)), max_leaves=12)


# ----------------------------------------------------------------------------- strategies

def ts_valid() -> st.SearchStrategy[datetime]:
    return st.datetimes(min_value=datetime(2026, 9, 1), max_value=datetime(2026, 10, 2, 11, 0),
                        timezones=st.just(timezone.utc))


def rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


MACS = st.lists(st.integers(0, 255), min_size=6, max_size=6).map(lambda b: ":".join(f"{x:02x}" for x in b))
IPV4 = st.ip_addresses(v=4).map(str)
DST_IP = st.one_of(st.ip_addresses(v=4), st.ip_addresses(v=6)).map(str)
COUNTER = st.integers(min_value=0, max_value=2**40)

BAD_IP = st.sampled_from(["999.1.1.1", "1.2.3", "not-an-ip", "1.2.3.4.5", "::g", "10.0.0.1/24", "0x7f.1",
                          "١٢٣.1.1.1"])
BAD_TS = st.sampled_from(["yesterday", "2026-13-01T00:00:00Z", "2026-10-01 25:00", "1e400", "--", "T",
                          "2026-10-01T00:00:00"])          # the last one is naive (no offset) -> ambiguous
BAD_INT = st.sampled_from(["-1", "1.5", "0x10", "ten", "1e3", "99999999999999999999999"])


@st.composite
def netflow_row(draw: st.DrawFn) -> tuple[str, str | None, dict]:
    """A CSV row plus the field made invalid (None = all fields valid) and the values used."""
    vals = {
        "ts": rfc3339(draw(ts_valid())), "device_id": draw(MACS),
        "device_class": draw(st.sampled_from(["android_tv", "phone", "", "-"])),
        "src_ip": draw(IPV4), "src_port": str(draw(st.integers(0, 65535))), "dst_ip": draw(DST_IP),
        "dst_port": str(draw(st.integers(0, 65535))), "proto": draw(st.sampled_from(["6", "17", "1", "tcp", "udp"])),
        "packets_out": str(draw(COUNTER)), "bytes_out": str(draw(COUNTER)),
        "packets_in": str(draw(COUNTER)), "bytes_in": str(draw(COUNTER)),
        "duration_ms": str(draw(st.integers(0, 10**7))),
    }
    broken = draw(st.sampled_from([None, None, "ts", "dst_ip", "dst_port", "bytes_out", "packets_in",
                                   "src_ip", "missing_dst"]))
    if broken == "ts":
        vals["ts"] = draw(BAD_TS)
    elif broken in ("dst_ip", "src_ip"):
        vals[broken] = draw(BAD_IP)
    elif broken in ("dst_port", "bytes_out", "packets_in"):
        vals[broken] = draw(BAD_INT)
    elif broken == "missing_dst":
        vals["dst_ip"] = ""
    row = ",".join(vals[k] for k in NETFLOW_HEADER.split(","))
    return row, broken, vals


# ----------------------------------------------------------------------------- arbitrary bytes, all formats

@given(st.sampled_from(["netflow", "dns", "zeek_conn", "zeek_dns", "cpe"]), st.binary(max_size=2048))
def test_arbitrary_bytes_never_crash_any_parser(source_id, payload):
    run = Run()
    stats = run.ingest(source_id, payload)
    check_invariants(run, stats)


@given(st.sampled_from(["netflow", "dns", "zeek_conn", "zeek_dns", "cpe"]),
       st.lists(st.one_of(NASTY_TEXT, st.sampled_from(["#fields\tts\tid.orig_h", "{", "}", "[", "]", "null",
                                                        "Summary", "#separator \\x09", NETFLOW_HEADER, ",,,,",
                                                        '{"records": [1, {}]}', '"', "\x00"])), max_size=25))
def test_line_structured_garbage_never_crashes(source_id, lines):
    run = Run()
    stats = run.ingest(source_id, "\n".join(lines).encode("utf-8", "surrogatepass"))
    check_invariants(run, stats)


# ----------------------------------------------------------------------------- NetFlow CSV

@given(st.lists(netflow_row(), min_size=1, max_size=20))
def test_netflow_valid_rows_accepted_exactly_invalid_rows_quarantined(rows):
    run = Run()
    payload = (NETFLOW_HEADER + "\n" + "\n".join(r for r, _, _ in rows) + "\n").encode()
    stats = run.ingest("netflow", payload)
    check_invariants(run, stats)
    good = [(r, v) for r, b, v in rows if b is None]
    n_bad = sum(1 for _, b, _ in rows if b is not None)
    distinct_good = len({r for r, _ in good})
    assert stats.accepted == distinct_good, (stats, reasons_of(run))
    assert stats.quarantined == n_bad, reasons_of(run)
    assert stats.duplicates == len(good) - distinct_good
    by_raw = {r: v for r, v in good}
    seen = set()
    for ev in run.events:
        # the accepted event reflects exactly the row it came from
        match = [v for r, v in by_raw.items() if r not in seen and ev.flow is not None
                 and ev.flow.dst_ip == str(ipaddress.ip_address(v["dst_ip"]))
                 and ev.flow.bytes_out == int(v["bytes_out"]) and ev.flow.packets_in == int(v["packets_in"])
                 and ev.observed_at == datetime.strptime(v["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)]
        assert match, ev
    for q in run.quarantine.list(run.pipe.sources["netflow"].tenant_id, 10**6):
        assert q.stage in ("parse", "normalize", "validate") and q.raw_artifact_ref


@given(st.lists(st.tuples(st.sampled_from(["ts", "device_id", "src_ip", "dst_ip", "bytes_out", "zzz", "ts"]),
                          NASTY_TEXT), max_size=6),
       st.lists(st.lists(NASTY_TEXT, max_size=8), max_size=10))
def test_netflow_hostile_headers_and_cells(header_cols, rows):
    run = Run()
    header = ",".join(c for c, _ in header_cols) or "ts,dst_ip"
    body = "\n".join(",".join(cell.replace("\n", " ") for cell in r) for r in rows)
    stats = run.ingest("netflow", (header + "\n" + body + "\n").encode())
    check_invariants(run, stats)


def test_netflow_without_required_header_is_quarantined_as_a_whole():
    run = Run()
    stats = run.ingest("netflow", b"device_id,src_ip\naa:bb:cc:dd:ee:ff,10.0.0.1\n")
    check_invariants(run, stats)
    assert stats.accepted == 0 and stats.quarantine_reasons == {"unparseable_input": 1}


# ----------------------------------------------------------------------------- DNS JSONL

@st.composite
def dns_obj(draw: st.DrawFn) -> tuple[dict, str | None]:
    obj = {"ts": rfc3339(draw(ts_valid())), "device_id": draw(MACS), "client_ip": draw(IPV4),
           "qname": draw(st.from_regex(r"\A[a-z0-9]{1,12}(\.[a-z0-9]{1,12}){1,3}\Z")),
           "qtype": draw(st.sampled_from(["A", "AAAA", 28, "TXT"])),
           "rcode": draw(st.sampled_from(["NOERROR", "NXDOMAIN", 0, 3])),
           "answers": draw(st.lists(IPV4, max_size=3))}
    broken = draw(st.sampled_from([None, None, "ts", "qname", "qname_type", "no_entity", "answers", "ts_type"]))
    if broken == "ts":
        obj["ts"] = draw(BAD_TS)
    elif broken == "ts_type":
        obj["ts"] = draw(st.one_of(st.booleans(), st.lists(st.integers(), max_size=2), st.just({"a": 1})))
    elif broken == "qname":
        obj["qname"] = draw(st.sampled_from(["", " ", "a..b", "x" * 300, "bad label.com", "a\x00b"]))
    elif broken == "qname_type":
        obj["qname"] = draw(st.one_of(st.integers(), st.lists(st.text(max_size=3), max_size=2), st.just({"q": 1})))
    elif broken == "no_entity":
        del obj["device_id"], obj["client_ip"]
    elif broken == "answers":
        # answers may legitimately hold names (CNAME targets); non-string answers never are valid
        obj["answers"] = draw(st.one_of(st.just({"a": 1}), st.just([1, 2]), st.just([None]), st.just(7)))
    extra = draw(st.dictionaries(st.sampled_from(["zzz", "foo", "@timestamp2", "meta"]), JSON_VALUES, max_size=2))
    obj.update(extra)
    return obj, broken


@given(st.lists(dns_obj(), min_size=1, max_size=15))
def test_dns_valid_objects_accepted_invalid_quarantined(objs):
    run = Run()
    payload = ("\n".join(json.dumps(o) for o, _ in objs) + "\n").encode()
    stats = run.ingest("dns", payload)
    check_invariants(run, stats)
    good = {json.dumps(o) for o, b in objs if b is None}
    n_bad = sum(1 for _, b in objs if b is not None)
    assert stats.accepted == len(good), (stats, reasons_of(run))
    assert stats.quarantined == n_bad, reasons_of(run)
    names = {o["qname"].lower() for o, b in objs if b is None}
    assert {ev.dns.qname.lower().rstrip(".") for ev in run.events} <= names


@given(st.lists(JSON_VALUES, max_size=12))
def test_dns_arbitrary_json_values(values):
    run = Run()
    payload = ("\n".join(json.dumps(v) for v in values) + "\n").encode()
    stats = run.ingest("dns", payload)
    check_invariants(run, stats)
    # an object without a timestamp, a name and an entity can never become an event
    assert stats.accepted <= sum(1 for v in values if isinstance(v, dict))


# ----------------------------------------------------------------------------- Zeek TSV

ZEEK_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "duration",
                    "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"]


@st.composite
def zeek_conn_row(draw: st.DrawFn) -> tuple[str, str | None]:
    epoch = draw(ts_valid()).timestamp()
    vals = [f"{epoch:.6f}", "C" + draw(st.text(string.ascii_letters, min_size=5, max_size=8)), draw(IPV4),
            str(draw(st.integers(0, 65535))), draw(IPV4), str(draw(st.integers(0, 65535))),
            draw(st.sampled_from(["tcp", "udp", "icmp"])), draw(st.sampled_from(["-", "0.5", "12.25"])),
            str(draw(COUNTER)), str(draw(COUNTER)), str(draw(COUNTER)), str(draw(COUNTER))]
    broken = draw(st.sampled_from([None, None, "ts", "resp_h", "orig_h", "orig_bytes", "columns"]))
    if broken == "ts":
        vals[0] = draw(st.sampled_from(["x", "-", "1e999", "12:00"]))
    elif broken == "resp_h":
        vals[4] = draw(BAD_IP)
    elif broken == "orig_h":
        vals[2] = draw(st.sampled_from(["-", "not-an-ip", "300.1.1.1"]))
    elif broken == "orig_bytes":
        vals[8] = draw(BAD_INT)
    elif broken == "columns":
        vals = vals[:-2]
    return "\t".join(vals), broken


@given(st.lists(zeek_conn_row(), min_size=1, max_size=15), st.booleans())
def test_zeek_conn_valid_rows_accepted_invalid_quarantined(rows, with_header):
    run = Run()
    head = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
            "#fields\t" + "\t".join(ZEEK_CONN_FIELDS)] if with_header else []
    stats = run.ingest("zeek_conn", ("\n".join(head + [r for r, _ in rows]) + "\n").encode())
    check_invariants(run, stats)
    if not with_header:
        assert stats.accepted == 0                       # data before #fields is never guessed at
        return
    good = {r for r, b in rows if b is None}
    assert stats.accepted == len(good), (stats, reasons_of(run))
    assert stats.quarantined == sum(1 for _, b in rows if b is not None), reasons_of(run)


@given(st.lists(st.one_of(st.text(alphabet="\t,-#(){}:. abcdefghij0123456789", max_size=60), NASTY_TEXT),
                max_size=20))
def test_zeek_dns_arbitrary_lines(lines):
    run = Run()
    head = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tquery\tqtype_name\trcode_name\tanswers"
    stats = run.ingest("zeek_dns", (head + "\n" + "\n".join(lines) + "\n").encode("utf-8", "surrogatepass"))
    check_invariants(run, stats)


# ----------------------------------------------------------------------------- CPE JSON

CPE_RECORD = st.fixed_dictionaries(
    {"type": st.sampled_from(["flow", "dns", "FLOW", "weird", 7]), "ts": st.one_of(ts_valid().map(rfc3339), BAD_TS),
     "device_id": st.one_of(MACS, st.just(""), st.integers()), "dst_ip": st.one_of(DST_IP, BAD_IP),
     "qname": st.one_of(st.just("svc.example"), st.just(""), st.integers())},
    optional={"bytes_out": st.one_of(COUNTER, BAD_INT, st.floats()), "answers": JSON_VALUES, "extra": JSON_VALUES})


@given(st.one_of(
    st.lists(CPE_RECORD, max_size=8).map(lambda rs: json.dumps(rs)),
    st.lists(CPE_RECORD, max_size=8).map(lambda rs: json.dumps({"records": rs})),
    st.lists(st.fixed_dictionaries({"device_id": MACS, "flows": st.lists(CPE_RECORD, max_size=3),
                                    "dns": st.one_of(st.lists(CPE_RECORD, max_size=3), JSON_VALUES)}),
             max_size=3).map(lambda ds: json.dumps({"devices": ds})),
    st.lists(CPE_RECORD, max_size=8).map(lambda rs: "\n".join(json.dumps(r) for r in rs)),
    JSON_VALUES.map(json.dumps)))
def test_cpe_documents_and_lines(payload):
    run = Run()
    stats = run.ingest("cpe", payload.encode())
    check_invariants(run, stats)


# ----------------------------------------------------------------------------- validator

def _valid_event() -> dict:
    return {
        "event_id": "4b9c7f1e-2d3a-4e5f-8a9b-0c1d2e3f4a5b", "schema_version": "3.0", "tenant_id": "fuzz-isp",
        "observed_at": "2026-10-02T11:00:00+00:00", "ingested_at": "2026-10-02T11:00:05+00:00",
        "source_id": "netflow", "source_kind": "netflow", "vantage": "device",
        "collection_authorization_id": "auth-fuzz", "entity_pseudonym": "p_" + "a" * 32, "device_class": "phone",
        "flow": {"src_ip": None, "dst_ip": "198.18.0.1", "dst_port": 443, "protocol": "tcp", "bytes_out": 10,
                 "bytes_in": 20, "packets_out": 1, "packets_in": 1, "duration_ms": 5},
        "dns": None, "raw_artifact_ref": None, "data_class": "security_metadata",
        "retention_until": "2026-11-01T11:00:00+00:00", "integrity_sha256": "b" * 64,
    }


VALIDATOR = Validator(clock=FixedClock(NOW))

MUTATIONS = [
    ("observed_at", "2026-10-02T11:00:00"), ("observed_at", "2027-01-01T00:00:00+00:00"),
    ("observed_at", 1790000000), ("schema_version", "2.0"), ("tenant_id", None), ("tenant_id", 5),
    ("entity_pseudonym", "aa:bb:cc:dd:ee:ff"), ("entity_pseudonym", "10.0.0.1"), ("entity_pseudonym", None),
    ("entity_pseudonym", "p_" + "A" * 32), ("integrity_sha256", "xyz"), ("integrity_sha256", "B" * 64),
    ("retention_until", "2026-10-01T00:00:00+00:00"), ("collection_authorization_id", " "),
    ("data_class", "payload"), ("unknown_field", 1), ("dns", {"qname": "a.example"}), ("flow", None),
    ("flow.src_ip", "10.0.0.9"), ("flow.dst_ip", "999.0.0.1"), ("flow.bytes_out", -1), ("flow.bytes_out", "10"),
    ("flow.dst_port", 70000), ("flow.protocol", "sctp"), ("flow.extra", True), ("vantage", "satellite"),
    ("ingested_at", "2026-10-02T10:00:00+00:00"),
]


@given(st.sampled_from(MUTATIONS))
def test_validator_rejects_every_known_invalid_mutation(mutation):
    field, value = mutation
    ev = _valid_event()
    assert isinstance(VALIDATOR.validate(json.dumps(ev).encode()), ObservationEvent)
    if "." in field:
        outer, inner = field.split(".")
        ev[outer][inner] = value
    else:
        ev[field] = value
    for form in (json.dumps(ev).encode(), ev):
        out = VALIDATOR.validate(form)
        assert isinstance(out, Quarantined), (field, value)
        assert out.reason and out.raw_size > 0 and len(out.raw_sha256) == 64


@given(st.one_of(st.binary(max_size=512), JSON_VALUES.map(lambda v: json.dumps(v).encode()),
                 st.dictionaries(NASTY_TEXT, JSON_VALUES, max_size=6)))
def test_validator_never_raises(payload):
    out = VALIDATOR.validate(payload)
    assert isinstance(out, (ObservationEvent, Quarantined))
    if isinstance(out, Quarantined):
        assert out.reason


@given(st.dictionaries(st.sampled_from(sorted(_valid_event())), JSON_VALUES, min_size=1, max_size=4))
def test_validator_random_field_overwrites_are_never_silently_accepted(overwrite):
    ev = _valid_event()
    ev.update(overwrite)
    out = VALIDATOR.validate(json.dumps(ev).encode())
    if isinstance(out, ObservationEvent):
        # accepted only if every overwritten value is itself valid for its field: re-validate the
        # accepted event and check the overwrite is reflected verbatim (nothing coerced)
        dumped = out.model_dump(mode="json")
        for k, v in overwrite.items():
            if k in ("observed_at", "ingested_at", "retention_until"):
                assume(isinstance(v, str))
                assert datetime.fromisoformat(dumped[k]) == datetime.fromisoformat(v)
            else:
                assert dumped[k] == v, k
        assert out.observed_at <= NOW + timedelta(seconds=300)
