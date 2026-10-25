import gzip
import io
import json

import pytest

from aegis.ingest import parsers
from aegis.ingest.parsers import (
    ParseError,
    iter_lines,
    parse,
    parse_cpe_json,
    parse_dns_jsonl,
    parse_netflow_csv,
    parse_zeek_conn,
    parse_zeek_dns,
)

NF = (
    "ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,packets_in,"
    "bytes_in,duration_ms\n"
    "2026-10-01T00:00:00.000Z,02:aa:bb:cc:dd:ee,android_tv,100.64.0.1,40000,198.18.0.5,443,6,10,1000,12,,60000\n"
)


def test_netflow_native_header_and_missing_tokens():
    recs = list(parse_netflow_csv(NF))
    assert len(recs) == 1
    r = recs[0]
    assert r["record_type"] == "flow" and r["dst_ip"] == "198.18.0.5" and r["protocol"] == "6"
    assert r["bytes_in"] is None  # empty stays missing, never "0"
    assert r["_raw"] == NF.splitlines()[1].encode()
    assert r["_line_no"] == 2


def test_netflow_nfdump_aliases_and_summary_footer():
    text = ("ts,te,td,sa,da,sp,dp,pr,flg,ipkt,ibyt,opkt,obyt\n"
            "2026-10-01T08:00:01Z,x,0.75,100.64.9.10,198.18.0.20,1,443,6,.A,12,4210,15,18892\n"
            "Summary\nflows,bytes\n1,2\n")
    (r,) = list(parse_netflow_csv(text))
    assert r["src_ip"] == "100.64.9.10" and r["bytes_out"] == "4210" and r["bytes_in"] == "18892"
    assert r["duration_s"] == "0.75" and r["packets_in"] == "15"


def test_netflow_bad_lines_are_yielded_with_error():
    text = NF + "a,b\n" + '"unterminated,1\n' + b"\xff\xfe,1".decode("latin-1") + "\n"
    recs = list(parse_netflow_csv(text.encode("utf-8")))
    assert recs[1]["_error"] == "column_count"
    assert all("_raw" in r for r in recs)
    bad = list(parse_netflow_csv(NF.encode() + b"\xff\xfe\n"))
    assert bad[-1]["_error"] == "encoding" and bad[-1]["_raw"] == b"\xff\xfe"


def test_netflow_quoted_fields():
    text = NF.splitlines()[0] + "\n" + '"2026-10-01T00:00:00Z","02:aa:bb:cc:dd:ee","a,b",100.64.0.1,1,198.18.0.5,443,6,1,1,1,1,1\n'
    (r,) = list(parse_netflow_csv(text))
    assert r["device_class"] == "a,b"


def test_netflow_header_errors():
    with pytest.raises(ParseError):
        list(parse_netflow_csv("a,b,c\n1,2,3\n"))
    with pytest.raises(ParseError):
        list(parse_netflow_csv(""))
    with pytest.raises(ParseError):
        list(parse_netflow_csv("# only a comment\n"))


def test_netflow_from_path_and_gzip(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text(NF)
    g = tmp_path / "f.csv.gz"
    g.write_bytes(gzip.compress(NF.encode()))
    assert list(parse_netflow_csv(p))[0]["dst_ip"] == "198.18.0.5"
    assert list(parse_netflow_csv(str(g)))[0]["dst_ip"] == "198.18.0.5"
    assert list(parse_netflow_csv(io.StringIO(NF)))[0]["dst_ip"] == "198.18.0.5"
    assert list(parse_netflow_csv(io.BytesIO(NF.encode())))[0]["dst_ip"] == "198.18.0.5"


def test_iter_lines_skips_blank_and_strips_crlf():
    assert list(iter_lines(b"a\r\n\r\n  \nb\n")) == [(1, b"a"), (4, b"b")]
    with pytest.raises(TypeError):
        list(iter_lines(42))  # type: ignore[arg-type]


def test_dns_jsonl_aliases_and_errors():
    lines = [
        json.dumps({"timestamp": "2026-10-01T00:00:00Z", "client": "100.64.0.1", "query": "a.example",
                    "type": "AAAA", "response_code": "NXDOMAIN", "answers": "-"}),
        "{not json",
        "[1,2]",
        json.dumps({"ts": 1790812800, "client_ip": "100.64.0.2", "qname": "b.example", "answers": ["1.2.3.4"]}),
    ]
    recs = list(parse_dns_jsonl("\n".join(lines)))
    assert recs[0]["qname"] == "a.example" and recs[0]["qtype"] == "AAAA" and recs[0]["answers"] is None
    assert recs[1]["_error"] == "invalid_json"
    assert recs[2]["_error"] == "not_object"
    assert recs[3]["observed_at"] == 1790812800 and recs[3]["answers"] == ["1.2.3.4"]


ZEEK_CONN = "\n".join([
    "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\t"
    "resp_bytes\tconn_state\torig_pkts\tresp_pkts\ttunnel_parents",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\tset[string]",
    "1790812800.5\tCabc\t100.64.0.1\t40000\t198.18.0.5\t443\ttcp\t-\t0.25\t100\t-\tSF\t2\t-\t(empty)",
    "1790812801.0\tCdef\t100.64.0.1\t40000",
    "#close\t2026-10-01-01-00-00",
])


def test_zeek_conn_tsv():
    recs = list(parse_zeek_conn(ZEEK_CONN))
    assert recs[0]["src_ip"] == "100.64.0.1" and recs[0]["duration_s"] == "0.25"
    assert recs[0]["bytes_in"] is None and recs[0]["bytes_out"] == "100"
    assert recs[1]["_error"] == "column_count"


def test_zeek_dns_tsv_and_json_lines():
    text = "\n".join([
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype\tqtype_name\trcode\t"
        "rcode_name\tanswers\tTTLs",
        "1790812800.1\tC1\t100.64.0.1\t5353\t198.18.255.53\t53\tudp\ta.example\t1\tA\t0\tNOERROR\t1.2.3.4,5.6.7.8\t300,300",
        "1790812800.2\tC2\t100.64.0.1\t5353\t198.18.255.53\t53\tudp\tb.example\t28\t-\t3\t-\t-\t-",
        json.dumps({"ts": 1790812800.3, "id.orig_h": "100.64.0.1", "query": "c.example", "qtype_name": "A",
                    "rcode_name": "NXDOMAIN", "answers": []}),
    ])
    recs = list(parse_zeek_dns(text))
    assert recs[0]["answers"] == ["1.2.3.4", "5.6.7.8"] and recs[0]["rcode"] == "NOERROR"
    assert recs[1]["qtype"] == "28" and recs[1]["rcode"] == "3"  # numeric fallbacks
    assert recs[2]["qname"] == "c.example" and recs[2]["rcode"] == "NXDOMAIN"


def test_zeek_data_before_fields():
    (r,) = list(parse_zeek_conn("1\t2\t3\n"))
    assert r["_error"] == "zeek_no_fields"


def test_cpe_json_document_lines_and_inference():
    doc = {"devices": [{"device_id": "02:00:00:00:00:01", "device_class": "camera",
                        "flows": [{"ts": "2026-10-01T00:00:00Z", "dst_ip": "198.18.0.1"}],
                        "dns": [{"ts": "2026-10-01T00:00:00Z", "qname": "a.example"}]}]}
    recs = list(parse_cpe_json(json.dumps(doc, indent=2)))
    assert [r["record_type"] for r in recs] == ["flow", "dns"]
    assert all(r["device_id"] == "02:00:00:00:00:01" for r in recs)
    jsonl = "\n".join([json.dumps({"ts": 1, "dst_ip": "198.18.0.1", "device_id": "d"}),
                       json.dumps({"ts": 1, "qname": "x.example", "device_id": "d"}),
                       json.dumps({"ts": 1, "device_id": "d"}),
                       json.dumps({"type": "weird", "device_id": "d"}),
                       "garbage"])
    recs = list(parse_cpe_json(jsonl))
    assert [r.get("record_type") for r in recs[:2]] == ["flow", "dns"]
    assert recs[0]["_raw"] == jsonl.splitlines()[0].encode()
    assert recs[2]["_error"] == recs[3]["_error"] == "unknown_record_type"
    assert recs[4]["_error"] == "invalid_json"


def test_cpe_json_array_and_records_wrapper():
    arr = json.dumps([{"type": "flow", "ts": 1, "dst_ip": "198.18.0.1"}, 5])
    recs = list(parse_cpe_json(arr))
    assert recs[0]["record_type"] == "flow" and recs[1]["_error"] == "not_object"
    wrapped = json.dumps({"records": [{"type": "dns", "ts": 1, "qname": "a.example"}]})
    assert list(parse_cpe_json(wrapped))[0]["record_type"] == "dns"
    assert list(parse_cpe_json("")) == []


def test_cpe_json_damaged_multiline_falls_back_to_lines():
    text = '{"type": "flow", "ts": 1,\n{"type":"dns","ts":1,"qname":"a.example"}'
    recs = list(parse_cpe_json(text))
    assert recs[0]["_error"] == "invalid_json" and recs[1]["record_type"] == "dns"


def test_parse_registry():
    assert set(parsers.PARSERS) == {"netflow_csv", "dns_jsonl", "zeek_conn", "zeek_dns", "cpe_json"}
    with pytest.raises(ParseError):
        parse("nope", "")
