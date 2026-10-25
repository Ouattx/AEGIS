"""Fuzzing of the scale-out routing fast paths and of sharded-vs-single equivalence.

* The coordinator's identifier extraction for NetFlow CSV / DNS JSONL lines must pick the same
  shard as routing the fully parsed record (``route_raw``), for arbitrary lines.
* For arbitrary small inputs (valid and hostile lines mixed), the line-sharded pipeline produces
  exactly the single-node ingest statistics and accepted events.
"""
from __future__ import annotations

import json

from hypothesis import given
from hypothesis import strategies as st

from aegis.ingest import parsers
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.scale import InlineCluster, LineShardConfig, Partitioner, ShardedLinePipeline
from aegis.scale.lines import FixedClock
from aegis.scale.routing import RecordRouter, decode_items, route_raw
from fuzz_support import KEY, NOW, SOURCES, TENANT, Run

PSEUDO = Pseudonymizer(KEY)
PART = Partitioner(7)
CELL = st.one_of(st.sampled_from(["", " ", "-", "N/A", "null", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
                                  "10.0.0.1", " 10.0.0.1 ", "::1", "x", '"q"', '"a,b"', "2026-10-01T00:00:00Z"]),
                 st.text(alphabet=st.characters(codec="utf-8", exclude_categories=("Cs",), exclude_characters="\n\r"),
                         max_size=12))
HEADERS = st.sampled_from([
    "ts,device_id,src_ip,dst_ip", "ts,src_ip,dst_ip", "ts,dst_ip,device_id", "ts,mac,sa,da",
    "ts,device_id,device_id,src_ip,dst_ip", "time,da,sa,ibyt"])


@given(HEADERS, st.lists(st.lists(CELL, min_size=1, max_size=6), max_size=15),
       st.sampled_from(["netflow", "zeek_conn"]))
def test_netflow_fast_route_equals_full_parse_route(header, rows, source_id):
    src = SOURCES["netflow"] if source_id == "netflow" else SOURCES["netflow"].model_copy(
        update={"entity_field": "src_ip"})
    payload = (header + "\n" + "\n".join(",".join(r) for r in rows) + "\n").encode()
    router = RecordRouter(src, PSEUDO, PART)
    fast = list(router.route(payload))
    full = list(parsers.parse_netflow_csv(payload))
    assert len(fast) == len(full)
    for (shard, item), rec in zip(fast, full):
        assert shard == route_raw(rec, src, PSEUDO, PART)
        assert item[1] == rec["_raw"] and item[0] == rec["_line_no"]
    decoded = [r for _, r in decode_items(router.context, [(i, it) for i, (_, it) in enumerate(fast)])]
    assert decoded == full


@given(st.lists(st.one_of(
    st.dictionaries(st.sampled_from(["device_id", "DEVICE", "mac", "client_ip", "client", "src_ip", "ts", "qname",
                                     "Device_Id", "cpe_device_id"]),
                    st.one_of(CELL, st.integers(), st.none(), st.lists(st.integers(), max_size=2)), max_size=6)
    .map(json.dumps),
    CELL), max_size=12))
def test_dns_fast_route_equals_full_parse_route(lines):
    payload = ("\n".join(lines) + "\n").encode()
    router = RecordRouter(SOURCES["dns"], PSEUDO, PART)
    fast = list(router.route(payload))
    full = list(parsers.parse_dns_jsonl(payload))
    assert len(fast) == len(full)
    for (shard, _), rec in zip(fast, full):
        assert shard == route_raw(rec, SOURCES["dns"], PSEUDO, PART)


ROW = st.builds(lambda mac, ip, dst, b, ts: f"{ts},{mac},phone,{ip},1234,{dst},443,6,1,{b},1,1,10",
                st.sampled_from([f"02:00:00:00:00:{i:02x}" for i in range(12)] + ["", "-"]),
                st.sampled_from(["10.0.0.1", "10.0.0.2", "bad-ip", ""]),
                st.sampled_from(["198.18.0.1", "198.18.0.2", "999.9.9.9", ""]),
                st.sampled_from(["100", "-1", "x", ""]),
                st.sampled_from(["2026-10-01T00:00:00Z", "2026-10-01T05:00:00Z", "2099-01-01T00:00:00Z", "bad"]))
HEAD = "ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,packets_in,bytes_in," \
       "duration_ms"


@given(st.lists(st.lists(ROW, max_size=20), min_size=1, max_size=4), st.integers(1, 5), st.integers(1, 30))
def test_sharded_ingest_equals_single_node(payload_rows, n_shards, batch_size):
    payloads = [(HEAD + "\n" + "\n".join(rows) + "\n").encode() for rows in payload_rows]
    ref = Run()
    ref_stats = [ref.ingest("netflow", p) for p in payloads]
    cfg = LineShardConfig(sources=SOURCES, tenant_keys={TENANT: KEY}, mode="ingest", clock=FixedClock(NOW))
    with InlineCluster(cfg, n_shards) as cl:
        sp = ShardedLinePipeline(cl, cfg, batch_size=batch_size)
        stats = [sp.ingest_text(p, "netflow", name="fuzz") for p in payloads]
        res = sp.finish()
    for a, b in zip(ref_stats, stats):
        assert (a.records_read, a.accepted, a.quarantined, a.duplicates) == \
            (b.records_read, b.accepted, b.quarantined, b.duplicates)
        assert a.quarantine_reasons == b.quarantine_reasons
    key = lambda e: e.model_dump_json(exclude={"event_id"})  # noqa: E731
    assert sorted(map(key, ref.events)) == sorted(map(key, res.events))
