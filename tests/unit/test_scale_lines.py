"""Line-sharded ingestion / feature windows / SENTINEL equal the single-node pipeline exactly."""
from __future__ import annotations

import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis.contracts.models import SourceKind, Vantage
from aegis.ingest import IngestPipeline, IngestStats, Pseudonymizer, QuarantineStore, SourceConfig, Validator
from aegis.lab import generate_corpus
from aegis.lab.corpus import SOURCE_DNS, SOURCE_NETFLOW, SOURCE_ZEEK_CONN
from aegis.scale import (
    CollectingBus,
    FixedClock,
    InlineCluster,
    LineShardConfig,
    Partitioner,
    ProcessCluster,
    ShardedLinePipeline,
    merge_ingest_stats,
)
from aegis.scale.windows import plan_close
from aegis.sentinel import Sentinel, WindowStore, load_default
from aegis.sentinel.training import lab_bundle


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    c = generate_corpus(seed=21, days=2, n_devices=30, malicious_fraction=0.15, tenant_id="scale-isp")
    d = tmp_path_factory.mktemp("scale-corpus")
    c.write_raw(d)
    return c, d


def _inputs(c, d: Path) -> list[tuple[str, bytes, str]]:
    """Interleaved NetFlow / DNS chunks, hostile lines, exact re-deliveries, a Zeek file and a broken input."""
    nf = (d / "netflow.csv").read_bytes().split(b"\n")
    header, rows = nf[0], [r for r in nf[1:] if r]
    dns = [r for r in (d / "dns.jsonl").read_bytes().split(b"\n") if r]
    rnd = random.Random(3)
    hostile = [b"2026-10-01T00:00:00Z,aa:bb,android_tv,10.0.0.1,1,not-an-ip,443,6,1,1,1,1,1",
               b"2026-10-01T00:00:00Z,aa:bb,android_tv,10.0.0.1,1,198.18.0.1,443,6,-5,1,1,1,1",
               b"\xff\xfe\x00garbage,,,", b"too,few,columns", b'"unterminated,quote',
               b"2099-01-01T00:00:00Z,aa:cc,phone,10.0.0.2,1,198.18.0.2,443,6,1,1,1,1,1",
               b"2026-10-01T00:00:00Z,,phone,,1,198.18.0.2,443,6,1,1,1,1,1"]
    out: list[tuple[str, bytes, str]] = []
    i = j = 0
    while i < len(rows) or j < len(dns):
        chunk = rows[i:i + 2500]
        chunk = chunk + (hostile if i == 0 else [rnd.choice(hostile)] if rnd.random() < 0.5 else [])
        out.append((SOURCE_NETFLOW, header + b"\n" + b"\n".join(chunk) + b"\n", f"nf-{i}"))
        out.append((SOURCE_DNS, b"\n".join(dns[j:j + 900] + [b"{not json", b"[1,2]"]) + b"\n", f"dns-{j}"))
        i += 2500
        j += 900
    out.append((SOURCE_NETFLOW, header + b"\n" + b"\n".join(rows[:200]) + b"\n", "redelivery"))
    out.append((SOURCE_ZEEK_CONN, (d / "zeek" / "conn.log").read_bytes(), "conn.log"))
    out.append((SOURCE_NETFLOW, b"no,header,here\n1,2,3\n", "broken"))
    return out


def _single(c, inputs, now, mode, model=None, bundle=None):
    store = WindowStore("24h")
    sen = Sentinel(model, bundle, None, window_store=store) if mode == "sentinel" else None
    events, fvs, findings = [], [], []

    def on(ev):
        events.append(ev)
        if sen is not None:
            findings.extend(sen.process(ev))
        elif mode == "features":
            fvs.extend(store.update(ev))

    bus = CollectingBus()
    bus.subscribe("observations", on)
    q = QuarantineStore()
    pipe = IngestPipeline(bus, Validator(clock=FixedClock(now)), c.sources,
                          pseudonymizers={c.tenant_id: Pseudonymizer(c.tenant_key)}, quarantine=q,
                          clock=FixedClock(now))
    stats = [pipe.ingest_text(data, sid, name=name) for sid, data, name in inputs]
    if sen is not None:
        findings.extend(sen.flush(now))
    elif mode == "features":
        fvs.extend(store.flush(now))
    return dict(events=events, fvs=fvs, findings=findings, stats=stats, quarantine=q.list(c.tenant_id, 10**6),
                window_stats=vars(store.stats), sentinel=sen)


def _sharded(c, inputs, now, mode, cluster_cls=InlineCluster, n_shards=3, model=None, bundle=None,
             batch_size=1500, **kw):
    cfg = LineShardConfig(sources=c.sources, tenant_keys={c.tenant_id: c.tenant_key}, mode=mode,
                          clock=FixedClock(now), model=model, bundle=bundle, **kw)
    cluster = cluster_cls(cfg, n_shards) if cluster_cls is InlineCluster else cluster_cls(cfg, n_shards, 2)
    try:
        pipe = ShardedLinePipeline(cluster, cfg, batch_size=batch_size)
        stats = [pipe.ingest_text(data, sid, name=name) for sid, data, name in inputs]
        pipe.flush(now)
        return stats, pipe.finish()
    finally:
        cluster.close()


def _ekey(e):
    return e.model_dump_json(exclude={"event_id"})


def _fkey(f):
    return (f.entity_pseudonym, f.window_end, f.device_class, f.event_count,
            tuple(sorted(f.values.items())), tuple(sorted(f.missing.items())))


def _findkey(f):
    return (f.entity_pseudonym, f.label, f.verdict, f.score, f.calibration_id, f.observed_window_start,
            f.observed_window_end, f.created_at, f.ingested_at, f.requires_review, f.explanation,
            tuple(sorted(f.component_scores.items())))


def _qkey(q):
    return (q.reason, q.stage, q.raw_sha256, q.line_no, q.raw_artifact_ref, q.source_id, q.detail)


COUNTERS = ("records_read", "accepted", "published", "quarantined", "duplicates", "skipped")


def _assert_stats_equal(single: list[IngestStats], sharded: list[IngestStats]):
    assert len(single) == len(sharded)
    for a, b in zip(single, sharded):
        assert (a.source_id, a.input_ref) == (b.source_id, b.input_ref)
        for name in COUNTERS:
            assert getattr(a, name, 0) == getattr(b, name, 0), (a.input_ref, name)
        assert a.quarantine_reasons == b.quarantine_reasons, a.input_ref


def test_features_mode_identical_to_single_node(corpus):
    c, d = corpus
    now = c.end + timedelta(hours=1)
    inputs = _inputs(c, d)
    ref = _single(c, inputs, now, "features")
    stats, res = _sharded(c, inputs, now, "features", collect="all")
    _assert_stats_equal(ref["stats"], stats)
    assert sorted(map(_fkey, ref["fvs"])) == sorted(map(_fkey, res.features))
    assert len(res.features) > 1000
    assert res.window_stats == ref["window_stats"]
    assert ref["window_stats"]["late_events"] > 0          # the interleaving really exercises lateness
    assert sorted(map(_qkey, ref["quarantine"])) == sorted(map(_qkey, res.quarantined))
    assert {r for s in ref["stats"] for r in s.quarantine_reasons} >= {"bad_dst_ip", "bad_packets_out",
                                                                        "column_count", "invalid_json"}
    assert any(s.duplicates for s in stats) and any(s.quarantine_reasons.get("unparseable_input") for s in stats)
    # every event lives on the shard its line pseudonym hashes to
    part = Partitioner(3)
    assert sum(res.per_shard_events.values()) == res.n_events == len(ref["events"])
    shard_of = Counter(part.line_shard(e.entity_pseudonym) for e in ref["events"])
    assert dict(shard_of) == {s: n for s, n in res.per_shard_events.items() if n}


def test_sentinel_mode_identical_to_single_node(corpus):
    c, d = corpus
    now = c.end + timedelta(hours=1)
    inputs = _inputs(c, d)
    model, bundle = load_default(), lab_bundle(c)
    ref = _single(c, inputs, now, "sentinel", model, bundle)
    _, res = _sharded(c, inputs, now, "sentinel", model=model, bundle=bundle, collect="all")
    assert ref["findings"], "the corpus must produce findings"
    assert sorted(map(_findkey, ref["findings"])) == sorted(map(_findkey, res.findings))
    st = ref["sentinel"].stats
    assert res.sentinel_stats["windows"] == st.windows and res.sentinel_stats["findings"] == st.findings
    assert res.sentinel_stats["verdicts"] == dict(st.verdicts) and res.sentinel_stats["suppressed"] == st.suppressed


def test_process_cluster_matches_single_node(corpus):
    c, d = corpus
    now = c.end + timedelta(hours=1)
    inputs = _inputs(c, d)[:12]
    ref = _single(c, inputs, now, "features")
    stats, res = _sharded(c, inputs, now, "features", cluster_cls=ProcessCluster, n_shards=4, collect="all")
    _assert_stats_equal(ref["stats"], stats)
    assert sorted(map(_fkey, ref["fvs"])) == sorted(map(_fkey, res.features))


def test_ingest_mode_events_identical(corpus):
    c, d = corpus
    now = c.end + timedelta(hours=1)
    inputs = _inputs(c, d)
    ref = _single(c, inputs, now, "ingest")
    stats, res = _sharded(c, inputs, now, "ingest", n_shards=5, collect="all", batch_size=777)
    _assert_stats_equal(ref["stats"], stats)
    assert sorted(map(_ekey, ref["events"])) == sorted(map(_ekey, res.events))
    assert res.barriers == 0


def test_count_mode_keeps_counters_only(corpus):
    c, d = corpus
    now = c.end + timedelta(hours=1)
    inputs = _inputs(c, d)[:6]
    ref = _single(c, inputs, now, "features")
    _, res = _sharded(c, inputs, now, "features", collect="count")
    assert res.features == [] and res.events == [] and res.quarantined == []
    assert res.n_features == len(ref["fvs"]) and res.n_events == len(ref["events"])


def _flow_csv(rows):
    head = "ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,packets_in," \
           "bytes_in,duration_ms"
    return (head + "\n" + "\n".join(rows) + "\n").encode()


def test_out_of_order_stream_with_drops_and_gaps_is_identical():
    """Short hopping windows, shuffled arrival, a multi-hour gap: exercises late, dropped and skipped windows."""
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    src = SourceConfig(tenant_id="t1", source_id="nf", source_kind=SourceKind.NETFLOW,
                       vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-1")
    rnd = random.Random(5)
    base = datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()
    rows = []
    for k in range(4000):
        t = base + k * 2.0 + (6 * 3600 if k > 2500 else 0) + rnd.choice([0, 0, 0, -400, -900, -4000])
        dev = f"02:00:00:00:{rnd.randrange(60):02x}:01"
        ts = datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        rows.append(f"{ts},{dev},phone,10.0.{rnd.randrange(3)}.9,5000,198.18.{rnd.randrange(4)}.{rnd.randrange(30)},"
                    f"443,6,3,900,2,400,{rnd.choice([30, 60000])}")
    payloads = [_flow_csv(rows[i:i + 700]) for i in range(0, len(rows), 700)]
    key = b"k" * 32
    store = WindowStore("15m", timedelta(minutes=5), min_population=3)
    fvs = []
    bus = CollectingBus()
    bus.subscribe("observations", lambda ev: fvs.extend(store.update(ev)))
    pipe = IngestPipeline(bus, Validator(clock=FixedClock(now)), {"nf": src}, pseudonymizers={"t1": Pseudonymizer(key)},
                          clock=FixedClock(now))
    for p in payloads:
        pipe.ingest_text(p, "nf")
    fvs.extend(store.flush(now))
    assert store.stats.dropped_late > 0 and store.stats.late_events > 0
    cfg = LineShardConfig(sources={"nf": src}, tenant_keys={"t1": key}, mode="features", clock=FixedClock(now),
                          window="15m", hop_s=300, min_population=3)
    with InlineCluster(cfg, 4) as cl:
        sp = ShardedLinePipeline(cl, cfg, batch_size=333)
        for p in payloads:
            sp.ingest_text(p, "nf")
        sp.flush(now)
        res = sp.finish()
    assert res.window_stats == vars(store.stats)
    assert sorted(map(_fkey, fvs)) == sorted(map(_fkey, res.features))


def test_plan_close_mirrors_window_loop():
    # no data: jump to the watermark
    p = plan_close(set(), 10, 3600 * 15 + 5, 3600, 24, "t")
    assert p.end_indices == () and p.next_boundary_idx == 15 and p.emitted_idx == 15
    # gap before buffered data: skip empty windows, emit only windows with data
    p = plan_close({20, 21}, 10, 3600 * 23, 3600, 1, "t")
    assert p.end_indices == (21, 22) and p.next_boundary_idx == 23 and p.emitted_idx == 23
    # watermark not past the next boundary: nothing changes
    p = plan_close({5}, 10, 3600 * 11 - 1, 3600, 24, "t")
    assert p.end_indices == () and p.emitted_idx == -2


def test_merge_ingest_stats_is_field_generic():
    a = IngestStats("s", "t", "in", "netflow_csv", records_read=3, accepted=2, quarantined=1,
                    quarantine_reasons={"x": 1})
    b = IngestStats("s", "t", "in", "netflow_csv", records_read=5, accepted=5, duplicates=1,
                    quarantine_reasons={"x": 2, "y": 1})
    m = merge_ingest_stats([a, b], source_id="s", tenant_id="t", input_ref="in", fmt="netflow_csv")
    assert (m.records_read, m.accepted, m.quarantined, m.duplicates) == (8, 7, 1, 1)
    assert m.quarantine_reasons == {"x": 3, "y": 1}


def test_pipeline_rejects_bad_arguments(corpus):
    c, _ = corpus
    cfg = LineShardConfig(sources=c.sources, tenant_keys={c.tenant_id: c.tenant_key}, mode="features")
    with InlineCluster(cfg, 2) as cl:
        with pytest.raises(ValueError):
            ShardedLinePipeline(cl, cfg, batch_size=0)
        sp = ShardedLinePipeline(cl, cfg)
        with pytest.raises(ValueError):
            sp.flush(datetime(2026, 1, 1))
        with pytest.raises(KeyError):
            sp.ingest_text(b"x", "no-such-source")


def test_sentinel_shards_persist_evidence_and_keep_the_ledger_valid(corpus, tmp_path):
    from aegis.provenance.evidence import EvidenceStore
    from aegis.provenance.ledger import Ledger
    from aegis.provenance.signing import Signer
    from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

    c, d = corpus
    now = c.end + timedelta(hours=1)
    eng = make_engine(f"sqlite:///{tmp_path / 'ev.db'}")
    Base.metadata.create_all(eng, tables=[Base.metadata.tables[t] for t in ("docs", "ledger_entries", "ledger_heads")])
    sf = make_session_factory(eng)
    store = EvidenceStore(DocStore(sf), Ledger(sf, signer=Signer.generate("k1")))
    _, res = _sharded(c, _inputs(c, d)[:10], now, "sentinel", model=load_default(), bundle=lab_bundle(c),
                      collect="all", evidence_factory=lambda: store,
                      sentinel_kwargs={"tenant_id": c.tenant_id})
    assert res.findings
    for f in res.findings:
        assert f.evidence_ids
        assert len(store.list_for(c.tenant_id, f.evidence_ids)) == len(f.evidence_ids)
    ok, bad = store.ledger.verify_chain(c.tenant_id)
    assert ok and bad is None
    eng.dispose()


def test_line_shard_config_fails_closed_on_tenancy():
    src = SourceConfig(tenant_id="t1", source_id="nf", source_kind=SourceKind.NETFLOW,
                       vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-1")
    with pytest.raises(ValueError, match="without a pseudonym key"):
        LineShardConfig(sources={"nf": src}, tenant_keys={"t2": b"k" * 32}, mode="ingest")
    with pytest.raises(ValueError, match="exactly one tenant"):
        LineShardConfig(sources={"nf": src}, tenant_keys={"t1": b"k" * 32, "t2": b"j" * 32}, mode="sentinel")
    with pytest.raises(ValueError, match="does not match"):
        LineShardConfig(sources={"nf": src}, tenant_keys={"t1": b"k" * 32}, mode="sentinel",
                        sentinel_kwargs={"tenant_id": "t2"})
    cfg = LineShardConfig(sources={"nf": src}, tenant_keys={"t1": b"k" * 32}, mode="sentinel")
    assert cfg.sentinel_kwargs["tenant_id"] == "t1"     # SENTINEL rejects any other tenant's event
