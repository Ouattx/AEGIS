import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aegis.contracts.models import ObservationEvent, SourceKind, Vantage
from aegis.ingest import (
    Backpressure,
    InMemoryBus,
    IngestBackpressureError,
    IngestPipeline,
    Pseudonymizer,
    QuarantineStore,
    Quarantined,
    SourceConfig,
    TenantKeyProvider,
    UnknownSourceError,
    Validator,
)

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
SAMPLES = Path(__file__).resolve().parents[2] / "sample_data"
HEADER = ("ts,device_id,device_class,src_ip,src_port,dst_ip,dst_port,proto,packets_out,bytes_out,packets_in,"
          "bytes_in,duration_ms")


def line(i, **kw):
    vals = dict(ts=f"2026-10-01T00:00:{i % 60:02d}.000Z", dev="02:00:5e:00:00:01", dst="198.18.0.5", bo=str(1000 + i))
    vals.update(kw)
    return f"{vals['ts']},{vals['dev']},android_tv,100.64.0.1,40000,{vals['dst']},443,6,1,{vals['bo']},1,2,3"


def sources():
    return [
        SourceConfig(tenant_id="t1", source_id="nf", source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
                     collection_authorization_id="a1"),
        SourceConfig(tenant_id="t2", source_id="nf2", source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
                     collection_authorization_id="a2"),
        SourceConfig(tenant_id="t1", source_id="dns", source_kind=SourceKind.DNS, vantage=Vantage.DEVICE,
                     collection_authorization_id="a1"),
        SourceConfig(tenant_id="t1", source_id="cpe", source_kind=SourceKind.CPE, vantage=Vantage.DEVICE,
                     collection_authorization_id="a1"),
        SourceConfig(tenant_id="t1", source_id="zc", source_kind=SourceKind.ZEEK_CONN,
                     vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="a1"),
    ]


def make(bus=None, **kw):
    bus = bus or InMemoryBus()
    got: list[ObservationEvent] = []
    bus.subscribe("observations", got.append)
    keys = TenantKeyProvider(b"m" * 32)
    pl = IngestPipeline(bus, Validator(clock=lambda: NOW), sources(), key_provider=keys, clock=lambda: NOW, **kw)
    return pl, bus, got


def test_every_record_is_accounted_for():
    pl, bus, got = make()
    text = "\n".join([HEADER, line(1), line(2), "garbage", line(3, dst="x"), line(1)]) + "\n"
    st = pl.ingest_text(text, "nf", name="upload.csv")
    bus.drain()
    assert st.records_read == 5
    assert (st.accepted, st.published, st.quarantined, st.duplicates) == (2, 2, 2, 1)
    assert st.accepted + st.quarantined + st.duplicates == st.records_read
    assert st.quarantine_reasons == {"column_count": 1, "bad_dst_ip": 1}
    assert st.success_rate == pytest.approx(0.5)
    assert len(got) == 2 and all(e.tenant_id == "t1" for e in got)
    assert got[0].raw_artifact_ref == "raw://nf/upload.csv#L2"
    qs = pl.quarantine.list("t1")
    assert {q.reason for q in qs} == {"column_count", "bad_dst_ip"}
    garbage = next(q for q in qs if q.reason == "column_count")
    assert garbage.raw_bytes() == b"garbage" and garbage.line_no == 4 and garbage.stage == "parse"
    d = st.to_dict()
    assert d["records_read"] == 5 and d["events_per_s"] is not None and json.dumps(d)


def test_reingesting_same_file_is_idempotent(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("\n".join([HEADER, line(1), line(2)]) + "\n")
    pl, bus, got = make()
    pl.ingest_file(p, "nf")
    st = pl.ingest_file(p, "nf")
    bus.drain()
    assert st.duplicates == 2 and st.published == 0 and len(got) == 2
    pl2, bus2, got2 = make(dedupe_window=0)
    pl2.ingest_file(p, "nf")
    pl2.ingest_file(p, "nf")
    bus2.drain()
    assert len(got2) == 4


def test_tenant_isolation_of_pseudonyms():
    pl, bus, got = make()
    text = "\n".join([HEADER, line(1)])
    pl.ingest_text(text, "nf")
    pl.ingest_text(text, "nf2")
    bus.drain()
    assert got[0].tenant_id == "t1" and got[1].tenant_id == "t2"
    assert got[0].entity_pseudonym != got[1].entity_pseudonym
    assert got[0].integrity_sha256 == got[1].integrity_sha256


def test_unknown_source_fails_closed(tmp_path):
    pl, _, _ = make()
    with pytest.raises(UnknownSourceError):
        pl.ingest_text("x", "nope")
    with pytest.raises(UnknownSourceError):
        pl.ingest_file(tmp_path / "x.csv", "nope")


def test_unparseable_input_is_quarantined_not_raised():
    pl, _, _ = make()
    st = pl.ingest_text("no,header,here\n1,2,3\n", "nf", name="bad.csv")
    assert st.quarantined == 1 and st.quarantine_reasons == {"unparseable_input": 1}
    assert pl.quarantine.list("t1")[0].stage == "parse"


def test_backpressure_drains_and_retries():
    bus = InMemoryBus(max_queue=3, per_tenant_quota=2)
    pl, bus, got = make(bus)
    text = "\n".join([HEADER] + [line(i) for i in range(10)])
    st = pl.ingest_text(text, "nf")
    bus.drain()
    assert st.published == 10 and len(got) == 10 and st.backpressure_waits > 0


class StuckBus:
    def __init__(self):
        self.handlers = []

    def publish(self, topic, event):
        raise Backpressure("stuck", retry_after_s=0.0)

    def subscribe(self, topic, handler):
        self.handlers.append(handler)

    def drain(self):
        return 0


def test_persistent_backpressure_aborts_with_partial_stats():
    pl, _, _ = make(StuckBus(), max_publish_retries=2)
    with pytest.raises(IngestBackpressureError) as ei:
        pl.ingest_text("\n".join([HEADER, line(1), line(2)]), "nf")
    assert ei.value.stats.records_read == 1 and ei.value.stats.backpressure_waits == 3


def test_other_formats(tmp_path):
    pl, bus, got = make()
    dns = json.dumps({"ts": "2026-10-01T00:00:00Z", "device_id": "d1", "qname": "a.example", "rcode": "NOERROR"})
    assert pl.ingest_text(dns, "dns").published == 1
    st = pl.ingest_file(SAMPLES / "formats" / "cpe.json", "cpe")
    assert st.published == 3 and st.quarantined == 0
    st = pl.ingest_file(SAMPLES / "zeek" / "conn.log", "zc")
    assert st.published > 0 and st.quarantined == 0
    bus.drain()
    assert {e.source_kind for e in got} == {SourceKind.DNS, SourceKind.CPE, SourceKind.ZEEK_CONN}


def test_malformed_sample_quarantines_every_bad_line():
    pl, bus, got = make()
    st = pl.ingest_file(SAMPLES / "formats" / "malformed_netflow.csv", "nf")
    assert st.records_read == 9 and st.published == 1 and st.quarantined == 8
    assert set(st.quarantine_reasons) == {"naive_timestamp", "bad_dst_ip", "bad_dst_port", "bad_bytes_out",
                                          "column_count", "future_timestamp", "missing_entity"}
    for q in pl.quarantine.list("t1"):
        assert q.raw_artifact_ref.startswith("raw://nf/malformed_netflow.csv#L")
        assert len(q.raw_sha256) == 64 and q.raw_bytes()


def test_validator_rejection_inside_pipeline_is_quarantined():
    bus = InMemoryBus()
    strict = Validator(clock=lambda: NOW, allowed_authorizations={"t1": ["other"]})
    pl = IngestPipeline(bus, strict, sources(), pseudonymizers={"t1": Pseudonymizer(b"k" * 32)}, clock=lambda: NOW)
    st = pl.ingest_text("\n".join([HEADER, line(1)]), "nf")
    assert st.quarantine_reasons == {"unauthorized_collection": 1}
    q = pl.quarantine.list("t1")[0]
    assert q.line_no == 2 and q.raw_artifact_ref == "raw://nf/inline#L2"


def test_ingest_event_payloads():
    pl, bus, got = make()
    pl.ingest_text("\n".join([HEADER, line(1)]), "nf")
    bus.drain()
    good = got[0].model_dump(mode="json")
    good["event_id"] = "new"
    assert isinstance(pl.ingest_event(json.dumps(good)), ObservationEvent)
    bus.drain()
    assert got[-1].event_id == "new"
    unknown = dict(good, source_id="ghost")
    assert pl.ingest_event(unknown).reason == "unknown_source"
    mismatch = dict(good, collection_authorization_id="forged")
    assert pl.ingest_event(mismatch).reason == "source_mismatch"
    bad = dict(good, entity_pseudonym="02:aa:bb:cc:dd:ee")
    assert pl.ingest_event(bad).reason == "raw_identifier"
    assert pl.quarantine.count("t1") == 3


def test_register_source_and_explicit_pseudonymizers():
    bus = InMemoryBus()
    got = []
    bus.subscribe("observations", got.append)
    p = Pseudonymizer(b"z" * 32)
    pl = IngestPipeline(bus, None, {}, pseudonymizers={"t9": p}, quarantine=QuarantineStore(), clock=lambda: NOW)
    pl.register_source(SourceConfig(tenant_id="t9", source_id="s9", source_kind=SourceKind.NETFLOW,
                                    vantage=Vantage.DEVICE, collection_authorization_id="a"))
    pl.ingest_records([{"record_type": "flow", "observed_at": "2026-10-01T00:00:00Z", "device_id": "d",
                        "dst_ip": "198.18.0.9"}], "s9")
    bus.drain()
    assert got[0].entity_pseudonym == p.pseudonym("d")
    assert got[0].raw_artifact_ref == "raw://s9/records"
    assert pl.pseudonymizer_for("t9") is p


def test_default_key_provider_from_env(monkeypatch):
    monkeypatch.setenv("AEGIS_PSEUDONYM_MASTER_KEY", "cd" * 32)
    pl = IngestPipeline(InMemoryBus(), None, sources())
    assert pl.pseudonymizer_for("t1").pseudonym("x") == TenantKeyProvider(bytes.fromhex("cd" * 32)) \
        .pseudonymizer("t1").pseudonym("x")


def test_quarantined_records_never_reach_bus():
    pl, bus, got = make()
    pl.ingest_text("\n".join([HEADER, line(1, bo="-1"), line(2, ts="2026-10-01T00:00:00")]), "nf")
    bus.drain()
    assert got == [] and all(isinstance(q, Quarantined) for q in pl.quarantine.list("t1"))
