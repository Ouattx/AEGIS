import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from aegis.contracts.models import SourceKind, Vantage
from aegis.ingest.normalize import SourceConfig, normalize
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.ingest.validator import (
    MAX_RAW_BYTES,
    Quarantined,
    QuarantineStore,
    Validator,
    make_quarantined,
    validate,
)
from aegis.storage.db import Base, DocStore, make_engine, make_session_factory

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def event(**overrides):
    src = SourceConfig(tenant_id="t1", source_id="s1", source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
                       collection_authorization_id="auth-1")
    raw = {"record_type": "flow", "observed_at": "2026-10-01T00:00:00Z", "device_id": "dev-1",
           "dst_ip": "198.18.0.5", "bytes_out": "10", "_raw": b"x"}
    ev = normalize(raw, src, Pseudonymizer(b"k" * 32), NOW)
    d = ev.model_dump(mode="json")
    for path, value in overrides.items():
        cur = d
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur[p]
        if value is KeyError:
            cur.pop(parts[-1])
        else:
            cur[parts[-1]] = value
    return ev, d


V = Validator(clock=lambda: NOW)


def test_valid_inputs_in_all_forms():
    ev, d = event()
    assert V.validate(ev) is ev
    assert V.validate(d) == ev
    assert V.validate(json.dumps(d).encode()) == ev
    assert V.validate(json.dumps(d)) == ev
    assert V(d) == ev
    assert validate(d) == ev  # default module-level validator


@pytest.mark.parametrize("overrides,reason", [
    ({"flow.bytes_out": "10"}, "schema:flow.bytes_out:int_type"),
    ({"tenant_id": KeyError}, "schema:tenant_id:missing"),
    ({"schema_version": "2.0"}, "schema:schema_version:literal_error"),
    ({"surprise": 1}, "schema:surprise:extra_forbidden"),
    ({"observed_at": "2026-10-01T00:00:00"}, "naive_datetime"),
    ({"observed_at": "2027-01-01T00:00:00Z", "retention_until": "2027-02-01T00:00:00Z"}, "future_timestamp"),
    ({"ingested_at": "2026-09-01T00:00:00Z"}, "ingested_before_observed"),
    ({"retention_until": "2026-09-01T00:00:00Z"}, "bad_retention"),
    ({"integrity_sha256": "abc"}, "bad_integrity_hash"),
    ({"entity_pseudonym": None}, "missing_entity"),
    ({"entity_pseudonym": "02:aa:bb:cc:dd:ee"}, "raw_identifier"),
    ({"flow": None}, "observation_shape"),
    ({"dns": {"qname": "a.example", "qtype": "A", "rcode": "NOERROR", "answers": []}}, "observation_shape"),
    ({"flow.src_ip": "100.64.0.1"}, "subscriber_ip_present"),
    ({"flow.dst_ip": "not-ip"}, "bad_dst_ip"),
    ({"flow.dst_port": 70000}, "bad_dst_port"),
    ({"flow.bytes_in": -1}, "negative_counter"),
    ({"collection_authorization_id": "  "}, "missing_authorization"),
])
def test_quarantine_reasons(overrides, reason):
    _, d = event(**overrides)
    q = V.validate(d)
    assert isinstance(q, Quarantined), q
    assert q.reason == reason
    assert q.raw_size > 0 and len(q.raw_sha256) == 64


def test_bytes_quarantine_preserves_original_bytes():
    q = V.validate(b"\xff not json")
    assert isinstance(q, Quarantined) and q.reason == "invalid_json"
    assert q.raw_bytes() == b"\xff not json"
    assert q.tenant_id == "_unknown"
    assert V.validate(b"[1]").reason == "not_object"
    assert V.validate(42).reason == "unsupported_type"  # type: ignore[arg-type]
    assert V.validate({"tenant_id": "t9", "x": object()}).reason == "not_serializable"


def test_original_hash_is_of_exact_bytes():
    _, d = event(**{"flow.bytes_out": "oops"})
    payload = json.dumps(d, indent=3).encode()
    q = V.validate(payload)
    import hashlib
    assert q.raw_sha256 == hashlib.sha256(payload).hexdigest()
    assert q.tenant_id == "t1"


def test_tenant_pinning_and_authorization_registry():
    ev, d = event()
    assert Validator(expected_tenant="other", clock=lambda: NOW).validate(d).reason == "tenant_mismatch"
    reg = Validator(allowed_authorizations={"t1": ["auth-2"]}, clock=lambda: NOW)
    assert reg.validate(d).reason == "unauthorized_collection"
    assert Validator(allowed_authorizations={}, clock=lambda: NOW).validate(ev).reason == "unauthorized_collection"
    assert Validator(allowed_authorizations={"t1": ["auth-1"]}, clock=lambda: NOW).validate(d) == ev


def test_make_quarantined_truncation():
    big = b"a" * (MAX_RAW_BYTES + 10)
    q = make_quarantined(big, "x", now=NOW)
    assert q.raw_truncated and q.raw_size == len(big) and len(q.raw_bytes()) == MAX_RAW_BYTES
    assert q.retention_until == NOW + timedelta(days=30)
    assert base64.b64decode(q.raw_b64) == big[:MAX_RAW_BYTES]


def test_quarantine_store_memory_is_tenant_scoped():
    store = QuarantineStore(max_items=3)
    a = store.put(make_quarantined(b"1", "r1", tenant_id="t1", now=NOW))
    store.put(make_quarantined(b"2", "r2", tenant_id="t2", now=NOW))
    for _ in range(3):
        store.put(make_quarantined(b"3", "r1", tenant_id="t1", now=NOW))
    assert store.count("t1") == 4 and store.reasons("t1") == {"r1": 4}  # counters never truncated
    assert len(store.list("t1")) == 3 and store.list("t2") == []  # buffer bounded to newest 3
    assert store.get("t2", a.event_id) is None
    assert store.list("t3") == []


def test_quarantine_store_persists_to_docstore(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'q.db'}")
    Base.metadata.create_all(engine)  # only the docs table is needed here
    ds = DocStore(make_session_factory(engine))
    store = QuarantineStore(docstore=ds)
    q = store.put(make_quarantined(b"payload", "bad_dst_ip", tenant_id="t1", source_id="s", now=NOW))
    assert store.get("t1", q.event_id) == q
    assert store.get("t2", q.event_id) is None
    assert [x.event_id for x in store.list("t1")] == [q.event_id]
    assert store.get("t1", q.event_id).raw_bytes() == b"payload"
