import json
import sys
import threading
import types

import pytest

from aegis.ingest.bus import (
    DLQ_TOPIC,
    Backpressure,
    DeadLetter,
    EventBus,
    InMemoryBus,
    KafkaBus,
    QuotaExceeded,
    tenant_of,
)


def ev(tenant="t1", n=0):
    return {"tenant_id": tenant, "n": n}


def test_protocol_and_fifo_delivery():
    bus = InMemoryBus()
    assert isinstance(bus, EventBus)
    got = []
    bus.subscribe("obs", got.append)
    for i in range(5):
        bus.publish("obs", ev(n=i))
    assert bus.depth() == 5 and bus.depth("t1") == 5
    assert bus.drain() == 5
    assert [g["n"] for g in got] == list(range(5))
    assert bus.depth() == 0 and bus.stats.delivered == 5


def test_backpressure_when_full_and_recovery_after_drain():
    bus = InMemoryBus(max_queue=2)
    bus.publish("obs", ev())
    bus.publish("obs", ev())
    with pytest.raises(Backpressure) as ei:
        bus.publish("obs", ev())
    assert ei.value.reason == "queue_full" and not isinstance(ei.value, QuotaExceeded)
    assert bus.stats.rejected_queue_full == 1
    bus.drain()
    bus.publish("obs", ev())


def test_per_tenant_quota_isolates_noisy_tenant():
    bus = InMemoryBus(max_queue=100, per_tenant_quota=2, tenant_quotas={"vip": 5})
    bus.publish("obs", ev("noisy"))
    bus.publish("obs", ev("noisy"))
    with pytest.raises(QuotaExceeded) as ei:
        bus.publish("obs", ev("noisy"))
    assert ei.value.tenant_id == "noisy" and ei.value.reason == "tenant_quota"
    bus.publish("obs", ev("quiet"))  # other tenants unaffected
    for _ in range(5):
        bus.publish("obs", ev("vip"))
    with pytest.raises(QuotaExceeded):
        bus.publish("obs", ev("vip"))
    assert bus.stats.rejected_quota == 2
    bus.drain()
    bus.publish("obs", ev("noisy"))


def test_failing_handler_dead_letters_after_retries():
    bus = InMemoryBus(max_attempts=3)
    calls = {"n": 0}

    def bad(_e):
        calls["n"] += 1
        raise RuntimeError("boom")

    dlq = []
    bus.subscribe("obs", bad)
    bus.subscribe(DLQ_TOPIC, dlq.append)
    bus.publish("obs", ev())
    bus.drain()
    assert calls["n"] == 3
    assert len(bus.dead_letters) == 1 and len(dlq) == 1
    dl = dlq[0]
    assert isinstance(dl, DeadLetter) and dl.topic == "obs" and dl.attempts == 3 and "boom" in dl.error
    assert dl.to_dict()["event"] == ev()
    assert bus.stats.dead_lettered == 1 and bus.stats.handler_errors == 3
    assert bus.depth("t1") == 0  # quota released even on failure


def test_transient_failure_is_retried_not_dead_lettered():
    bus = InMemoryBus(max_attempts=3)
    state = {"n": 0}

    def flaky(_e):
        state["n"] += 1
        if state["n"] < 2:
            raise ValueError("transient")

    bus.subscribe("obs", flaky)
    bus.publish("obs", ev())
    bus.drain()
    assert not bus.dead_letters and bus.stats.delivered == 1


def test_failing_dlq_handler_does_not_recurse():
    bus = InMemoryBus(max_attempts=1)
    bus.subscribe("obs", lambda e: 1 / 0)
    bus.subscribe(DLQ_TOPIC, lambda e: 1 / 0)
    bus.publish("obs", ev())
    bus.drain()
    assert len(bus.dead_letters) == 1


def test_replay_dead_letters():
    bus = InMemoryBus(max_attempts=1)
    healthy = {"ok": False}
    got = []

    def handler(e):
        if not healthy["ok"]:
            raise RuntimeError("down")
        got.append(e)

    bus.subscribe("obs", handler)
    bus.subscribe("other", lambda e: 1 / 0)
    bus.publish("obs", ev(n=1))
    bus.publish("other", ev(n=2))
    bus.drain()
    assert len(bus.dead_letters) == 2
    healthy["ok"] = True
    assert bus.replay_dead_letters("obs") == 1
    bus.drain()
    assert got == [ev(n=1)]
    assert len(bus.dead_letters) == 1 and bus.dead_letters[0].topic == "other"


def test_replay_respects_backpressure():
    bus = InMemoryBus(max_queue=1, max_attempts=1)
    bus.subscribe("obs", lambda e: 1 / 0)
    bus.publish("obs", ev())
    bus.drain()
    bus.publish("obs", ev())  # fill the queue
    assert bus.replay_dead_letters() == 0 and len(bus.dead_letters) == 1


def test_dlq_overflow_is_counted():
    bus = InMemoryBus(max_attempts=1, max_dead_letters=1)
    bus.subscribe("obs", lambda e: 1 / 0)
    bus.publish("obs", ev())
    bus.publish("obs", ev())
    bus.drain()
    assert len(bus.dead_letters) == 1 and bus.stats.dlq_overflow == 1 and bus.stats.dead_lettered == 2


def test_handlers_may_publish_and_drain_limit():
    bus = InMemoryBus()
    out = []
    bus.subscribe("a", lambda e: bus.publish("b", e))
    bus.subscribe("b", out.append)
    bus.publish("a", ev())
    assert bus.drain(max_events=1) == 1 and out == []
    bus.drain()
    assert out == [ev()]


def test_unsubscribed_topics_are_consumed():
    bus = InMemoryBus(max_queue=1)
    bus.publish("nobody", ev())
    assert bus.drain() == 1
    bus.publish("nobody", ev())


def test_tenant_of_and_constructor_validation():
    class E:
        tenant_id = "x"
    assert tenant_of(E()) == "x" and tenant_of({"tenant_id": "y"}) == "y" and tenant_of(object()) == "_unknown"
    for kw in ({"max_queue": 0}, {"per_tenant_quota": 0}, {"max_attempts": 0}):
        with pytest.raises(ValueError):
            InMemoryBus(**kw)


def test_thread_safety_of_publish_and_drain():
    bus = InMemoryBus(max_queue=100_000)
    got = []
    lock = threading.Lock()

    def h(e):
        with lock:
            got.append(e)

    bus.subscribe("obs", h)

    def producer(t):
        for i in range(500):
            bus.publish("obs", ev(t, i))

    threads = [threading.Thread(target=producer, args=(f"t{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    bus.drain()
    assert len(got) == 2000 and bus.stats.to_dict()["published"] == 2000


# ---------------------------------------------------------------------- Kafka (fake client)

class _Msg:
    def __init__(self, topic, value, key=None, err=None):
        self._t, self._v, self._k, self._e = topic, value, key, err

    def topic(self):
        return self._t

    def value(self):
        return self._v

    def error(self):
        return self._e


def make_fake_kafka(capacity=1000):
    broker: dict[str, list[_Msg]] = {}

    class Producer:
        def __init__(self, conf):
            self.conf = conf
            self.pending = []

        def produce(self, topic, value=None, key=None, headers=None, on_delivery=None):
            if len(self.pending) >= capacity:
                raise BufferError("queue full")
            self.pending.append((topic, value, key, on_delivery))

        def poll(self, _t):
            return 0

        def flush(self, _t=None):
            for topic, value, key, cb in self.pending:
                broker.setdefault(topic, []).append(_Msg(topic, value, key))
                if cb:
                    cb(None, None)
            self.pending.clear()
            return 0

    class Consumer:
        def __init__(self, conf):
            self.conf = conf
            self.topics = []
            self.offsets: dict[str, int] = {}
            self.closed = False

        def subscribe(self, topics):
            self.topics = list(topics)

        def poll(self, _timeout):
            for t in self.topics:
                off = self.offsets.get(t, 0)
                msgs = broker.get(t, [])
                if off < len(msgs):
                    self.offsets[t] = off + 1
                    return msgs[off]
            return None

        def commit(self, message=None, asynchronous=True):
            return None

        def close(self):
            self.closed = True

    mod = types.ModuleType("confluent_kafka")
    mod.Producer = Producer
    mod.Consumer = Consumer
    return mod, broker


@pytest.fixture
def fake_kafka(monkeypatch):
    mod, broker = make_fake_kafka()
    monkeypatch.setitem(sys.modules, "confluent_kafka", mod)
    return broker


def test_kafka_requires_client(monkeypatch):
    monkeypatch.setitem(sys.modules, "confluent_kafka", None)
    with pytest.raises(RuntimeError, match="confluent-kafka"):
        KafkaBus("localhost:9092")


def test_kafka_publish_consume_and_dlq(fake_kafka):
    bus = KafkaBus("broker:9092", topic_prefix="aegis.", max_attempts=2)
    assert isinstance(bus, EventBus)
    got = []
    bus.subscribe("obs", got.append)
    bus.subscribe("bad", lambda e: 1 / 0)
    bus.publish("obs", ev(n=1))
    bus.publish("bad", ev(n=2))
    assert bus.drain(timeout_s=0) == 2
    assert got == [ev(n=1)]
    assert bus.stats.dead_lettered == 1 and bus.stats.handler_errors == 2
    bus.flush()
    dlq = [json.loads(m.value()) for m in fake_kafka["aegis.dlq"]]
    assert dlq[0]["event"] == ev(n=2) and dlq[0]["topic"] == "aegis.bad" and dlq[0]["tenant_id"] == "t1"
    assert fake_kafka["aegis.obs"][0]._k == b"t1"  # keyed by tenant
    bus.close()


def test_kafka_quota_and_release_on_delivery(fake_kafka):
    bus = KafkaBus("b", per_tenant_quota=1)
    bus.publish("obs", ev())
    with pytest.raises(QuotaExceeded):
        bus.publish("obs", ev())
    bus.flush()  # delivery callback releases the slot
    bus.publish("obs", ev())


def test_kafka_buffer_full_is_backpressure(monkeypatch):
    mod, _ = make_fake_kafka(capacity=1)
    monkeypatch.setitem(sys.modules, "confluent_kafka", mod)
    bus = KafkaBus("b", per_tenant_quota=5)
    bus.publish("obs", ev())
    with pytest.raises(Backpressure) as ei:
        bus.publish("obs", ev())
    assert ei.value.reason == "queue_full" and bus.stats.rejected_queue_full == 1
    bus.flush()
    bus.publish("obs", ev())


def test_kafka_model_decoding_and_undecodable(fake_kafka):
    from pydantic import BaseModel

    class M(BaseModel):
        tenant_id: str
        n: int

    bus = KafkaBus("b")
    got = []
    bus.subscribe("obs", got.append, model=M)
    bus.publish("obs", M(tenant_id="t1", n=3))
    fake_kafka.setdefault("aegis.obs", []).append(_Msg("aegis.obs", b"\xffnot json"))
    fake_kafka["aegis.obs"].append(_Msg("aegis.obs", None, err="partition eof"))
    bus.drain(timeout_s=0)
    assert got == [M(tenant_id="t1", n=3)]
    assert bus.stats.dead_lettered == 1
    assert bus.drain(timeout_s=0) == 0
