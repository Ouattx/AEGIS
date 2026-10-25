"""Event bus with backpressure, dead-letter queue and per-tenant quotas (spec section 13).

``InMemoryBus`` is the single-host bus used by the on-prem docker-compose
deployment and the tests. ``KafkaBus`` (requires ``confluent_kafka``) has the
same contract for Kafka/Redpanda deployments.

Contract
--------
- ``publish`` never blocks: when the bus is full it raises :class:`Backpressure`
  (``reason="queue_full"``), and when one tenant has too many undelivered
  events it raises :class:`QuotaExceeded` (a ``Backpressure`` subclass,
  ``reason="tenant_quota"``). Producers react by draining/slowing down; one noisy
  tenant can never starve the others.
- ``drain`` delivers queued events to subscribers. A handler that keeps failing
  after ``max_attempts`` sends the event to the ``dlq`` topic as a
  :class:`DeadLetter`; events are never silently lost.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from pydantic import BaseModel

log = logging.getLogger(__name__)

DLQ_TOPIC = "dlq"
OBSERVATIONS_TOPIC = "observations"
UNKNOWN_TENANT = "_unknown"

Handler = Callable[[Any], None]


class Backpressure(RuntimeError):
    """The bus cannot accept the event now; retry after draining / ``retry_after_s``."""

    def __init__(self, message: str, *, reason: str = "queue_full", tenant_id: str | None = None,
                 retry_after_s: float = 0.05):
        super().__init__(message)
        self.reason = reason
        self.tenant_id = tenant_id
        self.retry_after_s = retry_after_s


class QuotaExceeded(Backpressure):
    """A tenant has reached its in-flight event quota."""


@dataclass
class DeadLetter:
    topic: str
    event: Any
    error: str
    attempts: int
    tenant_id: str
    dead_lettered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        ev = self.event.model_dump(mode="json") if isinstance(self.event, BaseModel) else self.event
        return {"topic": self.topic, "event": ev, "error": self.error, "attempts": self.attempts,
                "tenant_id": self.tenant_id, "dead_lettered_at": self.dead_lettered_at.isoformat()}


@runtime_checkable
class EventBus(Protocol):
    def publish(self, topic: str, event: Any) -> None: ...

    def subscribe(self, topic: str, handler: Handler) -> None: ...

    def drain(self) -> int: ...


def tenant_of(event: Any) -> str:
    t = getattr(event, "tenant_id", None)
    if t is None and isinstance(event, Mapping):
        t = event.get("tenant_id")
    return t if isinstance(t, str) and t else UNKNOWN_TENANT


@dataclass
class BusStats:
    published: int = 0
    delivered: int = 0
    handler_errors: int = 0
    dead_lettered: int = 0
    rejected_queue_full: int = 0
    rejected_quota: int = 0
    dlq_overflow: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


class InMemoryBus:
    """Bounded in-process bus.

    Parameters
    ----------
    max_queue: total undelivered events across all topics before ``Backpressure``.
    per_tenant_quota: max undelivered events per tenant (``None`` = only ``max_queue``).
    tenant_quotas: per-tenant overrides of ``per_tenant_quota``.
    max_attempts: handler attempts per event before dead-lettering.
    max_dead_letters: retained ``DeadLetter`` records (overflow is counted).
    """

    def __init__(self, max_queue: int = 100_000, per_tenant_quota: int | None = None, *,
                 tenant_quotas: Mapping[str, int] | None = None, max_attempts: int = 3,
                 max_dead_letters: int = 100_000):
        if max_queue < 1:
            raise ValueError("max_queue must be >= 1")
        if per_tenant_quota is not None and per_tenant_quota < 1:
            raise ValueError("per_tenant_quota must be >= 1")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self.max_queue = max_queue
        self.per_tenant_quota = per_tenant_quota
        self.tenant_quotas = dict(tenant_quotas or {})
        self.max_attempts = max_attempts
        self._queue: deque[tuple[str, Any, str]] = deque()
        self._inflight: dict[str, int] = {}
        self._handlers: dict[str, list[Handler]] = {}
        self.dead_letters: deque[DeadLetter] = deque(maxlen=max_dead_letters)
        self.stats = BusStats()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ API
    def quota_for(self, tenant_id: str) -> int | None:
        return self.tenant_quotas.get(tenant_id, self.per_tenant_quota)

    def publish(self, topic: str, event: Any) -> None:
        tenant = tenant_of(event)
        with self._lock:
            if len(self._queue) >= self.max_queue:
                self.stats.rejected_queue_full += 1
                raise Backpressure(f"bus full ({self.max_queue} undelivered events)",
                                   reason="queue_full", tenant_id=tenant)
            quota = self.quota_for(tenant)
            if quota is not None and self._inflight.get(tenant, 0) >= quota:
                self.stats.rejected_quota += 1
                raise QuotaExceeded(f"tenant {tenant!r} reached its quota of {quota} in-flight events",
                                    reason="tenant_quota", tenant_id=tenant)
            self._queue.append((topic, event, tenant))
            self._inflight[tenant] = self._inflight.get(tenant, 0) + 1
            self.stats.published += 1

    def subscribe(self, topic: str, handler: Handler) -> None:
        with self._lock:
            self._handlers.setdefault(topic, []).append(handler)

    def depth(self, tenant_id: str | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                return len(self._queue)
            return self._inflight.get(tenant_id, 0)

    def drain(self, max_events: int | None = None) -> int:
        """Deliver queued events in FIFO order; return the number processed.

        Events on a topic with no subscriber are consumed (acknowledged) — the bus
        is not a store. Handlers run outside the bus lock so they may publish.
        """
        processed = 0
        while max_events is None or processed < max_events:
            with self._lock:
                if not self._queue:
                    break
                topic, event, tenant = self._queue.popleft()
                handlers = list(self._handlers.get(topic, ()))
            try:
                for h in handlers:
                    self._deliver(topic, event, tenant, h)
            finally:
                with self._lock:
                    left = self._inflight.get(tenant, 1) - 1
                    if left > 0:
                        self._inflight[tenant] = left
                    else:
                        self._inflight.pop(tenant, None)
            processed += 1
        return processed

    def replay_dead_letters(self, topic: str | None = None) -> int:
        """Re-enqueue dead letters (optionally only those from ``topic``) after a fix.

        Re-enqueued events go through normal backpressure/quota checks; letters
        that cannot be re-enqueued stay in the DLQ.
        """
        with self._lock:
            letters = list(self.dead_letters)
            self.dead_letters.clear()
        replayed = 0
        keep: list[DeadLetter] = []
        for dl in letters:
            if topic is not None and dl.topic != topic:
                keep.append(dl)
                continue
            try:
                self.publish(dl.topic, dl.event)
                replayed += 1
            except Backpressure:
                keep.append(dl)
        with self._lock:
            self.dead_letters.extend(keep)
        return replayed

    # ------------------------------------------------------------------ internals
    def _deliver(self, topic: str, event: Any, tenant: str, handler: Handler) -> None:
        last_error: BaseException | None = None
        for _attempt in range(self.max_attempts):
            try:
                handler(event)
                with self._lock:
                    self.stats.delivered += 1
                return
            except Exception as exc:  # handler bugs must not kill the bus
                last_error = exc
                with self._lock:
                    self.stats.handler_errors += 1
        self._dead_letter(topic, event, tenant, f"{type(last_error).__name__}: {last_error}")

    def _dead_letter(self, topic: str, event: Any, tenant: str, error: str) -> None:
        dl = DeadLetter(topic=topic, event=event, error=error, attempts=self.max_attempts, tenant_id=tenant)
        with self._lock:
            if len(self.dead_letters) == self.dead_letters.maxlen:
                self.stats.dlq_overflow += 1
            self.dead_letters.append(dl)
            self.stats.dead_lettered += 1
            dlq_handlers = list(self._handlers.get(DLQ_TOPIC, ())) if topic != DLQ_TOPIC else []
        log.warning("dead-lettered event from topic %s (tenant %s): %s", topic, tenant, error)
        for h in dlq_handlers:
            try:
                h(dl)
            except Exception:  # a failing DLQ consumer must not recurse into the DLQ
                log.exception("DLQ handler failed")


# ---------------------------------------------------------------------------- Kafka

def _default_serialize(event: Any) -> bytes:
    if isinstance(event, BaseModel):
        return event.model_dump_json().encode("utf-8")
    if isinstance(event, DeadLetter):
        return json.dumps(event.to_dict(), default=str).encode("utf-8")
    return json.dumps(event, default=str).encode("utf-8")


class KafkaBus:
    """Kafka / Redpanda bus with the same contract as :class:`InMemoryBus`.

    - Messages are keyed by tenant id (per-tenant ordering, tenant-sticky partitions)
      and carry ``tenant_id`` / ``schema`` headers.
    - Per-tenant quota counts produced-but-unacknowledged messages.
    - A producer queue overflow (``BufferError``) is surfaced as ``Backpressure``.
    - Failing handlers dead-letter to ``{topic_prefix}dlq`` after ``max_attempts``.

    ``subscribe(topic, handler, model=None)``: handlers receive the decoded JSON
    dict, or a validated ``model`` instance when given.
    """

    def __init__(self, bootstrap_servers: str, *, group_id: str = "aegis-ingest",
                 topic_prefix: str = "aegis.", per_tenant_quota: int | None = None,
                 max_attempts: int = 3, producer_config: Mapping[str, Any] | None = None,
                 consumer_config: Mapping[str, Any] | None = None,
                 serializer: Callable[[Any], bytes] = _default_serialize):
        try:
            import confluent_kafka  # noqa: PLC0415 - optional dependency
        except ImportError as exc:  # pragma: no cover - exercised via test with module absent
            raise RuntimeError("KafkaBus requires the 'confluent-kafka' package "
                               "(pip install 'aegis-omega[kafka]')") from exc
        self._ck = confluent_kafka
        pconf = {"bootstrap.servers": bootstrap_servers, "enable.idempotence": True,
                 "acks": "all", "linger.ms": 5}
        pconf.update(producer_config or {})
        cconf = {"bootstrap.servers": bootstrap_servers, "group.id": group_id,
                 "enable.auto.commit": False, "auto.offset.reset": "earliest"}
        cconf.update(consumer_config or {})
        self._producer = confluent_kafka.Producer(pconf)
        self._consumer_conf = cconf
        self._consumer: Any = None
        self.topic_prefix = topic_prefix
        self.per_tenant_quota = per_tenant_quota
        self.max_attempts = max_attempts
        self._serialize = serializer
        self._handlers: dict[str, list[tuple[Handler, type[BaseModel] | None]]] = {}
        self._inflight: dict[str, int] = {}
        self._lock = threading.Lock()
        self.stats = BusStats()
        self.delivery_errors: list[str] = []

    def _t(self, topic: str) -> str:
        return f"{self.topic_prefix}{topic}"

    def publish(self, topic: str, event: Any) -> None:
        tenant = tenant_of(event)
        with self._lock:
            if self.per_tenant_quota is not None and self._inflight.get(tenant, 0) >= self.per_tenant_quota:
                self.stats.rejected_quota += 1
                raise QuotaExceeded(f"tenant {tenant!r} reached its quota of {self.per_tenant_quota}",
                                    reason="tenant_quota", tenant_id=tenant)
            self._inflight[tenant] = self._inflight.get(tenant, 0) + 1
        try:
            self._producer.produce(self._t(topic), value=self._serialize(event),
                                   key=tenant.encode("utf-8"),
                                   headers=[("tenant_id", tenant.encode("utf-8")),
                                            ("schema", type(event).__name__.encode("utf-8"))],
                                   on_delivery=self._on_delivery_for(tenant))
        except BufferError as exc:
            self._release(tenant)
            self.stats.rejected_queue_full += 1
            self._producer.poll(0)
            raise Backpressure("kafka producer queue full", reason="queue_full", tenant_id=tenant,
                               retry_after_s=0.1) from exc
        self.stats.published += 1
        self._producer.poll(0)

    def _on_delivery_for(self, tenant: str) -> Callable[[Any, Any], None]:
        def cb(err: Any, _msg: Any) -> None:
            self._release(tenant)
            if err is not None:
                self.delivery_errors.append(str(err))
                log.error("kafka delivery failed for tenant %s: %s", tenant, err)
        return cb

    def _release(self, tenant: str) -> None:
        with self._lock:
            left = self._inflight.get(tenant, 1) - 1
            if left > 0:
                self._inflight[tenant] = left
            else:
                self._inflight.pop(tenant, None)

    def subscribe(self, topic: str, handler: Handler, model: type[BaseModel] | None = None) -> None:
        self._handlers.setdefault(self._t(topic), []).append((handler, model))
        if self._consumer is not None:
            self._consumer.subscribe(sorted(self._handlers))

    def flush(self, timeout_s: float = 10.0) -> int:
        return int(self._producer.flush(timeout_s))

    def drain(self, timeout_s: float = 1.0, max_messages: int = 10_000) -> int:
        """Flush the producer, then consume and dispatch available messages."""
        self.flush(timeout_s)
        if not self._handlers:
            return 0
        if self._consumer is None:
            self._consumer = self._ck.Consumer(self._consumer_conf)
            self._consumer.subscribe(sorted(self._handlers))
        processed = 0
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while processed < max_messages:
            msg = self._consumer.poll(0.1)
            if msg is None:
                if time.monotonic() >= deadline:
                    break
                continue
            if msg.error():
                log.error("kafka consumer error: %s", msg.error())
                continue
            self._dispatch(msg)
            self._consumer.commit(message=msg, asynchronous=False)
            processed += 1
        return processed

    def _dispatch(self, msg: Any) -> None:
        topic = msg.topic()
        try:
            payload = json.loads(msg.value())
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            self._to_dlq(topic, msg.value(), f"undecodable message: {exc}", UNKNOWN_TENANT)
            return
        tenant = tenant_of(payload)
        for handler, model in self._handlers.get(topic, ()):
            last: BaseException | None = None
            for _ in range(self.max_attempts):
                try:
                    handler(model.model_validate(payload) if model is not None else payload)
                    self.stats.delivered += 1
                    last = None
                    break
                except Exception as exc:
                    last = exc
                    self.stats.handler_errors += 1
            if last is not None:
                self._to_dlq(topic, payload, f"{type(last).__name__}: {last}", tenant)

    def _to_dlq(self, topic: str, event: Any, error: str, tenant: str) -> None:
        if isinstance(event, (bytes, bytearray)):
            event = event.decode("utf-8", "replace")
        dl = DeadLetter(topic=topic, event=event, error=error, attempts=self.max_attempts, tenant_id=tenant)
        self.stats.dead_lettered += 1
        self._producer.produce(self._t(DLQ_TOPIC), value=self._serialize(dl), key=tenant.encode("utf-8"),
                               headers=[("tenant_id", tenant.encode("utf-8")), ("schema", b"DeadLetter")])
        self._producer.poll(0)

    def close(self) -> None:
        self.flush()
        if self._consumer is not None:
            self._consumer.close()
