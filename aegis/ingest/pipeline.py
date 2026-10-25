"""Ingest pipeline: parse -> normalize/pseudonymize -> validate -> publish.

Every input record ends in exactly one of: published, quarantined (with its
original bytes), or skipped as an exact duplicate. ``IngestStats`` accounts for
all of them so the ingestion-success SLO (spec section 13) can be measured.
"""
from __future__ import annotations

import logging
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Union

from aegis.contracts.models import ObservationEvent
from aegis.ingest import parsers
from aegis.ingest.bus import OBSERVATIONS_TOPIC, Backpressure, EventBus
from aegis.ingest.normalize import NormalizationError, SourceConfig, normalize
from aegis.ingest.pseudonym import Pseudonymizer, TenantKeyProvider
from aegis.ingest.validator import QuarantineStore, Quarantined, Validator, make_quarantined

log = logging.getLogger(__name__)

ValidatorLike = Union[Validator, Callable[[Any], Union[ObservationEvent, Quarantined]]]


class IngestBackpressureError(RuntimeError):
    """The bus stayed saturated after all retries; ``stats`` holds partial progress.

    Records up to ``stats.records_read`` were processed; the caller can retry the
    remainder later (APIs map this to HTTP 429/503).
    """

    def __init__(self, message: str, stats: "IngestStats"):
        super().__init__(message)
        self.stats = stats


class UnknownSourceError(KeyError):
    pass


@dataclass
class IngestStats:
    source_id: str
    tenant_id: str
    input_ref: str
    format: str
    records_read: int = 0
    accepted: int = 0
    published: int = 0
    quarantined: int = 0
    duplicates: int = 0
    backpressure_waits: int = 0
    quarantine_reasons: dict[str, int] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    elapsed_s: float = 0.0

    @property
    def success_rate(self) -> float | None:
        """Share of non-duplicate records that became valid events (None if no records)."""
        considered = self.records_read - self.duplicates
        return None if considered <= 0 else self.accepted / considered

    @property
    def events_per_s(self) -> float | None:
        return None if self.elapsed_s <= 0 else self.records_read / self.elapsed_s

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id, "tenant_id": self.tenant_id, "input_ref": self.input_ref,
            "format": self.format, "records_read": self.records_read, "accepted": self.accepted,
            "published": self.published, "quarantined": self.quarantined,
            "duplicates": self.duplicates, "backpressure_waits": self.backpressure_waits,
            "quarantine_reasons": dict(self.quarantine_reasons), "success_rate": self.success_rate,
            "events_per_s": self.events_per_s, "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "elapsed_s": self.elapsed_s,
        }


class IngestPipeline:
    """Parse, normalize, validate and publish telemetry from registered sources.

    Parameters
    ----------
    bus: event bus to publish valid events to (topic ``topic``).
    validator: :class:`Validator` (or any callable with the same contract).
    sources: registered :class:`SourceConfig` objects (mapping by id or iterable).
    key_provider: per-tenant pseudonymization keys (default: ``TenantKeyProvider.from_env()``).
    pseudonymizers: explicit ``{tenant_id: Pseudonymizer}``; takes precedence over ``key_provider``.
    quarantine: where rejected records go (default: new in-memory store).
    max_publish_retries: drain-and-retry attempts on ``Backpressure`` before aborting.
    dedupe_window: number of recent ``(source, integrity hash)`` pairs remembered to
        drop exact re-deliveries of the same record (0 disables).
    """

    def __init__(self, bus: EventBus, validator: ValidatorLike | None, sources: Mapping[str, SourceConfig]
                 | Iterable[SourceConfig], *, key_provider: TenantKeyProvider | None = None,
                 pseudonymizers: Mapping[str, Pseudonymizer] | None = None,
                 quarantine: QuarantineStore | None = None, topic: str = OBSERVATIONS_TOPIC,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 max_publish_retries: int = 50, dedupe_window: int = 1_000_000):
        self.bus = bus
        self.validator: ValidatorLike = validator if validator is not None else Validator(clock=clock)
        if isinstance(sources, Mapping):
            self.sources: dict[str, SourceConfig] = dict(sources)
        else:
            self.sources = {s.source_id: s for s in sources}
        self._explicit = dict(pseudonymizers or {})
        self._key_provider = key_provider
        self.quarantine = quarantine if quarantine is not None else QuarantineStore()
        self.topic = topic
        self.clock = clock
        self.max_publish_retries = max_publish_retries
        self._dedupe_window = dedupe_window
        self._seen: OrderedDict[tuple[str, str], None] = OrderedDict()

    # ------------------------------------------------------------------ registry
    def register_source(self, source: SourceConfig) -> None:
        self.sources[source.source_id] = source

    def source(self, source_id: str) -> SourceConfig:
        try:
            return self.sources[source_id]
        except KeyError as exc:
            raise UnknownSourceError(f"source {source_id!r} is not registered (fail closed)") from exc

    def pseudonymizer_for(self, tenant_id: str) -> Pseudonymizer:
        p = self._explicit.get(tenant_id)
        if p is not None:
            return p
        if self._key_provider is None:
            self._key_provider = TenantKeyProvider.from_env()
        return self._key_provider.pseudonymizer(tenant_id)

    # ------------------------------------------------------------------ entry points
    def ingest_file(self, path: str | Path, source_id: str) -> IngestStats:
        """Ingest one collector file (``.gz`` supported) from a registered source."""
        src = self.source(source_id)
        p = Path(path)
        records = parsers.parse(src.parser_format, p)
        return self._run(records, src, input_ref=p.name)

    def ingest_text(self, data: str | bytes, source_id: str, name: str = "inline") -> IngestStats:
        """Ingest an in-memory payload (e.g. an API upload) from a registered source."""
        src = self.source(source_id)
        payload: Any = data.encode("utf-8") if isinstance(data, str) else data
        return self._run(parsers.parse(src.parser_format, payload), src, input_ref=name)

    def ingest_records(self, records: Iterable[dict[str, Any]], source_id: str,
                       name: str = "records") -> IngestStats:
        """Ingest already-parsed raw records (canonical keys, see ``parsers``)."""
        return self._run(iter(records), self.source(source_id), input_ref=name)

    def ingest_event(self, payload: bytes | str | dict[str, Any]) -> ObservationEvent | Quarantined:
        """Validate and publish one pre-normalized ``ObservationEvent`` payload.

        The event's ``source_id`` must be registered and match its tenant,
        authorization and kind (fail closed); pseudonymization must already have
        happened upstream (raw identifiers are rejected by the validator).
        """
        result = self.validator(payload)
        if isinstance(result, Quarantined):
            self.quarantine.put(result)
            return result
        src = self.sources.get(result.source_id)
        problem = None
        if src is None:
            problem = ("unknown_source", f"source {result.source_id!r} is not registered")
        elif (src.tenant_id != result.tenant_id or src.source_kind != result.source_kind
              or src.collection_authorization_id != result.collection_authorization_id):
            problem = ("source_mismatch", "tenant/kind/authorization do not match the registered source")
        if problem is not None:
            raw = payload.encode("utf-8") if isinstance(payload, str) else (
                payload if isinstance(payload, (bytes, bytearray)) else result.model_dump_json().encode())
            q = make_quarantined(bytes(raw), problem[0], detail=problem[1], tenant_id=result.tenant_id,
                                 source_id=result.source_id, now=self.clock())
            self.quarantine.put(q)
            return q
        self._publish(result, None)
        return result

    # ------------------------------------------------------------------ core loop
    def _run(self, records: Iterable[dict[str, Any]], src: SourceConfig, input_ref: str) -> IngestStats:
        stats = IngestStats(source_id=src.source_id, tenant_id=src.tenant_id, input_ref=input_ref,
                            format=src.parser_format, started_at=self.clock())
        reasons: Counter[str] = Counter()
        pseudo = self.pseudonymizer_for(src.tenant_id)
        t0 = time.perf_counter()
        try:
            for raw in records:
                stats.records_read += 1
                self._one(raw, src, pseudo, input_ref, stats, reasons)
        except parsers.ParseError as exc:
            # whole-input failure (e.g. missing header): quarantine a marker record
            q = make_quarantined(str(exc).encode("utf-8"), "unparseable_input", detail=str(exc),
                                 tenant_id=src.tenant_id, source_id=src.source_id, stage="parse",
                                 raw_artifact_ref=f"raw://{src.source_id}/{input_ref}",
                                 now=self.clock(), retention_days=src.retention_days)
            self.quarantine.put(q)
            stats.quarantined += 1
            reasons[q.reason] += 1
        finally:
            stats.quarantine_reasons = dict(reasons)
            stats.elapsed_s = time.perf_counter() - t0
            stats.finished_at = self.clock()
        log.info("ingested %s from %s: %d read, %d published, %d quarantined, %d duplicates",
                 input_ref, src.source_id, stats.records_read, stats.published, stats.quarantined,
                 stats.duplicates)
        return stats

    def _one(self, raw: dict[str, Any], src: SourceConfig, pseudo: Pseudonymizer, input_ref: str,
             stats: IngestStats, reasons: Counter[str]) -> None:
        line_no = raw.get("_line_no")
        ref = f"raw://{src.source_id}/{input_ref}#L{line_no}" if line_no is not None else \
            f"raw://{src.source_id}/{input_ref}"
        now = self.clock()
        try:
            event = normalize(raw, src, pseudo, now, raw_artifact_ref=ref)
        except NormalizationError as exc:
            self._quarantine_raw(raw, exc.code, exc.detail, src, ref, stats, reasons,
                                 stage="parse" if raw.get("_error") else "normalize")
            return
        result = self.validator(event)
        if isinstance(result, Quarantined):
            if result.raw_artifact_ref is None:
                result.raw_artifact_ref = ref
            result.line_no = line_no if isinstance(line_no, int) else None
            self.quarantine.put(result)
            stats.quarantined += 1
            reasons[result.reason] += 1
            return
        if self._is_duplicate(src.source_id, result.integrity_sha256):
            stats.duplicates += 1
            return
        stats.accepted += 1
        self._publish(result, stats)
        stats.published += 1

    def _quarantine_raw(self, raw: dict[str, Any], reason: str, detail: str, src: SourceConfig,
                        ref: str, stats: IngestStats, reasons: Counter[str], stage: str) -> None:
        original = raw.get("_raw")
        if not isinstance(original, (bytes, bytearray)):
            from aegis.contracts.canonical import canonical_bytes
            try:
                original = canonical_bytes({k: v for k, v in raw.items() if not k.startswith("_")})
            except Exception:
                original = repr(raw).encode("utf-8", "replace")
        q = make_quarantined(bytes(original), reason, detail=detail, tenant_id=src.tenant_id,
                             source_id=src.source_id, stage=stage,
                             line_no=raw.get("_line_no") if isinstance(raw.get("_line_no"), int) else None,
                             raw_artifact_ref=ref, now=self.clock(), retention_days=src.retention_days)
        self.quarantine.put(q)
        stats.quarantined += 1
        reasons[reason] += 1

    def _is_duplicate(self, source_id: str, digest: str) -> bool:
        if self._dedupe_window <= 0:
            return False
        key = (source_id, digest)
        if key in self._seen:
            self._seen.move_to_end(key)
            return True
        self._seen[key] = None
        if len(self._seen) > self._dedupe_window:
            self._seen.popitem(last=False)
        return False

    def _publish(self, event: ObservationEvent, stats: IngestStats | None) -> None:
        attempts = 0
        while True:
            try:
                self.bus.publish(self.topic, event)
                return
            except Backpressure as bp:
                attempts += 1
                if stats is not None:
                    stats.backpressure_waits += 1
                if attempts > self.max_publish_retries:
                    raise IngestBackpressureError(
                        f"bus saturated ({bp.reason}) after {self.max_publish_retries} retries",
                        stats or IngestStats(event.source_id, event.tenant_id, "event", "event")) from bp
                drained = self.bus.drain()
                if drained == 0:
                    time.sleep(min(bp.retry_after_s * attempts, 1.0))
