"""Strict ObservationEvent validation and quarantine.

``validate`` accepts an event as JSON bytes, a dict or an ``ObservationEvent``
and returns either a valid :class:`ObservationEvent` or a :class:`Quarantined`
record. Nothing is coerced: string numbers, naive datetimes, unknown fields and
unknown schema versions are rejected. Quarantined records keep the SHA-256 of the
original bytes and (up to ``max_raw_bytes``) the bytes themselves, so operators
can inspect and replay them under their retention policy.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import ObservationEvent, new_id
from aegis.ingest.normalize import canonical_ip
from aegis.ingest.pseudonym import is_pseudonym

UNKNOWN_TENANT = "_unknown"
MAX_RAW_BYTES = 65_536
_HEX = frozenset("0123456789abcdef")


class Quarantined(BaseModel):
    """A record that failed parsing, normalization or validation."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=new_id)   # quarantine record id (DocStore key)
    tenant_id: str
    source_id: str | None = None
    stage: str = "validate"                          # parse | normalize | validate
    reason: str                                      # stable reason code
    detail: str = ""
    raw_sha256: str                                  # sha256 of the full original bytes
    raw_size: int
    raw_b64: str                                     # original bytes (possibly truncated)
    raw_truncated: bool = False
    raw_artifact_ref: str | None = None
    line_no: int | None = None
    quarantined_at: datetime
    retention_until: datetime

    def raw_bytes(self) -> bytes:
        return base64.b64decode(self.raw_b64)


def make_quarantined(raw: bytes, reason: str, *, detail: str = "", tenant_id: str | None = None,
                     source_id: str | None = None, stage: str = "validate",
                     line_no: int | None = None, raw_artifact_ref: str | None = None,
                     now: datetime | None = None, retention_days: int = 30,
                     max_raw_bytes: int = MAX_RAW_BYTES) -> Quarantined:
    now = now or datetime.now(timezone.utc)
    kept = raw[:max_raw_bytes]
    return Quarantined(
        tenant_id=tenant_id or UNKNOWN_TENANT, source_id=source_id, stage=stage, reason=reason,
        detail=detail[:2000], raw_sha256=hashlib.sha256(raw).hexdigest(), raw_size=len(raw),
        raw_b64=base64.b64encode(kept).decode("ascii"), raw_truncated=len(kept) < len(raw),
        raw_artifact_ref=raw_artifact_ref, line_no=line_no, quarantined_at=now,
        retention_until=now + timedelta(days=retention_days),
    )


class QuarantineStore:
    """Tenant-scoped quarantine. In memory (bounded) and optionally persisted to a
    :class:`aegis.storage.db.DocStore`.

    The in-memory buffer keeps the most recent ``max_items`` records; per-tenant
    reason counters are never truncated so ingestion-success SLO accounting stays
    exact.
    """

    def __init__(self, docstore: Any | None = None, max_items: int = 100_000):
        self._docstore = docstore
        self._items: deque[Quarantined] = deque(maxlen=max_items)
        self._counts: dict[str, Counter[str]] = {}
        self._lock = threading.Lock()

    def put(self, q: Quarantined) -> Quarantined:
        with self._lock:
            self._items.append(q)
            self._counts.setdefault(q.tenant_id, Counter())[q.reason] += 1
        if self._docstore is not None:
            self._docstore.put(q)
        return q

    def list(self, tenant_id: str, limit: int = 1000) -> list[Quarantined]:
        if self._docstore is not None:
            return self._docstore.list(Quarantined, tenant_id, limit=limit)
        with self._lock:
            out = [q for q in reversed(self._items) if q.tenant_id == tenant_id]
        return out[:limit]

    def get(self, tenant_id: str, quarantine_id: str) -> Quarantined | None:
        if self._docstore is not None:
            return self._docstore.get(Quarantined, tenant_id, quarantine_id)
        with self._lock:
            for q in self._items:
                if q.event_id == quarantine_id and q.tenant_id == tenant_id:
                    return q
        return None

    def count(self, tenant_id: str) -> int:
        with self._lock:
            return sum(self._counts.get(tenant_id, Counter()).values())

    def reasons(self, tenant_id: str) -> dict[str, int]:
        with self._lock:
            return dict(self._counts.get(tenant_id, Counter()))


class Validator:
    """Strict semantic validator for ``ObservationEvent``.

    Parameters
    ----------
    expected_tenant:
        if set, events for any other tenant are quarantined (``tenant_mismatch``).
    allowed_authorizations:
        ``{tenant_id: {collection_authorization_id, ...}}``. When given, events whose
        authorization is not registered for their tenant are quarantined (fail closed).
    max_clock_skew_s:
        events observed further in the future than this (vs ``clock()``) are rejected.
    """

    def __init__(self, *, expected_tenant: str | None = None,
                 allowed_authorizations: Mapping[str, Iterable[str]] | None = None,
                 max_clock_skew_s: int = 300,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 retention_days: int = 30, max_raw_bytes: int = MAX_RAW_BYTES):
        self.expected_tenant = expected_tenant
        self.allowed_authorizations = (
            {t: frozenset(a) for t, a in allowed_authorizations.items()}
            if allowed_authorizations is not None else None)
        self.max_clock_skew = timedelta(seconds=max_clock_skew_s)
        self.clock = clock
        self.retention_days = retention_days
        self.max_raw_bytes = max_raw_bytes

    def __call__(self, raw: bytes | str | dict[str, Any] | ObservationEvent) -> ObservationEvent | Quarantined:
        return self.validate(raw)

    # ------------------------------------------------------------------ entry point
    def validate(self, raw: bytes | str | dict[str, Any] | ObservationEvent) -> ObservationEvent | Quarantined:
        if isinstance(raw, ObservationEvent):
            return self._semantic(raw, None)
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if isinstance(raw, (bytes, bytearray)):
            original = bytes(raw)
            try:
                obj = json.loads(original)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                return self._q(original, "invalid_json", str(exc))
            if not isinstance(obj, dict):
                return self._q(original, "not_object", "event must be a JSON object")
            json_text = original
        elif isinstance(raw, dict):
            obj = raw
            try:
                original = canonical_bytes(raw)
                json_text = json.dumps(raw, default=_json_default).encode("utf-8")
            except (TypeError, ValueError) as exc:
                fallback = repr(raw).encode("utf-8", "replace")
                return self._q(fallback, "not_serializable", str(exc), tenant=_tenant_of(raw))
        else:
            return self._q(repr(raw).encode("utf-8", "replace"), "unsupported_type", type(raw).__name__)

        tenant = _tenant_of(obj)
        try:
            ev = ObservationEvent.model_validate_json(json_text, strict=True)
        except ValidationError as exc:
            err = exc.errors()[0]
            loc = ".".join(str(p) for p in err.get("loc", ())) or "event"
            return self._q(original, f"schema:{loc}:{err.get('type', 'invalid')}",
                           f"{len(exc.errors())} error(s); first: {err.get('msg', '')}", tenant=tenant)
        return self._semantic(ev, original)

    # ------------------------------------------------------------------ checks
    def _semantic(self, ev: ObservationEvent, original: bytes | None) -> ObservationEvent | Quarantined:
        def q(reason: str, detail: str = "") -> Quarantined:
            # canonical bytes are only computed on the (rare) failure path
            return self._q(original if original is not None else canonical_bytes(ev), reason, detail, tenant=ev.tenant_id, source=ev.source_id,
                           ref=ev.raw_artifact_ref)

        for name in ("observed_at", "ingested_at", "retention_until"):
            dt = getattr(ev, name)
            if dt.tzinfo is None or dt.utcoffset() is None:
                return q("naive_datetime", f"{name} has no UTC offset")
        if self.expected_tenant is not None and ev.tenant_id != self.expected_tenant:
            return q("tenant_mismatch", f"event tenant {ev.tenant_id!r} != {self.expected_tenant!r}")
        if self.allowed_authorizations is not None:
            allowed = self.allowed_authorizations.get(ev.tenant_id, frozenset())
            if ev.collection_authorization_id not in allowed:
                return q("unauthorized_collection",
                         f"authorization {ev.collection_authorization_id!r} not registered for tenant")
        if not ev.collection_authorization_id.strip():
            return q("missing_authorization", "collection_authorization_id is empty")
        now = self.clock()
        if ev.observed_at > now + self.max_clock_skew:
            return q("future_timestamp", f"observed_at {ev.observed_at.isoformat()} ahead of clock")
        if ev.ingested_at + self.max_clock_skew < ev.observed_at:
            return q("ingested_before_observed", "ingested_at precedes observed_at")
        if ev.retention_until <= ev.observed_at:
            return q("bad_retention", "retention_until must be after observed_at")
        if len(ev.integrity_sha256) != 64 or not set(ev.integrity_sha256) <= _HEX:
            return q("bad_integrity_hash", "integrity_sha256 must be 64 lower-case hex chars")
        if ev.entity_pseudonym is None:
            return q("missing_entity", "entity_pseudonym is required")
        if not is_pseudonym(ev.entity_pseudonym):
            return q("raw_identifier", "entity_pseudonym is not a tenant pseudonym (p_<32 hex>)")
        if (ev.flow is None) == (ev.dns is None):
            return q("observation_shape", "exactly one of flow / dns must be present")
        if ev.flow is not None:
            f = ev.flow
            if f.src_ip is not None:
                return q("subscriber_ip_present", "src_ip must not be carried in events (pseudonyms only)")
            if not _valid_ip(f.dst_ip):
                return q("bad_dst_ip", f"{f.dst_ip!r} is not an IP address")
            if f.dst_port is not None and not 0 <= f.dst_port <= 65535:
                return q("bad_dst_port", f"{f.dst_port} out of range")
            for name in ("bytes_out", "bytes_in", "packets_out", "packets_in", "duration_ms"):
                v = getattr(f, name)
                if v is not None and v < 0:
                    return q("negative_counter", f"{name}={v}")
        if ev.dns is not None and not ev.dns.qname.strip():
            return q("missing_qname", "empty qname")
        return ev

    def _q(self, original: bytes, reason: str, detail: str = "", *, tenant: str | None = None,
           source: str | None = None, ref: str | None = None) -> Quarantined:
        return make_quarantined(original, reason, detail=detail, tenant_id=tenant, source_id=source,
                                stage="validate", raw_artifact_ref=ref, now=self.clock(),
                                retention_days=self.retention_days, max_raw_bytes=self.max_raw_bytes)


_default_validator = Validator()


def validate(raw: bytes | str | dict[str, Any] | ObservationEvent) -> ObservationEvent | Quarantined:
    """Validate with default settings (no tenant pinning, no authorization registry)."""
    return _default_validator.validate(raw)


def _tenant_of(obj: Mapping[str, Any]) -> str | None:
    t = obj.get("tenant_id")
    return t if isinstance(t, str) and t else None


def _valid_ip(s: str) -> bool:
    try:
        canonical_ip(s)
        return True
    except ValueError:
        return False


def _json_default(o: Any) -> Any:
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, BaseModel):
        return o.model_dump(mode="json")
    if hasattr(o, "value"):  # Enum
        return o.value
    raise TypeError(f"{type(o).__name__} is not JSON serializable")
