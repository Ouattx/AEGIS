"""Raw collector record -> canonical :class:`ObservationEvent`.

Normalization is strict. It never invents values: an absent optional field stays
``None``; an absent *required* field, a malformed value or an out-of-range value
raises :class:`NormalizationError` with a stable reason code, and the caller
quarantines the record with its original bytes.

Privacy: the identifying field (device id or subscriber source IP) is replaced by
a tenant-keyed pseudonym and the source IP is never copied into the event.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import (
    SCHEMA_VERSION,
    DnsObservation,
    FlowObservation,
    ObservationEvent,
    SourceKind,
    Vantage,
    new_id,
)
from aegis.ingest import parsers
from aegis.ingest.pseudonym import Pseudonymizer

# Largest integer RFC 8785 canonical JSON represents exactly (IEEE 754 double). Counters above
# it could not be hashed into the provenance ledger or re-validated, so they are rejected here.
_JSON_SAFE_INT_MAX = 2**53 - 1
_M = TypeVar("_M", bound=BaseModel)

DEFAULT_FORMATS: dict[SourceKind, str] = {
    SourceKind.NETFLOW: parsers.FORMAT_NETFLOW_CSV,
    SourceKind.DNS: parsers.FORMAT_DNS_JSONL,
    SourceKind.ZEEK_CONN: parsers.FORMAT_ZEEK_CONN,
    SourceKind.ZEEK_DNS: parsers.FORMAT_ZEEK_DNS,
    SourceKind.CPE: parsers.FORMAT_CPE_JSON,
}

_KIND_RECORD_TYPES: dict[SourceKind, frozenset[str]] = {
    SourceKind.NETFLOW: frozenset({"flow"}),
    SourceKind.ZEEK_CONN: frozenset({"flow"}),
    SourceKind.DNS: frozenset({"dns"}),
    SourceKind.ZEEK_DNS: frozenset({"dns"}),
    SourceKind.CPE: frozenset({"flow", "dns"}),
}

QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
               33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
               6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}
PROTOCOL_NUMBERS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}
#: rcode used when the collector logged a query without its response; explicit, never NOERROR
RCODE_UNKNOWN = "UNKNOWN"
#: qtype used when the collector did not log it; explicit, never defaulted to "A"
QTYPE_UNKNOWN = "UNKNOWN"

_EPOCH_RE = re.compile(r"^\d{1,13}(\.\d+)?$")
_INT_RE = re.compile(r"^\d+$")
_FLOAT_RE = re.compile(r"^\d+(\.\d+)?([eE][+-]?\d+)?$")
_DEVICE_CLASS_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_QNAME_RE = re.compile(r"^(?:[\x21-\x2d\x2f-\x7e]{1,63}\.)*[\x21-\x2d\x2f-\x7e]{1,63}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{1,16}$")


class RecordSkipped(Exception):
    """The record is valid but out of scope for this source (e.g. the return leg of a
    unidirectional flow): it is counted, not quarantined and not published."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class NormalizationError(ValueError):
    """Record cannot be normalized; ``code`` is a stable quarantine reason."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


class SourceConfig(BaseModel):
    """Configuration of one authorized telemetry source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=64)
    source_id: str = Field(min_length=1, max_length=128)
    source_kind: SourceKind
    vantage: Vantage
    collection_authorization_id: str = Field(min_length=1)
    retention_days: int = Field(default=30, ge=1, le=3650)
    #: parser format; defaults from ``source_kind``
    format: str | None = None
    #: which raw field identifies the entity; ``auto`` = device_id, else src_ip
    entity_field: Literal["auto", "device_id", "src_ip"] = "auto"
    #: accept timestamps without offset as UTC (off by default: ambiguous => quarantine)
    assume_utc_for_naive: bool = False
    #: records stamped further than this in the future are quarantined
    max_clock_skew_s: int = Field(default=300, ge=0)
    #: CIDRs of the subscriber (inside) address space. When set and the entity is the
    #: source IP, only flows *from* these prefixes are attributed: the return leg of a
    #: unidirectional flow (remote server -> subscriber) and transit flows are skipped,
    #: so a remote server never becomes a "device"
    subscriber_prefixes: tuple[str, ...] = ()
    #: reverse counters (bytes_in / packets_in): ``biflow`` keeps them as exported,
    #: ``uniflow`` treats them as missing, ``auto`` treats a 0 from a uniflow-style
    #: column (nfdump/nProbe ``obyt``/``opkt``) as missing (exporters write 0, not empty)
    flow_direction: Literal["auto", "biflow", "uniflow"] = "auto"

    @field_validator("subscriber_prefixes")
    @classmethod
    def _cidrs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        out = []
        for c in v:
            try:
                out.append(str(ipaddress.ip_network(str(c).strip(), strict=False)))
            except ValueError as exc:
                raise ValueError(f"invalid subscriber prefix {c!r}") from exc
        return tuple(out)

    @property
    def subscriber_networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return _networks(self.subscriber_prefixes)

    @field_validator("format")
    @classmethod
    def _known_format(cls, v: str | None) -> str | None:
        if v is not None and v not in parsers.PARSERS:
            raise ValueError(f"unknown format {v!r}")
        return v

    @property
    def parser_format(self) -> str:
        return self.format or DEFAULT_FORMATS[self.source_kind]


@lru_cache(maxsize=256)
def _networks(prefixes: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(p, strict=False) for p in prefixes)


def _inside(ip: str | None, nets: tuple[Any, ...]) -> bool:
    if ip is None:
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr.version == n.version and addr in n for n in nets)


# --------------------------------------------------------------------------- field parsers

def parse_timestamp(value: Any, assume_utc_for_naive: bool = False) -> datetime:
    """RFC 3339 / ISO 8601 string, or epoch seconds (ms if > 1e11), to aware UTC."""
    if value is None:
        raise NormalizationError("missing_timestamp", "observed_at is missing")
    if isinstance(value, bool):
        raise NormalizationError("bad_timestamp", "boolean is not a timestamp")
    if isinstance(value, (int, float)) or (isinstance(value, str) and _EPOCH_RE.match(value.strip())):
        try:
            secs = float(value)
        except (TypeError, ValueError) as exc:
            raise NormalizationError("bad_timestamp", str(exc)) from exc
        if secs > 1e11:
            secs /= 1000.0
        if not 946684800 <= secs < 32503680000:  # 2000-01-01 .. 3000-01-01
            raise NormalizationError("bad_timestamp", f"epoch out of range: {value!r}")
        return datetime.fromtimestamp(secs, tz=timezone.utc)
    if isinstance(value, str):
        return _parse_iso(value.strip(), assume_utc_for_naive)
    raise NormalizationError("bad_timestamp", f"unsupported timestamp type {type(value).__name__}")


def _parse_iso(text: str, assume_utc: bool) -> datetime:
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise NormalizationError("bad_timestamp", f"{text!r} is not RFC 3339") from exc
    if dt.tzinfo is None:
        if not assume_utc:
            raise NormalizationError("naive_timestamp", f"{text!r} has no UTC offset")
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _opt_int(rec: dict[str, Any], key: str, maximum: int = _JSON_SAFE_INT_MAX) -> int | None:
    v = rec.get(key)
    if v is None:
        return None
    t = type(v)
    if t is str:
        if not v.isdigit() or not v.isascii():
            v = v.strip()
            if not (v.isdigit() and v.isascii()):
                raise NormalizationError(f"bad_{key}", f"{v!r} is not a non-negative integer")
        n = int(v)
    elif t is int:
        n = v
    elif t is float:
        if not v.is_integer():
            raise NormalizationError(f"bad_{key}", f"{v!r} is not an integer")
        n = int(v)
    else:  # bool and anything else
        raise NormalizationError(f"bad_{key}", f"{v!r} is not a non-negative integer")
    if n < 0 or n > maximum:
        raise NormalizationError(f"bad_{key}", f"{n} out of range [0, {maximum}]")
    return n


def _duration_ms(rec: dict[str, Any]) -> int | None:
    if rec.get("duration_ms") is not None:
        return _opt_int(rec, "duration_ms")
    v = rec.get("duration_s")
    if v is None:
        return None
    if isinstance(v, bool):
        raise NormalizationError("bad_duration", "boolean is not a duration")
    if isinstance(v, (int, float)):
        secs = float(v)
    elif isinstance(v, str) and _FLOAT_RE.match(v.strip()):
        secs = float(v.strip())
    else:
        raise NormalizationError("bad_duration", f"{v!r} is not a duration in seconds")
    if secs < 0 or secs > 1e9:
        raise NormalizationError("bad_duration", f"{secs} out of range")
    return int(round(secs * 1000))


@lru_cache(maxsize=65536)
def canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _ip(v: Any, key: str) -> str:
    if not isinstance(v, str):
        raise NormalizationError(f"bad_{key}", f"{v!r} is not an IP address")
    try:
        return canonical_ip(v.strip())
    except ValueError as exc:
        raise NormalizationError(f"bad_{key}", f"{v!r} is not an IP address") from exc


def _protocol(v: Any) -> Literal["tcp", "udp", "icmp", "other"]:
    if v is None:
        return "other"
    if isinstance(v, bool):
        raise NormalizationError("bad_protocol", "boolean is not a protocol")
    if isinstance(v, int) or (isinstance(v, str) and _INT_RE.match(v.strip())):
        n = int(v)
        if n > 255:
            raise NormalizationError("bad_protocol", f"protocol number {n} > 255")
        return PROTOCOL_NUMBERS.get(n, "other")  # type: ignore[return-value]
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("tcp", "udp", "icmp"):
            return s  # type: ignore[return-value]
        if s in ("icmp6", "ipv6-icmp", "icmpv6"):
            return "icmp"
        if _TOKEN_RE.match(s):
            return "other"
    raise NormalizationError("bad_protocol", f"{v!r} is not a protocol")


def _qname(v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        raise NormalizationError("missing_qname", "DNS query name is missing")
    q = v.strip().rstrip(".").lower()
    if not q:
        return "."
    if not q.isascii():
        try:
            q = q.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise NormalizationError("bad_qname", f"{v!r} is not a valid domain name") from exc
    if len(q) > 253 or not _QNAME_RE.match(q):
        raise NormalizationError("bad_qname", f"{v!r} is not a valid domain name")
    return q


def _code(v: Any, names: dict[int, str], key: str, missing: str | None) -> str:
    if v is None:
        if missing is None:
            raise NormalizationError(f"missing_{key}", f"{key} is missing")
        return missing
    if isinstance(v, bool):
        raise NormalizationError(f"bad_{key}", "boolean is not a DNS code")
    if isinstance(v, int) or (isinstance(v, str) and _INT_RE.match(v.strip())):
        n = int(v)
        return names.get(n, f"{'TYPE' if key == 'qtype' else 'RCODE'}{n}")
    if isinstance(v, str) and _TOKEN_RE.match(v.strip()):
        return v.strip().upper()
    raise NormalizationError(f"bad_{key}", f"{v!r} is not a DNS {key}")


def _answers(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        items = [a for a in (x.strip() for x in v.split(",")) if a]
    elif isinstance(v, list):
        items = []
        for a in v:
            if isinstance(a, dict):  # {"data": "..."} / {"rdata": "..."} styles
                a = a.get("data", a.get("rdata"))
            if not isinstance(a, str):
                raise NormalizationError("bad_answers", f"answer {a!r} is not a string")
            if a.strip():
                items.append(a.strip())
    else:
        raise NormalizationError("bad_answers", "answers must be a list or comma-separated string")
    if len(items) > 256:
        raise NormalizationError("bad_answers", "more than 256 answers")
    return items


def _device_class(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str):
        raise NormalizationError("bad_device_class", f"{v!r} is not a string")
    return _device_class_str(v)


@lru_cache(maxsize=1024)
def _device_class_str(v: str) -> str:
    s = v.strip().lower().replace("-", "_").replace(" ", "_")
    if not _DEVICE_CLASS_RE.match(s):
        raise NormalizationError("bad_device_class", f"{v!r} is not a valid device class")
    return s


_FIELDS_SETS: dict[type, set[str]] = {}


def _construct(cls: type[_M], values: dict[str, Any]) -> _M:
    """Build an already-validated model without re-validation.

    Equivalent to ``cls.model_construct(**values)`` when ``values`` holds every
    field, at a fraction of the cost (ingest normalizes millions of records).
    All values here come from the strict field parsers above.
    """
    obj = object.__new__(cls)
    object.__setattr__(obj, "__dict__", values)
    # Every field is set, so one shared fields-set per class is exact: pydantic only
    # ever ``add``s an existing field name to it (a no-op). Saves ~1 KB per event.
    fields_set = _FIELDS_SETS.get(cls)
    if fields_set is None or len(fields_set) != len(values):
        fields_set = _FIELDS_SETS[cls] = set(values)
    object.__setattr__(obj, "__pydantic_fields_set__", fields_set)
    object.__setattr__(obj, "__pydantic_extra__", None)
    object.__setattr__(obj, "__pydantic_private__", None)
    return obj


_META_KEYS = ("_raw", "_line_no", "_format", "_error", "_error_detail", "_uniflow_reverse")


def _reverse(raw: dict[str, Any], key: str, source: SourceConfig) -> int | None:
    """A reverse-direction counter, or None when the exporter does not really provide it."""
    value = _opt_int(raw, key)
    if source.flow_direction == "uniflow":
        return None
    if source.flow_direction == "auto" and value == 0 and raw.get("_uniflow_reverse") is True:
        return None
    return value


def record_integrity_sha256(raw: dict[str, Any]) -> str:
    """SHA-256 of the record's original bytes (or of its canonical JSON if none)."""
    original = raw.get("_raw")
    if isinstance(original, (bytes, bytearray)):
        return sha256_hex(bytes(original))
    return sha256_hex({k: v for k, v in raw.items() if k not in _META_KEYS})


# --------------------------------------------------------------------------- normalize

def normalize(raw: dict[str, Any], source: SourceConfig, pseudonymizer: Pseudonymizer,
              now: datetime, *, event_id: str | None = None,
              raw_artifact_ref: str | None = None) -> ObservationEvent:
    """Convert one raw record into an :class:`ObservationEvent` or raise
    :class:`NormalizationError`."""
    if raw.get("_error"):
        raise NormalizationError(str(raw["_error"]), str(raw.get("_error_detail", "")))
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    rtype = raw.get("record_type")
    if rtype not in ("flow", "dns"):
        raise NormalizationError("unknown_record_type", f"record_type={rtype!r}")
    if rtype not in _KIND_RECORD_TYPES[source.source_kind]:
        raise NormalizationError("record_type_mismatch",
                                 f"{rtype} record from {source.source_kind.value} source")

    observed_at = parse_timestamp(raw.get("observed_at"), source.assume_utc_for_naive)
    if observed_at > now + timedelta(seconds=source.max_clock_skew_s):
        raise NormalizationError("future_timestamp",
                                 f"observed_at {observed_at.isoformat()} is ahead of ingest clock")

    src_ip = raw.get("src_ip")
    if src_ip is not None:
        src_ip = _ip(src_ip, "src_ip")  # validated, then dropped (subscriber identity)
    device_id = raw.get("device_id")
    if device_id is not None and (not isinstance(device_id, str) or not device_id.strip()):
        raise NormalizationError("bad_device_id", f"{device_id!r} is not a device identifier")

    if source.entity_field == "device_id":
        ident = device_id
    elif source.entity_field == "src_ip":
        ident = src_ip
    else:
        ident = device_id if device_id is not None else src_ip
    if (rtype == "flow" and source.subscriber_prefixes and ident is not None and ident == src_ip
            and not _inside(src_ip, source.subscriber_networks)):
        # return leg (remote -> subscriber) or transit: never attribute it to the remote address
        dst_raw = raw.get("dst_ip")
        try:
            dst_inside = _inside(_ip(dst_raw, "dst_ip"), source.subscriber_networks) if dst_raw else False
        except NormalizationError:
            dst_inside = False
        raise RecordSkipped("return_flow" if dst_inside else "outside_subscriber_prefixes")
    if ident is None:
        raise NormalizationError("missing_entity",
                                 f"no {source.entity_field if source.entity_field != 'auto' else 'device_id/src_ip'}"
                                 " to attribute the record to")
    entity = pseudonymizer.pseudonym(ident)

    flow = dns = None
    if rtype == "flow":
        dst = raw.get("dst_ip")
        if dst is None:
            raise NormalizationError("missing_dst_ip", "flow record has no destination IP")
        flow = _construct(FlowObservation, {
            "src_ip": None,
            "dst_ip": _ip(dst, "dst_ip"),
            "dst_port": _opt_int(raw, "dst_port", 65535),
            "protocol": _protocol(raw.get("protocol")),
            "bytes_out": _opt_int(raw, "bytes_out"),
            "bytes_in": _reverse(raw, "bytes_in", source),
            "packets_out": _opt_int(raw, "packets_out"),
            "packets_in": _reverse(raw, "packets_in", source),
            "duration_ms": _duration_ms(raw),
        })
        _opt_int(raw, "src_port", 65535)  # validated even though not retained
    else:
        dns = _construct(DnsObservation, {
            "qname": _qname(raw.get("qname")),
            "qtype": _code(raw.get("qtype"), QTYPE_NAMES, "qtype", QTYPE_UNKNOWN),
            "rcode": _code(raw.get("rcode"), RCODE_NAMES, "rcode", RCODE_UNKNOWN),
            "answers": _answers(raw.get("answers")),
        })

    return _construct(ObservationEvent, {
        "event_id": event_id or new_id(),
        "schema_version": SCHEMA_VERSION,
        "tenant_id": source.tenant_id,
        "observed_at": observed_at,
        "ingested_at": now.astimezone(timezone.utc),
        "source_id": source.source_id,
        "source_kind": source.source_kind,
        "vantage": source.vantage,
        "collection_authorization_id": source.collection_authorization_id,
        "entity_pseudonym": entity,
        "device_class": _device_class(raw.get("device_class")),
        "flow": flow,
        "dns": dns,
        "raw_artifact_ref": raw_artifact_ref,
        "data_class": "security_metadata",
        "retention_until": observed_at + timedelta(days=source.retention_days),
        "integrity_sha256": record_integrity_sha256(raw),
    })
