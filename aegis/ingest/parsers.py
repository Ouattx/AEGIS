"""Streaming parsers for collector formats.

Every parser yields *raw records*: plain dicts using the canonical field names
below, values exactly as found in the source (strings for text formats, JSON
types for JSON formats), ``None`` for tokens that mean "missing" (``""``, ``-``,
``null``, ``N/A``...). Parsers never coerce, default or drop data: a line that
cannot be parsed is still yielded, with ``_error`` set, so the pipeline can
quarantine it together with its original bytes.

Canonical raw-record keys
    record_type   "flow" | "dns"
    observed_at   timestamp (RFC 3339 string or epoch seconds)
    device_id     per-device identifier (MAC, CPE device id) when the vantage has one
    device_class  collector-provided device class hint
    src_ip, src_port, dst_ip, dst_port, protocol
    bytes_out, bytes_in, packets_out, packets_in   (out = from the observed entity)
    duration_ms | duration_s
    qname, qtype, rcode, answers
Meta keys
    _raw (bytes, original record bytes), _line_no (int, 1-based), _format (str),
    _error / _error_detail (only on unparseable records)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import os
from pathlib import Path
from typing import IO, Any, Callable, Iterable, Iterator, Union

import rfc8785

Source = Union[str, bytes, os.PathLike, IO[str], IO[bytes]]
RawRecord = dict[str, Any]

MISSING_TOKENS = frozenset({"", "-", "null", "NULL", "None", "none", "N/A", "n/a", "NA", "nan", "NaN"})

FORMAT_NETFLOW_CSV = "netflow_csv"
FORMAT_DNS_JSONL = "dns_jsonl"
FORMAT_ZEEK_CONN = "zeek_conn"
FORMAT_ZEEK_DNS = "zeek_dns"
FORMAT_CPE_JSON = "cpe_json"


class ParseError(ValueError):
    """The whole input is unusable (e.g. CSV without the required header)."""


# --------------------------------------------------------------------------- input helpers

def _looks_like_path(s: str) -> bool:
    return "\n" not in s and len(s) < 4096 and os.path.exists(s)


def iter_lines(src: Source) -> Iterator[tuple[int, bytes]]:
    """Yield ``(line_no, line_bytes)`` without trailing CR/LF; blank lines skipped.

    ``src`` may be a path (``Path`` or existing-path ``str``; ``.gz`` is
    decompressed), literal text (``str`` containing data), ``bytes``, or an open
    text/binary file object.
    """
    if isinstance(src, os.PathLike) or (isinstance(src, str) and _looks_like_path(src)):
        path = Path(src)
        opener: Callable[..., IO[bytes]] = gzip.open if path.suffix == ".gz" else open  # type: ignore[assignment]
        with opener(path, "rb") as fh:
            yield from _iter_binary(fh)
        return
    if isinstance(src, str):
        yield from _iter_binary(io.BytesIO(src.encode("utf-8")))
        return
    if isinstance(src, (bytes, bytearray)):
        yield from _iter_binary(io.BytesIO(bytes(src)))
        return
    if hasattr(src, "read"):
        if isinstance(src, io.TextIOBase):
            for n, line in enumerate(src, start=1):  # type: ignore[arg-type]
                b = line.rstrip("\r\n").encode("utf-8")
                if b.strip():
                    yield n, b
            return
        yield from _iter_binary(src)  # type: ignore[arg-type]
        return
    raise TypeError(f"unsupported source type: {type(src).__name__}")


def _iter_binary(fh: IO[bytes]) -> Iterator[tuple[int, bytes]]:
    for n, line in enumerate(fh, start=1):
        b = line.rstrip(b"\r\n")
        if b.strip():
            yield n, b


def _missing(v: Any) -> Any:
    if isinstance(v, str) and v.strip() in MISSING_TOKENS:
        return None
    return v


def _error_record(fmt: str, line_no: int, raw: bytes, code: str, detail: str = "") -> RawRecord:
    return {"_format": fmt, "_line_no": line_no, "_raw": raw, "_error": code, "_error_detail": detail}


def _decode(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


# --------------------------------------------------------------------------- NetFlow / IPFIX CSV

NETFLOW_ALIASES: dict[str, str] = {}
for _canon, _names in {
    "observed_at": ["ts", "timestamp", "time", "start", "start_time", "flow_start", "first_seen",
                    "flowstartmilliseconds", "observed_at"],
    "device_id": ["device_id", "device", "mac", "device_mac", "src_mac", "cpe_device_id"],
    "device_class": ["device_class", "class", "device_type"],
    "src_ip": ["src_ip", "sa", "srcaddr", "src_addr", "source_ip", "sourceipv4address",
               "sourceipv6address", "ipv4_src_addr"],
    "src_port": ["src_port", "sp", "srcport", "sourcetransportport", "l4_src_port"],
    "dst_ip": ["dst_ip", "da", "dstaddr", "dst_addr", "destination_ip", "destinationipv4address",
               "destinationipv6address", "ipv4_dst_addr"],
    "dst_port": ["dst_port", "dp", "dstport", "destinationtransportport", "l4_dst_port"],
    "protocol": ["protocol", "proto", "pr", "protocolidentifier"],
    "bytes_out": ["bytes_out", "ibyt", "in_bytes", "octetdeltacount", "orig_bytes", "bytes"],
    "bytes_in": ["bytes_in", "obyt", "out_bytes", "reverseoctetdeltacount", "resp_bytes"],
    "packets_out": ["packets_out", "ipkt", "in_pkts", "packetdeltacount", "orig_pkts", "packets"],
    "packets_in": ["packets_in", "opkt", "out_pkts", "reversepacketdeltacount", "resp_pkts"],
    "duration_ms": ["duration_ms"],
    "duration_s": ["duration_s", "duration", "td", "dur"],
}.items():
    for _n in _names:
        NETFLOW_ALIASES[_n] = _canon

NETFLOW_REQUIRED = ("observed_at", "dst_ip")

#: header names whose reverse-direction counters are written as ``0`` (not empty) by
#: unidirectional exporters (nfdump / nProbe on NetFlow v5/v9 without bi-flow):
#: their zeros mean "not exported", see ``SourceConfig.flow_direction``
UNIFLOW_REVERSE_COLUMNS = frozenset({"obyt", "opkt", "out_bytes", "out_pkts"})


class NetflowCsvParser:
    """Line-level NetFlow/IPFIX CSV parser bound to one header row.

    Accepts native AEGIS headers, nfdump ``-o csv`` short names (ts, sa, da, sp,
    dp, pr, ibyt, obyt, ipkt, opkt, td) and common IPFIX/nProbe element names.
    Bytes/packets "in" columns of nfdump/nProbe are *in the flow direction*, i.e.
    from the source (observed entity) and therefore map to ``bytes_out``.
    """

    def __init__(self, header: list[str]):
        self.columns: list[str | None] = []
        seen: set[str] = set()
        #: True when bytes_in / packets_in come from a uniflow-style "out" column
        self.zero_means_missing_reverse = False
        for h in header:
            name = h.strip().lower()
            canon = NETFLOW_ALIASES.get(name)
            if canon in seen:
                canon = None  # first matching column wins
            if canon:
                seen.add(canon)
                if canon in ("bytes_in", "packets_in") and name in UNIFLOW_REVERSE_COLUMNS:
                    self.zero_means_missing_reverse = True
            self.columns.append(canon)
        missing = [c for c in NETFLOW_REQUIRED if c not in seen]
        if missing:
            raise ParseError(f"netflow CSV header lacks required column(s): {', '.join(missing)}")
        self.width = len(header)

    def parse_line(self, raw: bytes, line_no: int) -> RawRecord:
        text = _decode(raw)
        if text is None:
            return _error_record(FORMAT_NETFLOW_CSV, line_no, raw, "encoding", "not valid UTF-8")
        if '"' in text:
            try:
                values = next(csv.reader([text]))
            except (csv.Error, StopIteration) as exc:
                return _error_record(FORMAT_NETFLOW_CSV, line_no, raw, "csv_syntax", str(exc))
        else:
            values = text.split(",")
        if len(values) != self.width:
            return _error_record(FORMAT_NETFLOW_CSV, line_no, raw, "column_count",
                                 f"expected {self.width} columns, got {len(values)}")
        rec: RawRecord = {"record_type": "flow", "_format": FORMAT_NETFLOW_CSV,
                          "_line_no": line_no, "_raw": raw}
        if self.zero_means_missing_reverse:
            rec["_uniflow_reverse"] = True
        for col, v in zip(self.columns, values):
            if col is not None:
                v = v.strip()
                rec[col] = None if v in MISSING_TOKENS else v
        return rec


def parse_netflow_csv(src: Source) -> Iterator[RawRecord]:
    parser: NetflowCsvParser | None = None
    for line_no, raw in iter_lines(src):
        if raw.startswith(b"#"):
            continue
        if parser is None:
            text = _decode(raw)
            if text is None:
                raise ParseError("netflow CSV header is not valid UTF-8")
            try:
                header = next(csv.reader([text]))
            except (csv.Error, StopIteration) as exc:
                raise ParseError(f"netflow CSV header is not valid CSV: {exc}") from exc
            parser = NetflowCsvParser(header)
            continue
        if raw.strip() == b"Summary":  # nfdump appends a summary block after the records
            return
        yield parser.parse_line(raw, line_no)
    if parser is None:
        raise ParseError("netflow CSV input is empty (no header row)")


# --------------------------------------------------------------------------- DNS JSONL

DNS_ALIASES: dict[str, str] = {}
for _canon, _names in {
    "observed_at": ["ts", "timestamp", "time", "query_time", "observed_at", "@timestamp"],
    "device_id": ["device_id", "device", "mac", "device_mac", "cpe_device_id"],
    "device_class": ["device_class", "class", "device_type"],
    "src_ip": ["client_ip", "client", "src_ip", "source_ip", "query_address"],
    "src_port": ["client_port", "src_port"],
    "dst_ip": ["resolver_ip", "server_ip", "dst_ip", "response_address"],
    "qname": ["qname", "query", "question", "name", "query_name"],
    "qtype": ["qtype", "type", "query_type", "qtype_name"],
    "rcode": ["rcode", "response_code", "rcode_name", "status"],
    "answers": ["answers", "answer", "response", "rdata"],
}.items():
    for _n in _names:
        DNS_ALIASES[_n] = _canon


def _map_json_record(obj: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in obj.items():
        canon = aliases.get(str(k).lower())
        if canon and canon not in out:
            out[canon] = _missing(v)
    return out


def parse_dns_line(raw: bytes, line_no: int, fmt: str = FORMAT_DNS_JSONL) -> RawRecord:
    text = _decode(raw)
    if text is None:
        return _error_record(fmt, line_no, raw, "encoding", "not valid UTF-8")
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return _error_record(fmt, line_no, raw, "invalid_json", str(exc))
    if not isinstance(obj, dict):
        return _error_record(fmt, line_no, raw, "not_object", "JSON line is not an object")
    rec: RawRecord = _map_json_record(obj, DNS_ALIASES)
    rec.update({"record_type": "dns", "_format": fmt, "_line_no": line_no, "_raw": raw})
    return rec


def parse_dns_jsonl(src: Source) -> Iterator[RawRecord]:
    for line_no, raw in iter_lines(src):
        yield parse_dns_line(raw, line_no)


# --------------------------------------------------------------------------- Zeek TSV / JSON

ZEEK_CONN_MAP = {
    "ts": "observed_at", "uid": "zeek_uid", "id.orig_h": "src_ip", "id.orig_p": "src_port",
    "id.resp_h": "dst_ip", "id.resp_p": "dst_port", "proto": "protocol", "duration": "duration_s",
    "orig_bytes": "bytes_out", "resp_bytes": "bytes_in", "orig_pkts": "packets_out",
    "resp_pkts": "packets_in",
}
ZEEK_DNS_MAP = {
    "ts": "observed_at", "uid": "zeek_uid", "id.orig_h": "src_ip", "id.orig_p": "src_port",
    "id.resp_h": "dst_ip", "query": "qname", "qtype_name": "qtype", "rcode_name": "rcode",
    "answers": "answers",
}
_ZEEK_DNS_FALLBACK = {"qtype": "qtype", "rcode": "rcode"}  # numeric columns if *_name absent


def _unescape_zeek(sep: str) -> str:
    return sep.encode("utf-8").decode("unicode_escape")


class _ZeekState:
    def __init__(self) -> None:
        self.sep = "\t"
        self.set_sep = ","
        self.empty = "(empty)"
        self.unset = "-"
        self.fields: list[str] | None = None


def _parse_zeek(src: Source, fmt: str, field_map: dict[str, str], record_type: str,
                set_fields: frozenset[str]) -> Iterator[RawRecord]:
    st = _ZeekState()
    for line_no, raw in iter_lines(src):
        text = _decode(raw)
        if text is None:
            yield _error_record(fmt, line_no, raw, "encoding", "not valid UTF-8")
            continue
        if text.startswith("#"):
            _zeek_directive(st, text)
            continue
        if text.lstrip().startswith("{"):
            yield _zeek_json_line(raw, text, line_no, fmt, field_map, record_type)
            continue
        if st.fields is None:
            yield _error_record(fmt, line_no, raw, "zeek_no_fields", "data line before #fields header")
            continue
        values = text.split(st.sep)
        if len(values) != len(st.fields):
            yield _error_record(fmt, line_no, raw, "column_count",
                                f"expected {len(st.fields)} columns, got {len(values)}")
            continue
        rec: RawRecord = {"record_type": record_type, "_format": fmt, "_line_no": line_no, "_raw": raw}
        extra: dict[str, Any] = {}
        for name, v in zip(st.fields, values):
            if v == st.unset:
                val: Any = None
            elif name in set_fields:
                val = [] if v == st.empty else v.split(st.set_sep)
            else:
                val = v
            canon = field_map.get(name)
            if canon:
                rec[canon] = val
            else:
                extra[name] = val
        if record_type == "dns":
            for col, canon in _ZEEK_DNS_FALLBACK.items():
                if rec.get(canon) is None and extra.get(col) is not None:
                    rec[canon] = extra[col]
        yield rec


def _zeek_directive(st: _ZeekState, text: str) -> None:
    if text.startswith("#separator"):
        parts = text.split(" ", 1)
        if len(parts) == 2:
            st.sep = _unescape_zeek(parts[1].strip())
        return
    parts = text.split(st.sep)
    key = parts[0]
    if key == "#set_separator" and len(parts) > 1:
        st.set_sep = parts[1]
    elif key == "#empty_field" and len(parts) > 1:
        st.empty = parts[1]
    elif key == "#unset_field" and len(parts) > 1:
        st.unset = parts[1]
    elif key == "#fields":
        st.fields = parts[1:]


def _zeek_json_line(raw: bytes, text: str, line_no: int, fmt: str, field_map: dict[str, str],
                    record_type: str) -> RawRecord:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        return _error_record(fmt, line_no, raw, "invalid_json", str(exc))
    if not isinstance(obj, dict):
        return _error_record(fmt, line_no, raw, "not_object", "JSON line is not an object")
    rec: RawRecord = {"record_type": record_type, "_format": fmt, "_line_no": line_no, "_raw": raw}
    for k, v in obj.items():
        canon = field_map.get(k)
        if canon:
            rec[canon] = _missing(v) if not isinstance(v, list) else v
    if record_type == "dns":
        for col, canon in _ZEEK_DNS_FALLBACK.items():
            if rec.get(canon) is None and obj.get(col) is not None:
                rec[canon] = obj[col]
    return rec


def parse_zeek_conn(src: Source) -> Iterator[RawRecord]:
    yield from _parse_zeek(src, FORMAT_ZEEK_CONN, ZEEK_CONN_MAP, "flow", frozenset({"tunnel_parents"}))


def parse_zeek_dns(src: Source) -> Iterator[RawRecord]:
    yield from _parse_zeek(src, FORMAT_ZEEK_DNS, ZEEK_DNS_MAP, "dns", frozenset({"answers", "TTLs"}))


# --------------------------------------------------------------------------- CPE / gateway JSON

CPE_ALIASES = dict(NETFLOW_ALIASES)
CPE_ALIASES.update(DNS_ALIASES)
CPE_ALIASES.update({"type": "record_type", "record_type": "record_type", "kind": "record_type"})


def _cpe_record(obj: Any, raw: bytes, line_no: int, inherited: dict[str, Any] | None = None) -> RawRecord:
    if not isinstance(obj, dict):
        return _error_record(FORMAT_CPE_JSON, line_no, raw, "not_object", "CPE record is not an object")
    rec: RawRecord = dict(inherited or {})
    rec.update(_map_json_record(obj, CPE_ALIASES))
    rt = rec.get("record_type")
    if isinstance(rt, str):
        rt = rt.strip().lower()
    if rt not in ("flow", "dns"):
        if rt is None:
            rt = "dns" if rec.get("qname") is not None else ("flow" if rec.get("dst_ip") is not None else None)
        else:
            rt = None
    if rt is None:
        return _error_record(FORMAT_CPE_JSON, line_no, raw, "unknown_record_type",
                             "record is neither a flow nor a DNS record")
    rec.update({"record_type": rt, "_format": FORMAT_CPE_JSON, "_line_no": line_no, "_raw": raw})
    return rec


def _expand_cpe_document(doc: Any) -> Iterator[tuple[Any, dict[str, Any] | None]]:
    if isinstance(doc, list):
        for item in doc:
            yield from _expand_cpe_document(item)
        return
    if isinstance(doc, dict) and isinstance(doc.get("records"), list):
        for item in doc["records"]:
            yield item, None
        return
    if isinstance(doc, dict) and isinstance(doc.get("devices"), list):
        for dev in doc["devices"]:
            if not isinstance(dev, dict):
                yield dev, None
                continue
            inherited = {k: v for k, v in _map_json_record(dev, CPE_ALIASES).items()
                         if k in ("device_id", "device_class", "src_ip")}
            for key, rt in (("flows", "flow"), ("dns", "dns")):
                for item in dev.get(key, []) or []:
                    if isinstance(item, dict):
                        item = {"type": rt, **item}
                    yield item, inherited
        return
    yield doc, None


def parse_cpe_json(src: Source) -> Iterator[RawRecord]:
    """CPE/gateway agent telemetry: JSON Lines, a JSON array, ``{"records": [...]}``
    or ``{"devices": [{"device_id", "device_class", "flows": [...], "dns": [...]}]}``.

    JSON Lines inputs are streamed and each record keeps its original line bytes.
    For whole-document inputs each record's original bytes are its RFC 8785
    canonical JSON encoding (there is no per-record line to preserve).
    """
    lines = iter_lines(src)
    first = next(lines, None)
    if first is None:
        return
    first_no, first_raw = first
    if not _is_json_line(first_raw):
        # a JSON array or a pretty-printed document: parse as one document
        rest = [(first_no, first_raw)] + list(lines)
        whole = b"\n".join(raw for _, raw in rest)
        text = _decode(whole)
        doc: Any = None
        parsed = False
        if text is not None:
            try:
                doc = json.loads(text)
                parsed = True
            except json.JSONDecodeError:
                parsed = False
        if parsed:
            yield from _cpe_document_records(doc)
        else:
            # not one document: treat as JSON Lines with damaged lines quarantined individually
            for line_no, raw in rest:
                yield from _parse_cpe_line(raw, line_no)
        return
    yield from _parse_cpe_line(first_raw, first_no)
    for line_no, raw in lines:
        yield from _parse_cpe_line(raw, line_no)


def _is_json_line(raw: bytes) -> bool:
    stripped = raw.strip()
    if stripped[:1] != b"{":
        return False
    try:
        json.loads(stripped)
        return True
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False


def _cpe_document_records(doc: Any) -> Iterator[RawRecord]:
    for idx, (item, inherited) in enumerate(_expand_cpe_document(doc), start=1):
        yield _cpe_record(item, _canonical_or_sorted(item), idx, inherited)


def _canonical_or_sorted(item: Any) -> bytes:
    try:
        return rfc8785.dumps(item)
    except Exception:  # values RFC 8785 cannot encode (e.g. out-of-range integers)
        return json.dumps(item, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _parse_cpe_line(raw: bytes, line_no: int) -> Iterator[RawRecord]:
    text = _decode(raw)
    if text is None:
        yield _error_record(FORMAT_CPE_JSON, line_no, raw, "encoding", "not valid UTF-8")
        return
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        yield _error_record(FORMAT_CPE_JSON, line_no, raw, "invalid_json", str(exc))
        return
    if isinstance(obj, dict) and ("devices" in obj or "records" in obj):
        for item, inherited in _expand_cpe_document(obj):
            yield _cpe_record(item, _canonical_or_sorted(item), line_no, inherited)
        return
    yield _cpe_record(obj, raw, line_no)


# --------------------------------------------------------------------------- registry

PARSERS: dict[str, Callable[[Source], Iterator[RawRecord]]] = {
    FORMAT_NETFLOW_CSV: parse_netflow_csv,
    FORMAT_DNS_JSONL: parse_dns_jsonl,
    FORMAT_ZEEK_CONN: parse_zeek_conn,
    FORMAT_ZEEK_DNS: parse_zeek_dns,
    FORMAT_CPE_JSON: parse_cpe_json,
}


def parse(fmt: str, src: Source) -> Iterable[RawRecord]:
    try:
        fn = PARSERS[fmt]
    except KeyError as exc:
        raise ParseError(f"unknown format {fmt!r}; known: {sorted(PARSERS)}") from exc
    return fn(src)
