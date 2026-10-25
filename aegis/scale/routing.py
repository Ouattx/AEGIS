"""Routing of collector records to line shards.

The coordinator must find each record's line identity without paying for a full parse
(the shards re-parse anyway). For the two high-volume line formats, NetFlow CSV and
resolver DNS JSONL, :class:`RecordRouter` extracts only the identifier and ships the
*original line bytes*; the shard parses them with the same public parser functions
(``NetflowCsvParser.parse_line`` / ``parse_dns_line``). For every other format (Zeek,
CPE documents) the coordinator runs the full parser and ships raw records.

Exactness: the shard chosen for a line equals ``route_raw(<parsed record>)`` in every case,
including malformed lines (routed by content). ``tests/fuzz/test_fuzz_scale_routing.py``
checks this property on arbitrary byte strings.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Union

from aegis.ingest import parsers
from aegis.ingest.normalize import SourceConfig
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.scale.partition import Partitioner

#: an item shipped to a shard: a parsed raw record, or ``(line_no, original line bytes)``
Item = Union[dict[str, Any], tuple[int, bytes]]

_DNS_IDENT_KEYS = {k: v for k, v in parsers.DNS_ALIASES.items() if v in ("device_id", "src_ip")}


def routing_identifier(raw: Mapping[str, Any], source: SourceConfig) -> str | None:
    """The raw identifier ``normalize`` will pseudonymize for this record (None if absent)."""
    return _pick(raw.get("device_id"), raw.get("src_ip"), source)


def _pick(device_id: Any, src_ip: Any, source: SourceConfig) -> str | None:
    if source.entity_field == "device_id":
        ident = device_id
    elif source.entity_field == "src_ip":
        ident = src_ip
    else:
        ident = device_id if device_id is not None else src_ip
    if isinstance(ident, str) and ident.strip():
        return ident
    return None


def route_raw(raw: Mapping[str, Any], source: SourceConfig, pseudonymizer: Pseudonymizer,
              partitioner: Partitioner) -> int:
    """Shard of a raw record: by the pseudonym of its identifier, else by its bytes.

    Records with the same identifier land with every event of that line; exact
    re-deliveries (same bytes) always land on the same shard, so deduplication is exact.
    """
    ident = routing_identifier(raw, source) if not raw.get("_error") else None
    original = raw.get("_raw")
    if not isinstance(original, (bytes, bytearray)):
        original = repr(sorted((str(k), repr(v)) for k, v in raw.items())).encode("utf-8", "replace")
    return _route_ident(ident, bytes(original), pseudonymizer, partitioner)


def _route_ident(ident: str | None, original: bytes, pseudonymizer: Pseudonymizer, partitioner: Partitioner) -> int:
    if ident is not None:
        try:
            return partitioner.line_shard(pseudonymizer.pseudonym(ident))
        except ValueError:
            pass
    return partitioner.raw_shard(original)


@dataclass
class FormatContext:
    """What a shard needs to parse shipped line bytes (the CSV header for NetFlow)."""
    fmt: str
    header: list[str] | None = None


def _missing(v: Any) -> Any:
    if isinstance(v, str) and v.strip() in parsers.MISSING_TOKENS:
        return None
    return v


@dataclass
class RecordRouter:
    """Streams ``(shard, item)`` pairs for one input; ``context`` is filled as it goes."""
    source: SourceConfig
    pseudonymizer: Pseudonymizer
    partitioner: Partitioner
    cache: dict[tuple[str, str], int] = field(default_factory=dict)
    cache_size: int = 1_000_000
    context: FormatContext | None = None

    def _shard_for(self, ident: str | None, original: bytes) -> int:
        if ident is None:
            return _route_ident(None, original, self.pseudonymizer, self.partitioner)
        key = (self.source.tenant_id, ident)
        s = self.cache.get(key)
        if s is None:
            if len(self.cache) >= self.cache_size:
                self.cache.clear()
            s = self.cache[key] = _route_ident(ident, original, self.pseudonymizer, self.partitioner)
        return s

    def route(self, payload: str | bytes | Path) -> Iterator[tuple[int, Item]]:
        """Route a whole input (text, bytes or a path). Raises ``parsers.ParseError`` like the parsers."""
        fmt = self.source.parser_format
        if isinstance(payload, str) and not isinstance(payload, Path):
            payload = payload.encode("utf-8")
        if fmt == parsers.FORMAT_NETFLOW_CSV:
            yield from self._route_netflow(payload)
        elif fmt == parsers.FORMAT_DNS_JSONL:
            self.context = FormatContext(fmt)
            for line_no, raw in parsers.iter_lines(payload):
                yield self._shard_for(self._dns_ident(raw), raw), (line_no, raw)
        else:
            yield from self.route_records(parsers.parse(fmt, payload))

    def route_records(self, records: Any) -> Iterator[tuple[int, Item]]:
        self.context = FormatContext("records")
        for raw in records:
            ident = routing_identifier(raw, self.source) if not raw.get("_error") else None
            if ident is not None:
                original = raw.get("_raw")
                yield self._shard_for(ident, bytes(original) if isinstance(original, (bytes, bytearray)) else b""), raw
            else:
                yield route_raw(raw, self.source, self.pseudonymizer, self.partitioner), raw

    # ------------------------------------------------------------------ NetFlow CSV
    def _route_netflow(self, payload: bytes | Path) -> Iterator[tuple[int, Item]]:
        header: list[str] | None = None
        parser: parsers.NetflowCsvParser | None = None
        idx_dev = idx_ip = -1
        for line_no, raw in parsers.iter_lines(payload):
            if raw.startswith(b"#"):
                continue
            if parser is None:
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise parsers.ParseError("netflow CSV header is not valid UTF-8") from exc
                header = next(csv.reader([text]))
                parser = parsers.NetflowCsvParser(header)
                self.context = FormatContext(parsers.FORMAT_NETFLOW_CSV, header)
                idx_dev = parser.columns.index("device_id") if "device_id" in parser.columns else -1
                idx_ip = parser.columns.index("src_ip") if "src_ip" in parser.columns else -1
                continue
            if raw.strip() == b"Summary":
                return
            yield self._shard_for(self._netflow_ident(raw, parser, idx_dev, idx_ip), raw), (line_no, raw)
        if parser is None:
            raise parsers.ParseError("netflow CSV input is empty (no header row)")

    def _netflow_ident(self, raw: bytes, parser: parsers.NetflowCsvParser, idx_dev: int, idx_ip: int) -> str | None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if '"' in text:
            rec = parser.parse_line(raw, 0)   # quoted CSV: use the real parser
            return None if rec.get("_error") else routing_identifier(rec, self.source)
        values = text.split(",")
        if len(values) != parser.width:
            return None

        def col(i: int) -> str | None:
            if i < 0:
                return None
            v = values[i].strip()
            return None if v in parsers.MISSING_TOKENS else v

        return _pick(col(idx_dev), col(idx_ip), self.source)

    # ------------------------------------------------------------------ DNS JSONL
    def _dns_ident(self, raw: bytes) -> str | None:
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(obj, dict):
            return None
        found: dict[str, Any] = {}
        for k, v in obj.items():
            canon = _DNS_IDENT_KEYS.get(str(k).lower())
            if canon and canon not in found:
                found[canon] = _missing(v)
        return _pick(found.get("device_id"), found.get("src_ip"), self.source)


def decode_items(context: FormatContext, items: list[tuple[int, Item]]) -> Iterator[tuple[int, dict[str, Any]]]:
    """Shard side: turn shipped items back into the raw records the parser would yield."""
    nf: parsers.NetflowCsvParser | None = None
    if context.fmt == parsers.FORMAT_NETFLOW_CSV:
        assert context.header is not None
        nf = parsers.NetflowCsvParser(context.header)
    for pos, item in items:
        if isinstance(item, dict):
            yield pos, item
        elif nf is not None:
            yield pos, nf.parse_line(item[1], item[0])
        elif context.fmt == parsers.FORMAT_DNS_JSONL:
            yield pos, parsers.parse_dns_line(item[1], item[0])
        else:
            raise ValueError(f"line items are not supported for format {context.fmt!r}")


__all__ = ["FormatContext", "Item", "RecordRouter", "decode_items", "route_raw", "routing_identifier"]
