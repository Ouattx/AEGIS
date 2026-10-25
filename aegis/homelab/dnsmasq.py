"""dnsmasq query-log parser (the lab access point's resolver log).

The home-lab access point runs dnsmasq with ``log-queries=extra`` and
``log-facility=<file>`` (see ``deploy/homelab``). Each client query produces a
``query[TYPE] name from client`` line followed by ``forwarded`` / ``cached`` /
``reply`` / ``config`` lines carrying the answers. With ``extra`` every line carries
a serial number and the client address, which ties replies to their query exactly.
Plain ``log-queries`` output (no serial) is also accepted: a reply is attached to the
most recent unanswered query for the same name (documented ambiguity when two lab
clients ask for the same name within the same second).

Output: canonical raw DNS records (see :mod:`aegis.ingest.parsers`) ready for
``IngestPipeline.ingest_records``, or DNS JSONL text accepted by
``aegis.ingest.parsers.parse_dns_jsonl`` (so the service can ingest it through an
ordinary ``dns`` source). Nothing is invented: a query whose reply is not in the log
has ``rcode=None`` (normalized to ``UNKNOWN``), never ``NOERROR``.

Timestamps: syslog-style lines (``Oct 25 10:00:01``) carry neither year nor timezone.
The caller passes both; the year rolls over when the month goes backwards (December
to January). ISO 8601 prefixes (journald ``-o short-iso``) are used as is.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Iterable, Iterator
from zoneinfo import ZoneInfo

from aegis.ingest.parsers import Source, iter_lines

FORMAT_DNSMASQ = "dnsmasq_log"

_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                       "Nov", "Dec"), start=1)}
_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
                     r"(?:(?P<host>[\w.\-]+)\s+)?(?P<prog>dnsmasq(?:-dhcp)?)\[\d+\]:\s(?P<msg>.*)$")
_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
                  r"(?:(?P<host>[\w.\-]+)\s+)?(?P<prog>dnsmasq(?:-dhcp)?)\[\d+\]:\s(?P<msg>.*)$")
_EXTRA = re.compile(r"^(?P<serial>\d+)\s+(?P<client>[0-9A-Fa-f:.]+)/(?P<port>\d+)\s+(?P<rest>.*)$")
_QUERY = re.compile(r"^query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>[0-9A-Fa-f:.]+)$")
_ANSWER = re.compile(r"^(?P<verb>reply|cached|config|cached-stale|validation)\s+(?P<name>\S+)\s+is\s+(?P<value>.+)$")

_RCODE_WORDS = {"NXDOMAIN": "NXDOMAIN", "SERVFAIL": "SERVFAIL", "REFUSED": "REFUSED", "NOTIMP": "NOTIMP"}


@dataclass
class _Query:
    line_no: int
    observed_at: datetime
    client: str
    qname: str
    qtype: str
    raw: list[bytes]
    answers: list[str] = field(default_factory=list)
    rcode: str | None = None
    cname: bool = False
    last_t: datetime | None = None

    def record(self) -> dict[str, Any]:
        return {"record_type": "dns", "observed_at": self.observed_at.isoformat(), "src_ip": self.client,
                "qname": self.qname, "qtype": self.qtype, "rcode": self.rcode, "answers": list(self.answers),
                "_format": FORMAT_DNSMASQ, "_line_no": self.line_no, "_raw": b"\n".join(self.raw)}


@dataclass
class DnsmasqParseStats:
    lines: int = 0
    queries: int = 0
    answered: int = 0
    unanswered: int = 0
    dhcp_lines: int = 0
    other_lines: int = 0
    unparsed_lines: int = 0
    orphan_replies: int = 0

    def to_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class DnsmasqLogParser:
    """Streaming-friendly dnsmasq parser; call :meth:`parse` once per log (lines in file order)."""

    def __init__(self, *, year: int, tz: str | tzinfo = "UTC", pending_ttl_s: float = 10.0):
        self.year = year
        self.tz: tzinfo = ZoneInfo(tz) if isinstance(tz, str) else tz
        self.pending_ttl = timedelta(seconds=pending_ttl_s)
        self.stats = DnsmasqParseStats()
        self._last_month: int | None = None

    # ------------------------------------------------------------------ timestamps
    def _syslog_time(self, mon: str, day: str, hms: str) -> datetime:
        month = _MONTHS[mon]
        if self._last_month is not None and month < self._last_month:
            self.year += 1                                      # December -> January rollover
        self._last_month = month
        hh, mm, ss = (int(x) for x in hms.split(":"))
        local = datetime(self.year, month, int(day), hh, mm, ss, tzinfo=self.tz)
        return local.astimezone(timezone.utc)

    def _iso_time(self, text: str) -> datetime:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.tz)
        return dt.astimezone(timezone.utc)

    # ------------------------------------------------------------------ main loop
    def parse(self, src: Source) -> Iterator[dict[str, Any]]:
        """Yield canonical raw DNS records in query order."""
        by_serial: dict[str, _Query] = {}
        by_name: dict[str, list[_Query]] = {}
        out: list[_Query] = []
        for line_no, raw in iter_lines(src):
            self.stats.lines += 1
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                self.stats.unparsed_lines += 1
                continue
            m = _SYSLOG.match(text)
            if m is not None:
                try:
                    ts = self._syslog_time(m["mon"], m["day"], m["time"])
                except (KeyError, ValueError):
                    self.stats.unparsed_lines += 1
                    continue
            else:
                m = _ISO.match(text)
                if m is None:
                    self.stats.unparsed_lines += 1
                    continue
                try:
                    ts = self._iso_time(m["ts"])
                except ValueError:
                    self.stats.unparsed_lines += 1
                    continue
            if m["prog"] == "dnsmasq-dhcp":
                self.stats.dhcp_lines += 1
                continue
            msg = m["msg"]
            serial: str | None = None
            ex = _EXTRA.match(msg)
            if ex is not None:
                serial, msg = ex["serial"], ex["rest"]
            q = _QUERY.match(msg)
            if q is not None:
                query = _Query(line_no=line_no, observed_at=ts, client=q["client"], qname=q["name"].rstrip("."),
                               qtype=q["qtype"].upper(), raw=[raw], last_t=ts)
                out.append(query)
                self.stats.queries += 1
                if serial is not None:
                    by_serial[serial] = query
                else:
                    by_name.setdefault(query.qname.lower(), []).append(query)
                    if self.stats.queries % 1000 == 0:
                        self._prune(by_name, ts)
                continue
            a = _ANSWER.match(msg)
            if a is None:
                self.stats.other_lines += 1      # forwarded / dnssec / config notices: no answer content
                if serial is not None and serial in by_serial:
                    by_serial[serial].raw.append(raw)
                continue
            target = by_serial.get(serial) if serial is not None else self._by_name(by_name, a["name"], ts)
            if target is None:
                self.stats.orphan_replies += 1
                continue
            target.raw.append(raw)
            target.last_t = ts
            self._apply(target, a["value"].strip())
        for query in out:
            if query.rcode is None and not query.answers:
                self.stats.unanswered += 1
            else:
                self.stats.answered += 1
            yield query.record()

    def _prune(self, by_name: dict[str, list[_Query]], ts: datetime) -> None:
        horizon = self.pending_ttl + timedelta(seconds=2)
        for key in list(by_name):
            keep = [q for q in by_name[key] if ts - (q.last_t or q.observed_at) <= horizon]
            if keep:
                by_name[key] = keep
            else:
                del by_name[key]

    def _by_name(self, by_name: dict[str, list[_Query]], name: str, ts: datetime) -> _Query | None:
        """Most recent pending query for ``name``, else a recent query whose answer was a CNAME chain."""
        key = name.rstrip(".").lower()
        cands = [q for q in by_name.get(key, []) if ts - q.observed_at <= self.pending_ttl]
        if cands:
            return cands[-1]
        recent: _Query | None = None
        for lst in by_name.values():
            for q in lst[-8:]:
                if not q.cname or q.last_t is None or not timedelta(0) <= ts - q.last_t <= timedelta(seconds=2):
                    continue
                if recent is None or recent.last_t is None or q.last_t >= recent.last_t:
                    recent = q
        return recent

    @staticmethod
    def _apply(q: _Query, value: str) -> None:
        if _is_ip(value):
            if value not in q.answers:
                q.answers.append(value)
            q.rcode = "NOERROR"
            return
        word = value.split()[0].upper()
        if word in _RCODE_WORDS:
            if not q.answers:
                q.rcode = _RCODE_WORDS[word]
            return
        if word.startswith("NODATA"):
            q.rcode = q.rcode or "NOERROR"
            return
        if value.startswith("<CNAME>"):
            q.cname = True
            q.rcode = q.rcode or "NOERROR"
            return
        if value.startswith("<"):
            q.rcode = q.rcode or "NOERROR"   # other RR types (<HTTPS>, <SRV>, ...): answer exists, not an address


def parse_dnsmasq_log(src: Source, *, year: int, tz: str | tzinfo = "UTC") -> list[dict[str, Any]]:
    """Parse a whole dnsmasq log into canonical raw DNS records."""
    return list(DnsmasqLogParser(year=year, tz=tz).parse(src))


def records_to_jsonl(records: Iterable[dict[str, Any]]) -> str:
    """DNS JSONL text (``parse_dns_jsonl`` aliases) for ingest through an ordinary ``dns`` source."""
    lines = []
    for r in records:
        obj = {"ts": r["observed_at"], "client_ip": r.get("src_ip"), "qname": r["qname"], "qtype": r.get("qtype"),
               "rcode": r.get("rcode"), "answers": list(r.get("answers") or [])}
        lines.append(json.dumps(obj, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines) + ("\n" if lines else "")


def dnsmasq_to_jsonl(src: Source, *, year: int, tz: str | tzinfo = "UTC") -> str:
    """Convenience: dnsmasq log -> DNS JSONL text."""
    return records_to_jsonl(parse_dnsmasq_log(src, year=year, tz=tz))


__all__ = ["DnsmasqLogParser", "DnsmasqParseStats", "FORMAT_DNSMASQ", "dnsmasq_to_jsonl", "parse_dnsmasq_log",
           "records_to_jsonl"]
