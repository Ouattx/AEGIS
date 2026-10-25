"""Offline parsers for public threat-feed formats.

Every parser takes the feed body (``str``, ``bytes`` or a :class:`~pathlib.Path`),
the :class:`~aegis.intel.catalog.FeedSpec` it came from, and the import time, and
returns a :class:`~aegis.intel.models.ParseResult`. Parsers never touch the network.

Normalization rules shared by all formats:

- domains are lower-cased, stripped of a trailing dot and validated as host names;
- IPs and CIDRs are canonicalized; private, loopback, link-local, multicast,
  CGNAT, reserved and unspecified space is refused (an indicator on ``10.0.0.1``
  would match every home network); IETF documentation ranges are accepted so the
  synthetic fixtures work, they are never routed in production;
- CIDRs broader than /8 (IPv4) or /16 (IPv6) are refused as over-broad;
- a URL indicator becomes an indicator on its *host*, except when the host is a
  shared file or code hosting platform (GitHub, cloud storage, CDNs, ...): listing
  the platform would accuse every subscriber who uses it, so such rows are skipped
  with reason ``shared_platform_url``;
- non-network indicators (file hashes) are skipped (``non_network_ioc``);
- duplicates inside one file are merged (earliest first_seen, latest last_seen).

Shadowserver reports describe the operator's *own* lines. The reported address is
pseudonymized immediately with the tenant :class:`~aegis.ingest.pseudonym.Pseudonymizer`
and dropped; without a pseudonymizer the victim rows are dropped, never stored raw.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from aegis.intel.catalog import FeedSpec
from aegis.intel.models import IntelIndicator, ParseResult, VictimReport

MAX_FEED_BYTES = 64 * 1024 * 1024

#: Host suffixes of shared hosting platforms. URL indicators on them are never turned
#: into host indicators (collateral on millions of legitimate users).
SHARED_PLATFORM_SUFFIXES: frozenset[str] = frozenset({
    "github.com", "githubusercontent.com", "github.io", "gitlab.com", "bitbucket.org",
    "google.com", "googleapis.com", "googleusercontent.com", "appspot.com", "firebaseapp.com",
    "web.app", "blogspot.com", "drive.google.com", "docs.google.com",
    "dropbox.com", "dropboxusercontent.com", "onedrive.live.com", "1drv.ms", "sharepoint.com",
    "live.com", "microsoft.com", "windows.net", "azureedge.net", "azurewebsites.net",
    "amazonaws.com", "cloudfront.net", "akamaihd.net", "akamaized.net", "fastly.net", "cloudflare.com",
    "r2.dev", "pages.dev", "workers.dev", "netlify.app", "vercel.app", "herokuapp.com",
    "discord.com", "discordapp.com", "discordapp.net", "telegram.org", "t.me",
    "mediafire.com", "mega.nz", "pastebin.com", "transfer.sh", "wetransfer.com", "sendspace.com",
    "archive.org", "sourceforge.net", "weebly.com", "wixsite.com", "000webhostapp.com",
    "ngrok.io", "ngrok-free.app", "duckdns.org", "no-ip.com",
})

_REFUSED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))
_HOST_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_GENERIC_TAGS = frozenset({
    "32-bit", "64-bit", "arm", "arm7", "mips", "mipsel", "x86", "x86-64", "elf", "exe", "dll", "sh", "bash",
    "ascii", "zip", "rar", "doc", "docx", "xls", "js", "vbs", "ps1", "powershell", "msi", "apk", "jar", "lnk",
    "iso", "html", "pdf", "payload", "malware", "botnet", "c2", "cc", "opendir", "dropper", "loader", "stealer",
})


class PseudonymizerLike(Protocol):
    def pseudonym(self, identifier: str) -> str: ...


class FeedParseError(ValueError):
    """The whole feed body is unusable (not the right format, too large, undecodable)."""


# ---------------------------------------------------------------------------- normalization

def _read(data: str | bytes | Path, max_bytes: int = MAX_FEED_BYTES) -> str:
    if isinstance(data, Path):
        if data.stat().st_size > max_bytes:
            raise FeedParseError(f"{data} exceeds {max_bytes} bytes")
        data = data.read_bytes()
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise FeedParseError(f"feed body exceeds {max_bytes} bytes")
        try:
            return data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise FeedParseError(f"feed is not UTF-8: {exc}") from exc
    if len(data) > max_bytes:
        raise FeedParseError(f"feed body exceeds {max_bytes} bytes")
    return data.lstrip("﻿")


def _refused(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(net.version == r.version and net.overlaps(r) for r in _REFUSED_NETS)  # type: ignore[arg-type]


def normalize_ip(value: str) -> str:
    """Canonical text of a routable unicast IP. Raises ``ValueError`` otherwise."""
    ip = ipaddress.ip_address(value.strip().strip("[]"))
    if _refused(ipaddress.ip_network(ip)):
        raise ValueError(f"non-routable address {ip}")
    return str(ip)


def normalize_cidr(value: str) -> tuple[str, str]:
    """``("ip"|"cidr", canonical)`` for a routable prefix; /32 and /128 become plain IPs."""
    net = ipaddress.ip_network(value.strip(), strict=False)
    if _refused(net):
        raise ValueError(f"non-routable prefix {net}")
    if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 16):
        raise ValueError(f"over-broad prefix {net}")
    if net.prefixlen == net.max_prefixlen:
        return "ip", str(net.network_address)
    return "cidr", str(net)


def normalize_domain(value: str) -> str:
    """Lower-case, IDNA-encoded host name with at least two labels. Raises ``ValueError``."""
    name = value.strip().lower().rstrip(".")
    if not name or len(name) > 253:
        raise ValueError("bad domain length")
    try:
        name = name.encode("idna").decode("ascii") if not name.isascii() else name
    except UnicodeError as exc:
        raise ValueError(f"bad IDN {value!r}") from exc
    labels = name.split(".")
    if len(labels) < 2 or not all(_HOST_LABEL.match(lbl) for lbl in labels):
        raise ValueError(f"not a host name: {value!r}")
    if labels[-1].isdigit():
        raise ValueError(f"looks like an address: {value!r}")
    return name


def is_shared_platform(host: str, extra: Iterable[str] = ()) -> bool:
    parts = host.split(".")
    suffixes = {".".join(parts[i:]) for i in range(len(parts))}
    return bool(suffixes & SHARED_PLATFORM_SUFFIXES) or bool(suffixes & set(extra))


def classify_host(host: str) -> tuple[str, str]:
    """``("ip", canonical)`` or ``("domain", canonical)``. Raises ``ValueError``."""
    h = host.strip().strip("[]")
    try:
        return "ip", normalize_ip(h)
    except ValueError as exc:
        if re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+:[0-9a-fA-F:.]*", h):
            raise ValueError(f"unusable address {h!r}") from exc
    return "domain", normalize_domain(h)


def host_of_url(url: str) -> str:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    host = urlsplit(raw).hostname
    if not host:
        raise ValueError(f"no host in URL {url!r}")
    return host


def parse_feed_time(value: str | None) -> datetime | None:
    """Parse the timestamp spellings used by the feeds (all UTC unless stated)."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s.lower() in {"none", "null", "n/a", "-"}:
        return None
    if s.isdigit() and len(s) >= 9:
        return datetime.fromtimestamp(int(s), tz=timezone.utc)
    s = s.replace(" UTC", "").replace("UTC", "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if len(s) == 10:
        s += "T00:00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = parsedate_to_datetime(str(value))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unparseable timestamp {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)   # feeds publish UTC
    return dt.astimezone(timezone.utc)


def _split_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else str(raw).replace(";", ",").split(",")
    out = []
    for t in items:
        t = str(t).strip().lower()
        if t and t not in {"none", "null"}:
            out.append(t[:64])
    return out


def _family_from_tags(tags: list[str]) -> str | None:
    for t in tags:
        if t not in _GENERIC_TAGS and not t.isdigit():
            return t
    return None


class _Builder:
    """Collects indicators for one parse, merging duplicates."""

    def __init__(self, spec: FeedSpec, now: datetime):
        self.spec = spec
        self.now = now
        self.result = ParseResult(feed_id=spec.feed_id)
        self._inds: dict[tuple[str, str, str, str], IntelIndicator] = {}

    def add(self, typ: str, value: str, *, label: str | None, family: str | None, confidence: float,
            first: datetime | None, last: datetime | None, tags: Iterable[str] = (),
            reference: str | None = None, expires: datetime | None = None, verdict: str = "malicious") -> None:
        first = first or last or self.result.generated_at or self.now
        last = max(last or first, first)
        exp = expires or (last + self.spec.ttl)
        ind = IntelIndicator(
            type=typ, value=value, verdict=verdict, threat_label=label,  # type: ignore[arg-type]
            malware_family=family, confidence=round(min(max(confidence, 0.0), 1.0), 4), first_seen=first,
            last_seen=last, expires_at=exp, source_group=self.spec.source_group, sources=(self.spec.feed_id,),
            license=self.spec.license, redistributable=self.spec.redistributable,
            tags=tuple(sorted(set(tags))), references=(reference,) if reference else ())
        prev = self._inds.get(ind.key)
        self._inds[ind.key] = prev.merged_with(ind) if prev else ind

    def finish(self) -> ParseResult:
        self.result.indicators = sorted(self._inds.values(), key=lambda i: (i.type, i.value, i.verdict))
        return self.result


def _comment_header(lines: list[str]) -> list[str] | None:
    """abuse.ch CSVs carry the header as the last ``# id,...`` comment line."""
    header = None
    for ln in lines:
        if ln.startswith("#"):
            body = ln.lstrip("#").strip()
            if "," in body and not body.lower().startswith(("last updated", "terms", "for questions")):
                header = next(csv.reader([body]))
        else:
            break
    return [h.strip().strip('"') for h in header] if header else None


def _generated_from_comments(lines: Iterable[str]) -> datetime | None:
    for ln in lines:
        if not ln.startswith(("#", ";")):
            break
        m = re.search(r"(?:last updated|generated|last-modified)\s*[:\-]?\s*(.+)$", ln, re.IGNORECASE)
        if m:
            rest = m.group(1)
            iso_like = re.search(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?", rest)
            candidate = iso_like.group(0) if iso_like else rest.replace("(UTC)", "").strip(" #")
            try:
                return parse_feed_time(candidate)
            except ValueError:
                continue
        m = re.search(r"(\d{4})/(\d{2})/(\d{2})", ln)
        if m:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
    return None


def _csv_rows(text: str) -> Iterator[tuple[int, dict[str, str]]]:
    lines = text.splitlines()
    header = _comment_header(lines)
    body = [(i + 1, ln) for i, ln in enumerate(lines) if ln.strip() and not ln.startswith("#")]
    if header is None:
        if not body:
            return
        header = [h.strip().strip('"').lower() for h in next(csv.reader([body[0][1]]))]
        body = body[1:]
    header = [h.lower() for h in header]
    for lineno, ln in body:
        try:
            values = next(csv.reader([ln]))
        except csv.Error:
            values = []
        if len(values) != len(header):
            yield lineno, {}
            continue
        yield lineno, {k: v.strip() for k, v in zip(header, values)}


# ---------------------------------------------------------------------------- URLhaus

def parse_urlhaus_csv(data: str | bytes | Path, spec: FeedSpec, now: datetime, *,
                      extra_shared_platforms: Iterable[str] = ()) -> ParseResult:
    """abuse.ch URLhaus CSV dump (``csv_recent`` / ``csv_online``).

    Columns: ``id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter``.
    One indicator per URL *host*; offline URLs keep a lower confidence and an ``offline`` tag.
    """
    text = _read(data)
    b = _Builder(spec, now)
    b.result.generated_at = _generated_from_comments(text.splitlines())
    extra = tuple(normalize_domain(d) for d in extra_shared_platforms)
    saw_rows = False
    for lineno, row in _csv_rows(text):
        b.result.rows += 1
        if not row or "url" not in row:
            b.result.errors.append((lineno, "malformed_row"))
            continue
        saw_rows = True
        try:
            typ, value = classify_host(host_of_url(row["url"]))
            added = parse_feed_time(row.get("dateadded"))
            last = parse_feed_time(row.get("last_online")) or added
        except ValueError as exc:
            b.result.errors.append((lineno, f"invalid:{exc}"))
            continue
        if typ == "domain" and is_shared_platform(value, extra):
            b.result.skipped["shared_platform_url"] += 1
            continue
        status = (row.get("url_status") or "").lower()
        tags = _split_tags(row.get("tags"))
        conf = spec.default_confidence if status != "offline" else spec.default_confidence * 0.6
        if status == "offline":
            tags.append("offline")
        threat = (row.get("threat") or "").lower()
        label = "malware_distribution" if threat in ("malware_download", "") else threat
        b.add(typ, value, label=label, family=_family_from_tags(tags), confidence=conf, first=added,
              last=last, tags=["from_url", *tags], reference=row.get("urlhaus_link") or None)
    if b.result.rows and not saw_rows:
        raise FeedParseError("no URLhaus rows recognised (missing url column)")
    return b.finish()


# ---------------------------------------------------------------------------- ThreatFox

_THREATFOX_LABELS = {"botnet_cc": "c2_beaconing", "payload_delivery": "malware_distribution",
                     "cc_skimming": "skimming", "payload": "malware_distribution"}


def parse_threatfox_json(data: str | bytes | Path, spec: FeedSpec, now: datetime, *,
                         extra_shared_platforms: Iterable[str] = ()) -> ParseResult:
    """abuse.ch ThreatFox JSON: the export format (``{"<id>": [{...}]}``) or the API format
    (``{"query_status": "ok", "data": [{...}]}``).

    ``ip:port`` → IP indicator (port kept as a tag), ``domain`` → domain, ``url`` → host
    (unless a shared platform); hashes are skipped. ``confidence_level`` (0-100) is used
    when present.
    """
    text = _read(data)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"ThreatFox body is not JSON: {exc}") from exc
    if isinstance(doc, dict) and "data" in doc and isinstance(doc["data"], list):
        records: list[tuple[str, Any]] = [(str(r.get("id", i)) if isinstance(r, dict) else str(i), r)
                                          for i, r in enumerate(doc["data"])]
    elif isinstance(doc, dict):
        records = []
        for k, v in doc.items():
            for r in (v if isinstance(v, list) else [v]):
                records.append((str(k), r))
    else:
        raise FeedParseError("ThreatFox body must be a JSON object")
    b = _Builder(spec, now)
    extra = tuple(normalize_domain(d) for d in extra_shared_platforms)
    for n, (rid, r) in enumerate(records, start=1):
        b.result.rows += 1
        if not isinstance(r, dict):
            b.result.errors.append((n, "malformed_record"))
            continue
        ioc = r.get("ioc_value", r.get("ioc"))
        ioc_type = str(r.get("ioc_type") or "").lower()
        if not isinstance(ioc, str) or not ioc_type:
            b.result.errors.append((n, "missing_ioc"))
            continue
        tags = _split_tags(r.get("tags"))
        try:
            if ioc_type == "ip:port":
                host, _, port = ioc.rpartition(":")
                typ, value = "ip", normalize_ip(host)
                if port.isdigit():
                    tags.append(f"port:{int(port)}")
            elif ioc_type == "domain":
                typ, value = "domain", normalize_domain(ioc)
            elif ioc_type == "url":
                typ, value = classify_host(host_of_url(ioc))
                tags.append("from_url")
                if typ == "domain" and is_shared_platform(value, extra):
                    b.result.skipped["shared_platform_url"] += 1
                    continue
            else:
                b.result.skipped["non_network_ioc"] += 1
                continue
            first = parse_feed_time(r.get("first_seen_utc", r.get("first_seen")))
            last = parse_feed_time(r.get("last_seen_utc", r.get("last_seen")))
        except ValueError as exc:
            b.result.errors.append((n, f"invalid:{exc}"))
            continue
        level = r.get("confidence_level")
        conf = (float(level) / 100.0 if isinstance(level, (int, float)) and not isinstance(level, bool)
                and 0 <= level <= 100 else spec.default_confidence)
        threat = str(r.get("threat_type") or "").lower()
        family = r.get("malware_printable") or r.get("malware")
        family = str(family).strip().lower() if family and str(family).lower() not in ("unknown", "none") else None
        b.add(typ, value, label=_THREATFOX_LABELS.get(threat, threat or None), family=family, confidence=conf,
              first=first, last=last, tags=tags, reference=f"threatfox:{rid}")
    return b.finish()


# ---------------------------------------------------------------------------- Feodo Tracker

def parse_feodo(data: str | bytes | Path, spec: FeedSpec, now: datetime) -> ParseResult:
    """Feodo Tracker IP blocklist: the CSV (``first_seen_utc, dst_ip, dst_port, c2_status,
    last_online, malware``) or the plain one-IP-per-line text list.

    The blocklist is a full snapshot of C2s considered active at generation time, so an
    ``online`` entry's ``last_seen`` is the generation time.
    """
    text = _read(data)
    lines = text.splitlines()
    b = _Builder(spec, now)
    gen = _generated_from_comments(lines)
    b.result.generated_at = gen
    data_lines = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    is_csv = any("," in ln for ln in data_lines[:5]) or _comment_header(lines) is not None
    if not is_csv:
        for lineno, ln in enumerate(lines, start=1):
            if not ln.strip() or ln.startswith("#"):
                continue
            b.result.rows += 1
            try:
                ip = normalize_ip(ln.strip())
            except ValueError as exc:
                b.result.errors.append((lineno, f"invalid:{exc}"))
                continue
            seen = gen or now
            b.add("ip", ip, label="c2_beaconing", family=None, confidence=spec.default_confidence,
                  first=seen, last=seen, tags=["c2"])
        return b.finish()
    for lineno, row in _csv_rows(text):
        b.result.rows += 1
        if not row or "dst_ip" not in row:
            b.result.errors.append((lineno, "malformed_row"))
            continue
        try:
            ip = normalize_ip(row["dst_ip"])
            first = parse_feed_time(row.get("first_seen_utc") or row.get("first_seen"))
            last = parse_feed_time(row.get("last_online"))
        except ValueError as exc:
            b.result.errors.append((lineno, f"invalid:{exc}"))
            continue
        status = (row.get("c2_status") or "").lower()
        if status == "online" and gen is not None:
            last = max(last or gen, gen)
        if last is not None and first is not None and last < first:
            last = first
        tags = ["c2"] + ([f"port:{int(row['dst_port'])}"] if (row.get("dst_port") or "").isdigit() else [])
        conf = spec.default_confidence if status != "offline" else spec.default_confidence * 0.6
        if status == "offline":
            tags.append("offline")
        family = (row.get("malware") or "").strip().lower() or None
        b.add("ip", ip, label="c2_beaconing", family=family, confidence=conf, first=first, last=last, tags=tags)
    return b.finish()


# ---------------------------------------------------------------------------- Spamhaus DROP / EDROP

def parse_spamhaus_drop(data: str | bytes | Path, spec: FeedSpec, now: datetime) -> ParseResult:
    """Spamhaus DROP / EDROP: the legacy text format (``192.0.2.0/24 ; SBL123``, ``;`` comments
    with ``Last-Modified`` / ``Expires``) or the JSON-lines format (``{"cidr": ..., "sblid": ...}``
    records followed by a ``{"type": "metadata", "timestamp": ...}`` record).

    DROP says nothing about when a range was first listed, so ``first_seen`` is the list's
    generation time; :class:`~aegis.intel.store.IntelStore` keeps the earliest across imports.
    """
    text = _read(data)
    b = _Builder(spec, now)
    stripped = text.lstrip()
    entries: list[tuple[int, str, str | None]] = []
    expires: datetime | None = None
    if stripped.startswith("{"):
        for lineno, ln in enumerate(text.splitlines(), start=1):
            if not ln.strip():
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                b.result.errors.append((lineno, "malformed_json_line"))
                continue
            if not isinstance(rec, dict):
                b.result.errors.append((lineno, "malformed_json_line"))
                continue
            if rec.get("type") == "metadata":
                ts = rec.get("timestamp")
                if isinstance(ts, (int, float)) and not isinstance(ts, bool):
                    b.result.generated_at = datetime.fromtimestamp(int(ts), tz=timezone.utc)
                continue
            if isinstance(rec.get("cidr"), str):
                entries.append((lineno, rec["cidr"], rec.get("sblid")))
            else:
                b.result.errors.append((lineno, "missing_cidr"))
    else:
        for lineno, ln in enumerate(text.splitlines(), start=1):
            s = ln.strip()
            if not s:
                continue
            if s.startswith(";"):
                m = re.match(r";\s*Last-Modified:\s*(.+)$", s, re.IGNORECASE)
                if m:
                    b.result.generated_at = parse_feed_time(m.group(1))
                m = re.match(r";\s*Expires:\s*(.+)$", s, re.IGNORECASE)
                if m:
                    expires = parse_feed_time(m.group(1))
                continue
            cidr, _, rest = s.partition(";")
            entries.append((lineno, cidr.strip(), rest.strip() or None))
        if b.result.generated_at is None:
            b.result.generated_at = _generated_from_comments(text.splitlines())
    seen = b.result.generated_at or now
    # a list that stated its own expiry is honoured only when it extends beyond the TTL floor
    exp = max(expires, seen + spec.ttl) if expires else None
    for lineno, cidr, sbl in entries:
        b.result.rows += 1
        try:
            typ, value = normalize_cidr(cidr)
        except ValueError as exc:
            b.result.errors.append((lineno, f"invalid:{exc}"))
            continue
        b.add(typ, value, label="hijacked_netblock", family=None, confidence=spec.default_confidence,
              first=seen, last=seen, expires=exp, tags=["drop"],
              reference=f"spamhaus:{sbl}" if isinstance(sbl, str) and sbl else None)
    return b.finish()


# ---------------------------------------------------------------------------- Shadowserver

_VICTIM_COLUMNS = ("src_ip", "ip")
_FAMILY_COLUMNS = ("infection", "malware", "family")


def parse_shadowserver_csv(data: str | bytes | Path, spec: FeedSpec, now: datetime, *, report_type: str,
                           pseudonymizer: PseudonymizerLike | None) -> ParseResult:
    """A Shadowserver report CSV about the operator's own address space.

    - infection reports (``event4_sinkhole*``, ``botnet_drone``, ``*_drone``, ``*infected*``)
      yield :class:`VictimReport` rows (``kind="infection"``) and C2 indicators from
      ``cc_ip`` / ``cc`` / ``cc_dns`` columns and from the sinkholed ``http_host``;
    - every other report (``scan_*``, ``open_*``, exposure) yields ``kind="exposure"``
      victim rows only: an open service is not a compromise;
    - sinkhole destination addresses are infrastructure of the sinkhole operator and are
      skipped (``sinkhole_infrastructure``).

    The victim address is pseudonymized and dropped; with ``pseudonymizer=None`` victim
    rows are counted as ``victim_dropped_no_pseudonymizer`` and nothing about them is kept.
    """
    text = _read(data)
    b = _Builder(spec, now)
    rt = report_type.strip().lower()
    infection = ("sinkhole" in rt or "drone" in rt or "infected" in rt or "botnet" in rt)
    sinkhole = "sinkhole" in rt
    for lineno, row in _csv_rows(text):
        b.result.rows += 1
        if not row or "timestamp" not in row:
            b.result.errors.append((lineno, "malformed_row"))
            continue
        try:
            ts = parse_feed_time(row.get("timestamp"))
        except ValueError as exc:
            b.result.errors.append((lineno, f"invalid:{exc}"))
            continue
        if ts is None:
            b.result.errors.append((lineno, "missing_timestamp"))
            continue
        family = next((row[c].strip().lower() for c in _FAMILY_COLUMNS if row.get(c, "").strip()), None)
        victim_raw = next((row[c] for c in _VICTIM_COLUMNS if row.get(c, "").strip()), None)
        if victim_raw is not None:
            if pseudonymizer is None:
                b.result.skipped["victim_dropped_no_pseudonymizer"] += 1
            else:
                try:
                    canonical = str(ipaddress.ip_address(victim_raw.strip()))
                except ValueError:
                    b.result.errors.append((lineno, "invalid_victim_address"))
                    canonical = None
                if canonical is not None:
                    b.result.victims.append(VictimReport(
                        line_pseudonym=pseudonymizer.pseudonym(canonical), observed_at=ts,
                        kind="infection" if infection else "exposure", report_type=rt, malware_family=family,
                        source=spec.feed_id, source_group=spec.source_group, license=spec.license))
        if not infection:
            continue
        candidates: list[tuple[str, str]] = []
        for col in ("cc_ip", "cc", "cc_dns", "cc_hostname"):
            v = row.get(col, "").strip()
            if v:
                candidates.append((col, v))
        if sinkhole:
            host = row.get("http_host", "").strip()
            if host:
                candidates.append(("http_host", host))
            if row.get("dst_ip", "").strip():
                b.result.skipped["sinkhole_infrastructure"] += 1
        for col, v in candidates:
            try:
                typ, value = classify_host(_c2_host(v))
            except ValueError:
                b.result.skipped["invalid_c2_value"] += 1
                continue
            tags = ["c2", f"report:{rt}"] + (["sinkholed"] if col == "http_host" else [])
            b.add(typ, value, label="c2_beaconing", family=family, confidence=spec.default_confidence,
                  first=ts, last=ts, tags=tags)
    return b.finish()


def _c2_host(value: str) -> str:
    """Host part of a C2 column value: a URL, ``host:port``, a bare IPv6 address or a host."""
    if "/" in value:
        return host_of_url(value)
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value


# ---------------------------------------------------------------------------- dispatcher

def parse_feed(data: str | bytes | Path, spec: FeedSpec, now: datetime, *, report_type: str | None = None,
               pseudonymizer: PseudonymizerLike | None = None,
               extra_shared_platforms: Iterable[str] = ()) -> ParseResult:
    """Parse ``data`` with the parser for ``spec.format``."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    fmt = spec.format
    if fmt == "urlhaus_csv":
        return parse_urlhaus_csv(data, spec, now, extra_shared_platforms=extra_shared_platforms)
    if fmt == "threatfox_json":
        return parse_threatfox_json(data, spec, now, extra_shared_platforms=extra_shared_platforms)
    if fmt in ("feodo_csv", "feodo_txt"):
        return parse_feodo(data, spec, now)
    if fmt == "spamhaus_drop":
        return parse_spamhaus_drop(data, spec, now)
    if fmt == "shadowserver_csv":
        if not report_type:
            raise ValueError("Shadowserver reports need report_type (e.g. 'event4_sinkhole_http')")
        return parse_shadowserver_csv(data, spec, now, report_type=report_type, pseudonymizer=pseudonymizer)
    raise ValueError(f"no parser for format {fmt!r}")


__all__ = [
    "FeedParseError", "MAX_FEED_BYTES", "SHARED_PLATFORM_SUFFIXES", "classify_host", "host_of_url",
    "is_shared_platform", "normalize_cidr", "normalize_domain", "normalize_ip", "parse_feed", "parse_feed_time",
    "parse_feodo", "parse_shadowserver_csv", "parse_spamhaus_drop", "parse_threatfox_json", "parse_urlhaus_csv",
]
