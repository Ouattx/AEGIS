"""One-command import of a home-lab capture into AEGIS ingest.

Input is a capture directory produced by ``deploy/homelab`` (or any directory holding
the same files)::

    capture.json                  optional manifest written by the capture scripts
    zeek/conn*.log[.gz]           Zeek connection logs (offline conversion of the pcaps)
    zeek/dns*.log[.gz]            Zeek DNS logs (used when no dnsmasq log is present)
    dnsmasq*.log[.N][.gz]         the access point's dnsmasq query log

Every record goes through the regular :class:`aegis.ingest.IngestPipeline` (strict
normalization, pseudonymization, validation, quarantine) with the single-home source
configs of :func:`aegis.homelab.config.single_home_sources`. Before that, the importer
removes only what is not device-to-internet telemetry, and counts it:

* flows from a lab client to lab-local, multicast or broadcast addresses (SSDP, mDNS,
  DNS to the access point itself) are summarized per device as *local chatter*;
* resolver queries not made by a lab client (the access point's own lookups).

Raw lab IP addresses never leave this module: devices are identified by tenant-keyed
pseudonyms, and user-chosen labels are attached to those pseudonyms.
"""
from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from aegis.contracts.models import ObservationEvent
from aegis.ingest.bus import OBSERVATIONS_TOPIC, InMemoryBus
from aegis.ingest.parsers import parse_zeek_conn, parse_zeek_dns
from aegis.ingest.pipeline import IngestPipeline, IngestStats
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.ingest.validator import Validator
from aegis.homelab.config import (
    SOURCE_DNSMASQ,
    SOURCE_ZEEK_CONN,
    SOURCE_ZEEK_DNS,
    HomeLabConfig,
    single_home_sources,
)
from aegis.homelab.dnsmasq import DnsmasqLogParser

_ZEEK_CONN_RE = re.compile(r"^conn(\..+)?\.log(\.gz)?$")
_ZEEK_DNS_RE = re.compile(r"^dns(\..+)?\.log(\.gz)?$")
_WINDOW_SLACK = timedelta(seconds=60)
_DNSMASQ_RE = re.compile(r"^dnsmasq.*\.log(\.\d+)?(\.gz)?$")


class CaptureError(ValueError):
    """The capture directory holds nothing that can be imported."""


@dataclass(frozen=True)
class InputFile:
    path: str
    kind: str                    # zeek_conn | zeek_dns | dnsmasq_log | capture_manifest
    sha256: str
    size_bytes: int
    #: False when the file was found but not used (e.g. Zeek dns.log while the dnsmasq log feeds DNS)
    used: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "kind": self.kind, "sha256": self.sha256, "size_bytes": self.size_bytes,
                "used": self.used}


@dataclass(frozen=True)
class CaptureManifest:
    """What the capture scripts recorded about the capture (all optional)."""
    capture_id: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    interface: str | None = None
    snaplen: int | None = None
    synthetic: bool = False
    tool: str | None = None
    notes: str | None = None
    #: timezone of the dnsmasq log's syslog timestamps, as recorded by the capture scripts
    dnsmasq_timezone: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CaptureManifest":
        def ts(v: Any) -> datetime | None:
            if not v:
                return None
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                raise CaptureError(f"capture manifest timestamp {v!r} has no timezone")
            return dt.astimezone(timezone.utc)
        snap = d.get("snaplen")
        return cls(capture_id=d.get("capture_id"), started_at=ts(d.get("started_at")), ended_at=ts(d.get("ended_at")),
                   interface=d.get("interface"), snaplen=int(snap) if snap is not None else None,
                   synthetic=bool(d.get("synthetic", False)), tool=d.get("tool"), notes=d.get("notes"),
                   dnsmasq_timezone=d.get("dnsmasq_timezone") or None)

    def to_dict(self) -> dict[str, Any]:
        return {"capture_id": self.capture_id,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "ended_at": self.ended_at.isoformat() if self.ended_at else None,
                "interface": self.interface, "snaplen": self.snaplen, "synthetic": self.synthetic,
                "tool": self.tool, "notes": self.notes, "dnsmasq_timezone": self.dnsmasq_timezone}


@dataclass
class CapturePaths:
    zeek_conn: list[Path] = field(default_factory=list)
    zeek_dns: list[Path] = field(default_factory=list)
    dnsmasq: list[Path] = field(default_factory=list)
    manifest: Path | None = None
    usage: Path | None = None              # optional user usage windows (usage.json / usage.csv)

    @property
    def empty(self) -> bool:
        return not (self.zeek_conn or self.zeek_dns or self.dnsmasq)


@dataclass
class LocalChatter:
    """Lab-local / multicast traffic of one device (summarized, not analyzed as infrastructure)."""
    flows: int = 0
    multicast_flows: int = 0
    destinations: set[str] = field(default_factory=set)       # pseudonymized local destinations
    ports: Counter[int] = field(default_factory=Counter)

    def to_dict(self) -> dict[str, Any]:
        return {"flows": self.flows, "multicast_flows": self.multicast_flows,
                "distinct_local_destinations": len(self.destinations),
                "top_ports": [[p, n] for p, n in self.ports.most_common(8)]}


@dataclass
class CaptureImport:
    cfg: HomeLabConfig
    events: list[ObservationEvent]
    files: list[InputFile]
    ingest: list[dict[str, Any]]
    prefilter: dict[str, int]
    local_chatter: dict[str, LocalChatter]
    devices: dict[str, str]                 # pseudonym -> label
    manifest: CaptureManifest
    quarantined: int
    quarantine_reasons: dict[str, int]
    dnsmasq_stats: dict[str, int] = field(default_factory=dict)
    pseudonym_key_fingerprint: str = ""

    @property
    def start(self) -> datetime:
        if self.manifest.started_at is not None:
            return self.manifest.started_at
        if not self.events:
            raise CaptureError("empty capture has no time span")
        return self.events[0].observed_at

    @property
    def end(self) -> datetime:
        if self.manifest.ended_at is not None:
            return self.manifest.ended_at
        if not self.events:
            raise CaptureError("empty capture has no time span")
        return self.events[-1].observed_at

    @property
    def span_s(self) -> float:
        return max(0.0, (self.end - self.start).total_seconds())

    @property
    def synthetic(self) -> bool:
        return self.manifest.synthetic

    def events_for(self, pseudonym: str) -> list[ObservationEvent]:
        return [e for e in self.events if e.entity_pseudonym == pseudonym]

    def summary(self) -> dict[str, Any]:
        return {"tenant_id": self.cfg.tenant_id, "events": len(self.events), "devices": dict(self.devices),
                "start": self.start.isoformat() if self.events or self.manifest.started_at else None,
                "end": self.end.isoformat() if self.events or self.manifest.ended_at else None,
                "files": [f.to_dict() for f in self.files], "ingest": self.ingest, "prefilter": dict(self.prefilter),
                "quarantined": self.quarantined, "quarantine_reasons": dict(self.quarantine_reasons),
                "dnsmasq": dict(self.dnsmasq_stats), "manifest": self.manifest.to_dict(),
                "local_chatter": {k: v.to_dict() for k, v in self.local_chatter.items()},
                "pseudonym_key_fingerprint": self.pseudonym_key_fingerprint}


# ---------------------------------------------------------------------------- discovery

def discover_capture(directory: str | Path) -> CapturePaths:
    """Find Zeek / dnsmasq logs and the manifest under ``directory`` (recursive)."""
    root = Path(directory)
    if not root.is_dir():
        raise CaptureError(f"{root} is not a directory")
    paths = CapturePaths()
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        name = p.name
        if name == "capture.json" and paths.manifest is None:
            paths.manifest = p
        elif name in ("usage.json", "usage.csv") and paths.usage is None:
            paths.usage = p
        elif _DNSMASQ_RE.match(name):
            paths.dnsmasq.append(p)
        elif _ZEEK_CONN_RE.match(name):
            paths.zeek_conn.append(p)
        elif _ZEEK_DNS_RE.match(name):
            paths.zeek_dns.append(p)
    # rotated dnsmasq logs: oldest (highest suffix) first so syslog year rollover is monotone
    paths.dnsmasq.sort(key=lambda p: (-_rotation_index(p.name), p.name))
    return paths


def _rotation_index(name: str) -> int:
    m = re.search(r"\.log\.(\d+)", name)
    return int(m.group(1)) if m else 0


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _open_text(path: Path) -> bytes:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as fh:
            return fh.read()
    return path.read_bytes()


# ---------------------------------------------------------------------------- import

def import_capture(capture: str | Path | CapturePaths, cfg: HomeLabConfig | None = None, *,
                   pseudonymizer: Pseudonymizer,
                   clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> CaptureImport:
    """Import a capture directory (or explicit :class:`CapturePaths`) as canonical events.

    Returns every accepted :class:`ObservationEvent` in time order plus ingest accounting
    (per-file :class:`IngestStats`, quarantine reasons, pre-filter counts) and the sha256
    of every input file (the root of the report's evidence trail).
    """
    cfg = cfg or HomeLabConfig()
    paths = capture if isinstance(capture, CapturePaths) else discover_capture(capture)
    if paths.empty:
        raise CaptureError("no Zeek conn/dns log and no dnsmasq log found")
    manifest = CaptureManifest()
    files: list[InputFile] = []
    if paths.manifest is not None:
        manifest = CaptureManifest.from_dict(json.loads(paths.manifest.read_text(encoding="utf-8")))
        files.append(InputFile(str(paths.manifest), "capture_manifest", file_sha256(paths.manifest),
                               paths.manifest.stat().st_size))

    sources = single_home_sources(cfg)
    bus = InMemoryBus(max_queue=200_000)
    events: list[ObservationEvent] = []
    bus.subscribe(OBSERVATIONS_TOPIC, events.append)
    validator = Validator(expected_tenant=cfg.tenant_id,
                          allowed_authorizations={cfg.tenant_id: {cfg.collection_authorization_id}},
                          clock=clock, retention_days=cfg.retention_days)
    pipeline = IngestPipeline(bus, validator, sources, pseudonymizers={cfg.tenant_id: pseudonymizer}, clock=clock)
    prefilter: Counter[str] = Counter()
    chatter: dict[str, LocalChatter] = {}
    stats: list[IngestStats] = []

    def run(records: Iterable[dict[str, Any]], source_id: str, name: str) -> None:
        stats.append(pipeline.ingest_records(records, source_id, name=name))
        while bus.drain():
            pass

    for p in paths.zeek_conn:
        files.append(InputFile(str(p), "zeek_conn", file_sha256(p), p.stat().st_size))
        run(_conn_filter(parse_zeek_conn(_open_text(p)), cfg, pseudonymizer, prefilter, chatter),
            SOURCE_ZEEK_CONN, p.name)
    use_zeek_dns = bool(paths.zeek_dns) and (cfg.dns_source in ("zeek", "both") or not paths.dnsmasq)
    use_dnsmasq = bool(paths.dnsmasq) and (cfg.dns_source in ("dnsmasq", "both") or not paths.zeek_dns)
    for p in paths.zeek_dns:
        files.append(InputFile(str(p), "zeek_dns", file_sha256(p), p.stat().st_size, used=use_zeek_dns))
        if use_zeek_dns:
            run(_dns_filter(parse_zeek_dns(_open_text(p)), cfg, prefilter), SOURCE_ZEEK_DNS, p.name)
    dstats: dict[str, int] = {}
    year = cfg.dnsmasq_year or (manifest.started_at.year if manifest.started_at else clock().year)
    for p in paths.dnsmasq:
        files.append(InputFile(str(p), "dnsmasq_log", file_sha256(p), p.stat().st_size, used=use_dnsmasq))
        if use_dnsmasq:
            parser = DnsmasqLogParser(year=year, tz=cfg.dnsmasq_timezone or manifest.dnsmasq_timezone or "UTC")
            run(_dns_filter(parser.parse(_open_text(p)), cfg, prefilter), SOURCE_DNSMASQ, p.name)
            for k, v in parser.stats.to_dict().items():
                dstats[k] = dstats.get(k, 0) + v
    if paths.usage is not None:
        files.append(InputFile(str(paths.usage), "usage_windows", file_sha256(paths.usage),
                               paths.usage.stat().st_size))

    events.sort(key=lambda e: (e.observed_at, e.event_id))
    if manifest.started_at is not None or manifest.ended_at is not None:
        # the resolver log is copied whole: keep only events inside the capture window
        lo = manifest.started_at - _WINDOW_SLACK if manifest.started_at else None
        hi = manifest.ended_at + _WINDOW_SLACK if manifest.ended_at else None
        inside = [e for e in events if (lo is None or e.observed_at >= lo) and (hi is None or e.observed_at <= hi)]
        if len(inside) != len(events):
            prefilter["outside_capture_window"] += len(events) - len(inside)
        events = inside
    quarantine_reasons: Counter[str] = Counter()
    for s in stats:
        quarantine_reasons.update(s.quarantine_reasons)
    return CaptureImport(cfg=cfg, events=events, files=files, ingest=[s.to_dict() for s in stats],
                         prefilter=dict(prefilter), local_chatter=chatter,
                         devices=_device_labels(events, cfg, pseudonymizer), manifest=manifest,
                         quarantined=sum(s.quarantined for s in stats), quarantine_reasons=dict(quarantine_reasons),
                         dnsmasq_stats=dstats, pseudonym_key_fingerprint=pseudonymizer.key_fingerprint)


def _with_class(records: Iterable[dict[str, Any]], cfg: HomeLabConfig) -> Iterator[dict[str, Any]]:
    for r in records:
        if cfg.device_class and not r.get("_error") and r.get("device_class") is None:
            r["device_class"] = cfg.device_class
        yield r


def _conn_filter(records: Iterable[dict[str, Any]], cfg: HomeLabConfig, pseudo: Pseudonymizer,
                 counts: Counter[str], chatter: dict[str, LocalChatter]) -> Iterator[dict[str, Any]]:
    for r in _with_class(records, cfg):
        if r.get("_error"):
            yield r                                   # quarantined by the pipeline with its bytes
            continue
        src, dst = r.get("src_ip"), r.get("dst_ip")
        if cfg.is_lab_client(src) and cfg.is_local_destination(dst) and not cfg.include_local:
            counts["local_chatter_flows"] += 1
            dev = pseudo.pseudonym(str(src))
            lc = chatter.setdefault(dev, LocalChatter())
            lc.flows += 1
            try:
                if ipaddress.ip_address(str(dst)).is_multicast:
                    lc.multicast_flows += 1
            except ValueError:
                pass
            lc.destinations.add(pseudo.pseudonym(str(dst)))
            port = r.get("dst_port")
            if port is not None and str(port).isdigit():
                lc.ports[int(port)] += 1
            continue
        if src is not None and not cfg.is_lab_client(src) and cfg.is_lab_client(dst):
            # inbound leg seen from the remote side; the pipeline would skip it too, count it explicitly
            counts["inbound_to_lab_client"] += 1
        yield r


def _dns_filter(records: Iterable[dict[str, Any]], cfg: HomeLabConfig, counts: Counter[str]
                ) -> Iterator[dict[str, Any]]:
    for r in _with_class(records, cfg):
        if r.get("_error"):
            yield r
            continue
        if not cfg.is_lab_client(r.get("src_ip")):
            counts["dns_not_from_lab_client"] += 1
            continue
        yield r


def _device_labels(events: list[ObservationEvent], cfg: HomeLabConfig, pseudo: Pseudonymizer) -> dict[str, str]:
    known = {pseudo.pseudonym(ip): label for ip, label in cfg.device_labels.items()}
    out: dict[str, str] = {}
    n = 0
    for e in events:
        p = e.entity_pseudonym
        if p is None or p in out:
            continue
        if p in known:
            out[p] = known[p]
        else:
            n += 1
            out[p] = f"lab device {n}"
    return out


__all__ = ["CaptureError", "CaptureImport", "CaptureManifest", "CapturePaths", "InputFile", "LocalChatter",
           "discover_capture", "file_sha256", "import_capture"]
