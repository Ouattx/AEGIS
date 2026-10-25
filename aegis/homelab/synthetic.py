"""Synthetic home-lab captures (demo, documentation and tests). SYNTHETIC DATA ONLY.

Writes the same files the real capture scripts produce (``capture.json``, Zeek
``conn.log`` / ``dns.log`` in TSV format, a dnsmasq ``log-queries=extra`` log and a
``usage.json``) for one fictional streaming box, so the whole pipeline can be exercised
without any real device. The manifest carries ``"synthetic": true`` and every report
built from it shows a synthetic banner.

The fictional box has benign timers that keep running while idle (NTP, a connectivity
check, a push keepalive reconnect), viewing-session traffic (CDN streams, API calls, a
player heartbeat that runs only while watching) and lab-local chatter (SSDP, DNS to the
access point). Optionally it also runs an emulated C2 beacon (a fixed-period check-in
to a dedicated host, around the clock) and an NXDOMAIN burst.

Only reserved names (``.example`` / ``.test``) and documentation address ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are used.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aegis.homelab.usage import UsageWindows

_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
                "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
                "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"]
_CONN_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "count", "count",
               "string", "bool", "bool", "count", "string", "count", "count", "count", "count", "set[string]"]
_DNS_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "rtt", "query",
               "qclass", "qclass_name", "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z",
               "answers", "TTLs", "rejected"]
_DNS_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "count", "interval", "string", "count",
              "string", "count", "string", "count", "string", "bool", "bool", "bool", "bool", "count",
              "vector[string]", "vector[interval]", "bool"]
_MON = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

#: fictional services of the synthetic box: name -> address (documentation ranges)
HOSTS = {
    "time.vendor-ntp.example": "203.0.113.123",
    "connectivity.platform-check.example": "203.0.113.20",
    "push.platform-services.example": "203.0.113.30",
    "api.streaming-service.example": "192.0.2.40",
    "hb.streaming-service.example": "192.0.2.41",
    "cdn-edge.streaming-service.example": "192.0.2.50",
    "updates.store-platform.example": "203.0.113.60",
}


@dataclass(frozen=True)
class SyntheticBoxSpec:
    start: datetime
    hours: float = 24.0
    seed: int = 7
    device_ip: str = "10.42.0.23"
    gateway_ip: str = "10.42.0.1"
    beacon: bool = True
    beacon_period_s: float = 600.0
    beacon_jitter: float = 0.10
    beacon_domain: str = "sync.tvbox-telemetry.test"
    beacon_ip: str = "198.51.100.77"
    nxdomain_burst: bool = False
    #: viewing sessions as (offset hours from start, duration hours)
    sessions: tuple[tuple[float, float], ...] = ((1.0, 1.5), (9.0, 2.5), (20.0, 1.0))

    def __post_init__(self) -> None:
        if self.start.tzinfo is None:
            raise ValueError("start must be timezone-aware")
        if self.hours <= 0:
            raise ValueError("hours must be positive")


@dataclass
class SyntheticCapture:
    directory: Path
    spec: SyntheticBoxSpec
    usage: UsageWindows
    truth: dict[str, Any] = field(default_factory=dict)


class _Writer:
    def __init__(self, spec: SyntheticBoxSpec):
        self.spec = spec
        self.rng = random.Random(spec.seed)
        self.conn: list[tuple[float, list[str]]] = []
        self.dns: list[tuple[float, list[str]]] = []
        self.dnsmasq: list[tuple[float, int, list[str]]] = []
        self.cache: dict[str, float] = {}
        self.serial = 0
        self.uid_n = 0

    def uid(self, prefix: str) -> str:
        self.uid_n += 1
        return f"{prefix}{self.spec.seed:02d}{self.uid_n:08d}"

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    # ------------------------------------------------------------------ records
    def lookup(self, t: float, name: str, ip: str | None, ttl: float = 300.0, *, force: bool = False,
               rcode: str = "NOERROR") -> None:
        """Resolver query unless cached (dnsmasq log + Zeek dns.log)."""
        exp = self.cache.get(name)
        if not force and exp is not None and t < exp:
            return
        self.cache[name] = t + ttl
        sp = self.spec
        cport = self.port()
        self.serial += 1
        s = self.serial
        client = f"{sp.device_ip}/{cport}"
        msgs = [f"{s} {client} query[A] {name} from {sp.device_ip}",
                f"{s} {client} forwarded {name} to 192.0.2.53"]
        if rcode == "NXDOMAIN":
            msgs.append(f"{s} {client} reply {name} is NXDOMAIN")
        elif ip is not None:
            msgs.append(f"{s} {client} reply {name} is {ip}")
        for k, m in enumerate(msgs):
            self.dnsmasq.append((t + 0.001 * k, s, [m]))
        answers = ip if (ip is not None and rcode == "NOERROR") else "-"
        ttls = f"{ttl:.6f}" if answers != "-" else "-"
        rc = 3 if rcode == "NXDOMAIN" else 0
        self.dns.append((t, [f"{t:.6f}", self.uid("D"), sp.device_ip, str(cport), sp.gateway_ip, "53", "udp",
                             str(self.rng.randint(1, 65535)), "0.012000", name, "1", "C_INTERNET", "1", "A", str(rc),
                             rcode, "F", "F", "T", "T", "0", answers, ttls, "F"]))

    def flow(self, t: float, ip: str, port: int, proto: str, dur: float, ob: int, rb: int,
             service: str = "-") -> None:
        sp = self.spec
        op = max(1, ob // 600 + 2)
        rp = max(1, rb // 1200 + 2)
        self.conn.append((t, [f"{t:.6f}", self.uid("C"), sp.device_ip, str(self.port()), ip, str(port), proto,
                              service, f"{dur:.6f}", str(ob), str(rb), "SF", "T", "F", "0",
                              "ShADadFf" if proto == "tcp" else "Dd", str(op), str(ob + 40 * op), str(rp),
                              str(rb + 40 * rp), "(empty)"]))

    def local(self, t: float, ip: str, port: int) -> None:
        self.flow(t, ip, port, "udp", 0.0, 300, 0)


def _periodic(rng: random.Random, t0: float, t1: float, period: float, jitter: float) -> list[float]:
    out: list[float] = []
    t = t0 + rng.uniform(0, period)
    while t < t1:
        out.append(t)
        t += period * (1.0 + rng.uniform(-jitter, jitter))
    return out


def _poisson(rng: random.Random, t0: float, t1: float, per_hour: float) -> list[float]:
    out: list[float] = []
    if per_hour <= 0:
        return out
    t = t0 + rng.expovariate(per_hour / 3600.0)
    while t < t1:
        out.append(t)
        t += rng.expovariate(per_hour / 3600.0)
    return out


def _syslog(t: float) -> str:
    d = datetime.fromtimestamp(t, timezone.utc)
    return f"{_MON[d.month - 1]} {d.day:2d} {d:%H:%M:%S}"


def _zeek(path: Path, kind: str, fields: list[str], types: list[str], rows: list[list[str]], t0: float,
          t1: float) -> None:
    head = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", f"#path\t{kind}",
            f"#open\t{datetime.fromtimestamp(t0, timezone.utc):%Y-%m-%d-%H-%M-%S}",
            "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types)]
    tail = [f"#close\t{datetime.fromtimestamp(t1, timezone.utc):%Y-%m-%d-%H-%M-%S}"]
    path.write_text("\n".join(head + ["\t".join(r) for r in rows] + tail) + "\n", encoding="utf-8")


def write_synthetic_capture(directory: str | Path, spec: SyntheticBoxSpec) -> SyntheticCapture:
    """Write a synthetic capture directory and return its ground truth."""
    out = Path(directory)
    (out / "zeek").mkdir(parents=True, exist_ok=True)
    w = _Writer(spec)
    rng = w.rng
    t0 = spec.start.timestamp()
    t1 = t0 + spec.hours * 3600.0
    sessions = [(t0 + a * 3600.0, min(t1, t0 + (a + d) * 3600.0)) for a, d in spec.sessions if t0 + a * 3600.0 < t1]

    # ---------------------------------------------------------------- benign, around the clock
    for t in _periodic(rng, t0, t1, 1024.0, 0.02):
        w.lookup(t - 0.05, "time.vendor-ntp.example", HOSTS["time.vendor-ntp.example"], ttl=3600)
        w.flow(t, HOSTS["time.vendor-ntp.example"], 123, "udp", 0.03, 48, 48, "ntp")
    for t in _periodic(rng, t0, t1, 900.0, 0.01):
        w.lookup(t - 0.05, "connectivity.platform-check.example", HOSTS["connectivity.platform-check.example"])
        w.flow(t, HOSTS["connectivity.platform-check.example"], 80, "tcp", 0.2, 320, 210, "http")
    for t in _periodic(rng, t0, t1, 1680.0, 0.05):
        w.lookup(t - 0.05, "push.platform-services.example", HOSTS["push.platform-services.example"], ttl=1800)
        w.flow(t, HOSTS["push.platform-services.example"], 443, "tcp", 1600.0, 4200, 3900, "ssl")
    for t in _poisson(rng, t0, t1, 1 / 3):
        w.lookup(t - 0.05, "updates.store-platform.example", HOSTS["updates.store-platform.example"])
        w.flow(t, HOSTS["updates.store-platform.example"], 443, "tcp", 3.0, 2400, 48_000, "ssl")
    for t in _periodic(rng, t0, t1, 300.0, 0.05):
        w.local(t, "239.255.255.250", 1900)                       # SSDP discovery (lab-local chatter)

    # ---------------------------------------------------------------- viewing sessions only
    for s, e in sessions:
        for t in _periodic(rng, s, e, 60.0, 0.03):
            w.lookup(t - 0.05, "hb.streaming-service.example", HOSTS["hb.streaming-service.example"])
            w.flow(t, HOSTS["hb.streaming-service.example"], 443, "tcp", 0.4, 600, 400, "ssl")
        for t in _poisson(rng, s, e, 30):
            w.lookup(t - 0.05, "api.streaming-service.example", HOSTS["api.streaming-service.example"])
            w.flow(t, HOSTS["api.streaming-service.example"], 443, "tcp", 1.5, 1800, 22_000, "ssl")
        t = s + 5.0
        while t < e:
            dur = min(300.0, e - t)
            w.lookup(t - 0.05, "cdn-edge.streaming-service.example", HOSTS["cdn-edge.streaming-service.example"])
            w.flow(t, HOSTS["cdn-edge.streaming-service.example"], 443, "tcp", dur, 90_000,
                   int(dur * rng.uniform(450_000, 650_000)), "ssl")
            t += dur + 0.5

    # ---------------------------------------------------------------- emulated threats (optional)
    beacon_times: list[float] = []
    if spec.beacon:
        beacon_times = _periodic(rng, t0, t1, spec.beacon_period_s, spec.beacon_jitter)
        for t in beacon_times:
            w.lookup(t - 0.05, spec.beacon_domain, spec.beacon_ip, ttl=3600)
            w.flow(t, spec.beacon_ip, 443, "tcp", 0.6, rng.randint(600, 1400), rng.randint(300, 900), "ssl")
    nx_names: list[str] = []
    if spec.nxdomain_burst:
        tb = t0 + 0.6 * (t1 - t0)
        for i in range(60):
            name = "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(12)) + ".test"
            nx_names.append(name)
            w.lookup(tb + 2.0 * i, name, None, rcode="NXDOMAIN", force=True)

    # DNS to the access point itself appears in the capture as lab-local flows
    for t, _ in list(w.dns):
        w.local(t, spec.gateway_ip, 53)

    w.conn.sort(key=lambda x: x[0])
    w.dns.sort(key=lambda x: x[0])
    w.dnsmasq.sort(key=lambda x: (x[0], x[1]))
    _zeek(out / "zeek" / "conn.log", "conn", _CONN_FIELDS, _CONN_TYPES, [r for _, r in w.conn], t0, t1)
    _zeek(out / "zeek" / "dns.log", "dns", _DNS_FIELDS, _DNS_TYPES, [r for _, r in w.dns], t0, t1)
    (out / "dnsmasq.log").write_text(
        "".join(f"{_syslog(t)} dnsmasq[812]: {m[0]}\n" for t, _, m in w.dnsmasq), encoding="utf-8")
    manifest = {"capture_id": f"synthetic-{spec.seed}-{spec.start:%Y%m%dT%H%M}",
                "started_at": spec.start.astimezone(timezone.utc).isoformat(),
                "ended_at": (spec.start + timedelta(hours=spec.hours)).astimezone(timezone.utc).isoformat(),
                "interface": "wlan0", "snaplen": 96, "synthetic": True, "tool": "aegis.homelab.synthetic",
                "notes": "SYNTHETIC capture of a fictional streaming box (no real device)."}
    (out / "capture.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    usage = UsageWindows(active=tuple(sessions))
    (out / "usage.json").write_text(json.dumps({"active": usage.to_dict()["active"]}, indent=2) + "\n",
                                    encoding="utf-8")
    truth = {"beacon": spec.beacon, "beacon_domain": spec.beacon_domain if spec.beacon else None,
             "beacon_ip": spec.beacon_ip if spec.beacon else None, "beacon_period_s": spec.beacon_period_s,
             "beacon_events": len(beacon_times), "nxdomain_names": nx_names,
             "idle_benign_timers": ["time.vendor-ntp.example", "connectivity.platform-check.example",
                                    "push.platform-services.example"],
             "active_only_timers": ["hb.streaming-service.example"]}
    return SyntheticCapture(directory=out, spec=spec, usage=usage, truth=truth)


__all__ = ["HOSTS", "SyntheticBoxSpec", "SyntheticCapture", "write_synthetic_capture"]
