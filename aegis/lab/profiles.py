"""Behavior emulation for lab devices: benign household profiles and malicious overlays.

Each simulated device owns a :class:`DeviceSim` that accumulates flow and DNS
records (epoch-second timestamps). Flows are exported the way a real NetFlow /
IPFIX exporter would: long-lived connections produce one record per 60 s active
timeout, short connections one record each.

Benign profiles deliberately include behaviors that naive detectors mistake for
abuse: 24/7 always-on IPTV boxes with dozens of destinations and heartbeat
traffic, smart-TV ACR telemetry, phone push keepalives, browser random-label
NXDOMAIN probes, night-time firmware downloads and sustained camera uploads.
Malicious overlays emulate published behaviors of TV-box botnets (BadBox 2.0
style C2 + residential proxy, Vo1d style DGA) and Mirai-style DDoS bots.
"""
from __future__ import annotations

import math
import random
import string
from dataclasses import dataclass, field
from typing import Callable, Sequence

from aegis.lab.topology import RESOLVER_IP, Endpoint, HostingTopology, dga_domains

DAY = 86_400.0
ACTIVE_TIMEOUT = 60.0

PROTO_TCP = 6
PROTO_UDP = 17

# record tuples (kept compact for speed):
#   flow: (t, 0, dst_ip, dst_port, proto, bytes_out, bytes_in, pkts_out, pkts_in, duration_ms, src_port)
#   dns:  (t, 1, qname, qtype, rcode, answers_tuple)
Record = tuple

BENIGN_PROFILES: dict[str, str] = {
    "android_tv_iptv": "android_tv",
    "iptv_busy_box": "android_tv",
    "smart_tv": "smart_tv",
    "console": "console",
    "phone": "phone",
    "laptop": "laptop",
    "laptop_vpn": "laptop",
    "iot_camera": "camera",
}

PROFILE_WEIGHTS: dict[str, float] = {
    "android_tv_iptv": 0.22, "iptv_busy_box": 0.06, "smart_tv": 0.17, "console": 0.09,
    "phone": 0.22, "laptop": 0.10, "laptop_vpn": 0.07, "iot_camera": 0.07,
}

MALICIOUS_BEHAVIORS: dict[str, str] = {        # label -> emulated family
    "c2_beaconing": "badbox2_emu",
    "residential_proxy": "badbox2_emu",
    "dga_activity": "vo1d_emu",
    "ddos_bot": "mirai_emu",
}


@dataclass
class DeviceSim:
    rng: random.Random
    topo: HostingTopology
    window_start: float
    window_end: float
    records: list[Record] = field(default_factory=list)
    _dns_cache: dict[str, float] = field(default_factory=dict)
    _ports: int = 0

    # ------------------------------------------------------------------ primitives
    def _in_window(self, t: float) -> bool:
        return self.window_start <= t < self.window_end

    def src_port(self) -> int:
        self._ports += 1
        return 32768 + (self._ports * 7919 + self.rng.randrange(97)) % 28000

    def flow(self, t: float, ip: str, port: int, proto: int, bytes_out: int | None, bytes_in: int | None,
             duration_ms: int | None, pkts_out: int | None = None, pkts_in: int | None = None,
             src_port: int | None = None) -> None:
        if not self._in_window(t):
            return
        if pkts_out is None and bytes_out is not None:
            pkts_out = max(1, bytes_out // self.rng.randint(500, 1400))
        if pkts_in is None and bytes_in is not None:
            pkts_in = max(0 if bytes_in == 0 else 1, bytes_in // self.rng.randint(900, 1450))
        self.records.append((t, 0, ip, port, proto, bytes_out, bytes_in, pkts_out, pkts_in, duration_ms,
                             src_port if src_port is not None else self.src_port()))

    def dns(self, t: float, qname: str, rcode: str = "NOERROR", answers: tuple[str, ...] | None = None,
            qtype: str = "A") -> None:
        if not self._in_window(t):
            return
        if answers is None:
            answers = tuple(self.topo.resolve(qname)) if rcode == "NOERROR" else ()
        self.records.append((t, 1, qname, qtype, rcode, answers))

    def lookup(self, t: float, hostname: str, ttl: float = 300.0) -> None:
        """Resolve unless a cached answer is still valid (models stub-resolver caching)."""
        last = self._dns_cache.get(hostname)
        if last is None or t - last >= ttl:
            self._dns_cache[hostname] = t
            self.dns(t, hostname)

    def connect(self, t: float, ep: Endpoint, bytes_out: int, bytes_in: int, duration_ms: int,
                ttl: float = 300.0) -> None:
        self.lookup(t - self.rng.uniform(0.005, 0.08), ep.hostname, ttl)
        self.flow(t, ep.ip, ep.port, PROTO_UDP if ep.protocol == "udp" else PROTO_TCP,
                  bytes_out, bytes_in, duration_ms)

    def long_flow(self, t0: float, t1: float, ep: Endpoint, in_bps: float, out_bps: float,
                  ttl: float = 300.0, resolve: bool = True) -> None:
        """One long-lived connection exported every ACTIVE_TIMEOUT seconds."""
        if t1 <= t0:
            return
        if resolve:
            self.lookup(t0 - self.rng.uniform(0.005, 0.08), ep.hostname, ttl)
        proto = PROTO_UDP if ep.protocol == "udp" else PROTO_TCP
        sport = self.src_port()
        t = t0
        r = self.rng
        while t < t1:
            span = min(ACTIVE_TIMEOUT, t1 - t)
            if t >= self.window_end:
                break
            if t >= self.window_start:
                bi = int(in_bps / 8 * span * r.uniform(0.8, 1.2))
                bo = int(out_bps / 8 * span * r.uniform(0.8, 1.2))
                self.flow(t, ep.ip, ep.port, proto, bo, bi, int(span * 1000), src_port=sport)
            t += span

    # ------------------------------------------------------------------ scheduling helpers
    def sessions(self, day0: float, spec: Sequence[tuple[float, float, float, float, float]]) -> list[tuple[float, float]]:
        """Activity sessions for a day. ``spec`` rows: (probability, start_h_lo, start_h_hi,
        min_len_h, max_len_h)."""
        out = []
        for p, lo, hi, mn, mx in spec:
            if self.rng.random() < p:
                s = day0 + self.rng.uniform(lo, hi) * 3600
                out.append((s, s + self.rng.uniform(mn, mx) * 3600))
        out.sort()
        merged: list[tuple[float, float]] = []
        for s, e in out:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(e, merged[-1][1]))
            else:
                merged.append((s, e))
        return merged

    def periodic(self, t0: float, t1: float, period: float, jitter: float,
                 fn: Callable[[float], None]) -> None:
        t = t0 + self.rng.uniform(0, period)
        while t < t1:
            fn(t)
            t += period * (1.0 + self.rng.uniform(-jitter, jitter))

    def poisson_times(self, t0: float, t1: float, rate_per_h: float) -> list[float]:
        out: list[float] = []
        if rate_per_h <= 0:
            return out
        t = t0
        while True:
            t += self.rng.expovariate(rate_per_h / 3600.0)
            if t >= t1:
                return out
            out.append(t)

    def pick(self, service: str) -> Endpoint:
        eps = self.topo.services[service]
        return eps[self.rng.randrange(len(eps))]


# ---------------------------------------------------------------------------- benign profiles

def _weekend(day0: float) -> bool:
    return int(day0 // DAY + 4) % 7 in (5, 6)  # 1970-01-01 was a Thursday


def _background_os(sim: DeviceSim, day0: float, on: list[tuple[float, float]], vendor: str | None) -> None:
    r = sim.rng
    for s, _end in on:
        conn = sim.topo.services.get(f"{vendor}_connectivity") if vendor else None
        ep = conn[0] if conn else sim.pick("connectivity")
        sim.connect(s + r.uniform(1, 5), ep, r.randint(300, 600), r.randint(200, 500), r.randint(20, 120))
    for _ in range(r.randint(2, 6)):
        sim.connect(day0 + r.uniform(0, DAY), sim.pick("ntp"), 76, 76, r.randint(10, 60))
    sim.connect(day0 + r.uniform(0, DAY), sim.pick("os_telemetry"), r.randint(4_000, 60_000),
                r.randint(1_000, 8_000), r.randint(300, 4_000))


def _iptv_session(sim: DeviceSim, s: float, e: float, switch_min: tuple[float, float],
                  kbps: tuple[float, float], heartbeat_s: float, parallel: int = 1) -> None:
    r = sim.rng
    mw = sim.topo.services["iptv_middleware"]
    sim.connect(s, mw[0], r.randint(1_500, 4_000), r.randint(8_000, 30_000), r.randint(200, 900))     # login
    sim.connect(s + 2, mw[2], r.randint(1_000, 3_000), r.randint(2_000, 9_000), r.randint(100, 600))  # DRM
    sim.connect(s + 4, mw[1], r.randint(2_000, 5_000), r.randint(800_000, 5_000_000),
                r.randint(2_000, 15_000))                                                         # EPG
    sim.periodic(s + 10, e, heartbeat_s, 0.03,
                 lambda t: sim.connect(t, mw[0], r.randint(400, 900), r.randint(600, 2_000),
                                       r.randint(40, 300), ttl=3600))
    for stream in range(parallel):
        t = s + 6 + stream * r.uniform(30, 300)
        while t < e:
            dwell = r.uniform(*switch_min) * 60
            ch = sim.pick("iptv_origins")
            sim.long_flow(t, min(t + dwell, e), ch, r.uniform(*kbps) * 1000, r.uniform(20, 60) * 1000, ttl=60)
            t += dwell + r.uniform(0.5, 3)
    if r.random() < 0.5:  # refresh EPG periodically on long sessions
        sim.periodic(s + 1800, e, 1800, 0.1,
                     lambda t: sim.connect(t, mw[1], r.randint(1_000, 3_000), r.randint(200_000, 1_500_000),
                                           r.randint(800, 6_000), ttl=3600))


def android_tv_iptv(sim: DeviceSim, day0: float) -> None:
    """Android TV box with a licensed IPTV app plus VOD apps."""
    wk = _weekend(day0)
    on = sim.sessions(day0, [(0.25, 6.5, 8.0, 0.3, 1.0), (0.4 if wk else 0.1, 10, 15, 1, 3),
                             (0.85, 18, 21, 1.5, 4.5)])
    _background_os(sim, day0, on, None)
    r = sim.rng
    for s, e in on:
        if r.random() < 0.7:
            _iptv_session(sim, s, e, (5, 40), (3_000, 8_000), 300)
        else:
            sim.long_flow(s, e, sim.pick("video_cdn"), r.uniform(3_000, 12_000) * 1000, 40_000)
    # standby: app-store update checks a few times a day
    for t in sim.poisson_times(day0, day0 + DAY, 0.25):
        sim.connect(t, sim.pick("appstore"), r.randint(2_000, 6_000), r.randint(5_000, 60_000), r.randint(300, 2_000))


def iptv_busy_box(sim: DeviceSim, day0: float, always_on: bool, parallel: int) -> None:
    """Hard negative: legitimate, very busy IPTV box (multi-room, frequent zapping,
    often left on 24/7). Many destinations, high volume, periodic heartbeats."""
    r = sim.rng
    if always_on:
        on = [(day0, day0 + DAY)]
    else:
        on = sim.sessions(day0, [(0.9, 6, 9, 2, 5), (0.9, 11, 14, 2, 5), (0.95, 16, 19, 4, 7)])
    _background_os(sim, day0, on[:1] if always_on else on, None)
    for s, e in on:
        _iptv_session(sim, s, e, (2, 12), (4_000, 9_000), 120, parallel=parallel)
        if r.random() < 0.6:
            vs = s + r.uniform(0, max(1.0, e - s - 3600))
            sim.long_flow(vs, min(e, vs + r.uniform(1800, 7200)), sim.pick("video_cdn"),
                          r.uniform(5_000, 15_000) * 1000, 50_000)


def smart_tv(sim: DeviceSim, day0: float, vendor: str) -> None:
    r = sim.rng
    on = sim.sessions(day0, [(0.2, 7, 8.5, 0.3, 1), (0.35 if _weekend(day0) else 0.1, 11, 16, 1, 3),
                             (0.85, 18.5, 21.5, 1.5, 4)])
    _background_os(sim, day0, on, vendor)
    acr = sim.topo.services[f"{vendor}_acr"][0]
    api = sim.topo.services[f"{vendor}_api"][0]
    for s, e in on:
        sim.long_flow(s + 5, e, sim.pick("video_cdn"), r.uniform(4_000, 15_000) * 1000, 30_000)
        sim.long_flow(s + 2, e, acr, r.uniform(0.3, 0.8) * 1000, r.uniform(1.5, 4) * 1000, ttl=3600)  # ACR
    sim.periodic(day0, day0 + DAY, 7200, 0.25,
                 lambda t: sim.connect(t, api, r.randint(800, 2_000), r.randint(2_000, 20_000),
                                       r.randint(100, 800), ttl=3600))


def console(sim: DeviceSim, day0: float) -> None:
    r = sim.rng
    on = sim.sessions(day0, [(0.6 if _weekend(day0) else 0.15, 12, 16, 1, 4), (0.7, 18, 22, 1, 3.5)])
    _background_os(sim, day0, on, None)
    pres = sim.topo.services["game_presence"][0]
    for s, e in on:
        sim.periodic(s, e, 120, 0.1, lambda t: sim.connect(t, pres, r.randint(300, 800), r.randint(300, 900),
                                                            r.randint(50, 300), ttl=3600))
        t = s + 60
        while t < e:
            match_len = r.uniform(8, 35) * 60
            ep = sim.pick("game_servers")
            mt1 = min(t + match_len, e)
            mt = t
            sport = sim.src_port()
            while mt < mt1:
                span = min(ACTIVE_TIMEOUT, mt1 - mt)
                pk = int(span * r.uniform(30, 60))
                sim.flow(mt, ep.ip, ep.port, PROTO_UDP, pk * r.randint(80, 140), pk * r.randint(110, 220),
                         int(span * 1000), pk, pk, src_port=sport)
                mt += span
            t = mt1 + r.uniform(30, 240)
    if r.random() < 0.12:  # game patch download
        s = day0 + r.uniform(0, DAY)
        sim.long_flow(s, s + r.uniform(600, 3600), sim.pick("game_cdn"), r.uniform(50, 200) * 1e6, 400_000)


def phone(sim: DeviceSim, day0: float) -> None:
    r = sim.rng
    away = (not _weekend(day0)) and r.random() < 0.7
    home = [(day0, day0 + 8 * 3600), (day0 + 18 * 3600, day0 + DAY)] if away else [(day0, day0 + DAY)]
    push = sim.topo.services["push"][0]
    sessions = sim.sessions(day0, [(0.6, 7, 8.5, 0.3, 1), (0.9, 18.5, 23, 1, 3)])
    active = [(max(s, hs), min(e, he)) for s, e in sessions for hs, he in home if min(e, he) > max(s, hs)]
    for hs, he in home:
        sim.periodic(hs, he, 28 * 60, 0.05,
                     lambda t: sim.connect(t, push, r.randint(100, 300), r.randint(100, 400), r.randint(20, 200),
                                           ttl=3600))
    for s, e in active:
        for t in sim.poisson_times(s, e, r.uniform(25, 70)):
            ep = sim.pick("web")
            sim.connect(t, ep, r.randint(800, 6_000), r.randint(5_000, 400_000), r.randint(100, 5_000))
        if r.random() < 0.4:
            vs = s + r.uniform(0, max(1.0, e - s - 600))
            sim.long_flow(vs, min(e, vs + r.uniform(300, 2400)), sim.pick("video_cdn"),
                          r.uniform(1_500, 4_000) * 1000, 20_000)
    _background_os(sim, day0, active[:1], None)


def _browser_probes(sim: DeviceSim, t: float) -> None:
    """Chromium's intranet-redirect detector: 3 random single-label queries at startup."""
    r = sim.rng
    for k in range(3):
        label = "".join(r.choice(string.ascii_lowercase) for _ in range(r.randint(7, 15)))
        sim.dns(t + k * 0.01, label, rcode="NXDOMAIN")


def laptop(sim: DeviceSim, day0: float, vpn: bool) -> None:
    r = sim.rng
    work = not _weekend(day0) and r.random() < 0.85
    spec = [(0.9, 18.5, 20.5, 1.5, 4), (0.5 if _weekend(day0) else 0.15, 10, 14, 1, 4)]
    if work:
        spec.append((1.0, 8.5, 9.5, 7.5, 9))
    on = sim.sessions(day0, spec)
    _background_os(sim, day0, on, None)
    for s, e in on:
        _browser_probes(sim, s + r.uniform(5, 30))
        if vpn and work and s < day0 + 10 * 3600:
            gw = sim.pick("vpn")
            sim.long_flow(s + 40, e, gw, r.uniform(300, 2_000) * 1000, r.uniform(100, 800) * 1000)
            continue
        for t in sim.poisson_times(s, e, r.uniform(20, 60)):
            sim.connect(t, sim.pick("web"), r.randint(1_000, 12_000), r.randint(10_000, 900_000),
                        r.randint(100, 8_000))
        if r.random() < 0.15:  # typo / stale bookmark
            sim.dns(s + r.uniform(0, e - s), f"www.{r.choice(['gooogle', 'exmaple', 'yotube'])}.example",
                    rcode="NXDOMAIN")
        if r.random() < 0.5:
            vs = s + r.uniform(0, max(1.0, e - s - 600))
            sim.long_flow(vs, min(e, vs + r.uniform(900, 5400)), sim.pick("video_cdn"),
                          r.uniform(3_000, 8_000) * 1000, 30_000)


def iot_camera(sim: DeviceSim, day0: float) -> None:
    """Cloud camera: sustained 24/7 upload (benign sustained egress)."""
    r = sim.rng
    cams = sim.topo.services["cam_cloud"]
    ep = cams[r.randrange(len(cams))]
    sim.long_flow(day0, day0 + DAY, ep, r.uniform(20, 60) * 1000, r.uniform(400, 1_500) * 1000, ttl=3600)
    _background_os(sim, day0, [], None)


def firmware_update(sim: DeviceSim, day0: float, vendor_hint: str | None) -> None:
    """Night-time firmware download burst from a vendor CDN (benign)."""
    r = sim.rng
    fw_eps = sim.topo.services["firmware"]
    ep = fw_eps[0] if vendor_hint == "tvvendor-a" else fw_eps[-1] if vendor_hint == "tvvendor-b" else fw_eps[
        r.randrange(len(fw_eps))]
    s = day0 + r.uniform(1.5, 5.0) * 3600
    sim.long_flow(s, s + r.uniform(300, 1500), ep, r.uniform(20, 80) * 1e6, r.uniform(100, 400) * 1000, ttl=3600)


# ---------------------------------------------------------------------------- malicious overlays

@dataclass
class C2Choice:
    domain: str
    ip: str
    port: int
    protocol: int


def c2_beaconing(sim: DeviceSim, t0: float, t1: float, c2: C2Choice, period: float, jitter: float,
                 dns_ttl: float) -> None:
    """Periodic small check-ins 24/7, occasional tasking downloads (BadBox/Vo1d style)."""
    r = sim.rng

    def beacon(t: float) -> None:
        sim.lookup(t - r.uniform(0.005, 0.05), c2.domain, dns_ttl)
        sim.flow(t, c2.ip, c2.port, c2.protocol, r.randint(300, 900), r.randint(200, 1_500), r.randint(150, 2_000))

    sim.periodic(t0, t1, period, jitter, beacon)
    for t in sim.poisson_times(t0, t1, 1 / 6.0):
        sim.flow(t + 1, c2.ip, c2.port, c2.protocol, r.randint(1_000, 4_000), r.randint(50_000, 600_000),
                 r.randint(2_000, 20_000))


def residential_proxy(sim: DeviceSim, t0: float, t1: float, controller: Endpoint, rate_per_h: float) -> None:
    """Backconnect proxy: persistent control channel + relayed sessions to many third parties.

    Relayed bytes flow back upstream to the controller, producing unexpected sustained
    egress at all hours.
    """
    r = sim.rng
    sim.long_flow(t0, t1, controller, r.uniform(2, 6) * 1000, r.uniform(1, 3) * 1000, ttl=3600)
    up_bytes = 0.0
    last_flush = t0
    for t in sim.poisson_times(t0, t1, rate_per_h * r.uniform(0.6, 1.4)):
        ep = sim.pick("web")
        bi = r.randint(5_000, 500_000)
        sim.connect(t, ep, r.randint(600, 4_000), bi, r.randint(200, 6_000), ttl=60)
        up_bytes += bi
        if t - last_flush >= ACTIVE_TIMEOUT:
            sim.flow(t + 0.5, controller.ip, controller.port, PROTO_TCP, int(up_bytes * r.uniform(1.02, 1.08)),
                     int(up_bytes * 0.02), int((t - last_flush) * 1000))
            up_bytes = 0.0
            last_flush = t


def dga_activity(sim: DeviceSim, t0: float, t1: float, seed: int, sink_ip: str, port: int) -> None:
    """Vo1d-style DGA: bursts of NXDOMAIN lookups; registered names lead to C2 contact."""
    r = sim.rng
    day = int(t0 // DAY)
    while day * DAY < t1:
        names = dga_domains(seed, day, 300)
        registered = set(names[:3])
        d0, d1 = max(t0, day * DAY), min(t1, (day + 1) * DAY)
        for b in sim.poisson_times(d0, d1, r.uniform(0.3, 0.8)):
            t = b
            for name in r.sample(names, r.randint(20, 80)):
                t += r.uniform(0.2, 2.0)
                if name in registered:
                    sim.dns(t, name, answers=(sink_ip,))
                    sim.flow(t + 0.05, sink_ip, port, PROTO_TCP, r.randint(300, 900), r.randint(300, 2_000),
                             r.randint(200, 2_000))
                else:
                    sim.dns(t, name, rcode="NXDOMAIN")
        day += 1


def ddos_bot(sim: DeviceSim, t0: float, t1: float, cnc: C2Choice) -> None:
    """Mirai-style: persistent C2 channel, telnet scanning, short flood bursts."""
    r = sim.rng
    sim.lookup(t0, cnc.domain, 3600)
    sim.long_flow(t0, t1, Endpoint(cnc.domain, cnc.ip, cnc.port), 120, 160, ttl=3600, resolve=False)
    for t in sim.poisson_times(t0, t1, r.uniform(20, 60)):  # scanning random hosts on 23/2323
        a, b = r.randrange(256), r.randrange(1, 255)
        sim.flow(t, f"198.19.{a}.{b}", r.choice((23, 23, 2323)), PROTO_TCP, 60, 0, 0, 1, 0)
    day = int(t0 // DAY)
    victims = sim.topo.services["ddos_victims"]
    while day * DAY < t1:
        d0, d1 = max(t0, day * DAY), min(t1, (day + 1) * DAY)
        for _ in range(r.randint(1, 3)):
            s = r.uniform(d0, d1)
            v = victims[r.randrange(len(victims))]
            udp = r.random() < 0.6
            dur = r.uniform(120, 900)
            t = s
            while t < min(s + dur, d1):
                span = min(ACTIVE_TIMEOUT, s + dur - t)
                pk = int(span * r.uniform(800, 6_000))
                size = r.randint(512, 1_400) if udp else 60
                sim.flow(t, v.ip, r.randrange(1024, 65535) if udp else 80, PROTO_UDP if udp else PROTO_TCP,
                         pk * size, 0, int(span * 1000), pk, 0)
                t += span
        day += 1


def lognormal_period(rng: random.Random) -> float:
    base = rng.choice((60.0, 120.0, 300.0, 600.0, 900.0))
    return base * math.exp(rng.uniform(-0.1, 0.1))


__all__ = [
    "BENIGN_PROFILES", "PROFILE_WEIGHTS", "MALICIOUS_BEHAVIORS", "DeviceSim", "C2Choice", "RESOLVER_IP",
    "android_tv_iptv", "iptv_busy_box", "smart_tv", "console", "phone", "laptop", "iot_camera",
    "firmware_update", "c2_beaconing", "residential_proxy", "dga_activity", "ddos_bot", "lognormal_period",
]
