"""Vectorized ISP-vantage scenario simulator and telemetry transforms for RESONANCE evaluation.

Builds subscriber-line populations (several devices behind each home NAT) on top of
the lab hosting topology (:func:`aegis.lab.topology.generate_topology`), with:

* benign traffic: browsing (Zipf destination popularity), streaming and IPTV long flows,
  IPTV middleware heartbeats while watching, always-on busy IPTV boxes (hard negative),
  NTP, push keepalives, OS and smart-TV telemetry, console presence, camera uploads and
  heartbeats, and *niche benign widget timers* (shared timers to rare destinations - the
  hardest negatives for any cross-line method), optionally a *new* benign timer rollout;
* campaigns: BadBox/Vo1d-style bots with configurable period, jitter, per-bot period
  desynchronization, DNS behavior (per-beacon lookups, cached lookups, hard-coded IPs),
  domain rotation over dedicated infrastructure, onset time and prevalence;
* transforms: NetFlow/IPFIX packet sampling 1:N (a flow of k packets survives with
  probability 1-(1-1/N)^k; resolver logs are unsampled), NAT aggregation (devices -> lines,
  intrinsic to the generator), and CGNAT-style line merging (:func:`merge_lines`).

Packet sampling draws come from an RNG stream independent of the population, so the same
seed yields the identical population at every sampling rate.

Everything is synthetic: reserved address ranges and ``.example``/``.test`` names only.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

import numpy as np
import pandas as pd

from aegis.lab.iocs import build_ioc_bundle
from aegis.lab.topology import HostingTopology, HostRecord, generate_topology
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import EventTable, build_event_table
from aegis.resonance.population import DestinationHistory, key_stats

DAY = 86_400.0
DEFAULT_START = datetime(2026, 10, 1, tzinfo=timezone.utc)
EXPORT_S = 120.0            # exporter active timeout used for long-lived flows

DEVICE_WEIGHTS = {"phone": 0.30, "laptop": 0.14, "smart_tv": 0.15, "android_tv": 0.17, "iptv_busy_box": 0.03,
                  "console": 0.08, "camera": 0.05}


@dataclass
class CampaignSpec:
    name: str
    period_s: float = 600.0
    period_range: tuple[float, float] | None = None   # per-bot uniform period (desynchronized timers)
    jitter: float = 0.15                              # uniform +-jitter fraction per interval
    prevalence: float = 0.01                          # fraction of lines with an infected device
    dns_mode: str = "cached"                          # per_beacon | cached | none | mixed
    dns_ttl_s: float = 3600.0
    n_domains: int = 1
    n_ips: int = 1
    rotate_s: float | None = None                     # rotate to the next domain every rotate_s
    known: bool = False                               # reuse lab C2 published in the IOC feed
    onset_s: float = 0.0                              # campaign start relative to window start
    onset_spread_s: float = 0.0
    double_infection: float = 0.15                    # share of infected lines with two bots (NAT mixture)
    beacon_pkts: tuple[int, int] = (4, 12)
    tasking_per_h: float = 1 / 6.0


@dataclass
class ScenarioSpec:
    n_lines: int = 2000
    days: float = 1.0
    start: datetime = DEFAULT_START
    mean_devices: float = 2.6
    campaigns: list[CampaignSpec] = field(default_factory=list)
    benign_new_app: bool = False      # a *new* benign shared timer rolled out to ~1.5 % of lines
    widgets: bool = True              # established niche benign timers
    seed: int = 7                     # world: households, devices, destinations, infections
    traffic_seed: int | None = None   # timing randomness (defaults to seed); warm-up history varies only this


@dataclass
class Scenario:
    spec: ScenarioSpec
    sampling: int
    flows: pd.DataFrame               # t, line, dst_ip, bytes, dur_s (categoricals)
    dns: pd.DataFrame                 # t, line, qname, answer_ip
    topology: HostingTopology
    line_names: list[str]
    infected: dict[str, set[str]]     # line -> campaign names
    campaign_keys: dict[str, set[str]]   # campaign -> destination keys (d:/ip:)
    campaign_onset: dict[str, float]  # campaign -> earliest bot start (epoch s)
    blocklist: set[str]               # static blocklist keys (d:/ip:) from the lab IOC bundle
    benign_timer_keys: set[str]       # keys of benign shared timers (for honest reporting)
    new_app_keys: set[str]

    @property
    def start(self) -> float:
        return self.spec.start.timestamp()

    @property
    def end(self) -> float:
        return self.start + self.spec.days * DAY

    def table(self, cfg: ResonanceConfig | None = None) -> EventTable:
        cfg = cfg or ResonanceConfig()
        return build_event_table(self.flows, self.dns, dns_join_ttl_s=cfg.dns_join_ttl_s,
                                 start=self.start, end=self.end)

    def malicious_keys(self) -> set[str]:
        out: set[str] = set()
        for v in self.campaign_keys.values():
            out |= v
        return out


# ---------------------------------------------------------------------------- transforms

def packet_sampling_keep(pkts: np.ndarray, n: int, rng: np.random.Generator) -> np.ndarray:
    """Keep-mask for flows under 1:n random packet sampling (n=1 keeps everything).

    A flow is exported iff at least one of its packets is sampled: P = 1-(1-1/n)^pkts.
    """
    u = rng.random(len(pkts))
    if n <= 1:
        return np.ones(len(pkts), dtype=bool)
    p = 1.0 - np.power(1.0 - 1.0 / n, np.maximum(pkts, 1).astype(np.float64))
    return u < p


def merge_lines(sc: Scenario, k: int, seed: int = 0) -> Scenario:
    """CGNAT-ish merging: groups of ``k`` lines become one observable entity."""
    if k <= 1:
        return sc
    rng = np.random.default_rng([seed, 4242])
    perm = rng.permutation(len(sc.line_names))
    group = {sc.line_names[i]: f"p_cg{j // k:06d}" for j, i in enumerate(perm)}
    cats = sorted(set(group.values()))

    def remap(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df["line"] = pd.Categorical(df["line"].astype(str).map(group), categories=cats)
        return df

    infected: dict[str, set[str]] = {}
    for ln, camps in sc.infected.items():
        infected.setdefault(group[ln], set()).update(camps)
    return replace(sc, flows=remap(sc.flows), dns=remap(sc.dns), line_names=cats, infected=infected)


# ---------------------------------------------------------------------------- generator internals

class _Reg:
    """Destination name/IP registry with categorical codes."""

    def __init__(self, topo: HostingTopology):
        self.topo = topo
        self.names: list[str] = []
        self.name_ip: list[str] = []
        self._ni: dict[str, int] = {}
        self.ips: list[str] = []
        self._ii: dict[str, int] = {}

    def ip(self, ip: str) -> int:
        i = self._ii.get(ip)
        if i is None:
            i = len(self.ips)
            self._ii[ip] = i
            self.ips.append(ip)
        return i

    def name(self, name: str, ip: str | None = None) -> int:
        i = self._ni.get(name)
        if i is None:
            if ip is None:
                res = self.topo.resolve(name)
                if not res:
                    raise KeyError(name)
                ip = res[0]
            i = len(self.names)
            self._ni[name] = i
            self.names.append(name)
            self.name_ip.append(ip)
            self.ip(ip)
        return i

    def name_ip_idx(self) -> np.ndarray:
        return np.array([self._ii[ip] for ip in self.name_ip], dtype=np.int64)


class _Buf:
    def __init__(self) -> None:
        self.f: dict[str, list[np.ndarray]] = {"t": [], "dev": [], "ip": [], "pk": [], "by": [], "du": []}
        self.d: dict[str, list[np.ndarray]] = {"t": [], "dev": [], "nm": []}

    def flows(self, t, dev, ip, pk, by, du) -> None:
        n = len(t)
        if n == 0:
            return
        bc = lambda x, dt: np.broadcast_to(np.asarray(x, dtype=dt), (n,)).copy()  # noqa: E731
        self.f["t"].append(np.asarray(t, dtype=np.float64))
        self.f["dev"].append(bc(dev, np.int64))
        self.f["ip"].append(bc(ip, np.int64))
        self.f["pk"].append(bc(pk, np.int64))
        self.f["by"].append(bc(by, np.float64))
        self.f["du"].append(bc(du, np.float64))

    def dns(self, t, dev, nm) -> None:
        n = len(t)
        if n == 0:
            return
        self.d["t"].append(np.asarray(t, dtype=np.float64))
        self.d["dev"].append(np.broadcast_to(np.asarray(dev, dtype=np.int64), (n,)).copy())
        self.d["nm"].append(np.broadcast_to(np.asarray(nm, dtype=np.int64), (n,)).copy())


def _periodic(rng: np.random.Generator, t0: np.ndarray, t1: np.ndarray, period: np.ndarray, jitter: np.ndarray
              ) -> tuple[np.ndarray, np.ndarray]:
    """Renewal timers: t_{k+1} = t_k + P (1 + U(-j, j)), first event at t0 + U(0, P)."""
    t0, t1, period, jitter = (np.asarray(x, dtype=np.float64) for x in (t0, t1, period, jitter))
    n = len(t0)
    if n == 0:
        return np.zeros(0), np.zeros(0, dtype=np.int64)
    cnt = np.maximum(0, np.ceil((t1 - t0) / (period * (1 - jitter))).astype(np.int64)) + 1
    inst = np.repeat(np.arange(n), cnt)
    inc = period[inst] * (1.0 + rng.uniform(-1, 1, len(inst)) * jitter[inst])
    first = np.concatenate([[0], np.cumsum(cnt)[:-1]])
    inc[first] = rng.uniform(0, 1, n) * period
    cs = np.cumsum(inc)
    base = np.repeat(cs[first] - inc[first], cnt)
    t = t0[inst] + (cs - base)
    ok = t < t1[inst]
    return t[ok], inst[ok]


def _poisson(rng: np.random.Generator, t0: np.ndarray, t1: np.ndarray, rate_s: np.ndarray
             ) -> tuple[np.ndarray, np.ndarray]:
    t0, t1, rate_s = (np.asarray(x, dtype=np.float64) for x in (t0, t1, rate_s))
    lam = np.maximum(0.0, (t1 - t0) * rate_s)
    cnt = rng.poisson(lam)
    inst = np.repeat(np.arange(len(t0)), cnt)
    t = t0[inst] + rng.random(len(inst)) * (t1 - t0)[inst]
    o = np.lexsort((t, inst))
    return t[o], inst[o]


def _first_in_bucket(t: np.ndarray, inst: np.ndarray, ttl: float, t_ref: float) -> np.ndarray:
    """Mask of events that are the first of their (instance, TTL bucket): stub-resolver caching."""
    if len(t) == 0:
        return np.zeros(0, dtype=bool)
    # each (device, host) cache entry has its own phase: no artificial cross-device alignment
    off = (inst.astype(np.int64) * 2654435761 % 1_000_003) / 1_000_003.0 * ttl
    b = np.floor((t - t_ref - off) / ttl).astype(np.int64)
    key = inst.astype(np.int64) * 10_000_000 + b
    o = np.lexsort((t, key))
    first = np.ones(len(t), dtype=bool)
    first[1:] = key[o][1:] != key[o][:-1]
    out = np.zeros(len(t), dtype=bool)
    out[o[first]] = True
    return out


def _sessions(rng: np.random.Generator, n: int, mean_start_h: float, sd_h: float, len_lo_h: float,
              len_hi_h: float) -> tuple[np.ndarray, np.ndarray]:
    s = np.clip(rng.normal(mean_start_h, sd_h, n), 0, 23.5) * 3600
    ln = rng.uniform(len_lo_h, len_hi_h, n) * 3600
    return s, ln


def _gate(t: np.ndarray, dev_of_ev: np.ndarray, s: np.ndarray, ln: np.ndarray, start: float) -> np.ndarray:
    tod = (t - start) % DAY
    rel = (tod - s[dev_of_ev]) % DAY
    return rel < ln[dev_of_ev]


def _free_ips(topo: HostingTopology, prefix: str, n: int, rng: np.random.Generator) -> list[str]:
    net = ipaddress.ip_network(prefix)
    used = set(topo.hosts)
    pool = [str(net.network_address + i) for i in range(2, net.num_addresses - 1)]
    pool = [p for p in pool if p not in used]
    idx = rng.choice(len(pool), size=n, replace=False)
    return [pool[i] for i in sorted(idx)]


# ---------------------------------------------------------------------------- generator

def generate_scenario(spec: ScenarioSpec, sampling: int = 1) -> Scenario:
    """Generate a scenario at NetFlow packet sampling 1:``sampling``. Deterministic in ``spec.seed``."""
    seed = spec.seed
    wr = np.random.default_rng([seed, 1])            # world
    rng = np.random.default_rng([spec.seed if spec.traffic_seed is None else spec.traffic_seed, 11])  # timing
    srng = np.random.default_rng([seed, 2, 0])      # sampling stream, independent of the population
    base = generate_topology(seed)
    t_start = spec.start.timestamp()
    t_end = t_start + spec.days * DAY

    # ------------------------------------------------------------------ extended topology (fresh infra)
    hosts = [HostRecord(h.ip, h.asn, h.provider, h.kind, list(h.hostnames)) for h in base.hosts.values()]
    extra_hosts: list[HostRecord] = []
    infra_rng = np.random.default_rng([seed, 3])
    camp_infra: dict[str, list[tuple[str, str]]] = {}
    bb = base.malicious["badbox2_emu"]
    for ci, c in enumerate(spec.campaigns):
        if c.known:
            camp_infra[c.name] = [(bb.c2_domains[0], bb.c2_ips[0])]
            continue
        # each fresh campaign on its own dedicated /24 (benchmarking range 198.19.0.0/16)
        prefix = f"198.19.{100 + ci}.0/24"
        asn, prov = 64720 + ci, f"Budget VPS {ci}"
        tmp = HostingTopology("tmp", hosts + extra_hosts, {})
        ips = _free_ips(tmp, prefix, c.n_ips, infra_rng)
        tag = "".join(infra_rng.choice(list("abcdefghijkmnpqrstuvwxyz"), 6))
        names = [f"{'sync' if j % 2 == 0 else 'cfg'}{j}.{tag}-tvupd.example" for j in range(c.n_domains)]
        pairs = [(nm, ips[j % len(ips)]) for j, nm in enumerate(names)]
        for ip in ips:
            extra_hosts.append(HostRecord(ip, asn, prov, "dedicated", [nm for nm, i2 in pairs if i2 == ip]))
        camp_infra[c.name] = pairs
    new_app_name = "api.newwidget-app.example"
    new_app_ip = _free_ips(HostingTopology("tmp", hosts + extra_hosts, {}), "198.18.64.0/18", 1, infra_rng)[0]
    extra_hosts.append(HostRecord(new_app_ip, 64630, "Hyperscale Cloud", "cloud", [new_app_name]))
    topo = HostingTopology(f"resonance-scenario-{seed}", hosts + extra_hosts, base.services,
                           base.malicious.values(), complete=True)
    reg = _Reg(topo)

    # ------------------------------------------------------------------ population: lines and devices
    n_lines = spec.n_lines
    ndev_line = 1 + wr.poisson(max(0.0, spec.mean_devices - 1.0), n_lines)
    ndev_line = np.minimum(ndev_line, 8)
    dev_line = np.repeat(np.arange(n_lines), ndev_line)
    nd = len(dev_line)
    classes = list(DEVICE_WEIGHTS)
    pw = np.array([DEVICE_WEIGHTS[c] for c in classes])
    dev_cls = wr.choice(len(classes), size=nd, p=pw / pw.sum())
    by_cls = {c: np.flatnonzero(dev_cls == i) for i, c in enumerate(classes)}
    buf = _Buf()
    T0 = np.full(nd, t_start)
    T1 = np.full(nd, t_end)

    svc = topo.services
    web = [e.hostname for e in svc["web"]]
    wr.shuffle(web)
    web_idx = np.array([reg.name(h) for h in web])
    zipf = 1.0 / np.arange(1, len(web_idx) + 1) ** 1.1
    zipf /= zipf.sum()

    def ep(service: str, i: int = 0) -> tuple[int, int]:
        e = svc[service][i]
        n = reg.name(e.hostname, e.ip)
        return n, reg.ip(e.ip)

    def fixed_host_flows(devs, t, inst, host: tuple[int, int], pk_lo, pk_hi, by_lo, by_hi, dur, ttl):
        n_i, ip_i = host
        d = devs[inst]
        pk = rng.integers(pk_lo, pk_hi + 1, len(t))
        by = rng.uniform(by_lo, by_hi, len(t))
        buf.flows(t, d, ip_i, pk, by, dur)
        if ttl is not None:
            m = _first_in_bucket(t, inst, ttl, t_start - rng.uniform(0, ttl))
            buf.dns(t[m] - 0.03, d[m], n_i)

    def periodic_app(devs, period, jitter, host, pk=(4, 10), by=(400, 3000), ttl=3600.0, gate=None, per_dev=None):
        if len(devs) == 0:
            return
        P = np.full(len(devs), period, dtype=np.float64) if per_dev is None else per_dev
        if gate is None:
            t, inst = _periodic(rng, T0[devs], T1[devs], P, np.full(len(devs), jitter))
        else:
            # generate only inside each day's session (sessions may run past midnight)
            s, ln = gate
            ts, ins = [], []
            for dday in range(-1, int(np.ceil(spec.days))):
                a0 = t_start + dday * DAY + s
                a1 = np.minimum(a0 + ln, t_end)
                a0c = np.maximum(a0, t_start)
                ok = a1 > a0c
                if not ok.any():
                    continue
                idx = np.flatnonzero(ok)
                tt, ii = _periodic(rng, a0c[idx], a1[idx], P[idx], np.full(len(idx), jitter))
                ts.append(tt)
                ins.append(idx[ii])
            t = np.concatenate(ts) if ts else np.zeros(0)
            inst = np.concatenate(ins) if ins else np.zeros(0, dtype=np.int64)
            o = np.lexsort((t, inst))
            t, inst = t[o], inst[o]
        fixed_host_flows(devs, t, inst, host, pk[0], pk[1], by[0], by[1], rng.uniform(50, 900, len(t)) / 1000, ttl)

    def browse(devs, per_day, gate):
        if len(devs) == 0:
            return
        s, ln = gate
        t, inst = _poisson(rng, T0[devs], T1[devs], np.full(len(devs), per_day / (ln.mean() if len(ln) else DAY)))
        k = _gate(t, inst, s, ln, t_start)
        t, inst = t[k], inst[k]
        dest = web_idx[rng.choice(len(web_idx), size=len(t), p=zipf)]
        d = devs[inst]
        pk = np.maximum(2, rng.lognormal(3.2, 1.0, len(t))).astype(np.int64)
        ipx = reg.name_ip_idx()[dest]
        buf.flows(t, d, ipx, pk, pk * rng.uniform(300, 1200, len(t)), rng.uniform(0.2, 20, len(t)))
        # DNS: first lookup of each (device, host) per 300 s TTL bucket
        m = _first_in_bucket(t, d * 100_000 + dest, 300.0, t_start)
        buf.dns(t[m] - 0.02, d[m], dest[m])

    def long_flows(devs, gate, hosts: list[tuple[int, int]], switch_s: float, bps: float):
        """Long-lived streams exported every EXPORT_S, switching host every ~switch_s."""
        if len(devs) == 0:
            return
        s, ln = gate
        n_days = int(np.ceil(spec.days))
        for dday in range(n_days):
            st = t_start + dday * DAY + s
            en = np.minimum(st + ln, t_end)
            cnt = np.maximum(0, np.floor((en - st) / EXPORT_S).astype(np.int64))
            inst = np.repeat(np.arange(len(devs)), cnt)
            k = np.arange(cnt.sum()) - np.repeat(np.cumsum(cnt) - cnt, cnt)
            t = st[inst] + k * EXPORT_S
            seg = (k * EXPORT_S // switch_s).astype(np.int64)
            hsel = (np.asarray(inst) * 7919 + seg * 104729 + dday * 31) % len(hosts)
            hn = np.array([h[0] for h in hosts])[hsel]
            hi = np.array([h[1] for h in hosts])[hsel]
            d = devs[inst]
            byt = bps * EXPORT_S * rng.uniform(0.6, 1.4, len(t))
            buf.flows(t, d, hi, (byt / 1300).astype(np.int64) + 1, byt, np.full(len(t), EXPORT_S))
            first = np.ones(len(t), dtype=bool)
            first[1:] = (inst[1:] != inst[:-1]) | (seg[1:] != seg[:-1])
            buf.dns(t[first] - 0.05, d[first], hn[first])

    # ------------------------------------------------------------------ benign behaviors per class
    awake = lambda n: _sessions(rng, n, 7.0, 1.0, 14.0, 17.0)  # noqa: E731
    evening = lambda n, lo, hi: _sessions(rng, n, 19.5, 1.5, lo, hi)  # noqa: E731
    ntp = ep("ntp")
    push = ep("push")
    conn = ep("connectivity")
    ostel = ep("os_telemetry")

    ph = by_cls["phone"]
    browse(ph, 70, awake(len(ph)))
    periodic_app(ph, 1680, 0.05, push, pk=(3, 6), ttl=3600)
    periodic_app(ph, 3600, 0.2, ostel, pk=(6, 14))

    lp = by_cls["laptop"]
    g = _sessions(rng, len(lp), 9.0, 1.5, 6.0, 12.0)
    browse(lp, 160, g)
    periodic_app(lp, 1024, 0.02, ntp, pk=(2, 2), by=(90, 90), ttl=86400, gate=g)

    st = by_cls["smart_tv"]
    vendor = wr.integers(0, 2, len(st))
    vod = [ep("video_cdn", i) for i in range(len(svc["video_cdn"]))]
    long_flows(st, evening(len(st), 1.0, 4.0), vod, 3000, 8e5)
    for vi, vname in enumerate(("tvvendor-a", "tvvendor-b")):
        dv = st[vendor == vi]
        periodic_app(dv, 7200, 0.25, ep(f"{vname}_acr"), pk=(8, 20))
        periodic_app(dv, 1800, 0.1, ep(f"{vname}_connectivity"), pk=(4, 8), ttl=3600)
    periodic_app(st, 1024, 0.02, ntp, pk=(2, 2), by=(90, 90), ttl=86400)

    at = by_cls["android_tv"]
    ga = evening(len(at), 1.5, 4.5)
    mw = ep("iptv_middleware", 0)
    epg = ep("iptv_middleware", 1)
    origins = [ep("iptv_origins", i) for i in range(len(svc["iptv_origins"]))]
    periodic_app(at, 30, 0.03, mw, pk=(5, 9), ttl=300, gate=ga)
    periodic_app(at, 1800, 0.1, epg, pk=(10, 40), ttl=3600, gate=ga)
    long_flows(at, ga, origins, 1200, 5e5)
    periodic_app(at, 1680, 0.05, push, pk=(3, 6))
    periodic_app(at, 1024, 0.02, ntp, pk=(2, 2), by=(90, 90), ttl=86400)
    cdev = at[wr.random(len(at)) < 0.5]
    t, inst = _poisson(rng, T0[cdev], T1[cdev], np.full(len(cdev), 6 / DAY))
    fixed_host_flows(cdev, t, inst, conn, 4, 8, 300, 900, 0.1, 300)

    bx = by_cls["iptv_busy_box"]
    always = np.zeros(len(bx), dtype=bool)
    always[wr.random(len(bx)) < 0.5] = True
    gb_s, gb_l = evening(len(bx), 6.0, 12.0)
    gb_s[always], gb_l[always] = 0.0, DAY
    periodic_app(bx, 30, 0.03, mw, pk=(5, 9), ttl=300, gate=(gb_s, gb_l))
    long_flows(bx, (gb_s, gb_l), origins, 900, 1.2e6)
    periodic_app(bx, 1800, 0.1, epg, pk=(10, 40), gate=(gb_s, gb_l))

    co = by_cls["console"]
    gc_ = evening(len(co), 1.0, 3.0)
    pres = ep("game_presence")
    periodic_app(co, 120, 0.1, pres, pk=(4, 8), gate=gc_)
    long_flows(co, gc_, [ep("game_servers", i) for i in range(len(svc["game_servers"]))], 1800, 4e4)

    cam = by_cls["camera"]
    cams = [ep("cam_cloud", i) for i in range(len(svc["cam_cloud"]))]
    long_flows(cam, (np.zeros(len(cam)), np.full(len(cam), DAY)), cams, DAY, 2.5e5)
    periodic_app(cam, 300, 0.05, cams[0], pk=(6, 12), ttl=3600)

    benign_timer_keys: set[str] = set()
    for h in (ntp, push, ostel, mw, epg, pres, cams[0]):
        benign_timer_keys.add("d:" + reg.names[h[0]])
    if spec.widgets:
        # established niche benign timers: shared timers to rare, dedicated destinations
        tail = web_idx[-40:]
        wrng = np.random.default_rng([seed, 5])
        for wi, (period, frac) in enumerate(((300, 0.012), (600, 0.02), (900, 0.008), (1800, 0.03), (3600, 0.015),
                                             (900, 0.01))):
            host = (int(tail[wi]), int(reg.name_ip_idx()[tail[wi]]))
            users = np.flatnonzero(wrng.random(nd) < frac)
            users = users[np.isin(dev_cls[users], [classes.index("phone"), classes.index("smart_tv"),
                                                   classes.index("android_tv")])]
            periodic_app(users, period, 0.05, host, pk=(4, 10), ttl=3600)
            benign_timer_keys.add("d:" + reg.names[host[0]])
    new_app_keys: set[str] = set()
    if spec.benign_new_app:
        nrng = np.random.default_rng([seed, 6])
        users = np.flatnonzero(nrng.random(nd) < 0.006)
        host = (reg.name(new_app_name, new_app_ip), reg.ip(new_app_ip))
        t, inst = _periodic(rng, T0[users] + 6 * 3600 + nrng.uniform(0, 3600, len(users)), T1[users],
                            np.full(len(users), 900.0), np.full(len(users), 0.05))
        fixed_host_flows(users, t, inst, host, 4, 10, 400, 3000, 0.3, 3600)
        new_app_keys = {"d:" + new_app_name, "ip:" + new_app_ip}

    # ------------------------------------------------------------------ campaigns (extra bot devices)
    infected: dict[str, set[str]] = {}
    campaign_keys: dict[str, set[str]] = {}
    campaign_onset: dict[str, float] = {}
    bot_dev_line: list[int] = []
    crng = np.random.default_rng([seed if spec.traffic_seed is None else spec.traffic_seed, 7])
    irng = np.random.default_rng([seed, 8])
    next_dev = nd
    for c in spec.campaigns:
        n_inf = int(round(c.prevalence * n_lines))
        if n_inf <= 0:
            continue
        lines_inf = np.sort(irng.choice(n_lines, size=min(n_inf, n_lines), replace=False))
        two = irng.random(len(lines_inf)) < c.double_infection
        bl = np.concatenate([lines_inf, lines_inf[two]])
        devs = np.arange(next_dev, next_dev + len(bl))
        next_dev += len(bl)
        bot_dev_line.extend(bl.tolist())
        for ln in lines_inf:
            infected.setdefault(f"p_line{ln:06d}", set()).add(c.name)
        b_t0 = t_start + c.onset_s + crng.uniform(0, max(c.onset_spread_s, 1e-9), len(devs))
        b_t1 = np.full(len(devs), t_end)
        if c.period_range is not None:
            P = crng.uniform(c.period_range[0], c.period_range[1], len(devs))
        else:
            P = np.full(len(devs), c.period_s)
        t, inst = _periodic(crng, b_t0, b_t1, P, np.full(len(devs), c.jitter))
        pairs = camp_infra[c.name]
        if c.rotate_s:
            di = (np.floor((t - t_start) / c.rotate_s).astype(np.int64)) % len(pairs)
        else:
            di = (inst % len(pairs)) if len(pairs) > 1 else np.zeros(len(t), dtype=np.int64)
        nm_idx = np.array([reg.name(nm, ip) for nm, ip in pairs])
        ip_idx = np.array([reg.ip(ip) for _, ip in pairs])
        d = devs[inst]
        pk = crng.integers(c.beacon_pkts[0], c.beacon_pkts[1] + 1, len(t))
        buf.flows(t, d, ip_idx[di], pk, crng.uniform(500, 2500, len(t)), crng.uniform(0.15, 2.0, len(t)))
        # DNS behavior
        mode = np.full(len(devs), c.dns_mode, dtype=object)
        if c.dns_mode == "mixed":
            mode = np.where(crng.random(len(devs)) < 0.5, "none", "cached")
        m_pb = mode[inst] == "per_beacon"
        m_ca = (mode[inst] == "cached") & _first_in_bucket(t, inst * 1000 + di, c.dns_ttl_s,
                                                         t_start - crng.uniform(0, c.dns_ttl_s))
        dm = m_pb | m_ca
        buf.dns(t[dm] - 0.02, d[dm], nm_idx[di[dm]])
        # tasking downloads (large, irregular)
        tt, ti = _poisson(crng, b_t0, b_t1, np.full(len(devs), c.tasking_per_h / 3600))
        tdi = np.zeros(len(tt), dtype=np.int64) if not c.rotate_s else \
            (np.floor((tt - t_start) / c.rotate_s).astype(np.int64)) % len(pairs)
        buf.flows(tt + 1, devs[ti], ip_idx[tdi], crng.integers(80, 600, len(tt)), crng.uniform(5e4, 6e5, len(tt)),
                  crng.uniform(2, 20, len(tt)))
        keys = {"d:" + nm for nm, _ in pairs} | {"ip:" + ip for _, ip in pairs}
        campaign_keys[c.name] = keys
        campaign_onset[c.name] = float(b_t0.min())

    # ------------------------------------------------------------------ assemble, sample, map devices -> lines
    all_dev_line = np.concatenate([dev_line, np.array(bot_dev_line, dtype=np.int64)])
    line_names = [f"p_line{i:06d}" for i in range(n_lines)]
    F = {k: np.concatenate(v) if v else np.zeros(0) for k, v in buf.f.items()}
    D = {k: np.concatenate(v) if v else np.zeros(0) for k, v in buf.d.items()}
    keep = packet_sampling_keep(F["pk"], sampling, srng) & (F["t"] >= t_start) & (F["t"] < t_end)
    fo = np.argsort(F["t"][keep], kind="stable")
    ip_cat = pd.CategoricalDtype(reg.ips)
    line_cat = pd.CategoricalDtype(line_names)
    flows = pd.DataFrame({
        "t": F["t"][keep][fo],
        "line": pd.Categorical.from_codes(all_dev_line[F["dev"][keep].astype(np.int64)][fo], dtype=line_cat),
        "dst_ip": pd.Categorical.from_codes(F["ip"][keep].astype(np.int64)[fo], dtype=ip_cat),
        "bytes": F["by"][keep][fo], "dur_s": F["du"][keep][fo]})
    dk = (D["t"] >= t_start) & (D["t"] < t_end)
    do = np.argsort(D["t"][dk], kind="stable")
    nm = D["nm"][dk].astype(np.int64)[do]
    dns = pd.DataFrame({
        "t": D["t"][dk][do],
        "line": pd.Categorical.from_codes(all_dev_line[D["dev"][dk].astype(np.int64)][do], dtype=line_cat),
        "qname": pd.Categorical.from_codes(nm, dtype=pd.CategoricalDtype(reg.names)),
        "answer_ip": pd.Categorical.from_codes(reg.name_ip_idx()[nm], dtype=ip_cat)})

    blocklist = static_blocklist(topo, spec.start, int(np.ceil(spec.days)), seed)
    return Scenario(spec=spec, sampling=sampling, flows=flows, dns=dns, topology=topo, line_names=line_names,
                    infected=infected, campaign_keys=campaign_keys, campaign_onset=campaign_onset,
                    blocklist=blocklist, benign_timer_keys=benign_timer_keys, new_app_keys=new_app_keys)


def static_blocklist(topo: HostingTopology, start: datetime, days: int, seed: int) -> set[str]:
    """Keys a static blocklist would match: every unexpired *malicious* indicator of the lab IOC bundle.

    Naive by design (it ignores contradicting allowlist entries), as many deployed blocklists are.
    """
    bundle = build_ioc_bundle(topo, start=start, days=days, seed=seed)
    out: set[str] = set()
    for ind in bundle["indicators"]:
        if ind["verdict"] != "malicious":
            continue
        if datetime.fromisoformat(ind["expires_at"].replace("Z", "+00:00")) <= start:
            continue
        out.add(("d:" if ind["type"] == "domain" else "ip:") + ind["value"].lower())
    return out


def baseline_history(spec: ScenarioSpec, cfg: ResonanceConfig | None = None, *, sampling: int = 1,
                     coverage_days: float = 30.0) -> DestinationHistory:
    """Warm-up history: a campaign-free day of the same population, treated as ``coverage_days`` of memory.

    Destinations seen in the warm-up get ``first_seen = start - coverage_days`` and their warm-up
    line count as typical population. Fresh campaign infrastructure and new apps are absent.
    """
    cfg = cfg or ResonanceConfig()
    warm = replace(spec, campaigns=[], benign_new_app=False,
                   traffic_seed=(spec.seed if spec.traffic_seed is None else spec.traffic_seed) + 100_003)
    sc = generate_scenario(warm, sampling=sampling)
    tb = sc.table(cfg)
    st = key_stats(tb, cfg)
    t0 = spec.start.timestamp() - coverage_days * DAY
    present = np.flatnonzero(st.n_events > 0)
    hist = DestinationHistory(coverage_start=t0)
    hist.observe([tb.keys.items[k] for k in present], st.n_lines[present], np.full(len(present), t0),
                 np.full(len(present), spec.start.timestamp()))
    return hist


def standard_campaigns(prevalence: float = 0.01) -> list[CampaignSpec]:
    """Benchmark campaigns: standard (fresh infra), slow heavy-jitter, evasive, and known (C2 in the IOC feed)."""
    return [
        CampaignSpec("standard", period_s=600, jitter=0.15, prevalence=prevalence, dns_mode="cached"),
        CampaignSpec("slow", period_s=2400, jitter=0.4, prevalence=prevalence, dns_mode="cached", dns_ttl_s=7200),
        CampaignSpec("evasive", period_range=(900, 3600), jitter=0.3, prevalence=prevalence, dns_mode="mixed",
                     n_domains=8, n_ips=4, rotate_s=6 * 3600, onset_s=4 * 3600, onset_spread_s=8 * 3600),
        CampaignSpec("known", period_s=900, jitter=0.1, prevalence=prevalence, dns_mode="cached", known=True),
    ]


def summarize(sc: Scenario) -> dict[str, Any]:
    return {"lines": len(sc.line_names), "flows": len(sc.flows), "dns": len(sc.dns), "sampling": sc.sampling,
            "infected_lines": {c: sum(1 for v in sc.infected.values() if c in v) for c in sc.campaign_keys}}
