"""Synthetic Box Farm captures and ISP populations for GENOME evaluation.

Wraps :mod:`aegis.resonance.sim` (not modified): ISP background traffic comes from
:func:`aegis.resonance.sim.generate_scenario` with no campaigns, and synthetic family
check-in timing is injected on chosen lines with the same packet-sampling model
(:func:`aegis.resonance.sim.packet_sampling_keep`; resolver logs unsampled) and home NAT
(bots share the line with the household's devices).

Everything is synthetic metadata: timestamps, byte counts, reserved address ranges
(198.19.0.0/16 benchmarking block) and ``.example`` / ``.test`` names. No payloads, no
protocol content, nothing that runs.
"""
from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from pandas.api.types import union_categoricals

from aegis.genome.capture import LabCapture
from aegis.lab.topology import HostingTopology, HostRecord
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import EventTable, build_event_table
from aegis.resonance.sim import (
    DEFAULT_START,
    Scenario,
    ScenarioSpec,
    generate_scenario,
    packet_sampling_keep,
)

DAY = 86_400.0


@dataclass(frozen=True)
class FamilySpec:
    name: str
    period_s: float
    jitter: str = "uniform"              # uniform | normal
    jitter_scale: float = 0.1            # half-width (uniform) or sd (normal), fraction of period
    flows_per_beacon: int = 1
    bytes_median: float = 800.0
    bytes_log_sd: float = 0.25
    dns_mode: str = "per_beacon"         # per_beacon | cached | none | dga
    dns_ttl_s: float = 3600.0
    n_domains: int = 1
    n_ips: int = 1
    rotate_s: float | None = None
    update_s: float | None = None        # large-transfer cadence
    box_models: tuple[str, ...] = ("boxmodel-x1",)
    infra_slot: int = 0                  # /24 slot within 198.19.200.0/21
    # variant knobs (used to model drift and evasion honestly in the benchmark)
    period_scale: float = 1.0
    drift_frac: float = 0.0              # linear period drift over the window (0.1 = +10 % by the end)

    def variant(self, **kw: Any) -> "FamilySpec":
        return replace(self, **kw)


def standard_families() -> list[FamilySpec]:
    """Four families with distinct genomes; alpha and delta have close periods (attribution stress)."""
    return [
        FamilySpec("tvbox_alpha", 600.0, "uniform", 0.10, 2, 900.0, 0.25, "per_beacon", n_domains=1, n_ips=1,
                   update_s=6 * 3600.0, box_models=("boxmodel-x1",), infra_slot=0),
        FamilySpec("tvbox_beta", 1500.0, "normal", 0.05, 1, 300.0, 0.20, "cached", dns_ttl_s=3600.0, n_domains=3,
                   n_ips=2, rotate_s=8 * 3600.0, update_s=12 * 3600.0, box_models=("boxmodel-q2",), infra_slot=1),
        FamilySpec("tvbox_gamma", 300.0, "uniform", 0.25, 3, 2500.0, 0.30, "dga", n_domains=4, n_ips=2,
                   box_models=("boxmodel-m9",), infra_slot=2),
        FamilySpec("tvbox_delta", 640.0, "normal", 0.03, 1, 180.0, 0.15, "none", n_ips=2, update_s=DAY,
                   box_models=("boxmodel-x1", "boxmodel-t4"), infra_slot=3),
    ]


# ---------------------------------------------------------------------------- infrastructure

def family_infra(f: FamilySpec, seed: int = 7, generation: int = 0) -> list[tuple[str, str]]:
    """(domain, ip) pairs. ``generation`` > 0 models new C2 infrastructure for the same family."""
    r = random.Random(f"genome-infra:{f.name}:{seed}:{generation}")
    slot = (f.infra_slot * 4 + generation) % 64
    net = ipaddress.ip_network(f"198.19.{192 + slot}.0/24")
    ips = [str(net.network_address + h) for h in sorted(r.sample(range(10, 250), f.n_ips))]
    tag = "".join(r.choice("abcdefghijkmnpqrstuvwxyz") for _ in range(6))
    n = max(1, f.n_domains, f.n_ips)
    if f.dns_mode == "dga":
        return [("", ip) for ip in ips]
    names = [f"{('upd', 'cfg', 'sync', 'api')[j % 4]}{j}.{tag}-{f.name.split('_')[-1]}.example" for j in range(n)]
    return [(nm, ips[j % len(ips)]) for j, nm in enumerate(names)]


def dga_names(f: FamilySpec, day: int, seed: int, generation: int = 0) -> list[str]:
    r = random.Random(f"genome-dga:{f.name}:{seed}:{generation}:{day}")
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ["".join(r.choice(alpha) for _ in range(r.randint(12, 16))) + ".test" for _ in range(max(1, f.n_domains))]


def _hosts_for(f: FamilySpec, seed: int, generation: int) -> list[HostRecord]:
    pairs = family_infra(f, seed, generation)
    by_ip: dict[str, list[str]] = {}
    for nm, ip in pairs:
        by_ip.setdefault(ip, [])
        if nm:
            by_ip[ip].append(nm)
    return [HostRecord(ip, 64780 + f.infra_slot, f"Budget VPS G{f.infra_slot}", "dedicated", names)
            for ip, names in by_ip.items()]


# ---------------------------------------------------------------------------- timing generator

def _beacons(f: FamilySpec, rng: np.random.Generator, t0: float, t1: float) -> np.ndarray:
    P0 = f.period_s * f.period_scale
    out = []
    t = t0 + rng.uniform(0, P0)
    span = max(1.0, t1 - t0)
    while t < t1:
        out.append(t)
        P = P0 * (1.0 + f.drift_frac * (t - t0) / span)
        if f.jitter == "normal":
            u = rng.normal(0.0, f.jitter_scale)
        else:
            u = rng.uniform(-f.jitter_scale, f.jitter_scale)
        t += max(1.0, P * (1.0 + u))
    return np.asarray(out)


def device_events(f: FamilySpec, rng: np.random.Generator, t0: float, t1: float, seed: int, generation: int = 0
                  ) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Flow and DNS metadata of one infected device: (t, dst_ip, bytes, dur_s, pkts), (t, qname, answer_ip)."""
    pairs = family_infra(f, seed, generation)
    b = _beacons(f, rng, t0, t1)
    if f.rotate_s:
        idx = (np.floor((b - t0) / f.rotate_s).astype(np.int64)) % len(pairs)
    else:
        idx = np.zeros(len(b), dtype=np.int64) if len(pairs) == 1 else rng.integers(0, len(pairs), len(b))
    ft, fip, fby, fdu = [], [], [], []
    k = max(1, f.flows_per_beacon)
    for j in range(k):
        ft.append(b + 0.4 * j + rng.uniform(0, 0.3, len(b)))
        fip.append(np.array([pairs[i][1] for i in idx], dtype=object))
        fby.append(np.exp(np.log(f.bytes_median) + f.bytes_log_sd * rng.standard_normal(len(b))))
        fdu.append(rng.uniform(0.1, 1.5, len(b)))
    if f.update_s:
        ut = np.arange(t0 + rng.uniform(0, f.update_s), t1, f.update_s)
        ut = ut + rng.uniform(-0.05, 0.05, len(ut)) * f.update_s
        ui = np.zeros(len(ut), dtype=np.int64)
        ft.append(ut)
        fip.append(np.array([pairs[i][1] for i in ui], dtype=object))
        fby.append(rng.uniform(2e5, 2e6, len(ut)))
        fdu.append(rng.uniform(5, 30, len(ut)))
    flows = pd.DataFrame({"t": np.concatenate(ft), "dst_ip": np.concatenate(fip),
                          "bytes": np.concatenate(fby), "dur_s": np.concatenate(fdu)})
    flows["pkts"] = (flows["bytes"] / 500).astype(np.int64) + 2
    # DNS behavior
    dt, dq, da = [], [], []
    if f.dns_mode == "per_beacon":
        dt = (b - 0.02).tolist()
        dq = [pairs[i][0] for i in idx]
        da = [pairs[i][1] for i in idx]
    elif f.dns_mode == "cached":
        last: dict[str, float] = {}
        for tb_, i in zip(b, idx):
            nm = pairs[i][0]
            if nm not in last or tb_ - last[nm] >= f.dns_ttl_s:
                last[nm] = tb_
                dt.append(tb_ - 0.02)
                dq.append(nm)
                da.append(pairs[i][1])
    elif f.dns_mode == "dga":
        cached: dict[str, float] = {}
        for tb_, i in zip(b, idx):
            day = int((tb_ - DEFAULT_START.timestamp()) // DAY)
            names = dga_names(f, day, seed, generation)
            nm = names[int(i) % len(names)]
            if nm not in cached or tb_ - cached[nm] >= 300.0:
                cached[nm] = tb_
                dt.append(tb_ - 0.02)
                dq.append(nm)
                da.append(pairs[i][1])
    dns = pd.DataFrame({"t": np.asarray(dt, dtype=float), "qname": pd.Series(dq, dtype=object),
                        "answer_ip": pd.Series(da, dtype=object)})
    return flows.sort_values("t", kind="stable").reset_index(drop=True), dns


# ---------------------------------------------------------------------------- lab captures

_BOX_BENIGN = [  # (name, ip, period_s, jitter, bytes) - box vendor telemetry, time sync, middleware
    ("ntp.isp-time.example", "198.18.255.123", 1024.0, 0.02, 90.0),
    ("telemetry.boxvendor.example", "198.18.33.40", 3600.0, 0.2, 4000.0),
    ("push.platform-svc.example", "198.18.64.20", 1680.0, 0.05, 600.0),
    ("mw.licensed-iptv.example", "198.18.52.10", 30.0, 0.03, 1500.0),
]


def _benign_box(rng: np.random.Generator, t0: float, t1: float, active: list[tuple[float, float]]
                ) -> tuple[pd.DataFrame, pd.DataFrame]:
    ft, fip, fby, fdu, dt, dq, da = [], [], [], [], [], [], []
    for name, ip, P, j, by in _BOX_BENIGN:
        spans = active if P <= 60 else [(t0, t1)]
        for a, b in spans:
            t = a + rng.uniform(0, P)
            ts = []
            while t < b:
                ts.append(t)
                t += P * (1 + rng.uniform(-j, j))
            ts = np.asarray(ts)
            ft.append(ts)
            fip.append(np.full(len(ts), ip, dtype=object))
            fby.append(by * rng.uniform(0.7, 1.3, len(ts)))
            fdu.append(rng.uniform(0.05, 0.8, len(ts)))
            look = ts[::max(1, int(3600 // P))]
            dt += (look - 0.03).tolist()
            dq += [name] * len(look)
            da += [ip] * len(look)
    # streaming while active (long flows every 120 s) and some browsing-like lookups
    for a, b in active:
        ts = np.arange(a, b, 120.0)
        ft.append(ts)
        fip.append(np.full(len(ts), "198.18.1.10", dtype=object))
        fby.append(rng.uniform(5e6, 1e7, len(ts)))
        fdu.append(np.full(len(ts), 120.0))
        dt.append(a)
        dq.append("edge1.streamcdn.example")
        da.append("198.18.1.10")
    flows = pd.DataFrame({"t": np.concatenate(ft), "dst_ip": np.concatenate(fip), "bytes": np.concatenate(fby),
                          "dur_s": np.concatenate(fdu)})
    dns = pd.DataFrame({"t": np.asarray(dt, dtype=float), "qname": pd.Series(dq, dtype=object),
                        "answer_ip": pd.Series(da, dtype=object)})
    return flows, dns


def lab_capture(f: FamilySpec | None, *, box_model: str | None = None, days: float = 3.0, seed: int = 7,
                start: datetime = DEFAULT_START, generation: int = 0, capture_id: str | None = None,
                firmware: str = "fw-synthetic-1.0") -> LabCapture:
    """One lab box over ``days``; ``f=None`` is a clean reference capture (factory image)."""
    rng = np.random.default_rng([seed, 9001, generation, 0 if f is None else f.infra_slot + 1])
    t0 = start.timestamp()
    t1 = t0 + days * DAY
    active = [(t0 + d * DAY + 19 * 3600, min(t1, t0 + d * DAY + 22 * 3600)) for d in range(int(np.ceil(days)))]
    bf, bd = _benign_box(rng, t0, t1, active)
    if f is not None:
        mf, md = device_events(f, rng, t0, t1, seed, generation)
        bf = pd.concat([bf, mf.drop(columns=["pkts"])], ignore_index=True)
        bd = pd.concat([bd, md], ignore_index=True)
    bf = bf.sort_values("t", kind="stable").reset_index(drop=True)
    bd = bd.sort_values("t", kind="stable").reset_index(drop=True)
    model = box_model or (f.box_models[0] if f is not None else "boxmodel-x1")
    cid = capture_id or f"cap-{(f.name if f else 'clean')}-{model}-g{generation}-s{seed}"
    return LabCapture(capture_id=cid, box_model=model, start=start, end=start + timedelta(seconds=days * DAY),
                      flows=bf, dns=bd, family=None if f is None else f.name, firmware=firmware,
                      active_periods=active)


# ---------------------------------------------------------------------------- ISP populations

@dataclass
class GenomeScenario:
    base: Scenario
    flows: pd.DataFrame
    dns: pd.DataFrame
    topology: HostingTopology
    infected: dict[str, str]                 # line -> family
    family_keys: dict[str, set[str]]
    onset: dict[str, float]
    sampling: int

    @property
    def start(self) -> float:
        return self.base.start

    @property
    def end(self) -> float:
        return self.base.end

    @property
    def line_names(self) -> list[str]:
        return self.base.line_names

    def table(self, cfg: ResonanceConfig | None = None, *, until: float | None = None) -> EventTable:
        cfg = cfg or ResonanceConfig()
        f, d = self.flows, self.dns
        end = self.end
        if until is not None:
            f, d, end = f[f.t < until], d[d.t < until], until
        return build_event_table(f, d, dns_join_ttl_s=cfg.dns_join_ttl_s, start=self.start, end=end)


def _cat_concat(a: pd.Series, b: pd.Series) -> pd.Categorical:
    a = a if isinstance(a.dtype, pd.CategoricalDtype) else a.astype("category")
    b = b.astype(str).astype("category") if len(b) else pd.Series(pd.Categorical([]))
    return union_categoricals([pd.Categorical(a), pd.Categorical(b)], ignore_order=True)


def isp_population(families: list[tuple[FamilySpec, int]], *, n_lines: int = 2000, days: float = 1.0,
                   sampling: int = 1, seed: int = 7, generation: int = 0, onset_s: float = 0.0,
                   base: Scenario | None = None, infra_seed: int = 7) -> GenomeScenario:
    """Background ISP population with ``(family, n_infected_lines)`` injected (NAT: bots share lines).

    ``seed`` drives the population and timing; ``infra_seed`` the families' infrastructure (a property of
    the family shared with the lab captures, not of the ISP population).
    """
    if base is None or base.sampling != sampling:
        base = generate_scenario(ScenarioSpec(n_lines=n_lines, days=days, seed=seed, campaigns=[]), sampling)
    t0, t1 = base.start, base.end
    irng = np.random.default_rng([seed, 777, generation])
    srng = np.random.default_rng([seed, 778, generation, sampling])
    trng = np.random.default_rng([seed, 779, generation])
    lines = np.array(base.line_names)
    free = list(irng.permutation(len(lines)))
    infected: dict[str, str] = {}
    fkeys: dict[str, set[str]] = {}
    onset: dict[str, float] = {}
    add_f, add_d = [], []
    extra_hosts: list[HostRecord] = []
    for f, n_inf in families:
        extra_hosts += _hosts_for(f, infra_seed, generation)
        keys = {"ip:" + ip for _, ip in family_infra(f, infra_seed, generation)}
        keys |= {"d:" + nm for nm, _ in family_infra(f, infra_seed, generation) if nm}
        chosen = [lines[free.pop()] for _ in range(min(n_inf, len(free)))]
        first = t1
        for ln in chosen:
            infected[ln] = f.name
            a = t0 + onset_s
            fl, dn = device_events(f, trng, a, t1, infra_seed, generation)
            fl = fl[packet_sampling_keep(fl["pkts"].to_numpy(), sampling, srng)]
            fl = fl.drop(columns=["pkts"])
            fl["line"] = ln
            dn["line"] = ln
            add_f.append(fl)
            add_d.append(dn)
            if len(fl) or len(dn):
                first = min(first, float(np.min(np.concatenate([fl.t.to_numpy(), dn.t.to_numpy(), [t1]]))))
            keys |= {"d:" + q for q in dn["qname"]}
        fkeys[f.name] = keys
        onset[f.name] = first
    flows, dns = base.flows, base.dns
    if add_f:
        af = pd.concat(add_f, ignore_index=True)
        if len(af):
            flows = pd.DataFrame({"t": np.concatenate([flows.t.to_numpy(), af.t.to_numpy()]),
                                  "line": _cat_concat(flows.line, af.line),
                                  "dst_ip": _cat_concat(flows.dst_ip, af.dst_ip),
                                  "bytes": np.concatenate([flows.bytes.to_numpy(), af.bytes.to_numpy()]),
                                  "dur_s": np.concatenate([flows.dur_s.to_numpy(), af.dur_s.to_numpy()])})
    if add_d:
        ad = pd.concat(add_d, ignore_index=True)
        if len(ad):
            dns = pd.DataFrame({"t": np.concatenate([dns.t.to_numpy(), ad.t.to_numpy()]),
                                "line": _cat_concat(dns.line, ad.line),
                                "qname": _cat_concat(dns.qname, ad.qname),
                                "answer_ip": _cat_concat(dns.answer_ip, ad.answer_ip)})
    flows = flows.sort_values("t", kind="stable").reset_index(drop=True)
    dns = dns.sort_values("t", kind="stable").reset_index(drop=True)
    topo0 = base.topology
    topo = HostingTopology(f"{topo0.topology_id}-genome-g{generation}", list(topo0.hosts.values()) + extra_hosts,
                           topo0.services, topo0.malicious.values(), complete=True)
    return GenomeScenario(base=base, flows=flows, dns=dns, topology=topo, infected=infected, family_keys=fkeys,
                          onset=onset, sampling=sampling)
