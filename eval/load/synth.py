"""Synthetic ISP telemetry for load testing (SYNTHETIC: not real traffic).

Generates NetFlow CSV (AEGIS native header, as written by ``aegis.lab.writers``) and
resolver DNS JSONL for ``n_lines`` subscriber lines at controlled per-line rates.
Everything is vectorized with numpy so generation is not the bottleneck of the run.

Traffic model (deliberately simple, documented so the numbers can be judged):

* flows and DNS queries per line are Poisson at ``flows_per_line_hour`` /
  ``dns_per_line_hour``; times are uniform over the simulated span;
* destinations follow a Zipf(1.1) law over ``n_destinations`` IPs (CDN-like head, long tail);
  query names follow the same law over ``n_names`` names, each resolving to one destination;
* ``beacon_fraction`` of lines also beacon every ``beacon_period_s`` (+-15 % jitter) to one of
  a few rare IPs, so detectors have real (periodic, rare) work to do;
* NXDOMAIN share ``nx_fraction`` with random labels.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

import numpy as np

from aegis.lab.writers import NETFLOW_HEADER

DEVICE_CLASSES = ("phone", "laptop", "smart_tv", "android_tv", "console", "camera", "unknown")


@dataclass(frozen=True)
class SynthSpec:
    n_lines: int = 10_000
    duration_s: float = 3600.0
    start: datetime = datetime(2026, 10, 1, tzinfo=timezone.utc)
    flows_per_line_hour: float = 120.0
    dns_per_line_hour: float = 60.0
    n_destinations: int = 50_000
    n_names: int = 20_000
    beacon_fraction: float = 0.005
    beacon_period_s: float = 600.0
    nx_fraction: float = 0.02
    seed: int = 7

    def as_dict(self) -> dict:
        d = asdict(self)
        d["start"] = self.start.isoformat()
        return d

    @property
    def events_per_line_hour(self) -> float:
        return self.flows_per_line_hour + self.dns_per_line_hour


@dataclass
class SynthBatch:
    """Serialized telemetry, time ordered within each source."""
    netflow_csv: bytes
    dns_jsonl: bytes
    n_flows: int
    n_dns: int
    t_min: float
    t_max: float

    @property
    def n_events(self) -> int:
        return self.n_flows + self.n_dns

    @property
    def flow_bytes_per_event(self) -> float:
        header = len(",".join(NETFLOW_HEADER)) + 1
        return (len(self.netflow_csv) - header) / max(1, self.n_flows)

    @property
    def dns_bytes_per_event(self) -> float:
        return len(self.dns_jsonl) / max(1, self.n_dns)


def _mac(i: np.ndarray) -> np.ndarray:
    b = [(i >> s) & 0xFF for s in (32, 24, 16, 8, 0)]
    return np.char.add("02:", np.char.add(np.char.mod("%02x:", b[0]), np.char.add(
        np.char.mod("%02x:", b[1]), np.char.add(np.char.mod("%02x:", b[2]), np.char.add(
            np.char.mod("%02x:", b[3]), np.char.mod("%02x", b[4]))))))


def _rfc3339(t: np.ndarray) -> np.ndarray:
    ms = np.round(t * 1000).astype(np.int64)
    dt = ms.astype("datetime64[ms]")
    s = np.datetime_as_string(dt, unit="ms")
    return np.char.add(s, "Z")


def _dest_ip(idx: np.ndarray) -> np.ndarray:
    # 198.18.0.0/15 is reserved for benchmarking (RFC 2544): never a real destination
    return np.char.add(np.char.add(np.char.mod("198.%d.", 18 + (idx >> 16) % 2), np.char.mod("%d.", (idx >> 8) & 0xFF)),
                       np.char.mod("%d", idx & 0xFF))


def _zipf_index(rng: np.random.Generator, n: int, size: int, a: float = 1.1) -> np.ndarray:
    ranks = np.arange(1, n + 1, dtype=np.float64)
    p = ranks ** -a
    p /= p.sum()
    return rng.choice(n, size=size, p=p)


def generate(spec: SynthSpec, *, line_offset: int = 0, seed_offset: int = 0) -> SynthBatch:
    """Generate one batch of telemetry for lines ``[line_offset, line_offset + n_lines)``."""
    rng = np.random.default_rng([spec.seed, seed_offset])
    t0 = spec.start.timestamp()
    hours = spec.duration_s / 3600.0
    n = spec.n_lines
    lines = np.arange(line_offset, line_offset + n, dtype=np.int64)
    macs = _mac(lines + 1)
    src_ips = np.char.add(np.char.add(np.char.mod("10.%d.", (lines >> 16) & 0xFF),
                                      np.char.mod("%d.", (lines >> 8) & 0xFF)), np.char.mod("%d", lines & 0xFF))
    classes = np.asarray(DEVICE_CLASSES)[(lines * 2654435761) % len(DEVICE_CLASSES)]

    # ---------------------------------------------------------------- flows
    nf = rng.poisson(spec.flows_per_line_hour * hours, size=n)
    f_line = np.repeat(np.arange(n), nf)
    f_t = t0 + rng.random(len(f_line)) * spec.duration_s
    f_dst = _zipf_index(rng, spec.n_destinations, len(f_line))
    beacon = np.flatnonzero(rng.random(n) < spec.beacon_fraction)
    if len(beacon):
        per = max(1, int(spec.duration_s // spec.beacon_period_s))
        b_line = np.repeat(beacon, per)
        k = np.tile(np.arange(per), len(beacon))
        phase = rng.random(len(beacon)) * spec.beacon_period_s
        b_t = t0 + np.repeat(phase, per) + k * spec.beacon_period_s * (1 + rng.uniform(-0.15, 0.15, len(b_line)))
        ok = b_t < t0 + spec.duration_s
        b_line, b_t = b_line[ok], b_t[ok]
        b_dst = spec.n_destinations + (b_line % 3)          # three rare "C2" addresses
        f_line = np.concatenate([f_line, b_line])
        f_t = np.concatenate([f_t, b_t])
        f_dst = np.concatenate([f_dst, b_dst])
    order = np.argsort(f_t, kind="stable")
    f_line, f_t, f_dst = f_line[order], f_t[order], f_dst[order]
    m = len(f_line)
    proto = np.where(rng.random(m) < 0.8, 6, 17)
    port = np.where(proto == 6, np.where(rng.random(m) < 0.9, 443, 80), np.where(rng.random(m) < 0.5, 443, 53))
    pk_out = rng.integers(1, 40, size=m)
    pk_in = rng.integers(1, 60, size=m)
    by_out = pk_out * rng.integers(60, 1200, size=m)
    by_in = pk_in * rng.integers(60, 1500, size=m)
    dur = rng.integers(10, 30_000, size=m)
    cols = [_rfc3339(f_t), macs[f_line], classes[f_line], src_ips[f_line],
            np.char.mod("%d", rng.integers(1024, 65535, size=m)), _dest_ip(f_dst), np.char.mod("%d", port),
            np.char.mod("%d", proto), np.char.mod("%d", pk_out), np.char.mod("%d", by_out),
            np.char.mod("%d", pk_in), np.char.mod("%d", by_in), np.char.mod("%d", dur)]
    rows = cols[0]
    for c in cols[1:]:
        rows = np.char.add(np.char.add(rows, ","), c)
    netflow = (",".join(NETFLOW_HEADER) + "\n" + "\n".join(rows.tolist()) + ("\n" if m else "")).encode()

    # ---------------------------------------------------------------- DNS
    nd = rng.poisson(spec.dns_per_line_hour * hours, size=n)
    d_line = np.repeat(np.arange(n), nd)
    d_t = np.sort(t0 + rng.random(len(d_line)) * spec.duration_s)
    d_line = rng.permutation(d_line)
    q = len(d_line)
    name_idx = _zipf_index(rng, spec.n_names, q)
    nx = rng.random(q) < spec.nx_fraction
    ts = _rfc3339(d_t).tolist()
    out = []
    mac_l, cls_l, ip_l = macs.tolist(), classes.tolist(), src_ips.tolist()
    dest_names = _dest_ip(np.arange(spec.n_names) * 7 % spec.n_destinations).tolist()
    rand_labels = rng.integers(0, 36 ** 8, size=int(nx.sum()))
    ri = 0
    for i in range(q):
        ln = int(d_line[i])
        if nx[i]:
            qname = np.base_repr(int(rand_labels[ri]), 36).lower() + ".nx-synth.example"
            ri += 1
            rec = {"ts": ts[i], "device_id": mac_l[ln], "device_class": cls_l[ln], "client_ip": ip_l[ln],
                   "qname": qname, "qtype": "A", "rcode": "NXDOMAIN", "answers": []}
        else:
            k = int(name_idx[i])
            rec = {"ts": ts[i], "device_id": mac_l[ln], "device_class": cls_l[ln], "client_ip": ip_l[ln],
                   "qname": f"svc{k}.synth.example", "qtype": "A", "rcode": "NOERROR", "answers": [dest_names[k]]}
        out.append(json.dumps(rec, separators=(",", ":")))
    dns = ("\n".join(out) + ("\n" if out else "")).encode()
    tmin = float(min(f_t.min() if m else np.inf, d_t.min() if q else np.inf))
    tmax = float(max(f_t.max() if m else -np.inf, d_t.max() if q else -np.inf))
    return SynthBatch(netflow, dns, m, q, tmin, tmax)
