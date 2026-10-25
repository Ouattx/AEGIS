"""Windowed per-device behavioral features (spec section 4) over bounded streaming state.

:class:`WindowStore` turns a stream of :class:`ObservationEvent` into
:class:`FeatureVector` objects, one per entity per closed window.

Design:

- **Event time, not wall clock.** Each tenant has a watermark (latest observed
  time minus ``allowed_lateness``). When the watermark passes a hop boundary, every
  entity with data inside the window ending at that boundary gets a feature vector.
  ``flush(now)`` closes everything up to ``now`` (end of stream / idle sensor).
- **Hopping windows.** A ``24h`` window with a ``1h`` hop is re-evaluated every hour
  over the trailing 24 hours, so detection delay is bounded by the hop while the
  features keep a full day of context. Tumbling windows are ``hop == window``.
- **Missing is not zero.** A feature that cannot be computed is ``None`` and flagged
  in ``FeatureVector.missing``: e.g. DNS ratios when the device made no DNS query,
  all DNS features when the tenant has no DNS source, periodicity features when no
  connection channel has enough check-ins, prevalence when the population is too
  small to be meaningful.
- **Population context.** Destination prevalence (how many devices of the tenant
  contacted a destination during the same window) normalizes "rare destination"
  features by network context: a licensed IPTV middleware is contacted by many
  boxes, a dedicated C2 server by a handful.

State layout (what one line costs in memory)
--------------------------------------------

Raw events are never retained. Each event is folded into its hop as

* 13 scalar aggregates per (entity, hop): counts, byte sums, protocol / small-flow /
  zero-reply / long-flow counters, peak packet rate, NXDOMAIN count;
* one packed 12-byte record per flow (millisecond offset in the hop, channel id, total
  bytes), one 8-byte record per DNS query (offset, name id with the NXDOMAIN bit) and
  one 8-byte record per distinct (name, answer) pair. Destination IPs, names and
  ``(dst, port, protocol)`` channels are interned once per tenant in vocabularies
  shared by every line (:class:`_Vocab`); ids no buffered hop references are freed;
* at most ``ceil(max_source_event_ids / bins)`` evidence ids per hop (16 bytes each for
  UUIDs).

Events arrive into a small per-entity pending buffer and are packed (numpy) at
every hop boundary, so the hot path stays pure Python and the window is a handful of
contiguous arrays per line. At the load-test traffic model (120 flows + 60 queries per
line-hour) a full 24 h window is about 60 KB per line (``eval/load/report``).

Bounds and exactness
--------------------

Below the per-hop caps of :class:`StateLimits` every feature is computed exactly from
the packed records (identical to folding raw events, up to the millisecond rounding of
timestamps). A hop that exceeds a cap keeps a **coordinated bottom-k sample by key**:
all events of the keys (channels / names) whose 64-bit hash is below the hop's
threshold ``tau``, plus keys with priority (destinations of the configured IOC bundle,
which are never sampled away, and keys that recur from earlier hops, so a periodic
channel on a busy line keeps being tracked). Because the hash is the same for every
line, samples are coordinated across the population. Above the cap:

* counts, byte sums, rates, ratios and every other scalar feature stay exact;
* distinct counts (``unique_dst_ip``, ``qname_unique``, ``nx_unique``, ...) are KMV
  estimates ``|{keys with hash < tau}| / tau`` (relative standard error about
  ``1 / sqrt(cap)``), never below the number of keys actually retained;
* ``dst_entropy`` uses the exact total and the sampled keys' exact counts;
  ``max_dst_share`` is the largest retained key's share (a lower bound);
* the gap features over all connection starts use a per-hop log-histogram
  (1/32 decade bins) recorded before sampling plus exact running moments, so
  ``burstiness`` stays exact and the interval quantiles are within about 0.016
  in log10 units;
* channel / name periodicity and prevalence are computed on the retained keys.

A hop's state is therefore at most ``12 * flow_events_per_bin + 8 * dns_events_per_bin
+ 8 * answers_per_bin`` bytes plus a 1.2 KB histogram when it overflowed, whatever
the event rate. Pending events are packed early when they exceed twice the caps,
which bounds the hot buffer too.

Feature definitions are in :data:`FEATURE_DOCS`.
"""
from __future__ import annotations

import hashlib
import math
import sys
import uuid
from array import array
from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import TYPE_CHECKING, Callable, Hashable, Iterable, Literal

import numpy as np

from aegis.contracts.models import FeatureVector, ObservationEvent

if TYPE_CHECKING:  # pragma: no cover
    from aegis.sentinel.rules import IOCBundle

WindowName = Literal["5m", "15m", "24h"]

WINDOW_SECONDS: dict[str, int] = {"5m": 300, "15m": 900, "24h": 86_400}

#: records at least this long are active-timeout continuations of long-lived
#: connections (streams, uploads), not discrete connection attempts
LONG_FLOW_MS = 55_000
#: a channel needs this many discrete connections in the window to be assessed for periodicity
MIN_CHANNEL_EVENTS = 6
#: robust CV at or below which a channel counts as periodic
PERIODIC_CV = 0.35
#: a periodic channel/name must be active in at least this share of the covered hops
#: (persistent, around-the-clock check-ins rather than a busy browsing session)
MIN_DUTY = 0.5
#: a flow with fewer total bytes than this counts as "small" (check-in sized)
SMALL_FLOW_BYTES = 2_000
#: a bin is "egress heavy" when it uploads more than it downloads and more than this many bytes
OUT_HEAVY_BYTES = 1_000_000
#: below this many active entities in a window, prevalence is not meaningful (missing)
DEFAULT_MIN_POPULATION = 20
#: evidence ids carried per feature vector (the detector cites at most 200)
DEFAULT_MAX_SOURCE_EVENT_IDS = 256

FEATURE_DOCS: dict[str, str] = {
    "coverage_h": "hours of the window covered by sensor data for the tenant",
    "flow_rate_h": "flow records per covered hour",
    "dns_rate_h": "DNS queries per covered hour",
    "bytes_out_rate_log": "log10(1 + bytes sent per covered hour)",
    "bytes_in_rate_log": "log10(1 + bytes received per covered hour)",
    "out_ratio": "bytes_out / (bytes_out + bytes_in)",
    "unique_dst_ip": "distinct destination IPs",
    "unique_dst_port": "distinct destination ports",
    "dst_entropy": "Shannon entropy (bits) of the flow distribution over destination IPs",
    "max_dst_share": "share of flows going to the single most contacted destination",
    "tcp_frac": "share of flows that are TCP",
    "udp_frac": "share of flows that are UDP",
    "small_flow_frac": f"share of flows with fewer than {SMALL_FLOW_BYTES} total bytes",
    "zero_reply_frac": "share of flows that received no bytes/packets back (scanning, floods)",
    "long_flow_frac": "share of flow records that are continuations of long-lived connections",
    "peak_out_pps_log": "log10(1 + peak outbound packets per second of any flow record)",
    "active_bin_frac": "share of covered hops with any traffic (24/7 activity is close to 1)",
    "out_heavy_bin_frac": "share of covered hops dominated by sustained egress",
    "nxdomain_rate": "share of DNS queries answered NXDOMAIN",
    "nx_unique": "distinct NXDOMAIN names",
    "nx_name_entropy": "mean character entropy (bits) of the first label of NXDOMAIN names",
    "qname_unique": "distinct queried names",
    "interval_p10_log": "log10 of the 10th percentile of gaps between discrete connections (s)",
    "interval_p50_log": "log10 of the median gap between discrete connections (s)",
    "interval_p90_log": "log10 of the 90th percentile of gaps between discrete connections (s)",
    "burstiness": "Goh-Barabasi burstiness of connection gaps, -1 periodic .. +1 bursty",
    "beacon_robust_cv": ("robust coefficient of variation (MAD/median) of the gaps on the reported channel: the "
                         "rarest persistent periodic channel when prevalence is known, else the most periodic one"),
    "beacon_period_log": "log10 of the median period (s) of the reported channel",
    "beacon_events": "connections on the reported channel",
    "beacon_bytes_log": "log10(1 + median bytes per connection) on the reported channel",
    "beacon_duty": "share of covered hops in which the reported channel was active",
    "beacon_dst_prevalence": "share of the tenant's active devices contacting that channel's destination",
    "rare_dst_frac": ("share of destinations reached by discrete connections (not long-lived streams or "
                      "downloads) that almost no other device contacts"),
    "rare_qname_frac": "share of distinct queried names queried by almost no other device",
    "periodic_qnames": ("names looked up on a persistent regular schedule (robust CV <= 0.35, active in at least "
                        "half the covered hops)"),
    "periodic_qname_prevalence": "share of active devices querying the rarest periodically looked-up name",
    "baseline_dev_flows": "robust z of the latest hop's flow count against earlier hops of the window",
    "baseline_dev_bytes_out": "robust z of the latest hop's egress against earlier hops of the window",
    "recent_flows_log": "log10(1 + flows in the latest hop)",
    "recent_bytes_out_log": "log10(1 + bytes sent in the latest hop)",
    "recent_unique_dst": "distinct destinations in the latest hop",
    "ioc_contacts": "distinct fresh malicious IOC indicators contacted (missing without a bundle)",
}

FEATURE_NAMES: tuple[str, ...] = tuple(FEATURE_DOCS)


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _log10p(x: float) -> float:
    return math.log10(1.0 + max(0.0, x))


def _shannon(counts: Iterable[int]) -> float:
    vals = [c for c in counts if c > 0]
    total = float(sum(vals))
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in vals)


def label_entropy(name: str) -> float:
    """Character entropy (bits) of the first DNS label of ``name``."""
    label = name.split(".", 1)[0]
    if not label:
        return 0.0
    return _shannon(Counter(label).values())


def _quantile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        raise ValueError("empty")
    pos = (len(sorted_vals) - 1) * q
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return sorted_vals[lo]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def _robust_z(x: float, history: list[float]) -> float:
    med = median(history)
    mad = median(abs(h - med) for h in history)
    scale = max(1.4826 * mad, 0.1)
    return max(-50.0, min(50.0, (x - med) / scale))


def normalize_name(name: str) -> str:
    return name.strip().lower().rstrip(".")


def key_hash(s: str) -> float:
    """Deterministic hash of a key in ``[0, 1)`` (same on every shard and every run)."""
    d = hashlib.blake2b(s.encode("utf-8", "surrogatepass"), digest_size=8).digest()
    return int.from_bytes(d, "big") / 18446744073709551616.0


# ---------------------------------------------------------------------------- contacts

@dataclass
class ContactSummary:
    """Who an entity talked to during one window (input to IOC matching)."""
    tenant_id: str
    entity_pseudonym: str
    window_start: datetime
    window_end: datetime
    dst_ips: Counter[str] = field(default_factory=Counter)
    qnames: Counter[str] = field(default_factory=Counter)
    answers: dict[str, set[str]] = field(default_factory=dict)
    ip_times: dict[str, tuple[float, float]] = field(default_factory=dict)
    qname_times: dict[str, tuple[float, float]] = field(default_factory=dict)
    authorization_ids: set[str] = field(default_factory=set)
    source_ids: set[str] = field(default_factory=set)
    #: True when a hop of the window exceeded its state cap (contacts are then a
    #: coordinated sample plus every IOC-bundle destination; see the module docstring)
    sampled: bool = False

    @classmethod
    def from_events(cls, events: Iterable[ObservationEvent], *, tenant_id: str, entity_pseudonym: str,
                    window_start: datetime, window_end: datetime) -> "ContactSummary":
        """Build from raw events (only those of the entity inside ``[window_start, window_end)``)."""
        cs = cls(tenant_id, entity_pseudonym, window_start, window_end)
        ws, we = window_start.timestamp(), window_end.timestamp()
        for ev in events:
            if ev.tenant_id != tenant_id or ev.entity_pseudonym != entity_pseudonym:
                continue
            ts = ev.observed_at.timestamp()
            if not ws <= ts < we:
                continue
            cs.add_event(ev, ts)
        return cs

    def add_event(self, ev: ObservationEvent, ts: float) -> None:
        self.authorization_ids.add(ev.collection_authorization_id)
        self.source_ids.add(ev.source_id)
        if ev.flow is not None:
            self._touch(self.dst_ips, self.ip_times, ev.flow.dst_ip, ts)
        if ev.dns is not None:
            q = normalize_name(ev.dns.qname)
            self._touch(self.qnames, self.qname_times, q, ts)
            if ev.dns.answers:
                self.answers.setdefault(q, set()).update(ev.dns.answers)

    @staticmethod
    def _touch(counter: Counter[str], times: dict[str, tuple[float, float]], key: str, ts: float,
               n: int = 1) -> None:
        counter[key] += n
        old = times.get(key)
        times[key] = (ts, ts) if old is None else (min(old[0], ts), max(old[1], ts))

    def merge_times(self, counter: Counter[str], times: dict[str, tuple[float, float]],
                    src_counter: Counter[str], src_times: dict[str, tuple[float, float]]) -> None:
        counter.update(src_counter)
        for k, (a, b) in src_times.items():
            old = times.get(k)
            times[k] = (a, b) if old is None else (min(old[0], a), max(old[1], b))

    def resolved_ips(self, qname: str) -> set[str]:
        return self.answers.get(normalize_name(qname), set())


# ---------------------------------------------------------------------------- limits

@dataclass(frozen=True)
class StateLimits:
    """Per (entity, hop) caps on retained window state; see the module docstring."""
    flow_events_per_bin: int = 512
    dns_events_per_bin: int = 256
    answers_per_bin: int = 256

    def __post_init__(self) -> None:
        for name in ("flow_events_per_bin", "dns_events_per_bin", "answers_per_bin"):
            if int(getattr(self, name)) < 16:
                raise ValueError(f"{name} must be at least 16")

    def bytes_per_bin(self) -> int:
        """Upper bound of one hop's packed records (excluding the overflow histogram)."""
        return 12 * self.flow_events_per_bin + 8 * self.dns_events_per_bin + 8 * self.answers_per_bin


# ---------------------------------------------------------------------------- vocabularies

_FREED = 1 << 62


class _Vocab:
    """Tenant-scoped interning of keys to dense ids, with per-id hash, pin flag and last hop.

    An id is freed (and later reused) once no buffered hop can reference it: every
    reference is made at a hop ``k`` that also raises ``last[id]`` to at least ``k``, so
    ``last[id] < lo`` with ``lo`` the oldest retained hop proves the id is unreferenced.
    """

    def __init__(self) -> None:
        self.items: list[Hashable | None] = []
        self.index: dict[Hashable, int] = {}
        self.last = array("q")
        self.hash = array("d")
        self.pinned = array("b")
        self.free: list[int] = []

    def __len__(self) -> int:
        return len(self.items)

    def intern(self, key: Hashable, k: int, text: Callable[[], str], pin: Callable[[], bool]) -> int:
        i = self.index.get(key)
        if i is not None:
            if self.last[i] < k:
                self.last[i] = k
            return i
        h = key_hash(text())
        p = 1 if pin() else 0
        if self.free:
            i = self.free.pop()
            self.items[i] = key
            self.last[i] = k
            self.hash[i] = h
            self.pinned[i] = p
            self._reset(i)
        else:
            i = len(self.items)
            self.items.append(key)
            self.last.append(k)
            self.hash.append(h)
            self.pinned.append(p)
            self._append()
        self.index[key] = i
        return i

    def _reset(self, i: int) -> None:
        """Clear per-id caches of subclasses when an id is reused."""

    def _append(self) -> None:
        """Grow per-id caches of subclasses."""

    def evict(self, lo: int) -> int:
        """Free every id whose last reference is older than hop ``lo``."""
        if not self.items:
            return 0
        lv = np.frombuffer(self.last, dtype=np.int64)
        dead = np.flatnonzero(lv < lo)
        del lv
        for i in dead.tolist():
            key = self.items[i]
            if key is not None:
                del self.index[key]
            self.items[i] = None
            self.last[i] = _FREED
            self.free.append(i)
        return len(dead)


class _Names(_Vocab):
    """Strings (destination / answer IPs, query names) with a lazily filled label-entropy cache."""

    def __init__(self) -> None:
        super().__init__()
        self.entropy = array("d")

    def _reset(self, i: int) -> None:
        self.entropy[i] = math.nan

    def _append(self) -> None:
        self.entropy.append(math.nan)

    def label_entropy(self, i: int) -> float:
        e = self.entropy[i]
        if e != e:  # NaN: not computed yet
            e = self.entropy[i] = label_entropy(str(self.items[i]))
        return e


class _Channels(_Vocab):
    """``(dst id, port, protocol, long)`` connection channels with their destination and port.

    The key is packed into one Python int (``dst``, ``port + 1`` in 17 bits, a per-tenant
    protocol code in 8 bits, the long-flow bit) instead of a tuple: about 100 bytes less per
    channel in the shared vocabulary.
    """

    def __init__(self) -> None:
        super().__init__()
        self.dst = array("q")
        self.port = array("q")
        self.long = array("b")
        self.protocols: dict[str, int] = {}

    def intern_channel(self, dst: int, dst_text: str, port: int, proto: str, long: bool, k: int,
                       pinned: bool) -> int:
        code = self.protocols.get(proto)
        if code is None:
            code = self.protocols[proto] = len(self.protocols) % 256
        key = (((dst << 17) | ((port + 1) & 0x1FFFF)) << 9) | (code << 1) | (1 if long else 0)
        i = self.index.get(key)
        if i is not None:
            if self.last[i] < k:
                self.last[i] = k
            return i
        i = self.intern(key, k, lambda: f"{dst_text}|{port}|{proto}|{int(long)}", lambda: pinned)
        self.dst[i] = dst
        self.port[i] = port
        self.long[i] = 1 if long else 0
        return i

    def _reset(self, i: int) -> None:
        pass

    def _append(self) -> None:
        self.dst.append(-1)
        self.port.append(-1)
        self.long.append(0)


# ---------------------------------------------------------------------------- per-entity state

# scalar aggregates per (entity, hop)
S_NF, S_ND, S_BO, S_BI, S_BK, S_TCP, S_UDP, S_SMALL, S_ZR, S_ZK, S_LONG, S_PPS, S_NX = range(13)
NS = 13

FLOW_DT = np.dtype([("off", "<u4"), ("ch", "<u4"), ("size", "<u4")])     # 12 bytes
DNS_DT = np.dtype([("off", "<u4"), ("q", "<u4")])                        # 8 bytes, NX in bit 31
ANS_DT = np.dtype([("q", "<u4"), ("ip", "<u4")])                         # 8 bytes
NO_SIZE = 0xFFFFFFFF
NX_BIT = 1 << 31
Q_MASK = NX_BIT - 1
_EMPTY_F = np.zeros(0, dtype=FLOW_DT)
_EMPTY_D = np.zeros(0, dtype=DNS_DT)
_EMPTY_A = np.zeros(0, dtype=ANS_DT)
_ZERO_OFF = np.zeros(1, dtype=np.int64)
_EMPTY_SC = np.zeros((0, NS), dtype=np.float64)

#: overflow histogram of connection gaps: log10(gap) in [-3, 6) at 1/32 decade
_H_PER_DECADE = 32
_H_LO = -3.0
_H_BINS = 9 * _H_PER_DECADE
#: persistence sketch of an overflowing entity: hops (decaying) in which a key hash bucket was seen
_PERSIST = 16384
#: the sketch halves every this many hops (a window of memory, not forever)
_PERSIST_HALF_LIFE = 8
#: a key seen in at least this many recent earlier hops counts as recurring
_PERSIST_MIN = 2
#: exact per-destination flow counts kept for the top talkers of a sampled hop
_HEAVY = 32
#: exact distinct destination ports kept per sampled hop
_PORTS_CAP = 4096


def _hbucket(gaps: np.ndarray) -> np.ndarray:
    b = np.floor((np.log10(np.maximum(gaps, 1e-3)) - _H_LO) * _H_PER_DECADE).astype(np.int64)
    return np.clip(b, 0, _H_BINS - 1)


def _hist_quantile(hist: np.ndarray, q: float) -> float:
    """Quantile of a log-bucketed sample with the order-statistic convention of :func:`_quantile`."""
    n = int(hist.sum())
    pos = (n - 1) * q
    cum = np.cumsum(hist)
    b = int(np.searchsorted(cum, pos + 0.5, side="left"))     # bucket holding order statistic round(pos)
    before = float(cum[b - 1]) if b else 0.0
    frac = min(1.0, max(0.0, (pos + 0.5 - before) / float(hist[b])))
    return 10.0 ** (_H_LO + (b + frac) / _H_PER_DECADE)


class _SlotSketch:
    """What a hop that exceeded its cap keeps besides its sample (see the module docstring)."""

    __slots__ = ("tau_f", "tau_q", "n", "mean", "m2", "hist", "first", "last", "heavy", "ports")

    def __init__(self) -> None:
        self.tau_f = 1.0
        self.tau_q = 1.0
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.hist: np.ndarray | None = None
        self.first = math.inf
        self.last = -math.inf
        self.heavy: dict[int, int] = {}                 # destination id -> exact flows (top talkers)
        self.ports: np.ndarray = np.zeros(0, dtype=np.int64)   # exact distinct ports (capped)

    def add_flows(self, dst: np.ndarray, ports: np.ndarray) -> None:
        """Exact top-destination counts and distinct ports of one run, before sampling."""
        u, c = np.unique(dst, return_counts=True)
        for i, n in zip(u.tolist(), c.tolist()):
            self.heavy[i] = self.heavy.get(i, 0) + n
        if len(self.heavy) > _HEAVY:
            top = sorted(self.heavy.items(), key=lambda kv: (-kv[1], kv[0]))[:_HEAVY]
            self.heavy = dict(top)
        p = np.union1d(self.ports, ports[ports >= 0])
        self.ports = p[:_PORTS_CAP]

    def add_starts(self, starts: np.ndarray) -> None:
        """Fold one run of discrete connection starts (seconds) into the gap summary."""
        if not len(starts):
            return
        s = np.sort(starts)
        if math.isfinite(self.last) and s[0] >= self.last:
            # in-order run (the usual case): the gap from the previous run's last start is a true gap
            s = np.concatenate([[self.last], s])
        self.first = min(self.first, float(s[0]))
        self.last = max(self.last, float(s[-1]))
        g = np.diff(s)
        g = g[g > 0]
        if not len(g):
            return
        if self.hist is None:
            self.hist = np.zeros(_H_BINS, dtype=np.int64)
        self.hist += np.bincount(_hbucket(g), minlength=_H_BINS)
        n2, mean2 = len(g), float(g.mean())
        m22 = float(((g - mean2) ** 2).sum())
        n = self.n + n2
        delta = mean2 - self.mean
        self.m2 += m22 + delta * delta * self.n * n2 / n
        self.mean += delta * n2 / n
        self.n = n


class _Entity:
    """One line's window: packed hops plus the pending (not yet packed) events."""

    __slots__ = ("device_class", "slots", "sc", "f", "fo", "d", "do", "a", "ao", "ovf", "ids", "raw_ids",
                 "tags", "hot", "pf", "pd", "pa", "persist", "hopbits", "seen_k", "last_emit")

    def __init__(self) -> None:
        self.device_class = "unknown"
        self.slots: list[int] = []                     # packed hops, ascending
        self.sc: np.ndarray = _EMPTY_SC                # (len(slots), NS) scalar aggregates
        self.f: np.ndarray = _EMPTY_F                  # flows of all packed hops, hop by hop
        self.fo: np.ndarray = _ZERO_OFF                # hop i's flows: f[fo[i]:fo[i + 1]]
        self.d: np.ndarray = _EMPTY_D
        self.do: np.ndarray = _ZERO_OFF
        self.a: np.ndarray = _EMPTY_A
        self.ao: np.ndarray = _ZERO_OFF
        self.ovf: dict[int, _SlotSketch] | None = None
        self.ids: dict[int, bytearray] = {}
        self.raw_ids: dict[int, list[str]] | None = None
        self.tags: dict[tuple[str, str], list[int]] = {}
        self.hot: dict[int, list[float]] = {}          # pending scalar aggregates per hop
        self.pf = array("d")                           # pending flows: (hop, ts, channel, size) * n
        self.pd = array("d")                           # pending queries: (hop, ts, name | NX) * n
        self.pa = array("d")                           # pending answers: (hop, name, ip) * n
        self.persist: np.ndarray | None = None         # uint8[_PERSIST] persistence sketch (busy lines only)
        self.hopbits: np.ndarray | None = None         # keys already counted in hop ``seen_k``
        self.seen_k = -(1 << 62)
        self.last_emit = -(1 << 62)                    # end index of the last emitted window

    def has_bin(self, k: int) -> bool:
        return k in self.hot or k in self.slots

    def live(self, lo: int) -> bool:
        return bool(self.hot) or (bool(self.slots) and self.slots[-1] >= lo)


@dataclass
class _Tenant:
    first_ts: float
    watermark: float
    next_boundary_idx: int          # index of the next bin whose end is a boundary to emit
    emitted_idx: int = -1           # bins with index < emitted_idx are closed
    has_flow: bool = False
    has_dns: bool = False
    entities: dict[str, _Entity] = field(default_factory=dict)
    bin_refs: dict[int, int] = field(default_factory=dict)     # hop -> entities holding it
    ips: _Names = field(default_factory=_Names)
    names: _Names = field(default_factory=_Names)
    channels: _Channels = field(default_factory=_Channels)
    last_boundary: int | None = None


@dataclass
class WindowStats:
    events: int = 0
    windows_emitted: int = 0
    late_events: int = 0
    dropped_late: int = 0
    rejected: int = 0
    sampled_bins: int = 0           # (entity, hop) pairs that exceeded a state cap


@dataclass
class _Context:
    """Population context of one window: active entities and per-key prevalence lookups."""
    population: int
    ip: Callable[[np.ndarray], np.ndarray]      # destination ids -> entities contacting them
    q: Callable[[np.ndarray], np.ndarray]       # name ids -> entities querying them


class _View:
    """One entity's packed state restricted to a window ``[lo, end)`` (views, no copies)."""

    def __init__(self, store: "WindowStore", t: _Tenant, eid: str, ent: _Entity, lo: int, end: int):
        self.eid = eid
        self.ent = ent
        i0 = bisect_left(ent.slots, lo)
        i1 = bisect_left(ent.slots, end)
        self.i0, self.i1 = i0, i1
        self.slots = ent.slots[i0:i1]
        self.sc = ent.sc[i0:i1]
        hop = store.hop_s
        sl = np.asarray(self.slots, dtype=np.int64)
        self.f = ent.f[ent.fo[i0]:ent.fo[i1]]
        self.fk = np.repeat(sl, np.diff(ent.fo[i0:i1 + 1]))
        self.ft = self.fk * float(hop) + self.f["off"] / 1000.0
        self.d = ent.d[ent.do[i0]:ent.do[i1]]
        self.dk = np.repeat(sl, np.diff(ent.do[i0:i1 + 1]))
        self.dt = self.dk * float(hop) + self.d["off"] / 1000.0
        self.a = ent.a[ent.ao[i0]:ent.ao[i1]]
        sk = [ent.ovf[s] for s in self.slots if s in ent.ovf] if ent.ovf else []
        self.sketches: dict[int, _SlotSketch] = {s: ent.ovf[s] for s in self.slots if s in ent.ovf} \
            if ent.ovf else {}
        self.tau_f = min((x.tau_f for x in sk), default=1.0)
        self.tau_q = min((x.tau_q for x in sk), default=1.0)
        ch_dst = np.frombuffer(t.channels.dst, dtype=np.int64)
        ch_long = np.frombuffer(t.channels.long, dtype=np.int8)
        ch = self.f["ch"].astype(np.int64)
        self.dst = ch_dst[ch]
        self.discrete = ch_long[ch] == 0
        self.qid = (self.d["q"] & Q_MASK).astype(np.int64)
        self.nx = (self.d["q"] & NX_BIT) != 0
        self.dst_u = np.unique(self.dst)
        self.q_u = np.unique(self.qid)

    @property
    def sampled(self) -> bool:
        return bool(self.sketches)


# ---------------------------------------------------------------------------- store

class WindowStore:
    """Per-tenant, per-entity hopping windows over the observation stream.

    ``window`` is the context length (``"5m"``, ``"15m"`` or ``"24h"``); ``hop`` is the
    re-evaluation step (defaults to ``1h`` for ``24h`` windows, else the window itself)
    and must divide the window. ``ioc_bundle``, when given, fills ``ioc_contacts``;
    ``retain_bundle`` (defaults to ``ioc_bundle``) names destinations that are never
    sampled away when a hop exceeds ``limits``. ``max_source_event_ids`` caps the evidence
    ids carried per feature vector (``None``: every id, unbounded memory).
    """

    def __init__(self, window: WindowName = "24h", hop: timedelta | None = None, *,
                 allowed_lateness: timedelta = timedelta(minutes=2),
                 max_future_skew: timedelta = timedelta(minutes=10),
                 min_population: int = DEFAULT_MIN_POPULATION,
                 max_source_event_ids: int | None = DEFAULT_MAX_SOURCE_EVENT_IDS,
                 ioc_bundle: "IOCBundle | None" = None,
                 retain_bundle: "IOCBundle | None" = None,
                 limits: StateLimits | None = None):
        if window not in WINDOW_SECONDS:
            raise ValueError(f"unsupported window {window!r}")
        self.window: WindowName = window
        self.window_s = WINDOW_SECONDS[window]
        if hop is None:
            hop = timedelta(hours=1) if window == "24h" else timedelta(seconds=self.window_s)
        hop_s = int(hop.total_seconds())
        if hop_s <= 0 or self.window_s % hop_s:
            raise ValueError("hop must be positive and divide the window length")
        if max_source_event_ids is not None and max_source_event_ids < 0:
            raise ValueError("max_source_event_ids must be >= 0 or None")
        self.hop_s = hop_s
        self.n_bins = self.window_s // hop_s
        self.lateness_s = allowed_lateness.total_seconds()
        self.max_future_skew = max_future_skew
        self.min_population = min_population
        self.max_ids = max_source_event_ids
        self.ids_per_bin: int | None = None if max_source_event_ids is None else \
            (0 if max_source_event_ids == 0 else -(-max_source_event_ids // self.n_bins))
        self.limits = limits or StateLimits()
        self.stats = WindowStats()
        self._tenants: dict[str, _Tenant] = {}
        self._ioc_bundle: "IOCBundle | None" = ioc_bundle
        self._retain: "IOCBundle | None" = retain_bundle

    # ------------------------------------------------------------------ bundles
    @property
    def ioc_bundle(self) -> "IOCBundle | None":
        return self._ioc_bundle

    @ioc_bundle.setter
    def ioc_bundle(self, bundle: "IOCBundle | None") -> None:
        self._ioc_bundle = bundle
        self._repin()

    @property
    def retain_bundle(self) -> "IOCBundle | None":
        return self._retain if self._retain is not None else self._ioc_bundle

    @retain_bundle.setter
    def retain_bundle(self, bundle: "IOCBundle | None") -> None:
        self._retain = bundle
        self._repin()

    def _pin_ip(self, ip: str) -> bool:
        b = self.retain_bundle
        return b is not None and bool(b.for_ip(ip))

    def _pin_name(self, q: str) -> bool:
        b = self.retain_bundle
        return b is not None and bool(b.for_domain(q))

    def _repin(self) -> None:
        """Recompute pin flags of every live key after a bundle change."""
        for t in self._tenants.values():
            for voc, fn in ((t.ips, self._pin_ip), (t.names, self._pin_name)):
                for i, key in enumerate(voc.items):
                    if key is not None:
                        voc.pinned[i] = 1 if fn(str(key)) else 0
            ch = t.channels
            for i, key in enumerate(ch.items):
                if key is not None:
                    ch.pinned[i] = t.ips.pinned[ch.dst[i]]

    # ------------------------------------------------------------------ ingest
    def update(self, event: ObservationEvent) -> list[FeatureVector]:
        """Fold one event in; return feature vectors of windows it closed (possibly none)."""
        if event.entity_pseudonym is None or (event.flow is None and event.dns is None):
            self.stats.rejected += 1
            return []
        observed = _utc(event.observed_at)
        if observed > _utc(event.ingested_at) + self.max_future_skew:
            # a timestamp from the future would advance the watermark and close windows early
            self.stats.rejected += 1
            return []
        ts = observed.timestamp()
        k = int(ts // self.hop_s)
        t = self._tenants.get(event.tenant_id)
        if t is None:
            t = _Tenant(first_ts=ts, watermark=ts - self.lateness_s, next_boundary_idx=k)
            self._tenants[event.tenant_id] = t
        self.stats.events += 1
        if k < t.emitted_idx:
            if k < t.emitted_idx - self.n_bins + 1:
                self.stats.dropped_late += 1
                return []
            self.stats.late_events += 1
        t.first_ts = min(t.first_ts, ts)
        ent = t.entities.get(event.entity_pseudonym)
        if ent is None:
            ent = t.entities[event.entity_pseudonym] = _Entity()
        if event.device_class:
            ent.device_class = event.device_class
        self._fold(t, ent, event, ts, k)
        if event.flow is not None:
            t.has_flow = True
        if event.dns is not None:
            t.has_dns = True
        lim = self.limits
        if len(ent.pf) > 8 * lim.flow_events_per_bin or len(ent.pd) > 6 * lim.dns_events_per_bin \
                or len(ent.pa) > 6 * lim.answers_per_bin:
            self._compact(t, ent, self._keep_from(t))
        t.watermark = max(t.watermark, ts - self.lateness_s)
        return self._advance(event.tenant_id, t, t.watermark)

    def _fold(self, t: _Tenant, ent: _Entity, ev: ObservationEvent, ts: float, k: int) -> None:
        acc = ent.hot.get(k)
        if acc is None:
            if k not in ent.slots:
                t.bin_refs[k] = t.bin_refs.get(k, 0) + 1
            acc = ent.hot[k] = [0.0] * NS
        cap = self.ids_per_bin
        if cap != 0:
            self._keep_id(ent, k, ev.event_id, cap)
        tag = (ev.collection_authorization_id, ev.source_id)
        bins = ent.tags.get(tag)
        if bins is None:
            ent.tags[tag] = [k]
        elif k not in bins:
            bins.append(k)
        f = ev.flow
        if f is not None:
            acc[S_NF] += 1
            dst_ip = f.dst_ip
            dst = t.ips.intern(dst_ip, k, lambda: dst_ip, lambda: self._pin_ip(dst_ip))
            if f.protocol == "tcp":
                acc[S_TCP] += 1
            elif f.protocol == "udp":
                acc[S_UDP] += 1
            total: int | None = None
            if f.bytes_out is not None and f.bytes_in is not None:
                acc[S_BK] += 1
                acc[S_BO] += f.bytes_out
                acc[S_BI] += f.bytes_in
                total = f.bytes_out + f.bytes_in
                if total < SMALL_FLOW_BYTES:
                    acc[S_SMALL] += 1
            elif f.bytes_out is not None:
                acc[S_BO] += f.bytes_out
            elif f.bytes_in is not None:
                acc[S_BI] += f.bytes_in
            if f.packets_in is not None or f.bytes_in is not None:
                acc[S_ZK] += 1
                if (f.packets_in == 0) or (f.bytes_in == 0):
                    acc[S_ZR] += 1
            dur = f.duration_ms
            if f.packets_out is not None and dur is not None and dur >= 1000:
                pps = f.packets_out / (dur / 1000.0)
                if pps > acc[S_PPS]:
                    acc[S_PPS] = pps
            long = dur is not None and dur >= LONG_FLOW_MS
            if long:
                acc[S_LONG] += 1
            port = f.dst_port if f.dst_port is not None else -1
            ch = t.channels.intern_channel(dst, dst_ip, port, f.protocol, long, k, bool(t.ips.pinned[dst]))
            size = NO_SIZE if total is None or long else min(total, NO_SIZE - 1)
            ent.pf.extend((k, ts, ch, size))
        d = ev.dns
        if d is not None:
            acc[S_ND] += 1
            q = normalize_name(d.qname)
            qi = t.names.intern(q, k, lambda: q, lambda: self._pin_name(q))
            if d.rcode.upper() == "NXDOMAIN":
                acc[S_NX] += 1
                qi |= NX_BIT
            ent.pd.extend((k, ts, qi))
            if d.answers:
                qa = qi & Q_MASK
                for ip in d.answers:
                    ii = t.ips.intern(ip, k, lambda ip=ip: ip, lambda ip=ip: self._pin_ip(ip))
                    ent.pa.extend((k, qa, ii))

    @staticmethod
    def _keep_id(ent: _Entity, k: int, event_id: str, cap: int | None) -> None:
        buf = ent.ids.get(k)
        if buf is None:
            buf = ent.ids[k] = bytearray()
        if cap is not None and len(buf) >= 16 * cap:
            return
        raw = _uuid_bytes(event_id)
        if raw is None:
            if ent.raw_ids is None:
                ent.raw_ids = {}
            ent.raw_ids.setdefault(k, []).append(event_id)
            raw = bytes(16)                      # marker: next raw id of this hop
        buf += raw

    def flush(self, now: datetime, tenant_id: str | None = None) -> list[FeatureVector]:
        """Close every window ending at or before ``now`` (ignores allowed lateness)."""
        now_ts = _utc(now).timestamp()
        out: list[FeatureVector] = []
        for tid, t in list(self._tenants.items()):
            if tenant_id is not None and tid != tenant_id:
                continue
            t.watermark = max(t.watermark, now_ts)
            out.extend(self._advance(tid, t, now_ts))
        return out

    def contacts_for(self, fv: FeatureVector) -> ContactSummary | None:
        """Contacts of the window that produced ``fv`` (available for the latest closed window only).

        Built on demand from the packed hops (no per-line contact set is kept between
        windows), so it reflects the events folded in when the window closed.
        """
        t = self._tenants.get(fv.tenant_id)
        if t is None or t.last_boundary is None:
            return None
        end_idx = t.last_boundary
        if _utc(fv.window_end).timestamp() != end_idx * self.hop_s:
            return None
        ent = t.entities.get(fv.entity_pseudonym)
        if ent is None or ent.last_emit != end_idx:
            return None
        w = _View(self, t, fv.entity_pseudonym, ent, end_idx - self.n_bins, end_idx)
        if not w.slots:
            return None
        return self._contact_summary(fv.tenant_id, t, w, end_idx)

    def entity_count(self, tenant_id: str) -> int:
        t = self._tenants.get(tenant_id)
        if t is None:
            return 0
        lo = t.emitted_idx - self.n_bins + 1
        return sum(1 for e in t.entities.values() if e.live(lo))

    def state_bytes(self, tenant_id: str | None = None) -> dict[str, int]:
        """Accounting of window state (``sys.getsizeof`` based, allocator slack excluded).

        ``packed``: numpy record arrays of all lines; ``line_overhead``: per-line Python
        objects (containers, array headers, evidence ids, pending events); ``vocab``: the
        tenant vocabularies shared by every line; ``lines``: entities held.
        """
        lines = packed = overhead = vocab = keys = 0
        shared = {id(x) for x in (_EMPTY_F, _EMPTY_D, _EMPTY_A, _ZERO_OFF, _EMPTY_SC)}
        for tid, t in self._tenants.items():
            if tenant_id is not None and tid != tenant_id:
                continue
            for e in t.entities.values():
                lines += 1
                overhead += sys.getsizeof(e) + sys.getsizeof(e.slots) + sys.getsizeof(e.ids) \
                    + sys.getsizeof(e.tags) + sys.getsizeof(e.hot) + sys.getsizeof(e.pf) + sys.getsizeof(e.pd) \
                    + sys.getsizeof(e.pa)
                for arr in (e.sc, e.f, e.fo, e.d, e.do, e.a, e.ao, e.persist, e.hopbits):
                    if arr is not None and id(arr) not in shared:
                        packed += arr.nbytes
                        overhead += sys.getsizeof(arr) - arr.nbytes
                overhead += sum(sys.getsizeof(b) for b in e.ids.values())
                overhead += sum(sys.getsizeof(k) + sys.getsizeof(b) for k, b in e.tags.items())
                overhead += sum(sys.getsizeof(r) for r in e.hot.values())
                if e.ovf:
                    overhead += sys.getsizeof(e.ovf) + sum(
                        200 + (x.hist.nbytes if x.hist is not None else 0) + x.ports.nbytes + 100 * len(x.heavy)
                        for x in e.ovf.values())
            for voc in (t.ips, t.names, t.channels):
                keys += len(voc.index)
                vocab += sys.getsizeof(voc.index) + sys.getsizeof(voc.items) + sys.getsizeof(voc.free)
                vocab += sum(sys.getsizeof(k) for k in voc.index)
                vocab += sum(sys.getsizeof(a) for a in (voc.last, voc.hash, voc.pinned))
            vocab += sys.getsizeof(t.names.entropy) + sys.getsizeof(t.ips.entropy)
            vocab += sum(sys.getsizeof(a) for a in (t.channels.dst, t.channels.port, t.channels.long))
        return {"lines": lines, "packed": packed, "line_overhead": overhead, "vocab": vocab, "vocab_keys": keys}

    # ------------------------------------------------------------------ packing
    def _keep_from(self, t: _Tenant) -> int:
        """Oldest hop to retain: the live window plus the hop just closed (contacts on demand)."""
        return t.emitted_idx - self.n_bins

    def _unref(self, t: _Tenant, k: int) -> None:
        n = t.bin_refs.get(k, 0) - 1
        if n > 0:
            t.bin_refs[k] = n
        else:
            t.bin_refs.pop(k, None)

    def _compact(self, t: _Tenant, ent: _Entity, keep_from: int) -> None:
        """Pack pending events into the entity's arrays and drop hops older than ``keep_from``."""
        if not ent.hot and (not ent.slots or ent.slots[0] >= keep_from):
            return
        old = ent.slots
        old_pos = {s: i for i, s in enumerate(old)}
        for s in old:
            if s < keep_from:
                self._unref(t, s)
        for s in ent.hot:
            if s < keep_from and s not in old_pos:
                self._unref(t, s)
        new_slots = sorted({s for s in old if s >= keep_from} | {s for s in ent.hot if s >= keep_from})
        pf = _group(ent.pf, 4)
        pd = _group(ent.pd, 3)
        pa = _group(ent.pa, 3)
        hop_ms = self.hop_s * 1000
        lim = self.limits
        f_parts: list[np.ndarray] = []
        d_parts: list[np.ndarray] = []
        a_parts: list[np.ndarray] = []
        fo = np.zeros(len(new_slots) + 1, dtype=np.int64)
        do = np.zeros(len(new_slots) + 1, dtype=np.int64)
        ao = np.zeros(len(new_slots) + 1, dtype=np.int64)
        sc = np.zeros((len(new_slots), NS), dtype=np.float64)
        ip_hash = np.frombuffer(t.ips.hash, dtype=np.float64)
        ip_pin = np.frombuffer(t.ips.pinned, dtype=np.int8)
        ch_dst = np.frombuffer(t.channels.dst, dtype=np.int64)
        ch_port = np.frombuffer(t.channels.port, dtype=np.int64)
        ch_long = np.frombuffer(t.channels.long, dtype=np.int8)
        q_hash = np.frombuffer(t.names.hash, dtype=np.float64)
        q_pin = np.frombuffer(t.names.pinned, dtype=np.int8)
        for j, s in enumerate(new_slots):
            i = old_pos.get(s)
            acc = ent.hot.get(s)
            if i is not None:
                sc[j] = ent.sc[i]
            if acc is not None:
                row = sc[j]
                peak = max(row[S_PPS], acc[S_PPS])
                row += np.asarray(acc)
                row[S_PPS] = peak
            # ---------------------------------------------------------- flows
            of = ent.f[ent.fo[i]:ent.fo[i + 1]] if i is not None else _EMPTY_F
            nf = pf.get(s)
            piece = of
            if nf is not None:
                new = np.empty(len(nf), dtype=FLOW_DT)
                new["off"] = _offsets(nf[:, 1], s, self.hop_s, hop_ms)
                new["ch"] = nf[:, 2].astype(np.uint32)
                new["size"] = nf[:, 3].astype(np.uint32)
                piece = np.concatenate([of, new]) if len(of) else new
                sk = ent.ovf.get(s) if ent.ovf else None
                if sk is not None or len(piece) > lim.flow_events_per_bin:
                    first = sk is None
                    sk = self._sketch(ent, s)
                    run = piece if first else new
                    rch = run["ch"].astype(np.int64)
                    disc = ch_long[rch] == 0
                    sk.add_starts(s * float(self.hop_s) + run["off"][disc] / 1000.0)
                    sk.add_flows(ch_dst[rch], ch_port[rch])
                    if len(piece) > lim.flow_events_per_bin:
                        keep, tau = self._select(ent, s, ch_dst[piece["ch"].astype(np.int64)], piece["off"],
                                                 ip_hash, ip_pin, lim.flow_events_per_bin)
                        piece = piece[keep]
                        sk.tau_f = min(sk.tau_f, tau)
            f_parts.append(piece)
            fo[j + 1] = fo[j] + len(piece)
            # ---------------------------------------------------------- dns
            od = ent.d[ent.do[i]:ent.do[i + 1]] if i is not None else _EMPTY_D
            nd = pd.get(s)
            dpiece = od
            if nd is not None:
                new_d = np.empty(len(nd), dtype=DNS_DT)
                new_d["off"] = _offsets(nd[:, 1], s, self.hop_s, hop_ms)
                new_d["q"] = nd[:, 2].astype(np.uint32)
                dpiece = np.concatenate([od, new_d]) if len(od) else new_d
                if len(dpiece) > lim.dns_events_per_bin:
                    qid = (dpiece["q"] & Q_MASK).astype(np.int64)
                    keep, tau = self._select(ent, s, qid, dpiece["off"], q_hash, q_pin, lim.dns_events_per_bin)
                    dpiece = dpiece[keep]
                    sk = self._sketch(ent, s)
                    sk.tau_q = min(sk.tau_q, tau)
            d_parts.append(dpiece)
            do[j + 1] = do[j] + len(dpiece)
            # ---------------------------------------------------------- answers
            oa = ent.a[ent.ao[i]:ent.ao[i + 1]] if i is not None else _EMPTY_A
            na = pa.get(s)
            apiece = oa
            if na is not None:
                new_a = np.empty(len(na), dtype=ANS_DT)
                new_a["q"] = na[:, 1].astype(np.uint32)
                new_a["ip"] = na[:, 2].astype(np.uint32)
                apiece = np.concatenate([oa, new_a]) if len(oa) else new_a
                packed = (apiece["q"].astype(np.uint64) << np.uint64(32)) | apiece["ip"].astype(np.uint64)
                _, first_idx = np.unique(packed, return_index=True)
                apiece = apiece[np.sort(first_idx)]
                sk = ent.ovf.get(s) if ent.ovf else None
                if sk is not None and sk.tau_q < 1.0:
                    # answers follow the hop's name sample
                    apiece = apiece[np.isin(apiece["q"], dpiece["q"] & Q_MASK)]
                if len(apiece) > lim.answers_per_bin:
                    h = q_hash[apiece["q"].astype(np.int64)]
                    apiece = apiece[np.sort(np.argsort(h, kind="stable")[:lim.answers_per_bin])]
            a_parts.append(apiece)
            ao[j + 1] = ao[j] + len(apiece)
        del ip_hash, ip_pin, ch_dst, ch_port, ch_long, q_hash, q_pin
        ent.slots = new_slots
        ent.sc = sc
        ent.f = np.concatenate(f_parts) if len(f_parts) > 1 else (f_parts[0].copy() if f_parts else _EMPTY_F)
        ent.fo = fo
        ent.d = np.concatenate(d_parts) if len(d_parts) > 1 else (d_parts[0].copy() if d_parts else _EMPTY_D)
        ent.do = do
        ent.a = np.concatenate(a_parts) if len(a_parts) > 1 else (a_parts[0].copy() if a_parts else _EMPTY_A)
        ent.ao = ao
        ent.hot = {}
        ent.pf = array("d")
        ent.pd = array("d")
        ent.pa = array("d")
        for k in [k for k in ent.ids if k < keep_from]:
            del ent.ids[k]
        if ent.raw_ids:
            for k in [k for k in ent.raw_ids if k < keep_from]:
                del ent.raw_ids[k]
        if ent.ovf:
            for k in [k for k in ent.ovf if k < keep_from]:
                del ent.ovf[k]
        for tag in list(ent.tags):
            kept = [b for b in ent.tags[tag] if b >= keep_from]
            if kept:
                ent.tags[tag] = kept
            else:
                del ent.tags[tag]

    def _sketch(self, ent: _Entity, s: int) -> _SlotSketch:
        if ent.ovf is None:
            ent.ovf = {}
        sk = ent.ovf.get(s)
        if sk is None:
            sk = ent.ovf[s] = _SlotSketch()
            self.stats.sampled_bins += 1
        return sk

    def _select(self, ent: _Entity, s: int, keys: np.ndarray, off: np.ndarray, hashes: np.ndarray,
                pinned: np.ndarray, cap: int) -> tuple[np.ndarray, float]:
        """Events to keep in an overflowing hop.

        Keys (destinations / names) are kept whole or not at all, except that a key keeps at
        most ``cap // 8`` events (its earliest, so the kept gaps are true gaps). Kept, in
        order: pinned keys; keys that recur over earlier hops (most persistent first, up to
        half the cap: a beacon recurs every hop, a browsing destination rarely does); then
        the bottom-k keys by hash. Returns the event mask and ``tau``: every key hashed below
        ``tau`` is kept (the coordinated-sample threshold behind the distinct-count estimates).
        """
        uk, inv, full = np.unique(keys, return_inverse=True, return_counts=True)
        per_key = max(4, cap // 8)
        cnt = np.minimum(full, per_key)
        h = hashes[uk]
        bucket = (h * _PERSIST).astype(np.int64)
        persistence = self._persistence(ent, s, bucket)
        keep_key = pinned[uk] == 1
        budget = cap - int(cnt[keep_key].sum())
        rec = np.flatnonzero((persistence >= _PERSIST_MIN) & ~keep_key)
        if len(rec) and budget > 0:
            order = rec[np.lexsort((h[rec], -persistence[rec].astype(np.int64)))]
            take = order[np.cumsum(cnt[order]) <= min(budget, cap // 2)]
            keep_key[take] = True
            budget -= int(cnt[take].sum())
        rest = np.flatnonzero(~keep_key)
        tau = 1.0
        if len(rest):
            order = rest[np.argsort(h[rest], kind="stable")]
            fits = np.cumsum(cnt[order]) <= max(0, budget)
            n_fit = int(np.argmin(fits)) if not fits.all() else len(order)
            keep_key[order[:n_fit]] = True
            if n_fit < len(order):
                tau = float(h[order[n_fit]])
        keep = keep_key[inv]
        if (full > per_key).any():
            o = np.lexsort((off, inv))
            first = np.zeros(len(uk) + 1, dtype=np.int64)
            first[1:] = np.cumsum(full)
            rank = np.empty(len(keys), dtype=np.int64)
            rank[o] = np.arange(len(keys)) - first[inv[o]]
            keep &= rank < per_key
        return keep, tau

    @staticmethod
    def _persistence(ent: _Entity, s: int, bucket: np.ndarray) -> np.ndarray:
        """Recent earlier hops in which each key's hash bucket was seen; then count hop ``s``."""
        if ent.persist is None or ent.hopbits is None:
            ent.persist = np.zeros(_PERSIST, dtype=np.uint8)
            ent.hopbits = np.zeros(_PERSIST // 8, dtype=np.uint8)
            ent.seen_k = s
        elif s > ent.seen_k:
            halvings = s // _PERSIST_HALF_LIFE - ent.seen_k // _PERSIST_HALF_LIFE
            if halvings:
                ent.persist >>= np.uint8(min(halvings, 8))
            ent.hopbits[:] = 0
            ent.seen_k = s
        out = ent.persist[bucket].copy()
        if s == ent.seen_k:
            byte, bit = bucket >> 3, (bucket & 7).astype(np.uint8)
            new = ((ent.hopbits[byte] >> bit) & 1) == 0
            nb = np.unique(bucket[new])
            ent.persist[nb] = np.minimum(ent.persist[nb].astype(np.int64) + 1, 255).astype(np.uint8)
            np.bitwise_or.at(ent.hopbits, nb >> 3, (np.uint8(1) << (nb & 7).astype(np.uint8)))
            if out.size:
                # within the current hop, earlier runs already counted this hop: do not count it as "earlier"
                out = out - (~new).astype(np.uint8) * (out > 0)
        return out

    # ------------------------------------------------------------------ emission
    def _advance(self, tenant_id: str, t: _Tenant, watermark: float) -> list[FeatureVector]:
        out: list[FeatureVector] = []
        while (t.next_boundary_idx + 1) * self.hop_s <= watermark:
            end_idx = t.next_boundary_idx + 1           # window = bins [end_idx - n_bins, end_idx)
            live_from = t.emitted_idx - self.n_bins + 1
            idxs = [k for k in t.bin_refs if k >= live_from]
            if not idxs:
                # no buffered data: jump straight to the watermark
                for eid in [e for e, ent in t.entities.items() if not ent.slots and not ent.hot]:
                    del t.entities[eid]
                t.next_boundary_idx = max(t.next_boundary_idx, int(watermark // self.hop_s))
                t.emitted_idx = t.next_boundary_idx
                break
            oldest = min(idxs)
            if oldest >= end_idx:
                # gap before the buffered data: skip empty windows
                t.next_boundary_idx = oldest
                t.emitted_idx = oldest
                continue
            out.extend(self._close_window(tenant_id, t, end_idx, None))
            t.next_boundary_idx = end_idx
            t.emitted_idx = end_idx
        return out

    def _close_window(self, tenant_id: str, t: _Tenant, end_idx: int, ctx: _Context | None
                      ) -> list[FeatureVector]:
        """Pack, emit the window ending at ``end_idx`` (with ``ctx`` or the local population), retire."""
        keep_from = end_idx - self.n_bins
        for eid in list(t.entities):
            ent = t.entities[eid]
            self._compact(t, ent, keep_from)
            if not ent.slots:
                del t.entities[eid]
        for voc in (t.channels, t.ips, t.names):
            voc.evict(keep_from)
        out = self._emit(tenant_id, t, end_idx, ctx)
        t.last_boundary = end_idx
        return out

    def _views(self, t: _Tenant, end_idx: int) -> list[_View]:
        lo = end_idx - self.n_bins
        out = []
        for eid, ent in t.entities.items():
            i0 = bisect_left(ent.slots, lo)
            if i0 < len(ent.slots) and ent.slots[i0] < end_idx:
                out.append(_View(self, t, eid, ent, lo, end_idx))
        return out

    def _local_context(self, t: _Tenant, views: list[_View]) -> _Context:
        nip, nq = len(t.ips), len(t.names)
        ipc = np.bincount(np.concatenate([w.dst_u for w in views]), minlength=nip) if views else np.zeros(nip)
        qc = np.bincount(np.concatenate([w.q_u for w in views]), minlength=nq) if views else np.zeros(nq)
        return _Context(len(views), lambda ids: ipc[ids], lambda ids: qc[ids])

    def _emit(self, tenant_id: str, t: _Tenant, end_idx: int, ctx: _Context | None) -> list[FeatureVector]:
        views = self._views(t, end_idx)
        if not views:
            return []
        if ctx is None:
            ctx = self._local_context(t, views)
        lo = end_idx - self.n_bins
        window_end_ts = end_idx * self.hop_s
        window_start_ts = window_end_ts - self.window_s
        coverage_start = max(window_start_ts, t.first_ts)
        coverage_s = max(float(self.hop_s) / 60.0, window_end_ts - coverage_start)
        first_bin = max(lo, int(t.first_ts // self.hop_s))
        population = ctx.population
        rare_cut = max(2, math.ceil(0.02 * population))
        prevalence_ok = population >= self.min_population
        window_end = datetime.fromtimestamp(window_end_ts, tz=timezone.utc)
        out = []
        for w in views:
            values = self._features(w, t, coverage_s, first_bin, end_idx, ctx, rare_cut, prevalence_ok)
            if self._ioc_bundle is not None:
                values["ioc_contacts"] = float(self._ioc_bundle.count_contacts(
                    self._ioc_candidates(tenant_id, t, w, window_end), window_end))
            n_events = int(w.sc[:, S_NF].sum() + w.sc[:, S_ND].sum())
            w.ent.last_emit = end_idx
            out.append(FeatureVector(
                tenant_id=tenant_id, entity_pseudonym=w.eid, device_class=w.ent.device_class or "unknown",
                window=self.window, window_end=window_end, values=values,
                missing={k: v is None for k, v in values.items()}, event_count=n_events,
                source_event_ids=self._window_ids(w.ent, w.slots)))
        self.stats.windows_emitted += len(out)
        return out

    def _window_ids(self, ent: _Entity, slots: list[int]) -> list[str]:
        if self.ids_per_bin == 0:
            return []
        ids: list[str] = []
        for s in slots:
            buf = ent.ids.get(s)
            if not buf:
                continue
            raw = iter(ent.raw_ids.get(s, ())) if ent.raw_ids else iter(())
            for o in range(0, len(buf), 16):
                b = bytes(buf[o:o + 16])
                ids.append(next(raw) if b == _RAW_MARKER else str(uuid.UUID(bytes=b)))
            if self.max_ids is not None and len(ids) >= self.max_ids:
                break
        return ids if self.max_ids is None else ids[: self.max_ids]

    def _ioc_candidates(self, tenant_id: str, t: _Tenant, w: _View, window_end: datetime) -> ContactSummary:
        """The window's contacts restricted to keys any bundle indicator names (all that can match)."""
        cs = ContactSummary(tenant_id, w.eid, window_end - timedelta(seconds=self.window_s), window_end)
        ip_pin = np.frombuffer(t.ips.pinned, dtype=np.int8)
        q_pin = np.frombuffer(t.names.pinned, dtype=np.int8)
        for i in w.dst_u[ip_pin[w.dst_u] == 1].tolist():
            cs.dst_ips[str(t.ips.items[i])] = 1
        for i in w.q_u[q_pin[w.q_u] == 1].tolist():
            cs.qnames[str(t.names.items[i])] = 1
        return cs

    def _contact_summary(self, tenant_id: str, t: _Tenant, w: _View, end_idx: int) -> ContactSummary:
        we = datetime.fromtimestamp(end_idx * self.hop_s, tz=timezone.utc)
        cs = ContactSummary(tenant_id, w.eid, we - timedelta(seconds=self.window_s), we, sampled=w.sampled)
        if len(w.dst):
            o = np.lexsort((w.ft, w.dst))
            dst, ft = w.dst[o], w.ft[o]
            u, start, cnt = np.unique(dst, return_index=True, return_counts=True)
            for i, a, c in zip(u.tolist(), start.tolist(), cnt.tolist()):
                ip = str(t.ips.items[i])
                cs.dst_ips[ip] = c
                cs.ip_times[ip] = (float(ft[a]), float(ft[a + c - 1]))
        if len(w.qid):
            o = np.lexsort((w.dt, w.qid))
            qid, dt = w.qid[o], w.dt[o]
            u, start, cnt = np.unique(qid, return_index=True, return_counts=True)
            for i, a, c in zip(u.tolist(), start.tolist(), cnt.tolist()):
                q = str(t.names.items[i])
                cs.qnames[q] = c
                cs.qname_times[q] = (float(dt[a]), float(dt[a + c - 1]))
        for qi, ii in zip(w.a["q"].tolist(), w.a["ip"].tolist()):
            cs.answers.setdefault(str(t.names.items[qi]), set()).add(str(t.ips.items[ii]))
        lo = end_idx - self.n_bins
        for (auth, src), bins in w.ent.tags.items():
            if any(lo <= b < end_idx for b in bins):
                cs.authorization_ids.add(auth)
                cs.source_ids.add(src)
        return cs

    # ------------------------------------------------------------------ features
    def _features(self, w: _View, t: _Tenant, coverage_s: float, first_bin: int, end_idx: int, ctx: _Context,
                  rare_cut: int, prevalence_ok: bool) -> dict[str, float | None]:
        v: dict[str, float | None] = {name: None for name in FEATURE_NAMES}
        hours = coverage_s / 3600.0
        v["coverage_h"] = round(hours, 4)
        sc = w.sc
        n_flows = int(sc[:, S_NF].sum())
        n_dns = int(sc[:, S_ND].sum())
        covered_bins = max(1, end_idx - first_bin)
        by_idx = {s: i for i, s in enumerate(w.slots)}
        last = by_idx.get(end_idx - 1)
        population = ctx.population

        # ---------------------------------------------------------------- volume / flows
        if t.has_flow:
            v["flow_rate_h"] = n_flows / hours
            v["active_bin_frac"] = min(1.0, int(np.count_nonzero(sc[:, S_NF])) / covered_bins)
            v["recent_flows_log"] = _log10p(sc[last, S_NF] if last is not None else 0)
            if last is None:
                v["recent_unique_dst"] = 0.0
            else:
                sk = w.sketches.get(end_idx - 1)
                v["recent_unique_dst"] = self._distinct(t, np.unique(w.dst[w.fk == end_idx - 1]),
                                                        sk.tau_f if sk is not None else 1.0)
            series_f = [float(sc[by_idx[k], S_NF]) if k in by_idx else 0.0 for k in range(first_bin, end_idx)]
            if len(series_f) >= 7:
                v["baseline_dev_flows"] = _robust_z(_log10p(series_f[-1]), [_log10p(x) for x in series_f[:-1]])
        bytes_known = int(sc[:, S_BK].sum())
        if t.has_flow and n_flows:
            bo = float(sc[:, S_BO].sum())
            bi = float(sc[:, S_BI].sum())
            if bytes_known:
                v["bytes_out_rate_log"] = _log10p(bo / hours)
                v["bytes_in_rate_log"] = _log10p(bi / hours)
                v["out_ratio"] = bo / (bo + bi) if bo + bi > 0 else None
                v["small_flow_frac"] = float(sc[:, S_SMALL].sum()) / bytes_known
                v["recent_bytes_out_log"] = _log10p(sc[last, S_BO] if last is not None else 0)
                heavy = int(np.count_nonzero((sc[:, S_BO] > sc[:, S_BI]) & (sc[:, S_BO] > OUT_HEAVY_BYTES)))
                v["out_heavy_bin_frac"] = min(1.0, heavy / covered_bins)
                series_b = [float(sc[by_idx[k], S_BO]) if k in by_idx else 0.0 for k in range(first_bin, end_idx)]
                if len(series_b) >= 7:
                    v["baseline_dev_bytes_out"] = _robust_z(_log10p(series_b[-1]),
                                                            [_log10p(x) for x in series_b[:-1]])
            ch_port = np.frombuffer(t.channels.port, dtype=np.int64)
            ud, cd = np.unique(w.dst, return_counts=True)
            ports = np.unique(ch_port[w.f["ch"].astype(np.int64)])
            ports = ports[ports >= 0]
            if w.sketches:
                # sampled hop(s): exact counts for the top talkers, KMV estimates for the rest
                cd = cd.astype(np.float64)
                heavy = np.zeros(len(ud), dtype=bool)
                for s, sk in w.sketches.items():
                    if not sk.heavy:
                        continue
                    ids = np.fromiter(sk.heavy, dtype=np.int64, count=len(sk.heavy))
                    exact = np.fromiter(sk.heavy.values(), dtype=np.float64, count=len(sk.heavy))
                    pos = np.searchsorted(ud, ids)
                    ok = (pos < len(ud)) & (ud[np.minimum(pos, len(ud) - 1)] == ids)
                    kept = np.bincount(np.searchsorted(ud, w.dst[(w.fk == s) & np.isin(w.dst, ids)]),
                                       minlength=len(ud))
                    cd[pos[ok]] += exact[ok] - kept[pos[ok]]
                    heavy[pos[ok]] = True
                    ports = np.union1d(ports, sk.ports)
                v["unique_dst_ip"] = self._distinct(t, ud, w.tau_f)
                v["unique_dst_port"] = float(len(ports))
                ip_hash = np.frombuffer(t.ips.hash, dtype=np.float64)
                c_heavy = cd[heavy]
                c_rest = cd[~heavy & (ip_hash[ud] < w.tau_f)]
                slog = math.fsum(c * math.log2(max(c, 1.0)) for c in c_heavy.tolist()) + \
                    math.fsum(c * math.log2(max(c, 1.0)) for c in c_rest.tolist()) / w.tau_f
                v["dst_entropy"] = max(0.0, math.log2(n_flows) - slog / n_flows)
                v["max_dst_share"] = min(1.0, float(cd.max()) / n_flows) if len(cd) else 0.0
            else:
                v["unique_dst_ip"] = float(len(ud))
                v["unique_dst_port"] = float(len(ports))
                v["dst_entropy"] = _shannon(sorted(cd.tolist()))      # canonical order: shard == single node
                v["max_dst_share"] = float(cd.max()) / n_flows if len(cd) else 0.0
            v["tcp_frac"] = float(sc[:, S_TCP].sum()) / n_flows
            v["udp_frac"] = float(sc[:, S_UDP].sum()) / n_flows
            zk = float(sc[:, S_ZK].sum())
            v["zero_reply_frac"] = float(sc[:, S_ZR].sum()) / zk if zk else None
            v["long_flow_frac"] = float(sc[:, S_LONG].sum()) / n_flows
            v["peak_out_pps_log"] = _log10p(float(sc[:, S_PPS].max()))
            self._timing(v, w, ctx, population, prevalence_ok, covered_bins, t)
            if prevalence_ok:
                discrete = np.unique(w.dst[w.discrete])
                if len(discrete):
                    v["rare_dst_frac"] = float(np.count_nonzero(ctx.ip(discrete) <= rare_cut)) / len(discrete)

        # ---------------------------------------------------------------- DNS
        if t.has_dns:
            v["dns_rate_h"] = n_dns / hours
            if n_dns:
                nx = float(sc[:, S_NX].sum())
                nx_names = np.unique(w.qid[w.nx])
                v["nxdomain_rate"] = nx / n_dns
                q_u = w.q_u
                if w.tau_q < 1.0:
                    q_hash = np.frombuffer(t.names.hash, dtype=np.float64)
                    v["nx_unique"] = float(max(len(nx_names),
                                               round(int((q_hash[nx_names] < w.tau_q).sum()) / w.tau_q)))
                    v["qname_unique"] = float(max(len(q_u), round(int((q_hash[q_u] < w.tau_q).sum()) / w.tau_q)))
                else:
                    v["nx_unique"] = float(len(nx_names))
                    v["qname_unique"] = float(len(q_u))
                if len(nx_names):
                    v["nx_name_entropy"] = math.fsum(t.names.label_entropy(i) for i in nx_names.tolist()) \
                        / len(nx_names)
                if prevalence_ok and len(q_u):
                    v["rare_qname_frac"] = float(np.count_nonzero(ctx.q(q_u) <= rare_cut)) / len(q_u)
                periodic = self._periodic_names(w, covered_bins)
                v["periodic_qnames"] = float(len(periodic))
                if prevalence_ok and len(periodic):
                    v["periodic_qname_prevalence"] = float(ctx.q(np.asarray(periodic, dtype=np.int64)).min()) \
                        / population
        return v

    @staticmethod
    def _distinct(t: _Tenant, ud: np.ndarray, tau: float) -> float:
        """Distinct destinations: exact, or the KMV estimate when the sample threshold ``tau`` < 1."""
        if tau >= 1.0:
            return float(len(ud))
        ip_hash = np.frombuffer(t.ips.hash, dtype=np.float64)
        return float(max(len(ud), round(int((ip_hash[ud] < tau).sum()) / tau)))

    def _duty(self, ks: np.ndarray, covered_bins: int) -> float:
        return min(1.0, len(np.unique(ks)) / covered_bins)

    def _periodic_names(self, w: _View, covered_bins: int) -> list[int]:
        """Names whose lookups recur on a regular schedule (resolver-cache driven check-ins)."""
        if len(w.qid) < MIN_CHANNEL_EVENTS:
            return []
        o = np.lexsort((w.dt, w.qid))
        qid, ts, ks = w.qid[o], w.dt[o], w.dk[o]
        u, start, cnt = np.unique(qid, return_index=True, return_counts=True)
        out = []
        for i in np.flatnonzero(cnt >= MIN_CHANNEL_EVENTS).tolist():
            a, n = int(start[i]), int(cnt[i])
            seg = ts[a:a + n]
            iv = np.diff(seg)
            iv = iv[iv >= 1.0]
            if len(iv) < MIN_CHANNEL_EVENTS - 1:
                continue
            med = float(np.median(iv))
            if 1.4826 * float(np.median(np.abs(iv - med))) / med <= PERIODIC_CV \
                    and self._duty(ks[a:a + n], covered_bins) >= MIN_DUTY:
                out.append(int(u[i]))
        return out

    def _timing(self, v: dict[str, float | None], w: _View, ctx: _Context, population: int,
                prevalence_ok: bool, covered_bins: int, t: _Tenant) -> None:
        disc = w.discrete
        if w.sketches:
            self._timing_sketched(v, w)
        else:
            starts = np.sort(w.ft[disc])
            gaps = np.diff(starts)
            gaps = gaps[gaps > 0]
            if len(gaps) >= 3:
                gs = np.sort(gaps).tolist()
                v["interval_p10_log"] = math.log10(max(0.001, _quantile(gs, 0.1)))
                v["interval_p50_log"] = math.log10(max(0.001, _quantile(gs, 0.5)))
                v["interval_p90_log"] = math.log10(max(0.001, _quantile(gs, 0.9)))
                mu = float(gaps.mean())
                sd = float(gaps.std())
                v["burstiness"] = (sd - mu) / (sd + mu) if sd + mu > 0 else 0.0
        if not disc.any():
            return
        ch = w.f["ch"].astype(np.int64)[disc]
        ts = w.ft[disc]
        ks = w.fk[disc]
        size = w.f["size"][disc]
        o = np.lexsort((ts, ch))
        ch, ts, ks, size = ch[o], ts[o], ks[o], size[o]
        u, start, cnt = np.unique(ch, return_index=True, return_counts=True)
        ch_dst = np.frombuffer(t.channels.dst, dtype=np.int64)
        ch_hash = np.frombuffer(t.channels.hash, dtype=np.float64)
        # candidate channels: (robust_cv, n, channel, median_period, median_bytes, duty)
        cands: list[tuple[float, int, int, float, float | None, float]] = []
        for i in np.flatnonzero(cnt >= MIN_CHANNEL_EVENTS).tolist():
            a, n = int(start[i]), int(cnt[i])
            iv = np.diff(ts[a:a + n])
            iv = iv[iv >= 1.0]
            if len(iv) < MIN_CHANNEL_EVENTS - 1:
                continue
            med = float(np.median(iv))
            mad = float(np.median(np.abs(iv - med)))
            sz = size[a:a + n]
            sz = sz[sz != NO_SIZE]
            cands.append((1.4826 * mad / med, n, int(u[i]), med,
                          float(np.median(sz)) if len(sz) else None, self._duty(ks[a:a + n], covered_bins)))
        if not cands:
            return
        # The reported channel is the *rarest periodic* one when prevalence is known
        # (a heartbeat to a popular service is normal; a periodic check-in to a
        # destination almost nobody else contacts is the beaconing signature), else
        # simply the most periodic one. Remaining ties resolve by channel hash (deterministic
        # across shards, unlike vocabulary ids).
        periodic = [c for c in cands if c[0] <= PERIODIC_CV and c[5] >= MIN_DUTY]
        if prevalence_ok and periodic:
            prev = ctx.ip(np.asarray([ch_dst[c[2]] for c in periodic], dtype=np.int64))
            best = min(zip(periodic, prev.tolist()), key=lambda cp: (cp[1], cp[0][0], -cp[0][1], ch_hash[cp[0][2]]))[0]
        else:
            best = min(cands, key=lambda c: (c[0], -c[1], ch_hash[c[2]]))
        rcv, n, chan, med, msize, duty = best
        v["beacon_duty"] = duty
        v["beacon_robust_cv"] = min(rcv, 10.0)
        v["beacon_period_log"] = math.log10(med)
        v["beacon_events"] = float(n)
        v["beacon_bytes_log"] = _log10p(msize) if msize is not None else None
        if prevalence_ok:
            v["beacon_dst_prevalence"] = float(ctx.ip(np.asarray([ch_dst[chan]], dtype=np.int64))[0]) / population

    def _timing_sketched(self, v: dict[str, float | None], w: _View) -> None:
        """Gap features when a hop of the window was sampled: merged histograms + exact moments."""
        hist = np.zeros(_H_BINS, dtype=np.int64)
        n, mean, m2 = 0, 0.0, 0.0
        prev_last: float | None = None

        def add(g: np.ndarray) -> None:
            nonlocal n, mean, m2
            g = g[g > 0]
            if not len(g):
                return
            hist[:] += np.bincount(_hbucket(g), minlength=_H_BINS)
            n2, mean2 = len(g), float(g.mean())
            m22 = float(((g - mean2) ** 2).sum())
            tot = n + n2
            delta = mean2 - mean
            m2 += m22 + delta * delta * n * n2 / tot
            mean += delta * n2 / tot
            n = tot

        disc = w.discrete
        for s in w.slots:
            sk = w.sketches.get(s)
            if sk is not None:
                if sk.n == 0 and not math.isfinite(sk.first):
                    continue
                first, last_ = sk.first, sk.last
                if sk.hist is not None:
                    hist += sk.hist
                    tot = n + sk.n
                    delta = sk.mean - mean
                    m2 += sk.m2 + delta * delta * n * sk.n / tot
                    mean += delta * sk.n / tot
                    n = tot
            else:
                st = np.sort(w.ft[(w.fk == s) & disc])
                if not len(st):
                    continue
                first, last_ = float(st[0]), float(st[-1])
                add(np.diff(st))
            if prev_last is not None:
                add(np.asarray([first - prev_last]))
            prev_last = last_
        if n >= 3:
            v["interval_p10_log"] = math.log10(max(0.001, _hist_quantile(hist, 0.1)))
            v["interval_p50_log"] = math.log10(max(0.001, _hist_quantile(hist, 0.5)))
            v["interval_p90_log"] = math.log10(max(0.001, _hist_quantile(hist, 0.9)))
            sd = math.sqrt(max(0.0, m2 / n))
            v["burstiness"] = (sd - mean) / (sd + mean) if sd + mean > 0 else 0.0


_RAW_MARKER = bytes(16)


def _uuid_bytes(s: str) -> bytes | None:
    """16-byte form of a canonical UUID string (``None`` for anything that would not round-trip)."""
    if len(s) != 36:
        return None
    try:
        u = uuid.UUID(s)
    except ValueError:
        return None
    b = u.bytes
    return b if str(u) == s and b != _RAW_MARKER else None


def _group(rows: array, width: int) -> dict[int, np.ndarray]:
    """Pending records ``(hop, ...)`` grouped by hop as float64 matrices (arrival order kept)."""
    if not rows:
        return {}
    m = np.array(rows, dtype=np.float64).reshape(-1, width)
    k = m[:, 0].astype(np.int64)
    o = np.argsort(k, kind="stable")
    m, k = m[o], k[o]
    cut = np.flatnonzero(np.diff(k)) + 1
    starts = np.concatenate([[0], cut])
    ends = np.concatenate([cut, [len(k)]])
    return {int(k[a]): m[a:b] for a, b in zip(starts.tolist(), ends.tolist())}


def _offsets(ts: np.ndarray, s: int, hop_s: int, hop_ms: int) -> np.ndarray:
    off = np.rint((ts - s * float(hop_s)) * 1000.0)
    return np.clip(off, 0, hop_ms - 1).astype(np.uint32)


__all__ = [
    "DEFAULT_MAX_SOURCE_EVENT_IDS", "FEATURE_DOCS", "FEATURE_NAMES", "WINDOW_SECONDS", "ContactSummary",
    "StateLimits", "WindowStats", "WindowStore", "key_hash", "label_entropy", "normalize_name",
]
