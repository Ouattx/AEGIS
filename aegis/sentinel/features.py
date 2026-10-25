"""Windowed per-device behavioral features (spec section 4).

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
- **Pre-aggregated bins.** Events are folded into one bin per hop; a window is the
  merge of its bins. Raw events are not retained.
- **Missing is not zero.** A feature that cannot be computed is ``None`` and flagged
  in ``FeatureVector.missing``: e.g. DNS ratios when the device made no DNS query,
  all DNS features when the tenant has no DNS source, periodicity features when no
  connection channel has enough check-ins, prevalence when the population is too
  small to be meaningful.
- **Population context.** Destination prevalence (how many devices of the tenant
  contacted a destination during the same window) normalizes "rare destination"
  features by network context: a licensed IPTV middleware is contacted by many
  boxes, a dedicated C2 server by a handful.

Feature definitions are in :data:`FEATURE_DOCS`.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import TYPE_CHECKING, Iterable, Literal

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


# ---------------------------------------------------------------------------- bins

class _Bin:
    """Aggregate of one entity's events during one hop."""

    __slots__ = ("n_flows", "n_dns", "bytes_out", "bytes_in", "bytes_known", "tcp", "udp", "small",
                 "zero_reply", "zero_known", "long_flows", "peak_pps", "dst", "ports", "channels",
                 "starts", "qnames", "qtimes", "nx", "nx_names", "answers", "ip_times", "qname_times",
                 "event_ids", "auth_ids", "source_ids")

    def __init__(self) -> None:
        self.n_flows = 0
        self.n_dns = 0
        self.bytes_out = 0
        self.bytes_in = 0
        self.bytes_known = 0
        self.tcp = 0
        self.udp = 0
        self.small = 0
        self.zero_reply = 0
        self.zero_known = 0
        self.long_flows = 0
        self.peak_pps = 0.0
        self.dst: Counter[str] = Counter()
        self.ports: set[int] = set()
        self.channels: dict[tuple[str, int, str], list[tuple[float, int | None]]] = {}
        self.starts: list[float] = []
        self.qnames: Counter[str] = Counter()
        self.qtimes: dict[str, list[float]] = {}
        self.nx = 0
        self.nx_names: set[str] = set()
        self.answers: dict[str, set[str]] = {}
        self.ip_times: dict[str, tuple[float, float]] = {}
        self.qname_times: dict[str, tuple[float, float]] = {}
        self.event_ids: list[str] = []
        self.auth_ids: set[str] = set()
        self.source_ids: set[str] = set()

    def add(self, ev: ObservationEvent, ts: float, keep_ids: bool) -> None:
        if keep_ids:
            self.event_ids.append(ev.event_id)
        self.auth_ids.add(ev.collection_authorization_id)
        self.source_ids.add(ev.source_id)
        f = ev.flow
        if f is not None:
            self.n_flows += 1
            ContactSummary._touch(self.dst, self.ip_times, f.dst_ip, ts)
            if f.dst_port is not None:
                self.ports.add(f.dst_port)
            if f.protocol == "tcp":
                self.tcp += 1
            elif f.protocol == "udp":
                self.udp += 1
            total: int | None = None
            if f.bytes_out is not None and f.bytes_in is not None:
                self.bytes_known += 1
                self.bytes_out += f.bytes_out
                self.bytes_in += f.bytes_in
                total = f.bytes_out + f.bytes_in
                if total < SMALL_FLOW_BYTES:
                    self.small += 1
            elif f.bytes_out is not None:
                self.bytes_out += f.bytes_out
            elif f.bytes_in is not None:
                self.bytes_in += f.bytes_in
            if f.packets_in is not None or f.bytes_in is not None:
                self.zero_known += 1
                if (f.packets_in == 0) or (f.bytes_in == 0):
                    self.zero_reply += 1
            dur = f.duration_ms
            if f.packets_out is not None and dur is not None and dur >= 1000:
                self.peak_pps = max(self.peak_pps, f.packets_out / (dur / 1000.0))
            if dur is not None and dur >= LONG_FLOW_MS:
                self.long_flows += 1
            else:
                self.starts.append(ts)
                key = (f.dst_ip, f.dst_port if f.dst_port is not None else -1, f.protocol)
                self.channels.setdefault(key, []).append((ts, total))
        d = ev.dns
        if d is not None:
            self.n_dns += 1
            q = normalize_name(d.qname)
            ContactSummary._touch(self.qnames, self.qname_times, q, ts)
            self.qtimes.setdefault(q, []).append(ts)
            if d.rcode.upper() == "NXDOMAIN":
                self.nx += 1
                self.nx_names.add(q)
            if d.answers:
                self.answers.setdefault(q, set()).update(d.answers)


@dataclass
class _Entity:
    bins: dict[int, _Bin] = field(default_factory=dict)
    device_class: str = "unknown"


@dataclass
class _Tenant:
    first_ts: float
    watermark: float
    next_boundary_idx: int          # index of the next bin whose end is a boundary to emit
    emitted_idx: int = -1           # bins with index < emitted_idx are closed
    has_flow: bool = False
    has_dns: bool = False
    entities: dict[str, _Entity] = field(default_factory=dict)


@dataclass
class WindowStats:
    events: int = 0
    windows_emitted: int = 0
    late_events: int = 0
    dropped_late: int = 0
    rejected: int = 0


@dataclass
class _Agg:
    """Merged bins for one entity window."""
    entity: str
    device_class: str
    bins: list[tuple[int, _Bin]]

    def __post_init__(self) -> None:
        self.dst: Counter[str] = Counter()
        self.qnames: Counter[str] = Counter()
        for _, b in self.bins:
            self.dst.update(b.dst)
            self.qnames.update(b.qnames)


class WindowStore:
    """Per-tenant, per-entity hopping windows over the observation stream.

    ``window`` is the context length (``"5m"``, ``"15m"`` or ``"24h"``); ``hop`` is the
    re-evaluation step (defaults to ``1h`` for ``24h`` windows, else the window itself)
    and must divide the window. ``ioc_bundle``, when given, fills ``ioc_contacts``.
    """

    def __init__(self, window: WindowName = "24h", hop: timedelta | None = None, *,
                 allowed_lateness: timedelta = timedelta(minutes=2),
                 max_future_skew: timedelta = timedelta(minutes=10),
                 min_population: int = DEFAULT_MIN_POPULATION,
                 max_source_event_ids: int | None = 10_000,
                 ioc_bundle: "IOCBundle | None" = None):
        if window not in WINDOW_SECONDS:
            raise ValueError(f"unsupported window {window!r}")
        self.window: WindowName = window
        self.window_s = WINDOW_SECONDS[window]
        if hop is None:
            hop = timedelta(hours=1) if window == "24h" else timedelta(seconds=self.window_s)
        hop_s = int(hop.total_seconds())
        if hop_s <= 0 or self.window_s % hop_s:
            raise ValueError("hop must be positive and divide the window length")
        self.hop_s = hop_s
        self.n_bins = self.window_s // hop_s
        self.lateness_s = allowed_lateness.total_seconds()
        self.max_future_skew = max_future_skew
        self.min_population = min_population
        self.max_ids = max_source_event_ids
        self.ioc_bundle = ioc_bundle
        self.stats = WindowStats()
        self._tenants: dict[str, _Tenant] = {}
        self._contacts: dict[tuple[str, str], ContactSummary] = {}

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
        b = ent.bins.get(k)
        if b is None:
            b = ent.bins[k] = _Bin()
        keep_ids = self.max_ids is None or self.max_ids > 0
        b.add(event, ts, keep_ids)
        if event.flow is not None:
            t.has_flow = True
        if event.dns is not None:
            t.has_dns = True
        t.watermark = max(t.watermark, ts - self.lateness_s)
        return self._advance(event.tenant_id, t, t.watermark)

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
        """Contacts of the window that produced ``fv`` (kept for the most recent window only)."""
        cs = self._contacts.get((fv.tenant_id, fv.entity_pseudonym))
        if cs is None or cs.window_end != fv.window_end:
            return None
        return cs

    def entity_count(self, tenant_id: str) -> int:
        t = self._tenants.get(tenant_id)
        return 0 if t is None else len(t.entities)

    # ------------------------------------------------------------------ emission
    def _advance(self, tenant_id: str, t: _Tenant, watermark: float) -> list[FeatureVector]:
        out: list[FeatureVector] = []
        while (t.next_boundary_idx + 1) * self.hop_s <= watermark:
            end_idx = t.next_boundary_idx + 1           # window = bins [end_idx - n_bins, end_idx)
            idxs = [k for e in t.entities.values() for k in e.bins]
            if not idxs:
                # no buffered data: jump straight to the watermark
                t.entities.clear()
                t.next_boundary_idx = max(t.next_boundary_idx, int(watermark // self.hop_s))
                t.emitted_idx = t.next_boundary_idx
                break
            oldest = min(idxs)
            if oldest >= end_idx:
                # gap before the buffered data: skip empty windows
                t.next_boundary_idx = oldest
                t.emitted_idx = oldest
                continue
            # contacts are kept for the most recent window of each entity only
            boundary = datetime.fromtimestamp(end_idx * self.hop_s, tz=timezone.utc)
            for key in [k for k, cs in self._contacts.items() if k[0] == tenant_id and cs.window_end < boundary]:
                del self._contacts[key]
            out.extend(self._emit(tenant_id, t, end_idx))
            t.next_boundary_idx = end_idx
            t.emitted_idx = end_idx
            lo = end_idx - self.n_bins + 1              # first bin of the next window
            for eid in list(t.entities):
                ent = t.entities[eid]
                for k in [k for k in ent.bins if k < lo]:
                    del ent.bins[k]
                if not ent.bins:
                    del t.entities[eid]
        return out

    def _emit(self, tenant_id: str, t: _Tenant, end_idx: int) -> list[FeatureVector]:
        lo = end_idx - self.n_bins
        aggs: list[_Agg] = []
        for eid, ent in t.entities.items():
            bins = sorted((k, b) for k, b in ent.bins.items() if lo <= k < end_idx)
            if bins:
                aggs.append(_Agg(eid, ent.device_class, bins))
        if not aggs:
            return []
        window_end_ts = end_idx * self.hop_s
        window_start_ts = window_end_ts - self.window_s
        coverage_start = max(window_start_ts, t.first_ts)
        coverage_s = max(float(self.hop_s) / 60.0, window_end_ts - coverage_start)
        first_bin = max(lo, int(t.first_ts // self.hop_s))
        population = len(aggs)
        ip_prev: Counter[str] = Counter()
        q_prev: Counter[str] = Counter()
        for a in aggs:
            ip_prev.update(a.dst.keys())
            q_prev.update(a.qnames.keys())
        rare_cut = max(2, math.ceil(0.02 * population))
        prevalence_ok = population >= self.min_population
        window_end = datetime.fromtimestamp(window_end_ts, tz=timezone.utc)
        window_start = datetime.fromtimestamp(window_start_ts, tz=timezone.utc)
        out = []
        for a in aggs:
            values = self._features(a, t, coverage_s, first_bin, end_idx, ip_prev, q_prev, population,
                                    rare_cut, prevalence_ok)
            cs = self._contact_summary(tenant_id, a, window_start, window_end)
            self._contacts[(tenant_id, a.entity)] = cs
            if self.ioc_bundle is not None:
                values["ioc_contacts"] = float(self.ioc_bundle.count_contacts(cs, window_end))
            ids: list[str] = []
            n_events = 0
            for _, b in a.bins:
                n_events += b.n_flows + b.n_dns
                if self.max_ids is None or len(ids) < self.max_ids:
                    ids.extend(b.event_ids)
            if self.max_ids is not None:
                ids = ids[: self.max_ids]
            out.append(FeatureVector(
                tenant_id=tenant_id, entity_pseudonym=a.entity, device_class=a.device_class or "unknown",
                window=self.window, window_end=window_end, values=values,
                missing={k: v is None for k, v in values.items()}, event_count=n_events,
                source_event_ids=ids))
        self.stats.windows_emitted += len(out)
        return out

    @staticmethod
    def _contact_summary(tenant_id: str, a: _Agg, ws: datetime, we: datetime) -> ContactSummary:
        cs = ContactSummary(tenant_id, a.entity, ws, we)
        for _, b in a.bins:
            cs.merge_times(cs.dst_ips, cs.ip_times, b.dst, b.ip_times)
            cs.merge_times(cs.qnames, cs.qname_times, b.qnames, b.qname_times)
            for q, ans in b.answers.items():
                cs.answers.setdefault(q, set()).update(ans)
            cs.authorization_ids |= b.auth_ids
            cs.source_ids |= b.source_ids
        return cs

    def _features(self, a: _Agg, t: _Tenant, coverage_s: float, first_bin: int, end_idx: int,
                  ip_prev: Counter[str], q_prev: Counter[str], population: int, rare_cut: int,
                  prevalence_ok: bool) -> dict[str, float | None]:
        v: dict[str, float | None] = {name: None for name in FEATURE_NAMES}
        hours = coverage_s / 3600.0
        v["coverage_h"] = round(hours, 4)
        bins = a.bins
        n_flows = sum(b.n_flows for _, b in bins)
        n_dns = sum(b.n_dns for _, b in bins)
        covered_bins = max(1, end_idx - first_bin)
        by_idx = dict(bins)
        last = by_idx.get(end_idx - 1)

        # ---------------------------------------------------------------- volume / flows
        if t.has_flow:
            v["flow_rate_h"] = n_flows / hours
            v["active_bin_frac"] = min(1.0, sum(1 for _, b in bins if b.n_flows) / covered_bins)
            v["recent_flows_log"] = _log10p(last.n_flows if last else 0)
            v["recent_unique_dst"] = float(len(last.dst) if last else 0)
            series_f = [float(by_idx[k].n_flows) if k in by_idx else 0.0 for k in range(first_bin, end_idx)]
            if len(series_f) >= 7:
                v["baseline_dev_flows"] = _robust_z(_log10p(series_f[-1]), [_log10p(x) for x in series_f[:-1]])
        bytes_known = sum(b.bytes_known for _, b in bins)
        if t.has_flow and n_flows:
            bo = sum(b.bytes_out for _, b in bins)
            bi = sum(b.bytes_in for _, b in bins)
            if bytes_known:
                v["bytes_out_rate_log"] = _log10p(bo / hours)
                v["bytes_in_rate_log"] = _log10p(bi / hours)
                v["out_ratio"] = bo / (bo + bi) if bo + bi > 0 else None
                v["small_flow_frac"] = sum(b.small for _, b in bins) / bytes_known
                v["recent_bytes_out_log"] = _log10p(last.bytes_out if last else 0)
                heavy = sum(1 for _, b in bins if b.bytes_out > b.bytes_in and b.bytes_out > OUT_HEAVY_BYTES)
                v["out_heavy_bin_frac"] = min(1.0, heavy / covered_bins)
                series_b = [float(by_idx[k].bytes_out) if k in by_idx else 0.0 for k in range(first_bin, end_idx)]
                if len(series_b) >= 7:
                    v["baseline_dev_bytes_out"] = _robust_z(_log10p(series_b[-1]),
                                                            [_log10p(x) for x in series_b[:-1]])
            v["unique_dst_ip"] = float(len(a.dst))
            ports: set[int] = set()
            for _, b in bins:
                ports |= b.ports
            v["unique_dst_port"] = float(len(ports))
            v["dst_entropy"] = _shannon(a.dst.values())
            v["max_dst_share"] = max(a.dst.values()) / n_flows
            v["tcp_frac"] = sum(b.tcp for _, b in bins) / n_flows
            v["udp_frac"] = sum(b.udp for _, b in bins) / n_flows
            zk = sum(b.zero_known for _, b in bins)
            v["zero_reply_frac"] = sum(b.zero_reply for _, b in bins) / zk if zk else None
            v["long_flow_frac"] = sum(b.long_flows for _, b in bins) / n_flows
            v["peak_out_pps_log"] = _log10p(max(b.peak_pps for _, b in bins))
            self._timing(v, bins, ip_prev, population, prevalence_ok, covered_bins)
            if prevalence_ok:
                discrete = {key[0] for _, b in bins for key in b.channels}
                if discrete:
                    v["rare_dst_frac"] = sum(1 for ip in discrete if ip_prev[ip] <= rare_cut) / len(discrete)

        # ---------------------------------------------------------------- DNS
        if t.has_dns:
            v["dns_rate_h"] = n_dns / hours
            if n_dns:
                nx = sum(b.nx for _, b in bins)
                nx_names: set[str] = set()
                for _, b in bins:
                    nx_names |= b.nx_names
                v["nxdomain_rate"] = nx / n_dns
                v["nx_unique"] = float(len(nx_names))
                v["qname_unique"] = float(len(a.qnames))
                if nx_names:
                    v["nx_name_entropy"] = sum(label_entropy(n) for n in nx_names) / len(nx_names)
                if prevalence_ok and a.qnames:
                    v["rare_qname_frac"] = sum(1 for q in a.qnames if q_prev[q] <= rare_cut) / len(a.qnames)
                periodic = self._periodic_names(bins, covered_bins)
                v["periodic_qnames"] = float(len(periodic))
                if prevalence_ok and periodic:
                    v["periodic_qname_prevalence"] = min(q_prev[q] for q in periodic) / population
        return v

    def _duty(self, ts: list[float], covered_bins: int) -> float:
        return min(1.0, len({int(t // self.hop_s) for t in ts}) / covered_bins)

    def _periodic_names(self, bins: list[tuple[int, _Bin]], covered_bins: int) -> list[str]:
        """Names whose lookups recur on a regular schedule (resolver-cache driven check-ins)."""
        times: dict[str, list[float]] = {}
        for _, b in bins:
            for q, ts in b.qtimes.items():
                times.setdefault(q, []).extend(ts)
        out = []
        for q, ts in times.items():
            if len(ts) < MIN_CHANNEL_EVENTS:
                continue
            ts.sort()
            iv = [g for g in (b - a for a, b in zip(ts, ts[1:])) if g >= 1.0]
            if len(iv) < MIN_CHANNEL_EVENTS - 1:
                continue
            med = median(iv)
            if 1.4826 * median(abs(x - med) for x in iv) / med <= PERIODIC_CV \
                    and self._duty(ts, covered_bins) >= MIN_DUTY:
                out.append(q)
        return out

    def _timing(self, v: dict[str, float | None], bins: list[tuple[int, _Bin]], ip_prev: Counter[str],
                population: int, prevalence_ok: bool, covered_bins: int) -> None:
        starts = sorted(s for _, b in bins for s in b.starts)
        gaps = [g for g in (b - a for a, b in zip(starts, starts[1:])) if g > 0]
        if len(gaps) >= 3:
            gs = sorted(gaps)
            v["interval_p10_log"] = math.log10(max(0.001, _quantile(gs, 0.1)))
            v["interval_p50_log"] = math.log10(max(0.001, _quantile(gs, 0.5)))
            v["interval_p90_log"] = math.log10(max(0.001, _quantile(gs, 0.9)))
            mu = sum(gaps) / len(gaps)
            sd = math.sqrt(sum((g - mu) ** 2 for g in gaps) / len(gaps))
            v["burstiness"] = (sd - mu) / (sd + mu) if sd + mu > 0 else 0.0
        channels: dict[tuple[str, int, str], list[tuple[float, int | None]]] = {}
        for _, b in bins:
            for key, recs in b.channels.items():
                channels.setdefault(key, []).extend(recs)
        # candidate channels: (robust_cv, n, key, median_period, median_bytes, duty)
        cands: list[tuple[float, int, tuple[str, int, str], float, float | None, float]] = []
        for key, recs in channels.items():
            if len(recs) < MIN_CHANNEL_EVENTS:
                continue
            ts = sorted(r[0] for r in recs)
            iv = [g for g in (b - a for a, b in zip(ts, ts[1:])) if g >= 1.0]
            if len(iv) < MIN_CHANNEL_EVENTS - 1:
                continue
            med = median(iv)
            mad = median(abs(x - med) for x in iv)
            sizes = [r[1] for r in recs if r[1] is not None]
            cands.append((1.4826 * mad / med, len(recs), key, med,
                          float(median(sizes)) if sizes else None, self._duty(ts, covered_bins)))
        if not cands:
            return
        # The reported channel is the *rarest periodic* one when prevalence is known
        # (a heartbeat to a popular service is normal; a periodic check-in to a
        # destination almost nobody else contacts is the beaconing signature), else
        # simply the most periodic one.
        periodic = [c for c in cands if c[0] <= PERIODIC_CV and c[5] >= MIN_DUTY]
        if prevalence_ok and periodic:
            best = min(periodic, key=lambda c: (ip_prev[c[2][0]], c[0], -c[1]))
        else:
            best = min(cands, key=lambda c: (c[0], -c[1]))
        rcv, n, key, med, msize, duty = best
        v["beacon_duty"] = duty
        v["beacon_robust_cv"] = min(rcv, 10.0)
        v["beacon_period_log"] = math.log10(med)
        v["beacon_events"] = float(n)
        v["beacon_bytes_log"] = _log10p(msize) if msize is not None else None
        if prevalence_ok:
            v["beacon_dst_prevalence"] = ip_prev[key[0]] / population


__all__ = [
    "FEATURE_DOCS", "FEATURE_NAMES", "WINDOW_SECONDS", "ContactSummary", "WindowStats", "WindowStore",
    "label_entropy", "normalize_name",
]
