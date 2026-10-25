"""EGRESS: outbound abuse detection on subscriber lines (DDoS participation, reflection,
residential-proxy relaying, spam and credential stuffing).

The detector reads flow :class:`~aegis.contracts.models.ObservationEvent` records of one
tenant over one window and works in three stages:

1. **Line signals** (per line, deterministic rules in :mod:`aegis.egress.config`):

   * ``flood``: packets per second toward one external target (host, or /24 for carpet
     bombing) at or above ``min_flood_pps`` while the target answers almost nothing
     (``packets_in / packets_out <= max_response_ratio``). Uploads, games, calls and VPNs
     are conversations: the far end sends ACKs or state back, so they never pass the
     response test regardless of volume;
   * ``sync_burst``: a sharp onset of one-way traffic toward a target (rate at least
     ``onset_ratio`` times the line's own median toward it over the preceding buckets);
   * ``amplification_request``: many distinct reflectors on an amplification port
     (DNS/NTP/SSDP/memcached/CLDAP/...) contacted at rate with almost no answers (the
     answers go to the spoofed victim). A home recursive resolver also talks to many DNS
     servers, but it receives the answers;
   * ``abused_reflector``: the line answers a single remote with roughly one response per
     request and an amplification factor >= ``reflector_min_amplification`` (an open
     service on the CPE). Never MALICIOUS: the subscriber is the victim of misconfiguration;
   * ``spoofing``: optional anti-spoofing counters (:class:`SpoofSignal`);
   * ``proxy_relay``: bytes arriving from many unrelated peers in short sessions leave
     again toward one persistent upstream ("sink") in the same or next bin: correlation
     >= ``relay_min_corr`` over bins where both are active, byte balance within
     [``relay_balance_min``, ``relay_balance_max``] and a sink that receives far more than
     it sends;
   * ``spam``: SMTP (port 25) to many distinct mail exchangers per hour;
   * ``credential_stuffing``: hundreds of short, byte-uniform, irregularly timed sessions
     per hour to one login service; ``auth_fanout``: one auth port across many hosts.

2. **Cross-line correlation** (campaigns): synchronized burst onsets or overlapping floods
   toward one target from ``sync_min_lines`` unrelated lines, a proxy sink shared by
   several lines, overlapping mail-exchanger sets, one login service attacked by several
   lines, reflectors on one port abused by several lines at once.

3. **Verdict policy** (pre-registered): a strong line signal *plus* corroboration (a
   cross-line campaign, spoofing counters, or a second abuse family on the same line) =>
   MALICIOUS; a strong signal alone, or campaign membership with a weak signal =>
   SUSPICIOUS; weak signals alone are not reported. Candidates that cannot be judged
   because counters are missing (uniflow exporters without reverse packets, records
   without byte counts) become ABSTAIN. Every verdict carries ``requires_review`` when
   turned into a Finding, and scores are rankings, not probabilities.

All evidence comes from the operator's own telemetry: corroboration *within* this
detector is never counted as an independent origin (see :mod:`aegis.egress.findings`).
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Protocol, Sequence

import numpy as np

from aegis.contracts.models import ObservationEvent
from aegis.egress.config import (
    EGRESS_VERSION,
    LABEL_AMPLIFICATION,
    LABEL_DDOS,
    LABEL_PROXY,
    LABEL_REFLECTOR,
    LABEL_SPAM,
    LABEL_STUFFING,
    EgressConfig,
)
from aegis.egress.models import (
    Abstention,
    EgressCampaign,
    EgressReport,
    LineSignal,
    LineVerdict,
    SpoofSignal,
)


class HostingContext(Protocol):
    """What EGRESS needs from operator hosting knowledge.

    :class:`aegis.resonance.DestinationContext` satisfies it; ``None`` means unknown.
    """

    def kind(self, ip: str) -> str | None: ...


ALTERNATIVES: dict[str, list[str]] = {
    LABEL_DDOS: [
        "authorized load or stress test run from this line",
        "misbehaving device firmware or application hammering a server it believes is down",
        "one-way UDP media or telemetry upload (would normally show replies or a low rate)",
    ],
    LABEL_AMPLIFICATION: [
        "home recursive DNS resolver or network inventory tool (would normally receive replies)",
        "research or internet-measurement scanner operated by the subscriber",
    ],
    LABEL_REFLECTOR: [
        "open DNS/NTP/SSDP/memcached service on the CPE or a home device abused by third parties: "
        "the subscriber is the victim of a misconfiguration, not an attacker",
    ],
    LABEL_PROXY: [
        "consented bandwidth-sharing application installed by the subscriber",
        "personal VPN or remote-access server used by the subscriber while away from home",
        "self-hosted proxy, Tor bridge or relay run deliberately by the subscriber",
    ],
    LABEL_SPAM: [
        "self-hosted mail server on a residential line",
        "mail client misconfigured to deliver directly on port 25",
    ],
    LABEL_STUFFING: [
        "automation, API client or monitoring probe hitting one service",
        "mail client or password manager stuck in a login retry loop",
        "authorized penetration test",
    ],
}

#: destination ports are listed in flood metrics only when there are at most this many
#: (a randomized-port flood lists none: a port match would not narrow a mitigation rule)
MAX_LISTED_PORTS = 8


@dataclass(slots=True)
class _Flow:
    t: float
    dst: str
    port: int | None
    proto: str
    bo: int | None
    bi: int | None
    po: int | None
    pi: int | None
    dur: int | None


@dataclass
class _Line:
    flows: list[_Flow] = field(default_factory=list)
    classes: Counter[str] = field(default_factory=Counter)


@dataclass
class _Onset:
    line: str
    key: str
    t: float
    end: float
    peak_pps: float
    response_ratio: float


@dataclass
class _Episode:
    line: str
    key: str
    start: float
    end: float
    buckets: int
    peak_pps: float
    mean_pps: float
    response_ratio: float | None
    protocols: list[str]
    distinct_ports: int
    ports: list[int]
    mean_packet_bytes: float | None
    onset_ratio: float | None


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _prefix(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    plen = 24 if a.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))


def _cv(values: Sequence[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = statistics.fmean(values)
    if mean <= 0:
        return None
    return statistics.pstdev(values) / mean


def _corr(a: Sequence[float], b: Sequence[float]) -> float | None:
    if len(a) < 3 or len(a) != len(b):
        return None
    x = np.asarray(a, dtype=float)
    y = np.asarray(b, dtype=float)
    if float(x.std()) == 0.0 or float(y.std()) == 0.0:
        return None
    return float(np.corrcoef(x, y)[0, 1])


def _overlap(a0: float, a1: float, b0: float, b1: float, slack: float) -> bool:
    return a0 - slack <= b1 and b0 - slack <= a1


def _campaign_id(tenant_id: str, label: str, kind: str, targets: Sequence[str], start: float) -> str:
    key = f"{tenant_id}|{label}|{kind}|{','.join(sorted(targets))}|{int(start // 60)}"
    return "egc_" + hashlib.sha256(key.encode()).hexdigest()[:20]


def _r(x: float | None, nd: int = 4) -> float | None:
    if x is None or not math.isfinite(x):
        return None
    return round(float(x), nd)


class EgressDetector:
    """Outbound-abuse detector for one tenant (stateless between calls)."""

    def __init__(self, config: EgressConfig | None = None, *, tenant_id: str,
                 context: HostingContext | None = None):
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("tenant_id is required")
        self.cfg = config or EgressConfig()
        self.tenant_id = tenant_id
        self.context = context

    # ------------------------------------------------------------------ public
    def detect(self, events: Iterable[ObservationEvent], *, start: datetime | None = None,
               end: datetime | None = None, spoof_signals: Iterable[SpoofSignal] = ()) -> EgressReport:
        """Analyse one window of flow events; see the module docstring for the method.

        Raises ``ValueError`` for an event or spoof signal of another tenant (no
        cross-tenant path, fail closed).
        """
        cfg = self.cfg
        lines, n_flows, n_missing_pk = self._collect(events)
        spoof = list(spoof_signals)
        for s in spoof:
            if s.tenant_id != self.tenant_id:
                raise ValueError("spoof signal belongs to a different tenant")
        ts_all = [f.t for ln in lines.values() for f in ln.flows]
        w0 = _aware(start).timestamp() if start else (min(ts_all) if ts_all else 0.0)
        w1 = _aware(end).timestamp() if end else (max(ts_all) + cfg.bucket_s if ts_all else w0 + cfg.bucket_s)
        if w1 <= w0:
            raise ValueError("end must be after start")
        report = EgressReport(tenant_id=self.tenant_id, detector_version=EGRESS_VERSION,
                              config_hash=cfg.config_hash(), window_start=_utc(w0), window_end=_utc(w1),
                              status="ok")
        stats: dict[str, Any] = {"flow_records": n_flows, "lines": len(lines),
                                 "flow_records_missing_packets": n_missing_pk,
                                 "sampling_interval": cfg.sampling_interval}
        report.stats = stats
        if n_flows < cfg.min_flow_records:
            report.status = "abstain"
            report.abstain_reason = f"only {n_flows} flow records in the window (minimum {cfg.min_flow_records})"
            return report
        if n_missing_pk / n_flows > cfg.max_missing_packets_fraction:
            report.status = "abstain"
            report.abstain_reason = (f"{n_missing_pk} of {n_flows} flow records have no packet counters: "
                                     "rates cannot be measured")
            return report

        hours = max((w1 - w0) / 3600.0, cfg.bucket_s / 3600.0)
        signals: list[LineSignal] = []
        abst: list[Abstention] = []
        onsets: list[_Onset] = []
        episodes: list[_Episode] = []
        popularity = self._popularity(lines)
        for line, ln in lines.items():
            ln.flows.sort(key=lambda f: f.t)
            ep, on, ab = self._floods(line, ln.flows, w0)
            episodes.extend(ep)
            onsets.extend(on)
            abst.extend(ab)
            s, ab = self._amplification(line, ln.flows, w0)
            signals.extend(s)
            abst.extend(ab)
            signals.extend(self._reflector(line, ln.flows, w0))
            s, ab = self._proxy(line, ln.flows, w0, w1)
            signals.extend(s)
            abst.extend(ab)
            signals.extend(self._spam(line, ln.flows))
            signals.extend(self._stuffing(line, ln.flows))
        signals.extend(self._episode_signals(episodes))
        signals.extend(self._onset_signals(onsets))
        signals.extend(self._spoofing(spoof, w0, w1))

        campaigns = self._campaigns(signals, onsets, episodes, popularity)
        report.campaigns = campaigns
        report.verdicts = self._verdicts(lines, signals, campaigns, abst, popularity)
        report.abstentions = abst
        stats.update({
            "signals": dict(Counter(s.kind for s in signals)),
            "campaigns": dict(Counter(c.label for c in campaigns)),
            "verdicts": dict(Counter(f"{v.label}:{v.verdict}" for v in report.verdicts)),
            "weak_signals_not_reported": sum(1 for s in signals if not s.strong and not any(
                s.entity_pseudonym in c.member_lines and c.label == s.label for c in campaigns)),
            "window_hours": round(hours, 4),
        })
        return report

    # ------------------------------------------------------------------ collection
    def _collect(self, events: Iterable[ObservationEvent]) -> tuple[dict[str, _Line], int, int]:
        lines: dict[str, _Line] = defaultdict(_Line)
        n = missing = 0
        for ev in events:
            if ev.tenant_id != self.tenant_id:
                raise ValueError(f"event {ev.event_id} belongs to tenant {ev.tenant_id!r}, "
                                 f"detector is scoped to {self.tenant_id!r}")
            fl = ev.flow
            if fl is None or not ev.entity_pseudonym:
                continue
            n += 1
            if fl.packets_out is None:
                missing += 1
            ln = lines[ev.entity_pseudonym]
            if ev.device_class:
                ln.classes[ev.device_class] += 1
            ln.flows.append(_Flow(ev.observed_at.timestamp(), fl.dst_ip, fl.dst_port, fl.protocol,
                                  fl.bytes_out, fl.bytes_in, fl.packets_out, fl.packets_in, fl.duration_ms))
        return dict(lines), n, missing

    def _popularity(self, lines: dict[str, _Line]) -> dict[str, float]:
        """Fraction of active lines that contacted each destination IP (empty below the line floor)."""
        if len(lines) < self.cfg.min_active_lines_for_popularity:
            return {}
        reach: Counter[str] = Counter()
        for ln in lines.values():
            reach.update({f.dst for f in ln.flows})
        total = len(lines)
        return {ip: c / total for ip, c in reach.items()}

    # ------------------------------------------------------------------ floods / bursts
    def _floods(self, line: str, flows: list[_Flow], w0: float
                ) -> tuple[list[_Episode], list[_Onset], list[Abstention]]:
        cfg = self.cfg
        k = cfg.sampling_interval
        bs = cfg.bucket_s
        # key -> bucket -> [pkts_out, pkts_in, pi_known, bytes_out, ports, protos, ips]
        agg: dict[str, dict[int, list[Any]]] = defaultdict(dict)
        pfx_ips: dict[tuple[str, int], set[str]] = defaultdict(set)
        for f in flows:
            if f.po is None:
                continue
            b = int((f.t - w0) // bs)
            keys = [f"ip:{f.dst}"]
            p = _prefix(f.dst)
            if p is not None:
                keys.append(f"pfx:{p}")
                pfx_ips[(p, b)].add(f.dst)
            for key in keys:
                cell = agg[key].get(b)
                if cell is None:
                    cell = agg[key][b] = [0, 0, True, 0, set(), set()]
                cell[0] += f.po * k
                if f.pi is None:
                    cell[2] = False
                else:
                    cell[1] += f.pi * k
                cell[3] += (f.bo or 0) * k
                if f.port is not None:
                    cell[4].add(f.port)
                cell[5].add(f.proto)
        episodes: list[_Episode] = []
        onsets: list[_Onset] = []
        abst: list[Abstention] = []
        unknown_peak = 0.0
        unknown_targets: set[str] = set()
        for key, buckets in agg.items():
            is_pfx = key.startswith("pfx:")
            idx = sorted(buckets)

            def pps(b: int, buckets: dict[int, list[Any]] = buckets) -> float:
                c = buckets.get(b)
                return 0.0 if c is None else c[0] / bs

            def usable(b: int, is_pfx: bool = is_pfx, net: str = key[4:]) -> bool:
                return not is_pfx or len(pfx_ips.get((net, b), ())) >= cfg.carpet_min_ips

            flood_b: list[int] = []
            for b in idx:
                c = buckets[b]
                rate = c[0] / bs
                if rate < cfg.min_flood_pps or not usable(b):
                    continue
                if not c[2]:
                    unknown_peak = max(unknown_peak, rate)
                    unknown_targets.add(key)
                    continue
                if c[0] > 0 and c[1] / c[0] <= cfg.max_response_ratio:
                    flood_b.append(b)
            for run in _runs(flood_b, gap=1):
                rates = [pps(b) for b in run]
                po = sum(buckets[b][0] for b in run)
                pi = sum(buckets[b][1] for b in run)
                bo = sum(buckets[b][3] for b in run)
                ports = set().union(*(buckets[b][4] for b in run))
                protos = sorted(set().union(*(buckets[b][5] for b in run)))
                first = run[0]
                prior = [pps(b) for b in range(first - cfg.onset_lookback_buckets, first)]
                onset = None
                if first >= cfg.onset_lookback_buckets:
                    med = statistics.median(prior)
                    onset = rates[0] / med if med > 0 else math.inf
                episodes.append(_Episode(
                    line=line, key=key, start=w0 + first * bs, end=w0 + (run[-1] + 1) * bs, buckets=len(run),
                    peak_pps=max(rates), mean_pps=statistics.fmean(rates),
                    response_ratio=(pi / po) if po else None, protocols=protos, distinct_ports=len(ports),
                    ports=sorted(ports)[:MAX_LISTED_PORTS] if len(ports) <= MAX_LISTED_PORTS else [],
                    mean_packet_bytes=(bo / po) if po else None, onset_ratio=onset))
            # weak synchronized-burst onsets (lower rate, sharp start against in-window history)
            burst_b = []
            for b in idx:
                c = buckets[b]
                rate = c[0] / bs
                if rate < cfg.sync_min_line_pps or not c[2] or not usable(b) or b < cfg.onset_lookback_buckets:
                    continue
                if c[0] <= 0 or c[1] / c[0] > cfg.sync_max_response_ratio:
                    continue
                burst_b.append(b)
            for run in _runs(burst_b, gap=1):
                first = run[0]
                med = statistics.median(pps(b) for b in range(first - cfg.onset_lookback_buckets, first))
                if med > 0 and pps(first) / med < cfg.onset_ratio:
                    continue
                po = sum(buckets[b][0] for b in run)
                pi = sum(buckets[b][1] for b in run)
                onsets.append(_Onset(line=line, key=key, t=w0 + first * bs, end=w0 + (run[-1] + 1) * bs,
                                     peak_pps=max(pps(b) for b in run), response_ratio=pi / po if po else 0.0))
        if unknown_targets and not any(e.line == line for e in episodes):
            abst.append(Abstention(entity_pseudonym=line, label=LABEL_DDOS, reason="reverse_counters_missing",
                                   detail={"peak_pps": _r(unknown_peak, 1),
                                           "targets": sorted(t.split(":", 1)[1] for t in unknown_targets)[:20],
                                           "why": "outbound rate is flood-like but the exporter does not report "
                                                  "packets_in, so replies cannot be ruled in or out"}))
        return episodes, onsets, abst

    def _episode_signals(self, episodes: list[_Episode]) -> list[LineSignal]:
        cfg = self.cfg
        out: list[LineSignal] = []
        by_line: dict[str, list[_Episode]] = defaultdict(list)
        for e in episodes:
            by_line[e.line].append(e)
        for line, eps in by_line.items():
            ip_targets = {e.key[3:] for e in eps if e.key.startswith("ip:")}
            for e in eps:
                if e.key.startswith("pfx:"):
                    net = ipaddress.ip_network(e.key[4:])
                    if any(ipaddress.ip_address(ip) in net for ip in ip_targets):
                        continue  # the host-level episode already covers it
                strong = e.buckets >= cfg.min_flood_buckets or e.peak_pps >= cfg.min_flood_pps * cfg.strong_flood_multiple
                target = e.key.split(":", 1)[1]
                out.append(LineSignal(
                    entity_pseudonym=line, kind="flood", label=LABEL_DDOS, strong=strong,
                    start=_utc(e.start), end=_utc(e.end), targets=[target],
                    metrics={"target_kind": "prefix" if e.key.startswith("pfx:") else "host",
                             "buckets": e.buckets, "bucket_s": cfg.bucket_s, "peak_pps": _r(e.peak_pps, 1),
                             "mean_pps": _r(e.mean_pps, 1), "response_ratio": _r(e.response_ratio, 5),
                             "protocols": e.protocols, "distinct_dst_ports": e.distinct_ports, "dst_ports": e.ports,
                             "mean_packet_bytes": _r(e.mean_packet_bytes, 1),
                             "onset_ratio": None if e.onset_ratio is None else (
                                 "inf" if math.isinf(e.onset_ratio) else _r(e.onset_ratio, 2)),
                             "target_kind_hosting": self._kind(target)},
                    summary=(f"one-way flood toward {target}: peak {e.peak_pps:,.0f} pps over {e.buckets} x "
                             f"{cfg.bucket_s} s, replies/requests {e.response_ratio or 0:.4f}")))
        return out

    def _onset_signals(self, onsets: list[_Onset]) -> list[LineSignal]:
        out = []
        for o in onsets:
            target = o.key.split(":", 1)[1]
            out.append(LineSignal(
                entity_pseudonym=o.line, kind="sync_burst", label=LABEL_DDOS, strong=False,
                start=_utc(o.t), end=_utc(o.end), targets=[target],
                metrics={"peak_pps": _r(o.peak_pps, 1), "response_ratio": _r(o.response_ratio, 5),
                         "target_kind": "prefix" if o.key.startswith("pfx:") else "host"},
                summary=f"sharp onset of one-way traffic toward {target} (peak {o.peak_pps:,.0f} pps)"))
        return out

    def _spoofing(self, spoof: list[SpoofSignal], w0: float, w1: float) -> list[LineSignal]:
        cfg = self.cfg
        agg: dict[str, list[Any]] = {}
        for s in spoof:
            a, b = s.interval_start.timestamp(), s.interval_end.timestamp()
            if b < w0 or a > w1:
                continue
            cell = agg.setdefault(s.entity_pseudonym, [0, 0, True, a, b, set()])
            cell[0] += s.packets_outside_prefix
            if s.packets_total is None:
                cell[2] = False
            else:
                cell[1] += s.packets_total
            cell[3], cell[4] = min(cell[3], a), max(cell[4], b)
            cell[5].add(s.source)
        out = []
        for line, (outside, total, known, a, b, sources) in agg.items():
            if outside < cfg.spoof_min_packets:
                continue
            frac = outside / total if known and total else None
            if frac is not None and frac < cfg.spoof_min_fraction:
                continue
            out.append(LineSignal(
                entity_pseudonym=line, kind="spoofing", label=LABEL_DDOS, strong=frac is not None,
                start=_utc(a), end=_utc(b), targets=[],
                metrics={"packets_outside_prefix": outside, "packets_total": total if known else None,
                         "fraction": _r(frac, 5), "sources": sorted(sources)},
                summary=(f"{outside:,} packets with a source address outside the line's prefix"
                         + (f" ({frac:.2%} of its traffic)" if frac is not None else " (no total exported)"))))
        return out

    # ------------------------------------------------------------------ reflection
    def _amplification(self, line: str, flows: list[_Flow], w0: float
                       ) -> tuple[list[LineSignal], list[Abstention]]:
        cfg = self.cfg
        k = cfg.sampling_interval
        per: dict[int, list[Any]] = {}
        for f in flows:
            if f.proto != "udp" or f.port not in cfg.amp_ports or f.po is None:
                continue
            cell = per.setdefault(f.port, [set(), 0, 0, True, set(), f.t, f.t, 0])
            cell[0].add(f.dst)
            cell[1] += f.po * k
            if f.pi is None:
                cell[3] = False
            else:
                cell[2] += f.pi * k
            cell[4].add(int((f.t - w0) // cfg.bucket_s))
            cell[5], cell[6] = min(cell[5], f.t), max(cell[6], f.t)
            cell[7] += (f.bo or 0) * k
        sig: list[LineSignal] = []
        abst: list[Abstention] = []
        for port, (dsts, po, pi, known, active, t0, t1, bo) in per.items():
            rate = po / (len(active) * cfg.bucket_s)
            if len(dsts) < cfg.amp_min_reflectors or rate < cfg.amp_min_pps:
                continue
            proto = cfg.amp_ports[port]
            if not known:
                abst.append(Abstention(entity_pseudonym=line, label=LABEL_AMPLIFICATION,
                                       reason="reverse_counters_missing",
                                       detail={"port": port, "service": proto, "reflectors": len(dsts),
                                               "pps": _r(rate, 1)}))
                continue
            ratio = pi / po if po else 0.0
            if ratio > cfg.amp_max_response_ratio:
                continue
            sig.append(LineSignal(
                entity_pseudonym=line, kind="amplification_request", label=LABEL_AMPLIFICATION, strong=True,
                start=_utc(t0), end=_utc(t1 + cfg.bucket_s), targets=sorted(dsts)[:200],
                metrics={"port": port, "service": proto, "distinct_reflectors": len(dsts), "pps": _r(rate, 1),
                         "response_ratio": _r(ratio, 5), "active_buckets": len(active),
                         "mean_request_bytes": _r(bo / po if po else None, 1)},
                summary=(f"{len(dsts)} distinct {proto} reflectors (udp/{port}) at {rate:,.0f} pps with almost "
                         f"no replies ({ratio:.3f}): spoofed-source reflection requests")))
        return sig, abst

    def _reflector(self, line: str, flows: list[_Flow], w0: float) -> list[LineSignal]:
        cfg = self.cfg
        k = cfg.sampling_interval
        cells: dict[tuple[str, int], list[int]] = defaultdict(lambda: [0, 0, 0, 0])
        unknown: set[tuple[str, int]] = set()
        for f in flows:
            if f.proto != "udp" or f.po is None or f.bo is None:
                continue
            key = (f.dst, int((f.t - w0) // cfg.bucket_s))
            if f.pi is None or f.bi is None:
                unknown.add(key)
                continue
            c = cells[key]
            c[0] += f.po * k
            c[1] += f.pi * k
            c[2] += f.bo * k
            c[3] += f.bi * k
        hits: dict[str, list[tuple[int, float, float, float]]] = defaultdict(list)
        for (dst, b), (po, pi, bo, bi) in cells.items():
            if (dst, b) in unknown or po <= 0 or bi <= 0:
                continue
            rate = po / cfg.bucket_s
            if rate < cfg.reflector_min_pps or pi / po < cfg.reflector_min_request_ratio:
                continue
            amp = bo / bi
            if amp < cfg.reflector_min_amplification:
                continue
            hits[dst].append((b, rate, amp, pi / po))
        out = []
        for dst, rows in hits.items():
            if len(rows) < cfg.reflector_min_buckets:
                continue
            rows.sort()
            out.append(LineSignal(
                entity_pseudonym=line, kind="abused_reflector", label=LABEL_REFLECTOR, strong=True,
                start=_utc(w0 + rows[0][0] * cfg.bucket_s), end=_utc(w0 + (rows[-1][0] + 1) * cfg.bucket_s),
                targets=[dst],
                metrics={"buckets": len(rows), "peak_pps": _r(max(r[1] for r in rows), 1),
                         "median_amplification": _r(statistics.median(r[2] for r in rows), 2),
                         "requests_per_response": _r(statistics.median(r[3] for r in rows), 3)},
                summary=(f"answers {dst} about one-for-one at up to {max(r[1] for r in rows):,.0f} pps with "
                         f"{statistics.median(r[2] for r in rows):.0f}x more bytes out than in: an open "
                         "amplifier on this line is being used against a third party")))
        return out

    # ------------------------------------------------------------------ proxy relaying
    def _proxy(self, line: str, flows: list[_Flow], w0: float, w1: float) -> tuple[list[LineSignal], list[Abstention]]:
        cfg = self.cfg
        k = cfg.sampling_interval
        rb = cfg.relay_bin_s
        nbins = max(1, math.ceil((w1 - w0) / rb))
        out_by: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        in_by: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        missing_bytes: set[str] = set()
        for f in flows:
            b = min(nbins - 1, max(0, int((f.t - w0) // rb)))
            if f.bo is None:
                missing_bytes.add(f.dst)
            else:
                out_by[f.dst][b] += f.bo * k
            if f.bi is not None:
                in_by[f.dst][b] += f.bi * k
        # A sink is persistent within its own lifetime (first to last active bin), so a relay
        # that started mid-window is judged on the bins where it could have been active.
        spans: dict[str, tuple[int, int]] = {}
        for dst, bins in out_by.items():
            lo, hi = min(bins), max(bins)
            n_span = hi - lo + 1
            if n_span < cfg.relay_min_bins or len(bins) / n_span < cfg.relay_sink_min_presence:
                continue
            if sum(bins.values()) / (n_span * rb / 3600.0) < cfg.relay_min_bytes_per_hour:
                continue
            spans[dst] = (lo, hi)
        sig: list[LineSignal] = []
        abst: list[Abstention] = []
        if not spans:
            return sig, abst
        tails = _continuations(flows, cfg.short_session_max_ms, cfg.continuation_slack_ms)
        for sink, (lo, hi) in sorted(spans.items()):
            span_h = (hi - lo + 1) * rb / 3600.0
            peers: set[str] = set()
            hourly: dict[int, set[str]] = defaultdict(set)
            inshort = [0] * nbins
            for i, f in enumerate(flows):
                if f.dst == sink or f.bi is None or i in tails:
                    continue
                if f.dur is not None and f.dur >= cfg.short_session_max_ms:
                    continue
                b = min(nbins - 1, max(0, int((f.t - w0) // rb)))
                if not lo <= b <= hi:
                    continue
                peers.add(f.dst)
                hourly[int((f.t - w0) // 3600)].add(f.dst)
                inshort[b] += f.bi * k
            # mean distinct peers per clock hour of the sink's lifetime (a whole-span count
            # saturates on long windows because popular sites repeat)
            n_hours = max(1, math.ceil(span_h))
            peers_h = sum(len(v) for v in hourly.values()) / n_hours
            if peers_h < cfg.relay_min_peers_per_hour:
                continue
            outs = [out_by[sink].get(b, 0) for b in range(nbins)]
            sink_in = sum(in_by[sink].values())
            relayed = sum(inshort)
            if relayed / span_h < cfg.relay_min_bytes_per_hour:
                continue
            if sink in missing_bytes:
                abst.append(Abstention(entity_pseudonym=line, label=LABEL_PROXY, reason="byte_counters_missing",
                                       detail={"sink": sink, "peers": len(peers)}))
                continue
            both = [b for b in range(nbins) if outs[b] > 0 and inshort[b] > 0]
            smooth = [inshort[b] + (inshort[b - 1] if b > 0 else 0) for b in range(nbins)]
            lag1 = [b for b in range(1, nbins) if outs[b] > 0 and inshort[b - 1] > 0]
            candidates = []
            if len(both) >= cfg.relay_min_bins:
                candidates.append(_corr([outs[b] for b in both], [inshort[b] for b in both]))
                candidates.append(_corr([outs[b] for b in both], [smooth[b] for b in both]))
            if len(lag1) >= cfg.relay_min_bins:
                candidates.append(_corr([outs[b] for b in lag1], [inshort[b - 1] for b in lag1]))
            valid = [c for c in candidates if c is not None]
            if not valid:
                continue
            corr = max(valid)
            sink_out = sum(outs)
            balance = sink_out / relayed if relayed else math.inf
            asym = sink_out / max(sink_in, 1)
            if corr < cfg.relay_min_corr or not cfg.relay_balance_min <= balance <= cfg.relay_balance_max:
                continue
            if asym < cfg.relay_sink_min_out_in_ratio:
                continue  # the sink sends back as much as it receives: a conversation, not an upstream
            active = [b for b in range(nbins) if outs[b] > 0]
            sig.append(LineSignal(
                entity_pseudonym=line, kind="proxy_relay", label=LABEL_PROXY, strong=True,
                start=_utc(w0 + active[0] * rb), end=_utc(w0 + (active[-1] + 1) * rb), targets=[sink],
                metrics={"sink": sink, "sink_kind": self._kind(sink), "distinct_peers": len(peers),
                         "peers_per_hour": _r(peers_h, 2), "relay_correlation": _r(corr, 4),
                         "byte_balance": _r(balance, 4), "sink_out_in_ratio": _r(asym, 2),
                         "relayed_bytes_per_hour": _r(relayed / span_h, 0), "bins_compared": len(both),
                         "bin_s": rb, "active_hours": _r(span_h, 2),
                         "sink_presence": _r(len(out_by[sink]) / (hi - lo + 1), 3)},
                summary=(f"bytes received from {len(peers)} unrelated peers leave again toward {sink} "
                         f"(correlation {corr:.2f}, balance {balance:.2f}): inbound-then-outbound relaying")))
        return sig, abst

    # ------------------------------------------------------------------ spam / stuffing
    def _active_hours(self, t0: float, t1: float) -> float:
        """Hours spanned by an activity, floored at one hour so a short burst is not extrapolated."""
        return max((t1 - t0 + self.cfg.bucket_s) / 3600.0, 1.0)

    def _spam(self, line: str, flows: list[_Flow]) -> list[LineSignal]:
        cfg = self.cfg
        dsts: set[str] = set()
        n = 0
        t0 = t1 = None
        for f in flows:
            if f.proto == "tcp" and f.port in cfg.spam_ports:
                dsts.add(f.dst)
                n += 1
                t0 = f.t if t0 is None else min(t0, f.t)
                t1 = f.t if t1 is None else max(t1, f.t)
        if t0 is None or t1 is None or len(dsts) < cfg.spam_min_dsts:
            return []
        rate = len(dsts) / self._active_hours(t0, t1)
        if rate < cfg.spam_min_dsts_per_hour:
            return []
        return [LineSignal(
            entity_pseudonym=line, kind="spam", label=LABEL_SPAM, strong=True, start=_utc(t0),
            end=_utc(t1 + cfg.bucket_s), targets=sorted(dsts)[:500],
            metrics={"distinct_mail_exchangers": len(dsts), "smtp_sessions": n, "mx_per_hour": _r(rate, 2),
                     "ports": list(cfg.spam_ports)},
            summary=f"direct SMTP to {len(dsts)} distinct mail exchangers ({rate:.0f}/h, {n} sessions)")]

    def _stuffing(self, line: str, flows: list[_Flow]) -> list[LineSignal]:
        cfg = self.cfg
        per: dict[tuple[str, int], list[_Flow]] = defaultdict(list)
        fan: dict[int, set[str]] = defaultdict(set)
        fan_t: dict[int, list[float]] = defaultdict(list)
        tails = _continuations(flows, cfg.short_session_max_ms, cfg.continuation_slack_ms)
        for i, f in enumerate(flows):
            if f.proto != "tcp" or f.port is None:
                continue
            if f.port in cfg.stuffing_ports and i not in tails and (f.dur is None or f.dur < cfg.short_session_max_ms):
                per[(f.dst, f.port)].append(f)
            if f.port in cfg.auth_ports:
                fan[f.port].add(f.dst)
                fan_t[f.port].append(f.t)
        out: list[LineSignal] = []
        for (dst, port), fl in per.items():
            if len(fl) < cfg.stuffing_min_sessions:
                continue
            span_h = max((fl[-1].t - fl[0].t) / 3600.0, cfg.bucket_s / 3600.0)
            rate = len(fl) / span_h
            if rate < cfg.stuffing_min_sessions_per_hour:
                continue
            bi = [float(f.bi) for f in fl if f.bi is not None]
            if len(bi) < 0.8 * len(fl):
                continue
            bcv = _cv(bi)
            gaps = [b.t - a.t for a, b in zip(fl, fl[1:])]
            icv = _cv(gaps)
            if bcv is None or bcv > cfg.stuffing_max_bytes_cv:
                continue
            if icv is None or icv < cfg.stuffing_min_interarrival_cv:
                continue
            strong = port in cfg.auth_ports or (rate >= 2 * cfg.stuffing_min_sessions_per_hour
                                                  and port not in (80, 443, 8080, 8443))
            out.append(LineSignal(
                entity_pseudonym=line, kind="credential_stuffing", label=LABEL_STUFFING, strong=strong,
                start=_utc(fl[0].t), end=_utc(fl[-1].t + cfg.bucket_s), targets=[dst],
                metrics={"port": port, "sessions": len(fl), "sessions_per_hour": _r(rate, 1),
                         "bytes_in_cv": _r(bcv, 4), "interarrival_cv": _r(icv, 4),
                         "median_bytes_in": _r(statistics.median(bi), 0)},
                summary=(f"{len(fl)} short login-like sessions to {dst}:{port} ({rate:,.0f}/h), near-identical "
                         f"reply sizes (cv {bcv:.2f}) and irregular timing (cv {icv:.2f})")))
        for port, dsts in fan.items():
            ts = fan_t[port]
            hours = self._active_hours(min(ts), max(ts))
            if len(dsts) < cfg.auth_fanout_min_dsts or len(dsts) / hours < cfg.auth_fanout_min_dsts_per_hour:
                continue
            out.append(LineSignal(
                entity_pseudonym=line, kind="auth_fanout", label=LABEL_STUFFING, strong=True,
                start=_utc(min(ts)), end=_utc(max(ts) + cfg.bucket_s), targets=[],
                metrics={"port": port, "distinct_hosts": len(dsts), "hosts_per_hour": _r(len(dsts) / hours, 2)},
                summary=f"tcp/{port} login service probed on {len(dsts)} distinct hosts ({len(dsts) / hours:.0f}/h)"))
        return out

    # ------------------------------------------------------------------ correlation
    def _campaigns(self, signals: list[LineSignal], onsets: list[_Onset], episodes: list[_Episode],
                   popularity: dict[str, float]) -> list[EgressCampaign]:
        cfg = self.cfg
        out: list[EgressCampaign] = []
        slack = float(cfg.sync_slack_s)

        # (a) synchronized onsets toward one target
        by_key: dict[str, list[_Onset]] = defaultdict(list)
        for o in onsets:
            by_key[o.key].append(o)
        for key, lst in by_key.items():
            lst.sort(key=lambda o: o.t)
            for cluster in _cluster(lst, lambda o: o.t, slack):
                members = sorted({o.line for o in cluster})
                if len(members) < cfg.sync_min_lines:
                    continue
                peak = {}
                for o in cluster:
                    peak[o.line] = max(peak.get(o.line, 0.0), o.peak_pps)
                agg = sum(peak.values())
                if agg < cfg.sync_min_aggregate_pps:
                    continue
                target = key.split(":", 1)[1]
                t0, t1 = cluster[0].t, max(o.end for o in cluster)
                spread = cluster[-1].t - cluster[0].t
                out.append(EgressCampaign(
                    campaign_id=_campaign_id(self.tenant_id, LABEL_DDOS, "sync_burst", [target], t0),
                    tenant_id=self.tenant_id, label=LABEL_DDOS, kind="sync_burst", member_lines=members,
                    n_lines=len(members), targets=[target], start=_utc(t0), end=_utc(t1),
                    metrics={"aggregate_peak_pps": _r(agg, 1), "onset_spread_s": _r(spread, 1),
                             "target_kind": "prefix" if key.startswith("pfx:") else "host"},
                    explanation=(f"{len(members)} unrelated lines started one-way bursts toward {target} within "
                                 f"{spread:.0f} s of each other (aggregate {agg:,.0f} pps)")))

        # (b) overlapping strong floods toward one target (onset may be outside the window)
        flood_sig = [s for s in signals if s.kind == "flood" and s.strong]
        by_target: dict[str, list[LineSignal]] = defaultdict(list)
        for s in flood_sig:
            by_target[s.targets[0]].append(s)
        covered = {(c.targets[0], m) for c in out for m in c.member_lines}
        for target, lst in by_target.items():
            lst.sort(key=lambda s: s.start)
            for cluster in _cluster_intervals(lst, slack):
                members = sorted({s.entity_pseudonym for s in cluster})
                if len(members) < cfg.sync_min_lines or all((target, m) in covered for m in members):
                    continue
                t0 = min(s.start for s in cluster)
                t1 = max(s.end for s in cluster)
                agg = sum(float(s.metrics.get("peak_pps") or 0) for s in cluster)
                out.append(EgressCampaign(
                    campaign_id=_campaign_id(self.tenant_id, LABEL_DDOS, "shared_target", [target], t0.timestamp()),
                    tenant_id=self.tenant_id, label=LABEL_DDOS, kind="shared_target", member_lines=members,
                    n_lines=len(members), targets=[target], start=t0, end=t1,
                    metrics={"aggregate_peak_pps": _r(agg, 1)},
                    explanation=f"{len(members)} lines flooded {target} during overlapping intervals"))

        # (c) amplification: same reflection port abused by several lines at once
        amp = [s for s in signals if s.kind == "amplification_request"]
        by_port: dict[int, list[LineSignal]] = defaultdict(list)
        for s in amp:
            by_port[int(s.metrics["port"])].append(s)
        for port, lst in by_port.items():
            lst.sort(key=lambda s: s.start)
            for cluster in _cluster_intervals(lst, slack):
                members = sorted({s.entity_pseudonym for s in cluster})
                if len(members) < cfg.campaign_min_lines:
                    continue
                reflectors = sorted(set().union(*(set(s.targets) for s in cluster)))
                t0 = min(s.start for s in cluster)
                shared = _shared_fraction([set(s.targets) for s in cluster])
                out.append(EgressCampaign(
                    campaign_id=_campaign_id(self.tenant_id, LABEL_AMPLIFICATION, "shared_reflector_port",
                                             [str(port)], t0.timestamp()),
                    tenant_id=self.tenant_id, label=LABEL_AMPLIFICATION, kind="shared_reflector_port",
                    member_lines=members, n_lines=len(members), targets=reflectors[:200], start=t0,
                    end=max(s.end for s in cluster),
                    metrics={"port": port, "service": cfg.amp_ports.get(port), "reflectors": len(reflectors),
                             "reflector_overlap": _r(shared, 4)},
                    explanation=(f"{len(members)} lines sent reflection requests to udp/{port} reflectors at the "
                                 f"same time ({len(reflectors)} reflectors, {shared:.0%} shared)")))

        # (d) proxy sink shared by several lines
        prox = [s for s in signals if s.kind == "proxy_relay"]
        by_sink: dict[str, list[LineSignal]] = defaultdict(list)
        for s in prox:
            by_sink[s.targets[0]].append(s)
        for sink, lst in by_sink.items():
            members = sorted({s.entity_pseudonym for s in lst})
            if len(members) < cfg.campaign_min_lines:
                continue
            if popularity.get(sink, 0.0) > cfg.popular_fraction:
                continue  # a popular service (VPN provider, cloud) is not evidence of a shared controller
            t0 = min(s.start for s in lst)
            out.append(EgressCampaign(
                campaign_id=_campaign_id(self.tenant_id, LABEL_PROXY, "shared_sink", [sink], t0.timestamp()),
                tenant_id=self.tenant_id, label=LABEL_PROXY, kind="shared_sink", member_lines=members,
                n_lines=len(members), targets=[sink], start=t0, end=max(s.end for s in lst),
                metrics={"sink_kind": self._kind(sink), "sink_popularity": _r(popularity.get(sink), 4)},
                explanation=f"{len(members)} unrelated lines relay traffic upstream to the same sink {sink}"))

        # (e) spam: overlapping mail-exchanger sets
        spam = [s for s in signals if s.kind == "spam"]
        groups = _union_groups(spam, lambda a, b: _overlap(a.start.timestamp(), a.end.timestamp(),
                                                           b.start.timestamp(), b.end.timestamp(), slack)
                               and _jaccard(set(a.targets), set(b.targets)) >= cfg.spam_campaign_min_jaccard)
        for grp in groups:
            members = sorted({s.entity_pseudonym for s in grp})
            if len(members) < cfg.campaign_min_lines:
                continue
            common = sorted(set.intersection(*(set(s.targets) for s in grp)))
            t0 = min(s.start for s in grp)
            out.append(EgressCampaign(
                campaign_id=_campaign_id(self.tenant_id, LABEL_SPAM, "shared_mx_set", members, t0.timestamp()),
                tenant_id=self.tenant_id, label=LABEL_SPAM, kind="shared_mx_set", member_lines=members,
                n_lines=len(members), targets=common[:200], start=t0, end=max(s.end for s in grp),
                metrics={"common_mail_exchangers": len(common)},
                explanation=f"{len(members)} lines delivered SMTP to overlapping mail-exchanger sets at the same time"))

        # (f) one login service attacked from several lines
        stuff = [s for s in signals if s.kind == "credential_stuffing"]
        by_dst: dict[str, list[LineSignal]] = defaultdict(list)
        for s in stuff:
            by_dst[s.targets[0]].append(s)
        for dst, lst in by_dst.items():
            members = sorted({s.entity_pseudonym for s in lst})
            need = cfg.campaign_min_lines if any(s.strong for s in lst) else cfg.sync_min_lines
            if len(members) < need:
                continue
            t0 = min(s.start for s in lst)
            out.append(EgressCampaign(
                campaign_id=_campaign_id(self.tenant_id, LABEL_STUFFING, "shared_target", [dst], t0.timestamp()),
                tenant_id=self.tenant_id, label=LABEL_STUFFING, kind="shared_target", member_lines=members,
                n_lines=len(members), targets=[dst], start=t0, end=max(s.end for s in lst),
                metrics={"sessions": sum(int(s.metrics["sessions"]) for s in lst)},
                explanation=f"{len(members)} unrelated lines ran login-like session storms against {dst}"))
        return out

    # ------------------------------------------------------------------ verdicts
    def _verdicts(self, lines: dict[str, _Line], signals: list[LineSignal], campaigns: list[EgressCampaign],
                  abst: list[Abstention], popularity: dict[str, float]) -> list[LineVerdict]:
        by: dict[tuple[str, str], list[LineSignal]] = defaultdict(list)
        for s in signals:
            by[(s.entity_pseudonym, s.label)].append(s)
        camp_of: dict[tuple[str, str], list[EgressCampaign]] = defaultdict(list)
        for c in campaigns:
            for m in c.member_lines:
                camp_of[(m, c.label)].append(c)
        strong_labels: dict[str, set[str]] = defaultdict(set)
        for (line, label), sigs in by.items():
            core = [s for s in sigs if s.kind != "spoofing"]
            if label != LABEL_REFLECTOR and any(s.strong for s in core):
                strong_labels[line].add(label)
        out: list[LineVerdict] = []
        for (line, label), sigs in sorted(by.items()):
            camps = camp_of.get((line, label), [])
            core = [s for s in sigs if s.kind != "spoofing"]
            spoof = [s for s in by.get((line, LABEL_DDOS), []) if s.kind == "spoofing"]
            strong = any(s.strong for s in core)
            corro: list[str] = [f"cross_line:{c.campaign_id}" for c in camps]
            if label in (LABEL_DDOS, LABEL_AMPLIFICATION) and spoof:
                corro.append("spoofing_counters")
            corro.extend(f"also:{other}" for other in sorted(strong_labels[line] - {label}))
            if label == LABEL_REFLECTOR:
                verdict = "suspicious"
            elif not core:
                # spoofing counters with no flood visible in flows
                if not any(s.strong for s in spoof):
                    continue
                verdict = "suspicious"
            elif strong and corro:
                verdict = "malicious"
            elif strong or camps:
                verdict = "suspicious"
            else:
                continue  # weak, uncorroborated: below reporting
            all_sigs = core + (spoof if label in (LABEL_DDOS, LABEL_AMPLIFICATION) else [])
            counter = self._counter_facts(label, core, popularity)
            score = self._score(verdict, strong, corro, core)
            start = min(s.start for s in all_sigs)
            end = max(s.end for s in all_sigs)
            out.append(LineVerdict(
                entity_pseudonym=line, device_class=_device_class(lines.get(line)), label=label,
                verdict=verdict, score=score, signals=all_sigs, campaign_ids=[c.campaign_id for c in camps],
                corroboration=corro, alternatives=list(ALTERNATIVES[label]), counter_facts=counter,
                explanation=_explain(label, verdict, all_sigs, camps, corro, counter), start=start, end=end))
        flagged = {(v.entity_pseudonym, v.label) for v in out}
        seen: set[tuple[str, str]] = set()
        for a in abst:
            key = (a.entity_pseudonym, a.label)
            if key in flagged or key in seen:
                continue
            seen.add(key)
            ln = lines.get(a.entity_pseudonym)
            now_ts = max((f.t for f in ln.flows), default=0.0) if ln else 0.0
            out.append(LineVerdict(
                entity_pseudonym=a.entity_pseudonym, device_class=_device_class(ln), label=a.label,
                verdict="abstain", score=0.0, alternatives=list(ALTERNATIVES[a.label]),
                counter_facts={"abstain_reason": a.reason, **a.detail},
                explanation=(f"EGRESS abstained on {a.label}: {a.reason.replace('_', ' ')}. The traffic shape is "
                             "a candidate but the counters needed to decide are not exported. No inference was made."),
                start=_utc(now_ts), end=_utc(now_ts)))
        return out

    def _counter_facts(self, label: str, sigs: list[LineSignal], popularity: dict[str, float]) -> dict[str, Any]:
        cfg = self.cfg
        facts: dict[str, Any] = {}
        if label == LABEL_PROXY:
            for s in sigs:
                sink = s.targets[0]
                kind = self._kind(sink)
                if kind is None:
                    facts["sink_topology_unknown"] = True
                elif kind in ("residential", "vpn", "cloud"):
                    facts["sink_kind"] = kind
                pop = popularity.get(sink)
                if pop is not None and pop > cfg.popular_fraction:
                    facts["sink_popular"] = _r(pop, 4)
        elif label == LABEL_SPAM:
            for s in sigs:
                if float(s.metrics.get("mx_per_hour") or 0) < 1.5 * cfg.spam_min_dsts_per_hour:
                    facts["rate_near_threshold"] = True
        elif label == LABEL_STUFFING:
            if all(int(s.metrics.get("port", 0)) in (80, 443, 8080, 8443) for s in sigs if s.kind == "credential_stuffing") \
                    and not any(s.kind == "auth_fanout" for s in sigs):
                facts["web_port_only"] = True
        elif label == LABEL_DDOS:
            for s in sigs:
                if s.kind == "flood" and s.metrics.get("target_kind_hosting") in ("game", "vpn"):
                    facts["target_is_game_or_vpn_service"] = s.metrics.get("target_kind_hosting")
        elif label == LABEL_REFLECTOR:
            facts["subscriber_likely_victim_of_misconfiguration"] = True
        return facts

    @staticmethod
    def _score(verdict: str, strong: bool, corro: list[str], sigs: list[LineSignal]) -> float:
        s = 0.55 if strong else 0.35
        if verdict == "malicious":
            s += 0.25
        s += 0.04 * min(len(corro), 3)
        s += 0.02 * min(len(sigs), 3)
        return round(min(s, 0.99), 4)

    def _kind(self, ip: str) -> str | None:
        if self.context is None:
            return None
        try:
            return self.context.kind(ip)
        except Exception:  # foreign context objects: unknown, never a crash
            return None


# ---------------------------------------------------------------------- helpers

def _runs(idx: list[int], gap: int) -> list[list[int]]:
    """Group sorted bucket indices into runs, tolerating ``gap`` missing buckets inside a run."""
    out: list[list[int]] = []
    for b in idx:
        if out and b - out[-1][-1] <= gap + 1:
            out[-1].append(b)
        else:
            out.append([b])
    return out


def _continuations(flows: list[_Flow], long_ms: int, slack_ms: int) -> set[int]:
    """Indices of records that are the tail slice of a long-lived connection.

    Exporters cut a long connection into active-timeout slices; the last slice is short
    and would otherwise look like a new session. Flow records carry no source port, so a
    record counts as a tail when it starts where an active-timeout slice toward the same
    destination and port ended (within ``slack_ms``). ``flows`` must be sorted by time.
    """
    last: dict[tuple[str, int | None], _Flow] = {}
    out: set[int] = set()
    for i, f in enumerate(flows):
        key = (f.dst, f.port)
        prev = last.get(key)
        if prev is not None and prev.dur is not None and prev.dur >= long_ms \
                and abs(prev.t + prev.dur / 1000.0 - f.t) * 1000.0 <= slack_ms:
            out.add(i)
        last[key] = f
    return out


def _cluster(items: list[Any], key: Any, slack: float) -> list[list[Any]]:
    out: list[list[Any]] = []
    for it in items:
        if out and key(it) - key(out[-1][-1]) <= slack:
            out[-1].append(it)
        else:
            out.append([it])
    return out


def _cluster_intervals(sigs: list[LineSignal], slack: float) -> list[list[LineSignal]]:
    out: list[list[LineSignal]] = []
    cur_end = -math.inf
    for s in sigs:
        a, b = s.start.timestamp(), s.end.timestamp()
        if out and a - slack <= cur_end:
            out[-1].append(s)
            cur_end = max(cur_end, b)
        else:
            out.append([s])
            cur_end = b
    return out


def _union_groups(items: list[LineSignal], linked: Any) -> list[list[LineSignal]]:
    parent = list(range(len(items)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i].entity_pseudonym != items[j].entity_pseudonym and linked(items[i], items[j]):
                parent[find(i)] = find(j)
    groups: dict[int, list[LineSignal]] = defaultdict(list)
    for i, it in enumerate(items):
        groups[find(i)].append(it)
    return list(groups.values())


def _jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a or b else 0.0


def _shared_fraction(sets: list[set[str]]) -> float:
    union = set().union(*sets)
    if not union:
        return 0.0
    counts = Counter(x for s in sets for x in s)
    return sum(1 for c in counts.values() if c > 1) / len(union)


def _device_class(ln: _Line | None) -> str:
    if ln is None or not ln.classes:
        return "unknown"
    return ln.classes.most_common(1)[0][0]


def _explain(label: str, verdict: str, sigs: list[LineSignal], camps: list[EgressCampaign],
             corro: list[str], counter: dict[str, Any]) -> str:
    parts = [f"{verdict.upper()} {label}."]
    parts.extend(s.summary + "." for s in sigs[:4])
    if len(sigs) > 4:
        parts.append(f"(+{len(sigs) - 4} more signals)")
    parts.extend(c.explanation + "." for c in camps[:2])
    if verdict == "malicious":
        parts.append("Corroborated by: " + ", ".join(c.split(":", 1)[0] if c.startswith("cross_line") else c
                                                   for c in corro) + ".")
    elif label != LABEL_REFLECTOR:
        parts.append("Not corroborated by a second signal or by other lines: needs analyst review.")
    if counter:
        parts.append("Facts against or limiting this reading: "
                     + ", ".join(f"{k}={v}" for k, v in sorted(counter.items())) + ".")
    parts.append("Benign explanations to rule out: " + "; ".join(ALTERNATIVES[label]) + ".")
    return " ".join(parts)


__all__ = ["ALTERNATIVES", "EgressDetector", "HostingContext"]
