"""Genome extraction from Box Farm lab captures.

Procedure (deterministic, metadata only):

1. **Baseline subtraction.** Destinations contacted by a *clean* reference capture of the
   same box model (factory image, no family present) are the box's own benign behavior
   (vendor telemetry, NTP, IPTV middleware) and are excluded. Without a clean reference,
   only operator allowlisted suffixes are excluded and the genome's confidence is halved.
2. **Infrastructure grouping.** Remaining domain and IP keys are grouped when a domain
   resolved to an IP, or when IPs share a /24 (rotation over one block).
3. **Timer recovery.** RESONANCE's difference periodogram ranks groups; the strongest
   group (and any group with the same period within 5 %) is the family's check-in set.
4. **Interval model.** Check-ins = events on the set, coalesced within ``coalesce_s``.
   Intervals one period apart give the jitter sample ``u = d / P - 1`` (parametric fit:
   uniform vs normal chosen by kurtosis, plus empirical quantiles).
5. **Burst, DNS, infrastructure and activity** statistics from the same events.

Captures of several boxes of one family pool their interval/size samples.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Sequence

import numpy as np
import pandas as pd

from aegis.genome.capture import LabCapture
from aegis.genome.models import (
    ActivityModel,
    BurstModel,
    DnsModel,
    Genome,
    GenomeProvenance,
    InfraModel,
    TimerModel,
)
from aegis.genome.names import name_stats
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import build_event_table, prepare_series
from aegis.resonance.periodicity import best_periods, make_grid, periodogram

EXTRACTOR_VERSION = "genome-extract/1.0.0"
DAY = 86_400.0


@dataclass(frozen=True)
class ExtractConfig:
    coalesce_s: float = 5.0
    z_min: float = 6.0                   # periodogram z needed for a check-in set
    r_min: float = 0.15
    same_period_tol: float = 0.05
    big_transfer_factor: float = 20.0    # flows this many times the median beacon size are fetches
    validity_days: float = 30.0
    allowlist: tuple[str, ...] = ()
    period_min_s: float = 50.0
    period_max_s: float = 7200.0


@dataclass
class _CaptureStats:
    capture: LabCapture
    keys: list[str]
    period: float
    z: float
    r: float
    beacons: np.ndarray
    u: np.ndarray
    flows_per_beacon: list[int]
    beacon_bytes: np.ndarray
    big_times: np.ndarray
    dns_names_seq: list[str]
    n_dns: int
    ips: set[str]
    n_events: int
    secondary: list[float] = field(default_factory=list)
    dns_period: float | None = None
    dns_u: np.ndarray = field(default_factory=lambda: np.zeros(0))


@dataclass
class ExtractionResult:
    genome: Genome | None
    reason: str | None                   # None when a genome was produced, else the abstention reason
    diagnostics: dict[str, Any] = field(default_factory=dict)


def _norm(q: str) -> str:
    return str(q).strip().lower().rstrip(".")


def _allowlisted(name: str, allow: Sequence[str]) -> bool:
    bare = name.split(":", 1)[1]
    return any(bare == a or bare.endswith("." + a) for a in (x.lower().rstrip(".") for x in allow))


def _p24(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return str(ipaddress.ip_network(f"{ip}/24" if a.version == 4 else f"{ip}/48", strict=False))


def capture_keys(capture: LabCapture) -> set[str]:
    """Destination keys (d:/ip:) contacted by a capture."""
    out = {"ip:" + str(ip) for ip in capture.flows.get("dst_ip", pd.Series(dtype=object)).dropna()}
    out |= {"d:" + _norm(q) for q in capture.dns.get("qname", pd.Series(dtype=object)).dropna()}
    out |= {"ip:" + str(ip) for ip in capture.dns.get("answer_ip", pd.Series(dtype=object)).dropna()}
    return out


def _interval_u(beacons: np.ndarray, period: float) -> np.ndarray:
    d = np.diff(beacons)
    if len(d) == 0:
        return np.zeros(0)
    k = np.rint(d / period)
    ok = k == 1
    return d[ok] / period - 1.0


def _refine_period(beacons: np.ndarray, p0: float) -> float:
    p = p0
    for _ in range(3):
        u = _interval_u(beacons, p)
        if len(u) < 3:
            break
        p = p * (1.0 + float(np.mean(u)))
    return p


def _analyze(capture: LabCapture, benign: set[str], cfg: ExtractConfig) -> tuple[_CaptureStats | None, str | None]:
    rcfg = ResonanceConfig(period_min_s=cfg.period_min_s, period_max_s=cfg.period_max_s, coalesce_s=cfg.coalesce_s,
                           series_cap=100_000)
    flows, dns = capture.frames_with_line()
    t0, t1 = capture.start.timestamp(), capture.end.timestamp()
    tb = build_event_table(flows if len(flows) else None, dns if len(dns) else None, start=t0, end=t1)
    if len(tb) == 0:
        return None, "no_events"
    # exclude the box's own benign destinations and allowlisted names
    excl = np.zeros(len(tb.keys), dtype=bool)
    for k, name in enumerate(tb.keys.items):
        ips = tb.key_ips.get(k, set())
        if name in benign or (cfg.allowlist and _allowlisted(name, cfg.allowlist)):
            excl[k] = True
        elif name.startswith("d:") and ips and all(("ip:" + ip) in benign for ip in ips):
            excl[k] = True
    # infrastructure grouping: domain <-> IP, IP <-> /24
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for k, name in enumerate(tb.keys.items):
        if excl[k]:
            continue
        find(name)
        ips = tb.key_ips.get(k, set()) if name.startswith("d:") else {name[3:]}
        for ip in ips:
            if ("ip:" + ip) in benign:
                continue
            union(name, "ip:" + ip)
            p = _p24(ip)
            if p:
                union("ip:" + ip, "p24:" + p)
    comp_names: dict[str, list[str]] = {}
    for k, name in enumerate(tb.keys.items):
        if not excl[k]:
            comp_names.setdefault(find(name), []).append(name)
    if not comp_names:
        return None, "no_non_baseline_destinations"
    roots = sorted(comp_names)
    root_id = {r: i for i, r in enumerate(roots)}
    key_map = np.full(len(tb.keys), len(roots), dtype=np.int64)   # excluded keys -> sentinel group
    for k, name in enumerate(tb.keys.items):
        if not excl[k]:
            key_map[k] = root_id[find(name)]
    S = prepare_series(tb, rcfg, key_map=key_map)
    rows = np.flatnonzero((S.key < len(roots)) & (S.counts >= 8))
    if len(rows) == 0:
        return None, "too_few_events_on_candidate_destinations"
    grid = make_grid(rcfg)
    usable = grid.usable(tb.span_s, rcfg.min_cycles)
    pg = periodogram(S, grid, rcfg, rows=rows)
    per, z, r = best_periods(pg, grid, usable)
    order = np.argsort(-np.nan_to_num(z, nan=-np.inf))
    best = order[0]
    if not np.isfinite(z[best]) or z[best] < cfg.z_min or r[best] < cfg.r_min:
        return None, f"no_check_in_timer_found (best z={float(np.nan_to_num(z[best])):.1f})"
    p0 = float(per[best])
    chosen = [best]
    secondary: list[float] = []
    for j in order[1:]:
        if not np.isfinite(z[j]) or z[j] < cfg.z_min or r[j] < cfg.r_min:
            continue
        if abs(per[j] / p0 - 1.0) <= cfg.same_period_tol:
            chosen.append(j)
        else:
            secondary.append(float(per[j]))
    groups = {int(S.key[rows[j]]) for j in chosen}
    keys = sorted(n for r_ in roots if root_id[r_] in groups for n in comp_names[r_] if not n.startswith("p24:"))
    sel = np.isin(key_map[tb.key], list(groups))
    t = np.sort(tb.t[sel])
    kinds = tb.kind[sel][np.argsort(tb.t[sel], kind="stable")]
    nbytes = tb.nbytes[sel][np.argsort(tb.t[sel], kind="stable")]
    fmask = (kinds == 0) & np.isfinite(nbytes)
    fb = nbytes[fmask].astype(np.float64)
    med = float(np.median(fb)) if len(fb) else np.nan
    big = fmask & (nbytes > cfg.big_transfer_factor * med) if len(fb) else np.zeros(len(t), dtype=bool)
    beacon_bytes = nbytes[fmask & ~big].astype(np.float64)
    big_times = t[big]
    # check-ins: coalesce bursts of non-transfer events
    t, kinds = t[~big], kinds[~big]
    start_mask = np.ones(len(t), dtype=bool)
    start_mask[1:] = np.diff(t) > cfg.coalesce_s
    beacons = t[start_mask]
    burst_id = np.cumsum(start_mask) - 1
    flows_per = np.bincount(burst_id, weights=(kinds == 0).astype(float), minlength=len(beacons)).astype(int)
    p = _refine_period(beacons, p0)
    u = _interval_u(beacons, p)
    dsel = sel & (tb.kind == 1)
    do = np.argsort(tb.t[dsel], kind="stable")
    dns_seq = [tb.keys.items[int(k)][2:] for k in tb.key[dsel][do]]
    dns_period, dns_u = _dns_timer(tb.t[dsel], rcfg, tb.span_s, cfg)
    ips: set[str] = set()
    for n in keys:
        if n.startswith("ip:"):
            ips.add(n[3:])
    return _CaptureStats(capture=capture, keys=keys, period=p, z=float(z[best]), r=float(r[best]), beacons=beacons,
                         u=u, flows_per_beacon=flows_per.tolist(), beacon_bytes=beacon_bytes, big_times=big_times,
                         dns_names_seq=dns_seq, n_dns=int(dsel.sum()), ips=ips, n_events=int(len(tb)),
                         secondary=secondary, dns_period=dns_period, dns_u=dns_u), None


def _dns_timer(times: np.ndarray, rcfg: ResonanceConfig, span_s: float, cfg: ExtractConfig
               ) -> tuple[float | None, np.ndarray]:
    """Timer of the resolver-lookup channel alone (None when lookups are too few or aperiodic)."""
    t = np.sort(np.asarray(times, dtype=np.float64))
    if len(t) < 20:
        return None, np.zeros(0)
    keep = np.ones(len(t), dtype=bool)
    keep[1:] = np.diff(t) > cfg.coalesce_s
    t = t[keep]
    import pandas as _pd
    tb = build_event_table(None, _pd.DataFrame({"t": t, "line": "x", "qname": "c2", "answer_ip": None}),
                           start=float(t[0]), end=float(t[0]) + span_s)
    S = prepare_series(tb, rcfg)
    grid = make_grid(rcfg)
    pg = periodogram(S, grid, rcfg)
    per, z, r = best_periods(pg, grid, grid.usable(span_s, rcfg.min_cycles))
    if not np.isfinite(z[0]) or z[0] < cfg.z_min or r[0] < cfg.r_min:
        return None, np.zeros(0)
    p = _refine_period(t, float(per[0]))
    return p, _interval_u(t, p)


def _jitter_model(u: np.ndarray) -> tuple[str, float, list[float]]:
    if len(u) < 5:
        return "uniform", 0.1, []
    sd = float(np.std(u))
    q = [float(x) for x in np.quantile(u, [0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95])]
    if sd <= 0:
        return "uniform", 1e-3, q
    kurt = float(np.mean((u - u.mean()) ** 4) / sd ** 4) - 3.0
    # uniform excess kurtosis -1.2, normal 0
    if abs(kurt + 1.2) < abs(kurt):
        return "uniform", sd * np.sqrt(3.0), q
    return "normal", sd, q


def _period_of(times: np.ndarray, p: float) -> float | None:
    if len(times) < 6:
        return None
    u = _interval_u(np.sort(times), p)
    if len(u) < 3:
        return None
    return float(p * (1.0 + np.median(u)))


def extract_genome(captures: Sequence[LabCapture], *, clean_reference: Iterable[LabCapture] = (),
                   cfg: ExtractConfig | None = None, family: str | None = None, now: datetime | None = None,
                   topology: Any = None) -> ExtractionResult:
    """Extract one genome from captures of one family (several boxes may be pooled)."""
    cfg = cfg or ExtractConfig()
    if not captures:
        return ExtractionResult(None, "no_captures")
    refs = list(clean_reference)
    benign: set[str] = set()
    for rc in refs:
        benign |= capture_keys(rc)
    stats: list[_CaptureStats] = []
    reasons: dict[str, str] = {}
    for c in captures:
        st, why = _analyze(c, benign, cfg)
        if st is None:
            reasons[c.capture_id] = why or "unknown"
        else:
            stats.append(st)
    if not stats:
        return ExtractionResult(None, "no_capture_yielded_a_timer", {"per_capture": reasons})
    # pool on the dominant period (captures disagreeing by > 10 % are reported, not pooled)
    p_ref = float(np.median([s.period for s in stats]))
    pooled = [s for s in stats if abs(s.period / p_ref - 1) <= 0.10]
    for s in stats:
        if s not in pooled:
            reasons[s.capture.capture_id] = f"period_disagrees ({s.period:.0f}s vs {p_ref:.0f}s)"
    u = np.concatenate([s.u for s in pooled])
    n_int = int(len(u))
    w = np.array([max(1, len(s.u)) for s in pooled], dtype=float)
    period = float(np.average([s.period for s in pooled], weights=w))
    jfam, jscale, jq = _jitter_model(u)
    dns_pooled = [s for s in pooled if s.dns_period is not None and len(s.dns_u) >= 10]
    dns_timer = None
    if dns_pooled:
        du = np.concatenate([s.dns_u for s in dns_pooled])
        dp = float(np.average([s.dns_period for s in dns_pooled], weights=[len(s.dns_u) for s in dns_pooled]))
        dfam, dscale, dq = _jitter_model(du)
        if abs(dp / period - 1.0) > 0.02 or abs(dscale / max(jscale, 1e-6) - 1.0) > 0.25:
            dns_timer = TimerModel(period_s=round(dp, 3), jitter_family=dfam, jitter_scale=round(float(dscale), 5),
                                   jitter_quantiles=dq, n_intervals=int(len(du)))
    fpb = [x for s in pooled for x in s.flows_per_beacon]
    bb = np.concatenate([s.beacon_bytes for s in pooled])
    lb = np.log(bb[bb > 0]) if len(bb) else np.zeros(0)
    burst = BurstModel(flows_per_beacon_mean=float(np.mean(fpb)) if fpb else 0.0,
                       bytes_log_mean=float(np.mean(lb)) if len(lb) >= 5 else None,
                       bytes_log_sd=float(max(np.std(lb), 0.05)) if len(lb) >= 5 else None,
                       bytes_quantiles=[float(x) for x in np.quantile(bb, [0.1, 0.5, 0.9])] if len(bb) >= 5 else [])
    names = sorted({n for s in pooled for n in s.dns_names_seq})
    n_beacons = sum(len(s.beacons) for s in pooled)
    dwell: list[float] = []
    for s in pooled:
        if not s.dns_names_seq:
            continue
        _, dns = s.capture.frames_with_line()
        wanted = set(s.dns_names_seq)
        dd = dns[dns["qname"].map(lambda q, w=wanted: _norm(q) in w)].sort_values("t")
        if len(dd) < 2:
            continue
        nm = dd["qname"].map(_norm).to_numpy()
        tt = dd["t"].to_numpy(dtype=float)
        change = np.flatnonzero(nm[1:] != nm[:-1]) + 1
        if len(change) >= 2:
            dwell.extend(np.diff(tt[change]).tolist())
    ns = name_stats(names)
    dnsm = DnsModel(lookups_per_beacon=float(sum(s.n_dns for s in pooled) / max(1, n_beacons)),
                    distinct_names=len(names), rotation_s=float(np.median(dwell)) if dwell else None,
                    name_entropy_mean=ns["entropy"], name_bigram_novelty=ns["novelty"],
                    name_length_mean=ns["length"], resolver_count=None)
    ips = sorted({ip for s in pooled for ip in s.ips})
    days = max(sum(s.capture.span_s for s in pooled) / DAY, 1.0 / 24)
    p24s = {p for p in (_p24(ip) for ip in ips) if p}
    asns: set[int] = set()
    if topology is not None:
        for ip in ips:
            h = topology.host(ip) if hasattr(topology, "host") else None
            if h is not None and getattr(h, "asn", None) is not None:
                asns.add(int(h.asn))
    infra = InfraModel(distinct_ips=len(ips), distinct_prefix24=len(p24s),
                       distinct_asns=len(asns) if topology is not None else None,
                       ip_churn_per_day=max(0, len(ips) - len(pooled)) / days,
                       prefix24_churn_per_day=max(0, len(p24s) - len(pooled)) / days)
    big = np.concatenate([np.sort(s.big_times) for s in pooled]) if pooled else np.zeros(0)
    upd = None
    gaps = [np.diff(np.sort(s.big_times)) for s in pooled if len(s.big_times) >= 3]
    if gaps:
        g = np.concatenate(gaps)
        g = g[g > 10 * cfg.coalesce_s]
        upd = float(np.median(g)) if len(g) else None
    idle_t: list[np.ndarray] = []
    act_t: list[np.ndarray] = []
    for s in pooled:
        if not s.capture.active_periods:
            continue
        m = np.zeros(len(s.beacons), dtype=bool)
        for a, b in s.capture.active_periods:
            m |= (s.beacons >= a) & (s.beacons < b)
        act_t.append(s.beacons[m])
        idle_t.append(s.beacons[~m])
    ip_ = _period_of(np.concatenate(idle_t), period) if idle_t else None
    ap_ = _period_of(np.concatenate(act_t), period) if act_t else None
    activity = ActivityModel(update_fetch_period_s=upd, idle_period_s=ip_, active_period_s=ap_,
                             idle_active_ratio=(ap_ / ip_) if ip_ and ap_ else None)
    strength = float(np.clip(np.median([s.r for s in pooled]), 0, 1))
    conf = (0.5 * min(1.0, n_int / 100.0) + 0.5 * strength) * (1.0 if refs else 0.5)
    created = now or max(s.capture.end for s in pooled)
    if created.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    fam = family if family is not None else (pooled[0].capture.family if len({s.capture.family for s in pooled}) == 1
                                             else None)
    genome = Genome(
        family=fam,
        timer=TimerModel(period_s=round(period, 3), secondary_periods_s=sorted({round(x, 1) for s in pooled
                                                                                for x in s.secondary})[:4],
                         jitter_family=jfam, jitter_scale=round(float(jscale), 5), jitter_quantiles=jq,
                         n_intervals=n_int),
        dns_timer=dns_timer,
        burst=burst, dns=dnsm, infra=infra, activity=activity,
        c2_keys=sorted({k for s in pooled for k in s.keys}),
        provenance=GenomeProvenance(
            capture_ids=sorted(s.capture.capture_id for s in pooled),
            lab_box_models=sorted({s.capture.box_model for s in pooled}),
            firmware=sorted({s.capture.firmware for s in pooled if s.capture.firmware}),
            lab_id=pooled[0].capture.lab_id,
            licence=pooled[0].capture.licence,
            capture_start=min(s.capture.start for s in pooled), capture_end=max(s.capture.end for s in pooled),
            n_events=sum(s.n_events for s in pooled), extractor_version=EXTRACTOR_VERSION),
        confidence=round(float(conf), 4), created_at=created,
        expires_at=created + timedelta(days=cfg.validity_days))
    diag = {"per_capture": reasons, "pooled": [s.capture.capture_id for s in pooled],
            "periods": {s.capture.capture_id: round(s.period, 2) for s in stats},
            "clean_reference": [r.capture_id for r in refs], "big_transfers": int(len(big))}
    return ExtractionResult(genome, None, diag)
