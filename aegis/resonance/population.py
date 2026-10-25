"""Destination population model: rarity, newness, hosting, traffic shape, clustering.

Resonance alone says *these lines share a timer*; it does not say the timer is
malicious. NTP, push keepalives and TV telemetry are shared timers too. The population
model decides which destinations are eligible campaign targets and how much weight a
test receives in the weighted Benjamini-Hochberg step:

* **rarity**: destinations reached by more than ``max_popularity`` of active lines are
  never targets (a botnet reaching 20 % of a tenant's lines would not need RESONANCE);
* **hosting**: IP-keyed destinations on shared hosting are never targets (blocking a CDN
  edge hits every co-tenant); domains served from shared hosting stay testable at reduced
  weight and are flagged *domain-only* for any downstream enforcement; unknown topology
  is treated as not enforcement-eligible (fail closed);
* **newness**: destinations established in the tenant's history (first seen more than
  ``established_days`` ago, with a stable line population) are standing timers, not
  campaigns, unless their line population surges;
* **shape**: heavy, long-lived flows (streaming, IPTV, uploads) are down-weighted and,
  beyond ``heavy_line_bytes`` (per line-day) / ``heavy_long_flow_frac``, ineligible.

Nothing here (or anywhere in RESONANCE) reads device class, vendor, IPTV app usage
or geography.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

import numpy as np
import pandas as pd

from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import KIND_FLOW, EventTable

DAY = 86_400.0


class TopologyLike(Protocol):
    def host(self, ip: str) -> Any: ...


class DestinationContext:
    """Operator hosting knowledge (e.g. :class:`aegis.lab.topology.HostingTopology`)."""

    def __init__(self, topology: TopologyLike | None = None):
        self.topology = topology

    def _host(self, ip: str) -> Any:
        if self.topology is None:
            return None
        try:
            return self.topology.host(ip)
        except Exception:  # pragma: no cover - defensive: foreign topology objects
            return None

    def shared(self, ip: str) -> bool | None:
        h = self._host(ip)
        if h is None:
            return None
        return bool(getattr(h, "shared", False))

    def cotenants(self, ip: str) -> int | None:
        h = self._host(ip)
        if h is None:
            return None
        return len(getattr(h, "hostnames", []) or [])

    def heavily_shared(self, ip: str, max_cotenants: int = 3) -> bool | None:
        """Shared CDN / multi-tenant hosting: never linked, never an IP-level target.

        Small co-hosting (a handful of names on one dedicated IP, typical of malicious
        infrastructure) is *not* heavy sharing; it stays linkable but :meth:`shared`
        still flags it for enforcement caution.
        """
        h = self._host(ip)
        if h is None:
            return None
        return getattr(h, "kind", None) == "shared_cdn" or (self.cotenants(ip) or 0) > max_cotenants

    def kind(self, ip: str) -> str | None:
        h = self._host(ip)
        return None if h is None else getattr(h, "kind", None)

    def asn(self, ip: str) -> int | None:
        h = self._host(ip)
        return None if h is None else getattr(h, "asn", None)

    def provider(self, ip: str) -> str | None:
        h = self._host(ip)
        return None if h is None else getattr(h, "provider", None)

    @staticmethod
    def prefix24(ip: str) -> str | None:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if a.version != 4:
            return str(ipaddress.ip_network(f"{ip}/48", strict=False))
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))


@dataclass
class KeyHistory:
    first_seen: float
    last_seen: float
    typical_lines: float


@dataclass
class DestinationHistory:
    """Tenant memory of destination keys (first sighting and usual line population).

    ``coverage_start`` is when the history began; without coverage, ages are unknown
    (``None``) rather than "new", so a cold start never makes everything look fresh.
    """
    coverage_start: float | None = None
    records: dict[str, KeyHistory] = field(default_factory=dict)

    def age_days(self, key: str, now: float) -> float | None:
        r = self.records.get(key)
        if r is not None:
            return max(0.0, (now - r.first_seen) / DAY)
        if self.coverage_start is None:
            return None
        return 0.0

    def typical_lines(self, key: str) -> float | None:
        r = self.records.get(key)
        return None if r is None else r.typical_lines

    def observe(self, keys: Iterable[str], n_lines: Iterable[int], first: Iterable[float],
                last: Iterable[float], *, alpha: float = 0.3) -> None:
        for k, n, f, l in zip(keys, n_lines, first, last):
            r = self.records.get(k)
            if r is None:
                self.records[k] = KeyHistory(float(f), float(l), float(n))
            else:
                r.first_seen = min(r.first_seen, float(f))
                r.last_seen = max(r.last_seen, float(l))
                r.typical_lines = (1 - alpha) * r.typical_lines + alpha * float(n)
        if self.coverage_start is None:
            fl = [float(x) for x in first]
            if fl:
                self.coverage_start = min(fl)

    def to_dict(self) -> dict[str, Any]:
        return {"coverage_start": self.coverage_start,
                "records": {k: [r.first_seen, r.last_seen, r.typical_lines] for k, r in sorted(self.records.items())}}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "DestinationHistory":
        return cls(d.get("coverage_start"), {k: KeyHistory(*v) for k, v in d.get("records", {}).items()})


@dataclass
class KeyStats:
    """Per key id (aligned with ``table.keys``)."""
    n_lines: np.ndarray
    n_events: np.ndarray
    first_t: np.ndarray
    last_t: np.ndarray
    median_bytes: np.ndarray      # median over lines of bytes per line-day; NaN when unknown
    long_frac: np.ndarray         # NaN when no flows
    active_lines: int


def key_stats(table: EventTable, cfg: ResonanceConfig) -> KeyStats:
    nk = len(table.keys)
    key = table.key.astype(np.int64)
    n_events = np.bincount(key, minlength=nk)
    pairs = np.unique(key * (len(table.lines) + 1) + table.line.astype(np.int64))
    n_lines = np.bincount(pairs // (len(table.lines) + 1), minlength=nk)
    first = np.full(nk, np.nan)
    last = np.full(nk, np.nan)
    if len(table):
        g = pd.Series(table.t).groupby(key)
        mn, mx = g.min(), g.max()
        first[mn.index.to_numpy()] = mn.to_numpy()
        last[mx.index.to_numpy()] = mx.to_numpy()
    med = np.full(nk, np.nan)
    lf = np.full(nk, np.nan)
    fl = table.kind == KIND_FLOW
    if fl.any():
        days = max(table.span_s / DAY, 1.0 / 24)
        df = pd.DataFrame({"k": key[fl], "l": table.line[fl], "b": table.nbytes[fl].astype(np.float64),
                           "lg": (np.nan_to_num(table.dur_s[fl], nan=0.0) >= cfg.long_flow_s).astype(np.float64)})
        per_line = df.groupby(["k", "l"])["b"].sum(min_count=1) / days
        mb = per_line.groupby(level=0).median()
        med[mb.index.to_numpy()] = mb.to_numpy()
        lg = df.groupby("k")["lg"].mean()
        lf[lg.index.to_numpy()] = lg.to_numpy()
    active = int(len(np.unique(table.line))) if len(table) else 0
    return KeyStats(n_lines, n_events, first, last, med, lf, active)


class _UF:
    def __init__(self) -> None:
        self.parent: dict[Any, Any] = {}

    def find(self, x: Any) -> Any:
        p = self.parent.setdefault(x, x)
        root = x
        while p != root:
            root = p
            p = self.parent.setdefault(root, root)
        while x != root:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: Any, b: Any) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # deterministic root choice
            if str(ra) < str(rb):
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb


def infrastructure_clusters(table: EventTable, ctx: DestinationContext, cfg: ResonanceConfig,
                            candidate_keys: np.ndarray) -> dict[int, int]:
    """Group candidate keys sharing dedicated infrastructure.

    Links: a domain to each IP it resolved to (only when the IP is not heavily shared, or
    unknown to the topology but co-resolved by at most 3 domains in the data); an IP key to
    its own IP; and, when ``cluster_prefix24`` is set, dedicated-hosting IPs within one /24.
    Shared hosting never links anything (it would merge unrelated co-tenants).
    Returns ``{key_id: component_id}`` (component id = smallest member key id).
    """
    uf = _UF()
    ip_domains: dict[str, int] = {}
    for k in candidate_keys:
        name = table.keys.items[int(k)]
        if name.startswith("d:"):
            for ip in table.key_ips.get(int(k), ()):
                ip_domains[ip] = ip_domains.get(ip, 0) + 1
    for k in candidate_keys:
        k = int(k)
        name = table.keys.items[k]
        uf.find(("k", k))
        ips = table.key_ips.get(k, set())
        if name.startswith("ip:"):
            ips = {name[3:]}
        for ip in sorted(ips):
            sh = ctx.heavily_shared(ip)
            if sh is True:
                continue
            if sh is None and name.startswith("d:") and ip_domains.get(ip, 0) > 3:
                continue
            uf.union(("k", k), ("ip", ip))
            if cfg.cluster_prefix24 and sh is False and ctx.kind(ip) == "dedicated":
                p = ctx.prefix24(ip)
                if p:
                    uf.union(("ip", ip), ("p24", p))
    comp: dict[Any, list[int]] = {}
    for k in candidate_keys:
        comp.setdefault(uf.find(("k", int(k))), []).append(int(k))
    out: dict[int, int] = {}
    for members in comp.values():
        cid = min(members)
        for m in members:
            out[m] = cid
    return out


@dataclass
class UnitInfo:
    """One testable hypothesis: a destination key or an infrastructure cluster of keys."""
    unit_id: str
    members: list[int]
    component: int
    n_lines: int
    popularity: float
    median_bytes: float | None
    long_frac: float | None
    first_t: float
    age_days: float | None
    shared_domain: bool           # a member domain is served from heavily shared hosting
    ip_shared: bool               # an IP-keyed member is heavily shared hosting (never a target)
    topology_unknown: bool
    established: bool
    surging: bool
    allowlisted: bool
    asns: list[int]
    ips: list[str]
    cohosted_ips: list[str] = field(default_factory=list)   # IPs serving other names too (IP actions need review)
    eligible: bool = False
    abstain: bool = False
    reasons: list[str] = field(default_factory=list)
    weight: float = 0.0
    weight_parts: dict[str, float] = field(default_factory=dict)

    @property
    def enforcement_eligible(self) -> bool:
        """Domain-level enforcement only; IPs only when dedicated and known (fail closed)."""
        return self.eligible and not self.topology_unknown


def _allowlisted(name: str, allow: tuple[str, ...]) -> bool:
    bare = name.split(":", 1)[1] if ":" in name else name
    for a in allow:
        a = a.lower().rstrip(".")
        if name == a or bare == a or bare.endswith("." + a):
            return True
    return False


def assess_unit(unit_id: str, members: list[int], component: int, n_lines: int, active_lines: int,
                median_bytes: float, long_frac: float, first_t: float, now: float, table: EventTable,
                ctx: DestinationContext, history: DestinationHistory | None, cfg: ResonanceConfig) -> UnitInfo:
    names = [table.keys.items[m] for m in members]
    ips: set[str] = set()
    for m, nm in zip(members, names):
        ips.update(table.key_ips.get(m, set()) if nm.startswith("d:") else {nm[3:]})
    heavy = {ip: ctx.heavily_shared(ip) for ip in ips}
    cohosted = sorted(ip for ip in ips if ctx.shared(ip) is True)
    ip_shared = any(nm.startswith("ip:") and heavy.get(nm[3:]) is True for nm in names)
    shared_domain = any(nm.startswith("d:") and any(heavy.get(ip) is True for ip in table.key_ips.get(m, ()))
                        for m, nm in zip(members, names))
    topo_unknown = any(v is None for v in heavy.values()) or not ips
    asns = sorted({a for a in (ctx.asn(ip) for ip in ips) if a is not None})
    pop = n_lines / max(1, active_lines)

    ages: list[float | None] = []
    established = bool(names)
    surging = False
    for nm in names:
        a = history.age_days(nm, now) if history is not None else None
        ages.append(a)
        if a is None or a < cfg.established_days:
            established = False
        if history is not None:
            tl = history.typical_lines(nm)
            if tl is not None and n_lines > cfg.surge_factor * tl + cfg.surge_min_extra:
                surging = True
    if surging:
        established = False
    known_ages = [a for a in ages if a is not None]
    age = min(known_ages) if known_ages and len(known_ages) == len(ages) else None
    allow = any(_allowlisted(nm, cfg.allowlist) for nm in names)

    u = UnitInfo(unit_id=unit_id, members=members, component=component, n_lines=n_lines, popularity=pop,
                 median_bytes=None if not np.isfinite(median_bytes) else float(median_bytes),
                 long_frac=None if not np.isfinite(long_frac) else float(long_frac), first_t=first_t,
                 age_days=age, shared_domain=shared_domain, ip_shared=ip_shared, topology_unknown=topo_unknown,
                 established=established, surging=surging, allowlisted=allow, asns=asns, ips=sorted(ips),
                 cohosted_ips=cohosted)
    if n_lines < cfg.min_lines:
        u.reasons.append("too_few_lines")
        u.abstain = True
    if pop > cfg.max_popularity:
        u.reasons.append("popular")
    if ip_shared:
        u.reasons.append("ip_on_shared_hosting")
    if u.median_bytes is not None and u.median_bytes > cfg.heavy_line_bytes:
        u.reasons.append("streaming_like_volume")
    if u.long_frac is not None and u.long_frac > cfg.heavy_long_flow_frac:
        u.reasons.append("long_lived_flows")
    if established:
        u.reasons.append("established_destination")
    if allow:
        u.reasons.append("operator_allowlist")
    u.eligible = not u.reasons
    if u.eligible:
        rarity = 1.0 - 0.5 * pop / cfg.max_popularity
        if age is None:
            newness = cfg.no_history_weight
        elif age < cfg.new_days:
            newness = 1.0
        else:
            newness = 0.8
        if u.median_bytes is None or u.median_bytes <= cfg.light_line_bytes:
            shape = 1.0
        else:
            frac = np.log(u.median_bytes / cfg.light_line_bytes) / np.log(cfg.heavy_line_bytes /
                                                                          cfg.light_line_bytes)
            shape = float(np.clip(1.0 - 0.7 * frac, 0.3, 1.0))
        hosting = cfg.shared_domain_weight if shared_domain else 1.0
        u.weight_parts = {"rarity": round(rarity, 4), "newness": newness, "shape": round(shape, 4),
                          "hosting": hosting}
        u.weight = float(rarity * newness * shape * hosting)  # every factor <= 1 => sum(w) <= m
    return u
