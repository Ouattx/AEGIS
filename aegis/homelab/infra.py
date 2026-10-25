"""Contacted infrastructure of one lab device, with threat-feed matches.

Destinations are keyed like RESONANCE keys: ``d:<domain>`` when the flow's address was
returned to the device by the resolver within ``dns_join_ttl_s`` before the flow (DNS
answer join), ``ip:<address>`` otherwise. An address contacted with no matching lookup
in the capture is listed as *contacted without lookup*: a hard-coded address, a lookup
cached before the capture started, or DNS that bypassed the lab resolver (DoH/DoT).

Feed matching follows the semantics of :mod:`aegis.sentinel.rules` and is evaluated as
of the end of the capture:

* only a **signed** :class:`IOCBundle` (verified by :func:`aegis.sentinel.load_bundle`)
  can produce a witness; an indicator counts only while ``active`` (not expired, not
  stale, already known);
* a malicious indicator is **contradicted** by an active benign indicator for the same
  value (or a parent domain) from a different source group; its effective confidence is
  reduced and the contradiction is kept as counter-evidence;
* a domain match is a **verified contact** only when the device also sent traffic to an
  address that name resolved to; a lookup alone is weaker;
* an optional *unverified local list* (plain text) is shown for orientation only and is
  never used as a witness.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

from aegis.contracts.models import ObservationEvent
from aegis.homelab.usage import ResolvedUsage
from aegis.sentinel.features import normalize_name
from aegis.sentinel.rules import DEFAULT_MIN_CONFIDENCE, Indicator, IOCBundle

#: a feed match qualifies as an independent witness at or above this effective confidence
WITNESS_MIN_CONFIDENCE = 0.5
LONG_FLOW_S = 30.0


@dataclass(frozen=True)
class FeedMatch:
    feed_kind: Literal["signed_bundle", "unverified_local_list"]
    matched_on: Literal["domain", "ip"]
    value: str
    indicator_id: str | None
    verdict: str
    threat_label: str | None
    malware_family: str | None
    source: str
    source_group: str
    confidence: float | None
    effective_confidence: float | None
    state: str                           # active | expired | stale | not_yet_known | unverified
    contradicted_by: tuple[str, ...] = ()
    verified_contact: bool = False

    @property
    def contradicted(self) -> bool:
        return bool(self.contradicted_by)

    @property
    def is_witness(self) -> bool:
        """Qualifies as an independent supporting witness (signed, active, malicious, verified contact)."""
        return (self.feed_kind == "signed_bundle" and self.state == "active" and self.verdict == "malicious"
                and self.verified_contact and (self.effective_confidence or 0.0) >= WITNESS_MIN_CONFIDENCE)

    @property
    def is_weak(self) -> bool:
        """Signed and active but not a witness (lookup only, contradicted or low confidence)."""
        return (self.feed_kind == "signed_bundle" and self.state == "active" and self.verdict == "malicious"
                and not self.is_witness and (self.effective_confidence or 0.0) >= DEFAULT_MIN_CONFIDENCE)

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["contradicted_by"] = list(self.contradicted_by)
        d["is_witness"] = self.is_witness
        return d


@dataclass
class Destination:
    key: str
    ips: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    flows: int = 0
    long_flows: int = 0
    bytes_out: int | None = None
    bytes_in: int | None = None
    ports: Counter[int] = field(default_factory=Counter)
    protocols: Counter[str] = field(default_factory=Counter)
    dns_queries: int = 0
    rcodes: Counter[str] = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    active_contacts: int = 0
    idle_contacts: int = 0
    matches: list[FeedMatch] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return "domain" if self.key.startswith("d:") else "ip"

    @property
    def display(self) -> str:
        return self.key.split(":", 1)[1]

    @property
    def contacted_without_lookup(self) -> bool:
        return self.kind == "ip" and self.flows > 0

    @property
    def contacts(self) -> int:
        return self.flows + self.dns_queries

    def _seen(self, t: datetime) -> None:
        self.first_seen = t if self.first_seen is None or t < self.first_seen else self.first_seen
        self.last_seen = t if self.last_seen is None or t > self.last_seen else self.last_seen

    def to_dict(self) -> dict[str, Any]:
        return {"key": self.key, "kind": self.kind, "ips": sorted(self.ips), "names": sorted(self.names),
                "flows": self.flows, "long_flows": self.long_flows, "bytes_out": self.bytes_out,
                "bytes_in": self.bytes_in, "ports": [[p, n] for p, n in self.ports.most_common(6)],
                "protocols": dict(self.protocols), "dns_queries": self.dns_queries, "rcodes": dict(self.rcodes),
                "first_seen": self.first_seen.isoformat() if self.first_seen else None,
                "last_seen": self.last_seen.isoformat() if self.last_seen else None,
                "active_contacts": self.active_contacts, "idle_contacts": self.idle_contacts,
                "contacted_without_lookup": self.contacted_without_lookup,
                "matches": [m.to_dict() for m in self.matches]}


@dataclass
class InfraSummary:
    entity_pseudonym: str
    destinations: list[Destination]
    nxdomain_names: list[str]
    external_resolvers: list[str]          # addresses contacted on 53/853 that are not the lab resolver
    dot_flows: int
    as_of: datetime
    bundle: dict[str, Any] | None
    local_list_entries: int

    @property
    def witness_matches(self) -> list[FeedMatch]:
        return [m for d in self.destinations for m in d.matches if m.is_witness]

    @property
    def weak_matches(self) -> list[FeedMatch]:
        return [m for d in self.destinations for m in d.matches if m.is_weak]

    @property
    def contradicted_matches(self) -> list[FeedMatch]:
        return [m for d in self.destinations for m in d.matches if m.contradicted]

    def to_dict(self) -> dict[str, Any]:
        return {"entity_pseudonym": self.entity_pseudonym, "as_of": self.as_of.isoformat(),
                "destinations": [d.to_dict() for d in self.destinations],
                "nxdomain_names": len(self.nxdomain_names), "nxdomain_sample": self.nxdomain_names[:20],
                "external_resolvers": self.external_resolvers, "dot_flows": self.dot_flows, "bundle": self.bundle,
                "local_list_entries": self.local_list_entries}


def _add(a: int | None, b: int | None) -> int | None:
    if b is None:
        return a
    return b if a is None else a + b


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True


def load_local_list(src: str | Path | Iterable[str]) -> list[str]:
    """Plain-text indicator list: one domain or IP per line, ``#`` comments. Unverified."""
    lines: Iterable[str]
    if isinstance(src, Path) or (isinstance(src, str) and "\n" not in src and Path(src).exists()):
        lines = Path(src).read_text(encoding="utf-8").splitlines()
    elif isinstance(src, str):
        lines = src.splitlines()
    else:
        lines = src
    out = []
    for line in lines:
        s = line.split("#", 1)[0].strip()
        if s:
            out.append(s if _is_ip(s) else normalize_name(s))
    return sorted(set(out))


def _bundle_matches(bundle: IOCBundle, matched_on: Literal["domain", "ip"], value: str, as_of: datetime,
                    verified: bool) -> list[FeedMatch]:
    inds: tuple[Indicator, ...] = bundle.for_domain(value) if matched_on == "domain" else bundle.for_ip(value)
    benign = [i for i in inds if i.verdict == "benign" and i.is_active(as_of, bundle.max_staleness)]
    out = []
    for ind in inds:
        if ind.verdict != "malicious":
            continue
        state = ind.state(as_of, bundle.max_staleness)
        contra = [b for b in benign if b.source_group != ind.source_group]
        eff = ind.confidence
        if contra:
            eff = ind.confidence * (1.0 - max(b.confidence for b in contra))
        out.append(FeedMatch(feed_kind="signed_bundle", matched_on=matched_on, value=value,
                             indicator_id=ind.indicator_id, verdict=ind.verdict, threat_label=ind.threat_label,
                             malware_family=ind.malware_family, source=ind.source, source_group=ind.source_group,
                             confidence=ind.confidence, effective_confidence=round(eff, 4), state=state,
                             contradicted_by=tuple(b.indicator_id for b in contra), verified_contact=verified))
    return out


def _local_matches(local: Sequence[str], matched_on: Literal["domain", "ip"], value: str,
                   verified: bool) -> list[FeedMatch]:
    if matched_on == "ip":
        hit = value in local
    else:
        parts = value.split(".")
        hit = any(".".join(parts[i:]) in local for i in range(len(parts) - 1))
    if not hit:
        return []
    return [FeedMatch(feed_kind="unverified_local_list", matched_on=matched_on, value=value, indicator_id=None,
                      verdict="listed", threat_label=None, malware_family=None, source="user:local-list",
                      source_group="user-local-list", confidence=None, effective_confidence=None,
                      state="unverified", verified_contact=verified)]


def analyze_infrastructure(events: Sequence[ObservationEvent], entity_pseudonym: str, *, as_of: datetime,
                           gateway_ip: str, bundle: IOCBundle | None = None, local_list: Sequence[str] = (),
                           usage: ResolvedUsage | None = None, dns_join_ttl_s: float = 3600.0) -> InfraSummary:
    """Destinations, DNS outcomes and feed matches for one device."""
    dev = sorted((e for e in events if e.entity_pseudonym == entity_pseudonym), key=lambda e: e.observed_at)
    dests: dict[str, Destination] = {}
    answers: dict[str, list[tuple[float, str]]] = {}      # ip -> [(t, name)] lookups that returned it
    name_ips: dict[str, set[str]] = {}
    nx: list[str] = []
    resolvers: set[str] = set()
    dot = 0

    def state_of(t: float) -> int:
        if usage is None:
            return -1
        return int(usage.state_of([t])[0])

    def dest(key: str) -> Destination:
        d = dests.get(key)
        if d is None:
            d = dests[key] = Destination(key)
        return d

    for e in dev:
        t = e.observed_at.timestamp()
        st = state_of(t)
        if e.dns is not None:
            name = normalize_name(e.dns.qname)
            d = dest("d:" + name)
            d.names.add(name)
            d.dns_queries += 1
            d.rcodes[e.dns.rcode] += 1
            d._seen(e.observed_at)
            if e.dns.rcode == "NXDOMAIN":
                nx.append(name)
            for a in e.dns.answers:
                if _is_ip(a):
                    answers.setdefault(a, []).append((t, name))
                    name_ips.setdefault(name, set()).add(a)
            d.active_contacts += st == 1
            d.idle_contacts += st == 0
        elif e.flow is not None:
            fl = e.flow
            if fl.dst_port in (53, 853) and fl.dst_ip != gateway_ip:
                resolvers.add(fl.dst_ip)
                dot += fl.dst_port == 853
            joined = None
            for ta, name in reversed(answers.get(fl.dst_ip, [])):
                if ta <= t + 1.0 and t - ta <= dns_join_ttl_s:
                    joined = name
                    break
            d = dest("d:" + joined if joined else "ip:" + fl.dst_ip)
            d.ips.add(fl.dst_ip)
            d.flows += 1
            if fl.duration_ms is not None and fl.duration_ms >= LONG_FLOW_S * 1000:
                d.long_flows += 1
            d.bytes_out = _add(d.bytes_out, fl.bytes_out)
            d.bytes_in = _add(d.bytes_in, fl.bytes_in)
            if fl.dst_port is not None:
                d.ports[fl.dst_port] += 1
            d.protocols[fl.protocol] += 1
            d._seen(e.observed_at)
            d.active_contacts += st == 1
            d.idle_contacts += st == 0

    # names seen for addresses contacted without a joined lookup (looser, display only)
    for d in dests.values():
        if d.kind == "ip":
            for ip in d.ips:
                d.names.update(n for _, n in answers.get(ip, []))

    for d in dests.values():
        if d.kind == "domain":
            name = d.display
            contacted = bool(d.flows) and bool(d.ips & name_ips.get(name, set()))
            if bundle is not None:
                d.matches.extend(_bundle_matches(bundle, "domain", name, as_of, verified=contacted))
            if local_list:
                d.matches.extend(_local_matches(local_list, "domain", name, verified=contacted))
        for ip in sorted(d.ips):
            if bundle is not None:
                d.matches.extend(_bundle_matches(bundle, "ip", ip, as_of, verified=d.flows > 0))
            if local_list:
                d.matches.extend(_local_matches(local_list, "ip", ip, verified=d.flows > 0))

    ordered = sorted(dests.values(), key=lambda x: (-(len([m for m in x.matches if m.is_witness])),
                                                    -x.contacts, x.key))
    return InfraSummary(entity_pseudonym=entity_pseudonym, destinations=ordered, nxdomain_names=sorted(set(nx)),
                        external_resolvers=sorted(resolvers), dot_flows=dot, as_of=as_of.astimezone(timezone.utc),
                        bundle=bundle.provenance() if bundle is not None else None,
                        local_list_entries=len(local_list))


__all__ = ["Destination", "FeedMatch", "InfraSummary", "WITNESS_MIN_CONFIDENCE", "analyze_infrastructure",
           "load_local_list"]
