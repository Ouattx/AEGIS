"""Feed-versus-traffic reconciliation: what the feeds saw, what is stale, what they missed.

Given one tenant's observations, its :class:`~aegis.intel.store.IntelStore` and
(optionally) RESONANCE campaigns and Shadowserver victim reports,
:func:`reconcile` answers four questions:

1. **Which feed indicators were seen** in traffic (active, malicious): how many lines
   contacted each, whether the contact is *verified* (a domain was resolved and the
   line then talked to an address it resolved to) or a lookup only, and whether the
   claim is contradicted by another group.
2. **Which sightings hit stale, expired or withdrawn indicators**: contacts that a
   naive blocklist would have alerted on although the feed no longer stands behind
   them. These are never evidence; they are reported to show the lifecycle filter at work.
3. **Which RESONANCE campaigns have no feed coverage** ("found what the feeds miss"),
   which were covered only later (with the lead time AEGIS had over the feeds), and
   which were covered before detection.
4. **Do third-party victim reports agree** with AEGIS: of the lines Shadowserver
   reported infected, how many are campaign members or contacted a feed indicator.

All matching is as of explicit times: an indicator counts as *known at detection* only
when it was active at the campaign's ``window_end``; indicators first seen after
``now`` are invisible. The report contains counts, indicator values and campaign ids;
it lists line pseudonyms only when ``include_pseudonyms=True`` (tenant-internal use).
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegis.contracts.models import ObservationEvent
from aegis.intel.models import IntelIndicator, VictimReport, utc
from aegis.intel.store import IntelStore
from aegis.resonance.models import Campaign

CoverageStatus = Literal["covered_before_detection", "covered_after_detection", "stale_only", "uncovered"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IndicatorSighting(_M):
    type: str
    value: str
    state: str
    threat_label: str | None
    malware_family: str | None
    source_group: str
    sources: list[str]
    confidence: float
    lines: int
    contacts: int
    first_contact: datetime
    last_contact: datetime
    verified_contact: bool
    contradicted: bool
    independent_groups: int
    matched: list[str] = Field(default_factory=list)       # observed names / addresses (max 8)
    line_pseudonyms: list[str] | None = None


class CampaignCoverage(_M):
    campaign_id: str
    destinations: list[str]
    n_lines: int
    detected_at: datetime
    status: CoverageStatus
    matched: list[dict[str, Any]] = Field(default_factory=list)
    lead_time_s: float | None = None          # > 0: AEGIS detected before any feed listed it


class VictimAgreement(_M):
    reported_infected_lines: int
    reported_exposed_lines: int
    infected_in_aegis_campaign: int
    infected_with_feed_contact: int
    infected_without_aegis_signal: int
    by_family: dict[str, int] = Field(default_factory=dict)


class GroupValue(_M):
    source_group: str
    active_malicious: int
    seen: int
    stale_seen: int


class ReconciliationReport(_M):
    tenant_id: str
    generated_at: datetime
    window_start: datetime | None
    window_end: datetime | None
    n_events: int
    n_lines: int
    indicator_states: dict[str, int]
    seen: list[IndicatorSighting]
    seen_stale: list[IndicatorSighting]
    active_not_seen: int
    campaigns: list[CampaignCoverage]
    uncovered_campaigns: list[str]
    victims: VictimAgreement | None
    groups: list[GroupValue]
    summary: dict[str, Any]


# ---------------------------------------------------------------------------- index

class IndicatorIndex:
    """Lookup of indicators by IP (exact and containing CIDR) and by domain (and parents)."""

    def __init__(self, indicators: Iterable[IntelIndicator]):
        self._ip: dict[str, list[IntelIndicator]] = defaultdict(list)
        self._dom: dict[str, list[IntelIndicator]] = defaultdict(list)
        self._cidr: dict[tuple[int, int], dict[int, list[IntelIndicator]]] = defaultdict(lambda: defaultdict(list))
        for ind in indicators:
            if ind.type == "ip":
                self._ip[ind.value].append(ind)
            elif ind.type == "domain":
                self._dom[ind.value].append(ind)
            else:
                net = ipaddress.ip_network(ind.value)
                self._cidr[(net.version, net.prefixlen)][int(net.network_address)].append(ind)
        self._prefixes = sorted(self._cidr)

    def for_ip(self, ip: str) -> list[IntelIndicator]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        out = list(self._ip.get(str(addr), ()))
        bits = addr.max_prefixlen
        a = int(addr)
        for version, plen in self._prefixes:
            if version != addr.version:
                continue
            masked = (a >> (bits - plen)) << (bits - plen)
            out.extend(self._cidr[(version, plen)].get(masked, ()))
        return out

    def for_domain(self, name: str) -> list[IntelIndicator]:
        n = name.strip().lower().rstrip(".")
        parts = n.split(".")
        out: list[IntelIndicator] = []
        for i in range(len(parts) - 1):
            out.extend(self._dom.get(".".join(parts[i:]), ()))
        return out


# ---------------------------------------------------------------------------- accumulation

@dataclass
class _Acc:
    ind: IntelIndicator
    lines: set[str] = field(default_factory=set)
    contacts: int = 0
    first: datetime | None = None
    last: datetime | None = None
    verified: bool = False
    matched: set[str] = field(default_factory=set)

    def touch(self, line: str, t: datetime, matched: str, verified: bool) -> None:
        self.lines.add(line)
        self.contacts += 1
        self.first = t if self.first is None or t < self.first else self.first
        self.last = t if self.last is None or t > self.last else self.last
        self.verified = self.verified or verified
        if len(self.matched) < 8:
            self.matched.add(matched)


def _ikey(ind: IntelIndicator) -> tuple[str, str, str, str]:
    return ind.key


def reconcile(store: IntelStore, observations: Iterable[ObservationEvent], *, now: datetime,
              campaigns: Sequence[Campaign] = (), victims: Sequence[VictimReport] | None = None,
              include_pseudonyms: bool = False) -> ReconciliationReport:
    """Reconcile the tenant's feeds against its traffic and campaigns (see module docstring).

    ``victims`` defaults to the store's own victim reports. Every observation and campaign
    must belong to ``store.tenant_id`` (``ValueError`` otherwise: no cross-tenant paths).
    """
    now = utc(now)
    tenant = store.tenant_id
    stale_after = store.max_staleness
    knowable = [i for i in store.indicators() if i.first_seen <= now]
    index = IndicatorIndex(i for i in knowable if i.verdict == "malicious")
    contradicted = {(c.type, c.value) for c in store.contradictions(now)}
    groups_by_value: dict[tuple[str, str], set[str]] = defaultdict(set)
    for i in knowable:
        if i.verdict == "malicious" and i.is_active(now, stale_after):
            groups_by_value[(i.type, i.value)].add(i.source_group)

    # resolver answers per line (for verified domain contacts) and contacted IPs per line
    events = sorted(observations, key=lambda e: e.observed_at)
    answers: dict[tuple[str, str], set[str]] = defaultdict(set)     # (line, qname) -> ips
    contacted: dict[str, set[str]] = defaultdict(set)               # line -> ips
    lines: set[str] = set()
    for ev in events:
        if ev.tenant_id != tenant:
            raise ValueError(f"observation {ev.event_id} belongs to another tenant")
        if ev.entity_pseudonym is None:
            continue
        lines.add(ev.entity_pseudonym)
        if ev.flow is not None:
            contacted[ev.entity_pseudonym].add(ev.flow.dst_ip)
        if ev.dns is not None and ev.dns.answers:
            answers[(ev.entity_pseudonym, ev.dns.qname.strip().lower().rstrip("."))].update(ev.dns.answers)

    accs: dict[tuple[str, str, str, str], _Acc] = {}
    for ev in events:
        line = ev.entity_pseudonym
        if line is None:
            continue
        t = utc(ev.observed_at)
        if ev.flow is not None:
            for ind in index.for_ip(ev.flow.dst_ip):
                accs.setdefault(_ikey(ind), _Acc(ind)).touch(line, t, ev.flow.dst_ip, True)
        if ev.dns is not None:
            q = ev.dns.qname.strip().lower().rstrip(".")
            for ind in index.for_domain(q):
                resolved = answers.get((line, q), set())
                verified = bool(resolved & contacted.get(line, set()))
                accs.setdefault(_ikey(ind), _Acc(ind)).touch(line, t, q, verified)

    def sighting(a: _Acc, state: str) -> IndicatorSighting:
        ind = a.ind
        assert a.first is not None and a.last is not None
        return IndicatorSighting(
            type=ind.type, value=ind.value, state=state, threat_label=ind.threat_label,
            malware_family=ind.malware_family, source_group=ind.source_group, sources=list(ind.sources),
            confidence=ind.confidence, lines=len(a.lines), contacts=a.contacts, first_contact=a.first,
            last_contact=a.last, verified_contact=a.verified, contradicted=(ind.type, ind.value) in contradicted,
            independent_groups=len(groups_by_value.get((ind.type, ind.value), ())) if state == "active" else 0,
            matched=sorted(a.matched), line_pseudonyms=sorted(a.lines) if include_pseudonyms else None)

    seen: list[IndicatorSighting] = []
    seen_stale: list[IndicatorSighting] = []
    for a in accs.values():
        st = a.ind.state(now, stale_after)
        (seen if st == "active" else seen_stale).append(sighting(a, st))
    seen.sort(key=lambda s: (-s.lines, s.type, s.value, s.source_group))
    seen_stale.sort(key=lambda s: (-s.lines, s.type, s.value, s.source_group))
    seen_keys = {k for k, a in accs.items() if a.ind.state(now, stale_after) == "active"}
    active_mal = [i for i in knowable if i.verdict == "malicious" and i.is_active(now, stale_after)]

    # ------------------------------------------------------------------ campaigns
    coverage: list[CampaignCoverage] = []
    for c in campaigns:
        if c.tenant_id != tenant:
            raise ValueError(f"campaign {c.campaign_id} belongs to another tenant")
        coverage.append(_campaign_coverage(c, index, now, stale_after))
    coverage.sort(key=lambda cc: (cc.status != "uncovered", -cc.n_lines, cc.campaign_id))

    # ------------------------------------------------------------------ victims
    vlist = list(store.victims() if victims is None else victims)
    agreement = None
    if vlist:
        infected = {v.line_pseudonym for v in vlist if v.kind == "infection"}
        exposed = {v.line_pseudonym for v in vlist if v.kind == "exposure"} - infected
        in_campaign = {ln for c in campaigns for ln in c.member_lines}
        with_feed = {ln for a in accs.values() if a.ind.state(now, stale_after) == "active" for ln in a.lines}
        fam = Counter(v.malware_family or "unknown" for v in vlist if v.kind == "infection")
        agreement = VictimAgreement(
            reported_infected_lines=len(infected), reported_exposed_lines=len(exposed),
            infected_in_aegis_campaign=len(infected & in_campaign),
            infected_with_feed_contact=len(infected & with_feed),
            infected_without_aegis_signal=len(infected - in_campaign - with_feed),
            by_family=dict(sorted(fam.items())))

    groups: dict[str, GroupValue] = {}
    for i in active_mal:
        g = groups.setdefault(i.source_group, GroupValue(source_group=i.source_group, active_malicious=0, seen=0,
                                                         stale_seen=0))
        g.active_malicious += 1
    for s in seen:
        groups.setdefault(s.source_group, GroupValue(source_group=s.source_group, active_malicious=0, seen=0,
                                                     stale_seen=0)).seen += 1
    for s in seen_stale:
        groups.setdefault(s.source_group, GroupValue(source_group=s.source_group, active_malicious=0, seen=0,
                                                     stale_seen=0)).stale_seen += 1

    status_counts = Counter(cc.status for cc in coverage)
    leads = [cc.lead_time_s for cc in coverage if cc.lead_time_s is not None]
    summary = {
        "indicators_seen": len(seen), "stale_indicators_seen": len(seen_stale),
        "active_malicious_indicators": len(active_mal),
        "lines_contacting_active_indicators": len({ln for k in seen_keys for ln in accs[k].lines}),
        "campaigns": len(coverage), "campaign_coverage": dict(sorted(status_counts.items())),
        "campaigns_without_feed_coverage": status_counts.get("uncovered", 0) + status_counts.get("stale_only", 0),
        "median_lead_time_s": sorted(leads)[len(leads) // 2] if leads else None,
        "note": "Lead time is measured from the campaign's detection window end to the first feed listing.",
    }
    return ReconciliationReport(
        tenant_id=tenant, generated_at=now,
        window_start=utc(events[0].observed_at) if events else None,
        window_end=utc(events[-1].observed_at) if events else None,
        n_events=len(events), n_lines=len(lines), indicator_states=store.state_counts(now), seen=seen,
        seen_stale=seen_stale, active_not_seen=len(active_mal) - len(seen_keys), campaigns=coverage,
        uncovered_campaigns=[cc.campaign_id for cc in coverage if cc.status in ("uncovered", "stale_only")],
        victims=agreement, groups=sorted(groups.values(), key=lambda g: g.source_group), summary=summary)


def _campaign_coverage(c: Campaign, index: IndicatorIndex, now: datetime, stale_after: Any) -> CampaignCoverage:
    detected = utc(c.window_end)
    found: dict[tuple[str, str, str, str], tuple[IntelIndicator, str]] = {}
    for d in c.destinations:
        kind, _, val = d.partition(":")
        if kind == "d":
            for ind in index.for_domain(val):
                found.setdefault(ind.key, (ind, d))
        elif kind == "ip" and not c.shared_hosting_domain:
            for ind in index.for_ip(val):
                found.setdefault(ind.key, (ind, d))
    if not c.shared_hosting_domain:
        # a feed listing a shared CDN edge does not cover a domain-only campaign
        for ip in c.destination_ips:
            for ind in index.for_ip(ip):
                found.setdefault(ind.key, (ind, f"ip:{ip}"))
    before: list[IntelIndicator] = []
    after: list[IntelIndicator] = []
    matched: list[dict[str, Any]] = []
    for ind, dest in sorted(found.values(), key=lambda x: (x[0].first_seen, x[0].value)):
        at_detection = ind.state(detected, stale_after)
        at_now = ind.state(now, stale_after)
        if at_detection == "active":
            before.append(ind)
        elif ind.first_seen > detected and at_now in ("active", "stale", "expired", "withdrawn"):
            after.append(ind)
        matched.append({"destination": dest, "type": ind.type, "value": ind.value,
                        "source_group": ind.source_group, "first_seen": ind.first_seen.isoformat(),
                        "state_at_detection": at_detection, "state_now": at_now})
    status: CoverageStatus
    lead = None
    if before:
        status = "covered_before_detection"
    elif after:
        status = "covered_after_detection"
        lead = (min(i.first_seen for i in after) - detected).total_seconds()
    elif matched:
        status = "stale_only"
    else:
        status = "uncovered"
    return CampaignCoverage(campaign_id=c.campaign_id, destinations=list(c.destinations), n_lines=c.n_lines,
                            detected_at=detected, status=status, matched=matched[:32], lead_time_s=lead)


__all__ = ["CampaignCoverage", "CoverageStatus", "GroupValue", "IndicatorIndex", "IndicatorSighting",
           "ReconciliationReport", "VictimAgreement", "reconcile"]
