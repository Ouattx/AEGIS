"""Historic aggregate traffic used by MIRROR to estimate collateral impact.

Only aggregates are kept: per indicator (destination IP or queried domain) the
average daily flow/query count and the number of distinct pseudonymous entities
that contacted it over the lookback window. No per-subscriber timeline is
retained, which keeps the simulation inside the security-metadata purpose.

``None`` means "no data" (unknown), never zero. An indicator that was observed
zero times in a window the history actually covers returns ``0``.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Protocol, runtime_checkable

from aegis.contracts.models import ObservationEvent


@runtime_checkable
class TrafficHistory(Protocol):
    """Read-only historic aggregates for one or more tenants."""

    def daily_flows(self, tenant_id: str, indicator: str) -> float | None:
        """Average daily flows (IP) or queries (domain); ``None`` if not covered."""
        ...

    def distinct_entities(self, tenant_id: str, indicator: str) -> int | None:
        """Distinct entities that contacted ``indicator``; ``None`` if not covered."""
        ...


def _canon(indicator: str) -> str:
    v = indicator.strip()
    try:
        return ipaddress.ip_address(v).compressed
    except ValueError:
        return v.rstrip(".").lower()


@dataclass
class _TenantAgg:
    flows: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    entities: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    days: float = 1.0


class AggregateTrafficHistory:
    """In-memory :class:`TrafficHistory` built from counts or raw events.

    ``covered_tenants`` lists the tenants this history has a complete window for;
    lookups for other tenants return ``None`` (unknown) rather than zero.
    """

    def __init__(self) -> None:
        self._agg: dict[str, _TenantAgg] = {}

    # ------------------------------------------------------------------ building
    def set_window(self, tenant_id: str, days: float) -> None:
        if days <= 0:
            raise ValueError("days must be positive")
        self._agg.setdefault(tenant_id, _TenantAgg()).days = float(days)

    def add(self, tenant_id: str, indicator: str, *, flows: int = 1,
            entity: str | None = None) -> None:
        if flows < 0:
            raise ValueError("flows must be >= 0")
        agg = self._agg.setdefault(tenant_id, _TenantAgg())
        key = _canon(indicator)
        agg.flows[key] += flows
        if entity:
            agg.entities[key].add(entity)

    @classmethod
    def from_events(cls, events: Iterable[ObservationEvent], *,
                    start: datetime | None = None,
                    end: datetime | None = None) -> "AggregateTrafficHistory":
        """Aggregate flow destinations and DNS query names from observation events.

        The window length (in days) per tenant is ``end - start`` when given,
        otherwise the span of the observed events (minimum one day).
        """
        hist = cls()
        spans: dict[str, list[datetime]] = {}
        for ev in events:
            ts = ev.observed_at
            if start is not None and ts < start:
                continue
            if end is not None and ts >= end:
                continue
            span = spans.setdefault(ev.tenant_id, [ts, ts])
            span[0] = min(span[0], ts)
            span[1] = max(span[1], ts)
            if ev.flow is not None and ev.flow.dst_ip:
                hist.add(ev.tenant_id, ev.flow.dst_ip, entity=ev.entity_pseudonym)
            if ev.dns is not None and ev.dns.qname:
                hist.add(ev.tenant_id, ev.dns.qname, entity=ev.entity_pseudonym)
        for tenant_id, (lo, hi) in spans.items():
            if start is not None and end is not None:
                days = (end - start).total_seconds() / 86400.0
            else:
                days = (hi - lo).total_seconds() / 86400.0
            hist.set_window(tenant_id, max(1.0, days))
        return hist

    # ------------------------------------------------------------------ queries
    def daily_flows(self, tenant_id: str, indicator: str) -> float | None:
        agg = self._agg.get(tenant_id)
        if agg is None:
            return None
        return agg.flows.get(_canon(indicator), 0) / agg.days

    def distinct_entities(self, tenant_id: str, indicator: str) -> int | None:
        agg = self._agg.get(tenant_id)
        if agg is None:
            return None
        return len(agg.entities.get(_canon(indicator), ()))

    def entities_for(self, tenant_id: str, indicators: Iterable[str]) -> set[str] | None:
        """Union of distinct entities across ``indicators`` (``None`` if tenant uncovered)."""
        agg = self._agg.get(tenant_id)
        if agg is None:
            return None
        out: set[str] = set()
        for ind in indicators:
            out |= agg.entities.get(_canon(ind), set())
        return out
