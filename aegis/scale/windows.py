"""Exact line-sharded SENTINEL feature windows.

:class:`aegis.sentinel.features.WindowStore` is per entity *except* for four pieces
of tenant-wide state:

1. the event-time **watermark** (when windows close, which events are late or dropped);
2. the tenant's **first event time** (window coverage) and whether the tenant has flow /
   DNS telemetry at all (missing-vs-zero features);
3. the **population context** of every window: how many entities were active, and how
   many of them contacted each destination IP / queried each name (prevalence features);
4. the set of buffered **bin indices**, which drives the gap-skipping of the window loop.

Sharding by line pseudonym keeps every entity's bins on one shard. This module makes
the tenant-wide state global again, so the union of the shards' feature vectors is
*identical* to what one ``WindowStore`` produces on the same stream:

* :class:`TenantClock` (coordinator) replays the watermark / lateness / drop rules over the
  global stream of compact event descriptors, in input order, and says when a window
  boundary is crossed;
* at each crossing the coordinator runs a three-step barrier: shards report their bin
  indices (:meth:`ShardWindowStore.bin_indices`), the coordinator simulates the window loop
  on their union (:func:`plan_close`), shards report per-window partial population
  counts (:meth:`ShardWindowStore.local_contexts`), the coordinator sums them
  (:meth:`WindowContext.merge`; entities are disjoint across shards, so sums are exact),
  and shards emit with the global context (:meth:`ShardWindowStore.close`).

Shards never close windows on their own (their local watermark is disabled).

Coupling note: :class:`ShardWindowStore` re-implements ``WindowStore._advance`` /
``_emit`` around the injected context and therefore depends on the private layout of
``aegis.sentinel.features``. ``tests/unit/test_scale_windows.py`` asserts equality with
the reference implementation on lab corpora, so any drift fails CI loudly.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from aegis.contracts.models import FeatureVector, ObservationEvent
from aegis.sentinel import features as _sf
from aegis.sentinel.features import WindowName, WindowStore


@dataclass
class WindowContext:
    """Population context of one window (partial on a shard, global after merging)."""
    population: int = 0
    ip_prev: Counter[str] = field(default_factory=Counter)
    q_prev: Counter[str] = field(default_factory=Counter)

    @staticmethod
    def merge(parts: Iterable["WindowContext"]) -> "WindowContext":
        out = WindowContext()
        for p in parts:
            out.population += p.population
            out.ip_prev.update(p.ip_prev)
            out.q_prev.update(p.q_prev)
        return out


@dataclass
class TenantGlobal:
    """Tenant-wide window state shared by all shards (mirrors ``features._Tenant``)."""
    first_ts: float
    watermark: float
    next_boundary_idx: int
    emitted_idx: int = -1
    has_flow: bool = False
    has_dns: bool = False


@dataclass(frozen=True)
class EventDescriptor:
    """What the coordinator needs to know about one accepted event (no payload)."""
    position: int
    tenant_id: str
    observed_ts: float
    ingested_ts: float
    is_flow: bool
    is_dns: bool
    admissible: bool          # passes the window store's (and SENTINEL's) input checks


@dataclass(frozen=True)
class ClosePlan:
    tenant_id: str
    end_indices: tuple[int, ...]
    next_boundary_idx: int
    emitted_idx: int


def plan_close(bin_indices: Iterable[int], next_boundary_idx: int, watermark: float, hop_s: int,
               n_bins: int, tenant_id: str) -> ClosePlan:
    """Simulate ``WindowStore._advance`` on the union of all shards' bin indices."""
    idxs = set(bin_indices)
    nb = next_boundary_idx
    emitted: int | None = None
    ends: list[int] = []
    while (nb + 1) * hop_s <= watermark:
        end_idx = nb + 1
        if not idxs:
            nb = max(nb, int(watermark // hop_s))
            emitted = nb
            break
        oldest = min(idxs)
        if oldest >= end_idx:
            nb = oldest
            emitted = oldest
            continue
        ends.append(end_idx)
        nb = end_idx
        emitted = end_idx
        lo = end_idx - n_bins + 1
        idxs = {k for k in idxs if k >= lo}
    return ClosePlan(tenant_id, tuple(ends), nb, -2 if emitted is None else emitted)


class TenantClock:
    """Coordinator-side replica of the window store's tenant-wide rules.

    Feed :meth:`observe` every event descriptor in global input order. It returns the
    watermark to close at when the event crossed a window boundary (else ``None``).
    """

    def __init__(self, window: WindowName = "24h", hop: timedelta | None = None, *,
                 allowed_lateness: timedelta = timedelta(minutes=2)):
        ref = WindowStore(window, hop, allowed_lateness=allowed_lateness)
        self.hop_s = ref.hop_s
        self.n_bins = ref.n_bins
        self.lateness_s = ref.lateness_s
        self.tenants: dict[str, TenantGlobal] = {}
        self.events = 0
        self.late_events = 0
        self.dropped_late = 0
        self.rejected = 0

    def observe(self, d: EventDescriptor) -> float | None:
        if not d.admissible:
            self.rejected += 1
            return None
        ts = d.observed_ts
        k = int(ts // self.hop_s)
        t = self.tenants.get(d.tenant_id)
        if t is None:
            t = TenantGlobal(first_ts=ts, watermark=ts - self.lateness_s, next_boundary_idx=k)
            self.tenants[d.tenant_id] = t
        self.events += 1
        if k < t.emitted_idx:
            if k < t.emitted_idx - self.n_bins + 1:
                self.dropped_late += 1
                return None
            self.late_events += 1
        t.first_ts = min(t.first_ts, ts)
        t.has_flow = t.has_flow or d.is_flow
        t.has_dns = t.has_dns or d.is_dns
        t.watermark = max(t.watermark, ts - self.lateness_s)
        if (t.next_boundary_idx + 1) * self.hop_s <= t.watermark:
            return t.watermark
        return None

    def flush_watermark(self, tenant_id: str, now_ts: float) -> float:
        """``WindowStore.flush`` semantics: raise the watermark, close up to ``now``."""
        t = self.tenants[tenant_id]
        t.watermark = max(t.watermark, now_ts)
        return now_ts

    def apply_plan(self, plan: ClosePlan) -> None:
        t = self.tenants[plan.tenant_id]
        t.next_boundary_idx = plan.next_boundary_idx
        if plan.emitted_idx != -2:
            t.emitted_idx = plan.emitted_idx


class ShardWindowStore(WindowStore):
    """A :class:`WindowStore` holding one line shard's entities; windows close only on
    coordinator instruction, with the global tenant state and population context."""

    def __init__(self, window: WindowName = "24h", hop: timedelta | None = None, **kwargs: object):
        super().__init__(window, hop, **kwargs)  # type: ignore[arg-type]
        self.global_lateness_s = self.lateness_s
        # the local watermark never advances: closing is a coordinator decision
        self.lateness_s = math.inf

    # ------------------------------------------------------------------ input checks
    def admissible(self, event: ObservationEvent) -> bool:
        """Mirror of the checks ``WindowStore.update`` applies before touching state."""
        if event.entity_pseudonym is None or (event.flow is None and event.dns is None):
            return False
        return not (_sf._utc(event.observed_at) > _sf._utc(event.ingested_at) + self.max_future_skew)

    # ------------------------------------------------------------------ global state
    def prime(self, tenant_id: str, g: TenantGlobal) -> None:
        """Install the global tenant state before applying events or closing."""
        t = self._tenants.get(tenant_id)
        if t is None:
            t = _sf._Tenant(first_ts=g.first_ts, watermark=-math.inf, next_boundary_idx=g.next_boundary_idx)
            self._tenants[tenant_id] = t
        t.first_ts = g.first_ts
        t.next_boundary_idx = g.next_boundary_idx
        t.emitted_idx = g.emitted_idx
        t.has_flow = g.has_flow
        t.has_dns = g.has_dns
        t.watermark = -math.inf

    # ------------------------------------------------------------------ barrier steps
    def bin_indices(self, tenant_id: str) -> set[int]:
        t = self._tenants.get(tenant_id)
        if t is None:
            return set()
        return {k for e in t.entities.values() for k in e.bins}

    def local_contexts(self, tenant_id: str, end_indices: Iterable[int]) -> dict[int, WindowContext]:
        t = self._tenants.get(tenant_id)
        out: dict[int, WindowContext] = {}
        for end_idx in end_indices:
            ctx = WindowContext()
            if t is not None:
                lo = end_idx - self.n_bins
                for ent in t.entities.values():
                    dst: set[str] = set()
                    qn: set[str] = set()
                    found = False
                    for k, b in ent.bins.items():
                        if lo <= k < end_idx:
                            found = True
                            dst.update(k2 for k2, v in b.dst.items() if v)
                            qn.update(k2 for k2, v in b.qnames.items() if v)
                    if found:
                        ctx.population += 1
                        ctx.ip_prev.update(dst)
                        ctx.q_prev.update(qn)
            out[end_idx] = ctx
        return out

    def close(self, plan: ClosePlan, contexts: dict[int, WindowContext], g: TenantGlobal) -> list[FeatureVector]:
        """Emit the planned windows of this shard's entities with the global context."""
        self.prime(plan.tenant_id, g)
        t = self._tenants[plan.tenant_id]
        out: list[FeatureVector] = []
        for end_idx in plan.end_indices:
            boundary = datetime.fromtimestamp(end_idx * self.hop_s, tz=timezone.utc)
            for key in [k for k, cs in self._contacts.items()
                        if k[0] == plan.tenant_id and cs.window_end < boundary]:
                del self._contacts[key]
            out.extend(self._emit_global(plan.tenant_id, t, end_idx, contexts[end_idx]))
            lo = end_idx - self.n_bins + 1
            for eid in list(t.entities):
                ent = t.entities[eid]
                for k in [k for k in ent.bins if k < lo]:
                    del ent.bins[k]
                if not ent.bins:
                    del t.entities[eid]
        t.next_boundary_idx = plan.next_boundary_idx
        if plan.emitted_idx != -2:
            t.emitted_idx = plan.emitted_idx
        return out

    def _emit_global(self, tenant_id: str, t: "_sf._Tenant", end_idx: int,
                     ctx: WindowContext) -> list[FeatureVector]:
        lo = end_idx - self.n_bins
        aggs: list[_sf._Agg] = []
        for eid, ent in t.entities.items():
            bins = sorted((k, b) for k, b in ent.bins.items() if lo <= k < end_idx)
            if bins:
                aggs.append(_sf._Agg(eid, ent.device_class, bins))
        if not aggs:
            return []
        window_end_ts = end_idx * self.hop_s
        window_start_ts = window_end_ts - self.window_s
        coverage_start = max(window_start_ts, t.first_ts)
        coverage_s = max(float(self.hop_s) / 60.0, window_end_ts - coverage_start)
        first_bin = max(lo, int(t.first_ts // self.hop_s))
        population = ctx.population
        ip_prev, q_prev = ctx.ip_prev, ctx.q_prev
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


__all__ = ["ClosePlan", "EventDescriptor", "ShardWindowStore", "TenantClock", "TenantGlobal", "WindowContext",
           "plan_close"]
