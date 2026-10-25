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

Coupling note: :class:`ShardWindowStore` calls the reference store's private packing and
emission steps (``_compact``, ``_views``, ``_close_window``) with an injected population
context, so the feature code is shared, not copied. ``tests/unit/test_scale_lines.py``
asserts equality with the reference implementation on lab corpora, so any drift fails CI.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

import numpy as np

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
    coordinator instruction, with the global tenant state and population context.

    It reuses the reference store's packing, emission and feature code unchanged; only the
    population context (summed over shards by the coordinator) and the closing decision
    come from outside.
    """

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
        live_from = t.emitted_idx - self.n_bins + 1
        return {k for k in t.bin_refs if k >= live_from}

    def local_contexts(self, tenant_id: str, end_indices: Iterable[int]) -> dict[int, WindowContext]:
        t = self._tenants.get(tenant_id)
        out: dict[int, WindowContext] = {}
        if t is not None:
            # pack pending events (dropping nothing) so every window sees all of its hops
            for ent in t.entities.values():
                self._compact(t, ent, -(1 << 62))
        for end_idx in end_indices:
            ctx = WindowContext()
            if t is not None:
                for w in self._views(t, end_idx):
                    ctx.population += 1
                    ctx.ip_prev.update(str(t.ips.items[i]) for i in w.dst_u.tolist())
                    ctx.q_prev.update(str(t.names.items[i]) for i in w.q_u.tolist())
            out[end_idx] = ctx
        return out

    def close(self, plan: ClosePlan, contexts: dict[int, WindowContext], g: TenantGlobal) -> list[FeatureVector]:
        """Emit the planned windows of this shard's entities with the global context."""
        self.prime(plan.tenant_id, g)
        t = self._tenants[plan.tenant_id]
        out: list[FeatureVector] = []
        for end_idx in plan.end_indices:
            out.extend(self._close_window(plan.tenant_id, t, end_idx, _global_context(t, contexts[end_idx])))
            t.emitted_idx = end_idx
        t.next_boundary_idx = plan.next_boundary_idx
        if plan.emitted_idx != -2:
            t.emitted_idx = plan.emitted_idx
        return out


def _global_context(t: "_sf._Tenant", ctx: WindowContext) -> "_sf._Context":
    """Prevalence lookups over this shard's vocabulary ids, answered by the merged global counts."""
    ips, names = t.ips.items, t.names.items

    def ip(ids: np.ndarray) -> np.ndarray:
        return np.asarray([ctx.ip_prev.get(str(ips[i]), 0) for i in ids.tolist()], dtype=np.int64)

    def q(ids: np.ndarray) -> np.ndarray:
        return np.asarray([ctx.q_prev.get(str(names[i]), 0) for i in ids.tolist()], dtype=np.int64)

    return _sf._Context(ctx.population, ip, q)


__all__ = ["ClosePlan", "EventDescriptor", "ShardWindowStore", "TenantClock", "TenantGlobal", "WindowContext",
           "plan_close"]
