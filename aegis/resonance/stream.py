"""Streaming / incremental RESONANCE with bounded memory.

Events arrive in chunks (flow + DNS frames, canonical observations, or pre-built tables
sharing this stream's vocabularies). :meth:`ResonanceStream.advance` re-runs the batch
detector over a sliding ``horizon_s`` window every ``step_s`` seconds and reports which
campaigns are new (first-detection time = detection delay reference).

Memory bounds:

* events older than the horizon are dropped;
* resolver answers are kept only ``dns_join_ttl_s`` back (for the flow -> domain join);
* beyond ``max_events`` the buffer first collapses destinations that can never be
  campaign targets (popular keys keep one event per line, enough for popularity), then
  thins the remainder uniformly at random (random thinning preserves periodic structure,
  exactly like packet sampling does).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

import numpy as np
import pandas as pd

from aegis.contracts.models import ObservationEvent
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.detector import Resonance
from aegis.resonance.events import EventTable, Vocab, build_event_table, observations_to_frames
from aegis.resonance.models import Campaign, ResonanceReport
from aegis.resonance.population import DestinationContext, DestinationHistory, key_stats

DAY = 86_400.0


@dataclass
class StreamUpdate:
    now: float
    report: ResonanceReport
    new_campaigns: list[Campaign] = field(default_factory=list)
    first_detected: dict[str, float] = field(default_factory=dict)   # canonical campaign id -> epoch s
    canonical: dict[str, str] = field(default_factory=dict)          # campaign_id -> canonical id


class ResonanceStream:
    def __init__(self, cfg: ResonanceConfig | None = None, *, context: DestinationContext | None = None,
                 history: DestinationHistory | None = None, tenant_id: str = "default",
                 horizon_s: float = DAY, step_s: float = 3600.0, max_events: int = 5_000_000,
                 update_history: bool = True):
        self.cfg = cfg or ResonanceConfig()
        self.detector = Resonance(self.cfg, context=context, history=history, tenant_id=tenant_id)
        self.history = history
        self.horizon_s = float(horizon_s)
        self.step_s = float(step_s)
        self.max_events = int(max_events)
        self.update_history = update_history
        self.lines = Vocab()
        self.keys = Vocab()
        self.key_ips: dict[int, set[str]] = {}
        self._chunks: list[EventTable] = []
        self._dns_carry: pd.DataFrame | None = None
        self._next_run: float | None = None
        self._last_history_day: int | None = None
        self.first_detected: dict[str, float] = {}      # canonical campaign id -> first detection time
        self.canonical: dict[str, str] = {}             # campaign_id -> canonical id
        self._canon_dests: dict[str, set[str]] = {}
        self._t_first: float | None = None
        self.stats = {"ingested": 0, "dropped_old": 0, "thinned": 0, "runs": 0}

    # ------------------------------------------------------------------ ingestion
    def ingest_frames(self, flows: pd.DataFrame | None, dns: pd.DataFrame | None) -> int:
        tb = build_event_table(flows, dns, dns_join_ttl_s=self.cfg.dns_join_ttl_s, lines=self.lines, keys=self.keys,
                               key_ips=self.key_ips, dns_carry=self._dns_carry)
        if dns is not None and len(dns):
            ans = dns[dns["answer_ip"].notna()][["t", "line", "qname", "answer_ip"]].copy()
            for col in ("line", "qname", "answer_ip"):
                ans[col] = ans[col].astype(str)
            carry = ans if self._dns_carry is None else pd.concat([self._dns_carry, ans], ignore_index=True)
            tmax = float(carry["t"].max())
            self._dns_carry = carry[carry["t"] >= tmax - self.cfg.dns_join_ttl_s].reset_index(drop=True)
        return self.ingest_table(tb)

    def ingest_observations(self, events: Iterable[ObservationEvent]) -> int:
        flows, dns = observations_to_frames(events)
        return self.ingest_frames(flows, dns)

    def ingest_table(self, table: EventTable) -> int:
        if table.lines is not self.lines or table.keys is not self.keys:
            raise ValueError("table must be built with this stream's vocabularies (use ingest_frames)")
        if len(table):
            self._chunks.append(table)
            self.stats["ingested"] += len(table)
            tmin = float(table.t.min())
            self._t_first = tmin if self._t_first is None else min(self._t_first, tmin)
        return len(table)

    # ------------------------------------------------------------------ state management
    def _buffer(self) -> EventTable | None:
        if not self._chunks:
            return None
        if len(self._chunks) > 1:
            self._chunks = [EventTable.concat(self._chunks)]
        return self._chunks[0]

    def _prune(self, now: float) -> EventTable | None:
        buf = self._buffer()
        if buf is None:
            return None
        lo = now - self.horizon_s
        keep = (buf.t >= lo) & (buf.t < now)
        self.stats["dropped_old"] += int((buf.t < lo).sum())
        future = buf.t >= now
        # the observed window starts no earlier than the first event ever ingested
        win = buf.select(keep, start=max(lo, self._t_first if self._t_first is not None else lo), end=now)
        rest = buf.select(future) if future.any() else None
        if len(win) > self.max_events:
            win = self._shrink(win)
        self._chunks = [c for c in (win, rest) if c is not None and len(c)]
        return win

    def _shrink(self, win: EventTable) -> EventTable:
        cfg = self.cfg
        st = key_stats(win, cfg)
        popular = st.n_lines > cfg.max_popularity * max(1, st.active_lines)
        ev_pop = popular[win.key]
        # popular keys: keep only the first event per (line, key)
        code = win.key.astype(np.int64) * (len(win.lines) + 1) + win.line
        first = np.zeros(len(win), dtype=bool)
        _, idx = np.unique(code, return_index=True)
        first[idx] = True
        keep = ~ev_pop | first
        rng = np.random.default_rng([cfg.seed, len(win)])
        n_keep = int(keep.sum())
        if n_keep > self.max_events:
            p = self.max_events / n_keep
            keep &= (rng.random(len(win)) < p) | (ev_pop & first)
        self.stats["thinned"] += int(len(win) - keep.sum())
        return win.select(keep)

    # ------------------------------------------------------------------ detection
    def advance(self, now: float, *, force: bool = False) -> StreamUpdate | None:
        """Run detection when ``now`` reached the next step (or ``force``). Returns None otherwise."""
        if self._next_run is None:
            self._next_run = now
        if not force and now < self._next_run:
            return None
        self._next_run = now + self.step_s
        win = self._prune(now)
        if win is None or len(win) == 0:
            return None
        report = self.detector.detect(win, now=now)
        self.stats["runs"] += 1
        new = []
        for c in report.campaigns:
            cid = self._canonicalize(c)
            if cid not in self.first_detected:
                self.first_detected[cid] = now
                new.append(c)
        self._maybe_update_history(win, now)
        return StreamUpdate(now=now, report=report, new_campaigns=new, first_detected=dict(self.first_detected),
                            canonical=dict(self.canonical))

    def _canonicalize(self, c: Campaign) -> str:
        """Stable identity across windows: campaigns sharing any destination are the same campaign
        (a rotating-domain cluster grows over time and changes its ``campaign_id``)."""
        dests = set(c.destinations)
        if c.campaign_id in self.canonical:
            cid = self.canonical[c.campaign_id]
        else:
            cid = next((k for k, v in self._canon_dests.items() if v & dests), c.campaign_id)
            self.canonical[c.campaign_id] = cid
        self._canon_dests.setdefault(cid, set()).update(dests)
        return cid

    def _maybe_update_history(self, win: EventTable, now: float) -> None:
        if not self.update_history or self.history is None:
            return
        day = int(now // DAY)
        if self._last_history_day == day:
            return
        self._last_history_day = day
        st = key_stats(win, self.cfg)
        present = np.flatnonzero(st.n_events > 0)
        self.history.observe([win.keys.items[k] for k in present], st.n_lines[present], st.first_t[present],
                             st.last_t[present])

    @property
    def buffered_events(self) -> int:
        return sum(len(c) for c in self._chunks)
