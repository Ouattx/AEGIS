"""Sharded RESONANCE input preparation and destination population statistics.

RESONANCE's hourly job has three stages with different natural partition keys:

1. **DNS-answer join and destination-key assignment** (``build_event_table``): a flow is
   keyed ``d:<domain>`` when the *same line* resolved its IP shortly before. The join is
   per (line, IP), so it partitions exactly by **line pseudonym** (:func:`line_contacts`).
2. **Destination population statistics** (``population.key_stats``: lines per destination,
   events, first/last contact, median bytes per line-day, long-flow share): every statistic
   is per destination key, so after a shuffle by **destination hash** each shard computes
   its keys' statistics completely (:func:`destination_partial`). The only global quantity,
   the number of active lines, is the size of the union of the shards' line sets.
   :func:`merge_population` merges the partials in shard order; the result is identical
   (bit for bit, including NaN placement) to ``key_stats`` on the single-node table.
3. **Detection** (timer recovery, permutation null, weighted BH): the null distribution
   replaces each member line's series by *the same line's* series to other destinations,
   so a hypothesis needs every destination of its lines; it does not partition by
   destination. The coordinator rebuilds one canonical table from the shards' contact
   rows (:func:`merge_contacts`) and runs :class:`aegis.resonance.Resonance` once; the
   report equals a single-node run on the canonical single-node table (tested). The merged
   table equals that table up to the relative order of *different lines'* rows that share a
   timestamp; within every (line, destination) group the order is identical, and every
   RESONANCE computation groups by line first.

Canonical tables: vocabularies (line and destination ids) are re-encoded in sorted string
order (:func:`canonical_table`), so a table no longer depends on which process saw which
string first. Detection on a canonical table is deterministic for a fixed config seed.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import EventTable, Vocab, build_event_table
from aegis.resonance.population import KeyStats, key_stats
from aegis.scale.executor import ShardCluster
from aegis.scale.partition import Partitioner


@dataclass
class ContactRows:
    """Destination-contact rows with string ids (process- and shard-independent).

    Rows are in the order ``build_event_table`` produced them on the line shard (stable by
    time), which preserves the relative order of every (line, destination) group.
    """
    t: np.ndarray
    line: np.ndarray            # object array of line pseudonyms
    key: np.ndarray             # object array of destination keys
    kind: np.ndarray
    nbytes: np.ndarray
    dur_s: np.ndarray
    key_ips: dict[str, set[str]] = field(default_factory=dict)
    source_shard: int = 0

    def __len__(self) -> int:
        return len(self.t)

    def select(self, mask: np.ndarray) -> "ContactRows":
        keys = set(self.key[mask].tolist())
        return ContactRows(self.t[mask], self.line[mask], self.key[mask], self.kind[mask], self.nbytes[mask],
                           self.dur_s[mask], {k: set(v) for k, v in self.key_ips.items() if k in keys},
                           self.source_shard)

    @property
    def extent(self) -> tuple[float, float] | None:
        if not len(self.t):
            return None
        return float(self.t.min()), float(self.t.max())


def split_frames_by_line(flows: pd.DataFrame | None, dns: pd.DataFrame | None,
                         partitioner: Partitioner) -> dict[int, tuple[pd.DataFrame | None, pd.DataFrame | None]]:
    """Partition RESONANCE input frames (column ``line``) by line pseudonym hash."""
    out: dict[int, tuple[pd.DataFrame | None, pd.DataFrame | None]] = {}

    def shard_col(fr: pd.DataFrame) -> np.ndarray:
        uniq = pd.unique(fr["line"].astype(str))
        m = {u: partitioner.line_shard(u) for u in uniq}
        return fr["line"].astype(str).map(m).to_numpy()

    fs = shard_col(flows) if flows is not None and len(flows) else None
    ds = shard_col(dns) if dns is not None and len(dns) else None
    for s in range(partitioner.n_shards):
        f = flows[fs == s] if fs is not None and flows is not None else None
        d = dns[ds == s] if ds is not None and dns is not None else None
        out[s] = (f, d)
    return out


def line_contacts(flows: pd.DataFrame | None, dns: pd.DataFrame | None, *, dns_join_ttl_s: float = 3600.0,
                  source_shard: int = 0) -> ContactRows:
    """Stage 1 on one line shard: DNS-answer join and destination keys, as string rows."""
    tb = build_event_table(flows, dns, dns_join_ttl_s=dns_join_ttl_s)
    lines = np.asarray(tb.lines.items, dtype=object)
    keys = np.asarray(tb.keys.items, dtype=object)
    return ContactRows(tb.t.copy(), lines[tb.line] if len(tb) else np.zeros(0, dtype=object),
                       keys[tb.key] if len(tb) else np.zeros(0, dtype=object), tb.kind.copy(), tb.nbytes.copy(),
                       tb.dur_s.copy(), {tb.keys.items[k]: set(v) for k, v in tb.key_ips.items()}, source_shard)


def shuffle_by_destination(parts: Sequence[ContactRows], partitioner: Partitioner) -> dict[int, list[ContactRows]]:
    """Route every contact row to the shard owning its destination key."""
    out: dict[int, list[ContactRows]] = {s: [] for s in range(partitioner.n_shards)}
    for part in parts:
        if not len(part):
            continue
        uniq = pd.unique(part.key)
        m = {k: partitioner.destination_shard(str(k)) for k in uniq}
        dest = pd.Series(part.key).map(m).to_numpy()
        for s in range(partitioner.n_shards):
            mask = dest == s
            if mask.any():
                out[s].append(part.select(mask))
    return out


def _concat_sorted(parts: Sequence[ContactRows]) -> ContactRows:
    """Concatenate parts in source-shard order, then stable-sort by time (keeps each part's
    internal order, hence each (line, destination) group's order)."""
    parts = sorted((p for p in parts if len(p)), key=lambda p: p.source_shard)
    if not parts:
        e = np.zeros(0)
        return ContactRows(e, e.astype(object), e.astype(object), e.astype(np.int8), e.astype(np.float32),
                           e.astype(np.float32))
    cat = lambda name: np.concatenate([getattr(p, name) for p in parts])  # noqa: E731
    t = cat("t")
    order = np.argsort(t, kind="stable")
    ips: dict[str, set[str]] = {}
    for p in parts:
        for k, v in p.key_ips.items():
            ips.setdefault(k, set()).update(v)
    return ContactRows(t[order], cat("line")[order], cat("key")[order], cat("kind")[order], cat("nbytes")[order],
                       cat("dur_s")[order], ips)


def contacts_to_table(rows: ContactRows, *, start: float | None = None, end: float | None = None,
                      canonical: bool = True) -> EventTable:
    """Encode string rows as an :class:`EventTable` (sorted vocabularies when ``canonical``)."""
    line_names = sorted(set(rows.line.tolist())) if canonical else list(dict.fromkeys(rows.line.tolist()))
    key_names = set(rows.key.tolist()) | set(rows.key_ips)
    key_list = sorted(key_names) if canonical else list(dict.fromkeys([*rows.key.tolist(), *rows.key_ips]))
    lines, keys = Vocab(line_names), Vocab(key_list)
    li = {s: i for i, s in enumerate(lines.items)}
    ki = {s: i for i, s in enumerate(keys.items)}
    line = np.fromiter((li[s] for s in rows.line), dtype=np.int32, count=len(rows))
    key = np.fromiter((ki[s] for s in rows.key), dtype=np.int32, count=len(rows))
    key_ips = {ki[k]: set(v) for k, v in rows.key_ips.items()}
    return EventTable(rows.t.astype(np.float64), line, key, rows.kind.astype(np.int8), rows.nbytes.astype(np.float32),
                      rows.dur_s.astype(np.float32), lines, keys, key_ips, start, end)


def canonical_table(table: EventTable) -> EventTable:
    """Re-encode a table's vocabularies in sorted order (rows and their order unchanged)."""
    lines = np.asarray(table.lines.items, dtype=object)
    keys = np.asarray(table.keys.items, dtype=object)
    rows = ContactRows(table.t, lines[table.line] if len(table) else np.zeros(0, dtype=object),
                       keys[table.key] if len(table) else np.zeros(0, dtype=object), table.kind, table.nbytes,
                       table.dur_s, {table.keys.items[k]: set(v) for k, v in table.key_ips.items()})
    return contacts_to_table(rows, start=table.start, end=table.end, canonical=True)


# ----------------------------------------------------------------------------- population statistics

@dataclass
class KeyPopulation:
    """Population statistics of one destination key (fields of ``KeyStats``)."""
    n_lines: int
    n_events: int
    first_t: float
    last_t: float
    median_bytes: float          # NaN when unknown (no byte counts)
    long_frac: float             # NaN when no flows


@dataclass
class PopulationPartial:
    """One destination shard's complete statistics for the keys it owns."""
    shard_id: int
    keys: dict[str, KeyPopulation]
    lines: set[str]
    key_ips: dict[str, set[str]]


@dataclass
class PopulationStats:
    """Merged destination population statistics (equal to single-node ``key_stats``)."""
    keys: dict[str, KeyPopulation]
    active_lines: int
    key_ips: dict[str, set[str]]
    window: tuple[float, float]

    def candidate_keys(self, cfg: ResonanceConfig) -> list[str]:
        """Destinations RESONANCE may test (reached by at least 2 and at most
        ``max_popularity`` of the active lines), sorted."""
        cap = cfg.max_popularity * self.active_lines
        return sorted(k for k, s in self.keys.items() if 2 <= s.n_lines <= cap)

    def popular_keys(self, cfg: ResonanceConfig) -> list[str]:
        cap = cfg.max_popularity * self.active_lines
        return sorted(k for k, s in self.keys.items() if s.n_lines > cap)


def destination_partial(parts: Sequence[ContactRows], window: tuple[float, float], cfg: ResonanceConfig,
                        shard_id: int = 0) -> PopulationPartial:
    """Stage 2 on one destination shard: complete ``key_stats`` for the keys it owns.

    ``window`` is the job's global observation window (``key_stats`` scales bytes to
    per line-day with the global span, so every shard must use the same one).
    """
    rows = _concat_sorted(parts)
    tb = contacts_to_table(rows, start=window[0], end=window[1], canonical=True)
    st: KeyStats = key_stats(tb, cfg)
    present = np.flatnonzero(st.n_events > 0)
    keys = {tb.keys.items[int(k)]: KeyPopulation(int(st.n_lines[k]), int(st.n_events[k]), float(st.first_t[k]),
                                                 float(st.last_t[k]), float(st.median_bytes[k]),
                                                 float(st.long_frac[k]))
            for k in present}
    return PopulationPartial(shard_id, keys, set(rows.line.tolist()), rows.key_ips)


def merge_population(partials: Iterable[PopulationPartial], window: tuple[float, float]) -> PopulationStats:
    """Deterministic merge (shard order). Keys are disjoint across shards by construction;
    a key reported by two shards indicates a routing bug and is refused."""
    keys: dict[str, KeyPopulation] = {}
    lines: set[str] = set()
    ips: dict[str, set[str]] = {}
    for p in sorted(partials, key=lambda x: x.shard_id):
        dup = keys.keys() & p.keys.keys()
        if dup:
            raise ValueError(f"destination keys reported by two shards: {sorted(dup)[:5]}")
        keys.update(p.keys)
        lines |= p.lines
        for k, v in p.key_ips.items():
            ips.setdefault(k, set()).update(v)
    return PopulationStats(dict(sorted(keys.items())), len(lines), ips, window)


def single_node_population(table: EventTable, cfg: ResonanceConfig) -> PopulationStats:
    """Reference: ``key_stats`` on one table, keyed by destination name (for comparisons)."""
    st = key_stats(table, cfg)
    present = np.flatnonzero(st.n_events > 0)
    keys = {table.keys.items[int(k)]: KeyPopulation(int(st.n_lines[k]), int(st.n_events[k]), float(st.first_t[k]),
                                                    float(st.last_t[k]), float(st.median_bytes[k]),
                                                    float(st.long_frac[k]))
            for k in present}
    return PopulationStats(dict(sorted(keys.items())), st.active_lines,
                           {table.keys.items[k]: set(v) for k, v in table.key_ips.items()}, table.window)


def same_population(a: PopulationStats, b: PopulationStats) -> bool:
    """Exact equality (NaN == NaN) of two population statistics."""
    if a.active_lines != b.active_lines or a.keys.keys() != b.keys.keys():
        return False

    def eq(x: float, y: float) -> bool:
        return (math.isnan(x) and math.isnan(y)) or x == y

    for k, x in a.keys.items():
        y = b.keys[k]
        if (x.n_lines, x.n_events) != (y.n_lines, y.n_events):
            return False
        if not all(eq(u, v) for u, v in ((x.first_t, y.first_t), (x.last_t, y.last_t),
                                         (x.median_bytes, y.median_bytes), (x.long_frac, y.long_frac))):
            return False
    return True


def merge_contacts(parts: Sequence[ContactRows], *, start: float | None = None,
                   end: float | None = None) -> EventTable:
    """Stage 3 input: one canonical table from all line shards' contact rows."""
    return contacts_to_table(_concat_sorted(parts), start=start, end=end, canonical=True)


# ----------------------------------------------------------------------------- shard handler + coordinator

@dataclass
class ResonanceShardConfig:
    """Picklable factory of :class:`ResonanceShard` handlers."""
    cfg: ResonanceConfig = field(default_factory=ResonanceConfig)

    def __call__(self, shard_id: int) -> "ResonanceShard":
        return ResonanceShard(shard_id, self.cfg)


class ResonanceShard:
    """Stateless per-shard work for the RESONANCE hourly job (ops ``contacts``, ``partial``)."""

    def __init__(self, shard_id: int, cfg: ResonanceConfig):
        self.shard_id = shard_id
        self.cfg = cfg

    def handle(self, op: str, payload: Any) -> Any:
        if op == "contacts":
            flows, dns = payload
            return line_contacts(flows, dns, dns_join_ttl_s=self.cfg.dns_join_ttl_s, source_shard=self.shard_id)
        if op == "partial":
            parts, window = payload
            return destination_partial(parts, window, self.cfg, self.shard_id)
        raise ValueError(f"unknown op {op!r}")


@dataclass
class ShardedPrepResult:
    population: PopulationStats
    contacts: list[ContactRows]
    window: tuple[float, float]

    def table(self) -> EventTable:
        """The canonical detection table (window = the job window)."""
        return merge_contacts(self.contacts, start=self.window[0], end=self.window[1])


def sharded_resonance_prep(cluster: ShardCluster, flows: pd.DataFrame | None, dns: pd.DataFrame | None, *,
                           window: tuple[float, float] | None = None) -> ShardedPrepResult:
    """Run stages 1-2 on ``cluster`` (built with :class:`ResonanceShardConfig`).

    ``window`` defaults to the data extent (what a single-node ``build_event_table`` uses).
    In production the hourly job passes its fixed horizon ``(now - 24 h, now)``.
    """
    part = Partitioner(cluster.n_shards)
    frames = split_frames_by_line(flows, dns, part)
    contacts_by_shard: Mapping[int, ContactRows] = cluster.call({s: ("contacts", frames[s]) for s in frames})
    contacts = [contacts_by_shard[s] for s in sorted(contacts_by_shard)]
    if window is None:
        ext = [c.extent for c in contacts if c.extent is not None]
        window = (min(e[0] for e in ext), max(e[1] for e in ext)) if ext else (0.0, 0.0)
    routed = shuffle_by_destination(contacts, part)
    partials = cluster.call({s: ("partial", (routed[s], window)) for s in routed})
    return ShardedPrepResult(merge_population(partials.values(), window), contacts, window)


__all__ = ["ContactRows", "KeyPopulation", "PopulationPartial", "PopulationStats", "ResonanceShard",
           "ResonanceShardConfig", "ShardedPrepResult", "canonical_table", "contacts_to_table",
           "destination_partial", "line_contacts", "merge_contacts", "merge_population", "same_population",
           "sharded_resonance_prep", "shuffle_by_destination", "single_node_population", "split_frames_by_line"]
