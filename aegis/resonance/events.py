"""Columnar event tables for RESONANCE.

RESONANCE never touches payloads. Its input is, per subscriber line pseudonym, the
times at which the line contacted a *destination key*:

* ``d:<domain>`` when the flow's destination IP was returned to that line by the
  resolver within ``dns_join_ttl_s`` before the flow (DNS-answer join), and also for
  every resolver query itself (resolver logs are normally unsampled even when
  NetFlow/IPFIX is packet-sampled, so they are an independent timing channel);
* ``ip:<address>`` otherwise (hard-coded IPs, DoH, or answers outside the window).

Tables are numpy columns indexed into shared vocabularies so streaming chunks can
be concatenated without re-encoding strings.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Sequence

import numpy as np
import pandas as pd

from aegis.contracts.models import ObservationEvent
from aegis.resonance.config import ResonanceConfig

KIND_FLOW = 0
KIND_DNS = 1


class Vocab:
    """Append-only string <-> id mapping shared by every table of one detector instance."""

    def __init__(self, items: Iterable[str] = ()):
        self.items: list[str] = []
        self._index: dict[str, int] = {}
        for s in items:
            self.id(s)

    def __len__(self) -> int:
        return len(self.items)

    def id(self, s: str) -> int:
        i = self._index.get(s)
        if i is None:
            i = len(self.items)
            self._index[s] = i
            self.items.append(s)
        return i

    def ids(self, values: Sequence[str] | np.ndarray) -> np.ndarray:
        codes, uniques = pd.factorize(pd.Series(values, dtype=object), sort=False)
        mapping = np.fromiter((self.id(str(u)) for u in uniques), dtype=np.int64, count=len(uniques))
        out = np.empty(len(codes), dtype=np.int32)
        if len(codes):
            out[:] = mapping[codes]
        return out

    def get(self, s: str) -> int | None:
        return self._index.get(s)


@dataclass
class EventTable:
    """Destination-contact events. Arrays share one length; ``line``/``key`` index the vocabularies."""
    t: np.ndarray                 # float64 epoch seconds
    line: np.ndarray              # int32 -> lines vocab
    key: np.ndarray               # int32 -> keys vocab
    kind: np.ndarray              # int8 KIND_FLOW / KIND_DNS
    nbytes: np.ndarray            # float32, NaN when unknown (DNS rows)
    dur_s: np.ndarray             # float32, NaN when unknown
    lines: Vocab
    keys: Vocab
    key_ips: dict[int, set[str]] = field(default_factory=dict)   # key id -> IPs it resolved/refers to
    start: float | None = None    # observation window (epoch s); defaults to data extent
    end: float | None = None

    def __post_init__(self) -> None:
        n = len(self.t)
        for name in ("line", "key", "kind", "nbytes", "dur_s"):
            if len(getattr(self, name)) != n:
                raise ValueError(f"column {name} length mismatch")

    def __len__(self) -> int:
        return len(self.t)

    @property
    def window(self) -> tuple[float, float]:
        lo = self.start if self.start is not None else (float(self.t.min()) if len(self) else 0.0)
        hi = self.end if self.end is not None else (float(self.t.max()) if len(self) else 0.0)
        return lo, hi

    @property
    def span_s(self) -> float:
        lo, hi = self.window
        return max(0.0, hi - lo)

    def select(self, mask: np.ndarray, *, start: float | None = None, end: float | None = None) -> "EventTable":
        return EventTable(self.t[mask], self.line[mask], self.key[mask], self.kind[mask], self.nbytes[mask],
                          self.dur_s[mask], self.lines, self.keys, self.key_ips,
                          self.start if start is None else start, self.end if end is None else end)

    @staticmethod
    def concat(tables: Sequence["EventTable"]) -> "EventTable":
        if not tables:
            raise ValueError("nothing to concatenate")
        base = tables[0]
        for tb in tables[1:]:
            if tb.lines is not base.lines or tb.keys is not base.keys:
                raise ValueError("tables must share vocabularies")
        cat = lambda name: np.concatenate([getattr(tb, name) for tb in tables])  # noqa: E731
        starts = [tb.start for tb in tables if tb.start is not None]
        ends = [tb.end for tb in tables if tb.end is not None]
        merged_ips = base.key_ips
        for tb in tables[1:]:
            if tb.key_ips is not merged_ips:
                for k, v in tb.key_ips.items():
                    merged_ips.setdefault(k, set()).update(v)
        return EventTable(cat("t"), cat("line"), cat("key"), cat("kind"), cat("nbytes"), cat("dur_s"),
                          base.lines, base.keys, merged_ips, min(starts) if starts else None,
                          max(ends) if ends else None)

    def key_name(self, k: int) -> str:
        return self.keys.items[k]

    def line_name(self, i: int) -> str:
        return self.lines.items[i]


def _norm_name(q: str) -> str:
    return q.strip().lower().rstrip(".")


def _codes(s: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Integer codes (-1 = missing) and the unique values they index."""
    if isinstance(s.dtype, pd.CategoricalDtype):
        return s.cat.codes.to_numpy().astype(np.int64), np.asarray(s.cat.categories, dtype=object)
    codes, uniq = pd.factorize(s, sort=False)
    return codes.astype(np.int64), np.asarray(uniq, dtype=object)


def build_event_table(flows: pd.DataFrame | None, dns: pd.DataFrame | None, *,
                      dns_join_ttl_s: float = 3600.0, lines: Vocab | None = None, keys: Vocab | None = None,
                      key_ips: dict[int, set[str]] | None = None, start: float | None = None,
                      end: float | None = None, dns_carry: pd.DataFrame | None = None) -> EventTable:
    """Vectorized DNS-answer join and key assignment.

    ``flows`` columns: ``t, line, dst_ip`` and optionally ``bytes, dur_s``.
    ``dns`` columns: ``t, line, qname, answer_ip`` with one row per answer (rows sharing
    ``t, line, qname`` are one query; ``answer_ip`` may be null for answerless queries).
    String columns may be pandas categoricals (fast path for millions of rows).
    ``dns_carry`` holds answers from earlier chunks (streaming) usable for the join only.
    """
    lines = lines if lines is not None else Vocab()
    keys = keys if keys is not None else Vocab()
    key_ips = key_ips if key_ips is not None else {}
    empty_f = flows is None or len(flows) == 0
    empty_d = dns is None or len(dns) == 0

    parts: list[tuple[np.ndarray, ...]] = []
    ip_vocab = Vocab()

    def line_ids(s: pd.Series) -> np.ndarray:
        c, u = _codes(s)
        m = lines.ids(np.array([str(x) for x in u], dtype=object)) if len(u) else np.zeros(0, dtype=np.int32)
        return m[c].astype(np.int64) if len(c) else np.zeros(0, dtype=np.int64)

    def ip_ids(s: pd.Series) -> np.ndarray:
        c, u = _codes(s)
        m = np.array([ip_vocab.id(str(x)) for x in u], dtype=np.int64)
        out = np.full(len(c), -1, dtype=np.int64)
        ok = c >= 0
        out[ok] = m[c[ok]]
        return out

    def name_keys(s: pd.Series) -> np.ndarray:
        c, u = _codes(s)
        m = np.array([keys.id("d:" + _norm_name(str(x))) for x in u], dtype=np.int64)
        out = np.full(len(c), -1, dtype=np.int64)
        ok = c >= 0
        out[ok] = m[c[ok]]
        return out

    # ---------------------------------------------------------------- resolver answers (join side)
    ans_frames = []
    if dns_carry is not None and len(dns_carry):
        ans_frames.append(dns_carry)
    if not empty_d:
        ans_frames.append(dns)
    a_t = np.zeros(0)
    a_line = a_ip = a_key = np.zeros(0, dtype=np.int64)
    for fr in ans_frames:
        ok = fr["answer_ip"].notna().to_numpy()
        if not ok.any():
            continue
        sub = fr[ok]
        a_t = np.concatenate([a_t, sub["t"].to_numpy(dtype=np.float64)])
        a_line = np.concatenate([a_line, line_ids(sub["line"])])
        a_ip = np.concatenate([a_ip, ip_ids(sub["answer_ip"])])
        a_key = np.concatenate([a_key, name_keys(sub["qname"])])

    # ---------------------------------------------------------------- flows: join to most recent answer
    if not empty_f:
        ft = flows["t"].to_numpy(dtype=np.float64)
        fline = line_ids(flows["line"])
        fip = ip_ids(flows["dst_ip"])
        fkey = np.full(len(ft), -1, dtype=np.int64)
        if len(a_t):
            left = pd.DataFrame({"t": ft, "l": fline, "i": fip, "o": np.arange(len(ft))}).sort_values("t", kind="mergesort")
            right = pd.DataFrame({"t": a_t, "l": a_line, "i": a_ip, "k": a_key}).sort_values("t", kind="mergesort")
            m = pd.merge_asof(left, right, on="t", by=["l", "i"], direction="backward",
                              tolerance=float(dns_join_ttl_s), allow_exact_matches=True)
            kk = m["k"].to_numpy()
            okm = ~np.isnan(kk)
            fkey[m["o"].to_numpy()[okm]] = kk[okm].astype(np.int64)
        ipkey = np.array([keys.id("ip:" + s) for s in ip_vocab.items], dtype=np.int64)
        nomatch = fkey < 0
        fkey[nomatch] = ipkey[fip[nomatch]]
        pairs = np.unique(fkey * (len(ip_vocab) + 1) + fip)
        for v in pairs:
            key_ips.setdefault(int(v // (len(ip_vocab) + 1)), set()).add(ip_vocab.items[int(v % (len(ip_vocab) + 1))])
        fb = flows["bytes"].to_numpy(dtype=np.float32) if "bytes" in flows else np.full(len(ft), np.nan, np.float32)
        fd = flows["dur_s"].to_numpy(dtype=np.float32) if "dur_s" in flows else np.full(len(ft), np.nan, np.float32)
        parts.append((ft, fline, fkey, np.full(len(ft), KIND_FLOW, dtype=np.int8), fb, fd))

    # ---------------------------------------------------------------- dns queries as timing events
    if not empty_d:
        dt = dns["t"].to_numpy(dtype=np.float64)
        dline = line_ids(dns["line"])
        dkey = name_keys(dns["qname"])
        q = pd.DataFrame({"t": dt, "l": dline, "k": dkey}).drop_duplicates()
        n = len(q)
        parts.append((q["t"].to_numpy(), q["l"].to_numpy(), q["k"].to_numpy(), np.full(n, KIND_DNS, dtype=np.int8),
                      np.full(n, np.nan, dtype=np.float32), np.full(n, np.nan, dtype=np.float32)))
    if len(a_t):
        pairs = np.unique(a_key * (len(ip_vocab) + 1) + a_ip)
        for v in pairs:
            key_ips.setdefault(int(v // (len(ip_vocab) + 1)), set()).add(ip_vocab.items[int(v % (len(ip_vocab) + 1))])

    if not parts:
        e = np.empty(0)
        return EventTable(e.astype(np.float64), e.astype(np.int32), e.astype(np.int32), e.astype(np.int8),
                          e.astype(np.float32), e.astype(np.float32), lines, keys, key_ips, start, end)
    cols = [np.concatenate([p[i] for p in parts]) for i in range(6)]
    order = np.argsort(cols[0], kind="stable")
    return EventTable(cols[0][order], cols[1][order].astype(np.int32), cols[2][order].astype(np.int32),
                      cols[3][order], cols[4][order], cols[5][order], lines, keys, key_ips, start, end)


def observations_to_frames(events: Iterable[ObservationEvent]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split canonical events into flow and DNS frames (line = ``entity_pseudonym``)."""
    fr: dict[str, list] = {"t": [], "line": [], "dst_ip": [], "bytes": [], "dur_s": []}
    dr: dict[str, list] = {"t": [], "line": [], "qname": [], "answer_ip": []}
    for ev in events:
        if not ev.entity_pseudonym:
            continue  # unattributable events cannot contribute to a per-line timer
        ts = ev.observed_at.timestamp()
        if ev.flow is not None:
            fl = ev.flow
            b = None if fl.bytes_out is None and fl.bytes_in is None else (fl.bytes_out or 0) + (fl.bytes_in or 0)
            fr["t"].append(ts)
            fr["line"].append(ev.entity_pseudonym)
            fr["dst_ip"].append(fl.dst_ip)
            fr["bytes"].append(np.nan if b is None else float(b))
            fr["dur_s"].append(np.nan if fl.duration_ms is None else fl.duration_ms / 1000.0)
        elif ev.dns is not None and ev.dns.rcode == "NOERROR":
            answers = ev.dns.answers or [None]
            for a in answers:
                dr["t"].append(ts)
                dr["line"].append(ev.entity_pseudonym)
                dr["qname"].append(ev.dns.qname)
                dr["answer_ip"].append(a)
    return pd.DataFrame(fr), pd.DataFrame(dr)


def events_from_observations(events: Iterable[ObservationEvent], cfg: ResonanceConfig | None = None, *,
                             start: datetime | None = None, end: datetime | None = None,
                             line_map: dict[str, str] | None = None) -> EventTable:
    """Adapter from canonical :class:`ObservationEvent` objects.

    ``line_map`` optionally maps device pseudonyms to line pseudonyms (NAT aggregation
    when the source vantage is per-device but the analysis should be per line).
    """
    cfg = cfg or ResonanceConfig()
    flows, dns = observations_to_frames(events)
    if line_map:
        if len(flows):
            flows["line"] = flows["line"].map(lambda x: line_map.get(x, x))
        if len(dns):
            dns["line"] = dns["line"].map(lambda x: line_map.get(x, x))
    return build_event_table(flows, dns, dns_join_ttl_s=cfg.dns_join_ttl_s,
                             start=start.timestamp() if start else None, end=end.timestamp() if end else None)


# ---------------------------------------------------------------------------- series preparation

@dataclass
class SeriesSet:
    """Per (line, key) event-time series after de-duplication.

    ``t`` is sorted by series then time; series ``s`` occupies ``t[offsets[s]:offsets[s+1]]``.
    """
    t: np.ndarray
    sid: np.ndarray
    line: np.ndarray              # per series
    key: np.ndarray               # per series
    offsets: np.ndarray           # len n_series + 1
    raw_counts: np.ndarray        # events per series before coalescing / thinning

    @property
    def n_series(self) -> int:
        return len(self.line)

    @property
    def counts(self) -> np.ndarray:
        return np.diff(self.offsets)

    def times(self, s: int) -> np.ndarray:
        return self.t[self.offsets[s]:self.offsets[s + 1]]


def continuation_mask(t: np.ndarray, grp: np.ndarray, kind: np.ndarray, dur: np.ndarray,
                      long_flow_s: float) -> np.ndarray:
    """True for flow records continuing a long-lived connection (exporter active-timeout splits).

    Arrays must be sorted by group then time. A record continues the previous one in its
    group when that one was a long flow ending (start + duration) within [-2, +5] s of this
    record's start. Continuations carry no timer information and would otherwise make
    every long download look like a perfect timer at the exporter's active timeout.
    """
    n = len(t)
    out = np.zeros(n, dtype=bool)
    if n < 2:
        return out
    prev_end = t[:-1] + np.nan_to_num(dur[:-1].astype(np.float64), nan=0.0)
    same = grp[1:] == grp[:-1]
    long_prev = (kind[:-1] == KIND_FLOW) & (np.nan_to_num(dur[:-1], nan=0.0) >= long_flow_s)
    gap = t[1:] - prev_end
    out[1:] = same & long_prev & (kind[1:] == KIND_FLOW) & (gap >= -2.0) & (gap <= 5.0)
    return out


def prepare_series(table: EventTable, cfg: ResonanceConfig, *, key_map: np.ndarray | None = None,
                   rng_seed: int | None = None) -> SeriesSet:
    """Group events into per-(line, key) series; drop continuations, coalesce bursts, cap size.

    ``key_map`` optionally remaps key ids (e.g. to infrastructure-cluster ids) before grouping.
    Thinning of over-long series is random (seeded), never regular decimation, because random
    thinning preserves periodic structure while decimation can alias it.
    """
    key = table.key if key_map is None else key_map[table.key]
    n = len(table)
    if n == 0:
        z = np.zeros(0, dtype=np.int64)
        return SeriesSet(np.zeros(0), z, z.astype(np.int32), z.astype(np.int32), np.zeros(1, dtype=np.int64), z)
    order = np.lexsort((table.t, key, table.line))
    t = table.t[order]
    ln = table.line[order].astype(np.int64)
    ky = key[order].astype(np.int64)
    grp = ln * (int(ky.max()) + 1) + ky
    cont = continuation_mask(t, grp, table.kind[order], table.dur_s[order], cfg.long_flow_s)
    keep = ~cont
    # raw counts per series (before coalescing)
    new_grp = np.ones(n, dtype=bool)
    new_grp[1:] = grp[1:] != grp[:-1]
    raw_sid = np.cumsum(new_grp) - 1
    raw_counts_all = np.bincount(raw_sid)
    t, grp, raw_sid = t[keep], grp[keep], raw_sid[keep]
    ln, ky = ln[keep], ky[keep]
    # coalesce bursts: keep an event only if it starts a series or follows the previous one by > coalesce_s
    if len(t):
        gap_ok = np.ones(len(t), dtype=bool)
        gap_ok[1:] = (grp[1:] != grp[:-1]) | ((t[1:] - t[:-1]) > cfg.coalesce_s)
        t, grp, raw_sid, ln, ky = t[gap_ok], grp[gap_ok], raw_sid[gap_ok], ln[gap_ok], ky[gap_ok]
    starts = np.ones(len(t), dtype=bool)
    starts[1:] = grp[1:] != grp[:-1]
    sid = np.cumsum(starts) - 1
    counts = np.bincount(sid) if len(sid) else np.zeros(0, dtype=np.int64)
    # random thinning of long series to series_cap events
    if len(counts) and counts.max() > cfg.series_cap:
        rng = np.random.default_rng(cfg.seed if rng_seed is None else rng_seed)
        keep_p = np.minimum(1.0, cfg.series_cap / counts[sid])
        km = rng.random(len(t)) < keep_p
        # never drop a series entirely
        km |= starts
        t, sid, ln, ky, raw_sid = t[km], sid[km], ln[km], ky[km], raw_sid[km]
        starts = np.ones(len(t), dtype=bool)
        starts[1:] = sid[1:] != sid[:-1]
        sid = np.cumsum(starts) - 1
        counts = np.bincount(sid)
    first = np.flatnonzero(starts)
    offsets = np.concatenate([[0], np.cumsum(counts)]).astype(np.int64)
    return SeriesSet(t=t, sid=sid.astype(np.int64), line=ln[first].astype(np.int32), key=ky[first].astype(np.int32),
                     offsets=offsets, raw_counts=raw_counts_all[raw_sid[first]])
