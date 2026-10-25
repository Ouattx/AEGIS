"""RESONANCE: cross-subscriber harmonic resonance with FDR control.

Pipeline for one observation window (batch mode; :mod:`aegis.resonance.stream`
re-runs it over a sliding horizon):

1. population model (:mod:`.population`): per destination key and per infrastructure
   cluster, popularity, hosting, history, shape -> eligibility and a weight in (0, 1];
2. timer recovery (:mod:`.periodicity`): a difference periodogram Z_l(P) for every
   (line, destination) series of every involved line;
3. resonance statistics per eligible hypothesis H with member lines l = 1..m:

       T_lock = max_P (sum_l g_l(P) - mu0(P)) / sd0(P)   (lines agree on one period; studentized
                                              per period with a pilot batch of null draws)
       T_free = sum_l max_P g_l(P)           (lines are periodic, periods may differ;
                                              only lines with >= free_min_events events)
       g_l(P) = clip(Z_l(P), -z_cap, z_cap) * persistence_l   (Z: signed cosine-fold z)

4. null distribution by *destination-label permutation within lines*: each member
   line's series for H is replaced by that same line's series to another destination
   (outside H's infrastructure cluster) with a similar event count. This preserves
   each line's sampling rate, NAT mixture, activity hours and benign timers, and breaks
   only the association "these lines' periodic traffic goes to the same place".
   Draws are sequential (Besag-Clifford stopping after ``sequential_h`` exceedances),
   with a generalized-Pareto tail approximation when the observation exceeds almost all
   draws. ``p = min(1, 2 * min(p_lock, p_free))`` (Bonferroni over the two statistics);
5. weighted Benjamini-Hochberg (Genovese, Roeder & Wasserman 2006) over all eligible
   hypotheses with the population weights (each <= 1, so sum(w) <= m and FDR <= q under
   independence / PRDS of the null p-values); q-values reported;
6. rejected hypotheses become :class:`Campaign` objects (cluster rejections absorb
   their member keys).

The guarantee is about *resonance* (shared timing structure beyond what the same
lines' traffic to other destinations shows). It is not a guarantee of maliciousness;
benign shared timers are kept out by the population model, which is why the
population gates are pre-registered and logged in every evidence payload.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

import numpy as np
import pandas as pd
from scipy import stats as sstats

from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import EventTable, SeriesSet, prepare_series
from aegis.resonance.models import Abstention, Campaign, LineSupport, ResonanceReport, TestedUnit
from aegis.resonance.periodicity import (
    PairPeriodicity,
    Periodogram,
    nominal_p,
    best_periods,
    make_grid,
    periodogram,
    persistence,
    phase_rayleigh,
)
from aegis.resonance.population import (
    DestinationContext,
    DestinationHistory,
    UnitInfo,
    assess_unit,
    infrastructure_clusters,
    key_stats,
)

ALT_WINDOW = 8          # candidates inspected on each side of the count-matched position
ALT_KEEP = 6            # nearest-count alternatives kept per member line
COUNT_TOL_FACTOR = 2.0  # null alternatives: exact event count for 1-2 events, within a factor of 2 above
MAX_GATHER = 25_000_000  # float32 elements per null batch (bounds memory)
PILOT_DRAWS = 64        # permutations used only to standardize candidate periods
REF_LINES_MIN = 300     # minimum reference lines sampled for the cross-line null fallback


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _unit_seed(seed: int, unit_id: str) -> np.random.Generator:
    h = int(hashlib.sha256(unit_id.encode()).hexdigest()[:12], 16)
    return np.random.default_rng([seed, h])


def campaign_id_for(tenant_id: str, destinations: Iterable[str]) -> str:
    return "rc-" + hashlib.sha256(("|".join([tenant_id, *sorted(destinations)])).encode()).hexdigest()[:20]


def weighted_bh(p: np.ndarray, w: np.ndarray, q: float) -> tuple[np.ndarray, np.ndarray]:
    """Weighted Benjamini-Hochberg. Returns (q-values, rejected mask).

    p-values are divided by their weights (capped at 1). With every weight <= 1 the
    procedure is at least as conservative as BH on the reweighted family.
    """
    p = np.asarray(p, dtype=np.float64)
    w = np.asarray(w, dtype=np.float64)
    m = len(p)
    if m == 0:
        return np.zeros(0), np.zeros(0, dtype=bool)
    pw = np.minimum(1.0, p / np.maximum(w, 1e-12))
    order = np.argsort(pw, kind="stable")
    ranked = pw[order] * m / np.arange(1, m + 1)
    qv_sorted = np.minimum.accumulate(ranked[::-1])[::-1]
    qv = np.empty(m)
    qv[order] = np.minimum(qv_sorted, 1.0)
    return qv, qv <= q


def _tail_p(null: np.ndarray, obs: float, floor: float) -> float | None:
    """Generalized Pareto tail estimate of P(null >= obs) (Knijnenburg et al. 2009)."""
    B = len(null)
    if B < 200:
        return None
    u = float(np.quantile(null, 0.9))
    exc = null[null > u] - u
    if len(exc) < 20 or not np.isfinite(obs) or obs <= u or np.ptp(exc) <= 0:
        return None
    if len(np.unique(np.round(exc, 6))) < 0.8 * len(exc):
        return None  # discrete null (few informative lines): extrapolation is meaningless
    try:
        c, _, scale = sstats.genpareto.fit(exc, floc=0.0)
        sf = float(sstats.genpareto.sf(obs - u, c, loc=0.0, scale=scale))
    except Exception:  # pragma: no cover - numerical failure falls back to empirical
        return None
    if not np.isfinite(sf) or scale <= 0:
        return None
    if c < 0:
        # a bounded fitted tail would claim p = 0 beyond its endpoint; use the heavier
        # exponential tail (shape 0, MLE scale) instead, which is conservative relative to it
        sf = float(np.exp(-(obs - u) / float(np.mean(exc))))
    return max(floor, len(exc) / B * sf)


@dataclass
class _Rows:
    """Series rows entering the statistics (single-key series + cluster series)."""
    line: np.ndarray
    comp: np.ndarray       # infrastructure component of the row's destination
    unit_key: np.ndarray   # key id (single) or -(component+1) for cluster rows
    count: np.ndarray
    raw: np.ndarray
    G: np.ndarray          # (n_rows, n_periods) capped, persistence-weighted Z
    gF: np.ndarray         # (n_rows,) own-period contribution
    Z: np.ndarray
    R: np.ndarray
    has: np.ndarray
    pers: np.ndarray
    times_src: list[tuple[SeriesSet, int]]   # where to fetch event times for a row
    index: dict[int, np.ndarray] | None = None   # unit key -> row ids (built lazily)


class Resonance:
    """Batch RESONANCE detector for one tenant."""

    def __init__(self, cfg: ResonanceConfig | None = None, *, context: DestinationContext | None = None,
                 history: DestinationHistory | None = None, tenant_id: str = "default"):
        self.cfg = cfg or ResonanceConfig()
        self.context = context or DestinationContext(None)
        self.history = history
        self.tenant_id = tenant_id
        self.grid = make_grid(self.cfg)

    # ------------------------------------------------------------------ helpers
    def _abstain(self, table: EventTable, reason: str, start: float, end: float, active: int,
                 timings: dict[str, float]) -> ResonanceReport:
        return ResonanceReport(tenant_id=self.tenant_id, detector_version=self.cfg.detector_version,
                               config_hash=self.cfg.config_hash, status="abstain", abstain_reason=reason,
                               window_start=_utc(start), window_end=_utc(end), active_lines=active,
                               n_events=len(table), n_series=0, n_tested=0, n_ineligible=0, timings_s=timings)

    # ------------------------------------------------------------------ main entry
    def detect(self, table: EventTable, *, now: float | None = None) -> ResonanceReport:
        cfg = self.cfg
        tm: dict[str, float] = {}
        t0 = time.perf_counter()
        start, end = table.window
        span = end - start
        if len(table) == 0:
            return self._abstain(table, "no_events", start, end, 0, tm)
        stats = key_stats(table, cfg)
        active = stats.active_lines
        if span < cfg.min_span_s:
            return self._abstain(table, f"observation_window_too_short ({span / 3600:.1f} h < "
                                        f"{cfg.min_span_s / 3600:.1f} h)", start, end, active, tm)
        if active < cfg.min_lines:
            return self._abstain(table, f"too_few_active_lines ({active} < {cfg.min_lines})", start, end, active, tm)
        usable = self.grid.usable(span, cfg.min_cycles)
        if not usable.any():
            return self._abstain(table, "window_too_short_for_any_candidate_period", start, end, active, tm)
        now = end if now is None else now
        nk = len(table.keys)
        max_lines = cfg.max_popularity * active
        tm["stats"] = time.perf_counter() - t0

        # ---------------------------------------------------------- population model
        t1 = time.perf_counter()
        cand = np.flatnonzero((stats.n_lines >= 2) & (stats.n_lines <= max_lines))
        comp_map = infrastructure_clusters(table, self.context, cfg, cand)
        comp_of_key = np.arange(nk, dtype=np.int64)
        for k, c in comp_map.items():
            comp_of_key[k] = c
        reasons_count: dict[str, int] = {}
        n_popular = int(np.sum(stats.n_lines > max_lines))
        if n_popular:
            reasons_count["popular"] = n_popular
        units: list[UnitInfo] = []
        for k in cand:
            k = int(k)
            u = assess_unit(table.keys.items[k], [k], int(comp_of_key[k]), int(stats.n_lines[k]), active,
                            float(stats.median_bytes[k]), float(stats.long_frac[k]), float(stats.first_t[k]),
                            now, table, self.context, self.history, cfg)
            units.append(u)
        # multi-key clusters
        comp_members: dict[int, list[int]] = {}
        for k in cand:
            comp_members.setdefault(int(comp_of_key[k]), []).append(int(k))
        multi = {c: sorted(m) for c, m in comp_members.items() if len(m) >= 2}
        cluster_event_mask = None
        if multi:
            in_multi = np.zeros(nk, dtype=bool)
            for m in multi.values():
                in_multi[m] = True
            cluster_event_mask = in_multi[table.key]
            ck = comp_of_key[table.key[cluster_event_mask]]
            cl = table.line[cluster_event_mask].astype(np.int64)
            ct = table.t[cluster_event_mask]
            df = pd.DataFrame({"c": ck, "l": cl, "t": ct,
                               "b": table.nbytes[cluster_event_mask].astype(np.float64),
                               "lg": (np.nan_to_num(table.dur_s[cluster_event_mask], nan=0.0)
                                      >= cfg.long_flow_s).astype(np.float64),
                               "f": table.kind[cluster_event_mask] == 0})
            nl = df.drop_duplicates(["c", "l"]).groupby("c").size()
            ft = df.groupby("c")["t"].min()
            fl = df[df["f"]]
            days = max(span / 86_400.0, 1.0 / 24)
            mb = (fl.groupby(["c", "l"])["b"].sum(min_count=1) / days).groupby(level=0).median()
            lf = fl.groupby("c")["lg"].mean()
            for c, members in sorted(multi.items()):
                uid = "cluster:" + "+".join(table.keys.items[m] for m in members[:3]) + \
                      (f"+{len(members) - 3}more" if len(members) > 3 else "")
                u = assess_unit(uid, members, c, int(nl.get(c, 0)), active, float(mb.get(c, np.nan)),
                                float(lf.get(c, np.nan)), float(ft.get(c, np.nan)), now, table, self.context,
                                self.history, cfg)
                units.append(u)
        for u in units:
            for r in u.reasons:
                reasons_count[r] = reasons_count.get(r, 0) + 1
        eligible = [u for u in units if u.eligible]
        abstentions = self._abstentions(units, stats, table)
        tm["population"] = time.perf_counter() - t1

        base = dict(tenant_id=self.tenant_id, detector_version=cfg.detector_version, config_hash=cfg.config_hash,
                    window_start=_utc(start), window_end=_utc(end), active_lines=active, n_events=len(table))
        if not eligible:
            return ResonanceReport(status="ok", n_series=0, n_tested=0, n_ineligible=len(units) + n_popular,
                                   ineligible_reasons=reasons_count, abstentions=abstentions, timings_s=tm, **base)

        # ---------------------------------------------------------- per-line timer recovery
        t2 = time.perf_counter()
        rows = self._build_rows(table, stats, eligible, comp_of_key, multi, cluster_event_mask, max_lines,
                                usable, start, end)
        tm["periodograms"] = time.perf_counter() - t2

        # ---------------------------------------------------------- resonance + permutation null
        t3 = time.perf_counter()
        pool = self._pool(rows)
        results = []
        for u in eligible:
            r = self._unit_rows(u, rows)
            results.append(self._test_unit(u, r, rows, pool, usable))
        tm["permutation"] = time.perf_counter() - t3

        # units without enough informative lines abstain and leave the multiple-testing family
        keep_idx = [i for i, res in enumerate(results) if not res.get("abstain")]
        for i, res in enumerate(results):
            if res.get("abstain"):
                u = eligible[i]
                abstentions.append(Abstention(
                    unit_id=u.unit_id, destinations=[table.keys.items[m] for m in u.members], n_lines=u.n_lines,
                    reason=f"too_few_informative_lines ({res['informative']} lines with repeated contacts < "
                           f"{cfg.min_lines})"))
        eligible = [eligible[i] for i in keep_idx]
        results = [results[i] for i in keep_idx]

        # ---------------------------------------------------------- weighted BH
        p = np.array([res["p"] for res in results])
        w = np.array([u.weight for u in eligible])
        qv, rej = weighted_bh(p, w, cfg.q)
        tested = [TestedUnit(unit_id=u.unit_id, destinations=[table.keys.items[m] for m in u.members],
                             n_lines=u.n_lines, popularity=round(u.popularity, 6), weight=round(u.weight, 6),
                             p_value=float(res["p"]), p_lock=float(res["p_lock"]), p_free=float(res["p_free"]),
                             q_value=float(q), period_s=res["period"], rejected=bool(rj))
                  for u, res, q, rj in zip(eligible, results, qv, rej)]
        tested.sort(key=lambda x: (x.q_value, x.p_value, x.unit_id))

        # fold member keys into rejected clusters
        rejected_comps = {u.component for u, rj in zip(eligible, rej) if rj and len(u.members) > 1}
        campaigns: list[Campaign] = []
        for u, res, q, rj in zip(eligible, results, qv, rej):
            if not rj:
                continue
            if len(u.members) == 1 and u.component in rejected_comps:
                continue
            campaigns.append(self._campaign(u, res, float(q), table, rows, start, end))
        campaigns.sort(key=lambda c: (c.q_value, c.campaign_id))
        tm["total"] = time.perf_counter() - t0
        return ResonanceReport(status="ok", n_series=len(rows.line), n_tested=len(eligible),
                               n_ineligible=len(units) - len(eligible) + n_popular,
                               ineligible_reasons=reasons_count, campaigns=campaigns, tested=tested,
                               abstentions=abstentions, timings_s={k: round(v, 4) for k, v in tm.items()}, **base)

    # ------------------------------------------------------------------ building blocks
    def _abstentions(self, units: list[UnitInfo], stats, table: EventTable) -> list[Abstention]:
        out = []
        for u in units:
            if u.reasons == ["too_few_lines"] and u.n_lines >= 2:
                ev = float(sum(stats.n_events[m] for m in u.members))
                if ev / max(1, u.n_lines) >= 4:  # repeated contact: worth telling the analyst we abstained
                    out.append(Abstention(unit_id=u.unit_id, destinations=[table.keys.items[m] for m in u.members],
                                          n_lines=u.n_lines,
                                          reason=f"too_few_lines ({u.n_lines} < {self.cfg.min_lines})"))
        out.sort(key=lambda a: (-a.n_lines, a.unit_id))
        return out[:500]

    def _build_rows(self, table: EventTable, stats, eligible: list[UnitInfo], comp_of_key: np.ndarray,
                    multi: dict[int, list[int]], cluster_event_mask, max_lines: float, usable: np.ndarray,
                    start: float, end: float) -> _Rows:
        cfg = self.cfg
        nk = len(table.keys)
        elig_keys = np.zeros(nk, dtype=bool)
        for u in eligible:
            elig_keys[u.members] = True
        involved = np.zeros(len(table.lines), dtype=bool)
        involved[np.unique(table.line[elig_keys[table.key]])] = True
        # reference lines: a seeded random sample of other active lines, so the cross-line fallback
        # of the null has a broad population of series (not only the hypotheses' own lines)
        active = np.zeros(len(table.lines), dtype=bool)
        active[np.unique(table.line)] = True
        others = np.flatnonzero(active & ~involved)
        n_ref = min(len(others), max(REF_LINES_MIN, 2 * int(involved.sum())))
        if n_ref:
            rs = np.random.default_rng([cfg.seed, 99])
            involved[rs.choice(others, size=n_ref, replace=False)] = True
        # every destination of a line is a legitimate permutation target (popular ones included:
        # shared benign timers in the null are absorbed by per-period studentization)
        mask = involved[table.line]
        sub = table.select(mask)
        S = prepare_series(sub, cfg)
        pg = periodogram(S, self.grid, cfg)
        pers = persistence(S, np.arange(S.n_series), start, end, cfg.persistence_block_s) \
            if cfg.persistence_weighting else np.ones(S.n_series, dtype=np.float32)
        parts = [(S, pg, pers, S.key.astype(np.int64), comp_of_key[S.key].astype(np.int64))]
        elig_comps = {u.component for u in eligible if len(u.members) > 1}
        if elig_comps and cluster_event_mask is not None:
            cm = cluster_event_mask & np.isin(comp_of_key[table.key], list(elig_comps))
            if cm.any():
                csub = table.select(cm)
                kmap = comp_of_key.copy()
                SC = prepare_series(csub, cfg, key_map=kmap)
                pgc = periodogram(SC, self.grid, cfg)
                persc = persistence(SC, np.arange(SC.n_series), start, end, cfg.persistence_block_s) \
                    if cfg.persistence_weighting else np.ones(SC.n_series, dtype=np.float32)
                comp = SC.key.astype(np.int64)
                parts.append((SC, pgc, persc, -(comp + 1), comp))
        lines, comps, ukeys, counts, raws, Zs, Rs, Hs, Ps, src = [], [], [], [], [], [], [], [], [], []
        for SS, pp, pe, uk, cp in parts:
            lines.append(SS.line.astype(np.int64))
            comps.append(cp)
            ukeys.append(uk)
            counts.append(SS.counts)
            raws.append(SS.raw_counts)
            Zs.append(pp.Z)
            Rs.append(pp.R)
            Hs.append(pp.has_pairs)
            Ps.append(pe)
            src.extend((SS, i) for i in range(SS.n_series))
        Z = np.vstack(Zs)
        R = np.vstack(Rs).astype(np.float16)
        H = np.vstack(Hs)
        pe = np.concatenate(Ps).astype(np.float32)
        G = np.clip(Z, -cfg.z_cap, cfg.z_cap) * pe[:, None]
        G[:, ~usable] = 0.0
        Zu = np.where(usable[None, :] & H, Z, -np.inf)
        zmax = Zu.max(axis=1)
        cnt_all = np.concatenate(counts)
        gF = np.where(np.isfinite(zmax) & (cnt_all >= cfg.free_min_events),
                      np.clip(zmax, -cfg.z_cap, cfg.z_cap), 0.0) * pe
        return _Rows(np.concatenate(lines), np.concatenate(comps), np.concatenate(ukeys), np.concatenate(counts),
                     np.concatenate(raws), np.ascontiguousarray(G, dtype=np.float32), gF.astype(np.float32),
                     Z, R, H, pe, src)

    def _unit_rows(self, u: UnitInfo, rows: _Rows) -> np.ndarray:
        if rows.index is None:
            order = np.argsort(rows.unit_key, kind="stable")
            uk = rows.unit_key[order]
            keys, starts = np.unique(uk, return_index=True)
            ends = np.append(starts[1:], len(uk))
            rows.index = {int(k): order[s:e] for k, s, e in zip(keys, starts, ends)}
        target = u.members[0] if len(u.members) == 1 else -(u.component + 1)
        return rows.index.get(int(target), np.zeros(0, dtype=np.int64))

    def _pool(self, rows: _Rows) -> dict[str, np.ndarray]:
        single = np.flatnonzero(rows.unit_key >= 0)
        lc = np.log(np.maximum(rows.count[single], 1)).astype(np.float64)
        ln = rows.line[single]
        combo = ln.astype(np.float64) * 100.0 + lc
        o = np.argsort(combo, kind="stable")
        go = np.argsort(lc, kind="stable")
        return {"rows": single[o], "combo": combo[o], "line": ln[o], "lc": lc[o],
                "g_rows": single[go], "g_lc": lc[go], "g_line": ln[go]}

    def _alternatives(self, r: np.ndarray, comp_u: int, rows: _Rows, pool: dict[str, np.ndarray]
                      ) -> tuple[np.ndarray, np.ndarray]:
        """Count-matched alternative rows per member line: (alts (m, W), n_valid (m,)).

        The first column is the member's own series (identity permutation). Further
        alternatives are the series of the *same line* to other infrastructure whose event
        counts are *nearest* to the member series (exact for 1-2 events, never beyond a
        factor of 2), taken symmetrically around the count so the right-skewed count
        distribution does not bias the null toward smaller (weaker) series. Lines with fewer
        than two such series borrow nearest-count series from other lines.
        """
        W = 2 * ALT_WINDOW + 1
        m = len(r)
        lines = rows.line[r]
        cnt = rows.count[r].astype(np.float64)
        lc = np.log(np.maximum(cnt, 1))
        tol = np.where(cnt >= 3, np.log(COUNT_TOL_FACTOR), 1e-9)
        offs = np.arange(-ALT_WINDOW, ALT_WINDOW + 1)

        def nearest(sorted_key: np.ndarray, sorted_rows: np.ndarray, sorted_lc: np.ndarray, sorted_line: np.ndarray,
                    query: np.ndarray, sel: np.ndarray, same_line: bool) -> tuple[np.ndarray, np.ndarray]:
            n = len(sorted_rows)
            q = query[sel]
            mid = (np.searchsorted(sorted_key, q, side="left") + np.searchsorted(sorted_key, q, side="right")) // 2
            idx = np.clip(mid[:, None] + offs[None, :], 0, max(0, n - 1))
            cand = sorted_rows[idx] if n else np.zeros((len(q), W), dtype=np.int64)
            diff = np.abs(sorted_lc[idx] - lc[sel][:, None]) if n else np.full((len(q), W), np.inf)
            line_ok = (sorted_line[idx] == lines[sel][:, None]) if same_line else (sorted_line[idx] != lines[sel][:, None])
            valid = line_ok & (rows.comp[cand] != comp_u) & (cand != r[sel][:, None]) & (diff <= tol[sel][:, None])
            dup = np.zeros_like(valid)
            dup[:, 1:] = idx[:, 1:] == idx[:, :-1]
            valid &= ~dup & (n > 0)
            # nearest counts first; deterministic tie-break by candidate row id
            score = np.where(valid, diff + 1e-9 * ((cand * 2654435761) % 1000), np.inf)
            order = np.argsort(score, axis=1, kind="stable")[:, :ALT_KEEP]
            return np.take_along_axis(cand, order, axis=1), np.take_along_axis(valid, order, axis=1)

        alts = np.zeros((m, ALT_KEEP), dtype=np.int64)
        valid = np.zeros((m, ALT_KEEP), dtype=bool)
        allsel = np.ones(m, dtype=bool)
        if len(pool["rows"]):
            a, v = nearest(pool["combo"], pool["rows"], pool["lc"], pool["line"], lines * 100.0 + lc, allsel, True)
            alts[:], valid[:] = a, v
        need = valid.sum(axis=1) < 2
        if need.any() and len(pool["g_rows"]):
            a, v = nearest(pool["g_lc"], pool["g_rows"], pool["g_lc"], pool["g_line"], lc, need, False)
            alts[need], valid[need] = a, v
        # the member's own series is part of its exchangeable set (identity permutation): without it
        # the null support excludes the observed configuration and the test is not a permutation test
        alts = np.concatenate([r[:, None], alts], axis=1)
        valid = np.concatenate([np.ones((m, 1), dtype=bool), valid], axis=1)
        nvalid = valid.sum(axis=1)
        order = np.argsort(~valid, axis=1, kind="stable")
        return np.take_along_axis(alts, order, axis=1), nvalid

    def _test_unit(self, u: UnitInfo, r: np.ndarray, rows: _Rows, pool: dict[str, np.ndarray],
                   usable: np.ndarray) -> dict:
        cfg = self.cfg
        m = len(r)
        G = rows.G
        col = G[r].sum(axis=0)
        j = int(np.argmax(col))
        t_lock = float(col[j])
        t_free = float(rows.gF[r].sum())
        period = float(self.grid.periods[j]) if col[j] > 0 else None
        res = {"rows": r, "t_lock": t_lock, "t_free": t_free, "period": period, "j": j, "m": m}
        informative = int(np.sum(np.any(rows.has[r][:, usable], axis=1))) if m else 0
        res["informative"] = informative
        if informative < cfg.min_lines:
            # too few lines carry any timing information (e.g. heavy sampling): abstain, never guess
            res.update(p=1.0, p_lock=1.0, p_free=1.0, method="abstain_uninformative", B=0, null_mean=0.0,
                       null_sd=0.0, abstain=True)
            return res
        alts, nvalid = self._alternatives(r, u.component, rows, pool)
        ok = nvalid > 1                                   # has at least one alternative besides itself
        if m == 0 or ok.sum() < max(2, m // 2):
            res.update(p=1.0, p_lock=1.0, p_free=1.0, method="no_null", B=0, null_mean=0.0, null_sd=0.0)
            return res
        rng = _unit_seed(cfg.seed, u.unit_id)
        nv = np.maximum(nvalid, 1)
        n_p = G.shape[1]
        cap = max(4, int(MAX_GATHER // max(1, m * n_p)))
        mrange = np.arange(m)[None, :]

        def draw(nb: int) -> tuple[np.ndarray, np.ndarray]:
            pick = (rng.random((nb, m)) * nv[None, :]).astype(np.int64)
            choice = alts[mrange, pick]
            choice = np.where(ok[None, :], choice, r[None, :])               # lines w/o null keep own row
            return G[choice].sum(axis=1), rows.gF[choice].sum(axis=1)        # (nb, n_p), (nb,)

        # pilot draws (not part of the p-value sample) standardize every candidate period:
        # studentized max-T, so periods that are common in the null (e.g. the 3600 s DNS-cache
        # refresh shared by countless benign apps) cannot dominate the maximum.
        pilot = []
        left = PILOT_DRAWS
        while left > 0:
            nb = min(left, cap)
            pilot.append(draw(nb)[0])
            left -= nb
        PL = np.concatenate(pilot)
        mu = PL.mean(axis=0)
        sd = PL.std(axis=0, ddof=1)
        sd_floor = max(1e-3, 0.25 * float(np.median(sd[usable]))) if usable.any() else 1e-3
        sd = np.maximum(sd, sd_floor)
        bad = ~usable

        def studentized(cols: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
            zc = (cols - mu) / sd
            zc[..., bad] = -np.inf
            return zc.max(axis=-1), zc.argmax(axis=-1)

        t_lock_s, j_s = studentized(col)
        t_lock = float(t_lock_s)
        j = int(j_s)
        period = float(self.grid.periods[j]) if col[j] > mu[j] else None
        res.update(t_lock=t_lock, t_lock_raw=float(col[j]), j=j, period=period, mu=mu, sd=sd)
        null_lock: list[np.ndarray] = []
        null_free: list[np.ndarray] = []
        b = 0
        el = ef = 0
        batch = 20
        while b < cfg.n_permutations:
            nb = min(batch, cfg.n_permutations - b, cap)
            cols, nf = draw(nb)
            nl = studentized(cols)[0]
            null_lock.append(nl)
            null_free.append(nf)
            el += int((nl >= t_lock).sum())
            ef += int((nf >= t_free).sum())
            b += nb
            if b >= cfg.min_permutations and el >= cfg.sequential_h and ef >= cfg.sequential_h:
                break
            batch = min(batch * 2, 400)
        NL = np.concatenate(null_lock)
        NF = np.concatenate(null_free)

        def pval(exceed: int, null: np.ndarray, obs: float) -> tuple[float, str]:
            if exceed >= cfg.tail_min_exceed or b < cfg.n_permutations:
                return (exceed + 1) / (b + 1), ("sequential" if b < cfg.n_permutations else "empirical")
            if cfg.tail_fit:
                tp = _tail_p(null, obs, cfg.p_floor)
                if tp is not None:
                    return min(tp, (exceed + 1) / (b + 1)), "gpd_tail"
            return (exceed + 1) / (b + 1), "empirical"

        p_lock, ml = pval(el, NL, t_lock)
        p_free, mf = pval(ef, NF, t_free)
        p = min(1.0, 2.0 * min(p_lock, p_free))
        lock_wins = p_lock <= p_free
        null = NL if lock_wins else NF
        res.update(p=p, p_lock=p_lock, p_free=p_free, method=ml if lock_wins else mf, B=b,
                   null_mean=float(null.mean()), null_sd=float(null.std(ddof=1)) if len(null) > 1 else 0.0,
                   lock_wins=lock_wins)
        return res

    # ------------------------------------------------------------------ campaign assembly
    def _campaign(self, u: UnitInfo, res: dict, q: float, table: EventTable, rows: _Rows,
                  start: float, end: float) -> Campaign:
        cfg = self.cfg
        r = res["rows"]
        dests = [table.keys.items[m] for m in u.members]
        lock = bool(res.get("lock_wins", True))
        usable = self.grid.usable(end - start, cfg.min_cycles)
        pg = Periodogram(rows.Z[r], rows.R[r], rows.has[r])
        own_p, own_z, own_r = best_periods(pg, self.grid, usable)
        j = res["j"]
        period = res["period"]
        if period is not None and 0 < j < self.grid.n_periods - 1 and "mu" in res:
            col = (rows.G[r].sum(axis=0) - res["mu"]) / res["sd"]
            y0, y1, y2 = col[j - 1], col[j], col[j + 1]
            den = y0 - 2 * y1 + y2
            if den < 0:
                off = float(np.clip(0.5 * (y0 - y2) / den, -0.5, 0.5))
                period = float(self.grid.periods[j] * np.exp(off * np.log(self.grid.periods[1] / self.grid.periods[0])))
        z_at = rows.Z[r, j]
        if lock:
            supports = z_at >= cfg.support_z
        else:
            supports = np.nan_to_num(own_z, nan=0.0) >= cfg.support_z
            period = float(np.nanmedian(own_p)) if np.isfinite(own_p).any() else None
        # first contact per member line
        member_mask = np.isin(table.key, u.members)
        fc = pd.Series(table.t[member_mask]).groupby(table.line[member_mask]).min()
        line_ids = rows.line[r]
        first = np.array([fc.get(int(l), np.nan) for l in line_ids])
        # phase locking across lines (absolute phase at the campaign period)
        plv = plv_p = None
        if lock and period:
            vec = []
            for row in r:
                SS, i = rows.times_src[row]
                tt = SS.times(i)
                if len(tt):
                    ph = 2 * np.pi * tt / period
                    v = np.exp(1j * ph).mean()
                    if abs(v) > 0:
                        vec.append(v / abs(v))
            if len(vec) >= 2:
                plv = float(abs(np.mean(vec)))
                plv_p = float(np.exp(-len(vec) * plv * plv))
        # onset and synchronization
        fs = np.sort(first[np.isfinite(first)])
        onset = float(fs[min(cfg.min_lines, len(fs)) - 1]) if len(fs) else None
        censor = start + max(period or 600.0, 600.0)
        nonc = fs[fs > censor]
        onset_sync = None
        if len(nonc) >= cfg.min_lines:
            med = float(np.median(nonc))
            onset_sync = float(np.mean(np.abs(nonc - med) <= 3600.0))
        agree = None
        if period:
            ratio = own_p / period
            agree = float(np.nanmean((np.abs(ratio - 1) <= 0.1) | (np.abs(ratio - 2) <= 0.2))) \
                if np.isfinite(own_p).any() else 0.0
        lines: list[LineSupport] = []
        for k, row in enumerate(r):
            zz = float(own_z[k]) if np.isfinite(own_z[k]) else None
            lines.append(LineSupport(
                line=table.lines.items[int(line_ids[k])], n_events=int(rows.count[row]), raw_events=int(rows.raw[row]),
                first_contact=_utc(float(first[k]) if np.isfinite(first[k]) else start),
                period_s=None if not np.isfinite(own_p[k]) else round(float(own_p[k]), 2),
                strength=None if not np.isfinite(own_r[k]) else round(float(own_r[k]), 4),
                z_at_campaign_period=round(float(z_at[k]), 4),
                p_nominal=None if zz is None else float(nominal_p(zz, self.grid.n_eff)),
                persistence=round(float(rows.pers[row]), 4), supports=bool(supports[k])))
        lines.sort(key=lambda s: s.line)
        m = len(r)
        stat_obs = res["t_lock"] if lock else res["t_free"]
        z_std = (stat_obs - res["null_mean"]) / res["null_sd"] if res["null_sd"] > 0 else float("inf")
        enforce = u.enforcement_eligible
        explanation = self._explain(u, dests, m, period, agree, lock, res, q, z_std, plv, plv_p, onset,
                                    onset_sync, int(np.sum(supports)))
        summary = {
            "statistic": "period_lock" if lock else "free_periodicity",
            "observed": round(stat_obs, 4), "null_mean": round(res["null_mean"], 4),
            "null_sd": round(res["null_sd"], 4), "standardized": None if not np.isfinite(z_std) else round(z_std, 3),
            "t_lock": round(res["t_lock"], 4), "t_free": round(res["t_free"], 4),
            "permutations": res["B"], "p_method": res["method"], "weight_parts": u.weight_parts,
            "population": {"n_lines": u.n_lines, "popularity": round(u.popularity, 6),
                           "median_bytes_per_line_day": u.median_bytes, "long_flow_frac": u.long_frac,
                           "age_days": u.age_days, "surging": u.surging},
            "infrastructure": {"ips": u.ips[:50], "asns": u.asns, "shared_hosting_domain": u.shared_domain, "cohosted_ips": u.cohosted_ips,
                               "topology_unknown": u.topology_unknown, "enforcement_eligible": enforce},
            "supporting_lines": int(np.sum(supports)),
            "uses_device_class": False,
        }
        return Campaign(
            campaign_id=campaign_id_for(self.tenant_id, dests), tenant_id=self.tenant_id,
            detector_version=cfg.detector_version, config_hash=cfg.config_hash, destinations=dests,
            destination_ips=u.ips, asns=u.asns, shared_hosting_domain=u.shared_domain,
            topology_unknown=u.topology_unknown, enforcement_eligible=enforce,
            member_lines=sorted(s.line for s in lines), supporting_lines=sorted(s.line for s in lines if s.supports),
            n_lines=m, popularity=u.popularity, destination_age_days=u.age_days,
            statistic="period_lock" if lock else "free_periodicity",
            period_s=None if period is None else round(float(period), 2), period_agreement=agree,
            resonance_statistic=round(z_std, 4) if np.isfinite(z_std) else 1e6, null_mean=res["null_mean"],
            null_sd=res["null_sd"], p_value=res["p"], p_lock=res["p_lock"], p_free=res["p_free"],
            p_method=res["method"], n_permutations=res["B"], weight=u.weight, weight_parts=u.weight_parts,
            q_value=q, q_target=cfg.q, phase_locking=plv, phase_locking_p=plv_p,
            onset_at=None if onset is None else _utc(onset), onset_sync=onset_sync, window_start=_utc(start),
            window_end=_utc(end), evidence_summary=summary, explanation=explanation, lines=lines)

    def _explain(self, u: UnitInfo, dests: list[str], m: int, period: float | None, agree: float | None,
                 lock: bool, res: dict, q: float, z_std: float, plv: float | None, plv_p: float | None,
                 onset: float | None, onset_sync: float | None, n_support: int) -> str:
        cfg = self.cfg
        names = ", ".join(d.split(":", 1)[1] for d in dests[:4]) + (f" (+{len(dests) - 4} more)" if len(dests) > 4 else "")
        age = "first seen in this window" if u.age_days == 0 else (
            "age unknown (no history)" if u.age_days is None else f"first seen {u.age_days:.1f} days ago")
        parts = [f"{m} unrelated subscriber lines contacted {names} "
                 f"(reached by {100 * u.popularity:.2f}% of active lines; {age})."]
        if lock and period:
            parts.append(f"Their traffic resonates on a shared ~{period:.0f} s timer"
                         + (f"; {100 * agree:.0f}% of lines peak within 10% of it on their own" if agree is not None else "")
                         + f"; {n_support} lines show individual support (z >= {cfg.support_z:g}).")
        else:
            parts.append("Most member lines are individually periodic toward it although their periods differ "
                         f"(median ~{period:.0f} s)" if period else "Member lines are individually periodic toward it.")
        zs = "" if not np.isfinite(z_std) else f", {z_std:.1f} null SDs above the permutation mean"
        parts.append(f"Resonance p = {res['p']:.2e} ({res['method']}, {res['B']} destination-label permutations"
                     f"{zs}); weighted-BH q = {q:.2e} at target q = {cfg.q:g}.")
        if plv is not None and plv_p is not None and plv_p < 0.01:
            parts.append(f"Lines are also phase-locked (PLV {plv:.2f}), suggesting synchronized tasking.")
        if onset_sync is not None and onset_sync >= 0.5:
            parts.append(f"{100 * onset_sync:.0f}% of lines that started inside the window started within 1 h of "
                         "each other (synchronized onset).")
        if u.shared_domain:
            parts.append("Served from shared hosting: any action must target the domain only, never the IPs.")
        if u.topology_unknown:
            parts.append("Hosting topology unknown for some IPs: not enforcement-eligible until verified.")
        parts.append("Inferred from cross-line timing only; device class, vendor, IPTV usage and geography were not used. "
                     "Score is a ranking, not a probability.")
        return " ".join(parts)


# ---------------------------------------------------------------------------- per-pair API

def pair_periodicities(table: EventTable, cfg: ResonanceConfig | None = None, *,
                       lines: Iterable[str] | None = None, keys: Iterable[str] | None = None
                       ) -> list[PairPeriodicity]:
    """Per (line, destination) period estimate, strength and nominal confidence."""
    cfg = cfg or ResonanceConfig()
    mask = np.ones(len(table), dtype=bool)
    if lines is not None:
        ids = [table.lines.get(x) for x in lines]
        mask &= np.isin(table.line, [i for i in ids if i is not None])
    if keys is not None:
        ids = [table.keys.get(x) for x in keys]
        mask &= np.isin(table.key, [i for i in ids if i is not None])
    sub = table.select(mask)
    S = prepare_series(sub, cfg)
    grid = make_grid(cfg)
    pg = periodogram(S, grid, cfg)
    usable = grid.usable(table.span_s, cfg.min_cycles)
    per, z, r = best_periods(pg, grid, usable)
    out = []
    for i in range(S.n_series):
        ok = np.isfinite(per[i])
        pn = float(nominal_p(z[i], grid.n_eff)) if ok else None
        pc = phase_rayleigh(S.times(i), float(per[i]))[0] if ok else None
        out.append(PairPeriodicity(line=table.lines.items[int(S.line[i])], key=table.keys.items[int(S.key[i])],
                                   n_events=int(S.counts[i]), raw_events=int(S.raw_counts[i]),
                                   period_s=float(per[i]) if ok else None, strength=float(r[i]) if ok else None,
                                   z=float(z[i]) if ok else None, p_nominal=pn,
                                   confidence=None if pn is None else 1.0 - pn, phase_coherence=pc))
    return out
