"""Matched-filter genome detection on ISP line telemetry, with population-level FDR control.

Per (line, destination) series and per genome ``g`` the statistic is a matched filter on
pair differences (the same pair-difference representation RESONANCE uses, so it is robust
to jitter accumulation, packet sampling and NAT mixing), but with the template *known*
(the genome's check-in timer and, when distinct, its resolver-lookup timer; the score is the
maximum over templates, computed identically for observed and null series):

    x = d / P'          k = round(x), 1 <= k <= M          P' = P_g (1 + delta), |delta| <= drift_tol
    sigma_k = sqrt(k s_g^2 + (res / P')^2)                 s_g = genome jitter sd (fraction of period)
    e = exp(-(x - k)^2 / (2 sigma_k^2))
    w_k = exp(-2 pi^2 sigma_k^2)  (0 when < 0.05)          timer information surviving at multiple k
    z_timer = sum w_k (e - m_k) / sqrt(sum w_k^2 v_k)

``m_k`` / ``v_k`` are the mean / variance of ``e`` when ``d`` is uniform within the k-th
period bin (the null of no timer). Searching only a narrow band around a known period
removes the look-elsewhere cost of a blind period search and matching the kernel width
to the family's jitter maximizes signal-to-noise: this is why a genome needs fewer
infected lines than generic RESONANCE (see the benchmark for where this holds and fails).

The detection statistic is the timer matched filter only: it is zero-mean for any series
without the genome's timer, whatever the destination type. Byte counts depend strongly on
destination type (telemetry, browsing, streaming), so a size-rhythm term in the detection
statistic breaks exchangeability with the permutation null (measured: hundreds of false
campaigns on a cold-start benign population). Size rhythm is therefore used for *family
attribution* (likelihood) and reported as evidence (``size_match`` per campaign).

Population test per (genome, destination unit): ``T = max_delta sum_lines g_line(delta)`` with
``g = clip(score, -8, 8) * persistence`` (RESONANCE's around-the-clock persistence).
Null: destination-label permutation within lines (each member line's series is replaced by
the same line's series to another destination with a similar event count), sequential
Besag-Clifford draws, generalized-Pareto tail when exceedances are rare. Weighted
Benjamini-Hochberg (``aegis.resonance.weighted_bh``) over all (genome, unit) tests with
RESONANCE's population weights. Eligibility reuses RESONANCE's population model
(popularity, shared hosting, streaming volume, established destinations, allowlist), so
popular CDNs and licensed IPTV are never tested. Nothing reads device class.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

import numpy as np
import pandas as pd
from scipy import stats as sstats
from scipy.special import erf

from aegis.contracts.canonical import sha256_hex
from aegis.genome.models import (
    DeviceModelHypothesis,
    TimerModel,
    Genome,
    GenomeAbstention,
    GenomeCampaign,
    GenomeReport,
)
from aegis.genome.registry import load_genomes
from aegis.provenance.signing import KeyRing
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.detector import weighted_bh
from aegis.resonance.events import KIND_FLOW, EventTable, SeriesSet, prepare_series
from aegis.resonance.periodicity import persistence
from aegis.resonance.population import (
    DestinationContext,
    DestinationHistory,
    assess_unit,
    infrastructure_clusters,
    key_stats,
)

GENOME_DETECTOR_VERSION = "1.0.0"


@dataclass(frozen=True)
class GenomeConfig:
    q: float = 0.01
    n_permutations: int = 2000
    min_alternatives: int = 8        # same-line null alternatives before topping up from other lines
    max_permutations: int = 50_000   # escalation while fewer than 2 null draws reach the observation
    min_permutations: int = 200
    sequential_h: int = 10
    max_multiple: int = 8
    neighbors: int = 8
    drift_tol: float = 0.02
    n_drift: int = 5
    timing_res_s: float = 2.0
    min_jitter: float = 0.01
    z_cap: float = 8.0
    persistence_weighting: bool = True   # around-the-clock timers weigh more than session-gated ones
    harmonic_veto: tuple[int, ...] = (2, 3)   # sub-harmonic periods (m P) vetoed by the k-not-divisible-by-m check
    harmonic_margin: float = 1.5
    size_weight: float = 0.5        # size-rhythm term: attribution and evidence only (not the detection statistic)
    support_z: float = 2.0
    min_support_fraction: float = 0.75  # rejected units with weaker per-line support are demoted to abstentions
    abstain_report_z: float = 3.0     # report too-few-lines units only when some line matches this well
    p_floor: float = 1e-12
    seed: int = 7
    resonance: ResonanceConfig = field(default_factory=lambda: ResonanceConfig(series_cap=600))

    def __post_init__(self) -> None:
        if not 0 < self.q < 1:
            raise ValueError("q must be within (0, 1)")
        if self.n_drift < 1 or self.drift_tol < 0:
            raise ValueError("invalid drift grid")

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["resonance"] = self.resonance.as_dict()
        return d

    @property
    def config_hash(self) -> str:
        return sha256_hex(self.as_dict())

    @property
    def detector_version(self) -> str:
        return f"genome/{GENOME_DETECTOR_VERSION}+cfg:{self.config_hash[:12]}"


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def jitter_sd(g: Genome | TimerModel) -> float:
    t = g.timer if isinstance(g, Genome) else g
    if t.jitter_family == "uniform":
        s = t.jitter_scale / np.sqrt(3.0)
    elif t.jitter_family == "normal":
        s = t.jitter_scale
    else:
        q = t.jitter_quantiles
        s = (q[-1] - q[0]) / 3.29 if len(q) >= 2 else t.jitter_scale
    return float(s)


def templates(g: Genome) -> list[TimerModel]:
    """Timer templates of a genome: all check-in events, plus the resolver-lookup channel when distinct."""
    return [g.timer] + ([g.dns_timer] if g.dns_timer is not None else [])


def _kernel_moments(sig: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Mean/variance of exp(-y^2 / (2 sig^2)) for y ~ U(-1/2, 1/2) (units of one period)."""
    m = sig * np.sqrt(2 * np.pi) * erf(0.5 / (np.sqrt(2) * sig))
    e2 = sig * np.sqrt(np.pi) * erf(0.5 / sig)
    return m, np.maximum(e2 - m * m, 1e-12)


def _tail_p(null: np.ndarray, obs: float, floor: float) -> float | None:
    """Generalized-Pareto tail estimate of P(null >= obs) (Knijnenburg et al. 2009); None if unusable."""
    B = len(null)
    if B < 200:
        return None
    u = float(np.quantile(null, 0.9))
    exc = null[null > u] - u
    if len(exc) < 20 or not np.isfinite(obs) or obs <= u or np.ptp(exc) <= 0:
        return None
    if len(np.unique(np.round(exc, 6))) < 0.8 * len(exc):
        return None
    try:
        c, _, scale = sstats.genpareto.fit(exc, floc=0.0)
        sf = float(sstats.genpareto.sf(obs - u, c, loc=0.0, scale=scale))
    except Exception:  # pragma: no cover - numerical failure falls back to empirical
        return None
    if not np.isfinite(sf) or scale <= 0:
        return None
    if c < 0:  # bounded tail would claim p = 0; use the heavier exponential tail (conservative)
        sf = float(np.exp(-(obs - u) / float(np.mean(exc))))
    return max(floor, len(exc) / B * sf)


@dataclass
class _Rows:
    rows: np.ndarray            # series indices
    line: np.ndarray
    key: np.ndarray             # unit (component) key id
    count: np.ndarray


class MatchedFilter:
    """Per-series matched-filter scores of one genome (vectorized over all selected series)."""

    def __init__(self, genome: Genome, cfg: GenomeConfig, template: TimerModel | None = None):
        self.g = genome
        self.cfg = cfg
        self.t = template or genome.timer
        self.s = max(cfg.min_jitter, jitter_sd(self.t))
        n = cfg.n_drift
        self.deltas = np.linspace(-cfg.drift_tol, cfg.drift_tol, n) if n > 1 else np.zeros(1)
        self.periods = self.t.period_s * (1.0 + self.deltas)

    @staticmethod
    def score(genome: Genome, cfg: GenomeConfig, series: SeriesSet, rows: np.ndarray) -> np.ndarray:
        """Harmonic-vetoed matched-filter score, max over the genome's templates (rows x drift grid).

        A template at period P also fits a timer whose true period is m P: its pairs sit only at
        multiples of m. Such a series has no support at multiples of P that are not divisible by
        any m in ``harmonic_veto`` (mainly k = 1). The score is therefore capped by that subset's z
        plus a small margin: ``min(z_all, z_nondivisible + harmonic_margin)``. A genuine P timer,
        thinned or not, keeps pairs at k = 1 and is not penalized.
        """
        out = []
        for t in templates(genome):
            mf = MatchedFilter(genome, cfg, t)
            z = mf.timer_z(series, rows)
            if cfg.harmonic_veto:
                z_nd = mf.timer_z(series, rows, exclude_multiples_of=tuple(cfg.harmonic_veto))
                z = np.minimum(z, z_nd + cfg.harmonic_margin)
            out.append(z)
        return np.max(np.stack(out), axis=0)

    def timer_z(self, series: SeriesSet, rows: np.ndarray, exclude_multiples_of: tuple[int, ...] = ()) -> np.ndarray:
        cfg = self.cfg
        nd = len(self.periods)
        out = np.zeros((len(rows), nd), dtype=np.float64)
        if len(rows) == 0:
            return out
        cnt = series.offsets[rows + 1] - series.offsets[rows]
        new_off = np.concatenate([[0], np.cumsum(cnt)]).astype(np.int64)
        idx = np.repeat(series.offsets[rows] - new_off[:-1], cnt) + np.arange(new_off[-1])
        t = series.t[idx]
        sid = np.repeat(np.arange(len(rows)), cnt)
        C = np.zeros((len(rows), nd))
        V = np.zeros((len(rows), nd))
        M = cfg.max_multiple
        for r in range(1, cfg.neighbors + 1):
            if len(t) <= r:
                break
            d = t[r:] - t[:-r]
            same = sid[r:] == sid[:-r]
            dmax = (M + 0.5) * self.periods.max()
            ok = same & (d >= 0.5 * self.periods.min()) & (d < dmax)
            if not ok.any():
                continue
            dd = d[ok]
            ss = sid[:-r][ok]
            for j, P in enumerate(self.periods):
                x = dd / P
                k = np.rint(x)
                v = (k >= 1) & (k <= M)
                for mm in exclude_multiples_of:
                    v &= (k % mm) != 0
                if not v.any():
                    continue
                kk = k[v]
                sig = np.sqrt(kk * self.s ** 2 + (cfg.timing_res_s / P) ** 2)
                e = np.exp(-0.5 * ((x[v] - kk) / sig) ** 2)
                m, var = _kernel_moments(sig)
                # information surviving at the k-th multiple: first-harmonic characteristic function
                # of the accumulated jitter; uninformative multiples (wide jitter) get ~0 weight
                w = np.exp(-2.0 * np.pi ** 2 * sig ** 2)
                w = np.where(w >= 0.05, w, 0.0)
                C[:, j] += np.bincount(ss[v], weights=w * (e - m), minlength=len(rows))
                V[:, j] += np.bincount(ss[v], weights=w * w * var, minlength=len(rows))
        with np.errstate(divide="ignore", invalid="ignore"):
            out = np.where(V > 0, C / np.sqrt(np.where(V > 0, V, 1.0)), 0.0)
        return out

    def size_term(self, lb_sum_llr: np.ndarray, n_flows: np.ndarray, llr_sd: float) -> np.ndarray:
        with np.errstate(divide="ignore", invalid="ignore"):
            z = np.where(n_flows > 0, lb_sum_llr / np.sqrt(np.maximum(n_flows, 1)) / max(llr_sd, 1e-6), 0.0)
        return self.cfg.size_weight * np.clip(z, -3.0, 3.0)


RHO_GRID = (0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.7, 0.85, 1.0)


def attribution_loglik(g: Genome, gaps: np.ndarray, lbytes: np.ndarray, *, d_max: float, eps: float = 0.1,
                       res_s: float = 2.0, min_jitter: float = 0.01) -> tuple[float, float]:
    """Log-likelihood of consecutive-event gaps (and flow sizes) under genome ``g``.

    Gaps follow a *thinned* renewal timer: with keep probability rho (packet sampling, NAT
    loss), the gap between consecutive kept check-ins spans k periods with probability
    rho (1 - rho)^(k-1) and is normal around k P with variance k (s P)^2 + res^2; a fraction
    ``eps`` is background, uniform on (0, d_max). rho is profiled over a grid. Flow sizes
    follow the genome's log-normal per-beacon model mixed with 30 % background (tenant-wide
    sizes enter through the caller's centering). Returns (log-likelihood, fitted rho).
    """
    ll_best, rho_best = -np.inf, 1.0
    if len(gaps):
        for tm in templates(g):
            P = tm.period_s
            s = max(min_jitter, jitter_sd(tm))
            K = max(1, int(d_max // P))
            k = np.arange(1, K + 1, dtype=np.float64)
            sd = np.sqrt(k * (s * P) ** 2 + res_s ** 2)
            dens = sstats.norm.pdf(gaps[:, None], k[None, :] * P, sd[None, :])      # (n, K)
            for rho in RHO_GRID:
                pk = rho * (1 - rho) ** (k - 1)
                pk = pk / pk.sum()
                f = (1 - eps) * dens @ pk + eps / d_max
                ll = float(np.sum(np.log(np.maximum(f, 1e-300))))
                if ll > ll_best:
                    ll_best, rho_best = ll, rho
    else:
        ll_best = 0.0
    if len(lbytes) and g.burst.bytes_log_mean is not None and g.burst.bytes_log_sd is not None:
        gs = float(np.hypot(g.burst.bytes_log_sd, 0.1))
        f = 0.7 * sstats.norm.pdf(lbytes, g.burst.bytes_log_mean, gs) + 0.3 * sstats.norm.pdf(lbytes, 7.0, 2.5)
        ll_best += float(np.sum(np.log(np.maximum(f, 1e-300))))
    elif len(lbytes):
        ll_best += float(np.sum(np.log(np.maximum(sstats.norm.pdf(lbytes, 7.0, 2.5), 1e-300))))
    return ll_best, rho_best


@dataclass
class _Unit:
    unit_id: str
    comp: int
    members: list[int]
    info: Any


class GenomeDetector:
    """Batch genome matched-filter detector for one tenant."""

    def __init__(self, genomes: Sequence[Genome], keyring: KeyRing, cfg: GenomeConfig | None = None, *,
                 context: DestinationContext | None = None, history: DestinationHistory | None = None,
                 tenant_id: str = "default"):
        self.all_genomes = list(genomes)
        self.keyring = keyring
        self.cfg = cfg or GenomeConfig()
        self.context = context or DestinationContext(None)
        self.history = history
        self.tenant_id = tenant_id

    # ------------------------------------------------------------------ helpers
    def _report(self, status: str, reason: str | None, start: float, end: float, n_loaded: int,
                ignored: dict[str, int], **kw: Any) -> GenomeReport:
        return GenomeReport(tenant_id=self.tenant_id, detector_version=self.cfg.detector_version, status=status,
                            abstain_reason=reason, n_genomes_loaded=n_loaded, n_genomes_ignored=ignored,
                            n_tested=kw.pop("n_tested", 0), window_start=_utc(start), window_end=_utc(end), **kw)

    def _units(self, table: EventTable, now: float) -> tuple[list[_Unit], list[_Unit], np.ndarray]:
        rc = self.cfg.resonance
        stats = key_stats(table, rc)
        active = stats.active_lines
        nk = len(table.keys)
        cand = np.flatnonzero((stats.n_lines >= 2) & (stats.n_lines <= rc.max_popularity * active))
        comp_map = infrastructure_clusters(table, self.context, rc, cand)
        comp_of_key = np.arange(nk, dtype=np.int64)
        for k, c in comp_map.items():
            comp_of_key[k] = c
        members: dict[int, list[int]] = {}
        for k in cand:
            members.setdefault(int(comp_of_key[k]), []).append(int(k))
        # component-level aggregates
        incand = np.zeros(nk, dtype=bool)
        incand[cand] = True
        m = incand[table.key]
        df = pd.DataFrame({"c": comp_of_key[table.key[m]], "l": table.line[m], "t": table.t[m],
                           "b": table.nbytes[m].astype(np.float64),
                           "lg": (np.nan_to_num(table.dur_s[m], nan=0.0) >= rc.long_flow_s).astype(np.float64),
                           "f": table.kind[m] == KIND_FLOW})
        days = max(table.span_s / 86400.0, 1.0 / 24)
        nl = df.drop_duplicates(["c", "l"]).groupby("c").size()
        first = df.groupby("c")["t"].min()
        fl = df[df.f]
        per_line = fl.groupby(["c", "l"])["b"].sum(min_count=1) / days
        med = per_line.groupby(level=0).median()
        lf = fl.groupby("c")["lg"].mean()
        eligible: list[_Unit] = []
        small: list[_Unit] = []
        for c, mem in sorted(members.items()):
            mem = sorted(mem)
            uid = table.keys.items[mem[0]] if len(mem) == 1 else "cluster:" + table.keys.items[min(mem)]
            info = assess_unit(uid, mem, c, int(nl.get(c, 0)), active, float(med.get(c, np.nan)),
                               float(lf.get(c, np.nan)), float(first.get(c, np.nan)), now, table, self.context,
                               self.history, rc)
            u = _Unit(uid, c, mem, info)
            if info.eligible:
                eligible.append(u)
            elif info.reasons == ["too_few_lines"]:
                small.append(u)
        return eligible, small, comp_of_key

    # ------------------------------------------------------------------ main entry
    def detect(self, table: EventTable, *, now: datetime | None = None) -> GenomeReport:
        cfg = self.cfg
        rc = cfg.resonance
        start, end = table.window
        now_dt = now or _utc(end)
        genomes, ignored = load_genomes(self.all_genomes, self.keyring, now_dt)
        if not genomes:
            return self._report("abstain", "no_valid_genomes (unsigned, untrusted, tampered or expired)", start,
                                end, 0, ignored)
        if len(table) == 0:
            return self._report("abstain", "no_events", start, end, len(genomes), ignored)
        span = end - start
        if span < rc.min_span_s:
            return self._report("abstain", f"observation_window_too_short ({span / 3600:.1f} h)", start, end,
                                len(genomes), ignored)
        abstentions: list[GenomeAbstention] = []
        usable = []
        for g in genomes:
            if span < rc.min_cycles * g.timer.period_s:
                abstentions.append(GenomeAbstention(genome_id=g.genome_id, destinations=[],
                                                    reason="window_too_short_for_genome_period"))
            else:
                usable.append(g)
        if not usable:
            return self._report("abstain", "window_too_short_for_every_genome", start, end, len(genomes), ignored,
                                abstentions=abstentions)
        eligible, small, comp_of_key = self._units(table, now_dt.timestamp())
        if not eligible and not small:
            return self._report("ok", None, start, end, len(genomes), ignored, abstentions=abstentions)

        # ---------------------------------------------------------- series of involved lines
        S = prepare_series(table, rc, key_map=comp_of_key)
        unit_comps = {u.comp for u in eligible} | {u.comp for u in small}
        series_in_unit = np.isin(S.key, list(unit_comps))
        involved_lines = np.unique(S.line[series_in_unit])
        rows = np.flatnonzero(np.isin(S.line, involved_lines))
        R = _Rows(rows=rows, line=S.line[rows].astype(np.int64), key=S.key[rows].astype(np.int64),
                  count=S.counts[rows].astype(np.int64))
        row_of = {(int(l), int(k)): i for i, (l, k) in enumerate(zip(R.line, R.key))}

        # ---------------------------------------------------------- size statistics per row
        fmask = (table.kind == KIND_FLOW) & np.isfinite(table.nbytes) & (table.nbytes > 0)
        lb_all = np.log(table.nbytes[fmask].astype(np.float64))
        bg_mu = float(np.median(lb_all)) if len(lb_all) else 0.0
        bg_sd = float(max(1.4826 * np.median(np.abs(lb_all - bg_mu)), 0.3)) if len(lb_all) else 1.0
        fl_line = table.line[fmask].astype(np.int64)
        fl_key = comp_of_key[table.key[fmask]]
        fl_row = np.array([row_of.get((int(a), int(b)), -1) for a, b in zip(fl_line, fl_key)], dtype=np.int64) \
            if len(fl_line) < 3_000_000 else np.full(len(fl_line), -1)
        has_row = fl_row >= 0
        n_flows = np.bincount(fl_row[has_row], minlength=len(rows)).astype(np.float64)
        lb_by_row = pd.Series(lb_all[has_row]).groupby(fl_row[has_row]).apply(np.asarray).to_dict() \
            if has_row.any() else {}

        # around-the-clock persistence per row (RESONANCE's definition): check-in timers run 24/7, while
        # session-gated benign timers (IPTV heartbeats while watching, resolver TTL renewals during use) do not
        pers = (persistence(S, rows, start, end, rc.persistence_block_s).astype(np.float64)
                if cfg.persistence_weighting else np.ones(len(rows)))

        # ---------------------------------------------------------- per-genome scores
        scores: dict[str, np.ndarray] = {}
        size_terms: dict[str, np.ndarray] = {}
        timer_scores: dict[str, np.ndarray] = {}
        for g in usable:
            mf = MatchedFilter(g, cfg)
            zt = np.clip(MatchedFilter.score(g, cfg, S, rows), -cfg.z_cap, cfg.z_cap) * pers[:, None]
            if g.burst.bytes_log_mean is not None and g.burst.bytes_log_sd is not None and len(lb_all):
                gs = float(np.hypot(g.burst.bytes_log_sd, 0.1))
                llr = (sstats.norm.logpdf(lb_all, g.burst.bytes_log_mean, gs)
                       - sstats.norm.logpdf(lb_all, bg_mu, bg_sd))
                llr = np.clip(llr, -4.0, 4.0)
                llr_sd = float(np.std(llr)) or 1.0
                llr_c = llr - float(np.mean(llr))    # centered on the tenant-wide flow population
                sums = np.bincount(fl_row[has_row], weights=llr_c[has_row], minlength=len(rows))
                sz = mf.size_term(sums, n_flows, llr_sd)
            else:
                sz = np.zeros(len(rows))
            scores[g.genome_id] = zt
            size_terms[g.genome_id] = sz
            timer_scores[g.genome_id] = zt

        # ---------------------------------------------------------- null pools
        by_line: dict[int, np.ndarray] = {}
        order = np.lexsort((R.count, R.line))
        lines_sorted = R.line[order]
        bounds = np.flatnonzero(np.r_[True, lines_sorted[1:] != lines_sorted[:-1], True])
        for a, b in zip(bounds[:-1], bounds[1:]):
            by_line[int(lines_sorted[a])] = order[a:b]
        glob = np.argsort(R.count, kind="stable")
        glob_counts = R.count[glob]

        def alternatives(i: int, comp: int, rng: np.random.Generator) -> np.ndarray:
            """Null alternatives for member row ``i``: the same line's series to other destinations
            with a comparable event count (the matched-filter z is count-normalized, so a factor-4
            band is used), topped up with other lines' series of similar count when the line has
            fewer than ``min_alternatives``."""
            c = int(R.count[i])
            lo, hi = (c, c) if c <= 2 else (max(3, c // 4), 4 * c)
            cand = by_line.get(int(R.line[i]), np.zeros(0, dtype=np.int64))
            cand = cand[(R.key[cand] != comp) & (R.count[cand] >= lo) & (R.count[cand] <= hi)]
            if len(cand) >= cfg.min_alternatives:
                return cand
            a, b = np.searchsorted(glob_counts, lo, "left"), np.searchsorted(glob_counts, hi, "right")
            pool = glob[a:b]
            pool = pool[(R.key[pool] != comp) & (R.line[pool] != R.line[i])]
            need = 64
            if len(pool) > need:
                pool = rng.choice(pool, need, replace=False)
            return np.concatenate([cand, pool])

        # ---------------------------------------------------------- tests
        def run_tests(excluded_comps: set[int]) -> list[dict[str, Any]]:
            excl = np.isin(R.key, list(excluded_comps)) if excluded_comps else np.zeros(len(R.key), dtype=bool)
            tests: list[dict[str, Any]] = []
            for u in eligible:
                mem_rows = np.array([row_of[(int(l), u.comp)] for l in involved_lines
                                     if (int(l), u.comp) in row_of], dtype=np.int64)
                if len(mem_rows) < rc.min_lines:
                    continue
                rng = np.random.default_rng([cfg.seed, int(hashlib.sha256(u.unit_id.encode()).hexdigest()[:12], 16)])
                alts = [a[~excl[a]] for a in (alternatives(int(i), u.comp, rng) for i in mem_rows)]
                valid = np.array([len(a) > 0 for a in alts])
                for g in usable:
                    tests.append(_perm_test(u, g, scores[g.genome_id], mem_rows, alts, valid))
            return tests

        def _perm_test(u, g, G, mem_rows, alts, valid) -> dict[str, Any]:
            obs_vec = G[mem_rows].sum(axis=0)
            T = float(obs_vec.max())
            null: list[np.ndarray] = []
            drawn, exceed = 0, 0
            grng = np.random.default_rng([cfg.seed, int(hashlib.sha256((u.unit_id + g.genome_id).encode())
                                                       .hexdigest()[:12], 16)])
            while drawn < cfg.max_permutations:
                if drawn >= cfg.n_permutations and exceed >= 2:
                    break
                nb = min(200 if drawn < cfg.n_permutations else 5000, cfg.max_permutations - drawn)
                idx = np.empty((nb, len(mem_rows)), dtype=np.int64)
                for j, a in enumerate(alts):
                    # lines without any alternative keep their own row (conservative: no signal removed)
                    idx[:, j] = grng.choice(a, nb) if len(a) else mem_rows[j]
                tn = G[idx].sum(axis=1).max(axis=1)
                null.append(tn)
                drawn += nb
                exceed += int(np.sum(tn >= T))
                if exceed >= cfg.sequential_h and drawn >= cfg.min_permutations:
                    break
            nl = np.concatenate(null)
            # exact lower bound: a permutation p-value cannot go below 1 / (distinct permutations + 1)
            log_combos = float(np.sum([np.log(max(1, len(a))) for a in alts]))
            p_min = float(np.exp(-np.logaddexp(log_combos, 0.0)))
            p_emp = max((1 + exceed) / (drawn + 1), p_min)
            p = p_emp
            method = "empirical" if exceed >= cfg.sequential_h else "sequential"
            if exceed < cfg.sequential_h:
                pt = _tail_p(nl, T, cfg.p_floor)
                if pt is not None:
                    p, method = max(min(p_emp, pt), p_min), "gpd_tail"
            sd = float(np.std(nl)) or 1.0
            return {"unit": u, "genome": g, "rows": mem_rows, "T": T, "p": float(p), "method": method,
                    "drawn": drawn, "z": (T - float(np.mean(nl))) / sd, "delta_idx": int(np.argmax(obs_vec)),
                    "null_mean": float(np.mean(nl)), "null_sd": sd, "no_alt_lines": int((~valid).sum()),
                    "weight": float(u.info.weight)}

        # pass 1; pass 2 removes the series of pass-1-rejected units from every null pool, because a
        # concurrent campaign at a harmonic period (e.g. 600 s vs 300 s) otherwise inflates other tests' nulls
        tests = run_tests(set())
        purified: list[int] = []
        if tests:
            _, rej1 = weighted_bh(np.array([t["p"] for t in tests]), np.array([t["weight"] for t in tests]), cfg.q)
            # only units that would become campaigns (pass the per-line support gate) are purified;
            # weakly supported rejections (benign shared structure) must stay in the null
            rej_tests: dict[int, list[dict[str, Any]]] = {}
            for t, r in zip(tests, rej1):
                if r:
                    rej_tests.setdefault(t["unit"].comp, []).append(t)
            for comp_id, ts_ in rej_tests.items():
                rows_ = ts_[0]["rows"]
                gmax = np.max(np.stack([scores[t["genome"].genome_id][rows_].max(axis=1) for t in ts_]), axis=0)
                if np.sum(gmax >= cfg.support_z) >= cfg.min_support_fraction * len(rows_):
                    purified.append(comp_id)
            purified.sort()
            if purified:
                tests = run_tests(set(purified))
        # abstentions: too few lines but a plausible match
        for u in small:
            mem_rows = [row_of[(int(l), u.comp)] for l in involved_lines if (int(l), u.comp) in row_of]
            for g in usable:
                if mem_rows and float(timer_scores[g.genome_id][mem_rows].max()) >= cfg.abstain_report_z:
                    abstentions.append(GenomeAbstention(
                        genome_id=g.genome_id, destinations=[table.keys.items[k] for k in u.members],
                        reason=f"insufficient_lines ({len(mem_rows)} < {rc.min_lines}): genome-like timer seen, "
                               f"no population decision made"))
        if not tests:
            return self._report("ok", None, start, end, len(genomes), ignored, abstentions=abstentions)
        p = np.array([t["p"] for t in tests])
        w = np.array([t["weight"] for t in tests])
        qv, rej = weighted_bh(p, w, cfg.q)
        for t, qq, rr in zip(tests, qv, rej):
            t["q"], t["rejected"] = float(qq), bool(rr)

        # ---------------------------------------------------------- campaigns (one per unit)
        campaigns: list[GenomeCampaign] = []
        hyps: list[DeviceModelHypothesis] = []
        by_unit: dict[str, list[dict[str, Any]]] = {}
        for t in tests:
            by_unit.setdefault(t["unit"].unit_id, []).append(t)
        for _uid, ts in sorted(by_unit.items()):
            rejected = [t for t in ts if t["rejected"]]
            if not rejected:
                continue
            mem_rows = rejected[0]["rows"]
            d_max = (cfg.max_multiple + 0.5) * max(tm.period_s for t in ts for tm in templates(t["genome"]))
            gaps_l: list[np.ndarray] = []
            lbs_l: list[np.ndarray] = []
            for i in mem_rows:
                tt = S.times(int(R.rows[i]))
                dd = np.diff(tt)
                gaps_l.append(dd[(dd > 0) & (dd < d_max)])
                lbs_l.append(lb_by_row.get(int(i), np.zeros(0)))
            gaps = np.concatenate(gaps_l) if gaps_l else np.zeros(0)
            lbs = np.concatenate(lbs_l) if lbs_l else np.zeros(0)
            lls = {}
            rhos = {}
            for t in ts:
                ll, rho = attribution_loglik(t["genome"], gaps, lbs, d_max=d_max, res_s=cfg.timing_res_s,
                                             min_jitter=cfg.min_jitter)
                lls[t["genome"].genome_id], rhos[t["genome"].genome_id] = ll, rho
            # tempered by member lines (pairs within a line are dependent): average per-line log-LR
            ll_bg = float(len(gaps) * np.log(1.0 / d_max))
            if len(lbs):
                ll_bg += float(np.sum(sstats.norm.logpdf(lbs, 7.0, 2.5)))
            vals = np.array([lls[t["genome"].genome_id] for t in ts]) / max(1, len(mem_rows))
            gain = float(vals.max() - ll_bg / max(1, len(mem_rows)))
            post = np.exp(vals - vals.max())
            post /= post.sum()
            fam_share: dict[str, float] = {}
            for t, pv in zip(ts, post):
                fam = t["genome"].family or "unlabeled"
                fam_share[fam] = fam_share.get(fam, 0.0) + float(pv)
            best_ll = ts[int(np.argmax(vals))]
            best_test = min(rejected, key=lambda t: t["q"])
            best = best_ll if best_ll["rejected"] else {**best_ll, "q": best_test["q"], "p": best_test["p"]}
            u = best["unit"]
            g = best["genome"]
            G = scores[g.genome_id][:, best["delta_idx"]]
            mem_rows = best["rows"]
            lines = [table.lines.items[int(R.line[i])] for i in mem_rows]
            # a line supports the campaign when its own series matches any genome that rejected the unit
            g_rej = np.max(np.stack([scores[t["genome"].genome_id][mem_rows].max(axis=1) for t in rejected]), axis=0)
            supp = [table.lines.items[int(R.line[i])] for i, gv in zip(mem_rows, g_rej) if gv >= cfg.support_z]
            if len(supp) < cfg.min_support_fraction * len(lines):
                abstentions.append(GenomeAbstention(
                    genome_id=g.genome_id, destinations=[table.keys.items[k] for k in u.members],
                    reason=(f"weak_per_line_support ({len(supp)}/{len(lines)} lines individually match; population "
                            f"q={best['q']:.1e}): shared structure without a per-device timer is typical of benign "
                            f"services or resolver caching; not reported as a campaign")))
                continue
            top = max(fam_share.values())
            conf = float(round(top * (1.0 - best["q"]), 4))
            dests = [table.keys.items[k] for k in u.members]
            campaigns.append(GenomeCampaign(
                genome_id=g.genome_id, family=g.family, destinations=dests, member_lines=sorted(lines),
                n_lines=len(lines), statistic=round(best["T"], 4), p_value=best["p"], q_value=best["q"],
                q_target=cfg.q, n_permutations=best["drawn"],
                attribution={k: round(v, 4) for k, v in sorted(fam_share.items())}, attribution_confidence=conf,
                evidence={"p_method": best["method"], "null_mean": best["null_mean"], "null_sd": best["null_sd"],
                          "standardized": round(best["z"], 3),
                          "period_s": round(g.timer.period_s * (1 + MatchedFilter(g, cfg).deltas[best["delta_idx"]]),
                                            3),
                          "genome_period_s": g.timer.period_s, "genome_confidence": g.confidence,
                          "supporting_lines": sorted(supp),
                          "genome_gain_per_line": round(gain, 3),
                          "size_match": round(float(np.mean(size_terms[g.genome_id][mem_rows])), 3), "lines_without_null_alternative": best["no_alt_lines"],
                          "population": {"weight": u.info.weight, "weight_parts": u.info.weight_parts,
                                         "popularity": u.info.popularity, "age_days": u.info.age_days,
                                         "shared_domain": u.info.shared_domain,
                                         "topology_unknown": u.info.topology_unknown, "asns": u.info.asns},
                          "per_genome": [{"genome_id": t["genome"].genome_id, "family": t["genome"].family,
                                          "p": t["p"], "q": t["q"], "standardized": round(t["z"], 3),
                                          "rejected": t["rejected"],
                                          "loglik_per_line": round(lls[t["genome"].genome_id] / max(1, len(mem_rows)), 3),
                                          "fitted_keep_rate": rhos[t["genome"].genome_id]}
                                         for t in sorted(ts, key=lambda t: -lls[t["genome"].genome_id])],
                          "detected_by": sorted(t["genome"].genome_id for t in rejected),
                          "null_purified_units": len(purified),
                          "attribution_method": "tempered likelihood ratio (thinned renewal timer + size model)",
                          "config_hash": cfg.config_hash},
                explanation=(f"{len(lines)} lines contact {', '.join(dests[:3])} with timing matching genome "
                             f"{g.genome_id} ({g.family or 'unlabeled'}, period {g.timer.period_s:.0f}s); "
                             f"permutation p={best['p']:.2e}, BH q={best['q']:.2e} at target {cfg.q}. "
                             f"Attribution share {top:.2f}. Shadow-mode finding; requires analyst review.")))
            # device-model hypotheses: ranked from behavioral match only
            fam_genomes = [t for t in ts if t["genome"].family == g.family]
            for i, ln in zip(mem_rows, lines):
                if G[i] < cfg.support_z:
                    continue
                ranked: dict[str, dict[str, Any]] = {}
                for t in fam_genomes:
                    sc = float(scores[t["genome"].genome_id][i].max())
                    for bm in t["genome"].provenance.lab_box_models:
                        cur = ranked.get(bm)
                        if cur is None or sc > cur["score"]:
                            ranked[bm] = {"box_model": bm, "score": round(sc, 3),
                                          "evidence": [{"genome_id": t["genome"].genome_id,
                                                        "line_match_z": round(sc, 3),
                                                        "n_events": int(R.count[i]),
                                                        "capture_ids": t["genome"].provenance.capture_ids}]}
                hyps.append(DeviceModelHypothesis(line=ln, ranked=sorted(ranked.values(),
                                                                          key=lambda r: (-r["score"], r["box_model"]))))
        return self._report("ok", None, start, end, len(genomes), ignored, n_tested=len(tests), campaigns=campaigns,
                            device_hypotheses=hyps, abstentions=abstentions)
