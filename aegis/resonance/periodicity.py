"""Line-level timer recovery robust to jitter, packet sampling and NAT mixing.

Why not a plain periodogram of absolute event times? A malware timer is usually a
*renewal* process: ``t[k+1] = t[k] + P * (1 + u_k)`` with jitter ``u_k``. Its absolute
phase random-walks (after n beacons the phase spread is ~ sigma*sqrt(n) periods), so the
classical Lomb-Scargle / Rayleigh power of absolute times washes out over a day for
any realistic jitter. Packet sampling makes it worse: it deletes most events.

RESONANCE therefore folds *pair differences* instead of absolute times. For a
candidate period P it takes every pair of events on the same series whose separation
d lies within ``[0.5 P, (M + 0.5) P]`` and measures the circular concentration of
``d / P`` (a Rayleigh statistic on differences, i.e. the first Fourier harmonic of the
series' autocorrelogram folded at P):

    C(P)  = sum_pairs w_k(d/P) * cos(2 pi d / P)
    Z(P)  = C(P) / sqrt(sum_pairs w_k(d/P)^2 / 2)     (~ N(0, 1) for unstructured pairs)
    R(P)  = C(P) / sum_pairs w_k(d/P)                (signed concentration in [-1, 1])

Unlike absolute-time folding, the phase of a true timer is *known* here: pairs sit at
d ~ kP, i.e. phase 0. Only the cosine component is used. This is not just a factor-2
noise reduction: a smooth trend in the density of differences (human sessions make
short separations more frequent than long ones on every line alike) leaks into the
*sine* component with the same sign on every line and would otherwise add up across
lines as spurious "resonance". The signed Z is zero-mean for unstructured series of
any length (no pairs => 0), so per-line contributions can be summed across lines.

* jitter: a pair k periods apart has phase spread ~ sigma*sqrt(k); weights ``w_k``
  decrease with k and k <= M, so concentration is measured where it survives;
* sampling: deleting events (thinning) only changes *which* multiples appear;
  surviving pairs are still concentrated near integer multiples of P;
* NAT mixing: pairs within one device's process are concentrated, pairs across
  processes are uniform noise that lowers but does not destroy Z;
* the window spans an integer number of cycles, so a locally uniform distribution
  of differences yields uniform phases.

Computation is fully vectorized: pair differences are histogrammed into log-spaced
bins per series, and Z for all series and periods is one dense matrix product with a
precomputed (bins x periods) kernel.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from scipy.signal import lombscargle

from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import SeriesSet


@dataclass(frozen=True)
class PeriodGrid:
    periods: np.ndarray           # candidate periods (s), ascending
    centers: np.ndarray           # difference-bin centers (s)
    log_dmin: float
    log_ratio: float
    kernel: np.ndarray            # float32 (n_bins, 4 * n_periods): [C | S | W1 | W2]
    n_eff: float                  # effective number of independent periods (for nominal p-values)

    @property
    def n_periods(self) -> int:
        return len(self.periods)

    @property
    def n_bins(self) -> int:
        return len(self.centers)

    @property
    def dmin(self) -> float:
        return float(np.exp(self.log_dmin))

    @property
    def dmax(self) -> float:
        return float(np.exp(self.log_dmin + self.log_ratio * self.n_bins))

    def usable(self, span_s: float, min_cycles: float) -> np.ndarray:
        """Periods identifiable in a window of ``span_s`` seconds."""
        return self.periods * min_cycles <= span_s


@lru_cache(maxsize=16)
def _grid(pmin: float, pmax: float, step: float, max_multiple: int, weights: tuple[float, ...],
          bin_ratio: float) -> PeriodGrid:
    n_p = int(np.floor(np.log(pmax / pmin) / step)) + 1
    periods = pmin * np.exp(step * np.arange(n_p))
    dmin = 0.5 * pmin
    dmax = (max_multiple + 0.5) * pmax
    log_ratio = float(np.log1p(bin_ratio))
    n_b = int(np.ceil(np.log(dmax / dmin) / log_ratio))
    edges = dmin * np.exp(log_ratio * np.arange(n_b + 1))
    centers = np.sqrt(edges[:-1] * edges[1:])
    x = centers[:, None] / periods[None, :]
    k = np.rint(x)
    w = np.zeros_like(x)
    wt = np.asarray(weights[:max_multiple], dtype=np.float64)
    ok = (k >= 1) & (k <= max_multiple) & (x >= 0.5) & (x < max_multiple + 0.5)
    w[ok] = wt[(k[ok] - 1).astype(int)]
    ang = 2 * np.pi * x
    kern = np.concatenate([w * np.cos(ang), w * np.sin(ang), w, w * w], axis=1).astype(np.float32)
    n_eff = max(1.0, np.log(pmax / pmin) / 0.1)
    return PeriodGrid(periods=periods, centers=centers, log_dmin=float(np.log(dmin)), log_ratio=log_ratio,
                      kernel=np.ascontiguousarray(kern), n_eff=float(n_eff))


def make_grid(cfg: ResonanceConfig) -> PeriodGrid:
    return _grid(cfg.period_min_s, cfg.period_max_s, cfg.period_step, cfg.max_multiple,
                 tuple(cfg.multiple_weights), cfg.bin_ratio)


@dataclass
class Periodogram:
    """Per-series difference periodograms."""
    Z: np.ndarray                 # float32 (n_series, n_periods) signed z; 0 where no pairs fall in the window
    R: np.ndarray                 # float32 signed concentration in [-1, 1]
    has_pairs: np.ndarray         # bool (n_series, n_periods)

    @property
    def n_series(self) -> int:
        return self.Z.shape[0]


def _block_ranges(offsets: np.ndarray, max_series: int, max_events: int):
    n_s = len(offsets) - 1
    s0 = 0
    while s0 < n_s:
        s1 = min(n_s, s0 + max_series)
        # shrink so the block holds at most max_events events (but at least one series)
        while s1 > s0 + 1 and offsets[s1] - offsets[s0] > max_events:
            s1 = s0 + max(1, (s1 - s0) // 2)
        yield s0, s1
        s0 = s1


def periodogram(series: SeriesSet, grid: PeriodGrid, cfg: ResonanceConfig, *,
                rows: np.ndarray | None = None, max_series_block: int = 8192,
                max_events_block: int = 400_000) -> Periodogram:
    """Difference periodograms for ``rows`` (series indices; all series when None)."""
    n_p = grid.n_periods
    if rows is None:
        rows = np.arange(series.n_series)
    rows = np.asarray(rows, dtype=np.int64)
    Z = np.zeros((len(rows), n_p), dtype=np.float32)
    R = np.zeros((len(rows), n_p), dtype=np.float32)
    HP = np.zeros((len(rows), n_p), dtype=bool)
    if len(rows) == 0:
        return Periodogram(Z, R, HP)
    # gather the selected series into a compact contiguous layout
    cnt = series.offsets[rows + 1] - series.offsets[rows]
    new_off = np.concatenate([[0], np.cumsum(cnt)]).astype(np.int64)
    idx = np.repeat(series.offsets[rows] - new_off[:-1], cnt) + np.arange(new_off[-1])
    t_all = series.t[idx]
    local_sid = np.repeat(np.arange(len(rows)), cnt)
    n_b = grid.n_bins
    dmin, dmax = grid.dmin, grid.dmax
    K = cfg.neighbors
    for s0, s1 in _block_ranges(new_off, max_series_block, max_events_block):
        e0, e1 = new_off[s0], new_off[s1]
        t = t_all[e0:e1]
        sid = local_sid[e0:e1] - s0
        ns = s1 - s0
        flat_parts = []
        for r in range(1, K + 1):
            if len(t) <= r:
                break
            d = t[r:] - t[:-r]
            ok = (sid[r:] == sid[:-r]) & (d >= dmin) & (d < dmax)
            if not ok.any():
                continue
            b = ((np.log(d[ok]) - grid.log_dmin) / grid.log_ratio).astype(np.int64)
            np.clip(b, 0, n_b - 1, out=b)
            flat_parts.append(sid[:-r][ok] * n_b + b)
        if not flat_parts:
            continue
        flat = np.concatenate(flat_parts)
        H = np.bincount(flat, minlength=ns * n_b).astype(np.float32).reshape(ns, n_b)
        out = H @ grid.kernel
        C, W1, W2 = out[:, :n_p], out[:, 2 * n_p:3 * n_p], out[:, 3 * n_p:]
        has = W2 > 1e-6
        with np.errstate(divide="ignore", invalid="ignore"):
            Z[s0:s1] = np.where(has, C / np.sqrt(np.where(has, W2, 1.0) / 2.0), 0.0)
            R[s0:s1] = np.where(has, C / np.where(has, W1, 1.0), 0.0)
        HP[s0:s1] = has
    np.clip(R, -1.0, 1.0, out=R)
    return Periodogram(Z, R, HP)


@dataclass(frozen=True)
class PairPeriodicity:
    """Per (line, destination) timer estimate."""
    line: str
    key: str
    n_events: int                 # after coalescing / thinning
    raw_events: int
    period_s: float | None        # None = not estimable (too few pairs / span too short)
    strength: float | None        # signed concentration R at the period (1 = perfect timer)
    z: float | None               # cosine-fold z statistic at the period
    p_nominal: float | None       # n_eff * (1 - Phi(z)): nominal, NOT calibrated (bursty traffic violates it)
    confidence: float | None      # 1 - p_nominal
    phase_coherence: float | None  # absolute-phase Rayleigh R at the period (phase-locked timers only)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def best_periods(pg: Periodogram, grid: PeriodGrid, usable: np.ndarray, refine: bool = True
                 ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """(period, Z, R) at each series' strongest usable period; NaN period where none."""
    Zu = np.where(usable[None, :] & pg.has_pairs, pg.Z, -np.inf)
    j = np.argmax(Zu, axis=1)
    zbest = Zu[np.arange(len(j)), j]
    per = grid.periods[j].astype(np.float64)
    if refine and grid.n_periods >= 3:
        # parabolic refinement on log-period
        jm = np.clip(j, 1, grid.n_periods - 2)
        y0 = Zu[np.arange(len(j)), jm - 1]
        y1 = Zu[np.arange(len(j)), jm]
        y2 = Zu[np.arange(len(j)), jm + 1]
        with np.errstate(divide="ignore", invalid="ignore"):
            den = y0 - 2 * y1 + y2
            off = np.where((den < 0) & (jm == j) & np.isfinite(y0) & np.isfinite(y2), 0.5 * (y0 - y2) / den, 0.0)
        off = np.clip(np.nan_to_num(off), -0.5, 0.5)
        step = np.log(grid.periods[1] / grid.periods[0])
        per = grid.periods[jm] * np.exp(off * step)
        per = np.where(jm == j, per, grid.periods[j])
    rbest = pg.R[np.arange(len(j)), j]
    none = ~np.isfinite(zbest)
    per = np.where(none, np.nan, per)
    return per, np.where(none, np.nan, zbest), np.where(none, np.nan, rbest)


def phase_rayleigh(times: np.ndarray, period: float) -> tuple[float, float]:
    """Absolute-phase Rayleigh (R, Z=n R^2) of ``times`` folded at ``period``.

    Equivalent to the (unnormalized) Lomb-Scargle power of the event impulse train at
    that period; high only for phase-locked (low-jitter or synchronized) timers.
    """
    n = len(times)
    if n == 0 or not np.isfinite(period) or period <= 0:
        return 0.0, 0.0
    ph = 2 * np.pi * (times / period)
    c, s = np.cos(ph).sum(), np.sin(ph).sum()
    r = float(np.hypot(c, s) / n)
    return r, n * r * r


def lomb_scargle_power(times: np.ndarray, periods: np.ndarray, *, bin_s: float | None = None) -> np.ndarray:
    """Normalized Lomb-Scargle power of a binned event-count series (scipy).

    Provided for analysts and for comparison with classical beacon detectors; RESONANCE's
    decision statistic uses difference folding (see module docstring) because absolute-time
    periodograms lose renewal-process timers to accumulated jitter.
    """
    times = np.asarray(times, dtype=np.float64)
    periods = np.asarray(periods, dtype=np.float64)
    if len(times) < 3:
        return np.zeros(len(periods))
    bin_s = bin_s or max(1.0, float(periods.min()) / 8.0)
    t0 = times.min()
    nb = int(np.ceil((times.max() - t0) / bin_s)) + 1
    counts = np.bincount(((times - t0) / bin_s).astype(np.int64), minlength=nb).astype(np.float64)
    x = t0 + bin_s * (np.arange(nb) + 0.5)
    y = counts - counts.mean()
    if not np.any(y):
        return np.zeros(len(periods))
    return lombscargle(x, y, 2 * np.pi / periods, normalize=True)


def persistence(series: SeriesSet, rows: np.ndarray, start: float, end: float, block_s: float) -> np.ndarray:
    """Around-the-clock persistence per series in [0, 1].

    Observed number of distinct ``block_s`` blocks containing events divided by the number
    expected if the same events were spread uniformly over the window. Timers running 24/7
    (thinned by sampling or not) score ~1; timers gated by human sessions (IPTV heartbeats
    while watching, console presence while gaming) score well below 1.
    """
    rows = np.asarray(rows, dtype=np.int64)
    out = np.ones(len(rows), dtype=np.float32)
    nblk = max(1, int(np.ceil((end - start) / block_s)))
    if nblk <= 1 or len(rows) == 0:
        return out
    cnt = series.offsets[rows + 1] - series.offsets[rows]
    idx = np.repeat(series.offsets[rows], cnt) + (np.arange(cnt.sum()) - np.repeat(np.cumsum(cnt) - cnt, cnt))
    loc = np.repeat(np.arange(len(rows)), cnt)
    blk = np.clip(((series.t[idx] - start) // block_s).astype(np.int64), 0, nblk - 1)
    uniq = np.unique(loc * nblk + blk)
    obs = np.bincount(uniq // nblk, minlength=len(rows)).astype(np.float64)
    expct = nblk * (1.0 - (1.0 - 1.0 / nblk) ** cnt.astype(np.float64))
    with np.errstate(divide="ignore", invalid="ignore"):
        out[:] = np.where(expct > 0, np.clip(obs / expct, 0.0, 1.0), 1.0)
    return out


def nominal_p(z: np.ndarray | float, n_eff: float) -> np.ndarray | float:
    """Look-elsewhere-corrected one-sided nominal p-value (uncalibrated)."""
    from scipy.special import ndtr
    return np.minimum(1.0, n_eff * (1.0 - ndtr(z)))
