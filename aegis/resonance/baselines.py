"""Comparison baselines for the RESONANCE benchmark.

* :func:`per_line_periodicity` - RITA-style beacon scoring per (line, destination): the
  same difference-fold timer recovery, a nominal look-elsewhere-corrected p-value per pair
  and Benjamini-Hochberg across all pairs. No population model, no cross-line pooling.
* :func:`static_blocklist` - flag lines contacting any blocklisted domain or IP.
"""
from __future__ import annotations

import numpy as np

from aegis.resonance.config import ResonanceConfig
from aegis.resonance.detector import weighted_bh
from aegis.resonance.events import EventTable, prepare_series
from aegis.resonance.periodicity import best_periods, make_grid, nominal_p, periodogram


def per_line_periodicity(table: EventTable, cfg: ResonanceConfig | None = None, *, q: float = 0.01,
                         min_events: int = 6) -> dict[str, set[str]]:
    """{line: {keys flagged as beaconing}} from per-pair periodicity + BH at ``q``."""
    cfg = cfg or ResonanceConfig()
    S = prepare_series(table, cfg)
    rows = np.flatnonzero(S.counts >= min_events)
    out: dict[str, set[str]] = {}
    if len(rows) == 0:
        return out
    grid = make_grid(cfg)
    pg = periodogram(S, grid, cfg, rows=rows)
    usable = grid.usable(table.span_s, cfg.min_cycles)
    _, z, _ = best_periods(pg, grid, usable, refine=False)
    p = np.where(np.isfinite(z), nominal_p(np.nan_to_num(z, nan=-10.0), grid.n_eff), 1.0)
    _, rej = weighted_bh(p, np.ones(len(p)), q)
    for i in np.flatnonzero(rej):
        s = rows[i]
        out.setdefault(table.lines.items[int(S.line[s])], set()).add(table.keys.items[int(S.key[s])])
    return out


def static_blocklist(table: EventTable, blocklist: set[str]) -> dict[str, set[str]]:
    """{line: {matched keys}}; a domain key also matches when it resolved to a blocklisted IP."""
    bl = {b.lower() for b in blocklist}
    hit = np.zeros(len(table.keys), dtype=bool)
    for k, name in enumerate(table.keys.items):
        if name in bl:
            hit[k] = True
        elif any(("ip:" + ip) in bl for ip in table.key_ips.get(k, ())):
            hit[k] = True
    out: dict[str, set[str]] = {}
    m = hit[table.key]
    for ln, k in set(zip(table.line[m].tolist(), table.key[m].tolist())):
        out.setdefault(table.lines.items[ln], set()).add(table.keys.items[k])
    return out
