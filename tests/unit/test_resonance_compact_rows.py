"""RESONANCE keeps per-period matrices for informative series only, without changing any value."""
from __future__ import annotations

import numpy as np

from aegis.resonance import DestinationContext, Resonance, ResonanceConfig
from aegis.resonance.detector import _Rows
from aegis.resonance.events import prepare_series
from aegis.resonance.periodicity import periodogram, persistence
from aegis.resonance.sim import ScenarioSpec, generate_scenario, standard_campaigns


def test_compact_rows_equal_the_dense_periodograms():
    sc = generate_scenario(ScenarioSpec(n_lines=300, days=1.0, campaigns=standard_campaigns(0.03), seed=4),
                           sampling=100)
    cfg = ResonanceConfig()
    tb = sc.table(cfg)
    det = Resonance(cfg, context=DestinationContext(sc.topology), tenant_id="t")
    captured: list[_Rows] = []
    build = det._build_rows

    def spy(*a, **k):
        r = build(*a, **k)
        captured.append(r)
        return r

    det._build_rows = spy  # type: ignore[method-assign]
    rep = det.detect(tb)
    assert rep.status == "ok" and captured
    rows = captured[0]
    # the compact matrices hold only informative rows plus the shared zero row
    assert len(rows.G) < len(rows.line) and not rows.G[0].any() and not rows.has[0].any()
    assert (rows.gidx[rows.count < 2] == 0).all()
    assert len(np.unique(rows.gidx[rows.gidx > 0])) == len(rows.G) - 1
    # dense reference for the single-key part, computed the pre-compaction way (all series)
    S = rows.parts[0]
    start, end = tb.window
    usable = det.grid.usable(end - start, cfg.min_cycles)
    pg = periodogram(S, det.grid, cfg)
    pe = persistence(S, np.arange(S.n_series), start, end, cfg.persistence_block_s)
    dense = np.clip(pg.Z, -cfg.z_cap, cfg.z_cap) * pe[:, None]
    dense[:, ~usable] = 0.0
    single = rows.src_part == 0
    np.testing.assert_allclose(rows.G[rows.gidx[single]], dense[rows.src_series[single]], rtol=1e-6, atol=1e-6)
    assert np.array_equal(rows.has[rows.gidx[single]], pg.has_pairs[rows.src_series[single]])
    # event times are still reachable per row
    r = int(np.flatnonzero(rows.count >= 2)[0])
    assert len(rows.times(r)) == rows.count[r]
    assert prepare_series(tb, cfg).n_series >= S.n_series
