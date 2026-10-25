"""RESONANCE building blocks: timer recovery, event tables, population model, weighted BH."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from aegis.lab.topology import generate_topology
from aegis.resonance import ResonanceConfig, build_event_table, lomb_scargle_power, weighted_bh
from aegis.resonance.events import KIND_FLOW, continuation_mask, prepare_series
from aegis.resonance.periodicity import best_periods, make_grid, periodogram, persistence, phase_rayleigh
from aegis.resonance.population import (
    DestinationContext,
    DestinationHistory,
    assess_unit,
    infrastructure_clusters,
    key_stats,
)
from aegis.resonance.sim import packet_sampling_keep

T0 = 1_790_000_000.0
DAY = 86_400.0


def _beacons(rng, period, jitter, n_lines, keep_p, ip="203.0.113.9", span=DAY):
    rows = []
    for ln in range(n_lines):
        t = T0 + rng.uniform(0, period) + np.cumsum(period * (1 + rng.uniform(-jitter, jitter, int(span / period) + 5)))
        t = t[(t < T0 + span) & (rng.random(len(t)) < keep_p)]
        rows += [(x, f"L{ln}", ip) for x in t]
    return rows


def test_difference_fold_recovers_jittered_thinned_timer_when_pooled():
    rng = np.random.default_rng(1)
    rows = _beacons(rng, 600.0, 0.2, 40, keep_p=0.08)            # ~1:100 sampling of ~8-packet beacons
    for ln in range(40):                                          # unrelated Poisson traffic on the same lines
        rows += [(x, f"L{ln}", "198.18.64.5") for x in np.sort(rng.uniform(T0, T0 + DAY, 12))]
    tb = build_event_table(pd.DataFrame(rows, columns=["t", "line", "dst_ip"]), None, start=T0, end=T0 + DAY)
    cfg = ResonanceConfig()
    S = prepare_series(tb, cfg)
    grid = make_grid(cfg)
    pg = periodogram(S, grid, cfg)
    j = int(np.argmin(np.abs(grid.periods - 600)))
    beacon = S.key == tb.keys.get("ip:203.0.113.9")
    noise = ~beacon
    # per line the signal is weak; pooled over 40 lines it is unmistakable
    assert pg.Z[beacon, j].sum() > 6 * np.sqrt(beacon.sum())
    assert abs(pg.Z[noise, j].sum()) < 3.5 * np.sqrt(noise.sum())
    pooled = pg.Z[beacon].sum(axis=0)
    usable = grid.usable(DAY, cfg.min_cycles)
    best = grid.periods[np.argmax(np.where(usable, pooled, -np.inf))]
    assert best == pytest.approx(600, rel=0.06) or best == pytest.approx(1200, rel=0.06)


def test_unsampled_timer_per_pair_estimate():
    rng = np.random.default_rng(2)
    rows = _beacons(rng, 900.0, 0.1, 1, keep_p=1.0)
    tb = build_event_table(pd.DataFrame(rows, columns=["t", "line", "dst_ip"]), None, start=T0, end=T0 + DAY)
    cfg = ResonanceConfig()
    S = prepare_series(tb, cfg)
    grid = make_grid(cfg)
    per, z, r = best_periods(periodogram(S, grid, cfg), grid, grid.usable(DAY, cfg.min_cycles))
    assert per[0] == pytest.approx(900, rel=0.05)
    assert z[0] > 10 and 0.3 < r[0] <= 1.0
    # absolute-phase coherence decays with jitter accumulation; difference folding does not
    assert phase_rayleigh(S.times(0), float(per[0]))[0] < r[0]
    ls = lomb_scargle_power(S.times(0), np.array([900.0, 1234.0]))
    assert ls.shape == (2,) and np.all(ls >= 0)


def test_continuation_records_and_bursts_are_collapsed():
    # a long download exported every 120 s plus a burst of 5 flows within 2 s
    t = np.array([0.0, 120.0, 240.0, 360.0, 1000.0, 1000.5, 1001.0, 1001.5, 1002.0]) + T0
    rows = pd.DataFrame({"t": t, "line": "L", "dst_ip": "203.0.113.1",
                         "dur_s": [120, 120, 120, 50, 1, 1, 1, 1, 1], "bytes": 1000.0})
    tb = build_event_table(rows, None)
    m = continuation_mask(tb.t, np.zeros(len(tb), dtype=np.int64), tb.kind, tb.dur_s, 30.0)
    assert m.tolist() == [False, True, True, True, False, False, False, False, False]
    S = prepare_series(tb, ResonanceConfig())
    assert S.n_series == 1 and S.counts[0] == 2 and S.raw_counts[0] == 9


def test_dns_join_assigns_domain_keys_and_ip_fallback():
    flows = pd.DataFrame({"t": [T0 + 10, T0 + 20, T0 + 5000], "line": ["A", "B", "A"],
                          "dst_ip": ["192.0.2.7", "192.0.2.7", "192.0.2.7"]})
    dns = pd.DataFrame({"t": [T0 + 9], "line": ["A"], "qname": ["C2.Example."], "answer_ip": ["192.0.2.7"]})
    tb = build_event_table(flows, dns, dns_join_ttl_s=3600)
    keys = {(tb.lines.items[l], tb.keys.items[k], int(kind)) for l, k, kind in zip(tb.line, tb.key, tb.kind)}
    assert ("A", "d:c2.example", KIND_FLOW) in keys          # joined (and normalized)
    assert ("B", "ip:192.0.2.7", KIND_FLOW) in keys          # other line never resolved it
    assert ("A", "ip:192.0.2.7", KIND_FLOW) in keys          # answer older than the TTL window
    assert tb.key_ips[tb.keys.get("d:c2.example")] == {"192.0.2.7"}


def test_persistence_separates_round_the_clock_from_session_timers():
    rng = np.random.default_rng(3)
    allday = np.sort(rng.uniform(T0, T0 + DAY, 30))
    evening = np.sort(rng.uniform(T0 + 19 * 3600, T0 + 22 * 3600, 30))
    rows = [(x, "L", "203.0.113.1") for x in allday] + [(x, "L", "203.0.113.2") for x in evening]
    tb = build_event_table(pd.DataFrame(rows, columns=["t", "line", "dst_ip"]), None, start=T0, end=T0 + DAY)
    S = prepare_series(tb, ResonanceConfig())
    p = persistence(S, np.arange(S.n_series), T0, T0 + DAY, 3600)
    by_key = {tb.keys.items[int(k)]: v for k, v in zip(S.key, p)}
    assert by_key["ip:203.0.113.1"] > 0.8 and by_key["ip:203.0.113.2"] < 0.3


def test_packet_sampling_transform():
    rng = np.random.default_rng(0)
    pk = np.full(100_000, 5)
    assert packet_sampling_keep(pk, 1, rng).all()
    frac = packet_sampling_keep(pk, 100, rng).mean()
    assert frac == pytest.approx(1 - 0.99 ** 5, abs=0.005)
    assert packet_sampling_keep(np.full(1000, 10_000), 1000, rng).mean() > 0.99


def test_weighted_bh_known_values_and_weights():
    p = np.array([0.001, 0.008, 0.039, 0.041, 0.042, 0.06, 0.074, 0.205])
    q, rej = weighted_bh(p, np.ones(8), 0.05)
    assert rej.tolist() == [True, True, False, False, False, False, False, False]
    assert q[0] == pytest.approx(0.008) and q[1] == pytest.approx(0.032)
    # down-weighting can only make rejection harder
    _, rej2 = weighted_bh(p, np.array([0.1] + [1.0] * 7), 0.05)
    assert rej2.sum() <= rej.sum()
    assert weighted_bh(np.zeros(0), np.zeros(0), 0.1)[1].size == 0


def test_population_clusters_shared_hosting_and_gates():
    topo = generate_topology(7)
    ctx = DestinationContext(topo)
    bb = topo.malicious["badbox2_emu"]
    cdn_dom = bb.cohosted_domains[0]
    cdn_ip = topo.resolve(cdn_dom)[0]
    flows, dns = [], []
    for ln in range(12):
        for name, ip in ((bb.c2_domains[0], bb.c2_ips[0]), (bb.c2_domains[1], bb.c2_ips[1]), (cdn_dom, cdn_ip)):
            dns.append((T0 + ln, f"L{ln}", name, ip))
            flows.append((T0 + ln + 1, f"L{ln}", ip))
        flows.append((T0 + 50 + ln, f"L{ln}", cdn_ip))           # IP-keyed shared CDN edge
    for ln in range(100):
        flows.append((T0 + 7 * ln, f"Q{ln}", "198.18.64.77"))    # a popular destination
    tb = build_event_table(pd.DataFrame(flows, columns=["t", "line", "dst_ip"]),
                           pd.DataFrame(dns, columns=["t", "line", "qname", "answer_ip"]), start=T0, end=T0 + DAY)
    cfg = ResonanceConfig()
    st = key_stats(tb, cfg)
    cand = np.flatnonzero(st.n_lines >= 2)
    comp = infrastructure_clusters(tb, ctx, cfg, cand)
    k1, k2 = tb.keys.get("d:" + bb.c2_domains[0]), tb.keys.get("d:" + bb.c2_domains[1])
    kc = tb.keys.get("d:" + cdn_dom)
    # dedicated C2 IPs share a /24 -> one cluster; the CDN-hosted name never joins it
    assert comp[k1] == comp[k2] and comp[kc] != comp[k1]
    u_ip = assess_unit("x", [tb.keys.get("ip:" + cdn_ip)], 0, 12, st.active_lines, np.nan, np.nan, T0, T0 + DAY,
                       tb, ctx, None, cfg)
    assert not u_ip.eligible and "ip_on_shared_hosting" in u_ip.reasons
    u_dom = assess_unit("y", [kc], 0, 12, st.active_lines, np.nan, np.nan, T0, T0 + DAY, tb, ctx, None, cfg)
    assert u_dom.eligible and u_dom.shared_domain and u_dom.weight_parts["hosting"] == cfg.shared_domain_weight
    kp = tb.keys.get("ip:198.18.64.77")
    u_pop = assess_unit("z", [kp], 0, int(st.n_lines[kp]), st.active_lines, np.nan, np.nan, T0, T0 + DAY, tb, ctx,
                        None, cfg)
    assert "popular" in u_pop.reasons
    assert all(0 < u.weight <= 1 for u in (u_dom,))


def test_history_establishment_surge_and_allowlist():
    h = DestinationHistory(coverage_start=T0 - 30 * DAY)
    h.observe(["d:old.example"], [10], [T0 - 30 * DAY], [T0])
    assert h.age_days("d:old.example", T0) == pytest.approx(30)
    assert h.age_days("d:new.example", T0) == 0.0
    assert DestinationHistory().age_days("d:x", T0) is None       # no coverage -> unknown, not "new"
    rows = [(T0 + i, f"L{i}", "192.0.2.10") for i in range(40)]
    dns = [(T0 + i - 1, f"L{i}", "old.example", "192.0.2.10") for i in range(40)]
    tb = build_event_table(pd.DataFrame(rows, columns=["t", "line", "dst_ip"]),
                           pd.DataFrame(dns, columns=["t", "line", "qname", "answer_ip"]), start=T0, end=T0 + DAY)
    cfg = ResonanceConfig()
    k = tb.keys.get("d:old.example")
    ctx = DestinationContext(None)
    stable = assess_unit("o", [k], k, 12, 1000, np.nan, np.nan, T0, T0, tb, ctx, h, cfg)
    assert stable.established and not stable.eligible
    surge = assess_unit("o", [k], k, 40, 1000, np.nan, np.nan, T0, T0, tb, ctx, h, cfg)
    assert surge.surging and surge.eligible                         # synchronized growth re-enters testing
    allow = assess_unit("o", [k], k, 40, 1000, np.nan, np.nan, T0, T0, tb, ctx, h,
                        cfg.with_(allowlist=("example",)))
    assert "operator_allowlist" in allow.reasons and not allow.eligible
    assert DestinationHistory.from_dict(h.to_dict()).to_dict() == h.to_dict()


def test_config_validation_and_hash():
    cfg = ResonanceConfig()
    assert cfg.config_hash == ResonanceConfig().config_hash
    assert cfg.with_(q=0.05).config_hash != cfg.config_hash
    with pytest.raises(ValueError):
        ResonanceConfig(q=0.01, q_malicious=0.05)
    with pytest.raises(ValueError):
        ResonanceConfig(min_lines=1)
