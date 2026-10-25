"""Bounded window state: caps, coordinated sampling, retention of IOC / recurring keys, eviction."""
from __future__ import annotations

import math
import random
from collections import Counter
from datetime import timedelta

import numpy as np
import pytest

from aegis.sentinel.features import ContactSummary, StateLimits, WindowStore, key_hash
from aegis.sentinel.rules import load_bundle
from test_sentinel_helpers import T0, dns_event, flow_event
from test_sentinel_rules import ind, make_bundle, ring, signer  # noqa: F401  (pytest fixtures)

LIMITS = StateLimits(flow_events_per_bin=64, dns_events_per_bin=32, answers_per_bin=32)


def _run(store, events, flush_at):
    out = []
    for e in events:
        out.extend(store.update(e))
    out.extend(store.flush(flush_at))
    return out


def _ip_with_hash(lo: float, hi: float, prefix: str = "203.0.113.") -> str:
    for i in range(1, 255):
        ip = f"{prefix}{i}"
        if lo <= key_hash(ip) < hi:
            return ip
    raise AssertionError("no address in range")


def _busy(hours: int, per_hour: int, rnd: random.Random, entity: str = "p_dev1"):
    """A busy line: many distinct destinations, a heavy talker and ms-resolution timestamps."""
    evs = []
    for h in range(hours):
        for _ in range(per_hour):
            ms = rnd.randrange(3_600_000)
            dst = "198.18.0.1" if rnd.random() < 0.2 else f"198.19.{rnd.randrange(64)}.{rnd.randrange(250)}"
            evs.append(flow_event(T0 + timedelta(hours=h, milliseconds=ms), entity=entity, dst=dst,
                                  port=rnd.choice([443, 80, 8080])))
    return evs


def _exact(evs, start, end):
    """Reference values computed from the raw events of one window."""
    sel = [e for e in evs if start <= e.observed_at < end]
    dst = Counter(e.flow.dst_ip for e in sel)
    n = sum(dst.values())
    starts = np.sort([e.observed_at.timestamp() for e in sel])
    gaps = np.diff(starts)
    gaps = gaps[gaps > 0]
    mu, sd = gaps.mean(), gaps.std()
    ent = -sum(c / n * math.log2(c / n) for c in dst.values())
    return {"unique_dst_ip": len(dst), "dst_entropy": ent, "max_dst_share": max(dst.values()) / n,
            "burstiness": (sd - mu) / (sd + mu), "interval_p50_log": math.log10(np.quantile(gaps, 0.5)),
            "unique_dst_port": len({e.flow.dst_port for e in sel}), "n": n}


def test_state_per_hop_is_bounded_and_estimates_stay_close():
    rnd = random.Random(11)
    evs = sorted(_busy(4, 1500, rnd), key=lambda e: e.observed_at)
    store = WindowStore("24h", limits=LIMITS)
    out = _run(store, evs, T0 + timedelta(hours=4))
    assert store.stats.sampled_bins >= 4
    t = store._tenants["t1"]
    ent = t.entities["p_dev1"]
    assert len(ent.f) <= LIMITS.flow_events_per_bin * len(ent.slots)       # 4 x 1500 flows -> at most 4 x 64
    fv = out[-1]
    ref = _exact(evs, T0, T0 + timedelta(hours=4))
    v = fv.values
    assert fv.event_count == ref["n"] and v["flow_rate_h"] == pytest.approx(ref["n"] / v["coverage_h"], rel=1e-4)
    assert v["unique_dst_ip"] == pytest.approx(ref["unique_dst_ip"], rel=0.25)
    assert v["unique_dst_port"] == ref["unique_dst_port"]
    assert v["dst_entropy"] == pytest.approx(ref["dst_entropy"], rel=0.05)
    assert v["max_dst_share"] == pytest.approx(ref["max_dst_share"], rel=1e-9)               # heavy talker exact
    assert v["burstiness"] == pytest.approx(ref["burstiness"], abs=1e-6)                     # exact moments
    assert v["interval_p50_log"] == pytest.approx(ref["interval_p50_log"], abs=0.02)        # 1/32-decade histogram
    cs = store.contacts_for(fv)
    assert cs is not None and cs.sampled


def test_below_the_caps_features_equal_raw_event_computation():
    rnd = random.Random(5)
    evs = sorted(_busy(3, 40, rnd), key=lambda e: e.observed_at)
    store = WindowStore("24h", limits=LIMITS)
    fv = _run(store, evs, T0 + timedelta(hours=3))[-1]
    assert store.stats.sampled_bins == 0
    ref = _exact(evs, T0, T0 + timedelta(hours=3))
    for k in ("unique_dst_ip", "unique_dst_port"):
        assert fv.values[k] == ref[k]
    for k in ("dst_entropy", "max_dst_share", "burstiness", "interval_p50_log"):
        assert fv.values[k] == pytest.approx(ref[k], rel=1e-9)
    cs = store.contacts_for(fv)
    raw = ContactSummary.from_events(evs, tenant_id="t1", entity_pseudonym="p_dev1", window_start=T0 - timedelta(hours=21),
                                     window_end=T0 + timedelta(hours=3))
    assert cs is not None and not cs.sampled
    assert cs.dst_ips == raw.dst_ips
    assert all(cs.ip_times[k] == pytest.approx(raw.ip_times[k]) for k in raw.ip_times)


def test_periodic_channel_on_a_busy_line_survives_sampling():
    rnd = random.Random(3)
    c2 = _ip_with_hash(0.95, 1.0)                     # would never make a bottom-k sample on its own
    evs = _busy(24, 600, rnd)
    evs += [flow_event(T0 + timedelta(seconds=300 * i + 7), dst=c2, bytes_out=300, bytes_in=200, duration_ms=200)
            for i in range(24 * 12)]
    evs.sort(key=lambda e: e.observed_at)
    # 600 flows/hour overflow a 128-event hop; the beacon (12/hour) fits the per-key cap of 128 // 8
    store = WindowStore("24h", limits=StateLimits(flow_events_per_bin=128))
    fv = _run(store, evs, T0 + timedelta(hours=24))[-1]
    assert store.stats.sampled_bins >= 20
    cs = store.contacts_for(fv)
    assert cs is not None and cs.sampled and cs.dst_ips[c2] >= 24 * 12 - 24     # tracked after first recurrence
    assert fv.values["beacon_robust_cv"] == pytest.approx(0.0, abs=1e-6)
    assert 10 ** fv.values["beacon_period_log"] == pytest.approx(300.0, rel=1e-6)


def test_ioc_destinations_are_never_sampled_away(signer, ring):  # noqa: F811
    rnd = random.Random(8)
    bad = _ip_with_hash(0.97, 1.0, prefix="192.0.2.")
    b = load_bundle(make_bundle(signer, [ind(bad, typ="ip")]), ring)
    evs = _busy(2, 1500, rnd) + [flow_event(T0 + timedelta(hours=1, minutes=30), dst=bad)]
    evs.sort(key=lambda e: e.observed_at)
    store = WindowStore("24h", limits=LIMITS, ioc_bundle=b)
    fv = _run(store, evs, T0 + timedelta(hours=2))[-1]
    assert store.stats.sampled_bins >= 2
    assert fv.values["ioc_contacts"] == 1.0
    cs = store.contacts_for(fv)
    assert cs is not None and cs.dst_ips[bad] == 1


def test_dns_sampling_keeps_counts_exact_and_estimates_names():
    rnd = random.Random(2)
    evs = [dns_event(T0 + timedelta(seconds=rnd.uniform(0, 3599)), f"{rnd.randrange(10**9):x}.dga.example",
                     rcode="NXDOMAIN") for _ in range(2000)]
    evs += [dns_event(T0 + timedelta(seconds=rnd.uniform(0, 3599)), "www.news.example", answers=["198.18.0.5"])
            for _ in range(500)]
    evs.sort(key=lambda e: e.observed_at)
    store = WindowStore("15m", hop=timedelta(minutes=15), limits=LIMITS)
    out = _run(store, evs, T0 + timedelta(hours=1))
    for fv in out:
        end = fv.window_end
        sel = [e for e in evs if end - timedelta(minutes=15) <= e.observed_at < end]
        nx = [e for e in sel if e.dns.rcode == "NXDOMAIN"]
        assert fv.values["nxdomain_rate"] == pytest.approx(len(nx) / len(sel))      # exact
        assert fv.values["nx_unique"] == pytest.approx(len({e.dns.qname for e in nx}), rel=0.35)
        assert fv.values["nx_name_entropy"] > 2.0
        assert len(store._tenants["t1"].entities["p_dev1"].d) <= LIMITS.dns_events_per_bin * 2


def test_vocabulary_ids_are_freed_when_no_hop_references_them():
    store = WindowStore("24h")
    evs = [flow_event(T0 + timedelta(hours=h, minutes=m), dst=f"198.18.{h % 250}.{m}")
           for h in range(72) for m in range(0, 60, 6)]
    _run(store, evs, T0 + timedelta(hours=72))
    t = store._tenants["t1"]
    live = len(t.ips) - len(t.ips.free)
    assert live <= 26 * 10                    # one day of destinations (+ the closed hop), not three
    assert len(t.ips.index) == live and len(t.channels.index) == len(t.channels) - len(t.channels.free)


def test_evidence_ids_spread_over_the_window_and_non_uuid_ids_round_trip():
    store = WindowStore("24h", max_source_event_ids=48)
    evs = [flow_event(T0 + timedelta(hours=h, minutes=m)) for h in range(30) for m in range(0, 60, 5)]
    out = _run(store, evs, T0 + timedelta(hours=30))
    last = out[-1]
    assert len(last.source_event_ids) == 48 and last.event_count == 24 * 12
    by_id = {e.event_id: e for e in evs}
    hours = {by_id[i].observed_at for i in last.source_event_ids}
    assert min(hours) >= T0 + timedelta(hours=6) and len({h.replace(minute=0) for h in hours}) == 24
    assert all(i.startswith("ev-") for i in last.source_event_ids)      # test ids are not UUIDs


def test_state_limits_validation():
    with pytest.raises(ValueError):
        StateLimits(flow_events_per_bin=4)
    assert StateLimits().bytes_per_bin() == 12 * 512 + 8 * 256 + 8 * 256
