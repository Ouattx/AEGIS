from __future__ import annotations

import math
from datetime import timedelta

import pytest

from aegis.contracts.models import FeatureVector
from aegis.sentinel.features import (
    FEATURE_NAMES,
    ContactSummary,
    WindowStore,
    label_entropy,
)
from test_sentinel_helpers import T0, dns_event, flow_event


def run(store: WindowStore, events, flush_at=None) -> list[FeatureVector]:
    out = []
    for e in events:
        out.extend(store.update(e))
    if flush_at is not None:
        out.extend(store.flush(flush_at))
    return out


def beacon_events(entity="p_dev1", dst="203.0.113.10", period=300, hours=24, start=T0, **kw):
    t = start
    evs = []
    while t < start + timedelta(hours=hours):
        evs.append(flow_event(t, entity=entity, dst=dst, bytes_out=400, bytes_in=600, duration_ms=500, **kw))
        t += timedelta(seconds=period)
    return evs


def test_tumbling_window_emits_on_close_with_all_features():
    store = WindowStore("15m")
    evs = [flow_event(T0 + timedelta(minutes=m)) for m in range(0, 15)]
    assert run(store, evs) == []                       # window still open
    out = store.update(flow_event(T0 + timedelta(minutes=20)))
    assert len(out) == 1
    fv = out[0]
    assert fv.window == "15m" and fv.window_end == T0 + timedelta(minutes=15)
    assert fv.event_count == 15
    assert set(fv.values) == set(FEATURE_NAMES) == set(fv.missing)
    assert fv.values["flow_rate_h"] == pytest.approx(15 / 0.25)
    assert len(fv.source_event_ids) == 15


def test_hopping_24h_window_reevaluates_every_hour():
    store = WindowStore("24h")
    evs = beacon_events(hours=30)
    out = run(store, evs, flush_at=T0 + timedelta(hours=30))
    ends = [fv.window_end for fv in out]
    assert ends == [T0 + timedelta(hours=h) for h in range(1, 31)]
    # coverage grows until the window is full, then stays at 24h
    assert out[0].values["coverage_h"] == pytest.approx(1.0)
    assert out[-1].values["coverage_h"] == pytest.approx(24.0)
    assert out[-1].event_count == 24 * 12


def test_missing_values_are_none_and_flagged_not_zero():
    store = WindowStore("24h")
    out = run(store, beacon_events(hours=3), flush_at=T0 + timedelta(hours=3))
    fv = out[-1]
    # flow-only tenant: every DNS feature is missing (unknown), not zero
    for k in ("dns_rate_h", "nxdomain_rate", "nx_unique", "qname_unique", "rare_qname_frac"):
        assert fv.values[k] is None and fv.missing[k] is True
    # population of 1 is too small for prevalence
    assert fv.values["beacon_dst_prevalence"] is None and fv.missing["beacon_dst_prevalence"]
    assert fv.values["rare_dst_frac"] is None
    assert fv.values["ioc_contacts"] is None          # no bundle configured
    assert fv.missing["flow_rate_h"] is False


def test_dns_rate_known_zero_but_ratio_missing_when_device_made_no_query():
    store = WindowStore("15m")
    evs = [dns_event(T0 + timedelta(minutes=1), "a.example", entity="p_other")]
    evs += [flow_event(T0 + timedelta(minutes=m)) for m in range(10)]
    out = run(store, evs, flush_at=T0 + timedelta(minutes=15))
    fv = next(f for f in out if f.entity_pseudonym == "p_dev1")
    assert fv.values["dns_rate_h"] == 0.0 and fv.missing["dns_rate_h"] is False
    assert fv.values["nxdomain_rate"] is None and fv.missing["nxdomain_rate"] is True


def test_missing_bytes_do_not_become_zero():
    store = WindowStore("15m")
    evs = [flow_event(T0 + timedelta(minutes=m), bytes_out=None, bytes_in=None) for m in range(10)]
    fv = run(store, evs, flush_at=T0 + timedelta(minutes=15))[0]
    for k in ("bytes_out_rate_log", "bytes_in_rate_log", "out_ratio", "small_flow_frac"):
        assert fv.values[k] is None and fv.missing[k]
    assert fv.values["flow_rate_h"] is not None


def test_periodic_channel_detected_with_period_and_cv():
    store = WindowStore("24h")
    fv = run(store, beacon_events(period=300, hours=24), flush_at=T0 + timedelta(hours=24))[-1]
    assert fv.values["beacon_robust_cv"] == pytest.approx(0.0, abs=1e-9)
    assert 10 ** fv.values["beacon_period_log"] == pytest.approx(300.0)
    assert fv.values["beacon_events"] == 24 * 12
    assert fv.values["burstiness"] == pytest.approx(-1.0)


def test_long_flow_continuations_are_not_connections():
    store = WindowStore("24h")
    evs = [flow_event(T0 + timedelta(minutes=m), duration_ms=60_000, bytes_in=500_000) for m in range(120)]
    fv = run(store, evs, flush_at=T0 + timedelta(hours=2))[-1]
    assert fv.values["long_flow_frac"] == 1.0
    assert fv.values["beacon_robust_cv"] is None          # a stream is not a beacon
    assert fv.values["interval_p50_log"] is None


def test_prevalence_and_rare_destinations_with_population():
    store = WindowStore("24h", min_population=20)
    evs = []
    for i in range(30):
        evs += beacon_events(entity=f"p_{i:02d}", dst="198.18.0.10", period=600, hours=2)   # popular heartbeat
    evs += beacon_events(entity="p_00", dst="203.0.113.66", period=300, hours=2)             # rare beacon
    evs.sort(key=lambda e: e.observed_at)
    out = run(store, evs, flush_at=T0 + timedelta(hours=2))
    last = {fv.entity_pseudonym: fv for fv in out if fv.window_end == T0 + timedelta(hours=2)}
    infected, clean = last["p_00"], last["p_01"]
    assert infected.values["beacon_dst_prevalence"] == pytest.approx(1 / 30)
    assert clean.values["beacon_dst_prevalence"] == pytest.approx(1.0)
    assert infected.values["rare_dst_frac"] == pytest.approx(0.5)
    assert clean.values["rare_dst_frac"] == 0.0


def test_dns_features_nxdomain_and_entropy():
    store = WindowStore("15m")
    evs = [dns_event(T0 + timedelta(seconds=i), f"x{i}q7zk2m9v.test", rcode="NXDOMAIN") for i in range(30)]
    evs += [dns_event(T0 + timedelta(seconds=40 + i), "www.news.example", answers=["198.18.0.5"]) for i in range(10)]
    fv = run(store, evs, flush_at=T0 + timedelta(minutes=15))[0]
    assert fv.values["nxdomain_rate"] == pytest.approx(0.75)
    assert fv.values["nx_unique"] == 30
    assert fv.values["qname_unique"] == 31
    assert fv.values["nx_name_entropy"] > 2.5
    assert fv.values["flow_rate_h"] is None               # DNS-only tenant: flows unknown


def test_baseline_deviation_and_recent_metrics():
    store = WindowStore("24h")
    evs = []
    for h in range(12):
        evs += [flow_event(T0 + timedelta(hours=h, minutes=m)) for m in range(0, 60, 10)]
    evs += [flow_event(T0 + timedelta(hours=12, seconds=s)) for s in range(0, 3600, 10)]   # sudden burst
    fv = run(store, evs, flush_at=T0 + timedelta(hours=13))[-1]
    assert fv.values["recent_flows_log"] == pytest.approx(math.log10(361))
    assert fv.values["baseline_dev_flows"] > 5


def test_late_event_within_window_counts_and_too_late_is_dropped():
    store = WindowStore("24h")
    run(store, [flow_event(T0 + timedelta(minutes=5)), flow_event(T0 + timedelta(hours=3))])
    assert store.stats.windows_emitted >= 2
    store.update(flow_event(T0 + timedelta(minutes=30)))      # late, but still inside future windows
    assert store.stats.late_events == 1
    run(store, [flow_event(T0 + timedelta(hours=40))])
    store.update(flow_event(T0 + timedelta(hours=1)))         # older than any open window
    assert store.stats.dropped_late == 1


def test_allowed_lateness_delays_emission():
    store = WindowStore("15m", allowed_lateness=timedelta(minutes=2))
    store.update(flow_event(T0 + timedelta(minutes=1)))
    assert store.update(flow_event(T0 + timedelta(minutes=16))) == []      # watermark 14m
    assert len(store.update(flow_event(T0 + timedelta(minutes=17, seconds=1)))) == 1


def test_future_timestamp_rejected_and_does_not_advance_watermark():
    store = WindowStore("15m")
    store.update(flow_event(T0))
    bad = flow_event(T0 + timedelta(days=5), ingest_lag=timedelta(days=-5))
    assert store.update(bad) == []
    assert store.stats.rejected == 1
    assert store.update(flow_event(T0 + timedelta(minutes=3))) == []


def test_gap_skips_empty_windows():
    store = WindowStore("24h")
    run(store, [flow_event(T0)])
    out = run(store, [flow_event(T0 + timedelta(days=10))])
    # the first event's 24 windows are emitted, then nothing for the empty days
    assert len(out) == 24
    out2 = store.flush(T0 + timedelta(days=10, hours=2))
    assert [f.window_end for f in out2] == [T0 + timedelta(days=10, hours=1), T0 + timedelta(days=10, hours=2)]


def test_tenants_are_isolated():
    store = WindowStore("15m")
    evs = [flow_event(T0 + timedelta(minutes=1), tenant="a"), flow_event(T0 + timedelta(minutes=1), tenant="b",
                                                                          entity="p_dev1")]
    out = run(store, evs, flush_at=T0 + timedelta(minutes=15))
    assert sorted(f.tenant_id for f in out) == ["a", "b"]
    assert all(f.event_count == 1 for f in out)
    assert store.flush(T0 + timedelta(minutes=30), tenant_id="a") == []


def test_contacts_for_last_window_and_from_events():
    store = WindowStore("15m")
    evs = [dns_event(T0 + timedelta(minutes=1), "C2.Bad.Example.", answers=["203.0.113.5"]),
           flow_event(T0 + timedelta(minutes=2), dst="203.0.113.5")]
    fv = run(store, evs, flush_at=T0 + timedelta(minutes=15))[0]
    cs = store.contacts_for(fv)
    assert cs is not None
    assert cs.qnames["c2.bad.example"] == 1 and cs.dst_ips["203.0.113.5"] == 1
    assert cs.resolved_ips("c2.bad.example.") == {"203.0.113.5"}
    assert cs.authorization_ids == {"auth-1"}
    rebuilt = ContactSummary.from_events(evs, tenant_id="t1", entity_pseudonym="p_dev1",
                                         window_start=T0, window_end=T0 + timedelta(minutes=15))
    assert rebuilt.dst_ips == cs.dst_ips and rebuilt.qnames == cs.qnames
    stale = fv.model_copy(update={"window_end": T0})
    assert store.contacts_for(stale) is None


def test_event_without_entity_is_rejected():
    store = WindowStore("15m")
    ev = flow_event(T0).model_copy(update={"entity_pseudonym": None})
    assert store.update(ev) == [] and store.stats.rejected == 1


def test_device_class_defaults_to_unknown():
    store = WindowStore("15m")
    fv = run(store, [flow_event(T0, device_class=None)], flush_at=T0 + timedelta(minutes=15))[0]
    assert fv.device_class == "unknown"


def test_source_event_ids_capped():
    store = WindowStore("15m", max_source_event_ids=5)
    evs = [flow_event(T0 + timedelta(seconds=i)) for i in range(20)]
    fv = run(store, evs, flush_at=T0 + timedelta(minutes=15))[0]
    assert len(fv.source_event_ids) == 5 and fv.event_count == 20


@pytest.mark.parametrize("window,hop", [("bogus", None), ("24h", timedelta(minutes=7)), ("5m", timedelta(0))])
def test_invalid_configuration(window, hop):
    with pytest.raises(ValueError):
        WindowStore(window, hop)  # type: ignore[arg-type]


def test_label_entropy():
    assert label_entropy("aaaa.example") == 0.0
    assert label_entropy("abcd.example") == pytest.approx(2.0)
    assert label_entropy(".example") == 0.0


def test_periodic_dns_names_and_their_prevalence():
    store = WindowStore("24h", min_population=20)
    evs = []
    for i in range(25):
        for k in range(12):   # popular name looked up every 10 minutes by everyone
            evs.append(dns_event(T0 + timedelta(minutes=10 * k, seconds=i), "push.os.example", entity=f"p_{i:02d}"))
    for k in range(12):       # one device checks in with a rare name every 5 minutes
        evs.append(dns_event(T0 + timedelta(minutes=5 * k, seconds=30), "upd.rare.example", entity="p_00"))
    evs.sort(key=lambda e: e.observed_at)
    out = run(store, evs, flush_at=T0 + timedelta(hours=2))
    last = {fv.entity_pseudonym: fv for fv in out if fv.window_end == T0 + timedelta(hours=2)}
    assert last["p_00"].values["periodic_qnames"] == 2
    assert last["p_00"].values["periodic_qname_prevalence"] == pytest.approx(1 / 25)
    assert last["p_01"].values["periodic_qnames"] == 1
    assert last["p_01"].values["periodic_qname_prevalence"] == pytest.approx(1.0)
