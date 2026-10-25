"""EGRESS rule boundaries on tiny hand-written flow fixtures.

Each test builds the handful of flow records needed to sit just above or just below one
pre-registered threshold. Nothing here generates traffic at scale: the population-level
evaluation runs on the existing lab corpus (``test_egress_lab.py``).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.contracts.models import FlowObservation, ObservationEvent, SourceKind, Vantage
from aegis.egress import (
    LABEL_AMPLIFICATION,
    LABEL_DDOS,
    LABEL_PROXY,
    LABEL_REFLECTOR,
    LABEL_SPAM,
    LABEL_STUFFING,
    EgressConfig,
    EgressDetector,
    SpoofSignal,
)
from aegis.egress.detector import _continuations, _Flow

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
TENANT = "isp-a"
VICTIM = "192.0.2.10"
CFG = EgressConfig(min_flow_records=1)


def ev(line: str, t: float, dst: str, port: int | None, proto: str = "udp", *, bo: int | None = 1000,
       bi: int | None = 1000, po: int | None = 10, pi: int | None = 10, dur: int | None = 1000,
       tenant: str = TENANT, device_class: str = "android_tv") -> ObservationEvent:
    at = T0 + timedelta(seconds=t)
    return ObservationEvent(
        tenant_id=tenant, observed_at=at, ingested_at=at, source_id="nf", source_kind=SourceKind.NETFLOW,
        vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-test", entity_pseudonym=line,
        device_class=device_class, retention_until=at + timedelta(days=30), integrity_sha256="0" * 64,
        flow=FlowObservation(dst_ip=dst, dst_port=port, protocol=proto, bytes_out=bo, bytes_in=bi,
                             packets_out=po, packets_in=pi, duration_ms=dur))


def flood(line: str, buckets: range, pps: float, *, reply_ratio: float = 0.0, dst: str = VICTIM,
          bucket_s: int = 60, port: int = 80, proto: str = "udp", **kw) -> list[ObservationEvent]:
    """One flow record per bucket at ``pps`` toward ``dst`` (an exporter's active-timeout slice)."""
    out = []
    for b in buckets:
        po = int(pps * bucket_s)
        pi = int(po * reply_ratio)
        out.append(ev(line, b * bucket_s, dst, port, proto, bo=po * 512, bi=pi * 512, po=po, pi=pi,
                      dur=bucket_s * 1000, **kw))
    return out


def run(events, cfg: EgressConfig = CFG, minutes: int = 30, **kw):
    return EgressDetector(cfg, tenant_id=TENANT).detect(events, start=T0, end=T0 + timedelta(minutes=minutes), **kw)


def verdict(report, line: str, label: str):
    hits = [v for v in report.verdicts if v.entity_pseudonym == line and v.label == label]
    return hits[0] if hits else None


# ------------------------------------------------------------------ report-level abstention

def test_abstains_below_minimum_flow_records():
    rep = EgressDetector(tenant_id=TENANT).detect(flood("p_line00001", range(3), 2000))
    assert rep.status == "abstain" and "minimum" in rep.abstain_reason and rep.verdicts == []


def test_abstains_when_packet_counters_missing():
    events = [ev("p_line00001", i, VICTIM, 80, po=None, pi=None) for i in range(30)]
    rep = EgressDetector(tenant_id=TENANT).detect(events)
    assert rep.status == "abstain" and "no packet counters" in rep.abstain_reason


def test_tenant_scope_fails_closed():
    with pytest.raises(ValueError):
        run([ev("p_line00001", 0, VICTIM, 80, tenant="other-isp")])
    with pytest.raises(ValueError):
        EgressDetector(tenant_id=" ")
    sp = SpoofSignal(tenant_id="other-isp", entity_pseudonym="p_line00001", interval_start=T0,
                     interval_end=T0 + timedelta(minutes=5), packets_outside_prefix=500, packets_total=1000)
    with pytest.raises(ValueError):
        run(flood("p_line00001", range(2), 2000), spoof_signals=[sp])


def test_config_rejects_inconsistent_relay_balance_and_hash_is_stable():
    with pytest.raises(ValueError):
        EgressConfig(relay_balance_min=2.0, relay_balance_max=1.0)
    assert EgressConfig().config_hash() == EgressConfig().config_hash()
    assert EgressConfig().config_hash() != EgressConfig(min_flood_pps=2000).config_hash()


# ------------------------------------------------------------------ floods

def test_one_way_flood_is_suspicious_without_corroboration():
    rep = run(flood("p_line00001", range(2), 1_200))
    v = verdict(rep, "p_line00001", LABEL_DDOS)
    assert v is not None and v.verdict == "suspicious"
    sig = v.signals[0]
    assert sig.kind == "flood" and sig.strong and sig.metrics["dst_ports"] == [80]
    assert sig.metrics["response_ratio"] == 0.0
    assert v.alternatives and "needs analyst review" in v.explanation


def test_flood_rate_just_below_threshold_is_not_reported():
    rep = run(flood("p_line00001", range(3), 990))
    assert verdict(rep, "p_line00001", LABEL_DDOS) is None


def test_conversation_with_replies_is_never_a_flood():
    # cloud gaming / video call / VPN shape: heavy UDP both ways
    rep = run(flood("p_line00001", range(10), 5_000, reply_ratio=0.9))
    assert rep.verdicts == []
    # just above the response-ratio threshold (0.02) is still a conversation
    rep = run(flood("p_line00001", range(10), 5_000, reply_ratio=0.03))
    assert rep.verdicts == []


def test_single_short_bucket_is_weak_and_not_reported():
    rep = run(flood("p_line00001", range(1), 1_500))
    assert verdict(rep, "p_line00001", LABEL_DDOS) is None
    assert rep.stats["weak_signals_not_reported"] >= 1


def test_sampling_interval_scales_rates():
    sampled = flood("p_line00001", range(2), 120)
    assert run(sampled).verdicts == []
    rep = run(sampled, EgressConfig(min_flow_records=1, sampling_interval=10))
    assert verdict(rep, "p_line00001", LABEL_DDOS).verdict == "suspicious"


def test_flood_with_spoofing_counters_is_malicious():
    sp = SpoofSignal(tenant_id=TENANT, entity_pseudonym="p_line00001", interval_start=T0,
                     interval_end=T0 + timedelta(minutes=5), packets_outside_prefix=5_000,
                     packets_total=100_000, source="urpf:bng-1")
    rep = run(flood("p_line00001", range(2), 1_200), spoof_signals=[sp])
    v = verdict(rep, "p_line00001", LABEL_DDOS)
    assert v.verdict == "malicious" and "spoofing_counters" in v.corroboration
    assert {s.kind for s in v.signals} == {"flood", "spoofing"}


def test_spoofing_below_fraction_is_ignored_and_alone_without_total_is_not_reported():
    low = SpoofSignal(tenant_id=TENANT, entity_pseudonym="p_line00001", interval_start=T0,
                      interval_end=T0 + timedelta(minutes=5), packets_outside_prefix=500,
                      packets_total=1_000_000)
    rep = run(flood("p_line00001", range(2), 1_200), spoof_signals=[low])
    assert verdict(rep, "p_line00001", LABEL_DDOS).verdict == "suspicious"
    no_total = low.model_copy(update={"entity_pseudonym": "p_line00002", "packets_total": None})
    filler = [ev("p_line00002", 0, "198.51.100.1", 443, "tcp")]
    rep = run(filler, spoof_signals=[no_total])
    assert verdict(rep, "p_line00002", LABEL_DDOS) is None


def test_overlapping_floods_from_three_lines_form_a_campaign_and_are_malicious():
    events = [e for i in range(3) for e in flood(f"p_line0000{i}", range(i, i + 3), 1_500)]
    rep = run(events)
    camp = [c for c in rep.campaigns if c.label == LABEL_DDOS]
    assert len(camp) == 1 and camp[0].n_lines == 3 and camp[0].targets == [VICTIM]
    for i in range(3):
        v = verdict(rep, f"p_line0000{i}", LABEL_DDOS)
        assert v.verdict == "malicious" and v.campaign_ids == [camp[0].campaign_id]


def test_two_lines_do_not_make_a_flood_campaign():
    events = [e for i in range(2) for e in flood(f"p_line0000{i}", range(3), 1_500)]
    rep = run(events)
    assert not rep.campaigns
    assert {v.verdict for v in rep.verdicts} == {"suspicious"}


def test_synchronized_onsets_need_enough_lines_and_aggregate_rate():
    def line(i: int, pps: float) -> list[ObservationEvent]:
        quiet = flood(f"p_line0000{i}", range(0, 6), 1, reply_ratio=0.0)
        return quiet + flood(f"p_line0000{i}", range(6, 7), pps)

    rep = run([e for i in range(4) for e in line(i, 800)])
    camp = [c for c in rep.campaigns if c.kind == "sync_burst"]
    assert len(camp) == 1 and camp[0].n_lines == 4
    assert all(verdict(rep, f"p_line0000{i}", LABEL_DDOS).verdict == "suspicious" for i in range(4))
    # same shape, aggregate below sync_min_aggregate_pps (3 x 800 < 3000): nothing reported
    rep = run([e for i in range(3) for e in line(i, 800)])
    assert not rep.campaigns and rep.verdicts == []


def test_carpet_bombing_a_prefix_is_detected_at_prefix_level():
    events = []
    for b in range(3):
        for h in range(6):
            po = 300 * 60
            events.append(ev("p_line00001", b * 60 + h, f"203.0.113.{10 + h}", 53, bo=po * 100, bi=0, po=po, pi=0,
                             dur=60_000))
    rep = run(events)
    v = verdict(rep, "p_line00001", LABEL_DDOS)
    assert v is not None and v.signals[0].targets == ["203.0.113.0/24"]
    assert v.signals[0].metrics["target_kind"] == "prefix"


def test_uniflow_export_abstains_instead_of_guessing():
    events = [ev("p_line00001", b * 60, VICTIM, 80, bo=72_000 * 512, bi=None, po=72_000, pi=None, dur=60_000)
              for b in range(3)]
    rep = run(events)
    v = verdict(rep, "p_line00001", LABEL_DDOS)
    assert v.verdict == "abstain" and v.score == 0.0
    assert v.counter_facts["abstain_reason"] == "reverse_counters_missing"


def test_device_class_does_not_change_the_verdict():
    a = run(flood("p_line00001", range(2), 1_200, device_class="android_tv"))
    b = run(flood("p_line00001", range(2), 1_200, device_class="laptop"))
    assert [(v.label, v.verdict, v.score) for v in a.verdicts] == [(v.label, v.verdict, v.score) for v in b.verdicts]


# ------------------------------------------------------------------ reflection

def _amp(n_reflectors: int, *, reply: int = 0, pps: float = 60) -> list[ObservationEvent]:
    per = int(pps * 60 / n_reflectors)
    return [ev("p_line00001", b * 60 + i, f"198.51.100.{i + 1}", 123, bo=per * 48, bi=reply * per * 468,
               po=per, pi=reply * per, dur=100)
            for b in range(2) for i in range(n_reflectors)]


def test_reflection_requests_to_many_reflectors_without_replies():
    v = verdict(run(_amp(12)), "p_line00001", LABEL_AMPLIFICATION)
    assert v.verdict == "suspicious"
    assert v.signals[0].metrics["service"] == "ntp" and v.signals[0].metrics["distinct_reflectors"] == 12


def test_reflection_boundaries_reflector_count_and_replies():
    assert verdict(run(_amp(9)), "p_line00001", LABEL_AMPLIFICATION) is None
    # a home resolver / NTP client gets its answers back
    assert verdict(run(_amp(12, reply=1)), "p_line00001", LABEL_AMPLIFICATION) is None


def test_abused_reflector_is_suspicious_and_marks_subscriber_as_victim():
    events = []
    for b in range(3):
        po = 300 * 60
        events.append(ev("p_line00001", b * 60, VICTIM, 40_000, bo=po * 1_400, bi=po * 50, po=po, pi=po,
                         dur=60_000))
    v = verdict(run(events), "p_line00001", LABEL_REFLECTOR)
    assert v.verdict == "suspicious"
    assert v.counter_facts["subscriber_likely_victim_of_misconfiguration"] is True
    assert v.signals[0].metrics["median_amplification"] == 28.0


def test_low_amplification_answers_are_not_a_reflector():
    events = [ev("p_line00001", b * 60, VICTIM, 40_000, bo=18_000 * 500, bi=18_000 * 50, po=18_000, pi=18_000,
                 dur=60_000) for b in range(3)]
    assert verdict(run(events), "p_line00001", LABEL_REFLECTOR) is None


# ------------------------------------------------------------------ residential proxy

SINK = "198.51.100.200"


def _relay(*, sink_reply: float = 0.02, bins: int = 12, line: str = "p_line00001") -> list[ObservationEvent]:
    """Short inbound sessions from distinct peers; their bytes leave toward one sink in the same bin."""
    events = []
    for b in range(bins):
        n = 2 + (b * 7) % 5
        total = 0
        for k in range(n):
            bi = 400_000 + 50_000 * k
            total += bi
            events.append(ev(line, b * 300 + 10 + k * 20, f"203.0.113.{(b * 5 + k) % 250 + 1}", 443, "tcp",
                             bo=2_000, bi=bi, po=20, pi=300, dur=3_000))
        out = int(total * 1.05)
        events.append(ev(line, b * 300 + 200, SINK, 443, "tcp", bo=out, bi=int(out * sink_reply), po=out // 1400,
                         pi=max(1, int(out * sink_reply) // 1400), dur=60_000))
    return events


def test_inbound_then_outbound_relay_is_a_proxy_signal():
    rep = run(_relay(), minutes=60)
    v = verdict(rep, "p_line00001", LABEL_PROXY)
    assert v is not None and v.verdict == "suspicious"
    m = v.signals[0].metrics
    assert m["sink"] == SINK and m["relay_correlation"] >= 0.6 and 0.5 <= m["byte_balance"] <= 2.0
    assert "sink_topology_unknown" in v.counter_facts


def test_sink_that_answers_back_is_a_conversation_not_a_proxy():
    rep = run(_relay(sink_reply=0.5), minutes=60)
    assert verdict(rep, "p_line00001", LABEL_PROXY) is None


def test_relay_needs_enough_bins():
    rep = run(_relay(bins=5), minutes=60)
    assert verdict(rep, "p_line00001", LABEL_PROXY) is None


def test_two_lines_relaying_to_one_sink_form_a_campaign():
    rep = run(_relay() + _relay(line="p_line00002"), minutes=60)
    camp = [c for c in rep.campaigns if c.label == LABEL_PROXY]
    assert len(camp) == 1 and camp[0].targets == [SINK]
    assert verdict(rep, "p_line00001", LABEL_PROXY).verdict == "malicious"


def test_continuation_slices_are_not_new_sessions():
    flows = [_Flow(0.0, VICTIM, 443, "tcp", 1, 1, 1, 1, 60_000), _Flow(60.5, VICTIM, 443, "tcp", 1, 1, 1, 1, 12_000),
             _Flow(200.0, VICTIM, 443, "tcp", 1, 1, 1, 1, 12_000)]
    assert _continuations(flows, 55_000, 5_000) == {1}


# ------------------------------------------------------------------ spam / stuffing

def _smtp(n: int) -> list[ObservationEvent]:
    return [ev("p_line00001", i * 60, f"198.51.100.{i + 1}", 25, "tcp", bo=8_000, bi=600, dur=2_000)
            for i in range(n)]


def test_spam_boundary_on_distinct_mail_exchangers():
    v = verdict(run(_smtp(35), minutes=60), "p_line00001", LABEL_SPAM)
    assert v.verdict == "suspicious" and v.signals[0].metrics["distinct_mail_exchangers"] == 35
    assert verdict(run(_smtp(25), minutes=60), "p_line00001", LABEL_SPAM) is None


def _logins(n: int, *, regular: bool, port: int = 22) -> list[ObservationEvent]:
    events, t = [], 0.0
    for i in range(n):
        t += 4.0 if regular else (1.0 if i % 3 else 9.0) + (i % 7) * 0.7
        events.append(ev("p_line00001", t, VICTIM, port, "tcp", bo=900, bi=1_200 + (i % 3) * 10, dur=800))
    return events


def test_credential_stuffing_irregular_byte_uniform_sessions():
    v = verdict(run(_logins(150, regular=False), minutes=60), "p_line00001", LABEL_STUFFING)
    assert v.verdict == "suspicious" and v.signals[0].kind == "credential_stuffing" and v.signals[0].strong


def test_regular_timer_polling_is_not_stuffing():
    assert verdict(run(_logins(150, regular=True), minutes=60), "p_line00001", LABEL_STUFFING) is None


def test_auth_fanout_across_many_hosts():
    events = [ev("p_line00001", i * 30, f"198.18.{i // 200}.{i % 200 + 1}", 23, "tcp", bo=60, bi=0, po=1, pi=0, dur=0)
              for i in range(35)]
    v = verdict(run(events, minutes=60), "p_line00001", LABEL_STUFFING)
    assert v.verdict == "suspicious" and v.signals[0].kind == "auth_fanout"
    events = events[:25]
    assert verdict(run(events, minutes=60), "p_line00001", LABEL_STUFFING) is None


def test_second_abuse_family_corroborates():
    fan = [ev("p_line00001", i * 30, f"198.18.0.{i + 1}", 23, "tcp", bo=60, bi=0, po=1, pi=0, dur=0)
           for i in range(35)]
    rep = run(fan + flood("p_line00001", range(2), 1_200), minutes=60)
    assert verdict(rep, "p_line00001", LABEL_DDOS).verdict == "malicious"
    assert verdict(rep, "p_line00001", LABEL_STUFFING).verdict == "malicious"
    assert "also:egress_credential_stuffing" in verdict(rep, "p_line00001", LABEL_DDOS).corroboration
