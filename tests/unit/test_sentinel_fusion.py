from __future__ import annotations

from datetime import timedelta

import pytest

from aegis.contracts.models import Evidence, EvidenceKind, Verdict
from aegis.sentinel.anomaly import AnomalyScore, ChangePoint
from aegis.sentinel.fusion import DEFAULT_FUSION_POLICY, FusionPolicy, MLScore, fusion_policy, is_strong_hit
from test_sentinel_helpers import T0, make_fv

FV = make_fv()


def hit(*, conf=0.9, eff=None, verified=True, contradicted=False, group="grp:a", label="c2_beaconing"):
    return Evidence(tenant_id="t1", kind=EvidenceKind.IOC_MATCH, origin_source=f"feed:{group}",
                    source_independence_group=group, collected_at=T0, summary="hit", authorization_id="auth-1",
                    payload={"confidence": conf, "effective_confidence": conf if eff is None else eff,
                             "verified_contact": verified, "contradicted": contradicted,
                             "threat_labels": [label]})


def counter():
    return Evidence(tenant_id="t1", kind=EvidenceKind.THREAT_FEED, origin_source="feed:sinkhole",
                    source_independence_group="grp:sinkhole", collected_at=T0, summary="benign claim",
                    authorization_id="auth-1", supports=False)


def ml(p, persistence=3):
    return MLScore(p, "iso-abc", "m1", persistence)


def anomaly(pct):
    return AnomalyScore(percentile=pct, aggregate=5.0, top=(), baseline="android_tv", fallback=False,
                        features_used=10)


CP = ChangePoint("t1", "p_dev1", "recent_flows_log", "up", T0, 7.0, 1.0, 0.1, 3.0)


def test_insufficient_context_abstains():
    r = fusion_policy([hit()], ml(0.99), anomaly(1.0), [CP], make_fv(event_count=5))
    assert r.verdict == Verdict.ABSTAIN and r.rule == "F0_insufficient_context"
    assert r.signal and r.requires_review
    sparse = make_fv({"flow_rate_h": None, "bytes_out_rate_log": None, "unique_dst_ip": None, "dst_entropy": None,
                      "tcp_frac": None, "small_flow_frac": None, "dns_rate_h": None, "nxdomain_rate": None})
    assert fusion_policy([], ml(0.99), None, None, sparse).rule == "F0_insufficient_context"
    short = make_fv({"coverage_h": 0.5})
    r2 = fusion_policy([], ml(0.1), None, None, short)
    assert r2.verdict == Verdict.ABSTAIN and not r2.signal


def test_f1_strong_ioc_with_model():
    r = fusion_policy([hit()], ml(0.95), None, None, FV)
    assert r.verdict == Verdict.MALICIOUS and r.rule == "F1_ioc_corroborated"
    assert r.score == pytest.approx(0.95) and r.calibration_id == "iso-abc"


def test_f1_strong_ioc_two_independent_origins():
    r = fusion_policy([hit(group="grp:a"), hit(group="grp:b")], ml(0.05), None, None, FV)
    assert r.verdict == Verdict.MALICIOUS and r.calibration_id is None and r.score == pytest.approx(0.9)


def test_f1_syndicated_copies_do_not_count_twice():
    r = fusion_policy([hit(group="grp:a"), hit(group="grp:a")], ml(0.05), None, None, FV)
    assert r.verdict == Verdict.SUSPICIOUS and r.rule == "F2_ioc_only"


def test_f1_strong_ioc_with_changepoint():
    assert fusion_policy([hit()], None, None, CP, FV).verdict == Verdict.MALICIOUS


def test_f2_strong_ioc_alone_is_suspicious():
    r = fusion_policy([hit()], ml(0.1), anomaly(0.5), [], FV)
    assert r.verdict == Verdict.SUSPICIOUS and r.rule == "F2_ioc_only" and r.calibration_id is None


def test_f3_f4_model():
    r3 = fusion_policy([], ml(0.97), anomaly(0.99), None, FV)
    # model + anomaly read the same operator telemetry (one origin): capped at SUSPICIOUS
    assert r3.verdict == Verdict.SUSPICIOUS and r3.rule == "F3_model_corroborated"
    r4 = fusion_policy([], ml(0.97), anomaly(0.5), None, FV)
    assert r4.verdict == Verdict.SUSPICIOUS and r4.rule == "F4_model_only"
    # a change point is not enough to make a model-only finding MALICIOUS
    assert fusion_policy([], ml(0.97), anomaly(0.5), [CP], FV).rule == "F4_model_only"


def test_contradicting_feed_downgrades_malicious():
    r = fusion_policy([hit(), counter()], ml(0.97), anomaly(0.99), None, FV)
    assert r.verdict == Verdict.SUSPICIOUS and "downgraded" in r.reasons[0]
    assert r.component_scores["ioc_counter_evidence"] == 1.0
    r2 = fusion_policy([counter()], ml(0.97), anomaly(0.99), None, FV)
    assert r2.verdict == Verdict.SUSPICIOUS


def test_contradicted_hit_is_weak():
    contradicted = hit(eff=0.54, contradicted=True)
    assert not is_strong_hit(contradicted)
    r = fusion_policy([contradicted, counter()], ml(0.7), None, None, FV)
    assert r.verdict == Verdict.SUSPICIOUS and r.rule == "F5_weak_ioc_and_model"
    r2 = fusion_policy([contradicted, counter()], ml(0.1), None, None, FV)
    assert r2.verdict == Verdict.ABSTAIN and r2.rule == "F7_weak_ioc_only" and r2.signal


def test_lookup_only_and_low_confidence_are_weak():
    assert not is_strong_hit(hit(verified=False))
    assert not is_strong_hit(hit(conf=0.5))
    assert fusion_policy([hit(verified=False)], ml(0.1), None, None, FV).rule == "F7_weak_ioc_only"


def test_f6_f8_f11_bands():
    assert fusion_policy([], ml(0.7), None, CP, FV).rule == "F6_model_and_anomaly"
    r8 = fusion_policy([], ml(0.7), None, None, FV)
    assert r8.verdict == Verdict.ABSTAIN and r8.rule == "F8_model_uncorroborated" and r8.signal
    r11 = fusion_policy([], ml(0.45), anomaly(0.99), None, FV)
    assert r11.verdict == Verdict.ABSTAIN and r11.rule == "F11_uncertain" and not r11.signal


def test_benign_requires_low_model_score_and_no_hits():
    r = fusion_policy([], ml(0.01), anomaly(0.2), None, FV)
    assert r.verdict == Verdict.BENIGN and r.rule == "F10_benign" and not r.requires_review


def test_without_model_never_benign():
    r = fusion_policy([], None, anomaly(0.1), None, FV)
    assert r.verdict == Verdict.ABSTAIN and r.rule == "F9_no_model" and not r.signal


@pytest.mark.parametrize("pct,cps", [(1.0, []), (0.2, [CP]), (1.0, [CP])])
def test_anomaly_and_changepoint_alone_never_positive(pct, cps):
    for model in (None, ml(0.05), ml(0.45)):
        r = fusion_policy([], model, anomaly(pct), cps, FV)
        assert r.verdict in (Verdict.ABSTAIN, Verdict.BENIGN)


@pytest.mark.parametrize("klass", ["android_tv", "smart_tv", "phone", "camera", "unknown", "iptv_box"])
def test_device_class_is_not_an_input(klass):
    """The same behavior yields the same decision whatever the device class."""
    fv = make_fv(device_class=klass)
    for args in (([], ml(0.01), None, None), ([hit()], ml(0.95), None, None), ([], ml(0.7), None, None)):
        assert fusion_policy(*args, fv).as_dict() == fusion_policy(*args, FV).as_dict()


def test_single_window_model_spike_abstains():
    r = fusion_policy([], ml(0.99, persistence=1), anomaly(0.99), None, FV)
    assert r.verdict == Verdict.ABSTAIN and r.rule == "F2b_model_not_persistent" and r.signal
    # indicator-driven findings do not need persistence
    assert fusion_policy([hit()], ml(0.99, persistence=1), None, None, FV).verdict == Verdict.MALICIOUS
    # a weak indicator plus an elevated model score is still reviewed as SUSPICIOUS
    weak = hit(eff=0.54, contradicted=True)
    assert fusion_policy([weak], ml(0.8, persistence=1), None, None, FV).rule == "F5_weak_ioc_and_model"
    assert fusion_policy([], ml(0.99, persistence=2), anomaly(0.99), None, FV).verdict == Verdict.SUSPICIOUS


def test_float_ml_accepted_and_scores_clipped():
    r = fusion_policy([], 0.95, None, None, FV)
    assert r.verdict == Verdict.ABSTAIN and r.calibration_id is None   # bare score: one window, not persistent
    with pytest.raises(ValueError):
        MLScore(1.5, None, "m")


def test_policy_is_preregistered_and_hashed():
    assert DEFAULT_FUSION_POLICY.policy_hash == FusionPolicy().policy_hash
    assert FusionPolicy(ml_malicious=0.95).policy_hash != DEFAULT_FUSION_POLICY.policy_hash
    r = fusion_policy([], ml(0.01), None, None, FV)
    assert r.policy_hash == DEFAULT_FUSION_POLICY.policy_hash and r.as_dict()["policy_id"] == "sentinel-fusion/2"
    with pytest.raises(ValueError):
        FusionPolicy(ml_suspicious=0.95, ml_malicious=0.9)


def test_stricter_policy_changes_outcome():
    strict = FusionPolicy(ml_malicious=0.99, ml_suspicious=0.98)
    assert fusion_policy([], ml(0.97), anomaly(0.99), None, FV, strict).verdict == Verdict.ABSTAIN


def test_components_reported_without_averaging():
    r = fusion_policy([hit()], ml(0.95), anomaly(0.97), [CP], FV)
    assert r.component_scores == {"ioc": 0.9, "ioc_independent_origins": 1.0, "ioc_counter_evidence": 0.0,
                                  "ml": 0.95, "anomaly": 0.97, "changepoint": 1.0}
    assert r.score in (0.9, 0.95)


def test_window_end_irrelevant_to_policy():
    later = make_fv(window_end=T0 + timedelta(days=30))
    assert fusion_policy([], ml(0.97), None, None, later).verdict == Verdict.SUSPICIOUS


def test_malicious_is_reserved_for_verification_grade_evidence():
    """Single-origin agreement (model + anomaly + change point, all operator telemetry)
    never yields MALICIOUS; a verified signed indicator contact does."""
    from aegis.sentinel.fusion import format_probability

    r = fusion_policy([], ml(0.999, persistence=5), anomaly(0.999), [CP], FV)
    assert r.verdict == Verdict.SUSPICIOUS and "single telemetry origin" in r.reasons[0]
    assert fusion_policy([hit()], ml(0.999, persistence=5), anomaly(0.999), None, FV).verdict == Verdict.MALICIOUS
    assert format_probability(1.0) == ">0.99" and format_probability(0.5) == "0.50"
    assert format_probability(0.001) == "<0.01"
