"""Rule language: strict parsing, round-trips and three-valued evaluation."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from aegis.detengine import (
    Contacts,
    RuleSpec,
    RuleSpecError,
    evaluate_rule,
    parse_rule,
    spec_sha256,
)
from test_detengine_support import T0, contacts, fv

BASE = {"rule_id": "dga-storm-1", "title": "DGA storm", "label": "dga_activity"}


def rule(**kw):
    return RuleSpec.from_dict({**BASE, **kw})


def test_round_trip_and_hash_stable():
    spec = rule(conditions=[{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}],
                any_of=[{"feature": "nx_unique", "op": "gt", "value": 50},
                        {"feature": "nx_name_entropy", "op": "between", "low": 3.2, "high": 6}],
                destinations={"patterns": [{"kind": "domain_suffix", "value": "Bad.Example."},
                                           {"kind": "cidr", "value": "203.0.113.0/28"}]},
                periodicity={"min_period_s": 60, "max_period_s": 900}, baseline={"device_classes": ["smart_tv",
                                                                                                   "android_tv"]})
    again = RuleSpec.from_dict(json.loads(spec.to_json()))
    assert again == spec
    assert spec_sha256(again) == spec.sha256
    assert spec.destinations.patterns[0].value == "bad.example"      # normalized
    assert spec.baseline.device_classes == ("android_tv", "smart_tv")  # canonical order
    assert spec.element_count() == 6


def test_yaml_text_is_accepted():
    pytest.importorskip("yaml")
    spec = parse_rule("""
rule_id: dga-yaml
title: DGA from YAML
label: dga_activity
conditions:
  - {feature: nxdomain_rate, op: ge, value: 0.7}
""")
    assert spec.conditions[0].value == 0.7


@pytest.mark.parametrize("patch, needle", [
    ({"conditions": [{"feature": "device_class", "op": "eq", "value": 1}]}, "unknown feature"),
    ({"conditions": [{"feature": "nxdomain_rate", "op": "regex", "value": 1}]}, "op must be"),
    ({"conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": float("nan")}]}, "finite"),
    ({"conditions": [{"feature": "nxdomain_rate", "op": "between", "low": 0.8, "high": 0.2}]}, "low must be"),
    ({"conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": True}]}, "finite"),
    ({"exec": "rm -rf /"}, "unknown field"),
    ({"rule_id": "A bad id!"}, "rule_id"),
    ({"label": "Bad Label"}, "label"),
    ({"destinations": {"patterns": [{"kind": "regex", "value": ".*"}]}}, "kind must be"),
    ({"destinations": {"patterns": [{"kind": "ip", "value": "999.1.1.1"}]}}, "not a valid address"),
    ({"destinations": {"patterns": [{"kind": "cidr", "value": "203.0.113.5/24"}]}}, "CIDR"),
    ({"destinations": {"patterns": [{"kind": "ip", "value": "203.0.113.5", "verified_contact": True}]}},
     "domain patterns only"),
    ({"destinations": {"patterns": [{"kind": "domain_exact", "value": "a.example"}], "min_matches": 2}}, "exceeds"),
    ({"periodicity": {"min_period_s": 900, "max_period_s": 60}}, "min_period_s"),
    ({"baseline": {"device_classes": []}}, "device_classes"),
    ({"schema": "other/9"}, "schema"),
    ({"any_of": [{"feature": "nx_unique", "op": "gt", "value": 1}], "min_any": 3}, "min_any"),
])
def test_strict_parser_rejects(patch, needle):
    with pytest.raises(RuleSpecError) as exc:
        rule(**patch)
    assert any(needle in e for e in exc.value.errors), exc.value.errors


def test_parse_rejects_non_json_non_yaml():
    with pytest.raises(RuleSpecError):
        parse_rule("{not: [valid")


def test_conditions_fire_and_missing_abstains():
    spec = rule(conditions=[{"feature": "nxdomain_rate", "op": "ge", "value": 0.6},
                            {"feature": "nx_unique", "op": "gt", "value": 50}])
    assert evaluate_rule(spec, fv(nxdomain_rate=0.9, nx_unique=120)).outcome == "fired"
    assert evaluate_rule(spec, fv(nxdomain_rate=0.1, nx_unique=120)).outcome == "no_match"
    # missing is never zero: unknown -> abstain, unless something else is already false
    ev = evaluate_rule(spec, fv(nxdomain_rate=None, nx_unique=120))
    assert ev.outcome == "abstain" and ev.unknown == ("nxdomain_rate >= 0.6",)
    assert evaluate_rule(spec, fv(nxdomain_rate=None, nx_unique=2)).outcome == "no_match"


def test_any_of_counts_unknown_honestly():
    spec = rule(any_of=[{"feature": "nx_unique", "op": "gt", "value": 50},
                        {"feature": "nxdomain_rate", "op": "gt", "value": 0.5}], min_any=2)
    assert evaluate_rule(spec, fv(nx_unique=60, nxdomain_rate=0.7)).fired
    assert evaluate_rule(spec, fv(nx_unique=60, nxdomain_rate=None)).outcome == "abstain"
    assert evaluate_rule(spec, fv(nx_unique=10, nxdomain_rate=None)).outcome == "no_match"


def test_outside_and_eq_ops():
    spec = rule(conditions=[{"feature": "burstiness", "op": "outside", "low": -0.2, "high": 0.2},
                            {"feature": "beacon_events", "op": "ne", "value": 0}])
    assert evaluate_rule(spec, fv(burstiness=-0.8, beacon_events=12)).fired
    assert not evaluate_rule(spec, fv(burstiness=0.1, beacon_events=12)).fired


def test_baseline_selector_and_window_scope():
    spec = rule(conditions=[{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}],
                baseline={"device_classes": ["android_tv"]})
    assert evaluate_rule(spec, fv(device_class="phone", nxdomain_rate=0.9)).outcome == "not_applicable"
    assert evaluate_rule(spec, fv(device_class="android_tv", nxdomain_rate=0.9)).fired
    assert evaluate_rule(spec, fv(window="5m", nxdomain_rate=0.9)).outcome == "not_applicable"


def test_destination_patterns():
    spec = rule(destinations={"patterns": [
        {"kind": "domain_suffix", "value": "c2.example", "verified_contact": True},
        {"kind": "domain_exact", "value": "only.example"},
        {"kind": "ip", "value": "203.0.113.9"},
        {"kind": "cidr", "value": "198.51.100.0/28"}]})
    f = fv()
    assert evaluate_rule(spec, f, None).outcome == "abstain"           # no contacts -> unknown
    assert evaluate_rule(spec, f, contacts()).outcome == "no_match"
    # lookup without traffic to a resolved address is not a verified contact
    assert not evaluate_rule(spec, f, contacts(names=("a.c2.example",), answers={"a.c2.example": ("1.2.3.4",)})).fired
    ev = evaluate_rule(spec, f, contacts(ips=("1.2.3.4",), names=("a.c2.example",),
                                         answers={"a.c2.example": ("1.2.3.4",)}))
    assert ev.fired and ev.matched_destinations == ("domain_suffix:c2.example",)
    assert not evaluate_rule(spec, f, contacts(names=("x.only.example",))).fired   # exact means exact
    assert evaluate_rule(spec, f, contacts(names=("only.example",))).fired
    assert evaluate_rule(spec, f, contacts(ips=("203.0.113.9",))).fired
    assert evaluate_rule(spec, f, contacts(ips=("198.51.100.7",))).fired
    assert not evaluate_rule(spec, f, contacts(ips=("198.51.100.77",))).fired
    assert not evaluate_rule(spec, f, contacts(names=("evilc2.example",))).fired   # suffix is label-aligned


def test_destination_min_matches():
    spec = rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.9"},
                                           {"kind": "ip", "value": "203.0.113.10"}], "min_matches": 2})
    assert not evaluate_rule(spec, fv(), contacts(ips=("203.0.113.9",))).fired
    assert evaluate_rule(spec, fv(), contacts(ips=("203.0.113.9", "203.0.113.10"))).fired


def test_periodicity_constraint():
    spec = rule(periodicity={"min_period_s": 300, "max_period_s": 1200, "max_robust_cv": 0.2, "min_events": 10,
                             "min_duty": 0.6, "max_dst_prevalence": 0.02})
    good = dict(beacon_period_log=2.778, beacon_robust_cv=0.1, beacon_events=40, beacon_duty=0.9,
                beacon_dst_prevalence=0.01)      # 10**2.778 ~ 600 s
    assert evaluate_rule(spec, fv(**good)).fired
    assert evaluate_rule(spec, fv(**{**good, "beacon_dst_prevalence": 0.4})).outcome == "no_match"
    assert evaluate_rule(spec, fv(**{**good, "beacon_period_log": 4.0})).outcome == "no_match"
    assert evaluate_rule(spec, fv(**{**good, "beacon_robust_cv": None})).outcome == "abstain"
    assert evaluate_rule(spec, fv()).outcome == "abstain"


def test_contact_summary_is_accepted():
    from aegis.sentinel.features import ContactSummary
    cs = ContactSummary("acme", "p_dev1", T0, T0 + timedelta(days=1))
    cs.dst_ips["203.0.113.9"] += 3
    spec = rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.9"}]})
    assert evaluate_rule(spec, fv(), cs).fired
    assert Contacts.coerce(cs).dst_ips == frozenset({"203.0.113.9"})
    with pytest.raises(TypeError):
        Contacts.coerce({"dst_ips": []})  # type: ignore[arg-type]
