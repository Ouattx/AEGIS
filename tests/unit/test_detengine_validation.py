"""Static validation: device class is never a detection, no shared-hosting targets, bounded rules."""
from __future__ import annotations

import pytest

from aegis.api.topology import parse_topology
from aegis.detengine import RuleSpec, RuleSpecError, RuleValidationError, validate_rule
from aegis.detengine.validation import require_valid

TOPOLOGY = parse_topology({
    "topology_id": "topo-test", "complete": True,
    "prefixes": ["198.18.0.0/16", "203.0.113.0/24"],
    "hosts": [
        {"ip": "198.18.0.10", "kind": "shared_cdn", "hostnames": ["cdn.example", "news.example", "tv.example"]},
        {"ip": "203.0.113.9", "kind": "dedicated", "hostnames": ["c2.bad.example"]},
        {"ip": "203.0.113.10", "kind": "dedicated", "hostnames": ["c3.bad.example"]},
        {"ip": "203.0.113.200", "kind": "shared_cdn", "hostnames": ["img.bad.example", "shop.example"]},
    ],
})


def rule(**kw) -> RuleSpec:
    return RuleSpec.from_dict({"rule_id": "rule-under-test", "title": "t", "label": "c2_beaconing", **kw})


def errors(spec: RuleSpec, **kw) -> tuple[str, ...]:
    return validate_rule(spec, hosting=TOPOLOGY, **kw).errors


def test_device_class_only_is_refused():
    assert errors(rule(baseline={"device_classes": ["android_tv"]})) == ("device_class_only",)
    assert errors(rule()) == ("empty_rule",)


def test_coverage_alone_is_not_behavior():
    spec = rule(conditions=[{"feature": "coverage_h", "op": "ge", "value": 20}],
                baseline={"device_classes": ["android_tv"]})
    assert "no_behavioral_element" in errors(spec)


def test_behavioral_rule_with_selector_is_valid():
    spec = rule(conditions=[{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}],
                baseline={"device_classes": ["android_tv"]})
    res = validate_rule(spec, hosting=TOPOLOGY)
    assert res.ok and res.warnings == ()
    assert require_valid(spec, hosting=TOPOLOGY).ok


@pytest.mark.parametrize("cond, code", [
    ({"feature": "tcp_frac", "op": "ge", "value": 0}, "tautological_condition:tcp_frac"),
    ({"feature": "out_ratio", "op": "le", "value": 1.0}, "tautological_condition:out_ratio"),
    ({"feature": "burstiness", "op": "between", "low": -1, "high": 1}, "tautological_condition:burstiness"),
    ({"feature": "nxdomain_rate", "op": "gt", "value": 1.0}, "unsatisfiable_condition:nxdomain_rate"),
    ({"feature": "unique_dst_ip", "op": "lt", "value": 0}, "unsatisfiable_condition:unique_dst_ip"),
])
def test_meaningless_conditions(cond, code):
    assert code in errors(rule(conditions=[cond]))


def test_contradictory_conditions():
    spec = rule(conditions=[{"feature": "nxdomain_rate", "op": "gt", "value": 0.7},
                            {"feature": "nxdomain_rate", "op": "lt", "value": 0.3}])
    assert "contradictory_conditions:nxdomain_rate" in errors(spec)
    ok = rule(conditions=[{"feature": "nxdomain_rate", "op": "ge", "value": 0.3},
                          {"feature": "nxdomain_rate", "op": "le", "value": 0.3}])
    assert errors(ok) == ()


def test_shared_hosting_ip_is_refused():
    assert errors(rule(destinations={"patterns": [{"kind": "ip", "value": "198.18.0.10"}]})) == (
        "shared_hosting_ip:198.18.0.10",)
    assert errors(rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.9"}]})) == ()


def test_unknown_hosting_fails_closed():
    spec = rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.77"}]})
    assert errors(spec) == ("ip_hosting_unknown:203.0.113.77",)
    # no topology at all: every IP target is refused
    assert validate_rule(rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.9"}]})).errors == (
        "ip_hosting_unknown:203.0.113.9",)


def test_reserved_addresses_are_refused():
    for ip in ("127.0.0.1", "224.0.0.1", "169.254.1.1", "0.0.0.0"):
        assert f"reserved_address:{ip}" in errors(rule(destinations={"patterns": [{"kind": "ip", "value": ip}]}))


def test_cidr_rules():
    def cidr(v: str) -> tuple[str, ...]:
        return errors(rule(destinations={"patterns": [{"kind": "cidr", "value": v}]}))

    assert cidr("203.0.0.0/16") == ("cidr_too_broad:203.0.0.0/16",)
    assert cidr("203.0.113.0/28") == ()                                   # only dedicated hosts inside
    assert cidr("203.0.113.200/29") == ("shared_hosting_cidr:203.0.113.200/29",)
    assert cidr("192.0.2.0/24") == ("cidr_hosting_unknown:192.0.2.0/24",)  # outside the known prefixes
    assert cidr("203.0.113.64/28") == ("cidr_hosting_unknown:203.0.113.64/28",)  # no known host inside


def test_domain_rules():
    with pytest.raises(RuleSpecError):  # a bare label is not even a valid pattern
        rule(destinations={"patterns": [{"kind": "domain_suffix", "value": "example"}]})
    assert "domain_too_broad:co.uk" in errors(rule(destinations={"patterns": [{"kind": "domain_suffix",
                                                                                "value": "co.uk"}]}))
    res = validate_rule(rule(destinations={"patterns": [{"kind": "domain_exact", "value": "img.bad.example"}]}),
                        hosting=TOPOLOGY)
    assert res.ok and "domain_on_shared_hosting:img.bad.example" in res.warnings


def test_allowlist():
    spec = rule(destinations={"patterns": [{"kind": "domain_suffix", "value": "bad.example"}]})
    assert "allowlisted_destination:bad.example" in errors(spec, allowlist=["shop.bad.example"])
    assert errors(spec, allowlist=["other.example"]) == ()
    ip = rule(destinations={"patterns": [{"kind": "ip", "value": "203.0.113.9"}]})
    assert errors(ip, allowlist=["203.0.113.9"]) == ("allowlisted_destination:203.0.113.9",)


def test_periodicity_alone_needs_rarity():
    spec = rule(periodicity={"min_period_s": 60, "max_period_s": 600, "max_dst_prevalence": None})
    assert "periodicity_needs_rarity" in errors(spec)
    assert errors(rule(periodicity={"min_period_s": 60, "max_period_s": 600})) == ()
    assert "periodicity_range_too_broad" in errors(rule(periodicity={"min_period_s": 20, "max_period_s": 7200}))
    assert "periodicity_period_too_short" in errors(rule(periodicity={"min_period_s": 2, "max_period_s": 20}))


def test_bounded_complexity():
    many = [{"feature": "nxdomain_rate", "op": "ge", "value": 0.1 + i / 100} for i in range(13)]
    assert "too_many_conditions" in errors(rule(conditions=many))
    pats = [{"kind": "domain_exact", "value": f"h{i}.bad.example"} for i in range(65)]
    assert "too_many_destinations" in errors(rule(destinations={"patterns": pats}))


def test_require_valid_raises_with_codes():
    with pytest.raises(RuleValidationError) as exc:
        require_valid(rule(baseline={"device_classes": ["android_tv"]}), hosting=TOPOLOGY)
    assert exc.value.errors == ["device_class_only"]
