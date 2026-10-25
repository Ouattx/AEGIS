"""STIX 2.1 export: verified material only, victim-safe, privacy-safe, structurally valid."""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from test_egress_detector import TENANT, _relay, flood, run

from aegis.connectors.stix import (
    TLP_MARKINGS,
    VerifiedCampaign,
    VerifiedIndicator,
    build_bundle,
    from_egress_report,
    stix_export,
    validate_bundle,
)

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
PRODUCER = "Example ISP CERT"


def _proxy_and_ddos_report():
    events = _relay() + _relay(line="p_line00002")
    events += [e for i in range(3) for e in flood(f"p_line1000{i}", range(i, i + 3), 1_500)]
    return run(events, minutes=60)


def _verified_all(rep):
    return {c.campaign_id: f"case-{n}" for n, c in enumerate(rep.campaigns)}


def test_only_verified_campaigns_and_only_attacker_side_indicators():
    rep = _proxy_and_ddos_report()
    assert {c.label for c in rep.campaigns} == {"egress_residential_proxy", "egress_ddos_participation"}
    camps, inds = from_egress_report(rep, {})
    assert camps == [] and inds == []
    camps, inds = from_egress_report(rep, _verified_all(rep))
    assert len(camps) == 2
    assert [i.value for i in inds] == ["198.51.100.200"]          # the proxy sink, never the DDoS victim
    assert inds[0].indicator_types == ("anonymization", "malicious-activity")


def test_bundle_validates_and_leaks_no_pseudonym_or_tenant():
    rep = _proxy_and_ddos_report()
    camps, inds = from_egress_report(rep, _verified_all(rep))
    pl = stix_export(camps, inds, tenant_id=TENANT, producer_name=PRODUCER, now=NOW)
    bundle = json.loads(pl.body)
    assert validate_bundle(bundle) == []
    assert "p_line" not in pl.body and TENANT not in pl.body and "192.0.2.10" not in pl.body
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("campaign") == 2 and types.count("indicator") == 1 and types.count("relationship") == 1
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[ipv4-addr:value = '198.51.100.200']" and ind["pattern_type"] == "stix"
    assert ind["object_marking_refs"] == [TLP_MARKINGS["amber"]]
    assert pl.content_type.startswith("application/stix+json")


def test_ids_are_deterministic_for_the_same_material():
    rep = _proxy_and_ddos_report()
    camps, inds = from_egress_report(rep, _verified_all(rep))
    a = build_bundle(camps, inds, producer_name=PRODUCER, now=NOW)
    b = build_bundle(camps, inds, producer_name=PRODUCER, now=NOW)
    assert a == b and a["id"].startswith("bundle--")


def _valid():
    camp = VerifiedCampaign(key="c1", name="proxy relays", description="d", first_seen=NOW - timedelta(days=1),
                            last_seen=NOW, verification_ref="case-9")
    ind = VerifiedIndicator(kind="domain-name", value="Proxy-Upstream.Example.", name="upstream",
                            valid_from=NOW - timedelta(days=1), valid_until=NOW + timedelta(days=30),
                            campaign_key="c1", verification_ref="case-9")
    return build_bundle([camp], [ind], producer_name=PRODUCER, now=NOW, tlp="green")


def test_domain_indicator_is_normalized_and_tlp_applied():
    b = _valid()
    ind = next(o for o in b["objects"] if o["type"] == "indicator")
    assert ind["pattern"] == "[domain-name:value = 'proxy-upstream.example']"
    mark = next(o for o in b["objects"] if o["type"] == "marking-definition")
    assert mark["id"] == TLP_MARKINGS["green"] and mark["definition"] == {"tlp": "green"}


@pytest.mark.parametrize("mutate,needle", [
    (lambda b: b.update(id="bundle--not-a-uuid"), "bundle.id"),
    (lambda b: b.update(spec_version="2.1"), "must not carry spec_version"),
    (lambda b: b["objects"].append(copy.deepcopy(b["objects"][-1])), "duplicated"),
    (lambda b: _obj(b, "indicator").pop("pattern"), "pattern is required"),
    (lambda b: _obj(b, "indicator").update(pattern="[ipv4-addr:value = 1.2.3.4]"), "not a supported STIX"),
    (lambda b: _obj(b, "indicator").update(indicator_types=["evil"]), "indicator-type-ov"),
    (lambda b: _obj(b, "indicator").update(confidence=101), "confidence"),
    (lambda b: _obj(b, "indicator").update(valid_until="2026-01-01T00:00:00.000Z"), "valid_until"),
    (lambda b: _obj(b, "relationship").update(target_ref="campaign--00000000-0000-4000-8000-000000000000"),
     "does not resolve"),
    (lambda b: _obj(b, "campaign").update(modified="2020-01-01T00:00:00.000Z"), "modified is before created"),
    (lambda b: _obj(b, "campaign").update(created="2026-10-02 00:00:00"), "RFC 3339"),
    (lambda b: _obj(b, "campaign").update(spec_version="2.0"), "spec_version"),
    (lambda b: _obj(b, "marking-definition").update(definition={"tlp": "red"}), "predefined TLP"),
    (lambda b: _obj(b, "identity").update(type="malware"), "not supported"),
])
def test_validation_catches_structural_errors(mutate, needle):
    b = _valid()
    assert validate_bundle(b) == []
    mutate(b)
    errs = validate_bundle(b)
    assert any(needle in e for e in errs), errs


def _obj(bundle, kind):
    return next(o for o in bundle["objects"] if o["type"] == kind)


def test_unverified_private_or_dangling_material_is_refused():
    with pytest.raises(ValidationError):
        VerifiedIndicator(kind="ipv4-addr", value="198.51.100.9", name="x", valid_from=NOW, verification_ref=" ")
    priv = VerifiedIndicator(kind="ipv4-addr", value="10.1.2.3", name="x", valid_from=NOW, verification_ref="c")
    with pytest.raises(ValueError):
        build_bundle([], [priv], producer_name=PRODUCER, now=NOW)
    dangling = VerifiedIndicator(kind="ipv4-addr", value="198.51.100.9", name="x", valid_from=NOW,
                                 campaign_key="nope", verification_ref="c")
    with pytest.raises(ValueError):
        build_bundle([], [dangling], producer_name=PRODUCER, now=NOW)
    with pytest.raises(ValueError):
        build_bundle([], [], producer_name=" ", now=NOW)
    assert validate_bundle([]) == ["bundle is not an object"]
