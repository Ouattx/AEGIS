from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from aegis.contracts.models import EvidenceKind
from aegis.lab.iocs import lab_signer, sign_bundle
from aegis.provenance.evidence import independent_origins
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.features import ContactSummary
from aegis.sentinel.rules import (
    BUNDLE_SCHEMA,
    BundleError,
    BundleSignatureError,
    Indicator,
    ioc_match,
    load_bundle,
)
from test_sentinel_helpers import T0, dns_event, flow_event, make_fv

NOW = T0 + timedelta(hours=12)


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def ind(value, *, typ="domain", verdict="malicious", conf=0.9, group="grp:a", source="feed:a",
        first=T0 - timedelta(days=10), last=T0 - timedelta(days=1), exp=T0 + timedelta(days=30),
        label="c2_beaconing", iid=None):
    return {"indicator_id": iid or f"ind-{typ}-{value}-{verdict}-{source}", "type": typ, "value": value,
            "verdict": verdict, "threat_label": label if verdict == "malicious" else None,
            "malware_family": "fam" if verdict == "malicious" else None, "confidence": conf,
            "first_seen": iso(first), "last_seen": iso(last), "expires_at": iso(exp), "source": source,
            "source_group": group, "tags": [], "description": ""}


@pytest.fixture
def signer() -> Signer:
    return Signer.generate("ioc-k1")


@pytest.fixture
def ring(signer) -> KeyRing:
    r = KeyRing()
    r.add(signer.key_id, signer.public_pem())
    return r


def make_bundle(signer, indicators):
    raw = {"schema": BUNDLE_SCHEMA, "bundle_id": "b1", "version": "2026.10.01", "issuer": "test",
           "issued_at": iso(T0 - timedelta(hours=1)), "indicators": indicators}
    return sign_bundle(raw, signer)


def contacts(*, qnames=(), ips=(), answers=None, start=T0, end=T0 + timedelta(days=1)) -> ContactSummary:
    cs = ContactSummary("t1", "p_dev1", start, end)
    for q in qnames:
        cs._touch(cs.qnames, cs.qname_times, q, (T0 + timedelta(hours=1)).timestamp())
    for ip in ips:
        cs._touch(cs.dst_ips, cs.ip_times, ip, (T0 + timedelta(hours=2)).timestamp())
    for q, a in (answers or {}).items():
        cs.answers[q] = set(a)
    cs.authorization_ids.add("auth-1")
    return cs


# ------------------------------------------------------------------ loading / signatures

def test_lab_bundle_loads_and_verifies():
    from aegis.lab import generate_topology
    from aegis.lab.iocs import build_ioc_bundle
    s = lab_signer(7)
    ring = KeyRing()
    ring.add(s.key_id, s.public_pem())
    raw = build_ioc_bundle(generate_topology(7), start=T0, days=3, seed=7, signer=s)
    b = load_bundle(raw, ring)
    assert b.bundle_id == raw["bundle_id"] and len(b.indicators) == len(raw["indicators"])
    states = b.state_counts(T0)
    assert states["expired"] >= 2 and states["active"] > 5
    assert b.provenance()["sha256"] == b.sha256 and len(b.sha256) == 64
    # JSON text and bytes inputs work too
    assert load_bundle(json.dumps(raw), ring).sha256 == b.sha256
    assert load_bundle(json.dumps(raw).encode(), ring).sha256 == b.sha256


def test_bundle_from_path(tmp_path, signer, ring):
    p = tmp_path / "b.json"
    p.write_text(json.dumps(make_bundle(signer, [ind("bad.example")])))
    assert load_bundle(p, ring).indicators[0].value == "bad.example"


def test_tampered_bundle_rejected(signer, ring):
    raw = make_bundle(signer, [ind("bad.example")])
    raw["indicators"][0]["confidence"] = 0.1
    with pytest.raises(BundleSignatureError):
        load_bundle(raw, ring)


def test_unsigned_and_untrusted_and_revoked_rejected(signer, ring):
    raw = make_bundle(signer, [ind("bad.example")])
    unsigned = {k: v for k, v in raw.items() if k != "signature"}
    with pytest.raises(BundleSignatureError):
        load_bundle(unsigned, ring)
    with pytest.raises(BundleSignatureError):
        load_bundle(raw, KeyRing())
    other = Signer.generate("ioc-k1")          # same key id, different key
    with pytest.raises(BundleSignatureError):
        load_bundle(make_bundle(other, [ind("bad.example")]), ring)
    ring.revoke(signer.key_id)
    with pytest.raises(BundleSignatureError):
        load_bundle(raw, ring)


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(schema="other/1"),
    lambda b: b.update(indicators="nope"),
    lambda b: b["indicators"][0].update(type="url"),
    lambda b: b["indicators"][0].update(verdict="maybe"),
    lambda b: b["indicators"][0].update(confidence=1.5),
    lambda b: b["indicators"][0].update(first_seen="2026-10-01T00:00:00"),
    lambda b: b["indicators"][0].update(last_seen="2020-01-01T00:00:00Z"),
    lambda b: b["indicators"][0].update(value=""),
    lambda b: b["indicators"].append(copy.deepcopy(b["indicators"][0])),
])
def test_malformed_bundle_rejected_even_when_signed(signer, ring, mutate):
    raw = make_bundle(signer, [ind("bad.example")])
    unsigned = {k: v for k, v in raw.items() if k not in ("signature",)}
    mutate(unsigned)
    resigned = sign_bundle(unsigned, signer)
    with pytest.raises(BundleError):
        load_bundle(resigned, ring)


def test_non_json_rejected(ring):
    with pytest.raises(BundleError):
        load_bundle("{not json", ring)
    with pytest.raises(BundleError):
        load_bundle("[1, 2]", ring)


def test_indicator_states():
    i = Indicator.from_dict(ind("x.example", first=T0, last=T0 + timedelta(days=1), exp=T0 + timedelta(days=5)))
    assert i.state(T0 - timedelta(seconds=1)) == "not_yet_known"
    assert i.state(T0 + timedelta(days=2)) == "active"
    assert i.state(T0 + timedelta(days=5)) == "expired"
    old = Indicator.from_dict(ind("y.example", first=T0 - timedelta(days=400), last=T0 - timedelta(days=200),
                                  exp=T0 + timedelta(days=5)))
    assert old.state(T0) == "stale" and not old.is_active(T0)
    assert old.is_active(T0, max_staleness=timedelta(days=365))


# ------------------------------------------------------------------ matching

def test_fresh_domain_indicator_verified_contact(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("c2.bad.example")]), ring)
    cs = contacts(qnames=["c2.bad.example"], ips=["203.0.113.5"], answers={"c2.bad.example": ["203.0.113.5"]})
    ev = ioc_match(make_fv(), cs, b, NOW)
    assert len(ev) == 1
    e = ev[0]
    assert e.kind == EvidenceKind.IOC_MATCH and e.supports
    assert e.payload["verified_contact"] is True and e.payload["contradicted"] is False
    assert e.payload["effective_confidence"] == pytest.approx(0.9)
    assert e.payload["threat_labels"] == ["c2_beaconing"]
    assert e.source_independence_group == "grp:a" and e.authorization_id == "auth-1"
    assert e.payload["bundle"]["sha256"] == b.sha256
    assert "contacted c2.bad.example" in e.summary


def test_lookup_only_is_not_verified(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("c2.bad.example")]), ring)
    cs = contacts(qnames=["c2.bad.example"], answers={"c2.bad.example": ["203.0.113.5"]})
    (e,) = ioc_match(make_fv(), cs, b, NOW)
    assert e.payload["verified_contact"] is False and "looked up" in e.summary


def test_subdomain_matches_parent_indicator(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("bad.example")]), ring)
    (e,) = ioc_match(make_fv(), contacts(qnames=["cdn.x.bad.example"]), b, NOW)
    assert e.payload["matched"] == "cdn.x.bad.example" and e.payload["indicator_value"] == "bad.example"
    assert ioc_match(make_fv(), contacts(qnames=["notbad.example"]), b, NOW) == []


def test_ip_indicator_match(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("203.0.113.9", typ="ip", conf=0.8)]), ring)
    (e,) = ioc_match(make_fv(), contacts(ips=["203.0.113.9"]), b, NOW)
    assert e.payload["verified_contact"] is True and e.payload["contact_count"] == 1


def test_expired_stale_and_future_indicators_ignored(signer, ring):
    b = load_bundle(make_bundle(signer, [
        ind("expired.example", exp=T0),
        ind("stale.example", first=T0 - timedelta(days=500), last=T0 - timedelta(days=300)),
        ind("future.example", first=NOW + timedelta(hours=1), last=NOW + timedelta(hours=2)),
    ]), ring)
    cs = contacts(qnames=["expired.example", "stale.example", "future.example"])
    assert ioc_match(make_fv(), cs, b, NOW) == []
    # the future indicator becomes usable once it is known (contemporaneous evaluation)
    later = ioc_match(make_fv(), cs, b, NOW + timedelta(hours=3))
    assert [e.payload["indicator_value"] for e in later] == ["future.example"]


def test_contradicted_indicator_downgraded_with_counter_evidence(signer, ring):
    b = load_bundle(make_bundle(signer, [
        ind("cnc.example", conf=0.9, group="grp:alpha"),
        ind("cnc.example", verdict="benign", conf=0.4, group="grp:sinkhole", source="feed:sinkhole"),
    ]), ring)
    cs = contacts(qnames=["cnc.example"], ips=["203.0.113.7"], answers={"cnc.example": ["203.0.113.7"]})
    ev = ioc_match(make_fv(), cs, b, NOW)
    sup = [e for e in ev if e.supports]
    con = [e for e in ev if not e.supports]
    assert len(sup) == 1 and len(con) == 1
    assert sup[0].payload["contradicted"] is True
    assert sup[0].payload["effective_confidence"] == pytest.approx(0.9 * 0.6)
    assert sup[0].payload["contradicting_sources"] == ["feed:sinkhole"]
    assert con[0].kind == EvidenceKind.THREAT_FEED and con[0].source_independence_group == "grp:sinkhole"


def test_benign_claim_from_same_group_is_not_a_contradiction(signer, ring):
    b = load_bundle(make_bundle(signer, [
        ind("x.example", group="grp:a"),
        ind("x.example", verdict="benign", group="grp:a", source="feed:a2", conf=0.9),
    ]), ring)
    (e,) = ioc_match(make_fv(), contacts(qnames=["x.example"]), b, NOW)
    assert e.payload["contradicted"] is False


def test_overbroad_cdn_ip_contradicted_by_allowlist_is_dropped(signer, ring):
    b = load_bundle(make_bundle(signer, [
        ind("198.18.0.10", typ="ip", conf=0.5, group="grp:beta"),
        ind("198.18.0.10", typ="ip", verdict="benign", conf=0.95, group="grp:operator", source="feed:allow"),
    ]), ring)
    assert ioc_match(make_fv(), contacts(ips=["198.18.0.10"]), b, NOW) == []


def test_syndicated_copies_count_as_one_origin(signer, ring):
    b = load_bundle(make_bundle(signer, [
        ind("c2.example", group="grp:alpha", source="feed:alpha"),
        ind("c2.example", group="grp:alpha", source="feed:alpha_mirror"),
        ind("203.0.113.5", typ="ip", group="grp:alpha", source="feed:alpha"),
    ]), ring)
    cs = contacts(qnames=["c2.example"], ips=["203.0.113.5"], answers={"c2.example": ["203.0.113.5"]})
    ev = ioc_match(make_fv(), cs, b, NOW)
    assert len(ev) == 2                                   # one per matched value
    dom = next(e for e in ev if e.payload["indicator_type"] == "domain")
    assert dom.payload["sources"] == ["feed:alpha", "feed:alpha_mirror"]
    assert independent_origins(ev) == 1


def test_low_confidence_dropped(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("weak.example", conf=0.2)]), ring)
    assert ioc_match(make_fv(), contacts(qnames=["weak.example"]), b, NOW) == []
    assert len(ioc_match(make_fv(), contacts(qnames=["weak.example"]), b, NOW, min_confidence=0.1)) == 1


def test_match_from_raw_events_and_count_contacts(signer, ring):
    b = load_bundle(make_bundle(signer, [ind("c2.example"), ind("203.0.113.5", typ="ip")]), ring)
    evs = [dns_event(T0 + timedelta(hours=1), "c2.example", answers=["203.0.113.5"]),
           flow_event(T0 + timedelta(hours=1, seconds=1), dst="203.0.113.5"),
           flow_event(T0 + timedelta(hours=1), dst="203.0.113.5", entity="p_other")]
    fv = make_fv(window_end=T0 + timedelta(days=1))
    ev = ioc_match(fv, evs, b, NOW)
    assert {e.payload["indicator_value"] for e in ev} == {"c2.example", "203.0.113.5"}
    ip_ev = next(e for e in ev if e.payload["indicator_type"] == "ip")
    assert ip_ev.payload["contact_count"] == 1           # other entity's flow excluded
    cs = ContactSummary.from_events(evs, tenant_id="t1", entity_pseudonym="p_dev1", window_start=T0,
                                    window_end=T0 + timedelta(days=1))
    assert b.count_contacts(cs, NOW) == 2
    with pytest.raises(ValueError):
        ioc_match(fv, evs, b, datetime(2026, 10, 1))


def test_window_store_fills_ioc_contacts(signer, ring):
    from aegis.sentinel.features import WindowStore
    b = load_bundle(make_bundle(signer, [ind("c2.example")]), ring)
    store = WindowStore("15m", ioc_bundle=b)
    store.update(dns_event(T0 + timedelta(minutes=1), "c2.example"))
    (fv,) = store.flush(T0 + timedelta(minutes=15))
    assert fv.values["ioc_contacts"] == 1.0 and fv.missing["ioc_contacts"] is False


def test_timezone_parsing_normalizes_to_utc(signer, ring):
    i = ind("tz.example")
    i["first_seen"] = "2026-09-20T02:00:00+02:00"
    b = load_bundle(make_bundle(signer, [i]), ring)
    assert b.indicators[0].first_seen == datetime(2026, 9, 20, tzinfo=timezone.utc)
