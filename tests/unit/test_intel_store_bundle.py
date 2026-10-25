from __future__ import annotations

import copy
import json
from datetime import timedelta

import pytest

from aegis.intel import IntelStore, build_ioc_bundle, get_spec, parse_feed
from aegis.intel.catalog import FeedSpec
from aegis.lab.iocs import lab_signer
from aegis.provenance.evidence import independent_origins
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.features import ContactSummary
from aegis.sentinel.rules import BundleSignatureError, ioc_match, load_bundle
from test_intel_helpers import FEEDS, NOW, TENANT, flow, loaded_store, dns
from test_sentinel_helpers import make_fv


def test_dedup_within_group_and_independent_groups_across_feeds():
    st = loaded_store()
    recs = [r for r in st.indicators() if r.value == "203.0.113.50"]
    # ThreatFox + Feodo (both abuse.ch) merge into one record; Shadowserver is a second origin
    assert {r.source_group for r in recs} == {"grp:abuse.ch", "grp:shadowserver"}
    abuse = next(r for r in recs if r.source_group == "grp:abuse.ch")
    assert set(abuse.sources) == {"feed:threatfox", "feed:feodo"}
    assert abuse.confidence == 0.9                       # max within a group, never summed
    assert st.independent_groups("ip", "203.0.113.50", NOW) == ["grp:abuse.ch", "grp:shadowserver"]
    dom = [r for r in st.indicators() if r.value == "update-cdn.badbox.example"]
    assert len(dom) == 1 and set(dom[0].sources) == {"feed:urlhaus", "feed:threatfox"}


def test_syndicated_copy_is_folded_into_the_original_group():
    st = IntelStore(TENANT)
    st.ingest(parse_feed(FEEDS / "urlhaus_recent.csv", get_spec("feed:urlhaus"), NOW), get_spec("feed:urlhaus"), NOW)
    mirror = FeedSpec("feed:aggregator_x", "aggregator republishing URLhaus", "urlhaus_csv", None, "CC0-1.0", True,
                      "grp:aggregator_x", 0.9, timedelta(days=30), snapshot=False)
    rep = st.ingest(parse_feed(FEEDS / "urlhaus_recent.csv", mirror, NOW), mirror, NOW)
    assert rep.syndicated == 3 and rep.added == 0
    rec = next(r for r in st.indicators() if r.value == "198.51.100.23")
    assert rec.source_group == "grp:abuse.ch" and rec.syndicated_groups == ("grp:aggregator_x",)
    assert st.independent_groups("ip", "198.51.100.23", NOW) == ["grp:abuse.ch"]
    assert not any(r.source_group == "grp:aggregator_x" for r in st.indicators())


def test_snapshot_feed_withdrawal_and_reinstatement():
    spec = get_spec("feed:feodo")
    st = IntelStore(TENANT)
    full = (FEEDS / "feodo_ipblocklist.csv").read_text()
    st.ingest(parse_feed(full, spec, NOW), spec, NOW)
    later = NOW + timedelta(hours=6)
    without = "\n".join(ln for ln in full.splitlines() if "192.0.2.16" not in ln)
    rep = st.ingest(parse_feed(without, spec, later), spec, later)
    assert rep.withdrawn == 1
    rec = next(r for r in st.indicators() if r.value == "192.0.2.16")
    assert rec.state(later) == "withdrawn" and rec.state(NOW) == "active"
    again = later + timedelta(hours=6)
    rep2 = st.ingest(parse_feed(full, spec, again), spec, again)
    assert rep2.reinstated == 1
    assert next(r for r in st.indicators() if r.value == "192.0.2.16").state(again) == "active"


def test_contradictions_from_allowlist_and_new_contradiction_report():
    st = loaded_store()
    assert st.contradictions(NOW) == []
    st.add_allowlist(["cdn-edge.shared.example", "198.51.100.0/24"], reason="shared CDN edge", now=NOW)
    cons = {(c.type, c.value): c for c in st.contradictions(NOW)}
    assert ("domain", "cdn-edge.shared.example") in cons
    c = cons[("cidr", "198.51.100.0/24")]
    assert c.malicious_groups == ("grp:spamhaus",) and c.benign_groups == ("grp:operator",)
    with pytest.raises(ValueError):
        st.add_allowlist(["10.0.0.1"], reason="x", now=NOW)


def test_snapshot_round_trip_and_tenant_binding():
    st = loaded_store()
    snap = json.loads(json.dumps(st.snapshot()))
    back = IntelStore.from_snapshot(snap, tenant_id=TENANT)
    assert [r.to_dict() for r in back.indicators()] == [r.to_dict() for r in st.indicators()]
    assert len(back.victims()) == len(st.victims())
    with pytest.raises(PermissionError):
        IntelStore.from_snapshot(snap, tenant_id="other-tenant")
    assert back.status(NOW)["indicators"] == len(st.indicators())


def test_import_rejects_mismatched_spec():
    r = parse_feed(FEEDS / "feodo_ipblocklist.txt", get_spec("feed:feodo_txt"), NOW)
    with pytest.raises(ValueError):
        IntelStore(TENANT).ingest(r, get_spec("feed:feodo"), NOW)


# ---------------------------------------------------------------------------- bundles

def _keyring(signer: Signer) -> KeyRing:
    kr = KeyRing()
    kr.add_signer(signer)
    return kr


def test_bundle_loads_in_sentinel_and_matches_traffic():
    st = loaded_store()
    signer = lab_signer(11)
    bundle, rep = build_ioc_bundle(st, signer, now=NOW, issuer="operator-intel")
    loaded = load_bundle(bundle, _keyring(signer))
    assert loaded.bundle_id == rep.bundle_id and len(loaded.indicators) == rep.included
    assert rep.excluded["cidr_not_representable"] == 4
    assert rep.excluded["state:expired"] >= 2            # old ThreatFox domain + offline Feodo C2
    assert {i.type for i in loaded.indicators} == {"domain", "ip"}
    # SENTINEL's matcher counts abuse.ch and Shadowserver as two independent origins
    fv = make_fv(entity="p_line1", window_end=NOW, tenant=TENANT)
    events = [flow(NOW - timedelta(hours=1), "p_line1", "203.0.113.50")]
    cs = ContactSummary.from_events(events, tenant_id=TENANT, entity_pseudonym="p_line1",
                                    window_start=NOW - timedelta(days=1), window_end=NOW)
    ev = ioc_match(fv, cs, loaded, NOW)
    assert independent_origins([e for e in ev if e.supports]) == 2


def test_bundle_is_deterministic_and_tamper_evident():
    st = loaded_store()
    signer = lab_signer(11)
    b1, r1 = build_ioc_bundle(st, signer, now=NOW, issuer="operator-intel", version="v1")
    b2, r2 = build_ioc_bundle(st, signer, now=NOW, issuer="operator-intel", version="v1")
    assert b1 == b2 and r1.sha256 == r2.sha256
    bad = copy.deepcopy(b1)
    bad["indicators"][0]["confidence"] = 0.01
    with pytest.raises(BundleSignatureError):
        load_bundle(bad, _keyring(signer))
    other = Signer.generate("someone-else")
    with pytest.raises(BundleSignatureError):
        load_bundle(b1, _keyring(other))


def test_bundle_cidr_expansion_and_limits():
    st = loaded_store()
    signer = lab_signer(11)
    b, rep = build_ioc_bundle(st, signer, now=NOW, issuer="x", cidr_expand_max=64)
    vals = {i["value"] for i in b["indicators"]}
    assert "192.0.2.130" in vals                          # from EDROP 192.0.2.128/26 (64 addresses)
    assert "198.51.100.77" not in vals                     # /24 too large to expand
    assert rep.excluded["cidr_not_representable"] == 3
    load_bundle(b, _keyring(signer))
    with pytest.raises(ValueError):
        build_ioc_bundle(st, signer, now=NOW, issuer="x", max_indicators=3)


def test_withdrawn_and_allowlisted_values_reach_sentinel_correctly():
    st = loaded_store()
    st.add_allowlist(["cdn-edge.shared.example"], reason="shared CDN", now=NOW)
    signer = lab_signer(3)
    b, _ = build_ioc_bundle(st, signer, now=NOW, issuer="x")
    loaded = load_bundle(b, _keyring(signer))
    fv = make_fv(entity="p_l", window_end=NOW, tenant=TENANT)
    events = [dns(NOW - timedelta(hours=1), "p_l", "cdn-edge.shared.example", ["192.0.2.80"]),
              flow(NOW - timedelta(minutes=59), "p_l", "192.0.2.80")]
    cs = ContactSummary.from_events(events, tenant_id=TENANT, entity_pseudonym="p_l",
                                    window_start=NOW - timedelta(days=1), window_end=NOW)
    ev = ioc_match(fv, cs, loaded, NOW)
    # 0.5 confidence * (1 - 0.95 allowlist) falls below SENTINEL's minimum: no accusation
    assert [e for e in ev if e.supports] == []


def test_docstore_persistence(tmp_path):
    from aegis.intel import load_store, save_store
    from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory
    eng = make_engine(f"sqlite:///{tmp_path / 'i.db'}")
    init_db(eng)
    docs = DocStore(make_session_factory(eng))
    st = loaded_store()
    save_store(docs, st)
    back = load_store(docs, TENANT)
    assert back is not None and len(back.indicators()) == len(st.indicators())
    assert load_store(docs, "other-tenant") is None
