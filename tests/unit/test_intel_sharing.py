"""Consortium sharing: opt-in, keyed-hash indicators, no leaks, DP budgets, k-anonymity, PSI."""
from __future__ import annotations

import json
import math
import re
from fractions import Fraction

import pytest

from aegis.intel import (
    BudgetExceeded,
    ConsortiumIndex,
    ConsortiumKey,
    DocStoreBudgetStore,
    PrivacyAccountant,
    PSIError,
    PSIParty,
    SeededRandom,
    SharingDisabled,
    SharingError,
    SharingPolicy,
    ThreatIntelHub,
    build_indicator_package,
    campaign_indicators,
    release_campaign_counts,
    verify_package,
    verify_release,
)
from aegis.intel.dp import gaussian_sigma, noise_tail_bound, sample_discrete_gaussian, sample_discrete_laplace
from aegis.intel.psi import P, hash_to_group
from aegis.intel.sharing import assert_no_leak
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory
from test_intel_helpers import FIXTURES, NOW, SUBSCRIBER_SPACE, TENANT, campaign, dns, flow, loaded_store

SECRET = bytes(range(48))
PSEUDONYM = re.compile(r"p_[0-9a-f]{32}")


def key(epoch: str = "2026-10") -> ConsortiumKey:
    return ConsortiumKey("consortium-eu-1", SECRET, epoch)


def policy(tenant: str = TENANT, **kw) -> SharingPolicy:
    base = dict(tenant_id=tenant, enabled=True, share_indicators=True, share_aggregates=True,
                member_id=f"member-{tenant}", own_networks=(SUBSCRIBER_SPACE,), k_min=10,
                epsilon_per_release=0.4)
    base.update(kw)
    return SharingPolicy(**base)


def keyring(*signers: Signer) -> KeyRing:
    kr = KeyRing()
    for s in signers:
        kr.add_signer(s)
    return kr


@pytest.fixture()
def storage(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'intel.db'}")
    init_db(eng)
    sf = make_session_factory(eng)
    return DocStore(sf), Ledger(sf)


def lines(n: int, salt: str = "a") -> list[str]:
    return [f"p_{salt * 8}{i:024x}" for i in range(n)]


def local_campaigns():
    return [
        campaign(["d:beacon.novel-c2.example"], lines(40), cid="rc-novel", destination_ips=["192.0.2.66"]),
        # an infected line acting as relay: destination inside the operator's own subscriber space
        campaign(["ip:198.18.20.5"], lines(12, "b"), cid="rc-own-space"),
    ]


# ---------------------------------------------------------------------------- opt-in

def test_sharing_is_off_by_default_and_requires_explicit_consent():
    hub = ThreatIntelHub()
    hub.store(TENANT)
    signer = Signer.generate("member-signer")
    with pytest.raises(SharingDisabled):
        hub.share_indicators(TENANT, key(), signer, now=NOW, actor="a")
    with pytest.raises(SharingDisabled):
        hub.release_campaign_counts(TENANT, [], key(), signer, now=NOW, actor="a")
    st = loaded_store()
    with pytest.raises(SharingDisabled):
        build_indicator_package(st, policy(share_indicators=False), key(), signer, now=NOW)
    with pytest.raises(SharingDisabled):
        build_indicator_package(st, policy(member_id=""), key(), signer, now=NOW)
    with pytest.raises(SharingDisabled):
        build_indicator_package(st, policy(member_id="p_" + "0" * 32), key(), signer, now=NOW)
    with pytest.raises(PermissionError):
        build_indicator_package(st, policy(tenant="someone-else"), key(), signer, now=NOW)
    with pytest.raises(ValueError):
        ConsortiumKey("k", b"short", "e")
    assert "SECRET" not in repr(key()) and SECRET.hex() not in repr(key())


# ---------------------------------------------------------------------------- packages

def _package(**pol):
    st = loaded_store()
    st.add_indicators(campaign_indicators(local_campaigns(), TENANT, now=NOW))
    signer = Signer.generate("member-a")
    pkg, rep = build_indicator_package(st, policy(**pol), key(), signer, now=NOW,
                                       verified_local=[("domain", "beacon.novel-c2.example"),
                                                       ("ip", "192.0.2.66"), ("ip", "198.18.20.5")])
    return st, signer, pkg, rep


def test_package_never_contains_raw_values_pseudonyms_or_subscriber_data():
    st, signer, pkg, rep = _package()
    text = pkg.model_dump_json(by_alias=True)
    for ind in st.indicators():
        assert ind.value not in text, ind.value
    for v in st.victims():
        assert v.line_pseudonym not in text
    assert not PSEUDONYM.search(text)
    assert "198.18." not in text                          # no subscriber address, not even hashed raw text
    assert "rc-novel" not in text and "rc-own-space" not in text   # no campaign ids (tenant-derived)
    for c in local_campaigns():
        for ln in c.member_lines:
            assert ln not in text
    assert all(re.fullmatch(r"t1:[0-9a-f]{32}", e.token) for e in pkg.entries)


def test_package_gating_license_own_space_and_verification():
    st, signer, pkg, rep = _package()
    k = key()
    toks = {e.token for e in pkg.entries}
    assert k.token("domain", "beacon.novel-c2.example") in toks       # verified local detection
    assert k.token("ip", "192.0.2.66") in toks                         # outside subscriber space
    assert k.token("ip", "198.18.20.5") not in toks                    # inside subscriber space: never
    assert k.token("ip", "192.0.2.15") in toks                         # CC0 Feodo indicator
    assert k.token("cidr", "198.51.100.0/24") not in toks              # Spamhaus: not redistributable
    assert k.token("domain", "ping.badbox.example") not in toks        # Shadowserver: recipient only
    assert k.token("domain", "old-c2.legacy.example") not in toks      # expired
    assert rep.withheld["license"] >= 4 and rep.withheld["own_address_space"] == 1
    entry = next(e for e in pkg.entries if e.token == k.token("ip", "192.0.2.15"))
    assert entry.origin_groups == ["grp:abuse.ch"] and entry.first_seen_day == "2026-09-01"
    local = next(e for e in pkg.entries if e.token == k.token("domain", "beacon.novel-c2.example"))
    assert local.origin_groups == ["member"]


def test_unverified_local_detections_and_unconfigured_space_are_withheld():
    st = loaded_store()
    st.add_indicators(campaign_indicators(local_campaigns(), TENANT, now=NOW))
    signer = Signer.generate("member-a")
    pkg, rep = build_indicator_package(st, policy(), key(), signer, now=NOW)
    assert key().token("domain", "beacon.novel-c2.example") not in {e.token for e in pkg.entries}
    assert rep.withheld["unverified_local_detection"] >= 1
    pkg2, rep2 = build_indicator_package(st, policy(own_networks=(), share_unverified_detections=True), key(),
                                         signer, now=NOW)
    toks = {e.token for e in pkg2.entries}
    assert key().token("ip", "192.0.2.66") not in toks and key().token("ip", "198.18.20.5") not in toks
    assert rep2.withheld["own_networks_unconfigured"] >= 2
    assert key().token("domain", "beacon.novel-c2.example") in toks


def test_signature_epoch_and_tamper_checks():
    st, signer, pkg, rep = _package()
    kr = keyring(signer)
    assert verify_package(pkg.model_dump(mode="json", by_alias=True), kr, key()).package_id == pkg.package_id
    with pytest.raises(SharingError):
        verify_package(pkg, kr, key("2026-11"))
    forged = pkg.model_copy(update={"publisher": "member-evil"})
    with pytest.raises(SharingError):
        verify_package(forged, kr, key())
    with pytest.raises(SharingError):
        verify_package(pkg, keyring(Signer.generate("other")), key())


def test_cross_operator_matching_reveals_only_what_the_receiver_holds():
    _, signer_a, pkg_a, _ = _package()
    # operator B holds an overlapping public indicator and saw the novel C2 in its own traffic
    st_b = loaded_store(tenant="t-b")
    idx = ConsortiumIndex(key(), own_member_id="member-t-b")
    assert idx.add(verify_package(pkg_a, keyring(signer_a), key())) == len(pkg_a.entries)
    sightings = {(s.type, s.value): s for s in idx.match_indicators(st_b, NOW)}
    feodo = sightings[("ip", "192.0.2.15")]
    assert feodo.publishers == ["member-t-intel"] and feodo.origin_groups == ["grp:abuse.ch"]
    assert feodo.independent_origins == 1                 # a public feed re-shared is still one origin
    obs = [dns(NOW, "p_" + "1" * 32, "x.beacon.novel-c2.example", tenant="t-b"),
           flow(NOW, "p_" + "1" * 32, "192.0.2.66", tenant="t-b"),
           flow(NOW, "p_" + "1" * 32, "198.51.99.9", tenant="t-b")]
    hits = {(s.type, s.value): s for s in idx.match_observations(obs, "t-b")}
    assert set(hits) == {("domain", "beacon.novel-c2.example"), ("ip", "192.0.2.66")}
    assert hits[("domain", "beacon.novel-c2.example")].origin_groups == ["member:member-t-intel"]
    with pytest.raises(ValueError):
        idx.match_observations([flow(NOW, "p_x", "192.0.2.66", tenant="t-c")], "t-b")
    # an outsider with a different key learns nothing from the package
    outsider = ConsortiumIndex(ConsortiumKey("consortium-eu-1", bytes(48), "2026-10"), own_member_id="x")
    outsider.add(pkg_a)
    assert outsider.match_indicators(st_b, NOW) == []
    # own packages are ignored (no self-corroboration)
    assert ConsortiumIndex(key(), own_member_id="member-t-intel").add(pkg_a) == 0


def test_leak_guard_catches_planted_values():
    st, signer, pkg, _ = _package()
    planted = pkg.model_copy(update={"publisher": "member 192.0.2.15"})
    with pytest.raises(SharingError):
        assert_no_leak(planted, st)
    planted2 = pkg.model_copy(update={"publisher": "p_" + "e" * 32})
    with pytest.raises(SharingError):
        assert_no_leak(planted2)
    planted3 = pkg.model_copy(update={"publisher": "via-sub.c2.vo1d-emu.example"})
    with pytest.raises(SharingError):
        assert_no_leak(planted3, st)                      # a raw value hidden as a host-name suffix
    planted4 = pkg.model_copy(update={"publisher": "net 198.51.100.0/24"})
    with pytest.raises(SharingError):
        assert_no_leak(planted4, st)
    assert_no_leak(pkg, st)                               # the real package is clean


# ---------------------------------------------------------------------------- DP mechanisms

def test_discrete_laplace_matches_its_distribution():
    rng = SeededRandom(1)
    b = Fraction(2)
    xs = [sample_discrete_laplace(b, rng) for _ in range(6000)]
    r = math.exp(-1 / 2)
    var = 2 * r / (1 - r) ** 2
    mean = sum(xs) / len(xs)
    emp_var = sum((x - mean) ** 2 for x in xs) / len(xs)
    assert abs(mean) < 0.15
    assert emp_var == pytest.approx(var, rel=0.08)
    assert all(isinstance(x, int) for x in xs)


def test_discrete_gaussian_matches_its_variance():
    rng = SeededRandom(2)
    xs = [sample_discrete_gaussian(Fraction(9), rng) for _ in range(4000)]
    mean = sum(xs) / len(xs)
    emp_var = sum((x - mean) ** 2 for x in xs) / len(xs)
    assert abs(mean) < 0.2 and emp_var == pytest.approx(9.0, rel=0.08)


def test_gaussian_calibration_inverts_the_zcdp_conversion():
    for eps, delta in ((0.5, 1e-6), (1.0, 1e-5), (3.0, 1e-7)):
        sigma = gaussian_sigma(eps, delta, 1.0)
        rho = 1.0 / (2 * sigma ** 2)
        assert rho + 2 * math.sqrt(rho * math.log(1 / delta)) == pytest.approx(eps, rel=1e-9)
    assert noise_tail_bound("laplace", 0.5, 0.0, 1, 1e-6) == math.ceil(2 * math.log(1e6))
    with pytest.raises(ValueError):
        gaussian_sigma(0.0, 1e-6, 1.0)


# ---------------------------------------------------------------------------- budgets and releases

def test_budget_is_enforced_persisted_and_ledgered(storage):
    docs, ledger = storage
    acct = PrivacyAccountant(store=DocStoreBudgetStore(docs), ledger=ledger)
    acct.configure(TENANT, epsilon_total=1.0, delta_total=1e-5)
    signer = Signer.generate("member-a")
    camps = [campaign(["d:beacon.novel-c2.example"], lines(200), cid="rc-big")]
    pol = policy(epsilon_per_release=0.4)
    rng = SeededRandom(5)
    r1 = release_campaign_counts(camps, pol, acct, key(), signer, now=NOW, rng=rng)
    release_campaign_counts(camps, pol, acct, key(), signer, now=NOW, rng=rng)
    with pytest.raises(BudgetExceeded):
        release_campaign_counts(camps, pol, acct, key(), signer, now=NOW, rng=rng)
    eps_left, _ = acct.remaining(TENANT)
    assert eps_left == pytest.approx(0.2)
    # a fresh accountant on the same storage (e.g. after a restart) still refuses
    acct2 = PrivacyAccountant(store=DocStoreBudgetStore(docs))
    with pytest.raises(BudgetExceeded):
        release_campaign_counts(camps, pol, acct2, key(), signer, now=NOW, rng=rng)
    charges = ledger.entries(TENANT, entry_type="intel_dp_charge")
    assert len(charges) == 2 and charges[0].subject_id == r1.release_id
    # budgets only go up with explicit consent
    with pytest.raises(PermissionError):
        acct.configure(TENANT, epsilon_total=5.0, delta_total=1e-5)
    acct.configure(TENANT, epsilon_total=5.0, delta_total=1e-5, allow_increase=True, actor="dpo@op")
    assert ledger.entries(TENANT, entry_type="intel_dp_budget_change")
    release_campaign_counts(camps, pol, acct, key(), signer, now=NOW, rng=rng)


def test_unconfigured_budget_fails_closed():
    acct = PrivacyAccountant()
    with pytest.raises(BudgetExceeded):
        release_campaign_counts([campaign(["d:x.example"], lines(50))], policy(), acct, key(),
                                Signer.generate("s"), now=NOW)
    assert acct.remaining(TENANT) == (0.0, 0.0)


def test_release_k_anonymity_contribution_bound_and_no_leak():
    acct = PrivacyAccountant()
    acct.configure(TENANT, epsilon_total=10.0, delta_total=1e-3)
    signer = Signer.generate("member-a")
    shared_lines = lines(150)
    camps = [
        campaign(["d:big-a.example"], shared_lines, cid="rc-a"),
        campaign(["d:big-b.example", "ip:192.0.2.70"], shared_lines, cid="rc-b"),   # same lines, c=1
        campaign(["d:tiny.example"], lines(3, "c"), cid="rc-tiny"),                 # below k
        campaign(["d:cdn-only.example", "ip:192.0.2.71"], lines(80, "d"), cid="rc-cdn",
                 shared_hosting_domain=True),
    ]
    rel = release_campaign_counts(camps, policy(), acct, key(), signer, now=NOW, rng=SeededRandom(9))
    text = rel.model_dump_json(by_alias=True)
    assert not PSEUDONYM.search(text)
    for raw in ("big-a.example", "big-b.example", "tiny.example", "cdn-only.example", "192.0.2.70",
                "192.0.2.71", "rc-a", "rc-tiny"):
        assert raw not in text
    k = key()
    by_tok = {tuple(e.destination_tokens): e.noisy_count for e in rel.entries}
    assert (k.token("domain", "tiny.example"),) not in by_tok
    assert all(n >= rel.k_min for n in by_tok.values())
    # each line counts in at most one campaign: the two 150-line campaigns share ~150 lines between them
    a = by_tok.get((k.token("domain", "big-a.example"),), 0)
    b_key = tuple(sorted([k.token("domain", "big-b.example"), k.token("ip", "192.0.2.70")]))
    b = by_tok.get(b_key, 0)
    assert 110 <= a + b <= 190
    # shared-hosting campaign: domain token only, never the CDN IP
    assert (k.token("domain", "cdn-only.example"),) in by_tok
    assert rel.delta == pytest.approx(policy().threshold_beta)          # Laplace: delta is the threshold beta
    assert verify_release(rel.model_dump(mode="json", by_alias=True), keyring(signer)).release_id == rel.release_id
    with pytest.raises(SharingError):
        verify_release(rel.model_copy(update={"epsilon": 99.0}), keyring(signer))


def test_gaussian_release_charges_delta_plus_beta():
    acct = PrivacyAccountant()
    acct.configure(TENANT, epsilon_total=2.0, delta_total=1e-4)
    pol = policy(mechanism="gaussian", epsilon_per_release=1.0, delta_per_release=1e-6)
    rel = release_campaign_counts([campaign(["d:g.example"], lines(300))], pol, acct, key(),
                                  Signer.generate("s"), now=NOW, rng=SeededRandom(3))
    assert rel.mechanism == "gaussian" and rel.delta == pytest.approx(1e-6 + pol.threshold_beta)
    assert len(rel.entries) == 1 and abs(rel.entries[0].noisy_count - 300) < 40
    assert acct.remaining(TENANT)[0] == pytest.approx(1.0)


def test_hub_end_to_end_with_ledger(storage):
    docs, ledger = storage
    from test_intel_helpers import FEEDS, pseudonymizer
    hub = ThreatIntelHub(ledger=ledger, accountant=PrivacyAccountant(store=DocStoreBudgetStore(docs), ledger=ledger))
    for fid, fname, rt in FIXTURES:
        hub.import_feed(TENANT, fid, FEEDS / fname, now=NOW, actor="analyst@op", report_type=rt,
                        pseudonymizer=pseudonymizer())
    hub.allowlist(TENANT, ["cdn-edge.shared.example"], reason="shared CDN", now=NOW, actor="analyst@op")
    signer = Signer.generate("ioc-signer")
    bundle, rep = hub.build_bundle(TENANT, signer, now=NOW, issuer="operator-intel", actor="system")
    assert rep.included > 0
    assert hub.add_campaign_indicators(TENANT, local_campaigns(), now=NOW) >= 2
    hub.set_policy(policy(), actor="dpo@op")
    hub.accountant.configure(TENANT, epsilon_total=1.0, delta_total=1e-5)
    pkg, srep = hub.share_indicators(TENANT, key(), signer, now=NOW, actor="analyst@op")
    rel = hub.release_campaign_counts(TENANT, local_campaigns(), key(), signer, now=NOW, actor="analyst@op",
                                      rng=SeededRandom(1))
    status = hub.status(TENANT, NOW)
    assert status["sharing"]["enabled"] and status["dp_budget_remaining"]["epsilon"] == pytest.approx(0.6)
    assert status["fetching_enabled"] is False
    types = [e.entry_type for e in ledger.entries(TENANT)]
    for t in ("intel_feed_import", "intel_allowlist", "intel_bundle_built", "intel_sharing_policy", "intel_share",
              "intel_dp_charge", "intel_dp_release"):
        assert t in types, t
    assert ledger.verify_chain(TENANT)[0]
    ledger_text = json.dumps([e.payload for e in ledger.entries(TENANT)])
    assert not PSEUDONYM.search(ledger_text)            # victim pseudonyms are not echoed into the ledger
    assert rel.release_id and pkg.package_id
    # restore from a snapshot (as the composition root would after a restart)
    snap = hub.store(TENANT).snapshot()
    hub2 = ThreatIntelHub()
    hub2.restore(TENANT, snap)
    assert len(hub2.store(TENANT).indicators()) == len(hub.store(TENANT).indicators())


# ---------------------------------------------------------------------------- PSI

def test_dh_psi_learns_exactly_the_intersection():
    a_items = [("ip", "192.0.2.15"), ("domain", "beacon.novel-c2.example"), ("ip", "192.0.2.99")]
    b_items = [("ip", "192.0.2.15"), ("domain", "beacon.novel-c2.example"), ("domain", "other.example"),
               ("ip", "203.0.113.9")]
    a, b = PSIParty(a_items), PSIParty(b_items)
    msg1 = a.blinded()
    assert all("192.0.2" not in m and "example" not in m for m in msg1)
    reblinded, b_blinded = b.respond(msg1)
    assert sorted(a.intersect(reblinded, b_blinded)) == sorted([("ip", "192.0.2.15"),
                                                                ("domain", "beacon.novel-c2.example")])
    # blinded values differ between runs (fresh secret exponents): no linkage across sessions
    assert set(PSIParty(a_items).blinded()).isdisjoint(msg1)


def test_psi_rejects_invalid_elements_and_oversized_sets():
    a = PSIParty([("ip", "192.0.2.1")], max_items=2)
    bad_order = format(P - 1, "0512x")                  # order-2 element: small-subgroup attack
    with pytest.raises(PSIError):
        a.respond([bad_order])
    with pytest.raises(PSIError):
        a.respond(["zz"])
    with pytest.raises(PSIError):
        a.respond([a.blinded()[0]] * 3)
    with pytest.raises(PSIError):
        PSIParty([("ip", f"192.0.2.{i}") for i in range(5)], max_items=4)
    h = hash_to_group("ip", "192.0.2.1")
    assert pow(h, (P - 1) // 2, P) == 1
    with pytest.raises(PSIError):
        a.intersect([], [])


def test_campaign_indicators_respect_topology_and_tenancy():
    camps = [campaign(["d:x.example", "ip:192.0.2.5"], lines(10), cid="rc-1"),
             campaign(["d:y.example"], lines(10), cid="rc-2", topology_unknown=True),
             campaign(["d:z.example", "ip:192.0.2.6"], lines(10), cid="rc-3", shared_hosting_domain=True)]
    inds = campaign_indicators(camps, TENANT, now=NOW)
    assert {(i.type, i.value) for i in inds} == {("domain", "x.example"), ("ip", "192.0.2.5"),
                                                 ("domain", "z.example")}
    assert all(i.source_group == f"grp:operator:{TENANT}" and i.expires_at > NOW for i in inds)
    assert all(not PSEUDONYM.search(json.dumps(i.to_dict())) for i in inds)
    with pytest.raises(ValueError):
        campaign_indicators([campaign(["d:x.example"], lines(5), tenant="other")], TENANT, now=NOW)
