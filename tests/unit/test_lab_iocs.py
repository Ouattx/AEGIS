from datetime import datetime, timedelta, timezone

import pytest

from aegis.lab.iocs import BUNDLE_SCHEMA, build_ioc_bundle, bundle_signing_bytes, lab_signer, sign_bundle, verify_bundle
from aegis.lab.topology import generate_topology
from aegis.provenance.signing import KeyRing, Signer

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def keyring_for(signer):
    kr = KeyRing()
    kr.add(signer.key_id, signer.public_pem())
    return kr


@pytest.fixture(scope="module")
def topo():
    return generate_topology(7)


@pytest.fixture(scope="module")
def bundle(topo):
    return build_ioc_bundle(topo, start=START, days=3, seed=7)


def _parse(s):
    return datetime.fromisoformat(s)


def test_signed_and_tamper_evident(bundle):
    signer = lab_signer(7)
    kr = keyring_for(signer)
    assert bundle["schema"] == BUNDLE_SCHEMA and bundle["signer_key_id"] == signer.key_id
    assert verify_bundle(bundle, kr)
    tampered = dict(bundle, indicators=bundle["indicators"][1:])
    assert not verify_bundle(tampered, kr)
    swapped = dict(bundle, signer_key_id="someone-else")
    assert not verify_bundle(swapped, kr)
    kr.revoke(signer.key_id)
    assert not verify_bundle(bundle, kr)
    assert not verify_bundle({k: v for k, v in bundle.items() if k != "signature"}, keyring_for(signer))


def test_deterministic_and_custom_signer(topo, bundle):
    assert build_ioc_bundle(topo, start=START, days=3, seed=7) == bundle
    other = Signer.generate("ops-key")
    b2 = build_ioc_bundle(topo, start=START, days=3, seed=7, signer=other)
    assert verify_bundle(b2, keyring_for(other)) and not verify_bundle(b2, keyring_for(lab_signer(7)))
    resigned = sign_bundle(b2, lab_signer(7))
    assert verify_bundle(resigned, keyring_for(lab_signer(7)))
    assert b'"signature"' not in bundle_signing_bytes(bundle) and b'"signer_key_id"' in bundle_signing_bytes(bundle)
    with pytest.raises(ValueError):
        build_ioc_bundle(topo, start=datetime(2026, 10, 1))


def test_indicator_fields(bundle):
    required = {"indicator_id", "type", "value", "verdict", "threat_label", "malware_family", "confidence",
                "first_seen", "last_seen", "expires_at", "source", "source_group", "tags", "description"}
    for ind in bundle["indicators"]:
        assert set(ind) == required
        assert ind["type"] in ("domain", "ip") and ind["verdict"] in ("malicious", "benign")
        assert 0 <= ind["confidence"] <= 1
        assert _parse(ind["first_seen"]) <= _parse(ind["last_seen"])
        assert _parse(ind["expires_at"]).tzinfo is not None
    ids = [i["indicator_id"] for i in bundle["indicators"]]
    assert len(ids) == len(set(ids))


def test_hard_cases_present(topo, bundle):
    inds = bundle["indicators"]
    stale = [i for i in inds if _parse(i["expires_at"]) < START]
    assert stale and any(i["value"] == topo.services["push"][0].ip for i in stale)
    by_value: dict[str, set[str]] = {}
    for i in inds:
        by_value.setdefault(i["value"], set()).add(i["verdict"])
    contradicted = [v for v, verdicts in by_value.items() if verdicts == {"malicious", "benign"}]
    shared_ip = topo.resolve(topo.malicious["badbox2_emu"].cohosted_domains[0])[0]
    assert shared_ip in contradicted and "cnc.botnet-ctl.test" in contradicted
    # syndicated duplicates share one independence group
    alpha = [i for i in inds if i["value"] == "api.tvsync-update.example"]
    assert len({i["source"] for i in alpha}) == 2 and len({i["source_group"] for i in alpha}) == 1


def test_novel_infrastructure_is_not_published(topo, bundle):
    values = {i["value"] for i in bundle["indicators"]}
    for fam in topo.malicious.values():
        for ip in fam.novel_ips:
            assert ip not in values
    assert "upd2.tvsync-cdn.example" not in values


def test_fresh_indicators_cover_the_corpus_window(bundle):
    end = START + timedelta(days=3)
    fresh = [i for i in bundle["indicators"] if i["verdict"] == "malicious" and _parse(i["expires_at"]) > end]
    assert any(i["threat_label"] == "dga_activity" for i in fresh)
    assert any(i["threat_label"] == "ddos_bot" for i in fresh)
    assert any(i["threat_label"] == "residential_proxy" for i in fresh)
