import pytest

from aegis.ingest.pseudonym import (
    PSEUDONYM_PREFIX,
    Pseudonymizer,
    TenantKeyProvider,
    is_pseudonym,
    normalize_identifier,
)


def test_pseudonym_shape_and_determinism():
    p = Pseudonymizer(b"k" * 32)
    a = p.pseudonym("02:aa:bb:cc:dd:ee")
    assert a.startswith(PSEUDONYM_PREFIX) and len(a) == 34
    assert is_pseudonym(a)
    assert p.pseudonym("02:aa:bb:cc:dd:ee") == a
    assert Pseudonymizer(b"k" * 32).pseudonym("02:aa:bb:cc:dd:ee") == a


def test_equivalent_spellings_collapse():
    p = Pseudonymizer(b"k" * 32)
    mac = p.pseudonym("02:aa:bb:cc:dd:ee")
    assert p.pseudonym("02-AA-BB-CC-DD-EE") == mac
    assert p.pseudonym("02aa.bbcc.ddee") == mac
    assert p.pseudonym(" 02aabbccddee ") == mac
    assert p.pseudonym("2001:db8:0:0:0:0:0:1") == p.pseudonym("2001:DB8::1")


def test_tenant_keys_isolate_pseudonyms():
    assert Pseudonymizer(b"a" * 32).pseudonym("x") != Pseudonymizer(b"b" * 32).pseudonym("x")
    prov = TenantKeyProvider(b"m" * 32)
    assert prov.pseudonymizer("t1").pseudonym("x") != prov.pseudonymizer("t2").pseudonym("x")
    assert prov.pseudonymizer("t1") is prov.pseudonymizer("t1")
    assert prov.key_for("t1") == TenantKeyProvider(b"m" * 32).key_for("t1")


def test_pseudonym_does_not_contain_identifier():
    p = Pseudonymizer(b"k" * 32)
    ident = "100.64.0.1"
    assert ident not in p.pseudonym(ident)


@pytest.mark.parametrize("bad", [b"short", "notbytes"])
def test_rejects_weak_keys(bad):
    with pytest.raises(ValueError):
        Pseudonymizer(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("ident", ["", "   ", None, 5])
def test_rejects_empty_identifiers(ident):
    with pytest.raises(ValueError):
        Pseudonymizer(b"k" * 32).pseudonym(ident)  # type: ignore[arg-type]


def test_explicit_tenant_key_overrides_derivation():
    prov = TenantKeyProvider(b"m" * 32)
    before = prov.pseudonymizer("t1").pseudonym("x")
    prov.set_tenant_key("t1", b"z" * 32)
    assert prov.pseudonymizer("t1").pseudonym("x") == Pseudonymizer(b"z" * 32).pseudonym("x") != before
    with pytest.raises(ValueError):
        prov.set_tenant_key("t1", b"short")
    with pytest.raises(ValueError):
        prov.key_for("")


def test_from_env(monkeypatch):
    prov = TenantKeyProvider.from_env({"AEGIS_PSEUDONYM_MASTER_KEY": "ab" * 32})
    assert prov.key_for("t") == TenantKeyProvider(bytes.fromhex("ab" * 32)).key_for("t")
    with pytest.raises(ValueError):
        TenantKeyProvider.from_env({"AEGIS_PSEUDONYM_MASTER_KEY": "zz"})
    with pytest.raises(RuntimeError):
        TenantKeyProvider.from_env({"AEGIS_ENV": "production"})
    dev = TenantKeyProvider.from_env({})
    assert dev.pseudonymizer("t").pseudonym("x").startswith("p_")


def test_normalize_identifier_and_fingerprint():
    assert normalize_identifier("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_identifier("Router-17") == "router-17"
    fp = Pseudonymizer(b"k" * 32).key_fingerprint
    assert len(fp) == 16 and fp != Pseudonymizer(b"j" * 32).key_fingerprint


def test_is_pseudonym_rejects_raw_identifiers():
    assert not is_pseudonym("02:aa:bb:cc:dd:ee")
    assert not is_pseudonym("p_xyz")
    assert not is_pseudonym(None)
    assert not is_pseudonym("p_" + "A" * 32)
