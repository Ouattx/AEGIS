from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from aegis.contracts.models import ActionType, OperatorPolicy
from aegis.provenance.signing import (
    KeyRing,
    Signer,
    SigningKeyError,
    public_key_fingerprint,
    sign_model,
    verify_model,
)

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def _policy(**kw) -> OperatorPolicy:
    base = dict(policy_id="pol-1", tenant_id="t1", mode="shadow",
                allowed_actions=[ActionType.DNS_SINKHOLE], valid_from=NOW,
                valid_until=NOW + timedelta(days=30), signer_key_id="", signature="")
    base.update(kw)
    return OperatorPolicy(**base)


def test_sign_and_verify_roundtrip():
    s = Signer.generate("k1")
    ring = KeyRing()
    ring.add("k1", s.public_pem())
    sig = s.sign(b"hello")
    assert len(base64.b64decode(sig)) == 64
    assert ring.verify("k1", b"hello", sig)
    assert not ring.verify("k1", b"hellO", sig)


def test_verify_fails_closed_on_bad_inputs():
    s = Signer.generate("k1")
    ring = KeyRing()
    ring.add_signer(s)
    sig = s.sign(b"x")
    assert not ring.verify("unknown", b"x", sig)
    assert not ring.verify(None, b"x", sig)
    assert not ring.verify("k1", b"x", None)
    assert not ring.verify("k1", b"x", "")
    assert not ring.verify("k1", b"x", "not base64 !!")
    assert not ring.verify("k1", b"x", base64.b64encode(b"short").decode())
    other = Signer.generate("k2")
    assert not ring.verify("k1", b"x", other.sign(b"x"))


def test_revocation_is_permanent_and_retroactive():
    s = Signer.generate("k1")
    ring = KeyRing()
    ring.add_signer(s)
    old_sig = s.sign(b"signed before compromise")
    ring.revoke("k1")
    assert ring.is_revoked("k1")
    assert not ring.is_trusted("k1")
    assert not ring.verify("k1", b"signed before compromise", old_sig)
    assert ring.public_pem("k1") is None
    with pytest.raises(SigningKeyError):
        ring.add("k1", s.public_pem())
    # revoking an unknown id blocks it from ever being added
    ring.revoke("future")
    with pytest.raises(SigningKeyError):
        ring.add("future", Signer.generate("future").public_pem())


def test_key_id_cannot_be_rebound():
    ring = KeyRing()
    a, b = Signer.generate("k"), Signer.generate("k")
    ring.add("k", a.public_pem())
    ring.add("k", a.public_pem())  # idempotent
    with pytest.raises(SigningKeyError):
        ring.add("k", b.public_pem())


def test_pem_roundtrip_and_encrypted_export():
    s = Signer.generate("k1")
    s2 = Signer.from_private_pem("k1", s.private_pem())
    assert s2.public_pem() == s.public_pem()
    enc = s.private_pem(password=b"pw")
    assert b"ENCRYPTED" in enc
    s3 = Signer.from_private_pem("k1", enc, password=b"pw")
    assert s3.fingerprint() == s.fingerprint() == public_key_fingerprint(s.public_pem())
    with pytest.raises(SigningKeyError):
        Signer.from_private_pem("k1", b"garbage")
    assert "PRIVATE" not in repr(s)


def test_rejects_non_ed25519_keys_and_bad_ids():
    ec = generate_private_key(SECP256R1())
    ec_priv = ec.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    ec_pub = ec.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(SigningKeyError):
        Signer.from_private_pem("k", ec_priv)
    with pytest.raises(SigningKeyError):
        KeyRing().add("k", ec_pub)
    with pytest.raises(SigningKeyError):
        Signer.generate("")
    with pytest.raises(SigningKeyError):
        KeyRing().add("x" * 200, Signer.generate("ok").public_pem())
    with pytest.raises(TypeError):
        Signer.generate("k").sign("text")  # type: ignore[arg-type]


def test_keyring_export_roundtrip_keeps_revocations():
    a, b = Signer.generate("a"), Signer.generate("b")
    ring = KeyRing()
    ring.add_signer(a)
    ring.add_signer(b)
    ring.revoke("b")
    data = ring.export()
    assert set(data["keys"]) == {"a"}  # type: ignore[arg-type]
    ring2 = KeyRing.from_export(data)
    assert ring2.key_ids() == ["a"]
    assert ring2.revoked_ids() == ["b"]
    assert ring2.verify("a", b"m", a.sign(b"m"))
    assert not ring2.verify("b", b"m", b.sign(b"m"))
    with pytest.raises(SigningKeyError):
        KeyRing.from_export({"keys": [], "revoked": "x"})


def test_sign_model_sets_key_id_and_verifies():
    s = Signer.generate("ops-2026")
    ring = KeyRing()
    ring.add_signer(s)
    unsigned = _policy()
    signed = sign_model(unsigned, s)
    assert unsigned.signature == "" and unsigned.signer_key_id == ""  # original untouched
    assert signed.signer_key_id == "ops-2026"
    assert verify_model(signed, ring)


@pytest.mark.parametrize("change", [
    {"mode": "active"},
    {"max_targets_per_action": 1000},
    {"valid_until": NOW + timedelta(days=3650)},
    {"allowed_actions": [ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK]},
    {"tenant_id": "t2"},
    {"legal_signoff_ref": "forged"},
])
def test_verify_model_detects_any_field_change(change):
    s = Signer.generate("k1")
    ring = KeyRing()
    ring.add_signer(s)
    signed = sign_model(_policy(), s)
    tampered = signed.model_copy(update=change)
    assert not verify_model(tampered, ring)


def test_verify_model_key_swap_and_revocation():
    a, b = Signer.generate("a"), Signer.generate("b")
    ring = KeyRing()
    ring.add_signer(a)
    ring.add_signer(b)
    signed = sign_model(_policy(), a)
    assert not verify_model(signed.model_copy(update={"signer_key_id": "b"}), ring)
    assert not verify_model(signed.model_copy(update={"signature": ""}), ring)
    ring.revoke("a")
    assert not verify_model(signed, ring)


def test_verify_model_survives_json_roundtrip():
    s = Signer.generate("k1")
    ring = KeyRing()
    ring.add_signer(s)
    signed = sign_model(_policy(valid_from=datetime(2026, 1, 1, 14, tzinfo=timezone(timedelta(hours=2)))), s)
    restored = OperatorPolicy.model_validate_json(signed.model_dump_json())
    assert verify_model(restored, ring)


def test_sign_model_requires_signature_field():
    from pydantic import BaseModel

    class NoSig(BaseModel):
        x: int

    with pytest.raises(ValueError):
        sign_model(NoSig(x=1), Signer.generate("k"))
    assert not verify_model(NoSig(x=1), KeyRing())
