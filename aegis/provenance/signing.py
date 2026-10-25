"""Ed25519 signing, key rings with revocation, and signed contract models.

Signatures are base64 (standard alphabet) Ed25519 signatures. A ``KeyRing`` holds
only public keys. Revocation is permanent and fail closed: once a key id is revoked
(for example because the private key was compromised) every signature made with it
verifies as ``False``, including signatures made before the revocation, because an
attacker holding a compromised key can back-date anything. Records signed with a
revoked key must be re-attested with a fresh key.

Model signatures cover the RFC 8785 canonical JSON of the model with the signature
field removed. The signer key id field (when the model has one) is set before
signing, so it is covered by the signature and cannot be swapped afterwards.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import threading
from typing import TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel

from aegis.contracts.canonical import canonical_bytes

M = TypeVar("M", bound=BaseModel)


class SigningKeyError(ValueError):
    """Raised for invalid key material or key ring misuse."""


def _check_key_id(key_id: str) -> str:
    if not isinstance(key_id, str) or not key_id.strip():
        raise SigningKeyError("key_id must be a non-empty string")
    if len(key_id) > 128:
        raise SigningKeyError("key_id must be at most 128 characters")
    return key_id


def public_key_fingerprint(public_pem: bytes) -> str:
    """SHA-256 hex fingerprint of the raw 32-byte Ed25519 public key."""
    key = _load_public(public_pem)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _load_public(public_pem: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError(f"invalid public key PEM: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError("public key is not an Ed25519 key")
    return key


class Signer:
    """An Ed25519 private key bound to a key id."""

    __slots__ = ("_key_id", "_private")

    def __init__(self, key_id: str, private_key: Ed25519PrivateKey):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SigningKeyError("private key is not an Ed25519 key")
        self._key_id = _check_key_id(key_id)
        self._private = private_key

    @classmethod
    def generate(cls, key_id: str) -> "Signer":
        return cls(key_id, Ed25519PrivateKey.generate())

    @classmethod
    def from_private_pem(cls, key_id: str, pem: bytes, password: bytes | None = None) -> "Signer":
        try:
            key = serialization.load_pem_private_key(pem, password=password)
        except (ValueError, TypeError) as exc:
            raise SigningKeyError(f"invalid private key PEM: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningKeyError("private key is not an Ed25519 key")
        return cls(key_id, key)

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, data: bytes) -> str:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("sign() requires bytes")
        return base64.b64encode(self._private.sign(bytes(data))).decode("ascii")

    def public_pem(self) -> bytes:
        return self._private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_pem(self, password: bytes | None = None) -> bytes:
        """Export the private key as PKCS#8 PEM (encrypted when ``password`` is given)."""
        enc: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )
        return self._private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
        )

    def fingerprint(self) -> str:
        return public_key_fingerprint(self.public_pem())

    def __repr__(self) -> str:  # never leak key material
        return f"Signer(key_id={self._key_id!r})"


class KeyRing:
    """Thread-safe set of trusted Ed25519 public keys with permanent revocation."""

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._pems: dict[str, bytes] = {}
        self._revoked: set[str] = set()
        self._lock = threading.RLock()

    def add(self, key_id: str, public_pem: bytes) -> None:
        """Trust ``public_pem`` under ``key_id``.

        Re-adding the identical key is a no-op. Re-using a key id for a different key,
        or re-adding a revoked key id, raises: key ids are never recycled.
        """
        _check_key_id(key_id)
        key = _load_public(public_pem)
        with self._lock:
            if key_id in self._revoked:
                raise SigningKeyError(f"key id {key_id!r} is revoked and cannot be re-added")
            existing = self._keys.get(key_id)
            if existing is not None:
                if _raw(existing) != _raw(key):
                    raise SigningKeyError(f"key id {key_id!r} is already bound to a different key")
                return
            self._keys[key_id] = key
            self._pems[key_id] = public_pem

    def add_signer(self, signer: Signer) -> None:
        self.add(signer.key_id, signer.public_pem())

    def revoke(self, key_id: str) -> None:
        """Permanently distrust ``key_id`` (known or not, so it can never be added later)."""
        _check_key_id(key_id)
        with self._lock:
            self._revoked.add(key_id)
            self._keys.pop(key_id, None)

    def is_revoked(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._revoked

    def is_trusted(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._keys and key_id not in self._revoked

    def key_ids(self) -> list[str]:
        """Currently trusted (non-revoked) key ids, sorted."""
        with self._lock:
            return sorted(self._keys)

    def revoked_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._revoked)

    def public_pem(self, key_id: str) -> bytes | None:
        with self._lock:
            if key_id in self._revoked:
                return None
            return self._pems.get(key_id)

    def verify(self, key_id: str | None, data: bytes, signature: str | None) -> bool:
        """True only for a valid signature by a known, non-revoked key."""
        if not key_id or not signature or not isinstance(data, (bytes, bytearray)):
            return False
        with self._lock:
            if key_id in self._revoked:
                return False
            key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            raw_sig = base64.b64decode(signature.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            return False
        try:
            key.verify(raw_sig, bytes(data))
        except InvalidSignature:
            return False
        return True

    def export(self) -> dict[str, object]:
        """JSON-serializable form: trusted public keys and the revocation list."""
        with self._lock:
            return {
                "keys": {k: v.decode("ascii") for k, v in sorted(self._pems.items())
                         if k not in self._revoked},
                "revoked": sorted(self._revoked),
            }

    @classmethod
    def from_export(cls, data: dict[str, object]) -> "KeyRing":
        ring = cls()
        revoked = data.get("revoked") or []
        keys = data.get("keys") or {}
        if not isinstance(revoked, list) or not isinstance(keys, dict):
            raise SigningKeyError("malformed key ring export")
        for key_id in revoked:
            ring.revoke(str(key_id))
        for key_id, pem in keys.items():
            if str(key_id) in ring._revoked:
                continue
            ring.add(str(key_id), str(pem).encode("ascii"))
        return ring


def _raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signing_bytes(model: BaseModel, sig_field: str) -> bytes:
    body = model.model_dump(mode="json")
    body.pop(sig_field, None)
    return canonical_bytes(body)


def sign_model(model: M, signer: Signer, field: str = "signature",
               key_field: str = "signer_key_id") -> M:
    """Return a copy of ``model`` signed by ``signer``.

    If the model has ``key_field`` it is set to ``signer.key_id`` first so the key
    id is covered by the signature. The original model is not modified.
    """
    fields = type(model).model_fields
    if field not in fields:
        raise ValueError(f"{type(model).__name__} has no signature field {field!r}")
    update: dict[str, object] = {}
    if key_field in fields:
        update[key_field] = signer.key_id
    unsigned = model.model_copy(update=update, deep=True)
    signature = signer.sign(_signing_bytes(unsigned, field))
    return unsigned.model_copy(update={field: signature})


def verify_model(model: BaseModel, keyring: KeyRing, key_field: str = "signer_key_id",
                 sig_field: str = "signature") -> bool:
    """Verify a model signed by :func:`sign_model`. Fails closed on anything missing."""
    key_id = getattr(model, key_field, None)
    signature = getattr(model, sig_field, None)
    if not isinstance(key_id, str) or not isinstance(signature, str) or not signature:
        return False
    try:
        data = _signing_bytes(model, sig_field)
    except Exception:  # unserializable content can never verify
        return False
    return keyring.verify(key_id, data, signature)
