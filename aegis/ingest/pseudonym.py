"""Tenant-keyed pseudonymization of device and subscriber-line identifiers.

Raw identifiers (MAC addresses, subscriber IPs, CPE serials) never leave ingest:
they are replaced by ``p_`` + truncated HMAC-SHA256 under a per-tenant key. The
same identifier always maps to the same pseudonym for one tenant, and to
unrelated pseudonyms across tenants, so no cross-tenant linkage is possible.

Re-identification requires the tenant key, which the operator controls (spec
section 11: "separate tenant-controlled mappings"). This module never stores a
reverse mapping.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import threading
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

log = logging.getLogger(__name__)

PSEUDONYM_PREFIX = "p_"
PSEUDONYM_HEX_CHARS = 32  # 128 bits: collision probability negligible at ISP scale
MIN_KEY_BYTES = 16

_PSEUDONYM_RE = re.compile(rf"^{PSEUDONYM_PREFIX}[0-9a-f]{{{PSEUDONYM_HEX_CHARS}}}$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}([:\-.]?[0-9a-f]{2}){5}$")
_MAC_DOTTED_RE = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$")

# Development-only fallback master key. Production refuses to use it.
_DEV_MASTER_KEY = hashlib.sha256(b"aegis-omega-dev-pseudonym-master-key").digest()


def is_pseudonym(value: str | None) -> bool:
    """True when ``value`` has the exact shape of a pseudonym produced here."""
    return bool(value) and bool(_PSEUDONYM_RE.match(value))  # type: ignore[arg-type]


def normalize_identifier(identifier: str) -> str:
    """Canonical form so that equivalent spellings map to one pseudonym.

    MAC addresses (any common separator) become lower-case colon form; IP
    addresses become their compressed canonical text; anything else is
    stripped and lower-cased.
    """
    s = identifier.strip().lower()
    if _MAC_RE.match(s) or _MAC_DOTTED_RE.match(s):
        hexes = re.sub(r"[^0-9a-f]", "", s)
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


class Pseudonymizer:
    """HMAC-SHA256 pseudonymizer bound to one tenant key."""

    def __init__(self, tenant_key: bytes):
        if not isinstance(tenant_key, (bytes, bytearray)) or len(tenant_key) < MIN_KEY_BYTES:
            raise ValueError(f"tenant_key must be at least {MIN_KEY_BYTES} bytes")
        self._key = bytes(tenant_key)
        self._cached = lru_cache(maxsize=262_144)(self._compute)

    def _compute(self, identifier: str) -> str:
        canonical = normalize_identifier(identifier)
        digest = hmac.new(self._key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return PSEUDONYM_PREFIX + digest[:PSEUDONYM_HEX_CHARS]

    def pseudonym(self, identifier: str) -> str:
        if not isinstance(identifier, str) or not identifier.strip():
            raise ValueError("identifier must be a non-empty string")
        return self._cached(identifier)

    @property
    def key_fingerprint(self) -> str:
        """Non-reversible fingerprint of the key, safe to log for key-rotation audits."""
        return hashlib.sha256(b"fp:" + self._key).hexdigest()[:16]


class TenantKeyProvider:
    """Derives one independent pseudonymization key per tenant from a master key.

    Keys are derived with HKDF-SHA256 (info = tenant id). Operators running
    on-prem set ``AEGIS_PSEUDONYM_MASTER_KEY`` (hex, >= 32 hex chars) from their
    secrets vault; SaaS deployments may instead register explicit per-tenant keys
    with :meth:`set_tenant_key`.
    """

    ENV_VAR = "AEGIS_PSEUDONYM_MASTER_KEY"

    def __init__(self, master_key: bytes):
        if len(master_key) < MIN_KEY_BYTES:
            raise ValueError(f"master key must be at least {MIN_KEY_BYTES} bytes")
        self._master = bytes(master_key)
        self._explicit: dict[str, bytes] = {}
        self._cache: dict[str, Pseudonymizer] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> "TenantKeyProvider":
        env = os.environ if environ is None else environ
        raw = env.get(cls.ENV_VAR)
        if raw:
            try:
                key = bytes.fromhex(raw.strip())
            except ValueError as exc:
                raise ValueError(f"{cls.ENV_VAR} must be hex encoded") from exc
            return cls(key)
        if env.get("AEGIS_ENV", "").lower() in {"prod", "production"}:
            raise RuntimeError(f"{cls.ENV_VAR} must be set when AEGIS_ENV=production")
        log.warning("%s not set: using the development pseudonymization key", cls.ENV_VAR)
        return cls(_DEV_MASTER_KEY)

    def set_tenant_key(self, tenant_id: str, key: bytes) -> None:
        if len(key) < MIN_KEY_BYTES:
            raise ValueError(f"tenant key must be at least {MIN_KEY_BYTES} bytes")
        with self._lock:
            self._explicit[tenant_id] = bytes(key)
            self._cache.pop(tenant_id, None)

    def key_for(self, tenant_id: str) -> bytes:
        if not tenant_id:
            raise ValueError("tenant_id required")
        explicit = self._explicit.get(tenant_id)
        if explicit is not None:
            return explicit
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"aegis-pseudonym-v1",
                    info=b"tenant:" + tenant_id.encode("utf-8")).derive(self._master)

    def pseudonymizer(self, tenant_id: str) -> Pseudonymizer:
        with self._lock:
            p = self._cache.get(tenant_id)
            if p is None:
                p = Pseudonymizer(self.key_for(tenant_id))
                self._cache[tenant_id] = p
            return p
