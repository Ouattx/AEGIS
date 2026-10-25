"""Canonical serialization and hashing.

Every hash in the platform is SHA-256 over RFC 8785 (JCS) canonical JSON, so the
same logical object always produces the same digest regardless of key order or
float formatting.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import rfc8785
from pydantic import BaseModel


def _normalize(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return _normalize(obj.model_dump(mode="json"))
    if isinstance(obj, dict):
        return {str(k): _normalize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalize(v) for v in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


def canonical_bytes(obj: Any) -> bytes:
    return rfc8785.dumps(_normalize(obj))


def sha256_hex(data: bytes | Any) -> str:
    if not isinstance(data, (bytes, bytearray)):
        data = canonical_bytes(data)
    return hashlib.sha256(data).hexdigest()
