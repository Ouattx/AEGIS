"""PROVENANCE: evidence integrity (spec section 11).

- :mod:`.signing`: Ed25519 ``Signer`` / ``KeyRing`` with revocation, ``sign_model`` / ``verify_model``
- :mod:`.ledger`: append-only, hash-chained, optionally signed per-tenant ``Ledger``
- :mod:`.evidence`: immutable content-hashed ``EvidenceStore`` and independence counting
- :mod:`.snapshot`: content-hashed ``snapshot`` and contemporaneous ``replay``
"""
from aegis.provenance.evidence import (
    EvidenceExistsError,
    EvidenceIntegrityError,
    EvidenceStore,
    independent_origins,
)
from aegis.provenance.ledger import (
    GENESIS_HASH,
    ChainReport,
    EntryType,
    Ledger,
    LedgerConflictError,
    LedgerError,
)
from aegis.provenance.signing import (
    KeyRing,
    Signer,
    SigningKeyError,
    sign_model,
    verify_model,
)
from aegis.provenance.snapshot import record_snapshot, replay, snapshot, verify_snapshot

__all__ = [
    "GENESIS_HASH", "ChainReport", "EntryType", "EvidenceExistsError", "EvidenceIntegrityError",
    "EvidenceStore", "KeyRing", "Ledger", "LedgerConflictError", "LedgerError", "Signer",
    "SigningKeyError", "independent_origins", "record_snapshot", "replay", "sign_model",
    "snapshot", "verify_model", "verify_snapshot",
]
