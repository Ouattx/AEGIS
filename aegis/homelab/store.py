"""Local provenance store for a home lab (evidence + signed, hash-chained ledger).

The Box Lab report's evidence trail is real provenance, not decoration: every evidence
record is appended through :class:`aegis.provenance.evidence.EvidenceStore` (sha256 of
its canonical form, one ledger entry each) into a SQLite file next to the report, and
the ledger is signed with a lab key so the chain can be re-verified later with
:meth:`LabStore.verify`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory

LAB_LEDGER_KEY_ID = "homelab-ledger"


@dataclass
class LabStore:
    engine: Engine
    evidence: EvidenceStore
    ledger: Ledger
    signer: Signer
    keyring: KeyRing
    path: Path | None

    def verify(self, tenant_id: str) -> dict[str, Any]:
        ok, bad = self.ledger.verify_chain(tenant_id, self.keyring)
        return {"verified": ok, "first_bad_seq": bad, "head_hash": self.ledger.head(tenant_id),
                "entries": self.ledger.count(tenant_id), "signer_key_id": self.signer.key_id,
                "database": str(self.path) if self.path else None}

    def close(self) -> None:
        self.engine.dispose()


def open_lab_store(db_path: str | Path | None = None, *, signer: Signer | None = None) -> LabStore:
    """Open (or create) a lab store. ``db_path=None`` keeps it in memory (tests, previews).

    ``signer`` defaults to a freshly generated Ed25519 key; pass the saved key
    (``Signer.from_private_pem``) to keep appending to an existing ledger.
    """
    if db_path is None:
        engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False},
                               future=True)
        path = None
    else:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = make_engine(f"sqlite:///{path}")
    init_db(engine)
    sf = make_session_factory(engine)
    signer = signer or Signer.generate(LAB_LEDGER_KEY_ID)
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    ledger = Ledger(sf, signer=signer)
    return LabStore(engine=engine, evidence=EvidenceStore(DocStore(sf), ledger), ledger=ledger, signer=signer,
                    keyring=ring, path=path)


__all__ = ["LAB_LEDGER_KEY_ID", "LabStore", "open_lab_store"]
