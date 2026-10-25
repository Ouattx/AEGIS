"""Seal, sign, verify and ledger genomes. Fail closed: only verified, unexpired genomes load."""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from aegis.genome.models import Genome
from aegis.provenance.signing import KeyRing, Signer, sign_model, verify_model

GENOME_ENTRY = "genome"


def seal(genome: Genome) -> Genome:
    """Set content hash and id from the content body (idempotent)."""
    h = genome.compute_hash()
    return genome.model_copy(update={"content_sha256": h, "genome_id": "gn-" + h[:20]})


def sign_genome(genome: Genome, signer: Signer) -> Genome:
    return sign_model(seal(genome), signer)


def verify_genome(genome: Genome, keyring: KeyRing) -> bool:
    """Signature valid, trusted key, and content hash / id consistent with the content."""
    if not genome.content_sha256 or genome.content_sha256 != genome.compute_hash():
        return False
    if genome.genome_id != "gn-" + genome.content_sha256[:20]:
        return False
    return verify_model(genome, keyring)


def load_genomes(genomes: Iterable[Genome], keyring: KeyRing, now: datetime) -> tuple[list[Genome], dict[str, int]]:
    """Return (usable genomes, ignored counts by reason)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    ok: list[Genome] = []
    ignored: dict[str, int] = {}
    for g in genomes:
        if not verify_genome(g, keyring):
            ignored["unverified"] = ignored.get("unverified", 0) + 1
        elif g.is_expired(now):
            ignored["expired"] = ignored.get("expired", 0) + 1
        else:
            ok.append(g)
    return ok, ignored


def ledger_genome(ledger, tenant_id: str, genome: Genome, recorded_at: datetime | None = None):
    """Write the genome (minus nothing: it is metadata only) to the provenance ledger."""
    return ledger.append(tenant_id, GENOME_ENTRY, genome.genome_id,
                         {"genome": genome.model_dump(mode="json", by_alias=True),
                          "content_sha256": genome.content_sha256, "family": genome.family,
                          "signer_key_id": genome.signer_key_id}, recorded_at=recorded_at)
