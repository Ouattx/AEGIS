"""GENOME: behavioral fingerprints of malware families from Box Farm lab captures.

Public API::

    from aegis.genome import (LabCapture, capture_from_observations, extract_genome, sign_genome,
                              verify_genome, load_genomes, ledger_genome, GenomeDetector, GenomeConfig,
                              detect_new_infrastructure, build_early_warning_bundle, tenant_exposure,
                              exposure_summary, to_findings)

    res = extract_genome(lab_captures, clean_reference=[clean_capture])   # ExtractionResult (genome or reason)
    g = sign_genome(res.genome, signer)                                   # content-hashed + Ed25519 signed
    report = GenomeDetector([g], keyring, context=ctx, history=hist, tenant_id=t).detect(event_table)
    findings = to_findings(report, [g], evidence_store=store)

See docs/GENOME.md for the method, guarantees, Box Farm containment design and limitations.
Metadata only: no payloads, nothing executable.
"""
from aegis.genome.capture import LabCapture, capture_from_observations
from aegis.genome.detector import GENOME_DETECTOR_VERSION, GenomeConfig, GenomeDetector, MatchedFilter
from aegis.genome.early_warning import (
    NewInfraCandidate,
    build_early_warning_bundle,
    detect_new_infrastructure,
    exposure_summary,
    tenant_exposure,
)
from aegis.genome.extract import EXTRACTOR_VERSION, ExtractConfig, ExtractionResult, extract_genome
from aegis.genome.findings import FINDING_LABEL, to_findings
from aegis.genome.models import (
    DeviceModelHypothesis,
    Genome,
    GenomeAbstention,
    GenomeCampaign,
    GenomeReport,
)
from aegis.genome.registry import ledger_genome, load_genomes, seal, sign_genome, verify_genome

__all__ = [
    "LabCapture", "capture_from_observations", "GenomeConfig", "GenomeDetector", "MatchedFilter",
    "GENOME_DETECTOR_VERSION", "NewInfraCandidate", "build_early_warning_bundle", "detect_new_infrastructure",
    "exposure_summary", "tenant_exposure", "EXTRACTOR_VERSION", "ExtractConfig", "ExtractionResult",
    "extract_genome", "FINDING_LABEL", "to_findings", "DeviceModelHypothesis", "Genome", "GenomeAbstention",
    "GenomeCampaign", "GenomeReport", "ledger_genome", "load_genomes", "seal", "sign_genome", "verify_genome",
]
