"""AEGIS ingest: parse collector telemetry, pseudonymize, normalize, validate,
quarantine, and publish to the event bus with backpressure, DLQ and quotas."""
from aegis.ingest.bus import (
    DLQ_TOPIC,
    OBSERVATIONS_TOPIC,
    Backpressure,
    BusStats,
    DeadLetter,
    EventBus,
    InMemoryBus,
    KafkaBus,
    QuotaExceeded,
)
from aegis.ingest.normalize import NormalizationError, SourceConfig, normalize, parse_timestamp
from aegis.ingest.parsers import (
    ParseError,
    parse_cpe_json,
    parse_dns_jsonl,
    parse_netflow_csv,
    parse_zeek_conn,
    parse_zeek_dns,
)
from aegis.ingest.pipeline import IngestBackpressureError, IngestPipeline, IngestStats, UnknownSourceError
from aegis.ingest.pseudonym import Pseudonymizer, TenantKeyProvider, is_pseudonym
from aegis.ingest.validator import QuarantineStore, Quarantined, Validator, make_quarantined, validate

__all__ = [
    "DLQ_TOPIC", "OBSERVATIONS_TOPIC", "Backpressure", "BusStats", "DeadLetter", "EventBus",
    "InMemoryBus", "KafkaBus", "QuotaExceeded", "NormalizationError", "SourceConfig", "normalize",
    "parse_timestamp", "ParseError", "parse_cpe_json", "parse_dns_jsonl", "parse_netflow_csv",
    "parse_zeek_conn", "parse_zeek_dns", "IngestBackpressureError", "IngestPipeline", "IngestStats",
    "UnknownSourceError", "Pseudonymizer", "TenantKeyProvider", "is_pseudonym", "QuarantineStore",
    "Quarantined", "Validator", "make_quarantined", "validate",
]
