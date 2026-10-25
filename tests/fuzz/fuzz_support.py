"""Pipeline harness and invariants shared by the fuzz tests."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from aegis.contracts.models import ObservationEvent, SourceKind, Vantage
from aegis.ingest import IngestPipeline, IngestStats, Pseudonymizer, QuarantineStore, SourceConfig, Validator
from aegis.ingest.pseudonym import is_pseudonym
from aegis.scale.lines import CollectingBus, FixedClock

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)

TENANT = "fuzz-isp"
KEY = b"fuzz-tenant-key-0123456789abcdef"
SOURCES = {
    "netflow": SourceConfig(tenant_id=TENANT, source_id="netflow", source_kind=SourceKind.NETFLOW,
                            vantage=Vantage.DEVICE, collection_authorization_id="auth-fuzz"),
    "dns": SourceConfig(tenant_id=TENANT, source_id="dns", source_kind=SourceKind.DNS,
                        vantage=Vantage.DEVICE, collection_authorization_id="auth-fuzz"),
    "zeek_conn": SourceConfig(tenant_id=TENANT, source_id="zeek_conn", source_kind=SourceKind.ZEEK_CONN,
                              vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-fuzz",
                              entity_field="src_ip"),
    "zeek_dns": SourceConfig(tenant_id=TENANT, source_id="zeek_dns", source_kind=SourceKind.ZEEK_DNS,
                             vantage=Vantage.SUBSCRIBER_LINE, collection_authorization_id="auth-fuzz",
                             entity_field="src_ip"),
    "cpe": SourceConfig(tenant_id=TENANT, source_id="cpe", source_kind=SourceKind.CPE,
                        vantage=Vantage.DEVICE, collection_authorization_id="auth-fuzz"),
}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
STAGES = {"parse", "normalize", "validate"}


class Run:
    def __init__(self) -> None:
        self.events: list[ObservationEvent] = []
        bus = CollectingBus()
        bus.subscribe("observations", self.events.append)
        self.quarantine = QuarantineStore()
        self.validator = Validator(clock=FixedClock(NOW))
        self.pipe = IngestPipeline(bus, self.validator, SOURCES, pseudonymizers={TENANT: Pseudonymizer(KEY)},
                                   quarantine=self.quarantine, clock=FixedClock(NOW))

    def ingest(self, source_id: str, payload: bytes) -> IngestStats:
        return self.pipe.ingest_text(payload, source_id, name="fuzz")


def check_invariants(run: Run, stats: IngestStats) -> None:
    """Nothing is lost, nothing is accepted unchecked, every rejection carries a reason."""
    reasons = dict(stats.quarantine_reasons)
    marker = 1 if reasons.get("unparseable_input") and stats.records_read == 0 else 0
    skipped = getattr(stats, "skipped", 0)
    assert stats.accepted + stats.quarantined + stats.duplicates + skipped == stats.records_read + marker, stats
    assert stats.accepted == stats.published == len(run.events)
    assert sum(reasons.values()) == stats.quarantined
    for q in run.quarantine.list(TENANT, 10**6) + run.quarantine.list("_unknown", 10**6):
        assert q.reason and isinstance(q.reason, str)
        assert q.stage in STAGES
        assert _HEX64.match(q.raw_sha256)
        assert q.raw_size >= 0
    for ev in run.events:
        assert is_pseudonym(ev.entity_pseudonym)
        assert ev.tenant_id == TENANT and ev.collection_authorization_id == "auth-fuzz"
        assert (ev.flow is None) != (ev.dns is None)
        if ev.flow is not None:
            assert ev.flow.src_ip is None
        if exceeds_json_safe_integers(ev):
            # known ingest defect (see test_known_defects.py): counters above 2**53 - 1 are accepted
            # although canonical JSON (RFC 8785) cannot hash them; tracked by a strict xfail test
            continue
        again = run.validator.validate(ev.model_dump(mode="json"))
        assert isinstance(again, ObservationEvent), getattr(again, "reason", again)


JSON_SAFE_MAX = 2**53 - 1


def exceeds_json_safe_integers(ev: ObservationEvent) -> bool:
    f = ev.flow
    if f is None:
        return False
    return any(v is not None and v > JSON_SAFE_MAX for v in
               (f.bytes_out, f.bytes_in, f.packets_out, f.packets_in, f.duration_ms))


def reasons_of(run: Run) -> list[str]:
    return [q.reason for q in run.quarantine.list(TENANT, 10**6)]


def as_dict(ev: ObservationEvent) -> dict[str, Any]:
    return ev.model_dump(mode="json")
