"""Shared builders for the INTEL unit tests (contains no tests itself)."""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aegis.contracts.models import DnsObservation, FlowObservation, ObservationEvent, SourceKind, Vantage
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.intel import IntelStore, get_spec, parse_feed
from aegis.resonance.models import Campaign

FEEDS = Path(__file__).resolve().parents[2] / "sample_data" / "feeds"
NOW = datetime(2026, 10, 20, 12, 30, tzinfo=timezone.utc)
TENANT = "t-intel"
TENANT_KEY = b"tenant-intel-test-key-0123456789"
SUBSCRIBER_SPACE = "198.18.0.0/15"
_ids = itertools.count()

FIXTURES: list[tuple[str, str, str | None]] = [
    ("feed:urlhaus", "urlhaus_recent.csv", None),
    ("feed:threatfox", "threatfox_recent.json", None),
    ("feed:feodo", "feodo_ipblocklist.csv", None),
    ("feed:spamhaus_drop", "spamhaus_drop.txt", None),
    ("feed:spamhaus_edrop", "spamhaus_edrop.txt", None),
    ("feed:shadowserver", "shadowserver_event4_sinkhole_http.csv", "event4_sinkhole_http"),
    ("feed:shadowserver", "shadowserver_botnet_drone.csv", "botnet_drone"),
    ("feed:shadowserver", "shadowserver_scan_telnet.csv", "scan_telnet"),
]


def pseudonymizer() -> Pseudonymizer:
    return Pseudonymizer(TENANT_KEY)


def loaded_store(tenant: str = TENANT, now: datetime = NOW) -> IntelStore:
    st = IntelStore(tenant)
    ps = pseudonymizer()
    for fid, fname, rt in FIXTURES:
        spec = get_spec(fid)
        st.ingest(parse_feed(FEEDS / fname, spec, now, report_type=rt, pseudonymizer=ps), spec, now)
    return st


def flow(t: datetime, line: str, dst: str, *, tenant: str = TENANT) -> ObservationEvent:
    return ObservationEvent(
        event_id=f"ev-{next(_ids)}", tenant_id=tenant, observed_at=t, ingested_at=t + timedelta(seconds=5),
        source_id="nf", source_kind=SourceKind.NETFLOW, vantage=Vantage.SUBSCRIBER_LINE,
        collection_authorization_id="auth-1", entity_pseudonym=line, device_class="unknown",
        flow=FlowObservation(dst_ip=dst, dst_port=443, protocol="tcp", bytes_out=300, bytes_in=500),
        retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)


def dns(t: datetime, line: str, qname: str, answers: list[str] | None = None, *,
        tenant: str = TENANT) -> ObservationEvent:
    return ObservationEvent(
        event_id=f"ev-{next(_ids)}", tenant_id=tenant, observed_at=t, ingested_at=t + timedelta(seconds=5),
        source_id="dns", source_kind=SourceKind.DNS, vantage=Vantage.SUBSCRIBER_LINE,
        collection_authorization_id="auth-1", entity_pseudonym=line, device_class="unknown",
        dns=DnsObservation(qname=qname, answers=answers or []),
        retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)


def campaign(destinations: list[str], lines: list[str], *, tenant: str = TENANT,
             window_end: datetime = NOW - timedelta(hours=2), destination_ips: list[str] | None = None,
             shared_hosting_domain: bool = False, topology_unknown: bool = False, q_value: float = 0.0005,
             cid: str | None = None, **extra: Any) -> Campaign:
    return Campaign(
        campaign_id=cid or f"rc-{next(_ids):06d}", tenant_id=tenant, detector_version="test", config_hash="x",
        destinations=destinations, destination_ips=destination_ips or [], shared_hosting_domain=shared_hosting_domain,
        topology_unknown=topology_unknown, enforcement_eligible=not topology_unknown, member_lines=lines,
        supporting_lines=lines, n_lines=len(lines), popularity=0.01, destination_age_days=2.0,
        statistic="period_lock", period_s=900.0, period_agreement=0.9, resonance_statistic=8.0, null_mean=0.0,
        null_sd=1.0, p_value=1e-5, p_lock=1e-5, p_free=0.5, p_method="empirical", n_permutations=1000, weight=1.0,
        q_value=q_value, q_target=0.01, window_start=window_end - timedelta(hours=24), window_end=window_end,
        onset_at=window_end - timedelta(hours=20), explanation="test campaign", **extra)
