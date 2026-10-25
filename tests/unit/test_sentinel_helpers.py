"""Shared builders for the Sentinel unit tests (contains no tests itself)."""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

from aegis.contracts.models import (
    DnsObservation,
    FeatureVector,
    FlowObservation,
    ObservationEvent,
    SourceKind,
    Vantage,
)
from aegis.sentinel.features import FEATURE_NAMES

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
_ids = itertools.count()


def flow_event(t: datetime, *, entity: str = "p_dev1", dst: str = "198.18.1.1", port: int = 443,
               proto: str = "tcp", bytes_out: int | None = 500, bytes_in: int | None = 800,
               packets_out: int | None = None, packets_in: int | None = None, duration_ms: int | None = 300,
               tenant: str = "t1", device_class: str | None = "android_tv", auth: str = "auth-1",
               ingest_lag: timedelta = timedelta(seconds=30)) -> ObservationEvent:
    return ObservationEvent(
        event_id=f"ev-{next(_ids)}", tenant_id=tenant, observed_at=t, ingested_at=t + ingest_lag,
        source_id="test-netflow", source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
        collection_authorization_id=auth, entity_pseudonym=entity, device_class=device_class,
        flow=FlowObservation(dst_ip=dst, dst_port=port, protocol=proto, bytes_out=bytes_out, bytes_in=bytes_in,
                             packets_out=packets_out, packets_in=packets_in, duration_ms=duration_ms),
        retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)


def dns_event(t: datetime, qname: str, *, entity: str = "p_dev1", rcode: str = "NOERROR",
              answers: list[str] | None = None, tenant: str = "t1", device_class: str | None = "android_tv",
              auth: str = "auth-1") -> ObservationEvent:
    return ObservationEvent(
        event_id=f"ev-{next(_ids)}", tenant_id=tenant, observed_at=t, ingested_at=t + timedelta(seconds=30),
        source_id="test-dns", source_kind=SourceKind.DNS, vantage=Vantage.DEVICE,
        collection_authorization_id=auth, entity_pseudonym=entity, device_class=device_class,
        dns=DnsObservation(qname=qname, rcode=rcode, answers=answers or []),
        retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)


def make_fv(values: dict[str, float | None] | None = None, *, entity: str = "p_dev1",
            device_class: str = "android_tv", window_end: datetime = T0 + timedelta(days=1),
            event_count: int = 500, tenant: str = "t1") -> FeatureVector:
    """A feature vector with benign-looking defaults, overridable per feature."""
    base: dict[str, float | None] = {name: None for name in FEATURE_NAMES}
    base.update({
        "coverage_h": 24.0, "flow_rate_h": 20.0, "dns_rate_h": 2.0, "bytes_out_rate_log": 4.5,
        "bytes_in_rate_log": 6.5, "out_ratio": 0.02, "unique_dst_ip": 12.0, "unique_dst_port": 3.0,
        "dst_entropy": 2.5, "max_dst_share": 0.3, "tcp_frac": 0.9, "udp_frac": 0.1, "small_flow_frac": 0.2,
        "zero_reply_frac": 0.0, "long_flow_frac": 0.6, "peak_out_pps_log": 1.2, "active_bin_frac": 0.5,
        "out_heavy_bin_frac": 0.0, "nxdomain_rate": 0.0, "nx_unique": 0.0, "qname_unique": 12.0,
        "interval_p10_log": 0.5, "interval_p50_log": 1.8, "interval_p90_log": 2.8, "burstiness": 0.3,
        "beacon_robust_cv": 0.05, "beacon_period_log": 2.48, "beacon_events": 100.0, "beacon_bytes_log": 3.0,
        "beacon_dst_prevalence": 0.25, "rare_dst_frac": 0.0, "rare_qname_frac": 0.0,
        "baseline_dev_flows": 0.0, "baseline_dev_bytes_out": 0.0, "recent_flows_log": 1.3,
        "recent_bytes_out_log": 4.5, "recent_unique_dst": 5.0,
    })
    if values:
        base.update(values)
    return FeatureVector(tenant_id=tenant, entity_pseudonym=entity, device_class=device_class, window="24h",
                         window_end=window_end, values=base, missing={k: v is None for k, v in base.items()},
                         event_count=event_count)
