"""Single-home lab configuration and the matching ingest source configs.

A home lab is one isolated Wi-Fi network (``lab_subnet``) with one or a few devices
under test, all owned by the person running the lab. Its telemetry is metadata only:
Zeek ``conn.log`` / ``dns.log`` converted offline from header-only captures, and the
dnsmasq query log of the lab access point.

The ingest sources registered for a lab use ``Vantage.DEVICE`` (every lab client IP is
one device) and attribute flows by source IP inside ``lab_subnet`` only, so a remote
server never becomes a "device" and the access point's own traffic is skipped.
"""
from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.contracts.models import SourceKind, Vantage
from aegis.ingest.normalize import SourceConfig

#: default lab addressing used by ``deploy/homelab`` (RFC 1918, unlikely to collide with home LANs)
DEFAULT_LAB_SUBNET = "10.42.0.0/24"
DEFAULT_GATEWAY = "10.42.0.1"

SOURCE_ZEEK_CONN = "homelab-zeek-conn"
SOURCE_ZEEK_DNS = "homelab-zeek-dns"
SOURCE_DNSMASQ = "homelab-dnsmasq"


class HomeLabConfig(BaseModel):
    """Everything the importer and the single-home analysis need to know about a lab."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(default="homelab", min_length=1, max_length=64)
    #: free-text reference to the lab owner's own authorization (it is their device and network)
    collection_authorization_id: str = Field(default="homelab-owner-consent", min_length=1)
    lab_subnet: str = DEFAULT_LAB_SUBNET
    gateway_ip: str = DEFAULT_GATEWAY
    retention_days: int = Field(default=30, ge=1, le=365)
    #: friendly labels for lab clients, keyed by their lab IP (the IP never leaves the importer:
    #: it is pseudonymized and only the label is kept)
    device_labels: dict[str, str] = Field(default_factory=dict)
    #: optional device class hint for SENTINEL's per-class baselines; never used as evidence
    device_class: str | None = None
    #: keep flows to lab-local / multicast / broadcast destinations in the detection input
    #: (off by default: SSDP / mDNS chatter is summarized separately instead)
    include_local: bool = False
    #: timezone of dnsmasq syslog-style timestamps; None = capture.json's ``dnsmasq_timezone``, else UTC
    #: (the Raspberry Pi scripts run dnsmasq with TZ=UTC)
    dnsmasq_timezone: str | None = None
    #: year of the first dnsmasq line (syslog timestamps carry no year); None = capture manifest or now
    dnsmasq_year: int | None = None
    #: when both dnsmasq and Zeek DNS logs are present, which one feeds DNS events
    dns_source: Literal["dnsmasq", "zeek", "both"] = "dnsmasq"

    @field_validator("lab_subnet")
    @classmethod
    def _subnet(cls, v: str) -> str:
        net = ipaddress.ip_network(v.strip(), strict=False)
        if not net.is_private:
            raise ValueError("lab_subnet must be a private (RFC 1918 / ULA) network")
        return str(net)

    @field_validator("gateway_ip")
    @classmethod
    def _gw(cls, v: str) -> str:
        return str(ipaddress.ip_address(v.strip()))

    @field_validator("device_labels")
    @classmethod
    def _labels(cls, v: dict[str, str]) -> dict[str, str]:
        out: dict[str, str] = {}
        for ip, label in v.items():
            addr = str(ipaddress.ip_address(str(ip).strip()))
            text = str(label).strip()
            if not text or len(text) > 64:
                raise ValueError("device labels must be 1-64 characters")
            out[addr] = text
        return out

    @model_validator(mode="after")
    def _gateway_inside(self) -> "HomeLabConfig":
        if ipaddress.ip_address(self.gateway_ip) not in ipaddress.ip_network(self.lab_subnet):
            raise ValueError("gateway_ip must lie inside lab_subnet")
        return self

    @property
    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.lab_subnet)

    def is_lab_client(self, ip: str | None) -> bool:
        """True for a lab client address (inside the lab subnet, not the access point itself)."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr in self.network and str(addr) != self.gateway_ip

    def is_local_destination(self, ip: str | None) -> bool:
        """Lab-local, multicast, broadcast, link-local or loopback destinations (not internet infrastructure)."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr in self.network or addr.is_multicast or addr.is_link_local or addr.is_loopback:
            return True
        return isinstance(addr, ipaddress.IPv4Address) and (str(addr) == "255.255.255.255"
                                                             or addr == self.network.broadcast_address)


def single_home_sources(cfg: HomeLabConfig) -> dict[str, SourceConfig]:
    """The ingest :class:`SourceConfig` objects of a single-home lab, keyed by source id.

    These are the "single-home" source configs: per-device vantage, attribution by lab
    client IP, flows from outside the lab subnet skipped (never attributed to a server).
    """
    def source(source_id: str, kind: SourceKind,
               flow_direction: Literal["auto", "biflow", "uniflow"] = "auto") -> SourceConfig:
        return SourceConfig(tenant_id=cfg.tenant_id, source_id=source_id, source_kind=kind, vantage=Vantage.DEVICE,
                            collection_authorization_id=cfg.collection_authorization_id,
                            retention_days=cfg.retention_days, entity_field="src_ip",
                            subscriber_prefixes=(cfg.lab_subnet,), flow_direction=flow_direction)

    return {
        # Zeek conn.log carries both directions of each connection (orig/resp counters)
        SOURCE_ZEEK_CONN: source(SOURCE_ZEEK_CONN, SourceKind.ZEEK_CONN, "biflow"),
        SOURCE_ZEEK_DNS: source(SOURCE_ZEEK_DNS, SourceKind.ZEEK_DNS),
        SOURCE_DNSMASQ: source(SOURCE_DNSMASQ, SourceKind.DNS),
    }


__all__ = ["DEFAULT_GATEWAY", "DEFAULT_LAB_SUBNET", "HomeLabConfig", "SOURCE_DNSMASQ", "SOURCE_ZEEK_CONN",
           "SOURCE_ZEEK_DNS", "single_home_sources"]
