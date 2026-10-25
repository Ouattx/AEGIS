"""EGRESS configuration: pre-registered thresholds, labels and the amplification port table.

Every threshold is a fixed, documented rule (no learned weights), so a reviewer can
reproduce a verdict by hand from the evidence payload. Rates are in packets per second
*after* undoing packet sampling (``sampling_interval``); when the operator does not know
the sampling interval, leave it at 1: rates are then underestimated, which only makes the
detector more conservative.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.contracts.canonical import sha256_hex

EGRESS_VERSION = "egress-1.0.0"

LABEL_DDOS = "egress_ddos_participation"
LABEL_AMPLIFICATION = "egress_amplification_reflection"
LABEL_REFLECTOR = "egress_abused_reflector"
LABEL_PROXY = "egress_residential_proxy"
LABEL_SPAM = "egress_spam"
LABEL_STUFFING = "egress_credential_stuffing"

ALL_LABELS = (LABEL_DDOS, LABEL_AMPLIFICATION, LABEL_REFLECTOR, LABEL_PROXY, LABEL_SPAM, LABEL_STUFFING)

#: UDP services abused for reflection/amplification (port -> protocol name).
#: Sources: US-CERT TA14-017A and later public advisories on memcached, CLDAP, WS-Discovery.
AMPLIFICATION_PORTS: dict[int, str] = {
    17: "qotd", 19: "chargen", 53: "dns", 69: "tftp", 111: "portmap", 123: "ntp", 137: "netbios",
    161: "snmp", 389: "cldap", 520: "rip", 1900: "ssdp", 3283: "ard", 3702: "ws-discovery",
    5353: "mdns", 5683: "coap", 10001: "ubiquiti-discovery", 11211: "memcached", 37810: "dvr-dhcpdiscover",
}

#: TCP services whose login endpoints are targeted by credential stuffing / brute force.
STUFFING_PORTS: tuple[int, ...] = (21, 22, 23, 80, 110, 143, 443, 465, 587, 993, 995, 2323, 3389, 5900,
                                   8080, 8443)
#: Interactive / mailbox authentication services (fan-out across many hosts = brute force scan).
AUTH_PORTS: tuple[int, ...] = (21, 22, 23, 110, 143, 445, 993, 995, 1433, 2323, 3306, 3389, 5900)


class EgressConfig(BaseModel):
    """Thresholds of the outbound-abuse detector (all pre-registered)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # -- telemetry ---------------------------------------------------------------------
    bucket_s: int = Field(default=60, ge=10, le=900)
    #: 1:N packet sampling of the flow exporter (1 = unsampled); packet/byte counts are scaled by it
    sampling_interval: int = Field(default=1, ge=1, le=100_000)
    #: report abstains when more than this fraction of flow records lack packet counters
    max_missing_packets_fraction: float = Field(default=0.5, ge=0.0, le=1.0)
    min_flow_records: int = Field(default=20, ge=1)

    # -- outbound flood (per line) -----------------------------------------------------
    min_flood_pps: float = Field(default=1_000.0, gt=0)
    strong_flood_multiple: float = Field(default=5.0, ge=1.0)
    min_flood_buckets: int = Field(default=2, ge=1)
    #: packets_in / packets_out at or below this = nobody answers (flood, not a conversation)
    max_response_ratio: float = Field(default=0.02, ge=0.0, le=1.0)
    #: distinct IPs inside one /24 (/48) in one bucket before the prefix is a carpet-bombing target
    carpet_min_ips: int = Field(default=4, ge=2)

    # -- synchronized bursts (cross-line) ----------------------------------------------
    sync_min_line_pps: float = Field(default=100.0, gt=0)
    sync_max_response_ratio: float = Field(default=0.05, ge=0.0, le=1.0)
    sync_min_lines: int = Field(default=3, ge=2)
    sync_slack_s: int = Field(default=120, ge=0)
    sync_min_aggregate_pps: float = Field(default=3_000.0, gt=0)
    #: buckets of in-window history toward the target required before a burst onset counts
    onset_lookback_buckets: int = Field(default=5, ge=1)
    #: burst rate / median rate of the lookback buckets toward the same target
    onset_ratio: float = Field(default=10.0, ge=1.0)

    # -- spoofing (optional side channel: uRPF / anti-spoofing counters) ---------------
    spoof_min_fraction: float = Field(default=0.01, gt=0.0, le=1.0)
    spoof_min_packets: int = Field(default=100, ge=1)

    # -- amplification reflection (bot side: spoofed requests to reflectors) ------------
    amp_ports: dict[int, str] = Field(default_factory=lambda: dict(AMPLIFICATION_PORTS))
    amp_min_reflectors: int = Field(default=10, ge=2)
    amp_min_pps: float = Field(default=50.0, gt=0)
    amp_max_response_ratio: float = Field(default=0.1, ge=0.0, le=1.0)

    # -- abused reflector (subscriber CPE answering spoofed requests) ------------------
    reflector_min_amplification: float = Field(default=20.0, gt=1.0)
    reflector_min_pps: float = Field(default=200.0, gt=0)
    reflector_min_request_ratio: float = Field(default=0.5, gt=0.0)
    reflector_min_buckets: int = Field(default=2, ge=1)

    # -- residential proxy relaying -----------------------------------------------------
    relay_bin_s: int = Field(default=300, ge=60)
    relay_min_bins: int = Field(default=6, ge=3)
    relay_min_corr: float = Field(default=0.6, ge=0.0, le=1.0)
    relay_balance_min: float = Field(default=0.5, gt=0.0)
    relay_balance_max: float = Field(default=2.0, gt=0.0)
    relay_min_peers_per_hour: float = Field(default=10.0, gt=0)
    #: bytes sent to the sink / bytes received from it: an upstream receives far more than it
    #: returns (a VPN, call or game server returns comparable volumes)
    relay_sink_min_out_in_ratio: float = Field(default=3.0, gt=1.0)
    relay_sink_min_presence: float = Field(default=0.5, gt=0.0, le=1.0)
    relay_min_bytes_per_hour: float = Field(default=2_000_000.0, gt=0)
    #: a flow record shorter than this is a session, not an active-timeout continuation slice
    short_session_max_ms: int = Field(default=55_000, ge=1_000)
    #: a record starting within this many ms of the end of an active-timeout slice toward the
    #: same destination and port is that connection's tail slice, not a new session
    continuation_slack_ms: int = Field(default=5_000, ge=0)

    # -- spam -----------------------------------------------------------------------------
    spam_ports: tuple[int, ...] = (25,)
    spam_min_dsts_per_hour: float = Field(default=20.0, gt=0)
    spam_min_dsts: int = Field(default=30, ge=1)
    spam_campaign_min_jaccard: float = Field(default=0.1, ge=0.0, le=1.0)

    # -- credential stuffing / brute force -------------------------------------------------
    stuffing_ports: tuple[int, ...] = STUFFING_PORTS
    auth_ports: tuple[int, ...] = AUTH_PORTS
    stuffing_min_sessions: int = Field(default=100, ge=10)
    stuffing_min_sessions_per_hour: float = Field(default=300.0, gt=0)
    #: login failures return near-identical byte counts
    stuffing_max_bytes_cv: float = Field(default=0.35, gt=0.0)
    #: timers (app polling) are regular; attack tools are not
    stuffing_min_interarrival_cv: float = Field(default=0.5, ge=0.0)
    auth_fanout_min_dsts: int = Field(default=30, ge=2)
    auth_fanout_min_dsts_per_hour: float = Field(default=20.0, gt=0)

    # -- correlation / output -------------------------------------------------------------
    campaign_min_lines: int = Field(default=2, ge=2)
    popular_fraction: float = Field(default=0.2, gt=0.0, le=1.0)
    min_active_lines_for_popularity: int = Field(default=20, ge=1)
    finding_ttl_hours: int = Field(default=24, ge=1)
    authorization_id: str = "egress-detector"

    @model_validator(mode="after")
    def _check(self) -> "EgressConfig":
        if self.relay_balance_min >= self.relay_balance_max:
            raise ValueError("relay_balance_min must be < relay_balance_max")
        if self.relay_bin_s < self.bucket_s:
            raise ValueError("relay_bin_s must be >= bucket_s")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def config_hash(self) -> str:
        return sha256_hex(self.as_dict())
