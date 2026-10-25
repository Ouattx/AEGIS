"""Deterministic analyst knowledge: benign explanations and discriminating tests.

Used by the alternative-hypothesis agent so that, with no LLM configured, every
case still gets concrete competing explanations, what evidence would separate
them from the malicious hypothesis, and a plausibility grade driven by the
evidence actually present (never by device class, vendor or geography alone).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Plausibility = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class HypothesisTemplate:
    key: str
    title: str
    rationale: str
    tests: tuple[str, ...]
    device_classes: tuple[str, ...] = ()       # empty = any


_LABEL_KB: dict[str, tuple[HypothesisTemplate, ...]] = {
    "c2_beaconing": (
        HypothesisTemplate(
            "push_keepalive", "Legitimate push-notification or keep-alive heartbeat",
            "Messaging, push and smart-home services hold long-lived connections with fixed "
            "heartbeat intervals that look periodic.",
            ("Check whether the destination resolves to a known push/CDN provider in CONSTELLATION",
             "Compare the interval with the device-class benign baseline",
             "Look for matching heartbeats on many unrelated devices of the same class")),
        HypothesisTemplate(
            "iptv_license_polling", "IPTV / streaming app licence, EPG or DRM polling",
            "Legitimate IPTV and streaming apps poll licence and EPG servers on a schedule; "
            "volume and periodicity alone do not indicate a compromised box.",
            ("Check the destination against the IPTV/streaming benign baseline",
             "Confirm the polling stops when the app is idle",
             "Verify no contact with indicators from a signed IOC bundle"),
            ("android_tv", "smart_tv", "set_top_box", "tv_box")),
        HypothesisTemplate(
            "firmware_telemetry", "Vendor firmware telemetry or NTP synchronisation",
            "Firmware agents report telemetry and sync time periodically, often to dedicated "
            "vendor infrastructure.",
            ("Check destination ASN/provider against the device vendor",
             "Check UDP/123 and vendor telemetry hostnames")),
        HypothesisTemplate(
            "stale_or_overbroad_ioc", "Stale or over-broad indicator on reassigned/shared infrastructure",
            "Indicators expire; IPs get reassigned and shared CDN edges host many tenants, so an "
            "IOC hit on such an address may reflect someone else's traffic.",
            ("Check indicator first_seen/last_seen/expires_at",
             "Check co-tenant count of the destination in CONSTELLATION",
             "Look for an operator allowlist or contradicting feed")),
    ),
    "dga_activity": (
        HypothesisTemplate(
            "browser_probes", "Browser intranet-redirect detection probes",
            "Browsers resolve a few random hostnames at start-up to detect NXDOMAIN hijacking; "
            "this produces short bursts of random-looking NXDOMAIN queries.",
            ("Count distinct random names per burst (probes: about 3)",
             "Check bursts align with browser/app start, not a fixed schedule")),
        HypothesisTemplate(
            "cdn_random_subdomains", "CDN / ad-tech randomized subdomains",
            "Some CDNs and ad platforms use per-request random labels under a stable registered "
            "domain.",
            ("Group queries by registered domain; legitimate cases share one parent",
             "Check whether resolutions succeed (NOERROR) for the parent domain")),
        HypothesisTemplate(
            "resolver_misconfiguration", "Resolver search-domain or typo misconfiguration",
            "Search-domain suffixing and mistyped names inflate NXDOMAIN rates.",
            ("Look for the local search suffix appended to queries",
             "Check whether the NXDOMAIN names are dictionary words or typos")),
    ),
    "residential_proxy": (
        HypothesisTemplate(
            "consumer_vpn", "Consumer VPN or privacy relay",
            "VPN and privacy relays create persistent tunnels to few endpoints with high byte "
            "counts.",
            ("Check the destination against known VPN providers",
             "Inbound-initiated connections suggest proxying; outbound tunnels suggest VPN")),
        HypothesisTemplate(
            "p2p_application", "Peer-to-peer application (file sharing, game patching, P2P video)",
            "P2P clients contact many residential peers, resembling proxy fan-out.",
            ("Check port/protocol mix for P2P signatures",
             "Check whether the fan-out follows user activity")),
    ),
    "ddos_bot": (
        HypothesisTemplate(
            "gaming_or_streaming_upload", "Online gaming, live-streaming upload or cloud backup",
            "Game sessions, live streaming and backups produce sustained or bursty upstream "
            "traffic.",
            ("Check destinations: a single game/streaming service vs. many victim IPs",
             "Check packet sizes and SYN/UDP flood patterns")),
        HypothesisTemplate(
            "speed_test", "Speed test or network diagnostic",
            "Speed tests generate short, very high-rate bursts to measurement servers.",
            ("Check destination against speed-test providers",
             "Burst duration under a minute and user-initiated")),
    ),
}

_GENERIC: tuple[HypothesisTemplate, ...] = (
    HypothesisTemplate(
        "nat_conflation", "Several devices aggregated behind one line or NAT",
        "At the subscriber-line vantage, traffic from several devices shares one pseudonym, "
        "so a combination of benign behaviours can look like one anomalous device.",
        ("Check the vantage (subscriber_line vs device)",
         "Look for device-level telemetry (CPE) separating the flows")),
    HypothesisTemplate(
        "telemetry_artifact", "Telemetry gap, duplication or spoofed records",
        "Collector restarts, duplicated exports or spoofed telemetry can fabricate patterns.",
        ("Check evidence integrity and ledger timestamps",
         "Check for duplicate event ids or gaps in the collector stream")),
)


def templates_for(label: str, device_class: str | None) -> list[HypothesisTemplate]:
    """Label-specific templates (filtered by device class) followed by generic ones."""
    dc = (device_class or "unknown").lower()
    specific = [t for t in _LABEL_KB.get(label, ())
                if not t.device_classes or dc in t.device_classes]
    return specific + list(_GENERIC)


def known_labels() -> list[str]:
    return sorted(_LABEL_KB)
