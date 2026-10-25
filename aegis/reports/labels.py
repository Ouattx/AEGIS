"""Display names for machine labels (threat classes, action types, device classes).

Shared by the PoV report templates and mirrored by the console (``web/src/lib/labels.ts``),
so a security audience reads "DDoS bot" and "DNS sinkhole", never "Ddos bot".
"""
from __future__ import annotations

DISPLAY_NAMES: dict[str, str] = {
    # threat classes (finding labels)
    "c2_beaconing": "C2 beaconing",
    "ddos_bot": "DDoS bot",
    "dga_activity": "DGA activity",
    "residential_proxy": "Residential proxy",
    "known_bad_contact": "Known-bad contact",
    "suspicious_activity": "Suspicious activity",
    # action types
    "dns_sinkhole": "DNS sinkhole",
    "ip_block": "IP block",
    "device_quarantine": "Device quarantine",
    "notify_subscriber": "Subscriber notification",
    # device classes
    "android_tv": "Android TV box",
    "smart_tv": "Smart TV",
    "iptv_box": "IPTV box",
    "console": "Game console",
    "phone": "Phone",
    "laptop": "Laptop",
    "camera": "IoT camera",
    "unknown": "Unknown",
}

_ACRONYMS = {"dns": "DNS", "ip": "IP", "ddos": "DDoS", "dga": "DGA", "c2": "C2", "tv": "TV", "iot": "IoT",
             "vpn": "VPN", "cdn": "CDN", "iptv": "IPTV", "rpz": "RPZ", "nx": "NX", "nxdomain": "NXDOMAIN"}


def display_label(value: object) -> str:
    """Human display name: the curated map first, then a casing that keeps acronyms."""
    key = str(value or "").strip()
    if key in DISPLAY_NAMES:
        return DISPLAY_NAMES[key]
    words = [w for w in key.replace("-", "_").split("_") if w]
    if not words:
        return key
    out = [_ACRONYMS.get(w.lower(), w) for w in words]
    first = out[0]
    out[0] = first if first.isupper() or first in _ACRONYMS.values() else first[:1].upper() + first[1:]
    return " ".join(out)


__all__ = ["DISPLAY_NAMES", "display_label"]
