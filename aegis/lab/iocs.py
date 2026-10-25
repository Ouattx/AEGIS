"""Sample signed IOC bundle for the lab (spec sections 4, 11, 15).

Bundle format (``schema = "aegis.ioc_bundle/1"``)::

    {
      "schema": "aegis.ioc_bundle/1",
      "bundle_id": str, "version": str, "issuer": str, "issued_at": RFC3339,
      "indicators": [
        {"indicator_id", "type": "domain"|"ip", "value",
         "verdict": "malicious"|"benign",          # benign = allowlist / contradiction
         "threat_label", "malware_family", "confidence": float in [0,1],
         "first_seen", "last_seen", "expires_at",   # RFC3339; expired => stale, must be ignored
         "source", "source_group",                 # feeds syndicating one report share a group
         "tags": [str], "description": str}
      ],
      "signer_key_id": str,
      "signature": str   # base64 Ed25519 over RFC 8785 canonical JSON of the bundle minus "signature"
    }

The signature convention matches ``aegis.provenance.signing.verify_model``
(``key_field="signer_key_id"``, ``sig_field="signature"``) applied to a dict;
verify with :func:`verify_bundle` and an ``aegis.provenance.signing.KeyRing``.

The sample deliberately contains the hard cases the detection path must handle:
fresh indicators for emulated C2, a *syndicated* duplicate (same origin group),
a *stale* indicator on infrastructure that now hosts a legitimate service, an
*over-broad* indicator on a shared CDN IP contradicted by the operator allowlist,
a *contradicted* C2 domain, and C2 infrastructure deliberately left out (novel).
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.contracts.canonical import canonical_bytes
from aegis.lab.topology import HostingTopology, dga_domains
from aegis.provenance.signing import KeyRing, Signer

BUNDLE_SCHEMA = "aegis.ioc_bundle/1"


class SignerLike(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> str: ...

    def public_pem(self) -> bytes: ...


def lab_signer(seed: int = 7, key_id: str | None = None) -> Signer:
    """Deterministic lab IOC signer for ``seed``. Lab only: never sign production bundles with it."""
    key_id = key_id or f"lab-ioc-signer-{seed}"
    raw = hashlib.sha256(f"aegis-lab-ioc-signer:{seed}".encode()).digest()
    key = Ed25519PrivateKey.from_private_bytes(raw)
    return Signer(key_id, key)


def bundle_signing_bytes(bundle: dict[str, Any]) -> bytes:
    return canonical_bytes({k: v for k, v in bundle.items() if k != "signature"})


def sign_bundle(bundle: dict[str, Any], signer: SignerLike) -> dict[str, Any]:
    out = dict(bundle)
    out["signer_key_id"] = signer.key_id
    out.pop("signature", None)
    out["signature"] = signer.sign(bundle_signing_bytes(out))
    return out


def verify_bundle(bundle: dict[str, Any], keyring: KeyRing) -> bool:
    """True when the bundle is signed by a trusted, non-revoked key in ``keyring``."""
    key_id = bundle.get("signer_key_id")
    sig = bundle.get("signature")
    if not isinstance(key_id, str) or not isinstance(sig, str):
        return False
    return keyring.verify(key_id, bundle_signing_bytes(bundle), sig)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_ioc_bundle(topology: HostingTopology, *, start: datetime, days: int = 3, seed: int = 7,
                     signer: SignerLike | None = None, issued_at: datetime | None = None) -> dict[str, Any]:
    """Build and sign the lab IOC bundle for a corpus window starting at ``start``."""
    if start.tzinfo is None:
        raise ValueError("start must be timezone-aware")
    signer = signer or lab_signer(seed)
    issued = issued_at or start - timedelta(hours=1)
    fresh_first = start - timedelta(days=21)
    fresh_last = start - timedelta(days=1)
    fresh_exp = start + timedelta(days=max(days, 1) + 30)
    inds: list[dict[str, Any]] = []

    def add(typ: str, value: str, *, verdict: str = "malicious", label: str | None, family: str | None,
            source: str, group: str, conf: float, first: datetime = fresh_first, last: datetime = fresh_last,
            exp: datetime = fresh_exp, tags: list[str] | None = None, desc: str = "") -> None:
        inds.append({
            "indicator_id": f"ind-{hashlib.sha256(f'{source}|{typ}|{value}|{verdict}'.encode()).hexdigest()[:16]}",
            "type": typ, "value": value, "verdict": verdict, "threat_label": label, "malware_family": family,
            "confidence": conf, "first_seen": _iso(first), "last_seen": _iso(last), "expires_at": _iso(exp),
            "source": source, "source_group": group, "tags": tags or [], "description": desc,
        })

    bb = topology.malicious["badbox2_emu"]
    vo = topology.malicious["vo1d_emu"]
    mi = topology.malicious["mirai_emu"]

    # fresh C2 indicators (novel infrastructure intentionally omitted)
    for dom, ip in zip(bb.c2_domains, bb.c2_ips):
        if ip in bb.novel_ips:
            continue
        add("domain", dom, label="c2_beaconing", family="badbox2_emu", source="feed:lab_cti_alpha",
            group="grp:alpha", conf=0.9, tags=["c2", "tv_box"], desc="BadBox-style TV box C2 (emulated)")
        add("ip", ip, label="c2_beaconing", family="badbox2_emu", source="feed:lab_cti_alpha",
            group="grp:alpha", conf=0.85, tags=["c2", "dedicated_hosting"])
        # syndicated copy: a second feed republishing alpha's report => same origin group
        add("domain", dom, label="c2_beaconing", family="badbox2_emu", source="feed:lab_cti_alpha_mirror",
            group="grp:alpha", conf=0.9, tags=["c2", "syndicated"], desc="republished from feed:lab_cti_alpha")
    for dom in bb.cohosted_domains:
        add("domain", dom, label="c2_beaconing", family="badbox2_emu", source="feed:lab_cti_beta",
            group="grp:beta", conf=0.8, tags=["c2", "cdn_fronted"])
        for ip in topology.resolve(dom):
            # over-broad: the feed also lists the shared CDN edge IP ...
            add("ip", ip, label="c2_beaconing", family="badbox2_emu", source="feed:lab_cti_beta",
                group="grp:beta", conf=0.5, tags=["c2", "shared_infrastructure"],
                desc="edge IP observed serving a C2 hostname")
            # ... which the operator allowlist contradicts
            add("ip", ip, verdict="benign", label=None, family=None, source="feed:operator_allowlist",
                group="grp:operator", conf=0.95, tags=["shared_cdn", "allowlist"],
                desc=f"shared CDN edge with {len(topology.cotenants(ip, [dom]))} legitimate co-tenants")
    for ip in bb.proxy_controllers:
        add("ip", ip, label="residential_proxy", family="badbox2_emu", source="feed:lab_cti_gamma",
            group="grp:gamma", conf=0.8, tags=["proxy_backconnect"])

    for dom, ip in zip(vo.c2_domains, vo.c2_ips):
        add("domain", dom, label="c2_beaconing", family="vo1d_emu", source="feed:lab_cti_gamma",
            group="grp:gamma", conf=0.85, tags=["c2", "tv_box"])
        add("ip", ip, label="c2_beaconing", family="vo1d_emu", source="feed:lab_cti_gamma",
            group="grp:gamma", conf=0.8, tags=["c2"])
    if vo.dga_seed is not None:
        day0 = int(start.timestamp() // 86400)
        for d in range(max(days, 1)):
            for name in dga_domains(vo.dga_seed, day0 + d, 300)[:3]:
                add("domain", name, label="dga_activity", family="vo1d_emu", source="feed:lab_cti_gamma",
                    group="grp:gamma", conf=0.9, first=start + timedelta(days=d) - timedelta(hours=6),
                    last=start + timedelta(days=d), tags=["dga", "registered"])

    for dom, ip in zip(mi.c2_domains, mi.c2_ips):
        if ip in mi.novel_ips:
            continue
        add("domain", dom, label="ddos_bot", family="mirai_emu", source="feed:lab_cti_alpha",
            group="grp:alpha", conf=0.9, tags=["c2", "ddos"])
        add("ip", ip, label="ddos_bot", family="mirai_emu", source="feed:lab_cti_alpha",
            group="grp:alpha", conf=0.85, tags=["c2", "ddos"])
        # contradicted: another origin claims the domain was sinkholed and is benign
        add("domain", dom, verdict="benign", label=None, family=None, source="feed:lab_sinkhole_registry",
            group="grp:sinkhole", conf=0.4, tags=["sinkhole_claim"],
            desc="registry claims this name is sinkholed (contradicts grp:alpha)")

    # stale: infrastructure that hosted malware long ago and now serves a legitimate service
    push_ep = topology.services["push"][0]
    add("ip", push_ep.ip, label="c2_beaconing", family="legacy_family", source="feed:lab_cti_delta",
        group="grp:delta", conf=0.7, first=start - timedelta(days=400), last=start - timedelta(days=200),
        exp=start - timedelta(days=100), tags=["stale"],
        desc="historic C2 IP; reassigned to a legitimate push service")
    add("domain", "old-tracker.example", label="c2_beaconing", family="legacy_family",
        source="feed:lab_cti_delta", group="grp:delta", conf=0.6, first=start - timedelta(days=500),
        last=start - timedelta(days=300), exp=start - timedelta(days=200), tags=["stale"])

    inds.sort(key=lambda i: i["indicator_id"])
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": f"lab-ioc-{seed}-{start:%Y%m%d}",
        "version": f"{issued:%Y.%m.%d}-lab.{seed}",
        "issuer": "aegis-lab",
        "issued_at": _iso(issued),
        "indicators": inds,
    }
    return sign_bundle(bundle, signer)
