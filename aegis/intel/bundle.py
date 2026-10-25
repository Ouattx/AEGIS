"""Emit signed ``aegis.ioc_bundle/1`` bundles that :func:`aegis.sentinel.rules.load_bundle` accepts.

The bundle schema supports ``domain`` and ``ip`` indicators only. CIDR indicators
(Spamhaus DROP) are therefore either left out (default, counted in the build report)
or expanded into per-address indicators when the prefix is small enough
(``cidr_expand_max``). Reconciliation (:mod:`aegis.intel.reconcile`) matches CIDRs
natively, so DROP coverage is still measured even when the bundle omits it.

Indicator ids are deterministic (``intel-`` + SHA-256 of group, type, value and
verdict), so rebuilding a bundle from the same store yields the same ids and the
same content hash. Signing uses the same canonical-bytes convention as
:mod:`aegis.lab.iocs` and :mod:`aegis.sentinel.rules`.
"""
from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from aegis.contracts.canonical import sha256_hex
from aegis.intel.models import IntelIndicator, iso, utc
from aegis.intel.store import OPERATOR_GROUP, IntelStore
from aegis.sentinel.rules import BUNDLE_SCHEMA, bundle_signing_bytes


class SignerLike(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> str: ...


@dataclass
class BundleBuildReport:
    bundle_id: str
    version: str
    sha256: str
    included: int
    by_type: dict[str, int] = field(default_factory=dict)
    excluded: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"bundle_id": self.bundle_id, "version": self.version, "sha256": self.sha256,
                "included": self.included, "by_type": self.by_type, "excluded": self.excluded}


def indicator_id(group: str, typ: str, value: str, verdict: str) -> str:
    return "intel-" + hashlib.sha256(f"{group}|{typ}|{value}|{verdict}".encode()).hexdigest()[:20]


#: independence group of evidence derived from the operator's own telemetry (SENTINEL, RESONANCE)
TELEMETRY_GROUP = "operator-telemetry"


def _is_operator_detection(ind: IntelIndicator) -> bool:
    """A malicious indicator the operator's own detectors produced (e.g. RESONANCE campaigns)."""
    return ind.verdict != "benign" and (ind.source_group == OPERATOR_GROUP
                                        or ind.source_group.startswith(OPERATOR_GROUP + ":"))


def _entry(ind: IntelIndicator, typ: str, value: str, group: str | None = None) -> dict[str, Any]:
    desc = f"{', '.join(ind.sources)}"
    if ind.syndicated_groups:
        desc += f"; republished by {', '.join(ind.syndicated_groups)}"
    desc += f"; license {ind.license}"
    if typ != ind.type:
        desc += f"; expanded from {ind.value}"
    tags = list(ind.tags)
    if typ != ind.type:
        tags.append("cidr_expanded")
    return {
        "indicator_id": indicator_id(group or ind.source_group, typ, value, ind.verdict), "type": typ, "value": value,
        "verdict": ind.verdict, "threat_label": ind.threat_label, "malware_family": ind.malware_family,
        "confidence": ind.confidence, "first_seen": iso(ind.first_seen), "last_seen": iso(ind.last_seen),
        "expires_at": iso(ind.withdrawn_at if ind.withdrawn_at and ind.withdrawn_at < ind.expires_at
                          else ind.expires_at),
        "source": ind.primary_source, "source_group": group or ind.source_group, "tags": sorted(set(tags)),
        "description": desc[:500],
    }


def build_ioc_bundle(source: IntelStore | Iterable[IntelIndicator], signer: SignerLike, *, now: datetime,
                     issuer: str, bundle_id: str | None = None, version: str | None = None,
                     states: Iterable[str] = ("active", "not_yet_known"), min_confidence: float = 0.0,
                     cidr_expand_max: int = 0, max_indicators: int = 500_000,
                     max_staleness: timedelta | None = None, include_operator_detections: bool = False
                     ) -> tuple[dict[str, Any], BundleBuildReport]:
    """Build and sign a SENTINEL IOC bundle from a store (or an indicator iterable).

    Malicious indicators that the operator's own detectors produced (``grp:operator*``,
    e.g. :func:`aegis.intel.sharing.campaign_indicators`) are left out by default
    (``operator_detection`` in the report): fed back as IOCs they would let one telemetry
    observation corroborate itself as if a feed had confirmed it. With
    ``include_operator_detections=True`` they are emitted in the ``operator-telemetry``
    independence group, so SENTINEL and the case state machine count them as the same
    origin as the detection that produced them. Operator allowlist (benign) entries are
    always kept: they contradict feed claims.

    ``states`` selects lifecycle states to include (expired, stale and withdrawn
    indicators are left out by default; SENTINEL would ignore them anyway).
    ``cidr_expand_max`` > 0 expands CIDRs with at most that many addresses.
    Raises ``ValueError`` when more than ``max_indicators`` would be emitted.
    """
    now = utc(now)
    stale: timedelta | None
    if isinstance(source, IntelStore):
        inds = source.indicators()
        stale = source.max_staleness
    else:
        inds = list(source)
        stale = max_staleness
    wanted = set(states)
    excluded: Counter[str] = Counter()
    entries: dict[str, dict[str, Any]] = {}
    for ind in inds:
        st = ind.state(now, stale) if stale is not None else ind.state(now)
        if st not in wanted:
            excluded[f"state:{st}"] += 1
            continue
        if ind.confidence < min_confidence:
            excluded["below_min_confidence"] += 1
            continue
        group = None
        if _is_operator_detection(ind):
            if not include_operator_detections:
                excluded["operator_detection"] += 1
                continue
            group = TELEMETRY_GROUP
        if ind.type == "cidr":
            net = ipaddress.ip_network(ind.value)
            if cidr_expand_max <= 0 or net.num_addresses > cidr_expand_max:
                excluded["cidr_not_representable"] += 1
                continue
            for addr in net:
                e = _entry(ind, "ip", str(addr), group)
                entries[e["indicator_id"]] = e
            continue
        e = _entry(ind, ind.type, ind.value, group)
        entries[e["indicator_id"]] = e
        if len(entries) > max_indicators:
            raise ValueError(f"bundle would exceed {max_indicators} indicators")
    if len(entries) > max_indicators:
        raise ValueError(f"bundle would exceed {max_indicators} indicators")
    body_list = [entries[k] for k in sorted(entries)]
    content_hash = sha256_hex(body_list)
    bid = bundle_id or f"intel-{content_hash[:16]}"
    ver = version or f"{now:%Y.%m.%d.%H%M%S}-intel"
    bundle: dict[str, Any] = {
        "schema": BUNDLE_SCHEMA, "bundle_id": bid, "version": ver, "issuer": issuer, "issued_at": iso(now),
        "indicators": body_list, "signer_key_id": signer.key_id,
    }
    bundle["signature"] = signer.sign(bundle_signing_bytes(bundle))
    report = BundleBuildReport(bundle_id=bid, version=ver, sha256=sha256_hex(bundle), included=len(body_list),
                               by_type=dict(sorted(Counter(e["type"] for e in body_list).items())),
                               excluded=dict(sorted(excluded.items())))
    return bundle, report


__all__ = ["BundleBuildReport", "build_ioc_bundle", "indicator_id"]
