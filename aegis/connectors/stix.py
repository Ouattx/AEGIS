"""STIX 2.1 bundles of *verified* campaigns and indicators, with structural validation.

Only analyst-verified material is exported: every :class:`VerifiedCampaign` and
:class:`VerifiedIndicator` carries a non-empty ``verification_ref`` (the case id or
review record that verified it). Bundles are meant to leave the operator, so they never
contain line pseudonyms, tenant ids or subscriber data: a campaign states how many lines
took part, not which.

Which EGRESS observables become indicators (:func:`from_egress_report`):

* residential-proxy upstream sinks (``shared_sink`` campaigns) -> ``indicator`` on the sink
  address (attacker-side infrastructure);
* DDoS / spam / credential-stuffing targets and abused reflectors are victims or abused
  third parties: they appear only as campaign context, never as indicators (sharing them
  as "malicious" would get victims blocked).

Object model (STIX 2.1, OASIS Committee Specification): ``identity`` (producer),
``marking-definition`` (the predefined TLP marking), ``campaign``, ``indicator``
(``pattern_type: stix``) and ``relationship`` (``indicates``). Identifiers are
deterministic UUIDv5 values, so re-exporting the same verified material yields the same
ids. :func:`validate_bundle` checks the structural rules this exporter relies on; it is
not a full STIX validator.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis.connectors.common import ExportPayload, utc
from aegis.contracts.canonical import canonical_bytes
from aegis.egress.config import LABEL_PROXY
from aegis.egress.models import EgressReport

Tlp = Literal["white", "green", "amber", "red"]

#: Predefined TLP marking-definition objects (STIX 2.1 section 7.2.1.4).
TLP_MARKINGS: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
_TLP_CREATED = "2017-01-20T00:00:00.000Z"
_NAMESPACE = uuid.UUID("6f2c3e0a-9d2b-5c1e-8a47-3b0e7d5c9a10")

#: subscriber-side and internal space: never exported as an indicator (documentation ranges
#: such as 192.0.2.0/24 stay allowed so lab exports work)
_NEVER_SHARED = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))

IndicatorKind = Literal["ipv4-addr", "ipv6-addr", "domain-name", "url"]

_ID = re.compile(r"^([a-z0-9][a-z0-9-]*[a-z0-9])--([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
_PATTERN = re.compile(r"^\[(ipv4-addr|ipv6-addr|domain-name|url):value = '((?:[^'\\]|\\.)*)'\]$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_INDICATOR_TYPES = {"anomalous-activity", "anonymization", "benign", "compromised", "malicious-activity",
                    "attribution", "unknown"}
_SDO_REQUIRED = {
    "identity": ("name",),
    "campaign": ("name",),
    "indicator": ("pattern", "pattern_type", "valid_from"),
    "relationship": ("relationship_type", "source_ref", "target_ref"),
    "marking-definition": (),
}


def stix_time(dt: datetime) -> str:
    return utc(dt).strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc(dt).microsecond // 1000:03d}Z"


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NAMESPACE, f'{kind}|{key}')}"


def _escape_pattern(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class VerifiedCampaign(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str                                 # stable local id (e.g. the EGRESS campaign_id)
    name: str
    description: str
    first_seen: datetime
    last_seen: datetime
    lines_involved: int | None = Field(default=None, ge=0)
    verification_ref: str

    @field_validator("verification_ref", "name", "key")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty (only verified material is exported)")
        return v.strip()


class VerifiedIndicator(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: IndicatorKind
    value: str
    name: str
    description: str = ""
    indicator_types: tuple[str, ...] = ("malicious-activity",)
    confidence: int = Field(default=70, ge=0, le=100)
    valid_from: datetime
    valid_until: datetime | None = None
    campaign_key: str | None = None
    verification_ref: str

    @field_validator("verification_ref")
    @classmethod
    def _verified(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("verification_ref is required (only verified material is exported)")
        return v.strip()

    @field_validator("indicator_types")
    @classmethod
    def _types(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        bad = set(v) - _INDICATOR_TYPES
        if bad or not v:
            raise ValueError(f"indicator_types must be from the STIX open vocabulary, got {sorted(bad) or v}")
        return v

    def normalized_value(self) -> str:
        if self.kind in ("ipv4-addr", "ipv6-addr"):
            a = ipaddress.ip_address(self.value.strip())
            if (a.version == 4) != (self.kind == "ipv4-addr"):
                raise ValueError(f"{self.value} is not an {self.kind}")
            if any(a in net for net in _NEVER_SHARED) or a.is_loopback or a.is_link_local or a.is_multicast \
                    or a.is_unspecified:
                raise ValueError(f"{self.value} is a private / internal address and is never shared")
            return a.compressed
        if self.kind == "domain-name":
            d = self.value.strip().rstrip(".").lower()
            if not _DOMAIN.match(d):
                raise ValueError(f"invalid domain {self.value!r}")
            return d
        if not re.match(r"^https?://[^\s'\\]+$", self.value.strip()):
            raise ValueError(f"invalid url {self.value!r}")
        return self.value.strip()


def from_egress_report(report: EgressReport, verified: Mapping[str, str], *,
                       indicator_ttl_days: int = 30) -> tuple[list[VerifiedCampaign], list[VerifiedIndicator]]:
    """Verified campaigns of ``report`` (``verified``: campaign_id -> verification ref).

    Campaigns absent from ``verified`` are not exported. Only proxy sinks become
    indicators; every other campaign is exported as context without indicators.
    """
    camps: list[VerifiedCampaign] = []
    inds: list[VerifiedIndicator] = []
    for c in report.campaigns:
        ref = (verified.get(c.campaign_id) or "").strip()
        if not ref:
            continue
        camps.append(VerifiedCampaign(
            key=c.campaign_id, name=f"{c.label.replace('_', ' ')} ({c.kind.replace('_', ' ')})",
            description=(f"{c.n_lines} subscriber lines of one operator observed together ({c.kind}); "
                         "verified by the operator's analysts. Targets of DDoS, spam or login attacks are victims "
                         "and are not listed as indicators."),
            first_seen=c.start, last_seen=c.end, lines_involved=c.n_lines, verification_ref=ref))
        if c.label == LABEL_PROXY and c.kind == "shared_sink":
            for sink in c.targets:
                try:
                    kind: IndicatorKind = "ipv4-addr" if ipaddress.ip_address(sink).version == 4 else "ipv6-addr"
                except ValueError:
                    continue
                inds.append(VerifiedIndicator(
                    kind=kind, value=sink, name=f"Residential proxy upstream {sink}",
                    description="Upstream that several unrelated subscriber lines relayed proxied traffic to.",
                    indicator_types=("anonymization", "malicious-activity"), valid_from=c.start,
                    valid_until=c.end + timedelta(days=indicator_ttl_days), campaign_key=c.campaign_id,
                    verification_ref=ref))
    return camps, inds


def build_bundle(campaigns: Iterable[VerifiedCampaign], indicators: Iterable[VerifiedIndicator], *,
                 producer_name: str, now: datetime, tlp: Tlp = "amber") -> dict[str, Any]:
    """A STIX 2.1 bundle (dict). Raises ``ValueError`` when the result does not validate."""
    if not producer_name or not producer_name.strip():
        raise ValueError("producer_name is required")
    if tlp not in TLP_MARKINGS:
        raise ValueError(f"unknown TLP {tlp!r}")
    ts = stix_time(now)
    marking = TLP_MARKINGS[tlp]
    ident = _sid("identity", producer_name.strip())
    common = {"spec_version": "2.1", "created_by_ref": ident, "object_marking_refs": [marking]}
    objects: list[dict[str, Any]] = [
        {"type": "marking-definition", "spec_version": "2.1", "id": marking, "created": _TLP_CREATED,
         "definition_type": "tlp", "name": f"TLP:{tlp.upper()}", "definition": {"tlp": tlp}},
        {"type": "identity", "spec_version": "2.1", "id": ident, "created": ts, "modified": ts,
         "name": producer_name.strip(), "identity_class": "organization", "object_marking_refs": [marking]},
    ]
    camp_ids: dict[str, str] = {}
    for c in campaigns:
        cid = _sid("campaign", c.key)
        camp_ids[c.key] = cid
        obj = {"type": "campaign", "id": cid, "created": ts, "modified": ts, "name": c.name,
               "description": c.description, "first_seen": stix_time(c.first_seen),
               "last_seen": stix_time(c.last_seen), **common}
        if c.lines_involved is not None:
            obj["x_aegis_lines_involved"] = c.lines_involved
        objects.append(obj)
    for i in indicators:
        value = i.normalized_value()
        iid = _sid("indicator", f"{i.kind}|{value}|{i.campaign_key or ''}")
        obj = {"type": "indicator", "id": iid, "created": ts, "modified": ts, "name": i.name,
               "indicator_types": list(i.indicator_types),
               "pattern": f"[{i.kind}:value = '{_escape_pattern(value)}']", "pattern_type": "stix",
               "pattern_version": "2.1", "valid_from": stix_time(i.valid_from), "confidence": i.confidence,
               **common}
        if i.description:
            obj["description"] = i.description
        if i.valid_until is not None:
            if utc(i.valid_until) <= utc(i.valid_from):
                raise ValueError("valid_until must be after valid_from")
            obj["valid_until"] = stix_time(i.valid_until)
        objects.append(obj)
        if i.campaign_key is not None:
            if i.campaign_key not in camp_ids:
                raise ValueError(f"indicator references unknown campaign {i.campaign_key!r}")
            objects.append({"type": "relationship", "id": _sid("relationship", f"{iid}|indicates|{camp_ids[i.campaign_key]}"),
                            "created": ts, "modified": ts, "relationship_type": "indicates", "source_ref": iid,
                            "target_ref": camp_ids[i.campaign_key], **common})
    seen: dict[str, dict[str, Any]] = {}
    for o in objects:
        seen.setdefault(o["id"], o)
    content = list(seen.values())
    bundle = {"type": "bundle", "id": _sid("bundle", canonical_bytes(content).decode("utf-8")), "objects": content}
    errors = validate_bundle(bundle)
    if errors:
        raise ValueError("STIX bundle failed validation: " + "; ".join(errors))
    return bundle


def _parse_ts(v: Any) -> datetime | None:
    if not isinstance(v, str) or not _TS.match(v):
        return None
    return datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def _check_id(v: Any, kind: str | None = None) -> bool:
    if not isinstance(v, str):
        return False
    m = _ID.match(v)
    if not m:
        return False
    try:
        u = uuid.UUID(m.group(2))
    except ValueError:
        return False
    if u.variant != uuid.RFC_4122:
        return False
    return kind is None or m.group(1) == kind


def validate_bundle(bundle: Any) -> list[str]:
    """Structural STIX 2.1 checks used by this exporter; empty list means valid."""
    errs: list[str] = []
    if not isinstance(bundle, dict):
        return ["bundle is not an object"]
    if bundle.get("type") != "bundle":
        errs.append("bundle.type must be 'bundle'")
    if not _check_id(bundle.get("id"), "bundle"):
        errs.append("bundle.id must be 'bundle--<RFC 4122 UUID>'")
    if "spec_version" in bundle:
        errs.append("bundle must not carry spec_version in STIX 2.1")
    objs = bundle.get("objects")
    if not isinstance(objs, list) or not objs:
        return errs + ["bundle.objects must be a non-empty list"]
    ids: set[str] = set()
    for n, o in enumerate(objs):
        where = f"objects[{n}]"
        if not isinstance(o, dict):
            errs.append(f"{where} is not an object")
            continue
        t = o.get("type")
        if t not in _SDO_REQUIRED:
            errs.append(f"{where}.type {t!r} is not supported by this exporter")
            continue
        oid = o.get("id")
        if not _check_id(oid, t):
            errs.append(f"{where}.id {oid!r} must be '{t}--<RFC 4122 UUID>'")
        elif oid in ids:
            errs.append(f"{where}.id {oid} is duplicated")
        else:
            ids.add(oid)
        if o.get("spec_version") != "2.1":
            errs.append(f"{where}.spec_version must be '2.1'")
        created = _parse_ts(o.get("created"))
        if created is None:
            errs.append(f"{where}.created must be an RFC 3339 UTC timestamp ending in Z")
        if t != "marking-definition":
            modified = _parse_ts(o.get("modified"))
            if modified is None:
                errs.append(f"{where}.modified must be an RFC 3339 UTC timestamp ending in Z")
            elif created is not None and modified < created:
                errs.append(f"{where}.modified is before created")
        for f in _SDO_REQUIRED[t]:
            if o.get(f) in (None, ""):
                errs.append(f"{where}.{f} is required for {t}")
        if t == "indicator":
            pat = o.get("pattern")
            if isinstance(pat, str) and not _PATTERN.match(pat):
                errs.append(f"{where}.pattern {pat!r} is not a supported STIX comparison")
            if o.get("pattern_type") != "stix":
                errs.append(f"{where}.pattern_type must be 'stix'")
            vf, vu = _parse_ts(o.get("valid_from")), o.get("valid_until")
            if vf is None:
                errs.append(f"{where}.valid_from must be an RFC 3339 UTC timestamp")
            if vu is not None and (_parse_ts(vu) is None or (vf is not None and _parse_ts(vu) <= vf)):
                errs.append(f"{where}.valid_until must be a timestamp after valid_from")
            types = o.get("indicator_types")
            if types is not None and (not isinstance(types, list) or set(types) - _INDICATOR_TYPES):
                errs.append(f"{where}.indicator_types must use the indicator-type-ov vocabulary")
            conf = o.get("confidence")
            if conf is not None and (not isinstance(conf, int) or isinstance(conf, bool) or not 0 <= conf <= 100):
                errs.append(f"{where}.confidence must be an integer 0..100")
        if t == "identity" and "identity_class" in o and not isinstance(o["identity_class"], str):
            errs.append(f"{where}.identity_class must be a string")
        if t == "campaign":
            fs, ls = _parse_ts(o.get("first_seen")), _parse_ts(o.get("last_seen"))
            if fs is not None and ls is not None and ls < fs:
                errs.append(f"{where}.last_seen is before first_seen")
        if t == "marking-definition" and o.get("definition_type") == "tlp":
            tlp = (o.get("definition") or {}).get("tlp")
            if TLP_MARKINGS.get(tlp) != oid:
                errs.append(f"{where} is not the predefined TLP:{str(tlp).upper()} marking")
    for n, o in enumerate(objs):
        if not isinstance(o, dict):
            continue
        refs = [("created_by_ref", o.get("created_by_ref"))] if "created_by_ref" in o else []
        refs += [("object_marking_refs", r) for r in o.get("object_marking_refs") or []]
        if o.get("type") == "relationship":
            refs += [("source_ref", o.get("source_ref")), ("target_ref", o.get("target_ref"))]
        for name, ref in refs:
            if not _check_id(ref):
                errs.append(f"objects[{n}].{name} {ref!r} is not a STIX identifier")
            elif ref not in ids:
                errs.append(f"objects[{n}].{name} {ref} does not resolve inside the bundle")
        if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            if not str(o.get("source_ref", "")).startswith("indicator--"):
                errs.append(f"objects[{n}]: 'indicates' must have an indicator as source")
    return errs


def stix_export(campaigns: Iterable[VerifiedCampaign], indicators: Iterable[VerifiedIndicator], *,
                tenant_id: str, producer_name: str, now: datetime, tlp: Tlp = "amber") -> ExportPayload:
    """The validated bundle as an :class:`ExportPayload` (``tenant_id`` is never put in the bundle)."""
    camps, inds = list(campaigns), list(indicators)
    bundle = build_bundle(camps, inds, producer_name=producer_name, now=now, tlp=tlp)
    return ExportPayload.build("stix", tenant_id, "application/stix+json;version=2.1",
                               canonical_bytes(bundle).decode("utf-8"), records=len(bundle["objects"]),
                               generated_at=now)


__all__ = [
    "TLP_MARKINGS", "VerifiedCampaign", "VerifiedIndicator", "build_bundle", "from_egress_report", "stix_export",
    "stix_time", "validate_bundle",
]
