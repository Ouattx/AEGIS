"""Signed IOC bundles and deterministic indicator matching (spec sections 4, 11, 15).

Bundle format: ``aegis.ioc_bundle/1`` (see :mod:`aegis.lab.iocs` for a generator).
The signature is Ed25519 over the RFC 8785 canonical JSON of the bundle minus its
``signature`` field, made by ``signer_key_id``. :func:`load_bundle` refuses any
bundle that does not verify against the operator's :class:`KeyRing` (fail closed).

Matching rules, all evaluated *as of* the window end (contemporaneous):

- an indicator is **known** only once ``first_seen <= now``;
- it is **expired** when ``expires_at <= now`` and **stale** when ``last_seen`` is
  older than ``max_staleness``; expired and stale indicators never match;
- a malicious indicator is **contradicted** when an active *benign* indicator for the
  same value (or a parent domain) comes from a *different* source group. Its
  effective confidence becomes ``confidence * (1 - contradiction_confidence)``,
  the contradiction is returned as counter-evidence, and fusion downgrades it;
- matches below ``min_confidence`` (after contradiction) are dropped, so an
  over-broad indicator on a shared CDN edge that the operator allowlist contradicts
  does not generate evidence for every streaming device;
- corroboration is counted per ``source_group``: syndicated copies of one report
  produce evidence sharing one independence group;
- a domain match is a **verified contact** only when the device also sent traffic to
  an address that name resolved to; a lookup alone is weaker evidence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Literal

from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.contracts.models import Evidence, EvidenceKind, FeatureVector, ObservationEvent
from aegis.provenance.signing import KeyRing
from aegis.sentinel.features import WINDOW_SECONDS, ContactSummary, normalize_name

BUNDLE_SCHEMA = "aegis.ioc_bundle/1"
DEFAULT_MAX_STALENESS = timedelta(days=90)
DEFAULT_MIN_CONFIDENCE = 0.3


class BundleError(ValueError):
    """The bundle is malformed."""


class BundleSignatureError(BundleError):
    """The bundle signature is missing, invalid, or made by an untrusted/revoked key."""


def _parse_ts(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise BundleError(f"{name} must be an RFC 3339 string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BundleError(f"{name}: invalid timestamp {value!r}") from exc
    if dt.tzinfo is None:
        raise BundleError(f"{name} must carry a timezone")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class Indicator:
    indicator_id: str
    type: Literal["domain", "ip"]
    value: str
    verdict: Literal["malicious", "benign"]
    threat_label: str | None
    malware_family: str | None
    confidence: float
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime
    source: str
    source_group: str
    tags: tuple[str, ...] = ()
    description: str = ""

    def state(self, now: datetime, max_staleness: timedelta = DEFAULT_MAX_STALENESS) -> str:
        """``active``, ``not_yet_known``, ``expired`` or ``stale`` at ``now``."""
        if self.first_seen > now:
            return "not_yet_known"
        if self.expires_at <= now:
            return "expired"
        if now - self.last_seen > max_staleness:
            return "stale"
        return "active"

    def is_active(self, now: datetime, max_staleness: timedelta = DEFAULT_MAX_STALENESS) -> bool:
        return self.state(now, max_staleness) == "active"

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Indicator":
        if not isinstance(d, dict):
            raise BundleError("indicator must be an object")
        typ = d.get("type")
        if typ not in ("domain", "ip"):
            raise BundleError(f"indicator type must be domain or ip, got {typ!r}")
        verdict = d.get("verdict", "malicious")
        if verdict not in ("malicious", "benign"):
            raise BundleError(f"indicator verdict must be malicious or benign, got {verdict!r}")
        value = d.get("value")
        if not isinstance(value, str) or not value.strip():
            raise BundleError("indicator value must be a non-empty string")
        conf = d.get("confidence")
        if not isinstance(conf, (int, float)) or isinstance(conf, bool) or not 0.0 <= float(conf) <= 1.0:
            raise BundleError("indicator confidence must be a number in [0, 1]")
        for k in ("indicator_id", "source", "source_group"):
            if not isinstance(d.get(k), str) or not d[k].strip():
                raise BundleError(f"indicator {k} must be a non-empty string")
        first = _parse_ts(d.get("first_seen"), "first_seen")
        last = _parse_ts(d.get("last_seen"), "last_seen")
        exp = _parse_ts(d.get("expires_at"), "expires_at")
        if last < first:
            raise BundleError(f"indicator {d['indicator_id']}: last_seen before first_seen")
        tags = d.get("tags") or []
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise BundleError("indicator tags must be a list of strings")
        return cls(
            indicator_id=d["indicator_id"], type=typ,
            value=normalize_name(value) if typ == "domain" else value.strip(),
            verdict=verdict, threat_label=d.get("threat_label"), malware_family=d.get("malware_family"),
            confidence=float(conf), first_seen=first, last_seen=last, expires_at=exp, source=d["source"],
            source_group=d["source_group"], tags=tuple(tags), description=str(d.get("description") or ""))


@dataclass(frozen=True)
class IOCBundle:
    """A verified, immutable IOC bundle with lookup indexes."""
    bundle_id: str
    version: str
    issuer: str
    issued_at: datetime
    signer_key_id: str
    sha256: str
    indicators: tuple[Indicator, ...]
    max_staleness: timedelta = DEFAULT_MAX_STALENESS
    _index: dict[tuple[str, str], tuple[Indicator, ...]] = field(default_factory=dict, repr=False,
                                                                  compare=False)

    def __post_init__(self) -> None:
        idx: dict[tuple[str, str], list[Indicator]] = {}
        for ind in self.indicators:
            idx.setdefault((ind.type, ind.value), []).append(ind)
        object.__setattr__(self, "_index", {k: tuple(v) for k, v in idx.items()})

    # ------------------------------------------------------------------ lookup
    def for_ip(self, ip: str) -> tuple[Indicator, ...]:
        return self._index.get(("ip", ip.strip()), ())

    def for_domain(self, qname: str) -> tuple[Indicator, ...]:
        """Indicators on ``qname`` or any parent domain (``a.b.example`` matches ``b.example``)."""
        name = normalize_name(qname)
        out: list[Indicator] = []
        parts = name.split(".")
        for i in range(len(parts) - 1):
            out.extend(self._index.get(("domain", ".".join(parts[i:])), ()))
        return tuple(out)

    def active(self, now: datetime) -> list[Indicator]:
        return [i for i in self.indicators if i.is_active(now, self.max_staleness)]

    def state_counts(self, now: datetime) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in self.indicators:
            s = i.state(now, self.max_staleness)
            out[s] = out.get(s, 0) + 1
        return out

    def count_contacts(self, contacts: ContactSummary, now: datetime) -> int:
        """Distinct active malicious indicators contacted (the ``ioc_contacts`` feature)."""
        hit: set[str] = set()
        for ip in contacts.dst_ips:
            hit.update(i.indicator_id for i in self.for_ip(ip)
                       if i.verdict == "malicious" and i.is_active(now, self.max_staleness))
        for q in contacts.qnames:
            hit.update(i.indicator_id for i in self.for_domain(q)
                       if i.verdict == "malicious" and i.is_active(now, self.max_staleness))
        return len(hit)

    def provenance(self) -> dict[str, Any]:
        return {"bundle_id": self.bundle_id, "version": self.version, "issuer": self.issuer,
                "issued_at": self.issued_at.isoformat(), "signer_key_id": self.signer_key_id,
                "sha256": self.sha256, "indicators": len(self.indicators)}


def bundle_signing_bytes(data: dict[str, Any]) -> bytes:
    return canonical_bytes({k: v for k, v in data.items() if k != "signature"})


def load_bundle(data: dict[str, Any] | str | bytes | Path, keyring: KeyRing, *,
                max_staleness: timedelta = DEFAULT_MAX_STALENESS) -> IOCBundle:
    """Verify and parse a bundle. Raises :class:`BundleSignatureError` unless trusted.

    ``data`` may be the parsed dict, JSON text/bytes, or a path to a JSON file.
    """
    if isinstance(data, Path):
        data = data.read_bytes()
    if isinstance(data, (str, bytes)):
        try:
            data = json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BundleError(f"bundle is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BundleError("bundle must be a JSON object")
    key_id, sig = data.get("signer_key_id"), data.get("signature")
    if not isinstance(key_id, str) or not isinstance(sig, str) or not sig:
        raise BundleSignatureError("bundle is unsigned")
    if not keyring.verify(key_id, bundle_signing_bytes(data), sig):
        raise BundleSignatureError(f"bundle signature does not verify for key {key_id!r}")
    if data.get("schema") != BUNDLE_SCHEMA:
        raise BundleError(f"unsupported bundle schema {data.get('schema')!r}")
    for k in ("bundle_id", "version", "issuer"):
        if not isinstance(data.get(k), str) or not data[k]:
            raise BundleError(f"bundle {k} must be a non-empty string")
    raw = data.get("indicators")
    if not isinstance(raw, list):
        raise BundleError("bundle indicators must be a list")
    inds = tuple(Indicator.from_dict(d) for d in raw)
    ids = [i.indicator_id for i in inds]
    if len(set(ids)) != len(ids):
        raise BundleError("duplicate indicator_id in bundle")
    return IOCBundle(bundle_id=data["bundle_id"], version=data["version"], issuer=data["issuer"],
                     issued_at=_parse_ts(data.get("issued_at"), "issued_at"), signer_key_id=key_id,
                     sha256=sha256_hex(data), indicators=inds, max_staleness=max_staleness)


# ---------------------------------------------------------------------------- matching

@dataclass
class _Group:
    ind_type: str
    value: str
    group: str
    matched: str                      # the contacted qname / ip
    indicators: list[Indicator] = field(default_factory=list)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def ioc_match(fv: FeatureVector, events: Iterable[ObservationEvent] | ContactSummary, bundle: IOCBundle,
              now: datetime, *, min_confidence: float = DEFAULT_MIN_CONFIDENCE,
              authorization_id: str | None = None) -> list[Evidence]:
    """Match a window's contacts against fresh indicators.

    Returns supporting ``IOC_MATCH`` evidence (one per matched value and source group)
    followed by counter-evidence (``THREAT_FEED``, ``supports=False``) for every
    contradicting benign claim. Evidence is not persisted here.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if isinstance(events, ContactSummary):
        cs = events
    else:
        cs = ContactSummary.from_events(events, tenant_id=fv.tenant_id, entity_pseudonym=fv.entity_pseudonym,
                                        window_start=fv.window_end - _window_len(fv), window_end=fv.window_end)
    stale = bundle.max_staleness
    groups: dict[tuple[str, str, str], _Group] = {}
    for ip in cs.dst_ips:
        for ind in bundle.for_ip(ip):
            if ind.verdict == "malicious" and ind.is_active(now, stale):
                g = groups.setdefault(("ip", ind.value, ind.source_group), _Group("ip", ind.value,
                                                                                   ind.source_group, ip))
                g.indicators.append(ind)
    for q in cs.qnames:
        for ind in bundle.for_domain(q):
            if ind.verdict == "malicious" and ind.is_active(now, stale):
                g = groups.setdefault(("domain", ind.value, ind.source_group),
                                      _Group("domain", ind.value, ind.source_group, q))
                g.indicators.append(ind)

    auth = authorization_id or (sorted(cs.authorization_ids)[0] if cs.authorization_ids
                                else f"ioc-bundle:{bundle.bundle_id}")
    supporting: list[Evidence] = []
    counter: dict[tuple[str, str], Evidence] = {}
    for g in groups.values():
        contra = [b for b in (bundle.for_ip(g.matched) if g.ind_type == "ip" else bundle.for_domain(g.matched))
                  if b.verdict == "benign" and b.source_group != g.group and b.is_active(now, stale)]
        contra_conf = max((b.confidence for b in contra), default=0.0)
        conf = max(i.confidence for i in g.indicators)
        effective = conf * (1.0 - contra_conf)
        if effective < min_confidence:
            continue
        if g.ind_type == "ip":
            verified = g.matched in cs.dst_ips
            count = cs.dst_ips[g.matched]
            first, last = cs.ip_times.get(g.matched, (0.0, 0.0))
            resolved: list[str] = [g.matched]
        else:
            resolved = sorted(cs.resolved_ips(g.matched))
            verified = any(ip in cs.dst_ips for ip in resolved)
            count = cs.qnames[g.matched]
            first, last = cs.qname_times.get(g.matched, (0.0, 0.0))
        labels = sorted({i.threat_label for i in g.indicators if i.threat_label})
        families = sorted({i.malware_family for i in g.indicators if i.malware_family})
        sources = sorted({i.source for i in g.indicators})
        contact = "contacted" if verified else "looked up"
        summary = (f"{contact} {g.matched} ({g.ind_type} indicator {g.value}; "
                   f"{', '.join(labels) or 'malicious'}) {count}x; source group {g.group} "
                   f"({', '.join(sources)}), confidence {conf:.2f}"
                   + (f", contradicted by {', '.join(sorted({b.source for b in contra}))} -> effective "
                      f"{effective:.2f}" if contra else ""))
        supporting.append(Evidence(
            tenant_id=fv.tenant_id, kind=EvidenceKind.IOC_MATCH, origin_source=sources[0],
            source_independence_group=g.group, collected_at=now, summary=summary,
            authorization_id=auth, supports=True,
            payload={
                "entity_pseudonym": fv.entity_pseudonym, "window_end": fv.window_end.isoformat(),
                "indicator_type": g.ind_type, "indicator_value": g.value, "matched": g.matched,
                "indicator_ids": sorted(i.indicator_id for i in g.indicators), "sources": sources,
                "threat_labels": labels, "malware_families": families, "confidence": conf,
                "effective_confidence": round(effective, 6), "contradicted": bool(contra),
                "contradicting_sources": sorted({b.source for b in contra}),
                "contradiction_confidence": contra_conf, "verified_contact": verified,
                "resolved_ips": resolved[:16], "contact_count": count,
                "first_contact": _iso(first) if first else None, "last_contact": _iso(last) if last else None,
                "bundle": bundle.provenance(),
            }))
        for b in contra:
            key = (b.indicator_id, g.matched)
            if key in counter:
                continue
            counter[key] = Evidence(
                tenant_id=fv.tenant_id, kind=EvidenceKind.THREAT_FEED, origin_source=b.source,
                source_independence_group=b.source_group, collected_at=now, supports=False,
                authorization_id=auth,
                summary=(f"{b.source} asserts {b.value} is benign (confidence {b.confidence:.2f})"
                         + (f": {b.description}" if b.description else "")),
                payload={"entity_pseudonym": fv.entity_pseudonym, "indicator_id": b.indicator_id,
                         "indicator_type": b.type, "indicator_value": b.value, "matched": g.matched,
                         "confidence": b.confidence, "tags": list(b.tags), "contradicts_group": g.group,
                         "bundle": bundle.provenance()})
    supporting.sort(key=lambda e: (-e.payload["effective_confidence"], e.payload["indicator_value"],
                                   e.source_independence_group))
    return supporting + sorted(counter.values(), key=lambda e: (e.payload["indicator_value"],
                                                                 e.payload["indicator_id"]))


def _window_len(fv: FeatureVector) -> timedelta:
    return timedelta(seconds=WINDOW_SECONDS[fv.window])


__all__ = [
    "BUNDLE_SCHEMA", "DEFAULT_MAX_STALENESS", "DEFAULT_MIN_CONFIDENCE", "BundleError", "BundleSignatureError",
    "IOCBundle", "Indicator", "bundle_signing_bytes", "ioc_match", "load_bundle",
]
