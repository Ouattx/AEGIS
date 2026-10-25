"""Data types of the threat-intelligence layer (module-local; shared contracts stay in aegis.contracts).

Three kinds of records come out of feed parsing:

- :class:`IntelIndicator`: a network indicator (domain, IP or CIDR) asserted by a
  feed, normalized, with its lifecycle (``first_seen`` / ``last_seen`` /
  ``expires_at``), confidence, license and ``source_group`` (the independence
  group: syndicated copies of one report share it);
- :class:`VictimReport`: a third-party report that one of the operator's *own*
  lines was seen infected (Shadowserver). The line is pseudonymized at parse time
  with the tenant's pseudonymizer; the raw address is never stored. Victim reports
  are tenant-internal and never leave the tenant;
- :class:`ParseResult`: a parser's output plus skip counters and line-level errors.
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

IndicatorType = Literal["domain", "ip", "cidr"]
IndicatorVerdict = Literal["malicious", "benign"]
IndicatorState = Literal["active", "not_yet_known", "expired", "stale", "withdrawn"]

DEFAULT_MAX_STALENESS = timedelta(days=90)
"""Same default as :data:`aegis.sentinel.rules.DEFAULT_MAX_STALENESS`."""


def utc(dt: datetime) -> datetime:
    """Return ``dt`` as aware UTC. Naive datetimes are refused (feeds state their zone)."""
    if dt.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return utc(dt).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


@dataclass(frozen=True)
class IntelIndicator:
    """One normalized indicator after feed import (possibly merged across feeds of one group)."""
    type: IndicatorType
    value: str                               # normalized: lower-case domain / canonical IP / canonical CIDR
    verdict: IndicatorVerdict
    threat_label: str | None                 # c2_beaconing, malware_distribution, ddos_bot, hijacked_netblock ...
    malware_family: str | None
    confidence: float                        # in [0, 1]
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime
    source_group: str                        # independence group (syndicated copies share it)
    sources: tuple[str, ...]                 # feed ids that asserted it, e.g. ("feed:urlhaus",)
    license: str
    redistributable: bool                    # False => never shared with the consortium
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    withdrawn_at: datetime | None = None     # a snapshot feed stopped listing it
    syndicated_groups: tuple[str, ...] = ()  # other groups found to republish this report

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence}")
        if self.last_seen < self.first_seen:
            raise ValueError(f"{self.value}: last_seen before first_seen")
        for name in ("first_seen", "last_seen", "expires_at"):
            if getattr(self, name).tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Dedup key: one record per (type, value, verdict, independence group)."""
        return (self.type, self.value, self.verdict, self.source_group)

    @property
    def primary_source(self) -> str:
        return sorted(self.sources)[0]

    def state(self, now: datetime, max_staleness: timedelta = DEFAULT_MAX_STALENESS) -> IndicatorState:
        """Lifecycle state at ``now`` (same rules as SENTINEL, plus ``withdrawn``)."""
        if self.first_seen > now:
            return "not_yet_known"
        if self.withdrawn_at is not None and self.withdrawn_at <= now:
            return "withdrawn"
        if self.expires_at <= now:
            return "expired"
        if now - self.last_seen > max_staleness:
            return "stale"
        return "active"

    def is_active(self, now: datetime, max_staleness: timedelta = DEFAULT_MAX_STALENESS) -> bool:
        return self.state(now, max_staleness) == "active"

    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        if self.type == "ip":
            return ipaddress.ip_network(self.value)
        if self.type == "cidr":
            return ipaddress.ip_network(self.value, strict=False)
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type, "value": self.value, "verdict": self.verdict, "threat_label": self.threat_label,
            "malware_family": self.malware_family, "confidence": self.confidence,
            "first_seen": iso(self.first_seen), "last_seen": iso(self.last_seen),
            "expires_at": iso(self.expires_at), "source_group": self.source_group, "sources": list(self.sources),
            "license": self.license, "redistributable": self.redistributable, "tags": list(self.tags),
            "references": list(self.references),
            "withdrawn_at": iso(self.withdrawn_at) if self.withdrawn_at else None,
            "syndicated_groups": list(self.syndicated_groups),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "IntelIndicator":
        return cls(
            type=d["type"], value=d["value"], verdict=d["verdict"], threat_label=d.get("threat_label"),
            malware_family=d.get("malware_family"), confidence=float(d["confidence"]),
            first_seen=parse_iso(d["first_seen"]), last_seen=parse_iso(d["last_seen"]),
            expires_at=parse_iso(d["expires_at"]), source_group=d["source_group"],
            sources=tuple(d["sources"]), license=d["license"], redistributable=bool(d["redistributable"]),
            tags=tuple(d.get("tags") or ()), references=tuple(d.get("references") or ()),
            withdrawn_at=parse_iso(d["withdrawn_at"]) if d.get("withdrawn_at") else None,
            syndicated_groups=tuple(d.get("syndicated_groups") or ()))

    def merged_with(self, other: "IntelIndicator") -> "IntelIndicator":
        """Merge two records with the same :attr:`key` (dedup within one independence group).

        The widest lifecycle wins (earliest first_seen, latest last_seen and expiry) and the
        highest confidence wins: within one group the copies are the *same* witness, so their
        confidences are not combined.
        """
        if other.key != self.key:
            raise ValueError("can only merge indicators with the same key")
        withdrawn = None
        if self.withdrawn_at is not None and other.withdrawn_at is not None:
            withdrawn = max(self.withdrawn_at, other.withdrawn_at)
        return replace(
            self,
            threat_label=self.threat_label or other.threat_label,
            malware_family=self.malware_family or other.malware_family,
            confidence=max(self.confidence, other.confidence),
            first_seen=min(self.first_seen, other.first_seen),
            last_seen=max(self.last_seen, other.last_seen),
            expires_at=max(self.expires_at, other.expires_at),
            sources=tuple(sorted(set(self.sources) | set(other.sources))),
            license=self.license if self.license == other.license else
            " + ".join(sorted({self.license, other.license})),
            redistributable=self.redistributable and other.redistributable,
            tags=tuple(sorted(set(self.tags) | set(other.tags))),
            references=tuple(sorted(set(self.references) | set(other.references)))[:16],
            withdrawn_at=withdrawn,
            syndicated_groups=tuple(sorted(set(self.syndicated_groups) | set(other.syndicated_groups))),
        )


@dataclass(frozen=True)
class VictimReport:
    """A third party says one of the operator's lines was seen infected or exposed.

    ``line_pseudonym`` is the tenant pseudonym of the reported address (same
    pseudonymizer as ingest, so it joins with ``entity_pseudonym`` when ingest keys
    lines by source IP). Raw addresses are never kept. ``kind="exposure"`` (an open
    service seen by a scan) is *not* evidence of compromise and is never treated as such.
    """
    line_pseudonym: str
    observed_at: datetime
    kind: Literal["infection", "exposure"]
    report_type: str
    malware_family: str | None
    source: str
    source_group: str
    license: str


@dataclass
class ParseResult:
    """Output of one feed parser run."""
    feed_id: str
    indicators: list[IntelIndicator] = field(default_factory=list)
    victims: list[VictimReport] = field(default_factory=list)
    skipped: Counter[str] = field(default_factory=Counter)
    errors: list[tuple[int, str]] = field(default_factory=list)   # (line number, reason)
    generated_at: datetime | None = None                           # feed's own timestamp, when stated
    rows: int = 0

    def summary(self) -> dict[str, Any]:
        return {"feed_id": self.feed_id, "rows": self.rows, "indicators": len(self.indicators),
                "victims": len(self.victims), "skipped": dict(sorted(self.skipped.items())),
                "errors": len(self.errors),
                "generated_at": iso(self.generated_at) if self.generated_at else None}


@dataclass(frozen=True)
class Contradiction:
    """A malicious claim and a benign claim on the same value from different independence groups."""
    type: IndicatorType
    value: str
    malicious_groups: tuple[str, ...]
    benign_groups: tuple[str, ...]
    malicious_confidence: float
    benign_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value, "malicious_groups": list(self.malicious_groups),
                "benign_groups": list(self.benign_groups), "malicious_confidence": self.malicious_confidence,
                "benign_confidence": self.benign_confidence}


__all__ = [
    "DEFAULT_MAX_STALENESS", "Contradiction", "IndicatorState", "IndicatorType", "IndicatorVerdict",
    "IntelIndicator", "ParseResult", "VictimReport", "iso", "parse_iso", "utc",
]
