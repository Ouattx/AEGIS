"""Tenant-scoped indicator store: dedup, syndication grouping, withdrawal and contradictions.

:class:`IntelStore` holds one tenant's merged view of every imported feed. It is an
in-memory structure with a JSON-safe :meth:`IntelStore.snapshot` /
:meth:`IntelStore.from_snapshot` pair so the composition root can persist it (for
example as one document per tenant) and rebuild it at start-up.

Rules:

- **dedup** — one record per ``(type, value, verdict, source_group)``; copies inside a
  group merge (widest lifecycle, highest confidence, union of sources): one witness;
- **syndication** — a record arriving from a *different* group with the same value,
  verdict and reference and a ``first_seen`` within :data:`SYNDICATION_WINDOW` of an
  existing record is a republished copy: it is folded into the original group and the
  republishing group is listed in ``syndicated_groups`` (so it never counts as a second
  independent origin);
- **withdrawal** — for snapshot feeds (Feodo, DROP) an entry that a feed listed before
  and no longer lists is ``withdrawn`` from that import onward;
- **contradictions** — an active malicious claim and an active benign claim (operator
  allowlist, sinkhole registry, ...) on the same value from different groups.
"""
from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from aegis.intel.catalog import FeedSpec
from aegis.intel.formats import classify_host, normalize_cidr
from aegis.intel.models import (
    DEFAULT_MAX_STALENESS,
    Contradiction,
    IntelIndicator,
    ParseResult,
    VictimReport,
    iso,
    parse_iso,
    utc,
)

SNAPSHOT_SCHEMA = "aegis.intel_store/1"
SYNDICATION_WINDOW = timedelta(seconds=60)
OPERATOR_GROUP = "grp:operator"


@dataclass
class ImportReport:
    feed_id: str
    imported_at: datetime
    parsed: dict[str, Any]
    added: int = 0
    merged: int = 0
    syndicated: int = 0
    withdrawn: int = 0
    reinstated: int = 0
    victims: int = 0
    new_contradictions: list[Contradiction] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"feed_id": self.feed_id, "imported_at": iso(self.imported_at), "parsed": self.parsed,
                "added": self.added, "merged": self.merged, "syndicated": self.syndicated,
                "withdrawn": self.withdrawn, "reinstated": self.reinstated, "victims": self.victims,
                "new_contradictions": [c.to_dict() for c in self.new_contradictions]}


class IntelStore:
    """One tenant's merged indicator view. Thread-safe for concurrent imports and reads."""

    def __init__(self, tenant_id: str, *, max_staleness: timedelta = DEFAULT_MAX_STALENESS,
                 max_victim_reports: int = 100_000):
        if not tenant_id:
            raise ValueError("tenant_id required")
        self.tenant_id = tenant_id
        self.max_staleness = max_staleness
        self._max_victims = max_victim_reports
        self._lock = threading.RLock()
        self._records: dict[tuple[str, str, str, str], IntelIndicator] = {}
        self._by_value: dict[tuple[str, str, str], set[tuple[str, str, str, str]]] = {}
        self._feed_keys: dict[str, set[tuple[str, str, str, str]]] = {}   # snapshot feed -> keys listed last time
        self._victims: list[VictimReport] = []
        self._imports: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ import
    def ingest(self, result: ParseResult, spec: FeedSpec, imported_at: datetime) -> ImportReport:
        """Merge one parse result. ``spec`` must be the spec the result was parsed with."""
        if result.feed_id != spec.feed_id:
            raise ValueError(f"parse result is for {result.feed_id}, spec is {spec.feed_id}")
        now = utc(imported_at)
        report = ImportReport(feed_id=spec.feed_id, imported_at=now, parsed=result.summary())
        with self._lock:
            before = {(c.type, c.value) for c in self.contradictions(now)}
            listed: set[tuple[str, str, str, str]] = set()
            for ind in result.indicators:
                key = self._place(ind, report)
                listed.add(key)
            if spec.snapshot:
                for key in self._feed_keys.get(spec.feed_id, set()) - listed:
                    rec = self._records.get(key)
                    if rec is None or rec.withdrawn_at is not None:
                        continue
                    others = set(rec.sources) - {spec.feed_id}
                    if others:
                        continue                  # still asserted by another feed of the group
                    self._records[key] = replace(rec, withdrawn_at=now)
                    report.withdrawn += 1
                self._feed_keys[spec.feed_id] = listed
            for v in result.victims:
                if v.source_group != spec.source_group:
                    raise ValueError("victim report group does not match the feed spec")
                self._victims.append(v)
                report.victims += 1
            if len(self._victims) > self._max_victims:
                self._victims = self._victims[-self._max_victims:]
            report.new_contradictions = [c for c in self.contradictions(now) if (c.type, c.value) not in before]
            self._imports.append(report.to_dict())
            self._imports = self._imports[-200:]
        return report

    def _place(self, ind: IntelIndicator, report: ImportReport) -> tuple[str, str, str, str]:
        key = ind.key
        existing = self._records.get(key)
        if existing is None:
            original = self._syndication_origin(ind)
            if original is not None:
                folded = replace(ind, source_group=original.source_group,
                                 syndicated_groups=tuple(sorted({*ind.syndicated_groups, ind.source_group})))
                self._records[original.key] = original.merged_with(folded)
                report.syndicated += 1
                return original.key
            self._set(ind)
            report.added += 1
            return key
        merged = existing.merged_with(ind)
        if existing.withdrawn_at is not None:
            merged = replace(merged, withdrawn_at=None)
            report.reinstated += 1
        self._records[key] = merged
        report.merged += 1
        return key

    def _set(self, ind: IntelIndicator) -> None:
        self._records[ind.key] = ind
        self._by_value.setdefault((ind.type, ind.value, ind.verdict), set()).add(ind.key)

    def _syndication_origin(self, ind: IntelIndicator) -> IntelIndicator | None:
        if not ind.references:
            return None
        refs = set(ind.references)
        for k in sorted(self._by_value.get((ind.type, ind.value, ind.verdict), ())):
            rec = self._records[k]
            if rec.source_group == ind.source_group or not refs & set(rec.references):
                continue
            if abs(rec.first_seen - ind.first_seen) <= SYNDICATION_WINDOW:
                return rec
        return None

    def add_allowlist(self, values: Iterable[str], *, reason: str, now: datetime,
                      ttl: timedelta = timedelta(days=365), confidence: float = 0.95,
                      group: str = OPERATOR_GROUP) -> int:
        """Operator allowlist entries become *benign* indicators (they contradict feed claims)."""
        now = utc(now)
        n = 0
        with self._lock:
            for raw in values:
                try:
                    typ, value = normalize_cidr(raw) if "/" in raw else classify_host(raw)
                except ValueError as exc:
                    raise ValueError(f"allowlist entry {raw!r}: {exc}") from exc
                ind = IntelIndicator(type=typ, value=value,  # type: ignore[arg-type]
                                     verdict="benign", threat_label=None,
                                     malware_family=None, confidence=confidence, first_seen=now, last_seen=now,
                                     expires_at=now + ttl, source_group=group, sources=("feed:operator_allowlist",),
                                     license="operator-internal", redistributable=False, tags=("allowlist",),
                                     references=(f"reason:{reason[:120]}",))
                prev = self._records.get(ind.key)
                self._set(prev.merged_with(ind) if prev else ind)
                n += 1
        return n

    def add_indicators(self, indicators: Iterable[IntelIndicator]) -> int:
        """Add locally produced indicators (e.g. :func:`aegis.intel.sharing.campaign_indicators`)."""
        report = ImportReport(feed_id="local", imported_at=datetime(1970, 1, 1, tzinfo=timezone.utc), parsed={})
        with self._lock:
            for ind in indicators:
                self._place(ind, report)
        return report.added + report.merged + report.syndicated

    # ------------------------------------------------------------------ reads
    def indicators(self, *, states: Iterable[str] | None = None, now: datetime | None = None,
                   verdict: str | None = None) -> list[IntelIndicator]:
        """All records, optionally filtered by lifecycle state at ``now`` and verdict."""
        with self._lock:
            recs = list(self._records.values())
        if verdict is not None:
            recs = [r for r in recs if r.verdict == verdict]
        if states is not None:
            if now is None:
                raise ValueError("now is required to filter by state")
            wanted = set(states)
            recs = [r for r in recs if r.state(utc(now), self.max_staleness) in wanted]
        return sorted(recs, key=lambda r: (r.type, r.value, r.verdict, r.source_group))

    def active(self, now: datetime) -> list[IntelIndicator]:
        return self.indicators(states=("active",), now=now)

    def victims(self) -> list[VictimReport]:
        with self._lock:
            return list(self._victims)

    def state_counts(self, now: datetime) -> dict[str, int]:
        c: Counter[str] = Counter(r.state(utc(now), self.max_staleness) for r in self.indicators())
        return dict(sorted(c.items()))

    def contradictions(self, now: datetime) -> list[Contradiction]:
        now = utc(now)
        by_value: dict[tuple[str, str], list[IntelIndicator]] = {}
        with self._lock:
            for r in self._records.values():
                if r.is_active(now, self.max_staleness):
                    by_value.setdefault((r.type, r.value), []).append(r)
        out: list[Contradiction] = []
        for (typ, value), recs in by_value.items():
            mal = [r for r in recs if r.verdict == "malicious"]
            ben = [r for r in recs if r.verdict == "benign"]
            if not mal or not ben:
                continue
            mg, bg = {r.source_group for r in mal}, {r.source_group for r in ben}
            if mg == bg and len(mg) == 1:
                continue      # one group retracting itself is not a contradiction between witnesses
            out.append(Contradiction(type=typ, value=value,  # type: ignore[arg-type]
                                     malicious_groups=tuple(sorted(mg)),
                                     benign_groups=tuple(sorted(bg)),
                                     malicious_confidence=max(r.confidence for r in mal),
                                     benign_confidence=max(r.confidence for r in ben)))
        return sorted(out, key=lambda c: (c.type, c.value))

    def independent_groups(self, typ: str, value: str, now: datetime) -> list[str]:
        """Distinct independence groups currently asserting ``value`` malicious."""
        return sorted({r.source_group for r in self.indicators(states=("active",), now=now, verdict="malicious")
                       if r.type == typ and r.value == value})

    def status(self, now: datetime) -> dict[str, Any]:
        recs = self.indicators()
        return {"tenant_id": self.tenant_id, "indicators": len(recs), "states": self.state_counts(now),
                "by_group": dict(sorted(Counter(r.source_group for r in recs).items())),
                "by_type": dict(sorted(Counter(r.type for r in recs).items())),
                "contradictions": len(self.contradictions(now)), "victim_reports": len(self.victims()),
                "recent_imports": list(self._imports[-10:])}

    # ------------------------------------------------------------------ persistence
    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": SNAPSHOT_SCHEMA, "tenant_id": self.tenant_id,
                "max_staleness_s": int(self.max_staleness.total_seconds()),
                "indicators": [r.to_dict() for r in self.indicators()],
                "feed_keys": {f: sorted(list(k) for k in keys) for f, keys in sorted(self._feed_keys.items())},
                "victims": [{"line_pseudonym": v.line_pseudonym, "observed_at": iso(v.observed_at), "kind": v.kind,
                             "report_type": v.report_type, "malware_family": v.malware_family,
                             "source": v.source, "source_group": v.source_group, "license": v.license}
                            for v in self._victims],
                "imports": list(self._imports),
            }

    @classmethod
    def from_snapshot(cls, data: dict[str, Any], *, tenant_id: str) -> "IntelStore":
        """Rebuild a store. ``tenant_id`` must match the snapshot's (no cross-tenant loads)."""
        if data.get("schema") != SNAPSHOT_SCHEMA:
            raise ValueError(f"unsupported intel store schema {data.get('schema')!r}")
        if data.get("tenant_id") != tenant_id:
            raise PermissionError("snapshot belongs to another tenant")
        st = cls(tenant_id, max_staleness=timedelta(seconds=int(data.get("max_staleness_s",
                                                                           DEFAULT_MAX_STALENESS.total_seconds()))))
        for d in data.get("indicators", []):
            st._set(IntelIndicator.from_dict(d))
        for feed, keys in (data.get("feed_keys") or {}).items():
            st._feed_keys[feed] = {tuple(k) for k in keys}  # type: ignore[misc]
        for v in data.get("victims", []):
            st._victims.append(VictimReport(line_pseudonym=v["line_pseudonym"],
                                            observed_at=parse_iso(v["observed_at"]), kind=v["kind"],
                                            report_type=v["report_type"], malware_family=v.get("malware_family"),
                                            source=v["source"], source_group=v["source_group"],
                                            license=v["license"]))
        st._imports = list(data.get("imports", []))
        return st


class IntelStoreDoc(BaseModel):
    """DocStore envelope for a store snapshot (``doc_id = <tenant>:intel_store``)."""
    model_config = ConfigDict(extra="forbid")
    doc_id: str
    tenant_id: str
    snapshot: dict[str, Any]


class DocStoreLike(Protocol):
    def put(self, obj: BaseModel) -> None: ...

    def get(self, model: Any, tenant_id: str, id_: str) -> Any: ...


def save_store(docstore: DocStoreLike, store: IntelStore) -> None:
    """Persist ``store`` as one tenant-scoped document."""
    docstore.put(IntelStoreDoc(doc_id=f"{store.tenant_id}:intel_store", tenant_id=store.tenant_id,
                               snapshot=store.snapshot()))


def load_store(docstore: DocStoreLike, tenant_id: str) -> IntelStore | None:
    """Load the tenant's persisted store, or ``None`` when it has none."""
    doc = docstore.get(IntelStoreDoc, tenant_id, f"{tenant_id}:intel_store")
    if doc is None:
        return None
    return IntelStore.from_snapshot(doc.snapshot, tenant_id=tenant_id)


__all__ = ["ImportReport", "IntelStore", "IntelStoreDoc", "OPERATOR_GROUP", "SNAPSHOT_SCHEMA", "SYNDICATION_WINDOW",
           "load_store", "save_store"]
