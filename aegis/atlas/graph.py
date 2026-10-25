"""ATLAS: tenant-scoped temporal infrastructure graph (spec section 5).

Data model
----------
The graph is *bitemporal* and append-only:

* ``observed_at`` (valid time): when the relationship was seen in the world;
* ``recorded_at`` (knowledge time): when ATLAS learned about it.

Every upsert writes one immutable *observation* row keyed by
``(tenant_id, edge_id, provenance_id)``. Re-delivering the same provenance id is a
no-op (idempotent event consumer); re-delivering it with different content is a
:class:`AtlasConflictError` because it indicates a producer bug or tampering.
Edge attributes (``first_seen``, ``last_seen``, provenance ids, evidence grade,
independent-source count, TTL expiry) are always *derived* from the observations
visible at the query time, so "as known at T" (``as_of=T``) only folds observations
with ``recorded_at <= T`` and ``observed_at <= T``. Later knowledge can never leak
into a historical answer, and the same ``as_of`` always produces the same snapshot
hash.

Enforcement eligibility
-----------------------
ATLAS never authorizes anything; it only labels edges so downstream code (MIRROR,
ORACLE guards) can refuse weak links. An edge is ``enforcement_eligible`` only if
all of these hold:

* its type is ``observed_resolves_to``, ``verified_contacts`` or ``attributed_to``;
* it is not a candidate (predicted) link;
* it is active (not past its TTL at the reference time);
* evidence grade A/B, or grade C corroborated by >= 2 independent source groups;
* for ``observed_resolves_to``: the destination is not shared hosting.

``co_observed`` (co-hosting) edges are **never** eligible, and candidate link
prediction results are always flagged ``investigative_only``.

Overlinking guard
-----------------
:meth:`Atlas.related` traverses the graph for investigation context but does not
expand through hub nodes (e.g. shared CDN edges serving hundreds of tenants),
co-hosting edges or candidate edges, so one shared IP cannot pull an entire
CDN customer base into a case.
"""
from __future__ import annotations

import ipaddress
import json
import math
import threading
from collections import defaultdict, deque
from datetime import date, datetime, time, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
    or_,
    select,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column, sessionmaker

from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.storage.db import Base

ATLAS_SNAPSHOT_VERSION = 1
ATLAS_SNAPSHOT_ENTRY_TYPE = "atlas_snapshot"

# ----------------------------------------------------------------------------- enums


class NodeType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    ASN = "asn"
    CERTIFICATE = "certificate"
    MALWARE_FAMILY = "malware_family"
    INCIDENT = "incident"
    DEVICE_CLASS = "device_class"
    DEVICE = "device"            # pseudonymous device/line id only, never a subscriber id
    SOURCE = "source"
    CASE = "case"


class EdgeType(str, Enum):
    OBSERVED_RESOLVES_TO = "observed_resolves_to"
    VERIFIED_CONTACTS = "verified_contacts"
    CO_OBSERVED = "co_observed"
    ATTRIBUTED_TO = "attributed_to"
    MENTIONED_IN_CASE = "mentioned_in_case"


class EvidenceGrade(str, Enum):
    """Strength of the evidence behind an observation (A strongest).

    A: first-party verified fact (signed IOC hit, operator system of record).
    B: first-party sensor observation (operator resolver / flow sensor).
    C: single reputable third-party source.
    D: unverified or low-confidence third-party claim.
    E: inferred / predicted (candidate links). Never enforcement-eligible.
    """
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"

    @property
    def rank(self) -> int:
        return "ABCDE".index(self.value)


#: Edge types that may ever be considered for enforcement.
ENFORCEMENT_CAPABLE_EDGE_TYPES = frozenset({
    EdgeType.OBSERVED_RESOLVES_TO, EdgeType.VERIFIED_CONTACTS, EdgeType.ATTRIBUTED_TO,
})

#: Symmetric edge types: (a, b) and (b, a) are the same edge.
SYMMETRIC_EDGE_TYPES = frozenset({EdgeType.CO_OBSERVED})

#: Default TTL per edge type, in hours.
DEFAULT_TTL_HOURS: dict[EdgeType, int] = {
    EdgeType.OBSERVED_RESOLVES_TO: 72,
    EdgeType.VERIFIED_CONTACTS: 168,
    EdgeType.CO_OBSERVED: 24,
    EdgeType.ATTRIBUTED_TO: 720,
    EdgeType.MENTIONED_IN_CASE: 2160,
}

MAX_TTL_HOURS = 24 * 365 * 2


class AtlasError(RuntimeError):
    """Base class for ATLAS failures."""


class AtlasConflictError(AtlasError):
    """Same provenance id re-delivered with different content."""


# ----------------------------------------------------------------------------- time helpers


def _utc(dt: datetime) -> datetime:
    if not isinstance(dt, datetime):
        raise TypeError("expected a datetime")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc)


def _from_db(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------- node ids


def normalize_node_value(node_type: NodeType | str, value: str) -> str:
    """Canonical form of a node value (lower-case domains, compressed IPs, numeric ASNs)."""
    nt = NodeType(node_type)
    if not isinstance(value, str):
        raise TypeError("node value must be a string")
    v = value.strip()
    if not v:
        raise ValueError("node value must be non-empty")
    if nt is NodeType.DOMAIN:
        v = v.rstrip(".").lower()
        if not v or len(v) > 253 or any(c.isspace() for c in v) or ":" in v:
            raise ValueError(f"invalid domain {value!r}")
        return v
    if nt is NodeType.IP:
        try:
            return ipaddress.ip_address(v).compressed
        except ValueError as exc:
            raise ValueError(f"invalid IP address {value!r}") from exc
    if nt is NodeType.ASN:
        digits = v.upper().removeprefix("AS")
        if not digits.isdigit():
            raise ValueError(f"invalid ASN {value!r}")
        return str(int(digits))
    if len(v) > 200 or any(c in v for c in "\r\n\t"):
        raise ValueError(f"invalid {nt.value} value {value!r}")
    return v


def node_key(node_type: NodeType | str, value: str) -> str:
    """Node id ``"<type>:<normalized value>"``, e.g. ``domain:c2.example``."""
    nt = NodeType(node_type)
    return f"{nt.value}:{normalize_node_value(nt, value)}"


def parse_node_id(node_id: str) -> tuple[NodeType, str]:
    """Split and validate a node id; returns ``(type, normalized value)``."""
    if not isinstance(node_id, str) or ":" not in node_id:
        raise ValueError(f"node id must look like '<type>:<value>', got {node_id!r}")
    prefix, _, value = node_id.partition(":")
    try:
        nt = NodeType(prefix)
    except ValueError as exc:
        raise ValueError(f"unknown node type {prefix!r}") from exc
    return nt, normalize_node_value(nt, value)


def canonical_node_id(node_id: str) -> str:
    nt, value = parse_node_id(node_id)
    return f"{nt.value}:{value}"


def indicator_node_id(value: str) -> str:
    """Node id for an indicator string: an IP if it parses as one, else a domain."""
    try:
        return node_key(NodeType.IP, value)
    except ValueError:
        return node_key(NodeType.DOMAIN, value)


def _edge_id(tenant_id: str, src: str, dst: str, edge_type: EdgeType, candidate: bool) -> str:
    return sha256_hex({"t": tenant_id, "s": src, "d": dst, "e": edge_type.value,
                       "c": candidate})[:40]


# ----------------------------------------------------------------------------- tables


class AtlasNodeRow(Base):
    __tablename__ = "atlas_nodes"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(320), primary_key=True)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (Index("ix_atlas_nodes_tenant_type", "tenant_id", "node_type"),)


class AtlasNodeObservationRow(Base):
    __tablename__ = "atlas_node_observations"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    node_id: Mapped[str] = mapped_column(String(320), nullable=False)
    provenance_id: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attrs: Mapped[dict] = mapped_column(JSON, nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "node_id", "provenance_id", name="uq_atlas_node_obs"),
        Index("ix_atlas_node_obs_node", "tenant_id", "node_id"),
    )


class AtlasEdgeRow(Base):
    __tablename__ = "atlas_edges"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    src: Mapped[str] = mapped_column(String(320), nullable=False)
    dst: Mapped[str] = mapped_column(String(320), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(32), nullable=False)
    candidate: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        Index("ix_atlas_edges_src", "tenant_id", "src"),
        Index("ix_atlas_edges_dst", "tenant_id", "dst"),
    )


class AtlasEdgeObservationRow(Base):
    __tablename__ = "atlas_edge_observations"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    edge_id: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_id: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_grade: Mapped[str] = mapped_column(String(1), nullable=False)
    source_group: Mapped[str] = mapped_column(String(160), nullable=False)
    ttl_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    attrs: Mapped[dict] = mapped_column(JSON, nullable=False)
    __table_args__ = (
        UniqueConstraint("tenant_id", "edge_id", "provenance_id", name="uq_atlas_edge_obs"),
        Index("ix_atlas_edge_obs_edge", "tenant_id", "edge_id"),
    )


class AtlasSnapshotRow(Base):
    __tablename__ = "atlas_snapshots"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    snapshot_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    subject_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (Index("ix_atlas_snapshots_tenant_asof", "tenant_id", "as_of"),)


# ----------------------------------------------------------------------------- views


class _View(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AtlasNode(_View):
    tenant_id: str
    node_id: str
    node_type: NodeType
    value: str
    first_seen: datetime | None
    last_seen: datetime | None
    attrs: dict[str, Any] = Field(default_factory=dict)
    provenance_ids: list[str] = Field(default_factory=list)


class AtlasEdge(_View):
    tenant_id: str
    edge_id: str
    src: str
    dst: str
    edge_type: EdgeType
    first_seen: datetime
    last_seen: datetime
    provenance_ids: list[str]
    evidence_grade: EvidenceGrade
    independent_source_count: int
    source_groups: list[str]
    observation_count: int
    ttl_hours: int
    expires_at: datetime
    active: bool
    candidate: bool = False
    investigative_only: bool = False
    enforcement_eligible: bool = False
    eligibility_reasons: list[str] = Field(default_factory=list)
    attrs: dict[str, Any] = Field(default_factory=dict)


class Neighbor(_View):
    node_id: str
    node_type: NodeType
    direction: Literal["out", "in"]
    edge: AtlasEdge


class RelatedNode(_View):
    node_id: str
    node_type: NodeType
    depth: int
    path_edge_ids: list[str]
    hub: bool = False                  # not expanded further: degree above the hub limit
    via_weak_edge: bool = False        # reached through co-hosting or candidate edge
    enforcement_eligible_path: bool = False


class CandidateLink(_View):
    """Predicted link. Always investigative-only; never feeds enforcement."""
    tenant_id: str
    src: str
    dst: str
    score: float
    method: Literal["adamic_adar"] = "adamic_adar"
    shared_neighbors: list[str]
    rationale: str
    investigative_only: Literal[True] = True
    enforcement_eligible: Literal[False] = False


# ----------------------------------------------------------------------------- service


class _Obs:
    __slots__ = ("provenance_id", "observed_at", "recorded_at", "grade", "group", "ttl", "attrs")

    def __init__(self, row: AtlasEdgeObservationRow):
        self.provenance_id = row.provenance_id
        self.observed_at = _from_db(row.observed_at)
        self.recorded_at = _from_db(row.recorded_at)
        self.grade = EvidenceGrade(row.evidence_grade)
        self.group = row.source_group
        self.ttl = row.ttl_hours
        self.attrs = row.attrs or {}


class Atlas:
    """Temporal graph service. Every method is scoped to one tenant.

    ``ledger`` (optional, :class:`aegis.provenance.ledger.Ledger`) anchors recorded
    snapshots in the provenance chain. ``clock`` supplies "now" (UTC) and exists
    for deterministic tests.
    """

    def __init__(self, session_factory: sessionmaker[Session], *, ledger: Any | None = None,
                 shared_hosting_threshold: int = 3, hub_degree_limit: int = 25,
                 clock: Callable[[], datetime] | None = None):
        if shared_hosting_threshold < 2:
            raise ValueError("shared_hosting_threshold must be >= 2")
        if hub_degree_limit < 2:
            raise ValueError("hub_degree_limit must be >= 2")
        self._sf = session_factory
        self._ledger = ledger
        self._shared_threshold = shared_hosting_threshold
        self._hub_limit = hub_degree_limit
        self._clock = clock or _now
        self._lock = threading.Lock()

    @property
    def hub_degree_limit(self) -> int:
        return self._hub_limit

    # ------------------------------------------------------------------ writes

    def upsert_node(self, tenant_id: str, node_type: NodeType | str, value: str,
                    observed_at: datetime, provenance_id: str, *,
                    attrs: dict[str, Any] | None = None,
                    recorded_at: datetime | None = None) -> AtlasNode:
        """Record that a node was seen. Idempotent per ``provenance_id``."""
        nid = node_key(node_type, value)
        _check(tenant_id, "tenant_id", 64)
        _check(provenance_id, "provenance_id", 160)
        obs_at = _utc(observed_at)
        rec_at = _utc(recorded_at) if recorded_at is not None else self._clock()
        clean_attrs = _json_attrs(attrs)
        for attempt in range(3):
            try:
                with self._sf.begin() as s:
                    self._ensure_node(s, tenant_id, nid, rec_at)
                    existing = s.scalars(select(AtlasNodeObservationRow).where(
                        AtlasNodeObservationRow.tenant_id == tenant_id,
                        AtlasNodeObservationRow.node_id == nid,
                        AtlasNodeObservationRow.provenance_id == provenance_id)).first()
                    if existing is not None:
                        if (_from_db(existing.observed_at) != obs_at
                                or (existing.attrs or {}) != clean_attrs):
                            raise AtlasConflictError(
                                f"provenance {provenance_id!r} re-delivered for node {nid!r} "
                                "with different content")
                    else:
                        s.add(AtlasNodeObservationRow(
                            tenant_id=tenant_id, node_id=nid, provenance_id=provenance_id,
                            observed_at=obs_at, recorded_at=rec_at, attrs=clean_attrs))
                break
            except IntegrityError:
                if attempt == 2:
                    raise
        node = self.get_node(tenant_id, nid)
        assert node is not None
        return node

    def upsert_edge(self, tenant_id: str, src: str, dst: str, edge_type: EdgeType | str,
                    observed_at: datetime, provenance_id: str,
                    evidence_grade: EvidenceGrade | str, source_group: str,
                    ttl_hours: int | None = None, *, attrs: dict[str, Any] | None = None,
                    recorded_at: datetime | None = None) -> AtlasEdge:
        """Record one observation of ``src -[edge_type]-> dst``.

        Idempotent per ``provenance_id``: a redelivery with identical content returns
        the current edge; different content raises :class:`AtlasConflictError`.
        Grade ``E`` is reserved for candidate links (:meth:`add_candidate_edge`).
        """
        grade = EvidenceGrade(evidence_grade)
        if grade is EvidenceGrade.E:
            raise ValueError("grade E is reserved for candidate links; use add_candidate_edge")
        return self._upsert_edge(tenant_id, src, dst, EdgeType(edge_type), observed_at,
                                 provenance_id, grade, source_group, ttl_hours, attrs,
                                 recorded_at, candidate=False)

    def add_candidate_edge(self, tenant_id: str, src: str, dst: str, edge_type: EdgeType | str,
                           observed_at: datetime, provenance_id: str, *, rationale: str,
                           source_group: str = "agent:threat_correlation",
                           ttl_hours: int | None = None,
                           recorded_at: datetime | None = None) -> AtlasEdge:
        """Record a predicted/hypothesized link. Always grade E, investigative-only."""
        if not isinstance(rationale, str) or not rationale.strip():
            raise ValueError("candidate edges require a rationale")
        return self._upsert_edge(tenant_id, src, dst, EdgeType(edge_type), observed_at,
                                 provenance_id, EvidenceGrade.E, source_group, ttl_hours,
                                 {"rationale": rationale.strip()[:2000]}, recorded_at,
                                 candidate=True)

    def link_case(self, tenant_id: str, case_id: str, node_id: str, observed_at: datetime,
                  provenance_id: str, *, recorded_at: datetime | None = None) -> AtlasEdge:
        """``case -[mentioned_in_case]-> node`` (administrative, never eligible)."""
        return self.upsert_edge(tenant_id, node_key(NodeType.CASE, case_id), node_id,
                                EdgeType.MENTIONED_IN_CASE, observed_at, provenance_id,
                                EvidenceGrade.A, "operator:case_management",
                                recorded_at=recorded_at)

    def _upsert_edge(self, tenant_id: str, src: str, dst: str, et: EdgeType,
                     observed_at: datetime, provenance_id: str, grade: EvidenceGrade,
                     source_group: str, ttl_hours: int | None, attrs: dict[str, Any] | None,
                     recorded_at: datetime | None, *, candidate: bool) -> AtlasEdge:
        _check(tenant_id, "tenant_id", 64)
        _check(provenance_id, "provenance_id", 160)
        _check(source_group, "source_group", 160)
        src_id, dst_id = canonical_node_id(src), canonical_node_id(dst)
        if src_id == dst_id:
            raise ValueError("self-loops are not allowed")
        if et in SYMMETRIC_EDGE_TYPES and dst_id < src_id:
            src_id, dst_id = dst_id, src_id
        ttl = DEFAULT_TTL_HOURS[et] if ttl_hours is None else ttl_hours
        if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= MAX_TTL_HOURS:
            raise ValueError(f"ttl_hours must be an int in [1, {MAX_TTL_HOURS}]")
        obs_at = _utc(observed_at)
        rec_at = _utc(recorded_at) if recorded_at is not None else self._clock()
        group = source_group.strip().casefold()
        clean_attrs = _json_attrs(attrs)
        eid = _edge_id(tenant_id, src_id, dst_id, et, candidate)
        for attempt in range(3):
            try:
                with self._sf.begin() as s:
                    self._ensure_node(s, tenant_id, src_id, rec_at)
                    self._ensure_node(s, tenant_id, dst_id, rec_at)
                    if s.get(AtlasEdgeRow, (tenant_id, eid)) is None:
                        s.add(AtlasEdgeRow(tenant_id=tenant_id, edge_id=eid, src=src_id,
                                           dst=dst_id, edge_type=et.value, candidate=candidate,
                                           created_at=rec_at))
                        s.flush()
                    existing = s.scalars(select(AtlasEdgeObservationRow).where(
                        AtlasEdgeObservationRow.tenant_id == tenant_id,
                        AtlasEdgeObservationRow.edge_id == eid,
                        AtlasEdgeObservationRow.provenance_id == provenance_id)).first()
                    if existing is not None:
                        same = (_from_db(existing.observed_at) == obs_at
                                and existing.evidence_grade == grade.value
                                and existing.source_group == group
                                and existing.ttl_hours == ttl
                                and (existing.attrs or {}) == clean_attrs)
                        if not same:
                            raise AtlasConflictError(
                                f"provenance {provenance_id!r} re-delivered for edge {eid} "
                                "with different content")
                    else:
                        s.add(AtlasEdgeObservationRow(
                            tenant_id=tenant_id, edge_id=eid, provenance_id=provenance_id,
                            observed_at=obs_at, recorded_at=rec_at, evidence_grade=grade.value,
                            source_group=group, ttl_hours=ttl, attrs=clean_attrs))
                break
            except IntegrityError:
                if attempt == 2:
                    raise
        edge = self.get_edge(tenant_id, eid)
        assert edge is not None
        return edge

    @staticmethod
    def _ensure_node(s: Session, tenant_id: str, node_id: str, rec_at: datetime) -> None:
        if s.get(AtlasNodeRow, (tenant_id, node_id)) is None:
            nt, value = parse_node_id(node_id)
            s.add(AtlasNodeRow(tenant_id=tenant_id, node_id=node_id, node_type=nt.value,
                               value=value, created_at=rec_at))
            s.flush()

    # ------------------------------------------------------------------ consumers

    def ingest_event(self, event: Any, *, recorded_at: datetime | None = None) -> list[AtlasEdge]:
        """Idempotent consumer for :class:`~aegis.contracts.models.ObservationEvent`.

        DNS responses with IP answers become ``observed_resolves_to`` edges
        (grade B: the operator's own resolver saw it), provenance = event id.
        Other events carry no infrastructure relationship and are ignored.
        """
        dns = getattr(event, "dns", None)
        if dns is None or str(dns.rcode).upper() != "NOERROR":
            return []
        out: list[AtlasEdge] = []
        try:
            domain = node_key(NodeType.DOMAIN, dns.qname)
        except ValueError:
            return []
        for answer in dns.answers:
            try:
                ip = node_key(NodeType.IP, answer)
            except ValueError:
                continue  # CNAME / non-address answers are not resolution edges
            out.append(self.upsert_edge(
                event.tenant_id, domain, ip, EdgeType.OBSERVED_RESOLVES_TO, event.observed_at,
                f"{event.event_id}:{ip}", EvidenceGrade.B, f"sensor:{event.source_id}",
                recorded_at=recorded_at))
        return out

    def ingest_ioc_bundle(self, tenant_id: str, bundle: dict[str, Any], keyring: Any, *,
                          now: datetime | None = None,
                          recorded_at: datetime | None = None) -> int:
        """Load attributions from a signed IOC bundle (``aegis.ioc_bundle/1``).

        The bundle signature is verified with ``keyring`` first (unsigned or
        tampered bundles raise ``ValueError``). For each fresh malicious indicator
        with a malware family an ``attributed_to`` edge is recorded (grade C, the
        indicator's own ``source_group``, so syndicated copies count once). Benign
        verdicts are recorded as node observations (``benign_claim``) so analysts
        see the contradiction. Expired indicators are ignored. Returns the number
        of observations written or confirmed.
        """
        if not _verify_signed_dict(bundle, keyring):
            raise ValueError("IOC bundle signature verification failed")
        ref = _utc(now) if now is not None else self._clock()
        bundle_id = str(bundle.get("bundle_id", "bundle"))
        count = 0
        for ind in bundle.get("indicators", []):
            try:
                expires = _parse_ts(ind["expires_at"])
                last_seen = _parse_ts(ind["last_seen"])
                node = indicator_node_id(str(ind["value"]))
                ind_id = str(ind["indicator_id"])
                group = str(ind.get("source_group") or ind.get("source") or "unknown")
            except (KeyError, TypeError, ValueError):
                continue
            if expires <= ref:
                continue
            observed = min(last_seen, ref)
            prov = f"{bundle_id}:{ind_id}"[:160]
            if ind.get("verdict") == "benign":
                nt, value = parse_node_id(node)
                self.upsert_node(tenant_id, nt, value, observed, prov,
                                 attrs={"benign_claim": group,
                                        "benign_source": str(ind.get("source", ""))},
                                 recorded_at=recorded_at)
                count += 1
                continue
            family = ind.get("malware_family")
            if not family:
                continue
            conf = ind.get("confidence")
            grade = EvidenceGrade.C if isinstance(conf, (int, float)) and conf >= 0.6 \
                else EvidenceGrade.D
            self.upsert_edge(tenant_id, node, node_key(NodeType.MALWARE_FAMILY, str(family)),
                             EdgeType.ATTRIBUTED_TO, observed, prov, grade, group,
                             attrs={"threat_label": ind.get("threat_label"),
                                    "source": ind.get("source")},
                             recorded_at=recorded_at)
            count += 1
        return count

    # ------------------------------------------------------------------ reads

    def get_node(self, tenant_id: str, node_id: str, as_of: datetime | None = None) -> AtlasNode | None:
        nid = canonical_node_id(node_id)
        t = _utc(as_of) if as_of is not None else None
        with self._sf() as s:
            row = s.get(AtlasNodeRow, (tenant_id, nid))
            if row is None:
                return None
            obs = list(s.scalars(select(AtlasNodeObservationRow).where(
                AtlasNodeObservationRow.tenant_id == tenant_id,
                AtlasNodeObservationRow.node_id == nid).order_by(AtlasNodeObservationRow.id)))
            edge_obs = list(s.execute(
                select(AtlasEdgeObservationRow.observed_at, AtlasEdgeObservationRow.recorded_at)
                .join(AtlasEdgeRow, (AtlasEdgeRow.tenant_id == AtlasEdgeObservationRow.tenant_id)
                      & (AtlasEdgeRow.edge_id == AtlasEdgeObservationRow.edge_id))
                .where(AtlasEdgeRow.tenant_id == tenant_id, AtlasEdgeRow.candidate.is_(False),
                       or_(AtlasEdgeRow.src == nid, AtlasEdgeRow.dst == nid))))
            created = _from_db(row.created_at)
        if t is not None and created > t:
            return None
        seen: list[datetime] = []
        attrs: dict[str, Any] = {}
        provs: list[str] = []
        for o in sorted(obs, key=lambda o: (_from_db(o.observed_at), o.provenance_id)):
            o_obs, o_rec = _from_db(o.observed_at), _from_db(o.recorded_at)
            if t is not None and (o_rec > t or o_obs > t):
                continue
            seen.append(o_obs)
            attrs.update(o.attrs or {})
            provs.append(o.provenance_id)
        for o_obs, o_rec in edge_obs:
            o_obs, o_rec = _from_db(o_obs), _from_db(o_rec)
            if t is not None and (o_rec > t or o_obs > t):
                continue
            seen.append(o_obs)
        if t is not None and not seen:
            return None
        return AtlasNode(tenant_id=tenant_id, node_id=nid, node_type=NodeType(row.node_type),
                         value=row.value, first_seen=min(seen) if seen else None,
                         last_seen=max(seen) if seen else None, attrs=attrs,
                         provenance_ids=sorted(provs))

    def get_edge(self, tenant_id: str, edge_id: str, as_of: datetime | None = None) -> AtlasEdge | None:
        with self._sf() as s:
            row = s.get(AtlasEdgeRow, (tenant_id, edge_id))
            if row is None:
                return None
            obs = self._obs_for(s, tenant_id, [edge_id])
        edges = self._fold(tenant_id, [row], obs, as_of)
        return edges[0] if edges else None

    def neighbors(self, tenant_id: str, node_id: str, as_of: datetime | None = None, *,
                  edge_types: Iterable[EdgeType | str] | None = None,
                  include_expired: bool = False,
                  include_candidates: bool = False) -> list[Neighbor]:
        """Edges touching ``node_id`` as known at ``as_of`` (default: now)."""
        nid = canonical_node_id(node_id)
        types = {EdgeType(e).value for e in edge_types} if edge_types is not None else None
        edges = self._edges_touching(tenant_id, [nid], as_of)
        out: list[Neighbor] = []
        for e in edges:
            if types is not None and e.edge_type.value not in types:
                continue
            if e.candidate and not include_candidates:
                continue
            if not e.active and not include_expired:
                continue
            direction: Literal["out", "in"] = "out" if e.src == nid else "in"
            other = e.dst if direction == "out" else e.src
            out.append(Neighbor(node_id=other, node_type=parse_node_id(other)[0],
                                direction=direction, edge=e))
        out.sort(key=lambda n: (n.edge.edge_type.value, n.node_id))
        return out

    def edges(self, tenant_id: str, as_of: datetime | None = None, *,
              include_candidates: bool = True) -> list[AtlasEdge]:
        """All edges visible at ``as_of`` (expired ones included, flagged inactive)."""
        with self._sf() as s:
            rows = list(s.scalars(select(AtlasEdgeRow).where(AtlasEdgeRow.tenant_id == tenant_id)
                                  .order_by(AtlasEdgeRow.edge_id)))
            obs = self._obs_for(s, tenant_id, [r.edge_id for r in rows])
        out = self._fold(tenant_id, rows, obs, as_of)
        return [e for e in out if include_candidates or not e.candidate]

    def nodes(self, tenant_id: str, as_of: datetime | None = None) -> list[AtlasNode]:
        with self._sf() as s:
            ids = list(s.scalars(select(AtlasNodeRow.node_id).where(
                AtlasNodeRow.tenant_id == tenant_id).order_by(AtlasNodeRow.node_id)))
        out = []
        for nid in ids:
            n = self.get_node(tenant_id, nid, as_of)
            if n is not None:
                out.append(n)
        return out

    def degree(self, tenant_id: str, node_id: str, as_of: datetime | None = None) -> int:
        """Active, non-candidate edges touching the node."""
        return len(self.neighbors(tenant_id, node_id, as_of))

    def is_shared_hosting(self, tenant_id: str, ip_node_id: str, as_of: datetime | None = None) -> bool:
        """True if >= ``shared_hosting_threshold`` distinct domains actively resolve to the IP."""
        nid = canonical_node_id(ip_node_id)
        if parse_node_id(nid)[0] is not NodeType.IP:
            return False
        return self._resolving_domains(tenant_id, nid, as_of) >= self._shared_threshold

    def related(self, tenant_id: str, node_id: str, as_of: datetime | None = None, *,
                max_depth: int = 2, max_nodes: int = 200) -> list[RelatedNode]:
        """Bounded investigation context around ``node_id`` with the overlinking guard.

        Hubs (degree > ``hub_degree_limit``) are reported but never expanded;
        nodes reached through co-hosting or candidate edges are reported with
        ``via_weak_edge=True`` and never expanded either.
        """
        if max_depth < 1 or max_nodes < 1:
            raise ValueError("max_depth and max_nodes must be >= 1")
        root = canonical_node_id(node_id)
        visited: dict[str, RelatedNode] = {}
        queue: deque[tuple[str, int, list[str], bool]] = deque([(root, 0, [], True)])
        seen = {root}
        while queue:
            current, depth, path, eligible_path = queue.popleft()
            if depth >= max_depth:
                continue
            nbrs = self.neighbors(tenant_id, current, as_of, include_candidates=True)
            for nb in nbrs:
                if nb.node_id in seen:
                    continue
                if len(visited) >= max_nodes:
                    return list(visited.values())
                seen.add(nb.node_id)
                weak = nb.edge.candidate or nb.edge.edge_type is EdgeType.CO_OBSERVED
                nb_degree = self.degree(tenant_id, nb.node_id, as_of)
                hub = nb_degree > self._hub_limit
                new_path = path + [nb.edge.edge_id]
                elig = eligible_path and nb.edge.enforcement_eligible
                visited[nb.node_id] = RelatedNode(
                    node_id=nb.node_id, node_type=nb.node_type, depth=depth + 1,
                    path_edge_ids=new_path, hub=hub, via_weak_edge=weak,
                    enforcement_eligible_path=elig)
                if not hub and not weak:
                    queue.append((nb.node_id, depth + 1, new_path, elig))
        return list(visited.values())

    def candidate_links(self, tenant_id: str, node_id: str, as_of: datetime | None = None, *,
                        limit: int = 10, min_score: float = 0.0) -> list[CandidateLink]:
        """Link prediction (Adamic-Adar over shared non-hub neighbours).

        Results are hypotheses for analysts: always ``investigative_only=True`` and
        ``enforcement_eligible=False``. Hub neighbours (shared CDN edges) are
        excluded from scoring so co-tenancy alone never produces a candidate.
        """
        root = canonical_node_id(node_id)
        direct = {n.node_id for n in self.neighbors(tenant_id, root, as_of)}
        mids = [n for n in direct if self.degree(tenant_id, n, as_of) <= self._hub_limit]
        scores: dict[str, float] = defaultdict(float)
        shared: dict[str, list[str]] = defaultdict(list)
        for mid in mids:
            mid_nbrs = self.neighbors(tenant_id, mid, as_of)
            deg = len(mid_nbrs)
            if deg < 2:
                continue
            for nb in mid_nbrs:
                if nb.node_id == root or nb.node_id in direct:
                    continue
                if nb.edge.edge_type is EdgeType.MENTIONED_IN_CASE:
                    continue
                scores[nb.node_id] += 1.0 / math.log(deg + 1)
                shared[nb.node_id].append(mid)
        out = [CandidateLink(tenant_id=tenant_id, src=root, dst=dst, score=round(sc, 6),
                             shared_neighbors=sorted(shared[dst]),
                             rationale=(f"{len(shared[dst])} shared non-hub neighbour(s); "
                                        "investigative hypothesis only"))
               for dst, sc in scores.items() if sc > min_score]
        out.sort(key=lambda c: (-c.score, c.dst))
        return out[:max(0, limit)]

    # ------------------------------------------------------------------ snapshots

    def snapshot(self, tenant_id: str, as_of: datetime) -> dict[str, Any]:
        """Content-hashed graph state as known at ``as_of``.

        The hash covers every visible node and the derived attributes of every
        visible edge, so identical knowledge at ``as_of`` always yields the same
        hash, and knowledge recorded after ``as_of`` never changes it.
        """
        t = _utc(as_of)
        nodes = self.nodes(tenant_id, t)
        edges = self.edges(tenant_id, t)
        body = {
            "v": ATLAS_SNAPSHOT_VERSION,
            "tenant_id": tenant_id,
            "as_of": t.isoformat(),
            "nodes": [{"id": n.node_id, "first_seen": n.first_seen, "last_seen": n.last_seen,
                       "attrs": n.attrs} for n in nodes],
            "edges": [{"id": e.edge_id, "src": e.src, "dst": e.dst, "type": e.edge_type.value,
                       "first_seen": e.first_seen, "last_seen": e.last_seen,
                       "grade": e.evidence_grade.value, "sources": e.independent_source_count,
                       "provenance_ids": e.provenance_ids, "expires_at": e.expires_at,
                       "active": e.active, "candidate": e.candidate,
                       "eligible": e.enforcement_eligible} for e in edges],
        }
        digest = sha256_hex(body)
        return {"snapshot_id": f"atlas_{digest[:32]}", "snapshot_hash": digest,
                "tenant_id": tenant_id, "as_of": t, "node_count": len(nodes),
                "edge_count": len(edges)}

    def snapshot_hash(self, tenant_id: str, as_of: datetime) -> str:
        return self.snapshot(tenant_id, as_of)["snapshot_hash"]

    def record_snapshot(self, tenant_id: str, as_of: datetime | None = None, *,
                        reason: str = "scheduled", subject_id: str | None = None) -> dict[str, Any]:
        """Compute, persist and (if a ledger is attached) anchor a snapshot.

        Use daily (:meth:`daily_snapshot`) and on major case transitions
        (``reason="case_transition:VERIFIED"``, ``subject_id=case_id``).
        Recording the same snapshot twice is idempotent.
        """
        _check(reason, "reason", 128)
        snap = self.snapshot(tenant_id, as_of if as_of is not None else self._clock())
        created = False
        with self._lock, self._sf.begin() as s:
            if s.get(AtlasSnapshotRow, (tenant_id, snap["snapshot_id"])) is None:
                created = True
                s.add(AtlasSnapshotRow(
                    tenant_id=tenant_id, snapshot_id=snap["snapshot_id"], as_of=snap["as_of"],
                    snapshot_hash=snap["snapshot_hash"], node_count=snap["node_count"],
                    edge_count=snap["edge_count"], reason=reason, subject_id=subject_id,
                    created_at=self._clock()))
        # anchor new snapshots, and every snapshot taken for a specific subject (case)
        if self._ledger is not None and (created or subject_id is not None):
            self._ledger.append(tenant_id, ATLAS_SNAPSHOT_ENTRY_TYPE,
                                subject_id or snap["snapshot_id"], {
                                    "snapshot_id": snap["snapshot_id"],
                                    "snapshot_hash": snap["snapshot_hash"],
                                    "as_of": snap["as_of"],
                                    "node_count": snap["node_count"],
                                    "edge_count": snap["edge_count"],
                                    "reason": reason,
                                })
        return snap

    def daily_snapshot(self, tenant_id: str, day: date) -> dict[str, Any]:
        """Snapshot as known at the end of ``day`` (UTC)."""
        end = datetime.combine(day, time(23, 59, 59, 999999), tzinfo=timezone.utc)
        return self.record_snapshot(tenant_id, end, reason=f"daily:{day.isoformat()}")

    def snapshots(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._sf() as s:
            rows = list(s.scalars(select(AtlasSnapshotRow).where(
                AtlasSnapshotRow.tenant_id == tenant_id).order_by(AtlasSnapshotRow.as_of)))
        return [{"snapshot_id": r.snapshot_id, "snapshot_hash": r.snapshot_hash,
                 "as_of": _from_db(r.as_of), "node_count": r.node_count,
                 "edge_count": r.edge_count, "reason": r.reason, "subject_id": r.subject_id}
                for r in rows]

    def verify_snapshot(self, tenant_id: str, snap: dict[str, Any]) -> bool:
        """True if recomputing the snapshot at its ``as_of`` reproduces its hash."""
        try:
            as_of = snap["as_of"]
            if isinstance(as_of, str):
                as_of = datetime.fromisoformat(as_of)
            return self.snapshot_hash(tenant_id, as_of) == snap.get("snapshot_hash")
        except (KeyError, TypeError, ValueError):
            return False

    # ------------------------------------------------------------------ internals

    @staticmethod
    def _obs_for(s: Session, tenant_id: str, edge_ids: list[str]) -> dict[str, list[_Obs]]:
        out: dict[str, list[_Obs]] = defaultdict(list)
        for i in range(0, len(edge_ids), 500):
            chunk = edge_ids[i:i + 500]
            for row in s.scalars(select(AtlasEdgeObservationRow).where(
                    AtlasEdgeObservationRow.tenant_id == tenant_id,
                    AtlasEdgeObservationRow.edge_id.in_(chunk))
                    .order_by(AtlasEdgeObservationRow.id)):
                out[row.edge_id].append(_Obs(row))
        return out

    def _edges_touching(self, tenant_id: str, node_ids: list[str],
                        as_of: datetime | None) -> list[AtlasEdge]:
        with self._sf() as s:
            rows = list(s.scalars(select(AtlasEdgeRow).where(
                AtlasEdgeRow.tenant_id == tenant_id,
                or_(AtlasEdgeRow.src.in_(node_ids), AtlasEdgeRow.dst.in_(node_ids)))
                .order_by(AtlasEdgeRow.edge_id)))
            obs = self._obs_for(s, tenant_id, [r.edge_id for r in rows])
        return self._fold(tenant_id, rows, obs, as_of)

    def _resolving_domains(self, tenant_id: str, ip_id: str, as_of: datetime | None) -> int:
        with self._sf() as s:
            rows = list(s.scalars(select(AtlasEdgeRow).where(
                AtlasEdgeRow.tenant_id == tenant_id, AtlasEdgeRow.dst == ip_id,
                AtlasEdgeRow.edge_type == EdgeType.OBSERVED_RESOLVES_TO.value,
                AtlasEdgeRow.candidate.is_(False))))
            obs = self._obs_for(s, tenant_id, [r.edge_id for r in rows])
        ref = _utc(as_of) if as_of is not None else self._clock()
        n = 0
        for r in rows:
            agg = _aggregate(obs.get(r.edge_id, []), _utc(as_of) if as_of is not None else None)
            if agg is not None and agg["expires_at"] > ref:
                n += 1
        return n

    def _shared_nodes(self, tenant_id: str, node_ids: set[str],
                      as_of: datetime | None) -> set[str]:
        """Nodes among ``node_ids`` explicitly flagged ``shared_hosting`` as known at ``as_of``."""
        if not node_ids:
            return set()
        t = _utc(as_of) if as_of is not None else None
        out: set[str] = set()
        ids = sorted(node_ids)
        with self._sf() as s:
            for i in range(0, len(ids), 500):
                for row in s.scalars(select(AtlasNodeObservationRow).where(
                        AtlasNodeObservationRow.tenant_id == tenant_id,
                        AtlasNodeObservationRow.node_id.in_(ids[i:i + 500]))):
                    if (row.attrs or {}).get("shared_hosting") is not True:
                        continue
                    if t is None or (_from_db(row.recorded_at) <= t
                                     and _from_db(row.observed_at) <= t):
                        out.add(row.node_id)
        return out

    def _fold(self, tenant_id: str, rows: list[AtlasEdgeRow], obs: dict[str, list[_Obs]],
              as_of: datetime | None) -> list[AtlasEdge]:
        t = _utc(as_of) if as_of is not None else None
        ref = t if t is not None else self._clock()
        shared_attr = self._shared_nodes(
            tenant_id, {r.dst for r in rows if r.edge_type == EdgeType.OBSERVED_RESOLVES_TO.value},
            as_of)
        fan_in_cache: dict[str, bool] = {}
        out: list[AtlasEdge] = []
        for r in rows:
            agg = _aggregate(obs.get(r.edge_id, []), t)
            if agg is None:
                continue
            et = EdgeType(r.edge_type)
            active = agg["expires_at"] > ref
            reasons: list[str] = []
            if r.candidate:
                reasons.append("candidate_link_investigative_only")
            if et is EdgeType.CO_OBSERVED:
                reasons.append("co_hosting_edge_never_enforcement_eligible")
            elif et is EdgeType.MENTIONED_IN_CASE:
                reasons.append("case_reference_not_infrastructure")
            if not active:
                reasons.append("expired")
            grade: EvidenceGrade = agg["grade"]
            sources: int = agg["sources"]
            if not (grade.rank <= 1 or (grade is EvidenceGrade.C and sources >= 2)):
                reasons.append("insufficient_evidence_grade")
            if et is EdgeType.OBSERVED_RESOLVES_TO and not r.candidate:
                if r.dst not in fan_in_cache:
                    fan_in_cache[r.dst] = (r.dst in shared_attr
                                           or self._resolving_domains(tenant_id, r.dst, as_of)
                                           >= self._shared_threshold)
                if fan_in_cache[r.dst]:
                    reasons.append("shared_hosting_destination")
            eligible = et in ENFORCEMENT_CAPABLE_EDGE_TYPES and not reasons
            out.append(AtlasEdge(
                tenant_id=tenant_id, edge_id=r.edge_id, src=r.src, dst=r.dst, edge_type=et,
                first_seen=agg["first_seen"], last_seen=agg["last_seen"],
                provenance_ids=agg["provenance_ids"], evidence_grade=grade,
                independent_source_count=sources, source_groups=agg["groups"],
                observation_count=agg["count"], ttl_hours=agg["ttl"],
                expires_at=agg["expires_at"], active=active, candidate=bool(r.candidate),
                investigative_only=bool(r.candidate), enforcement_eligible=eligible,
                eligibility_reasons=reasons, attrs=agg["attrs"]))
        return out


# ----------------------------------------------------------------------------- helpers


def _aggregate(obs: list[_Obs], t: datetime | None) -> dict[str, Any] | None:
    vis = [o for o in obs if t is None or (o.recorded_at <= t and o.observed_at <= t)]
    if not vis:
        return None
    best = min(vis, key=lambda o: o.grade.rank).grade
    latest_expiry = max(vis, key=lambda o: o.observed_at + timedelta(hours=o.ttl))
    groups = sorted({o.group for o in vis})
    attrs: dict[str, Any] = {}
    for o in sorted(vis, key=lambda o: (o.observed_at, o.provenance_id)):
        attrs.update(o.attrs)
    return {
        "first_seen": min(o.observed_at for o in vis),
        "last_seen": max(o.observed_at for o in vis),
        "provenance_ids": sorted({o.provenance_id for o in vis}),
        "grade": best,
        "groups": groups,
        "sources": len(groups),
        "count": len(vis),
        "ttl": latest_expiry.ttl,
        "expires_at": latest_expiry.observed_at + timedelta(hours=latest_expiry.ttl),
        "attrs": attrs,
    }


def _check(value: str, name: str, max_len: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(f"{name} must be at most {max_len} characters")


def _json_attrs(attrs: dict[str, Any] | None) -> dict[str, Any]:
    if attrs is None:
        return {}
    if not isinstance(attrs, dict):
        raise TypeError("attrs must be a dict")
    try:
        return json.loads(canonical_bytes(attrs))
    except Exception as exc:
        raise ValueError(f"attrs are not JSON serializable: {exc}") from exc


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _utc(value)
    if not isinstance(value, str):
        raise TypeError("timestamp must be a string")
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _verify_signed_dict(data: dict[str, Any], keyring: Any) -> bool:
    """Verify an Ed25519 signature over canonical JSON of ``data`` minus ``signature``."""
    if not isinstance(data, dict) or keyring is None:
        return False
    key_id, sig = data.get("signer_key_id"), data.get("signature")
    if not isinstance(key_id, str) or not isinstance(sig, str) or not sig:
        return False
    body = {k: v for k, v in data.items() if k != "signature"}
    try:
        return bool(keyring.verify(key_id, canonical_bytes(body), sig))
    except Exception:
        return False
