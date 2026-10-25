"""AEGIS composition root: one object wiring every module of the shadow pipeline.

:class:`AegisService` owns the storage engine and builds, in dependency order::

    storage (DocStore, coverage tables)
      -> provenance (signed Ledger, KeyRings, EvidenceStore)
      -> atlas (temporal graph)          -> oracle (CaseService, Investigator, toolset)
      -> ingest (per-tenant IngestPipeline over one EventBus, quarantine, tenant keys)
      -> sentinel (per-tenant Sentinel: shared calibrated model + tenant IOC bundle)
      -> mirror (operator topology, traffic history, simulate/authorize, Executor)
      -> reports (proof-of-value report over the same stores)

Every public method takes the caller's ``tenant_id`` (from the verified token)
first and only touches that tenant's records. Domain refusals surface as
:class:`ServiceError` subclasses that the API maps to HTTP statuses; guard
failures carry the machine-readable ``failed`` checks of the state machine,
the authorizer or the executor.

Trust anchors (policy-signing, IOC-signing and ledger public keys) are read from
``<data_dir>/trusted/{policy,ioc,ledger}/<key_id>.pem``: they are installed by the
operator on disk, never uploaded through the API.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Sequence

from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, Integer, String, event, func, select, text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.api.settings import Settings
from aegis.api.topology import OperatorTopology, TopologyError, parse_topology
from aegis.atlas.graph import (
    Atlas,
    AtlasError,
    EdgeType,
    EvidenceGrade,
    NodeType,
    canonical_node_id,
    indicator_node_id,
    node_key,
)
from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import (
    ActionType,
    AuthorizationDecision,
    Case,
    CaseState,
    Evidence,
    EvidenceKind,
    Finding,
    MirrorResult,
    ObservationEvent,
    OperatorPolicy,
    ProposedAction,
    SourceKind,
    Vantage,
    Verdict,
)
from aegis.ingest.bus import OBSERVATIONS_TOPIC, InMemoryBus
from aegis.ingest.normalize import SourceConfig
from aegis.ingest.pipeline import IngestBackpressureError, IngestPipeline, IngestStats
from aegis.ingest.pseudonym import TenantKeyProvider
from aegis.ingest.validator import Quarantined, QuarantineStore, Validator
from aegis.mirror.adapters import DryRunAdapter
from aegis.mirror.authorize import authorize as mirror_authorize
from aegis.mirror.base import EnforcementAdapter, ExecutionRecord, ExecutionStatus, InvalidTargetError, normalize_target
from aegis.mirror.breaker import CircuitBreaker
from aegis.mirror.executor import ExecutionError, Executor
from aegis.mirror.history import AggregateTrafficHistory
from aegis.mirror.simulate import simulate as mirror_simulate
from aegis.oracle.investigation import InvestigationReport, Investigator
from aegis.oracle.llm import llm_from_env
from aegis.oracle.state_machine import ALLOWED_TRANSITIONS, TERMINAL_STATES, CaseService, GuardError
from aegis.oracle.tools import build_default_toolset, indicators_from_evidence
from aegis.provenance.evidence import EvidenceIntegrityError, EvidenceStore
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing, Signer, SigningKeyError, verify_model
from aegis.provenance.snapshot import replay as ledger_replay
from aegis.reports.inputs import CoverageStats, ReportPeriod
from aegis.reports.pov import collect_pov_report, render_pov_html
from aegis.sentinel.detector import Sentinel
from aegis.sentinel.model import TrainedModel, default_model_dir
from aegis.sentinel.model import load as load_model
from aegis.sentinel.rules import BundleError, IOCBundle, load_bundle
from aegis.storage.db import Base, DocRow, DocStore, init_db, make_engine, make_session_factory

log = logging.getLogger(__name__)

AEGIS_VERSION = "1.0.0"
ALERT_VERDICTS = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
API_AUDIT_ENTRY = "api_audit"
INGEST_ENTRY = "ingest_batch"
CONFIG_ENTRY = "configuration"
KEY_KINDS = ("policy", "ioc", "ledger")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


# ============================================================================ errors


class ServiceError(Exception):
    """Base class. ``code`` is a stable identifier, ``failed`` lists failed checks."""
    status = 400
    code = "bad_request"

    def __init__(self, detail: str, *, failed: Iterable[str] = (), code: str | None = None):
        super().__init__(detail)
        self.detail = detail
        self.failed = list(failed)
        if code:
            self.code = code


class NotFoundError(ServiceError):
    status = 404
    code = "not_found"


class ConflictError(ServiceError):
    """A guard, the authorizer or the executor refused (state unchanged)."""
    status = 409
    code = "refused"


class InvalidInputError(ServiceError):
    status = 422
    code = "invalid"


class ForbiddenActionError(ServiceError):
    """Separation-of-duties violation (e.g. approving one's own proposal)."""
    status = 403
    code = "forbidden"


class OverloadedError(ServiceError):
    status = 503
    code = "overloaded"


# ============================================================================ records


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceRecord(_Record):
    """A registered, authorized telemetry source (``doc_id = <tenant>:<source_id>``)."""
    doc_id: str
    tenant_id: str
    config: dict[str, Any]
    created_by: str
    created_at: datetime


class IocBundleRecord(_Record):
    """The tenant's active signed IOC bundle (``doc_id = <tenant>:ioc``)."""
    doc_id: str
    tenant_id: str
    bundle: dict[str, Any]
    version: str
    sha256: str
    signer_key_id: str
    loaded_by: str
    loaded_at: datetime


class TopologyRecord(_Record):
    """The tenant's operator hosting inventory (``doc_id = <tenant>:topology``)."""
    doc_id: str
    tenant_id: str
    topology: dict[str, Any]
    sha256: str
    loaded_by: str
    loaded_at: datetime


class MirrorRecord(_Record):
    """Latest MIRROR simulation for an action (keyed by ``action_id``, a server-generated UUID)."""
    tenant_id: str
    action_id: str
    result: MirrorResult
    simulated_by: str


class AuthorizationRecord(_Record):
    """Latest authorization assessment for an action (keyed by ``action_id``)."""
    tenant_id: str
    action_id: str
    decision: AuthorizationDecision
    evaluated_by: str
    evidence_quality_ok: bool


class CoverageDayRow(Base):
    """One observed device-day (denominator of every per-device-day rate)."""
    __tablename__ = "coverage_device_days"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entity_pseudonym: Mapped[str] = mapped_column(String(128), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    device_class: Mapped[str] = mapped_column(String(64))
    events: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CoverageSourceDayRow(Base):
    __tablename__ = "coverage_source_days"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    events: Mapped[int] = mapped_column(Integer)


# ============================================================================ results


@dataclass
class Page:
    items: list[Any]
    total: int
    limit: int
    offset: int


@dataclass
class IngestOutcome:
    stats: list[dict[str, Any]]
    events: int
    findings: list[Finding] = field(default_factory=list)
    cases_opened: list[str] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        verdicts = Counter(f.verdict.value for f in self.findings)
        return {"events": self.events, "stats": self.stats, "findings": len(self.findings),
                "findings_by_verdict": dict(sorted(verdicts.items())),
                "finding_ids": [f.finding_id for f in self.findings],
                "cases_opened": self.cases_opened, "rejected": self.rejected}


@dataclass
class LabContext:
    """Independent ground truth for a lab/demo tenant (shown in the PoV validation section)."""
    onsets: dict[str, datetime]
    ground_truth: dict[tuple[str, date], str]
    source: str
    period: ReportPeriod


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _page(items: Sequence[Any], limit: int, offset: int) -> Page:
    return Page(items=list(items[offset:offset + limit]), total=len(items), limit=limit, offset=offset)


# ============================================================================ service


class AegisService:
    """The running AEGIS SHIELD deployment. Thread-safe; one instance per process."""

    def __init__(self, settings: Settings, *, model: TrainedModel | None = None, load_default_model: bool = True,
                 adapter: EnforcementAdapter | None = None, llm: Any | None = None, use_env_llm: bool = True,
                 clock: Callable[[], datetime] | None = None):
        self.settings = settings
        self.clock = clock or _utcnow
        self._prepare_dirs()

        # -- storage
        self.engine = make_engine(settings.resolved_database_url)
        if self.engine.dialect.name == "sqlite":
            event.listen(self.engine, "connect", _sqlite_pragmas)
        init_db(self.engine)  # also creates the coverage tables declared above
        self.sf = make_session_factory(self.engine)
        self.docs = DocStore(self.sf)

        # -- provenance
        self.ledger_signer = self._load_or_create_ledger_signer()
        self.ledger_keyring = KeyRing()
        self.policy_keyring = KeyRing()
        self.ioc_keyring = KeyRing()
        self.reload_trusted_keys()
        self.ledger = Ledger(self.sf, signer=self.ledger_signer)
        self.evidence = EvidenceStore(self.docs, self.ledger)

        # -- graph and cases
        self.atlas = Atlas(self.sf, ledger=self.ledger, clock=self.clock)
        self.cases = CaseService(self.docs, self.evidence, self.ledger, keyring=self.policy_keyring,
                                 atlas=self.atlas, clock=self.clock)
        self.history = AggregateTrafficHistory()
        self._history_span: dict[str, tuple[datetime, datetime]] = {}
        self._topologies: dict[str, OperatorTopology] = {}
        self.toolset = build_default_toolset(docstore=self.docs, evidence_store=self.evidence, ledger=self.ledger,
                                             atlas=self.atlas, keyring=self.policy_keyring,
                                             simulator=self._simulate_for_agent, clock=self.clock)
        self.llm = llm if llm is not None else (llm_from_env() if (use_env_llm and settings.llm_enabled) else None)
        self.investigator = Investigator(self.llm, self.toolset, case_service=self.cases, clock=self.clock)

        # -- detection model (shared, read-only)
        self.model = model if model is not None else (self._load_model() if load_default_model else None)

        # -- ingest
        self.key_provider = TenantKeyProvider.from_env()
        self._load_tenant_keys()
        self.quarantine = QuarantineStore(docstore=self.docs)
        self.bus = InMemoryBus(max_queue=settings.bus_max_queue, per_tenant_quota=settings.bus_per_tenant_quota)
        self._buffer: list[ObservationEvent] = []
        self.bus.subscribe(OBSERVATIONS_TOPIC, self._buffer.append)
        self._pipelines: dict[str, IngestPipeline] = {}
        self._sentinels: dict[str, Sentinel] = {}
        self._bundles: dict[str, IOCBundle] = {}
        self._atlas_seen: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
        self._ingest_lock = threading.RLock()
        self._state_lock = threading.RLock()
        self._lab: dict[str, LabContext] = {}

        # -- enforcement
        self.breaker = CircuitBreaker()
        self.adapter = adapter or self._build_adapter()
        self.executor = Executor(self.adapter, self.ledger, self.breaker, clock=self.clock)

        self._restore_state()

    # ------------------------------------------------------------------ setup helpers

    def _prepare_dirs(self) -> None:
        s = self.settings
        s.data_dir.mkdir(parents=True, exist_ok=True)
        s.keys_dir.mkdir(parents=True, exist_ok=True)
        try:
            s.keys_dir.chmod(0o700)
        except OSError:  # pragma: no cover - platform dependent
            pass
        for kind in KEY_KINDS:
            (s.trusted_dir / kind).mkdir(parents=True, exist_ok=True)

    def _load_or_create_ledger_signer(self) -> Signer:
        key_id = self.settings.ledger_key_id
        path = self.settings.keys_dir / f"ledger-{key_id}.pem"
        if path.is_file():
            signer = Signer.from_private_pem(key_id, path.read_bytes())
        else:
            signer = Signer.generate(key_id)
            _write_secret(path, signer.private_pem())
            log.warning("generated a new ledger signing key %s at %s", key_id, path)
        pub = self.settings.trusted_dir / "ledger" / f"{key_id}.pem"
        if not pub.is_file():
            pub.write_bytes(signer.public_pem())
        return signer

    def reload_trusted_keys(self) -> dict[str, list[str]]:
        """(Re)load trusted public keys from disk into the live key rings."""
        rings = {"policy": self.policy_keyring, "ioc": self.ioc_keyring, "ledger": self.ledger_keyring}
        out: dict[str, list[str]] = {}
        for kind, ring in rings.items():
            for pem in sorted((self.settings.trusted_dir / kind).glob("*.pem")):
                try:
                    ring.add(pem.stem, pem.read_bytes())
                except (SigningKeyError, ValueError) as exc:
                    log.error("cannot trust %s key %s: %s", kind, pem.name, exc)
            out[kind] = ring.key_ids()
        self.ledger_keyring.add_signer(self.ledger_signer)
        out["ledger"] = self.ledger_keyring.key_ids()
        return out

    def trust_key(self, kind: Literal["policy", "ioc", "ledger"], key_id: str, public_pem: bytes) -> None:
        """Install a trusted public key on disk and in the live key ring (CLI / operator use)."""
        if kind not in KEY_KINDS:
            raise InvalidInputError(f"unknown key kind {kind!r}")
        if not _KEY_ID_RE.match(key_id):
            raise InvalidInputError("invalid key id")
        ring = {"policy": self.policy_keyring, "ioc": self.ioc_keyring, "ledger": self.ledger_keyring}[kind]
        try:
            ring.add(key_id, public_pem)
        except (SigningKeyError, ValueError) as exc:
            raise InvalidInputError(str(exc)) from exc
        (self.settings.trusted_dir / kind / f"{key_id}.pem").write_bytes(public_pem)

    def _load_model(self) -> TrainedModel | None:
        directory = self.settings.model_dir or default_model_dir()
        try:
            model = load_model(directory, keyring=self.ledger_keyring if self.settings.model_require_signature
                               else None, require_signature=self.settings.model_require_signature)
        except Exception as exc:  # missing or tampered model => rules + abstain only (safe)
            log.error("detection model not loaded from %s (%s): running rules-only with abstain",
                      directory, type(exc).__name__)
            return None
        log.info("loaded detection model %s from %s", model.model_id, directory)
        return model

    def _build_adapter(self) -> EnforcementAdapter:
        s = self.settings
        if s.enforcement_adapter == "rpz":
            from aegis.mirror.rpz import RPZAdapter
            assert s.rpz_zone_path is not None
            return RPZAdapter(s.rpz_zone_path, reload_command=list(s.rpz_reload_command) or None)
        if s.enforcement_adapter == "webhook":
            from aegis.mirror.webhook import WebhookAdapter
            assert s.webhook_url is not None and s.webhook_secret is not None
            return WebhookAdapter(s.webhook_url, s.webhook_secret.encode("utf-8"))
        return DryRunAdapter()

    def _load_tenant_keys(self) -> None:
        d = self.settings.keys_dir / "pseudonym"
        if not d.is_dir():
            return
        for f in sorted(d.glob("*.key")):
            try:
                self.key_provider.set_tenant_key(f.stem, bytes.fromhex(f.read_text().strip()))
            except ValueError as exc:
                log.error("ignoring pseudonym key %s: %s", f.name, exc)

    def set_tenant_pseudonym_key(self, tenant_id: str, key: bytes) -> None:
        """Register (and persist, mode 0600) an explicit per-tenant pseudonymization key."""
        _check_tenant(tenant_id)
        self.key_provider.set_tenant_key(tenant_id, key)
        _write_secret(self.settings.keys_dir / "pseudonym" / f"{tenant_id}.key", key.hex().encode())

    def _restore_state(self) -> None:
        """Rebuild in-memory views (sources, bundles, topology, live executions) from storage."""
        with self.sf() as s:
            rows = list(s.execute(select(DocRow.kind, DocRow.tenant_id, DocRow.body).where(
                DocRow.kind.in_(["SourceRecord", "IocBundleRecord", "TopologyRecord"]))))
        for kind, tenant_id, body in rows:
            try:
                if kind == "SourceRecord":
                    self._pipeline(tenant_id).register_source(SourceConfig.model_validate(body["config"]))
                elif kind == "IocBundleRecord":
                    self._bundles[tenant_id] = load_bundle(body["bundle"], self.ioc_keyring)
                elif kind == "TopologyRecord":
                    self._topologies[tenant_id] = parse_topology(body["topology"])
            except (BundleError, TopologyError, ValueError, KeyError) as exc:
                log.error("cannot restore %s for tenant %s: %s", kind, tenant_id, exc)
        for tenant_id in self.ledger.tenants():
            try:
                self.executor.recover(tenant_id)
            except Exception as exc:  # pragma: no cover - defensive: never block startup
                log.error("executor recovery failed for tenant %s: %s", tenant_id, exc)

    # ------------------------------------------------------------------ health

    def ready(self) -> dict[str, Any]:
        checks: dict[str, Any] = {}
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:
            checks["database"] = f"error: {type(exc).__name__}"
        checks["model"] = self.model.model_id if self.model is not None else "not_loaded (rules-only)"
        checks["llm"] = "configured" if self.llm is not None else "disabled (deterministic investigation)"
        checks["enforcement_adapter"] = self.adapter.name
        checks["circuit_breaker"] = self.breaker.state.value
        return {"ready": checks["database"] == "ok", "checks": checks, "version": AEGIS_VERSION}

    def detector_version(self, tenant_id: str) -> str:
        return self._sentinel(tenant_id).detector_version

    # ------------------------------------------------------------------ sources

    def _pipeline(self, tenant_id: str) -> IngestPipeline:
        with self._state_lock:
            p = self._pipelines.get(tenant_id)
            if p is None:
                p = IngestPipeline(self.bus, Validator(clock=self.clock), {}, key_provider=self.key_provider,
                                   quarantine=self.quarantine, clock=self.clock)
                self._pipelines[tenant_id] = p
            return p

    def register_source(self, tenant_id: str, actor: str, *, source_id: str, source_kind: SourceKind | str,
                        vantage: Vantage | str, collection_authorization_id: str, retention_days: int = 30,
                        format: str | None = None, entity_field: str = "auto",
                        assume_utc_for_naive: bool = False) -> SourceConfig:
        _check_tenant(tenant_id)
        if not _ID_RE.match(source_id or ""):
            raise InvalidInputError("source_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
        try:
            cfg = SourceConfig(tenant_id=tenant_id, source_id=source_id, source_kind=SourceKind(source_kind),
                               vantage=Vantage(vantage), collection_authorization_id=collection_authorization_id,
                               retention_days=retention_days, format=format, entity_field=entity_field,  # type: ignore[arg-type]
                               assume_utc_for_naive=assume_utc_for_naive)
        except ValueError as exc:
            raise InvalidInputError(f"invalid source: {exc}") from exc
        doc_id = f"{tenant_id}:{source_id}"
        with self._state_lock:
            if self.docs.get(SourceRecord, tenant_id, doc_id) is not None:
                raise ConflictError(f"source {source_id!r} already registered", code="exists")
            self.ledger.append(tenant_id, CONFIG_ENTRY, f"source:{source_id}"[:128], {
                "event": "source_registered", "source": cfg.model_dump(mode="json"), "actor": actor})
            self.docs.put(SourceRecord(doc_id=doc_id, tenant_id=tenant_id, config=cfg.model_dump(mode="json"),
                                       created_by=actor, created_at=self.clock()))
            self._pipeline(tenant_id).register_source(cfg)
            sentinel = self._sentinels.get(tenant_id)
            if sentinel is not None:
                sentinel.authorized = self._authorized_collections(tenant_id)
        return cfg

    def list_sources(self, tenant_id: str) -> list[SourceConfig]:
        return sorted(self._pipeline(tenant_id).sources.values(), key=lambda c: c.source_id)

    def _authorized_collections(self, tenant_id: str) -> frozenset[str]:
        return frozenset(c.collection_authorization_id for c in self._pipeline(tenant_id).sources.values())

    # ------------------------------------------------------------------ IOC bundles

    def load_ioc_bundle(self, tenant_id: str, actor: str, data: dict[str, Any]) -> IOCBundle:
        """Verify a signed IOC bundle against the trusted IOC keys and activate it."""
        try:
            bundle = load_bundle(data, self.ioc_keyring)
        except BundleError as exc:
            raise InvalidInputError(f"IOC bundle rejected: {exc}", code="bundle_rejected") from exc
        with self._state_lock:
            self.ledger.append(tenant_id, EntryType.RULE_BUNDLE, f"ioc:{bundle.bundle_id}"[:128], {
                "event": "ioc_bundle_loaded", "bundle_id": bundle.bundle_id, "version": bundle.version,
                "rule_bundle_version": bundle.version, "sha256": bundle.sha256,
                "signer_key_id": bundle.signer_key_id, "issuer": bundle.issuer,
                "indicators": len(bundle.indicators), "actor": actor})
            self.docs.put(IocBundleRecord(doc_id=f"{tenant_id}:ioc", tenant_id=tenant_id, bundle=data,
                                          version=bundle.version, sha256=bundle.sha256,
                                          signer_key_id=bundle.signer_key_id, loaded_by=actor,
                                          loaded_at=self.clock()))
            self._bundles[tenant_id] = bundle
            sentinel = self._sentinels.get(tenant_id)
            if sentinel is not None:
                sentinel.bundle = bundle
        try:
            self.atlas.ingest_ioc_bundle(tenant_id, data, self.ioc_keyring, now=self.clock())
        except (AtlasError, ValueError) as exc:
            log.error("ATLAS could not ingest IOC bundle attributions: %s", exc)
        return bundle

    def ioc_status(self, tenant_id: str) -> dict[str, Any] | None:
        b = self._bundles.get(tenant_id)
        if b is None:
            return None
        return {"bundle_id": b.bundle_id, "version": b.version, "issuer": b.issuer, "sha256": b.sha256,
                "signer_key_id": b.signer_key_id, "issued_at": b.issued_at, "indicators": len(b.indicators),
                "indicator_states": b.state_counts(self.clock())}

    # ------------------------------------------------------------------ topology

    def load_topology(self, tenant_id: str, actor: str, data: dict[str, Any]) -> OperatorTopology:
        try:
            topo = parse_topology(data)
        except TopologyError as exc:
            raise InvalidInputError(f"topology rejected: {exc}", code="topology_rejected") from exc
        digest = sha256_hex(data)
        with self._state_lock:
            self.ledger.append(tenant_id, CONFIG_ENTRY, f"topology:{topo.topology_id}"[:128], {
                "event": "topology_loaded", "topology_id": topo.topology_id, "sha256": digest,
                "summary": topo.summary(), "actor": actor})
            self.docs.put(TopologyRecord(doc_id=f"{tenant_id}:topology", tenant_id=tenant_id, topology=data,
                                         sha256=digest, loaded_by=actor, loaded_at=self.clock()))
            self._topologies[tenant_id] = topo
        return topo

    def topology_status(self, tenant_id: str) -> dict[str, Any] | None:
        t = self._topologies.get(tenant_id)
        return t.summary() if t is not None else None

    # ------------------------------------------------------------------ policies

    def load_policy(self, tenant_id: str, actor: str, data: dict[str, Any]) -> OperatorPolicy:
        """Store a signed operator policy. The signature must verify against a trusted policy key."""
        try:
            policy = OperatorPolicy.model_validate(data)
        except ValueError as exc:
            raise InvalidInputError(f"invalid policy: {exc}") from exc
        if policy.tenant_id != tenant_id:
            raise InvalidInputError("policy belongs to another tenant", failed=["policy_tenant_mismatch"])
        if not verify_model(policy, self.policy_keyring):
            raise InvalidInputError("policy signature does not verify against a trusted policy key",
                                    failed=["policy_signature_invalid"], code="signature_invalid")
        if not _ID_RE.match(policy.policy_id):
            raise InvalidInputError("invalid policy_id")
        with self._state_lock:
            if self._doc_id_taken("OperatorPolicy", policy.policy_id):
                raise ConflictError(f"policy {policy.policy_id!r} already exists; policies are immutable, "
                                    "issue a new policy_id", code="exists")
            self.ledger.append(tenant_id, EntryType.POLICY, policy.policy_id, {
                "event": "policy_loaded", "policy_id": policy.policy_id, "mode": policy.mode,
                "signer_key_id": policy.signer_key_id, "policy_sha256": sha256_hex(policy),
                "allowed_actions": [a.value for a in policy.allowed_actions],
                "legal_signoff_ref": policy.legal_signoff_ref, "valid_from": policy.valid_from,
                "valid_until": policy.valid_until, "actor": actor})
            self.docs.put(policy)
        return policy

    def list_policies(self, tenant_id: str) -> list[dict[str, Any]]:
        now = self.clock()
        out = []
        for p in sorted(self.docs.iter_all(OperatorPolicy, tenant_id), key=lambda p: _aware(p.valid_from),
                        reverse=True):
            out.append({"policy": p.model_dump(mode="json"),
                        "signature_valid": verify_model(p, self.policy_keyring),
                        "valid_now": _aware(p.valid_from) <= now < _aware(p.valid_until)})
        return out

    def _doc_id_taken(self, kind: str, doc_id: str) -> bool:
        """Global id check: DocStore keys are (kind, id), so ids must never collide across tenants."""
        with self.sf() as s:
            return s.get(DocRow, (kind, doc_id)) is not None

    def _select_policy(self, tenant_id: str, action: ProposedAction, policy_id: str | None) -> OperatorPolicy | None:
        if policy_id:
            p = self.docs.get(OperatorPolicy, tenant_id, policy_id)
            if p is None:
                raise NotFoundError(f"policy {policy_id!r} not found")
            return p
        now = self.clock()
        candidates = [p for p in self.docs.iter_all(OperatorPolicy, tenant_id)
                      if verify_model(p, self.policy_keyring) and _aware(p.valid_from) <= now < _aware(p.valid_until)]
        if not candidates:
            return None
        # prefer a policy that covers the action type, then active mode, then the most recent
        candidates.sort(key=lambda p: (action.action_type in p.allowed_actions, p.mode == "active",
                                       _aware(p.valid_from)), reverse=True)
        return candidates[0]

    # ------------------------------------------------------------------ ingest and detection

    def _sentinel(self, tenant_id: str) -> Sentinel:
        with self._state_lock:
            s = self._sentinels.get(tenant_id)
            if s is None:
                s = Sentinel(self.model, self._bundles.get(tenant_id), self.evidence, tenant_id=tenant_id,
                             authorized_collections=self._authorized_collections(tenant_id))
                self._sentinels[tenant_id] = s
            return s

    def ingest_text(self, tenant_id: str, source_id: str, data: bytes, *, name: str = "upload",
                    flush: bool = False) -> IngestOutcome:
        """Ingest a collector payload (CSV / JSONL / Zeek log) from a registered source."""
        return self.ingest_batch(tenant_id, [(source_id, data, name)], flush=flush)

    def ingest_files(self, tenant_id: str, files: Sequence[tuple[str | Path, str]], *,
                     flush_at: datetime | None = None) -> IngestOutcome:
        """Ingest collector files ``[(path, source_id)]`` as one time-ordered batch."""
        with self._ingest_lock:
            pipeline = self._pipeline(tenant_id)
            stats: list[IngestStats] = []
            for path, source_id in files:
                self._require_source(pipeline, source_id)
                stats.append(self._run_pipeline(pipeline.ingest_file, path, source_id))
            return self._finish_batch(tenant_id, stats, flush_at=flush_at)

    def ingest_batch(self, tenant_id: str, items: Sequence[tuple[str, bytes, str]], *,
                     flush: bool = False) -> IngestOutcome:
        with self._ingest_lock:
            pipeline = self._pipeline(tenant_id)
            stats: list[IngestStats] = []
            for source_id, data, name in items:
                self._require_source(pipeline, source_id)
                stats.append(self._run_pipeline(pipeline.ingest_text, data, source_id, name))
            return self._finish_batch(tenant_id, stats, flush_to_last_event=flush)

    def ingest_events(self, tenant_id: str, payloads: Sequence[Any], *, flush: bool = False) -> IngestOutcome:
        """Validate and process pre-normalized ``ObservationEvent`` payloads (JSON objects)."""
        rejected: list[dict[str, Any]] = []
        with self._ingest_lock:
            pipeline = self._pipeline(tenant_id)
            accepted = 0
            for i, payload in enumerate(payloads):
                if not isinstance(payload, dict):
                    rejected.append({"index": i, "reason": "not_an_object"})
                    continue
                if payload.get("tenant_id") != tenant_id:
                    # never write a record into another tenant's quarantine
                    rejected.append({"index": i, "reason": "tenant_mismatch"})
                    continue
                result = self._run_pipeline(pipeline.ingest_event, payload)
                if isinstance(result, Quarantined):
                    rejected.append({"index": i, "reason": result.reason, "quarantine_id": result.event_id})
                else:
                    accepted += 1
            stat = {"source_id": "events-api", "tenant_id": tenant_id, "records_read": len(payloads),
                    "accepted": accepted, "published": accepted, "quarantined": len(rejected),
                    "duplicates": 0}
            out = self._finish_batch(tenant_id, [], flush_to_last_event=flush, extra_stats=[stat])
            out.rejected = rejected
            return out

    @staticmethod
    def _require_source(pipeline: IngestPipeline, source_id: str) -> None:
        if source_id not in pipeline.sources:
            raise NotFoundError(f"source {source_id!r} is not registered for this tenant", code="unknown_source")

    def _run_pipeline(self, fn: Callable[..., Any], *args: Any) -> Any:
        try:
            return fn(*args)
        except IngestBackpressureError as exc:
            self._buffer.clear()
            raise OverloadedError(f"ingest backpressure: {exc}") from exc

    def _finish_batch(self, tenant_id: str, stats: list[IngestStats], *, flush_at: datetime | None = None,
                      flush_to_last_event: bool = False,
                      extra_stats: list[dict[str, Any]] | None = None) -> IngestOutcome:
        self.bus.drain()
        events = [e for e in self._buffer if e.tenant_id == tenant_id]
        foreign = len(self._buffer) - len(events)
        self._buffer.clear()
        if foreign:  # cannot happen with per-tenant pipelines; never process another tenant's data
            log.error("dropped %d events of another tenant from tenant %s batch", foreign, tenant_id)
        events.sort(key=lambda e: (e.observed_at, e.event_id))
        if flush_to_last_event and events and flush_at is None:
            flush_at = events[-1].observed_at
        findings, opened = self._detect(tenant_id, events, flush_at)
        stat_dicts = [s.to_dict() for s in stats] + list(extra_stats or [])
        if stat_dicts or events:
            self.ledger.append(tenant_id, INGEST_ENTRY, f"ingest:{uuid.uuid4()}", {
                "event": "ingest_batch", "events": len(events),
                "sources": [{k: s.get(k) for k in ("source_id", "input_ref", "records_read", "accepted",
                                                    "quarantined", "duplicates")} for s in stat_dicts],
                "finding_ids": [f.finding_id for f in findings], "case_ids": opened,
                "detector_version": self._sentinel(tenant_id).detector_version,
                "first_event_at": events[0].observed_at if events else None,
                "last_event_at": events[-1].observed_at if events else None})
        return IngestOutcome(stats=stat_dicts, events=len(events), findings=findings, cases_opened=opened)

    def _detect(self, tenant_id: str, events: list[ObservationEvent],
                flush_at: datetime | None) -> tuple[list[Finding], list[str]]:
        if events:
            self._update_coverage(tenant_id, events)
            self._update_history(tenant_id, events)
            self._update_atlas(tenant_id, events)
        sentinel = self._sentinel(tenant_id)
        findings = sentinel.process_batch(events)
        if flush_at is not None:
            findings += sentinel.flush(flush_at)
        opened: list[str] = []
        for f in findings:
            self.docs.put(f)
            if f.verdict in ALERT_VERDICTS:
                try:
                    case = self.cases.open_case(f)
                    opened.append(case.case_id)
                except (GuardError, ValueError) as exc:  # pragma: no cover - defensive
                    log.error("could not open case for finding %s: %s", f.finding_id, exc)
        return findings, opened

    def flush_detection(self, tenant_id: str, until: datetime) -> IngestOutcome:
        """Close detection windows up to ``until`` (end of a backfill or an idle sensor)."""
        with self._ingest_lock:
            return self._finish_batch(tenant_id, [], flush_at=_aware(until))

    def _update_coverage(self, tenant_id: str, events: list[ObservationEvent]) -> None:
        dd: dict[tuple[str, str], dict[str, Any]] = {}
        sd: Counter[tuple[str, str]] = Counter()
        for ev in events:
            t = _aware(ev.observed_at)
            day = t.date().isoformat()
            sd[(ev.source_id, day)] += 1
            if ev.entity_pseudonym is None:
                continue
            key = (ev.entity_pseudonym, day)
            cur = dd.get(key)
            if cur is None:
                cur = dd[key] = {"classes": Counter(), "events": 0, "first": t, "last": t}
            cur["classes"][ev.device_class or "unknown"] += 1
            cur["events"] += 1
            cur["first"] = min(cur["first"], t)
            cur["last"] = max(cur["last"], t)
        with self.sf.begin() as s:
            for (entity, day), v in dd.items():
                row = s.get(CoverageDayRow, (tenant_id, entity, day))
                klass = v["classes"].most_common(1)[0][0]
                if row is None:
                    s.add(CoverageDayRow(tenant_id=tenant_id, entity_pseudonym=entity, day=day, device_class=klass,
                                         events=v["events"], first_seen=v["first"], last_seen=v["last"]))
                else:
                    row.events += v["events"]
                    row.first_seen = min(_aware(row.first_seen), v["first"])
                    row.last_seen = max(_aware(row.last_seen), v["last"])
                    if row.device_class == "unknown":
                        row.device_class = klass
            for (source_id, day), n in sd.items():
                row2 = s.get(CoverageSourceDayRow, (tenant_id, source_id, day))
                if row2 is None:
                    s.add(CoverageSourceDayRow(tenant_id=tenant_id, source_id=source_id, day=day, events=n))
                else:
                    row2.events += n

    def coverage(self, tenant_id: str, period: ReportPeriod) -> CoverageStats:
        """Observed population inside ``period`` (UTC days overlapping the period)."""
        first_day = period.start.date().isoformat()
        last_day = (period.end - timedelta(microseconds=1)).date().isoformat()
        with self.sf() as s:
            rows = list(s.scalars(select(CoverageDayRow).where(
                CoverageDayRow.tenant_id == tenant_id, CoverageDayRow.day >= first_day,
                CoverageDayRow.day <= last_day)))
            srows = list(s.scalars(select(CoverageSourceDayRow).where(
                CoverageSourceDayRow.tenant_id == tenant_id, CoverageSourceDayRow.day >= first_day,
                CoverageSourceDayRow.day <= last_day)))
        classes: dict[str, Counter[str]] = defaultdict(Counter)
        days: dict[str, int] = Counter()
        first: datetime | None = None
        last: datetime | None = None
        for r in rows:
            classes[r.entity_pseudonym][r.device_class] += r.events
            days[r.entity_pseudonym] += 1
            fs, ls = _aware(r.first_seen), _aware(r.last_seen)
            first = fs if first is None or fs < first else first
            last = ls if last is None or ls > last else last
        by_class: Counter[str] = Counter()
        dd_by_class: Counter[str] = Counter()
        for ent, n in days.items():
            k = classes[ent].most_common(1)[0][0]
            by_class[k] += 1
            dd_by_class[k] += n
        return CoverageStats(devices_observed=len(days), device_days=sum(days.values()),
                             events=sum(r.events for r in srows) if srows else None,
                             devices_by_class=dict(sorted(by_class.items())),
                             device_days_by_class=dict(sorted(dd_by_class.items())),
                             sources=tuple(sorted({r.source_id for r in srows})),
                             first_event_at=first, last_event_at=last)

    def _update_history(self, tenant_id: str, events: list[ObservationEvent]) -> None:
        with self._state_lock:
            for ev in events:
                if ev.flow is not None and ev.flow.dst_ip:
                    self.history.add(tenant_id, ev.flow.dst_ip, entity=ev.entity_pseudonym)
                if ev.dns is not None and ev.dns.qname:
                    self.history.add(tenant_id, ev.dns.qname, entity=ev.entity_pseudonym)
            lo, hi = _aware(events[0].observed_at), _aware(events[-1].observed_at)
            span = self._history_span.get(tenant_id)
            if span is not None:
                lo, hi = min(lo, span[0]), max(hi, span[1])
            self._history_span[tenant_id] = (lo, hi)
            self.history.set_window(tenant_id, max(1.0, (hi - lo).total_seconds() / 86400.0))

    def _update_atlas(self, tenant_id: str, events: list[ObservationEvent]) -> None:
        """Resolver answers -> ``observed_resolves_to`` edges, one observation per (name, ip, day)."""
        seen = self._atlas_seen[tenant_id]
        for ev in events:
            dns = ev.dns
            if dns is None or str(dns.rcode).upper() != "NOERROR" or not dns.answers:
                continue
            day = _aware(ev.observed_at).date().isoformat()
            try:
                domain = node_key(NodeType.DOMAIN, dns.qname)
            except ValueError:
                continue
            for answer in dns.answers:
                key = (domain, answer, day)
                if key in seen:
                    continue
                try:
                    ip = node_key(NodeType.IP, answer)
                except ValueError:
                    continue
                seen.add(key)
                try:
                    self.atlas.upsert_edge(tenant_id, domain, ip, EdgeType.OBSERVED_RESOLVES_TO, ev.observed_at,
                                           f"{ev.event_id}:{ip}", EvidenceGrade.B, f"sensor:{ev.source_id}")
                except (AtlasError, ValueError) as exc:
                    log.warning("ATLAS rejected resolution edge: %s", exc)
        if len(seen) > 2_000_000:  # bound memory; ATLAS itself is idempotent per provenance id
            seen.clear()

    # ------------------------------------------------------------------ queries

    def list_findings(self, tenant_id: str, *, verdict: str | None = None, label: str | None = None,
                      status: str | None = None, entity: str | None = None, since: datetime | None = None,
                      until: datetime | None = None, limit: int = 50, offset: int = 0) -> Page:
        out = []
        for f in self.docs.iter_all(Finding, tenant_id):
            if verdict and f.verdict.value != verdict:
                continue
            if label and f.label != label:
                continue
            if status and f.status.value != status:
                continue
            if entity and f.entity_pseudonym != entity:
                continue
            end = _aware(f.observed_window_end)
            if since and end < since:
                continue
            if until and end >= until:
                continue
            out.append(f)
        out.sort(key=lambda f: (_aware(f.observed_window_end), f.finding_id), reverse=True)
        return _page(out, limit, offset)

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding:
        f = self.docs.get(Finding, tenant_id, finding_id)
        if f is None:
            raise NotFoundError("finding not found")
        return f

    def list_cases(self, tenant_id: str, *, state: str | None = None, severity: str | None = None,
                   limit: int = 50, offset: int = 0) -> Page:
        out = [c for c in self.docs.iter_all(Case, tenant_id)
               if (not state or c.state.value == state) and (not severity or c.severity == severity)]
        out.sort(key=lambda c: (_aware(c.updated_at), c.case_id), reverse=True)
        return _page(out, limit, offset)

    def get_case(self, tenant_id: str, case_id: str) -> Case:
        c = self.cases.get(tenant_id, case_id)
        if c is None:
            raise NotFoundError("case not found")
        return c

    def case_detail(self, tenant_id: str, case_id: str) -> dict[str, Any]:
        case = self.get_case(tenant_id, case_id)
        assessment = self.cases.assess_evidence(case)
        findings = [f for f in (self.docs.get(Finding, tenant_id, fid) for fid in case.finding_ids) if f]
        actions = [a for a in self.docs.iter_all(ProposedAction, tenant_id) if a.case_id == case_id]
        actions.sort(key=lambda a: _aware(a.created_at))
        report = self.docs.get(InvestigationReport, tenant_id, case_id)
        return {
            "case": case, "findings": findings,
            "evidence_assessment": {**assessment.as_dict(), "contested": assessment.contested,
                                    "verification_blockers": assessment.verification_blockers()},
            "allowed_transitions": sorted(s.value for s in ALLOWED_TRANSITIONS[case.state]),
            "actions": actions,
            "investigation": ({"report_id": report.report_id, "finished_at": report.finished_at,
                               "recommendation": report.verification.recommendation,
                               "escalate": report.escalate} if report else None),
        }

    def case_evidence(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        case = self.get_case(tenant_id, case_id)
        return [self.evidence_view(tenant_id, eid) for eid in dict.fromkeys(case.evidence_ids)
                if self._evidence_exists(tenant_id, eid)]

    def _evidence_exists(self, tenant_id: str, evidence_id: str) -> bool:
        return self.docs.get(Evidence, tenant_id, evidence_id) is not None

    def evidence_view(self, tenant_id: str, evidence_id: str) -> dict[str, Any]:
        try:
            ev = self.evidence.get(tenant_id, evidence_id)
            verified = ev is not None and self.evidence.verify(tenant_id, evidence_id)
        except EvidenceIntegrityError:
            ev = self.docs.get(Evidence, tenant_id, evidence_id)
            verified = False
        if ev is None:
            raise NotFoundError("evidence not found")
        return {"evidence": ev, "integrity_verified": verified,
                "superseded_by": self.evidence.superseded_by(tenant_id, evidence_id)}

    def case_history(self, tenant_id: str, case_id: str) -> list[dict[str, Any]]:
        self.get_case(tenant_id, case_id)
        return self.cases.history(tenant_id, case_id)

    def latest_investigation(self, tenant_id: str, case_id: str) -> InvestigationReport:
        self.get_case(tenant_id, case_id)
        r = self.docs.get(InvestigationReport, tenant_id, case_id)
        if r is None:
            raise NotFoundError("no investigation has been run for this case")
        return r

    def replay_case(self, tenant_id: str, case_id: str, as_of: datetime | None = None) -> dict[str, Any]:
        self.get_case(tenant_id, case_id)
        return ledger_replay(tenant_id, self.ledger, case_id, _aware(as_of) if as_of else self.clock())

    def graph_view(self, tenant_id: str, node: str, as_of: datetime | None = None) -> dict[str, Any]:
        node = node.strip()
        try:
            nid = canonical_node_id(node) if ":" in node and not _is_ipv6(node) else indicator_node_id(node)
        except ValueError:
            try:
                nid = indicator_node_id(node)
            except ValueError as exc:
                raise InvalidInputError(f"not a graph node or indicator: {node!r}") from exc
        t = _aware(as_of) if as_of else None
        n = self.atlas.get_node(tenant_id, nid, t)
        if n is None:
            raise NotFoundError("node not found")
        neighbors = self.atlas.neighbors(tenant_id, nid, t)
        try:
            shared = self.atlas.is_shared_hosting(tenant_id, nid, t)
        except ValueError:
            shared = False
        return {"node": n, "shared_hosting": shared, "degree": len(neighbors),
                "neighbors": neighbors[:500], "truncated": len(neighbors) > 500,
                "candidate_links": self.atlas.candidate_links(tenant_id, nid, t, limit=10),
                "as_of": t}

    def verify_ledger(self, tenant_id: str) -> dict[str, Any]:
        report = self.ledger.verify_report(tenant_id, self.ledger_keyring)
        return {**report.as_dict(), "entry_count": self.ledger.count(tenant_id),
                "trusted_ledger_keys": self.ledger_keyring.key_ids()}

    def ledger_entries(self, tenant_id: str, *, subject_id: str | None = None, entry_type: str | None = None,
                       limit: int = 50, offset: int = 0) -> Page:
        entries = self.ledger.entries(tenant_id, subject_id=subject_id, entry_type=entry_type)
        entries.reverse()  # newest first
        return _page(entries, limit, offset)

    def list_quarantine(self, tenant_id: str, *, limit: int = 50, offset: int = 0) -> Page:
        items = self.quarantine.list(tenant_id, limit=offset + limit)
        with self.sf() as s:
            total = s.scalar(select(func.count()).select_from(DocRow).where(
                DocRow.kind == Quarantined.__name__, DocRow.tenant_id == tenant_id)) or 0
        return Page(items=items[offset:offset + limit], total=total, limit=limit, offset=offset)

    # ------------------------------------------------------------------ case work

    def transition_case(self, tenant_id: str, case_id: str, to_state: CaseState, actor: str, reason: str) -> Case:
        if to_state in (CaseState.PROPOSED, CaseState.APPROVED, CaseState.EXECUTED, CaseState.ROLLED_BACK):
            raise InvalidInputError(f"{to_state.value} is reached through the actions workflow "
                                    "(authorize / approve / execute / rollback)", code="use_actions_workflow")
        self.get_case(tenant_id, case_id)
        try:
            return self.cases.transition(tenant_id, case_id, to_state, actor, reason)
        except GuardError as exc:
            raise ConflictError(str(exc), failed=exc.failed) from exc

    def review_case(self, tenant_id: str, case_id: str, actor: str, alternatives: list[str], notes: str) -> Case:
        self.get_case(tenant_id, case_id)
        try:
            return self.cases.record_counter_hypothesis_review(tenant_id, case_id, reviewer=actor,
                                                               alternatives=alternatives, notes=notes)
        except GuardError as exc:
            raise ConflictError(str(exc), failed=exc.failed) from exc

    def add_case_note(self, tenant_id: str, case_id: str, actor: str, note: str) -> Evidence:
        """Append an analyst note as evidence (never qualifies for verification) and attach it."""
        case = self.get_case(tenant_id, case_id)
        if case.state in TERMINAL_STATES:
            raise ConflictError(f"case is {case.state.value}", failed=["terminal_state"])
        text_ = note.strip()
        if not text_:
            raise InvalidInputError("note is empty")
        ev = self.evidence.append(Evidence(
            tenant_id=tenant_id, kind=EvidenceKind.ANALYST_NOTE, origin_source=f"analyst:{actor}"[:200],
            source_independence_group=f"analyst:{actor}"[:200], collected_at=self.clock(),
            summary=text_[:500], payload={"note": text_[:8000], "author": actor, "case_id": case_id},
            authorization_id="operator:case-work"))
        self.cases.attach_evidence(tenant_id, case_id, [ev.evidence_id], actor=actor)
        return ev

    def investigate_case(self, tenant_id: str, case_id: str, actor: str) -> InvestigationReport:
        case = self.get_case(tenant_id, case_id)
        if case.state in TERMINAL_STATES:
            raise ConflictError(f"case is {case.state.value}", failed=["terminal_state"])
        self.ledger.append(tenant_id, "investigation_requested", case_id, {"case_id": case_id, "actor": actor})
        return self.investigator.investigate(case)

    # ------------------------------------------------------------------ actions (MIRROR workflow)

    def list_actions(self, tenant_id: str, *, case_id: str | None = None, limit: int = 50, offset: int = 0) -> Page:
        items = [a for a in self.docs.iter_all(ProposedAction, tenant_id) if not case_id or a.case_id == case_id]
        items.sort(key=lambda a: (_aware(a.created_at), a.action_id), reverse=True)
        return _page(items, limit, offset)

    def get_action(self, tenant_id: str, action_id: str) -> ProposedAction:
        a = self.docs.get(ProposedAction, tenant_id, action_id)
        if a is None:
            raise NotFoundError("action not found")
        return a

    def action_detail(self, tenant_id: str, action_id: str) -> dict[str, Any]:
        action = self.get_action(tenant_id, action_id)
        mirror = self.docs.get(MirrorRecord, tenant_id, action_id)
        authz = self.docs.get(AuthorizationRecord, tenant_id, action_id)
        return {"action": action, "mirror": mirror.result if mirror else None,
                "authorization": authz.decision if authz else None,
                "evidence_quality_ok": authz.evidence_quality_ok if authz else None,
                "executions": self.execution_records(tenant_id, action_id),
                "live": action_id in self.executor.active()}

    def execution_records(self, tenant_id: str, action_id: str) -> list[ExecutionRecord]:
        out = []
        for e in self.ledger.entries(tenant_id, subject_id=action_id, entry_type=EntryType.EXECUTION):
            if e.payload.get("phase") == "outcome" and isinstance(e.payload.get("record"), dict):
                out.append(ExecutionRecord.model_validate(e.payload["record"]))
        return out

    def propose_action(self, tenant_id: str, actor: str, *, case_id: str, action_type: ActionType | str,
                       targets: list[str], scope: dict[str, Any] | None = None, legal_basis: str | None = None,
                       expires_at: datetime | None = None, rollback_plan: str | None = None,
                       rollback_verified: bool = False) -> ProposedAction:
        case = self.get_case(tenant_id, case_id)
        if case.state is not CaseState.VERIFIED:
            raise ConflictError("actions can only be proposed for VERIFIED cases",
                                failed=[f"case_state:{case.state.value}"])
        try:
            atype = ActionType(action_type)
        except ValueError as exc:
            raise InvalidInputError(f"unknown action type {action_type!r}") from exc
        clean = [t.strip() for t in targets if isinstance(t, str) and t.strip()]
        if not clean:
            raise InvalidInputError("at least one target is required")
        if len(clean) > 1000:
            raise InvalidInputError("too many targets")
        try:
            for t in clean:
                normalize_target(atype, t)
        except InvalidTargetError as exc:
            raise InvalidInputError(f"invalid target: {exc}") from exc
        now = self.clock()
        if expires_at is not None and _aware(expires_at) <= now:
            raise InvalidInputError("expires_at must be in the future")
        action = ProposedAction(tenant_id=tenant_id, case_id=case_id, action_type=atype, targets=clean,
                                scope=dict(scope or {}), legal_basis=legal_basis,
                                expires_at=_aware(expires_at) if expires_at else None,
                                rollback_plan=rollback_plan, rollback_verified=bool(rollback_verified),
                                created_by=actor, created_at=now)
        self.ledger.append(tenant_id, EntryType.ACTION, action.action_id, {
            "event": "proposed", "action_id": action.action_id, "case_id": case_id,
            "action_type": atype.value, "targets": clean, "scope": action.scope, "legal_basis": legal_basis,
            "expires_at": action.expires_at, "rollback_verified": action.rollback_verified, "actor": actor})
        self.docs.put(action)
        return action

    def _case_indicators(self, case: Case) -> list[str]:
        evs = [e for e in (self.docs.get(Evidence, case.tenant_id, eid) for eid in case.evidence_ids)
               if e is not None and e.supports]
        return indicators_from_evidence(evs)

    def _run_simulation(self, action: ProposedAction) -> MirrorResult:
        case = self.cases.get(action.tenant_id, action.case_id)
        return mirror_simulate(action, self._topologies.get(action.tenant_id), self.atlas, self.history,
                               now=self.clock(), case_indicators=self._case_indicators(case) if case else ())

    def _simulate_for_agent(self, action: ProposedAction) -> MirrorResult:
        """Read-only simulator handed to the ORACLE response planner (nothing stored)."""
        return self._run_simulation(action)

    def simulate_action(self, tenant_id: str, actor: str, action_id: str) -> MirrorResult:
        action = self.get_action(tenant_id, action_id)
        result = self._run_simulation(action)
        self.ledger.append(tenant_id, "mirror_simulation", action_id, {
            "action_id": action_id, "case_id": action.case_id, "verdict": result.verdict.value,
            "affected_entities": result.affected_entities, "shared_infrastructure": result.shared_infrastructure,
            "unknowns": result.unknowns, "requires_human_approval": result.requires_human_approval,
            "actor": actor})
        self.docs.put(MirrorRecord(tenant_id=tenant_id,
                                   action_id=action_id, result=result, simulated_by=actor))
        return result

    def _assess(self, tenant_id: str, actor: str, action: ProposedAction, case: Case,
                policy_id: str | None
                ) -> tuple[AuthorizationDecision, OperatorPolicy | None, MirrorResult | None, bool]:
        mirror_rec = self.docs.get(MirrorRecord, tenant_id, action.action_id)
        mirror = mirror_rec.result if mirror_rec else None
        policy = self._select_policy(tenant_id, action, policy_id)
        quality_ok = (case.state in (CaseState.VERIFIED, CaseState.PROPOSED, CaseState.APPROVED)
                      and not self.cases.assess_evidence(case).verification_blockers())
        decision = mirror_authorize(action, policy, self.policy_keyring, mirror, quality_ok, now=self.clock())
        self.ledger.append(tenant_id, EntryType.AUTHORIZATION, action.action_id, {
            "action_id": action.action_id, "case_id": case.case_id, "allowed": decision.allowed,
            "failed_checks": decision.failed_checks, "policy_id": decision.policy_id,
            "requires_human_approval": decision.requires_human_approval, "evidence_quality_ok": quality_ok,
            "mirror_verdict": mirror.verdict.value if mirror else None, "actor": actor})
        self.docs.put(AuthorizationRecord(tenant_id=tenant_id,
                                          action_id=action.action_id, decision=decision, evaluated_by=actor,
                                          evidence_quality_ok=quality_ok))
        return decision, policy, mirror, quality_ok

    def authorize_action(self, tenant_id: str, actor: str, action_id: str, *,
                         policy_id: str | None = None) -> dict[str, Any]:
        """Run the deterministic authorization assessment; a VERIFIED case moves to PROPOSED."""
        action = self.get_action(tenant_id, action_id)
        case = self.get_case(tenant_id, action.case_id)
        if case.state not in (CaseState.VERIFIED, CaseState.PROPOSED):
            raise ConflictError("authorization is assessed for VERIFIED or PROPOSED cases",
                                failed=[f"case_state:{case.state.value}"])
        decision, _, _, quality_ok = self._assess(tenant_id, actor, action, case, policy_id)
        if case.state is CaseState.VERIFIED:
            try:
                case = self.cases.transition(tenant_id, case.case_id, CaseState.PROPOSED, actor,
                                             f"action {action_id} proposed; authorization "
                                             f"{'allowed' if decision.allowed else 'not allowed'}",
                                             authorization=decision)
            except GuardError as exc:
                raise ConflictError(str(exc), failed=exc.failed) from exc
        return {"decision": decision, "case_state": case.state.value, "evidence_quality_ok": quality_ok}

    def decide_action(self, tenant_id: str, actor: str, action_id: str, *, approve: bool, reason: str) -> Case:
        """Approver decision. Approval needs an allowed assessment and a different person than the proposer."""
        action = self.get_action(tenant_id, action_id)
        case = self.get_case(tenant_id, action.case_id)
        if case.state is not CaseState.PROPOSED:
            raise ConflictError("only PROPOSED cases can be approved or denied",
                                failed=[f"case_state:{case.state.value}"])
        if not reason or not reason.strip():
            raise InvalidInputError("a reason is required")
        if approve and actor.strip() == (action.created_by or "").strip():
            raise ForbiddenActionError("the proposer of an action cannot approve it (four-eyes)",
                                       failed=["approver_is_proposer"])
        authz = self.docs.get(AuthorizationRecord, tenant_id, action_id)
        to_state = CaseState.APPROVED if approve else CaseState.DENIED
        try:
            case = self.cases.transition(tenant_id, case.case_id, to_state, actor, reason,
                                         authorization=authz.decision if authz else None)
        except GuardError as exc:
            raise ConflictError(str(exc), failed=exc.failed) from exc
        self.ledger.append(tenant_id, EntryType.ACTION, action_id, {
            "event": "approved" if approve else "denied", "action_id": action_id, "case_id": case.case_id,
            "actor": actor, "reason": reason.strip()[:2000]})
        return case

    def execute_action(self, tenant_id: str, actor: str, action_id: str, *, reason: str = "") -> dict[str, Any]:
        """Execute an approved action. Every gate is re-evaluated now; any failure refuses."""
        action = self.get_action(tenant_id, action_id)
        case = self.get_case(tenant_id, action.case_id)
        failed: list[str] = []
        if case.state is not CaseState.APPROVED:
            failed.append(f"case_state:{case.state.value}")
        if actor.strip() == (action.created_by or "").strip():
            failed.append("approver_is_proposer")
        decision, policy, mirror, _ = self._assess(tenant_id, actor, action, case, None)
        if not failed:
            failed += self.cases.check_transition(tenant_id, case.case_id, CaseState.EXECUTED, actor,
                                                  authorization=decision, mirror=mirror, policy=policy)
        if failed:
            self.ledger.append(tenant_id, "execution_refused", action_id, {
                "action_id": action_id, "case_id": case.case_id, "actor": actor,
                "failed_checks": list(dict.fromkeys(failed)), "reason": reason[:2000]})
            raise ConflictError("execution refused", failed=list(dict.fromkeys(failed)))
        record = self.executor.execute(action, decision, actor)
        if record.status not in (ExecutionStatus.APPLIED, ExecutionStatus.DRY_RUN):
            raise ConflictError(f"executor did not apply the action ({record.status.value})",
                                failed=record.refusal_reasons or [record.reason])
        try:
            case = self.cases.transition(tenant_id, case.case_id, CaseState.EXECUTED, actor,
                                         reason.strip() or f"action {action_id} executed via {record.adapter}",
                                         authorization=decision, mirror=mirror, policy=policy)
        except GuardError as exc:
            # the world changed between the check and the transition: undo the enforcement
            self.executor.rollback(action_id, actor="system:guard", reason="case transition refused after apply",
                                   tenant_id=tenant_id)
            raise ConflictError(str(exc), failed=exc.failed) from exc
        return {"execution": record, "case_state": case.state.value}

    def rollback_action(self, tenant_id: str, actor: str, action_id: str, *, reason: str) -> dict[str, Any]:
        action = self.get_action(tenant_id, action_id)
        if not reason or not reason.strip():
            raise InvalidInputError("a reason is required")
        try:
            record = self.executor.rollback(action_id, actor=actor, reason=reason.strip(), tenant_id=tenant_id)
        except ExecutionError as exc:
            raise ConflictError(str(exc), failed=["no_live_execution"]) from exc
        if record.status is not ExecutionStatus.ROLLED_BACK:
            raise ConflictError(f"rollback failed: {record.reason}", failed=["rollback_failed"])
        case = self.get_case(tenant_id, action.case_id)
        if case.state is CaseState.EXECUTED:
            case = self.cases.transition(tenant_id, case.case_id, CaseState.ROLLED_BACK, actor, reason.strip())
        return {"execution": record, "case_state": case.state.value}

    def sweep_expired(self) -> list[str]:
        """Roll back live actions past their expiry and expire stale approvals."""
        changed: list[str] = []
        for rec in self.executor.sweep_expired():
            if rec.status is ExecutionStatus.ROLLED_BACK:
                case = self.cases.get(rec.tenant_id, rec.case_id)
                if case is not None and case.state is CaseState.EXECUTED:
                    self.cases.transition(rec.tenant_id, rec.case_id, CaseState.EXPIRED, "system:expiry",
                                          f"action {rec.action_id} expired and was rolled back")
                    changed.append(rec.case_id)
        now = self.clock()
        with self.sf() as s:
            rows = list(s.execute(select(DocRow.tenant_id, DocRow.body).where(DocRow.kind == "ProposedAction")))
        for tenant_id, body in rows:
            exp = body.get("expires_at")
            if not exp or datetime.fromisoformat(exp) > now:
                continue
            case = self.cases.get(tenant_id, body["case_id"])
            if case is not None and case.state is CaseState.APPROVED:
                try:
                    self.cases.transition(tenant_id, case.case_id, CaseState.EXPIRED, "system:expiry",
                                          f"approved action {body['action_id']} expired before execution")
                    changed.append(case.case_id)
                except GuardError as exc:  # pragma: no cover - defensive
                    log.error("could not expire case %s: %s", case.case_id, exc)
        return changed

    # ------------------------------------------------------------------ reports and metrics

    def default_period(self, tenant_id: str) -> ReportPeriod:
        lab = self._lab.get(tenant_id)
        if lab is not None:
            return lab.period
        with self.sf() as s:
            first = s.scalars(select(CoverageDayRow.day).where(CoverageDayRow.tenant_id == tenant_id)
                              .order_by(CoverageDayRow.day).limit(1)).first()
        now = self.clock()
        if first is None:
            return ReportPeriod(now - timedelta(days=30), now)
        start = datetime.fromisoformat(first).replace(tzinfo=timezone.utc)
        return ReportPeriod(start, max(now, start + timedelta(days=1)))

    def register_lab_context(self, tenant_id: str, ctx: LabContext) -> None:
        self._lab[tenant_id] = ctx

    def pov_report(self, tenant_id: str, *, start: datetime | None = None, end: datetime | None = None,
                   operator_name: str | None = None, false_alert_budget_per_10k: float | None = None,
                   fmt: Literal["html", "json"] = "html") -> str | dict[str, Any]:
        period = (ReportPeriod(_aware(start), _aware(end)) if start and end else self.default_period(tenant_id))
        lab = self._lab.get(tenant_id)
        kwargs: dict[str, Any] = {}
        if lab is not None:
            kwargs = {"onsets": lab.onsets, "ground_truth": lab.ground_truth, "ground_truth_source": lab.source}
        try:
            pov = collect_pov_report(tenant_id, self.docs, self.ledger, period, keyring=self.ledger_keyring,
                                     coverage=self.coverage(tenant_id, period), operator_name=operator_name,
                                     false_alert_budget_per_10k=false_alert_budget_per_10k,
                                     generated_at=self.clock(), **kwargs)
        except ValueError as exc:
            raise InvalidInputError(str(exc)) from exc
        self.ledger.append(tenant_id, "report_generated", f"pov:{pov.fingerprint}"[:128], {
            "report": "pov", "fingerprint": pov.fingerprint, "period_start": period.start,
            "period_end": period.end})
        if fmt == "json":
            return pov.model_dump(mode="json", by_alias=True)
        return render_pov_html(pov)

    def metrics_summary(self, tenant_id: str) -> dict[str, Any]:
        findings = list(self.docs.iter_all(Finding, tenant_id))
        cases = list(self.docs.iter_all(Case, tenant_id))
        actions = list(self.docs.iter_all(ProposedAction, tenant_id))
        executions = [e for e in self.ledger.entries(tenant_id, entry_type=EntryType.EXECUTION)
                      if e.payload.get("phase") == "outcome"]
        exec_status = Counter(e.payload.get("status", "unknown") for e in executions)
        period = self.default_period(tenant_id)
        cov = self.coverage(tenant_id, period)
        open_states = {CaseState.NEW, CaseState.TRIAGE, CaseState.INVESTIGATING, CaseState.PROPOSED,
                       CaseState.APPROVED}
        return {
            "tenant_id": tenant_id,
            "findings": {"total": len(findings),
                         "by_verdict": dict(sorted(Counter(f.verdict.value for f in findings).items())),
                         "by_label": dict(sorted(Counter(f.label for f in findings
                                                         if f.verdict in ALERT_VERDICTS).items()))},
            "cases": {"total": len(cases), "open": sum(1 for c in cases if c.state in open_states),
                      "by_state": dict(sorted(Counter(c.state.value for c in cases).items())),
                      "by_severity": dict(sorted(Counter(c.severity for c in cases).items()))},
            "actions": {"total": len(actions), "executions_by_status": dict(sorted(exec_status.items())),
                        "live_enforcements": sum(1 for a in actions if a.action_id in self.executor.active()),
                        "enforcement_applied": exec_status.get(ExecutionStatus.APPLIED.value, 0)},
            "coverage": {"period_start": period.start, "period_end": period.end,
                         "devices_observed": cov.devices_observed, "device_days": cov.device_days,
                         "events": cov.events, "devices_by_class": cov.devices_by_class},
            "ingest": {"quarantined": self.quarantine.count(tenant_id),
                       "quarantine_reasons": self.quarantine.reasons(tenant_id),
                       "sources": [c.source_id for c in self.list_sources(tenant_id)]},
            "detector_version": self.detector_version(tenant_id),
            "model_loaded": self.model is not None,
            "ioc_bundle": self.ioc_status(tenant_id),
            "topology": self.topology_status(tenant_id),
            "llm": self.llm is not None,
            "enforcement_adapter": self.adapter.name,
            "ledger": {"entries": self.ledger.count(tenant_id), "head": self.ledger.head(tenant_id)},
        }

    # ------------------------------------------------------------------ audit

    def audit(self, tenant_id: str, request_id: str, payload: dict[str, Any]) -> None:
        """Record an API call in the tenant's ledger (``api_audit``)."""
        self.ledger.append(tenant_id, API_AUDIT_ENTRY, f"req:{request_id}"[:128], payload)

    def close(self) -> None:
        self.engine.dispose()


# ============================================================================ helpers


def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    """Single-host SQLite deployments: WAL journal (readers never block the writer) and
    ``synchronous=NORMAL`` (durable across process crashes; PostgreSQL is the production store)."""
    cur = dbapi_conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA busy_timeout=10000")
    finally:
        cur.close()


def _check_tenant(tenant_id: str) -> None:
    if not isinstance(tenant_id, str) or not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", tenant_id):
        raise InvalidInputError("invalid tenant id")


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    tmp.replace(path)


__all__ = [
    "AEGIS_VERSION", "AegisService", "AuthorizationRecord", "ConflictError", "CoverageDayRow",
    "ForbiddenActionError", "IngestOutcome", "InvalidInputError", "IocBundleRecord", "LabContext",
    "MirrorRecord", "NotFoundError", "OverloadedError", "Page", "ServiceError", "SourceRecord",
    "TopologyRecord",
]
