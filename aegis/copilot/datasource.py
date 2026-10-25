"""Read-only, tenant-scoped data port used by every Copilot tool.

:class:`CopilotDataSource` is the only way the Copilot reads platform state. Every
method takes the caller's ``tenant_id`` (from the verified session, never from model
output) and returns ``None`` / empty results for ids that do not exist *in that
tenant*, so a cross-tenant id is indistinguishable from a missing one.

The single write is :meth:`CopilotDataSource.record_audit`, called by the engine (never
by a tool) to append one ``copilot_qa`` ledger entry per answered question.

:class:`ServiceDataSource` adapts :class:`aegis.service.AegisService` using only its
read paths. MIRROR simulation goes through a read-only simulator callable (by default
the service's ORACLE simulator), which stores nothing and executes nothing.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable, Protocol, runtime_checkable

from aegis.contracts.models import Case, Finding, LedgerEntry, MirrorResult, ProposedAction

log = logging.getLogger(__name__)

#: Ledger entry type written for every answered question.
COPILOT_AUDIT_ENTRY = "copilot_qa"
#: Ledger entry types read by the Copilot (written by other modules).
INGEST_ENTRY = "ingest_batch"
CAMPAIGN_ENTRY = "resonance_campaign"


class DataSourceError(RuntimeError):
    """The underlying store failed; the tool reports an error and the answer degrades."""


class InvalidQuery(ValueError):
    """The request was well-formed JSON but not a valid query (e.g. not a graph node)."""


@runtime_checkable
class CopilotDataSource(Protocol):
    def now(self) -> datetime: ...

    def find_findings(self, tenant_id: str, *, verdict: str | None = None, label: str | None = None,
                      status: str | None = None, entity: str | None = None, since: datetime | None = None,
                      limit: int = 20) -> tuple[list[Finding], int]: ...

    def exists(self, tenant_id: str, kind: str, entity_id: str) -> bool:
        """Whether an entity (finding/case/evidence/campaign/action/ledger/node) exists in this tenant."""
        ...

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding | None: ...

    def find_cases(self, tenant_id: str, *, state: str | None = None, severity: str | None = None,
                   limit: int = 20) -> tuple[list[Case], int]: ...

    def get_case_detail(self, tenant_id: str, case_id: str) -> dict[str, Any] | None: ...

    def get_evidence(self, tenant_id: str, evidence_id: str) -> dict[str, Any] | None: ...

    def get_action(self, tenant_id: str, action_id: str) -> ProposedAction | None: ...

    def list_campaigns(self, tenant_id: str, *, limit: int = 20) -> list[dict[str, Any]]: ...

    def campaign_exists(self, tenant_id: str, campaign_id: str) -> bool: ...

    def graph(self, tenant_id: str, node: str, *, as_of: datetime | None = None) -> dict[str, Any] | None: ...

    def node_exists(self, tenant_id: str, node_id: str) -> bool: ...

    def ledger_entries(self, tenant_id: str, *, subject_id: str | None = None, entry_type: str | None = None,
                       limit: int = 20) -> list[LedgerEntry]: ...

    def ledger_entry(self, tenant_id: str, seq: int) -> LedgerEntry | None: ...

    def verify_ledger(self, tenant_id: str) -> dict[str, Any]: ...

    def metrics(self, tenant_id: str) -> dict[str, Any]: ...

    def health(self, tenant_id: str) -> dict[str, Any]: ...

    def simulate(self, tenant_id: str, action: ProposedAction) -> MirrorResult: ...

    def record_audit(self, tenant_id: str, subject_id: str, payload: dict[str, Any]) -> int | None: ...


class ServiceDataSource:
    """:class:`CopilotDataSource` over an :class:`aegis.service.AegisService` (read paths only).

    ``simulator`` is a read-only MIRROR simulator ``(ProposedAction) -> MirrorResult``; it
    defaults to the service's ORACLE simulator, which stores no record and writes no
    ledger entry (unlike ``AegisService.simulate_action``).
    """

    def __init__(self, service: Any, *,
                 simulator: Callable[[ProposedAction], MirrorResult] | None = None):
        from aegis.service import InvalidInputError, NotFoundError  # composition-root errors

        self._svc = service
        self._not_found: tuple[type[Exception], ...] = (NotFoundError,)
        self._invalid: tuple[type[Exception], ...] = (InvalidInputError,)
        sim = simulator if simulator is not None else getattr(service, "_simulate_for_agent", None)
        if sim is None:
            raise ValueError("service exposes no read-only simulator; pass simulator=")
        self._simulator: Callable[[ProposedAction], MirrorResult] = sim

    # ------------------------------------------------------------------ basics

    def now(self) -> datetime:
        return self._svc.clock()

    def _guard(self, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except self._not_found:
            return None
        except self._invalid as exc:
            raise InvalidQuery(str(getattr(exc, "detail", exc))) from exc
        except (InvalidQuery, DataSourceError):
            raise
        except Exception as exc:
            log.warning("copilot data source failure: %s", type(exc).__name__)
            raise DataSourceError(type(exc).__name__) from exc

    def exists(self, tenant_id: str, kind: str, entity_id: str) -> bool:
        from aegis.contracts.models import Evidence

        svc = self._svc
        try:
            if kind == "finding":
                return svc.docs.get(Finding, tenant_id, entity_id) is not None
            if kind == "case":
                return svc.cases.get(tenant_id, entity_id) is not None
            if kind == "evidence":
                return svc.docs.get(Evidence, tenant_id, entity_id) is not None
            if kind == "action":
                return svc.docs.get(ProposedAction, tenant_id, entity_id) is not None
            if kind == "campaign":
                return self.campaign_exists(tenant_id, entity_id)
            if kind == "ledger":
                return entity_id.isdigit() and svc.ledger.get(tenant_id, int(entity_id)) is not None
            if kind == "node":
                return self.node_exists(tenant_id, entity_id)
        except (DataSourceError, InvalidQuery, ValueError):
            return False
        except Exception as exc:
            log.warning("copilot existence check failed: %s", type(exc).__name__)
            return False
        return False

    # ------------------------------------------------------------------ findings & cases

    def find_findings(self, tenant_id: str, *, verdict: str | None = None, label: str | None = None,
                      status: str | None = None, entity: str | None = None, since: datetime | None = None,
                      limit: int = 20) -> tuple[list[Finding], int]:
        page = self._guard(lambda: self._svc.list_findings(tenant_id, verdict=verdict, label=label, status=status,
                                                           entity=entity, since=since, limit=limit, offset=0))
        return list(page.items), int(page.total)

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding | None:
        return self._guard(lambda: self._svc.get_finding(tenant_id, finding_id))

    def find_cases(self, tenant_id: str, *, state: str | None = None, severity: str | None = None,
                   limit: int = 20) -> tuple[list[Case], int]:
        page = self._guard(lambda: self._svc.list_cases(tenant_id, state=state, severity=severity,
                                                        limit=limit, offset=0))
        return list(page.items), int(page.total)

    def get_case_detail(self, tenant_id: str, case_id: str) -> dict[str, Any] | None:
        return self._guard(lambda: self._svc.case_detail(tenant_id, case_id))

    def get_evidence(self, tenant_id: str, evidence_id: str) -> dict[str, Any] | None:
        return self._guard(lambda: self._svc.evidence_view(tenant_id, evidence_id))

    def get_action(self, tenant_id: str, action_id: str) -> ProposedAction | None:
        return self._guard(lambda: self._svc.get_action(tenant_id, action_id))

    # ------------------------------------------------------------------ RESONANCE campaigns

    def _campaign_entries(self, tenant_id: str) -> list[LedgerEntry]:
        return self._guard(lambda: self._svc.ledger.entries(tenant_id, entry_type=CAMPAIGN_ENTRY))

    def list_campaigns(self, tenant_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        latest: dict[str, LedgerEntry] = {}
        for e in self._campaign_entries(tenant_id):
            latest[e.subject_id] = e          # chain order: the last entry per campaign wins
        rows = sorted(latest.values(), key=lambda e: e.seq, reverse=True)[:limit]
        out: list[dict[str, Any]] = []
        for e in rows:
            p = e.payload
            ev_id = p.get("evidence_id")
            ev = self._evidence_doc(tenant_id, ev_id) if isinstance(ev_id, str) else None
            ep = ev.payload if ev is not None else {}
            out.append({
                "campaign_id": e.subject_id, "ledger_seq": e.seq, "recorded_at": e.recorded_at,
                "evidence_id": ev_id if ev is not None else None,
                "counterevidence_ids": list(p.get("counterevidence_ids") or []),
                "destinations": list(p.get("destinations") or [])[:20], "n_lines": p.get("n_lines"),
                "p_value": p.get("p_value"), "q_value": p.get("q_value"), "q_target": p.get("q_target"),
                "detector_version": p.get("detector_version"),
                "period_s": ep.get("period_s"), "statistic": ep.get("statistic"),
                "enforcement_eligible": ep.get("enforcement_eligible"),
                "shared_hosting_domain": ep.get("shared_hosting_domain"),
                "topology_unknown": ep.get("topology_unknown"),
                "window_start": ep.get("window_start"), "window_end": ep.get("window_end"),
                "explanation": ep.get("explanation"),
            })
        return out

    def _evidence_doc(self, tenant_id: str, evidence_id: str) -> Any:
        return self._guard(lambda: self._svc.evidence.get(tenant_id, evidence_id))

    def campaign_exists(self, tenant_id: str, campaign_id: str) -> bool:
        entries = self._guard(lambda: self._svc.ledger.entries(tenant_id, subject_id=campaign_id,
                                                               entry_type=CAMPAIGN_ENTRY, limit=1))
        return bool(entries)

    # ------------------------------------------------------------------ graph

    def graph(self, tenant_id: str, node: str, *, as_of: datetime | None = None) -> dict[str, Any] | None:
        return self._guard(lambda: self._svc.graph_view(tenant_id, node, as_of))

    def node_exists(self, tenant_id: str, node_id: str) -> bool:
        try:
            return self._svc.constellation.get_node(tenant_id, node_id) is not None
        except ValueError:
            return False

    # ------------------------------------------------------------------ ledger

    def ledger_entries(self, tenant_id: str, *, subject_id: str | None = None, entry_type: str | None = None,
                       limit: int = 20) -> list[LedgerEntry]:
        ledger = self._svc.ledger
        if subject_id is None and entry_type is None:
            head = self._guard(lambda: ledger.latest(tenant_id))
            if head is None:
                return []
            rows = self._guard(lambda: ledger.entries(tenant_id, after_seq=max(-1, head.seq - limit)))
        else:
            rows = self._guard(lambda: ledger.entries(tenant_id, subject_id=subject_id, entry_type=entry_type))
        return list(reversed(rows))[:limit]

    def ledger_entry(self, tenant_id: str, seq: int) -> LedgerEntry | None:
        return self._guard(lambda: self._svc.ledger.get(tenant_id, seq))

    def verify_ledger(self, tenant_id: str) -> dict[str, Any]:
        return self._guard(lambda: self._svc.verify_ledger(tenant_id))

    # ------------------------------------------------------------------ operations

    def metrics(self, tenant_id: str) -> dict[str, Any]:
        return self._guard(lambda: self._svc.metrics_summary(tenant_id))

    def health(self, tenant_id: str) -> dict[str, Any]:
        svc = self._svc
        ready = self._guard(svc.ready)
        out: dict[str, Any] = {"ready": ready.get("ready"), "checks": ready.get("checks", {}),
                               "version": ready.get("version")}
        tenant: dict[str, Any] = {}
        for key, fn in (("ioc_bundle", lambda: svc.ioc_status(tenant_id)),
                        ("topology", lambda: svc.topology_status(tenant_id)),
                        ("sources", lambda: [c.source_id for c in svc.list_sources(tenant_id)]),
                        ("quarantined", lambda: svc.quarantine.count(tenant_id)),
                        ("quarantine_reasons", lambda: svc.quarantine.reasons(tenant_id)),
                        ("bus_inflight", lambda: svc.bus.depth(tenant_id)),
                        ("live_enforcements", lambda: self._live_enforcements(tenant_id))):
            try:
                tenant[key] = fn()
            except Exception as exc:  # one missing gauge must not hide the others
                tenant[key] = None
                tenant.setdefault("unavailable", []).append(f"{key}:{type(exc).__name__}")
        out["tenant"] = tenant
        return out

    def _live_enforcements(self, tenant_id: str) -> int:
        """Live executions of *this tenant's* actions only.

        The executor is process-wide; its raw ``active()`` list (and the global bus depth)
        would disclose other tenants' activity, so each id is resolved through the
        tenant-scoped document store and foreign ids are dropped.
        """
        svc = self._svc
        return sum(1 for aid in svc.executor.active()
                   if svc.docs.get(ProposedAction, tenant_id, aid) is not None)

    def simulate(self, tenant_id: str, action: ProposedAction) -> MirrorResult:
        if action.tenant_id != tenant_id:
            raise InvalidQuery("action belongs to another scope")
        return self._guard(lambda: self._simulator(action))

    # ------------------------------------------------------------------ audit (engine only)

    def record_audit(self, tenant_id: str, subject_id: str, payload: dict[str, Any]) -> int | None:
        try:
            return self._svc.ledger.append(tenant_id, COPILOT_AUDIT_ENTRY, subject_id[:128], payload).seq
        except Exception as exc:
            log.error("copilot audit write failed: %s", type(exc).__name__)
            return None
