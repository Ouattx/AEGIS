"""Facade wiring drafting, validation, backtesting and the registry (one call per analyst step).

``draft_from_case`` is the AI-assisted part: from one VERIFIED case it drafts rules
(LLM if configured, deterministic otherwise), validates each, stores the valid ones
as ``draft`` and backtests them automatically on every configured frozen dataset,
leaving them ``backtested`` and waiting for a human. Everything after that
(approval, shadow, promotion, retirement) is an explicit human step on the registry.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import AbstractSet, Any, Callable, Iterable, Mapping, Sequence

from aegis.contracts.models import FeatureVector
from aegis.detengine.backtest import BacktestConfig, BacktestDataset, Backtester, DeviceDay, RuleBacktestReport
from aegis.detengine.drafting import CaseMaterial, RuleDrafter, check_material
from aegis.detengine.engine import RuleEngine
from aegis.detengine.registry import RuleRecord, RuleRegistry
from aegis.detengine.validation import HostingContext, RuleValidationError, validate_rule
from aegis.provenance.evidence import EvidenceStore

BACKTEST_ACTOR = "system:detengine-backtest"

#: dataset name -> existing detector name -> device-days it alerted on
ExistingAlerts = Mapping[str, Mapping[str, AbstractSet[DeviceDay]]]


@dataclass
class DraftOutcome:
    case_id: str
    records: list[RuleRecord] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    backtests: dict[str, list[RuleBacktestReport]] = field(default_factory=dict)
    llm_used: bool = False
    llm_status: str = "not_configured"
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"case_id": self.case_id, "llm_used": self.llm_used, "llm_status": self.llm_status,
                "rules": [{"rule_ref": r.ref, "state": r.state.value, "drafted_by": r.drafted_by,
                           "spec": r.spec, "validation": r.validation,
                           "backtests": [b.summary() for b in self.backtests.get(r.ref, [])]} for r in self.records],
                "rejected": self.rejected, "notes": self.notes}


class DetectionEngineering:
    """Detection-engineering workflow for one deployment (all methods tenant-scoped)."""

    def __init__(self, registry: RuleRegistry, *, drafter: RuleDrafter | None = None,
                 backtester: Backtester | None = None, datasets: Sequence[BacktestDataset] = (),
                 backtest_config: BacktestConfig | None = None, clock: Callable[[], datetime] | None = None):
        self.registry = registry
        self.drafter = drafter or RuleDrafter()
        self.backtester = backtester or Backtester(clock=clock or registry.clock)
        self.datasets = list(datasets)
        self.backtest_config = backtest_config or BacktestConfig()

    def reference_windows(self) -> list[FeatureVector]:
        """Unlabelled population windows before the time-forward split of the first dataset."""
        if not self.datasets:
            return []
        ds = self.datasets[0]
        return ds.reference_windows(self.backtest_config.split_at or ds.default_split())

    def _run_backtests(self, tenant_id: str, rec: RuleRecord, exclude: frozenset[str],
                       existing: ExistingAlerts | None, actor: str) -> list[RuleBacktestReport]:
        cfg = replace(self.backtest_config, exclude_entities=self.backtest_config.exclude_entities | exclude)
        spec = rec.rule_spec()
        return [self.backtester.run(spec, ds, tenant_id=tenant_id, actor=actor, config=cfg, rule_ref=rec.ref,
                                    existing=(existing or {}).get(ds.name)) for ds in self.datasets]

    def draft_from_case(self, tenant_id: str, material: CaseMaterial, *, hosting: HostingContext | None = None,
                        allowlist: Iterable[str] = (), existing: ExistingAlerts | None = None,
                        reference: Sequence[FeatureVector] | None = None) -> DraftOutcome:
        """Draft, validate, store and automatically backtest rules from one verified case."""
        if material.tenant_id != tenant_id:
            raise ValueError("case belongs to another tenant")
        check_material(material)
        allow = list(allowlist)
        ref = list(reference) if reference is not None else self.reference_windows()
        batch = self.drafter.draft(material, ref, hosting=hosting)
        out = DraftOutcome(case_id=material.case.case_id, rejected=list(batch.rejected), llm_used=batch.llm_used,
                           llm_status=batch.llm_status)
        if not self.datasets:
            out.notes.append("no frozen datasets configured: drafts stay in 'draft' and cannot be approved")
        exclude = frozenset(material.entities())
        for p in batch.proposals:
            result = validate_rule(p.spec, hosting=hosting, allowlist=allow)
            if not result.ok:
                out.rejected.append({"source": p.actor, "rule_id": p.spec.rule_id, "errors": list(result.errors)})
                continue
            try:
                rec = self.registry.submit_draft(
                    tenant_id, p.spec, actor=p.actor, drafter_kind=p.drafter_kind,
                    source_case_ids=[p.case_id], source_evidence_ids=list(p.evidence_ids), hosting=hosting,
                    allowlist=allow)
            except RuleValidationError as exc:
                out.rejected.append({"source": p.actor, "rule_id": p.spec.rule_id, "errors": exc.errors})
                continue
            if self.datasets and rec.state.value in ("draft", "backtested"):
                reports = self._run_backtests(tenant_id, rec, exclude, existing, BACKTEST_ACTOR)
                rec = self.registry.record_backtests(tenant_id, rec.ref, reports, actor=BACKTEST_ACTOR)
                out.backtests[rec.ref] = reports
            out.records.append(rec)
        return out

    def rebacktest(self, tenant_id: str, ref: str, *, existing: ExistingAlerts | None = None,
                   actor: str = BACKTEST_ACTOR) -> RuleRecord:
        """Re-run the backtests of a draft/backtested rule (e.g. after new frozen datasets were added)."""
        if not self.datasets:
            raise ValueError("no frozen datasets configured")
        rec = self.registry.require(tenant_id, ref)
        exclude: frozenset[str] = frozenset()
        reports = self._run_backtests(tenant_id, rec, exclude, existing, actor)
        return self.registry.record_backtests(tenant_id, ref, reports, actor=actor)

    def engine(self, tenant_id: str, *, evidence_store: EvidenceStore | None = None,
               hosting: HostingContext | None = None, allowlist: Iterable[str] = (),
               clock: Callable[[], datetime] | None = None) -> RuleEngine:
        """Engine over the tenant's verified shadow + promoted rules."""
        return self.registry.active_rules(tenant_id, evidence_store=evidence_store, hosting=hosting,
                                          allowlist=allowlist, clock=clock)


__all__ = ["BACKTEST_ACTOR", "DetectionEngineering", "DraftOutcome", "ExistingAlerts"]
