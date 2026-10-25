"""Execution engine: evaluates active rules on feature vectors and emits findings.

Only rules in the registry states ``shadow`` and ``promoted`` run (see
:meth:`aegis.detengine.registry.RuleRegistry.active_rules`, which also verifies each
rule's integrity before loading it).

* A **promoted** rule emits ordinary :class:`Finding` objects (verdict
  ``suspicious``, always ``requires_review``; the score is a fixed, *uncalibrated*
  severity weight, ``calibration_id`` is ``None``). With an evidence store, the
  supporting evidence is persisted and the finding is written to the ledger.
* A **shadow** rule emits *shadow findings* only: they are stored as
  :class:`RuleShadowFinding` documents (never as ``Finding`` documents, so they
  cannot open cases or reach enforcement) and ledgered as ``detection_rule_shadow``.

Rule evidence re-reads the operator's telemetry; it is therefore filed under the
same independence group as the sentinel's own telemetry evidence and can never act
as a second, independent witness for case verification.

Every finding carries the rule id and version in ``detector_version``
(``detengine:<rule_id>@v<version>``, suffixed ``+shadow`` for shadow findings) and
in its evidence payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Literal, Sequence

from pydantic import BaseModel, ConfigDict

from aegis.contracts.models import Evidence, EvidenceKind, FeatureVector, Finding, Verdict
from aegis.detengine.language import Contacts, RuleEvaluation, RuleSpec, evaluate_rule
from aegis.provenance.evidence import EvidenceStore, evidence_hash
from aegis.provenance.ledger import EntryType
from aegis.sentinel.features import WINDOW_SECONDS, ContactSummary
from aegis.storage.db import DocStore

#: same independence group as sentinel telemetry evidence (rules are not independent witnesses)
TELEMETRY_GROUP = "operator-telemetry"
SHADOW_ENTRY = "detection_rule_shadow"
SEVERITY_SCORE = {"low": 0.4, "medium": 0.6, "high": 0.8}
DEFAULT_FINDING_TTL = timedelta(hours=72)

RuleMode = Literal["shadow", "promoted"]


def rule_ref(rule_id: str, version: int) -> str:
    return f"{rule_id}@v{version}"


@dataclass(frozen=True)
class ActiveRule:
    """A rule version loaded for execution."""
    rule_id: str
    version: int
    spec: RuleSpec
    mode: RuleMode
    spec_sha256: str

    @property
    def ref(self) -> str:
        return rule_ref(self.rule_id, self.version)

    @property
    def detector_version(self) -> str:
        return f"detengine:{self.ref}" + ("+shadow" if self.mode == "shadow" else "")


@dataclass(frozen=True)
class RuleMatch:
    """A rule that fired or abstained on one window."""
    rule: ActiveRule
    fv: FeatureVector
    evaluation: RuleEvaluation
    contacts: Contacts | None


class RuleShadowFinding(BaseModel):
    """A shadow finding, kept apart from production findings (DocStore kind ``RuleShadowFinding``)."""
    model_config = ConfigDict(extra="forbid")
    doc_id: str                  # = finding id
    tenant_id: str
    rule_ref: str
    rule_id: str
    version: int
    spec_sha256: str
    finding: dict[str, Any]
    evidence: list[dict[str, Any]]
    recorded_at: datetime


@dataclass
class EngineResult:
    findings: list[Finding] = field(default_factory=list)
    shadow_findings: list[Finding] = field(default_factory=list)
    abstentions: list[RuleMatch] = field(default_factory=list)
    matches: list[RuleMatch] = field(default_factory=list)

    def extend(self, other: "EngineResult") -> None:
        self.findings.extend(other.findings)
        self.shadow_findings.extend(other.shadow_findings)
        self.abstentions.extend(other.abstentions)
        self.matches.extend(other.matches)


@dataclass(frozen=True)
class RejectedRule:
    """A rule the registry refused to load (integrity failure)."""
    ref: str
    reasons: tuple[str, ...]


class RuleEngine:
    """Evaluates a tenant's active rules. Never consults a language model."""

    def __init__(self, tenant_id: str, rules: Sequence[ActiveRule], *, evidence_store: EvidenceStore | None = None,
                 docstore: DocStore | None = None, clock: Callable[[], datetime] | None = None,
                 finding_ttl: timedelta = DEFAULT_FINDING_TTL, rejected: Sequence[RejectedRule] = ()):
        refs = [r.ref for r in rules]
        if len(set(refs)) != len(refs):
            raise ValueError("duplicate rule version in engine")
        self.tenant_id = tenant_id
        self.rules = tuple(sorted(rules, key=lambda r: r.ref))
        self.evidence_store = evidence_store
        self.docstore = docstore
        self.clock = clock
        self.finding_ttl = finding_ttl
        self.rejected = tuple(rejected)

    @property
    def promoted(self) -> tuple[ActiveRule, ...]:
        return tuple(r for r in self.rules if r.mode == "promoted")

    @property
    def shadow(self) -> tuple[ActiveRule, ...]:
        return tuple(r for r in self.rules if r.mode == "shadow")

    def versions(self) -> dict[str, str]:
        return {r.ref: r.spec_sha256 for r in self.rules}

    # ------------------------------------------------------------------ evaluation
    def evaluate(self, fv: FeatureVector, contacts: Contacts | ContactSummary | None = None) -> list[RuleMatch]:
        """Rules that fired or abstained on ``fv`` (pure; nothing is emitted or stored)."""
        if fv.tenant_id != self.tenant_id:
            raise ValueError("feature vector belongs to another tenant")
        c = Contacts.coerce(contacts)
        out: list[RuleMatch] = []
        for rule in self.rules:
            ev = evaluate_rule(rule.spec, fv, c)
            if ev.outcome in ("fired", "abstain"):
                out.append(RuleMatch(rule, fv, ev, c))
        return out

    def process(self, fv: FeatureVector, contacts: Contacts | ContactSummary | None = None) -> EngineResult:
        """Evaluate and emit findings (persisted when stores are configured)."""
        res = EngineResult()
        for m in self.evaluate(fv, contacts):
            res.matches.append(m)
            if m.evaluation.outcome == "abstain":
                res.abstentions.append(m)
                continue
            if m.rule.mode == "promoted":
                res.findings.append(self._emit(m))
            else:
                res.shadow_findings.append(self._emit(m))
        return res

    def process_many(self, items: Iterable[tuple[FeatureVector, Contacts | ContactSummary | None]]) -> EngineResult:
        out = EngineResult()
        for fv, c in items:
            out.extend(self.process(fv, c))
        return out

    # ------------------------------------------------------------------ emission
    def _now(self, fv: FeatureVector) -> datetime:
        now = self.clock() if self.clock is not None else fv.window_end
        if now.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return now.astimezone(timezone.utc)

    def _emit(self, m: RuleMatch) -> Finding:
        fv, rule, ev = m.fv, m.rule, m.evaluation
        now = self._now(fv)
        shadow = rule.mode == "shadow"
        window_start = fv.window_end - timedelta(seconds=WINDOW_SECONDS[fv.window])
        auth = sorted(m.contacts.authorization_ids)[0] if m.contacts and m.contacts.authorization_ids else "unknown"
        payload = {
            "entity_pseudonym": fv.entity_pseudonym, "device_class": fv.device_class, "window": fv.window,
            "window_start": window_start.isoformat(), "window_end": fv.window_end.isoformat(),
            "rule_id": rule.rule_id, "rule_version": rule.version, "rule_ref": rule.ref,
            "spec_sha256": rule.spec_sha256, "rule_bundle_version": f"detengine:{rule.ref}",
            "mode": rule.mode, "shadow": shadow, "label": rule.spec.label,
            "satisfied": list(ev.satisfied), "matched_destinations": list(ev.matched_destinations),
            "features": {k: v for k, v in ev.observed.items()},
            "source_ids": sorted(m.contacts.source_ids) if m.contacts else [],
        }
        evidence = Evidence(
            tenant_id=fv.tenant_id, kind=EvidenceKind.OBSERVATION, origin_source=f"aegis:detengine/{rule.ref}",
            source_independence_group=TELEMETRY_GROUP, collected_at=now, authorization_id=auth, payload=payload,
            summary=(f"{'shadow ' if shadow else ''}rule {rule.ref} ({rule.spec.title}) matched "
                     f"{fv.entity_pseudonym} in the {fv.window} window ending {fv.window_end.isoformat()}: "
                     + "; ".join(ev.satisfied[:6])))
        score = SEVERITY_SCORE[rule.spec.severity]
        explanation = (f"Detection rule {rule.ref} '{rule.spec.title}'"
                       f"{' (SHADOW: not acted on)' if shadow else ''} matched: " + "; ".join(ev.satisfied)
                       + (f". Destinations: {', '.join(ev.matched_destinations)}" if ev.matched_destinations else "")
                       + ". Score is a fixed severity weight, not a probability. Requires analyst review.")
        finding = Finding(
            tenant_id=fv.tenant_id, entity_pseudonym=fv.entity_pseudonym, device_class=fv.device_class,
            detector_version=rule.detector_version, label=rule.spec.label, verdict=Verdict.SUSPICIOUS, score=score,
            calibration_id=None, component_scores={f"rule:{rule.ref}": score},
            observed_window_start=window_start, observed_window_end=fv.window_end,
            evidence_ids=[evidence.evidence_id], requires_review=True, explanation=explanation,
            created_at=now, expires_at=now + self.finding_ttl)
        if shadow:
            self._persist_shadow(rule, finding, evidence, now)
        elif self.evidence_store is not None:
            self.evidence_store.append(evidence)
            self.evidence_store.ledger.append(fv.tenant_id, EntryType.FINDING, finding.finding_id, {
                "finding_id": finding.finding_id, "entity_pseudonym": finding.entity_pseudonym,
                "label": finding.label, "verdict": finding.verdict.value, "score": finding.score,
                "calibration_id": None, "detector_version": finding.detector_version,
                "rule_bundle_version": f"detengine:{rule.ref}", "spec_sha256": rule.spec_sha256,
                "evidence_ids": finding.evidence_ids, "observed_window_end": finding.observed_window_end,
            })
        return finding

    def _persist_shadow(self, rule: ActiveRule, finding: Finding, evidence: Evidence, now: datetime) -> None:
        if self.docstore is None and self.evidence_store is None:
            return
        sealed = evidence.model_copy(update={"sha256": evidence_hash(evidence)})
        if self.evidence_store is not None:
            self.evidence_store.ledger.append(finding.tenant_id, SHADOW_ENTRY, finding.finding_id, {
                "finding_id": finding.finding_id, "entity_pseudonym": finding.entity_pseudonym,
                "label": finding.label, "detector_version": finding.detector_version, "shadow": True,
                "rule_bundle_version": f"detengine:{rule.ref}", "spec_sha256": rule.spec_sha256,
                "evidence_sha256": sealed.sha256, "observed_window_end": finding.observed_window_end,
            })
        if self.docstore is not None:
            self.docstore.put(RuleShadowFinding(
                doc_id=finding.finding_id, tenant_id=finding.tenant_id, rule_ref=rule.ref, rule_id=rule.rule_id,
                version=rule.version, spec_sha256=rule.spec_sha256, finding=finding.model_dump(mode="json"),
                evidence=[sealed.model_dump(mode="json")], recorded_at=now))


__all__ = [
    "ActiveRule", "DEFAULT_FINDING_TTL", "EngineResult", "RejectedRule", "RuleEngine", "RuleMatch", "RuleMode",
    "SEVERITY_SCORE", "SHADOW_ENTRY", "RuleShadowFinding", "TELEMETRY_GROUP", "rule_ref",
]
