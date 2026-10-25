"""Model registry with a pre-registered promotion gate (spec sections 14 and 15).

Spec 15 requires that *model drift prevents silent promotion*; spec 14 sets the
release gate: a statistically supported improvement on at least one prioritized
metric without regression beyond predefined limits. This module implements both
as deterministic code. No language model and no agent can promote a model.

Lifecycle::

    register_artifact(dir) / register(model)  -> candidate
    evaluate(candidate, holdout, recent)      -> GateEvaluation (stored + ledgered)
    promote(candidate, evaluation, human)     -> champion (previous champion retired)

:class:`PromotionGate` is the pre-registered gate. Its checks:

* **integrity** - a candidate must come from a model artifact whose signed manifest
  verified against the trusted model keyring (``candidate_signature_unverified``)
  and must carry a complete model card (``model_card_incomplete``);
* **release metrics** - champion and candidate are scored on the *same* labelled,
  frozen holdout. The holdout must be large enough (``holdout_too_small``); the
  candidate may not lose recall (``recall_regression``), raise false alerts per 10k
  device-days (``false_alert_regression``) or exceed the calibration error limit
  (``calibration_error_exceeds_limit``) beyond the gate's limits, and it must show a
  statistically supported improvement on device-day PR-AUC, recall or false alerts
  (cluster-bootstrap CI clear of the champion's point estimate;
  ``no_statistically_supported_improvement``);
* **drift** - the candidate's calibrated score distribution on *recent production
  windows* is compared with its training reference (population stability index).
  The same is done for the champion, because a population that moved away from the
  champion's training data makes the holdout comparison unrepresentative.
  ``drift_detected:candidate_score_psi`` / ``drift_detected:champion_score_psi``, or
  ``drift_unknown:*`` when it cannot be measured (fail closed).

Drift checks are the only *acknowledgeable* failures: they block every automatic
promotion, and a human may promote despite them only by passing
``acknowledge_drift=True`` with a reason, as a different person than the one who
registered the candidate (four eyes). Every other failed check is a hard block.
Registration, evaluation, refusal and promotion are all written to the ledger
under the platform scope ``_platform`` (an id no tenant can have).
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict

from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.contracts.models import FeatureVector
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing
from aegis.sentinel.model import (
    ModelIntegrityError,
    TrainedModel,
    compute_metrics,
    load,
    resolve_labels,
)
from aegis.sentinel.model import Labels
from aegis.storage.db import DocStore

#: Ledger / document scope of the registry. Tenant ids must start with an alphanumeric
#: character, so this scope can never collide with a tenant.
REGISTRY_SCOPE = "_platform"
REQUIRED_CARD_KEYS = ("metrics", "intended_use", "limitations", "data", "split")

ModelStatus = Literal["candidate", "champion", "retired"]


class RegistryError(RuntimeError):
    """Invalid registry operation (unknown model, bad input)."""


class PromotionRefused(PermissionError):
    """A promotion was refused; ``failed`` lists the machine-readable reasons."""

    def __init__(self, message: str, failed: Sequence[str]):
        super().__init__(message)
        self.failed = list(failed)


def _is_human(actor: str) -> bool:
    a = (actor or "").strip().lower()
    return bool(a) and not a.startswith(("agent:", "system", "llm", "auto"))


# ----------------------------------------------------------------------------- gate


@dataclass(frozen=True)
class PromotionGate:
    """Pre-registered release gate. Change it only by issuing a new gate (new ``gate_id``)."""
    operating_point: str = "0.60"           # calibrated threshold whose metrics are compared
    max_score_psi: float = 0.25             # PSI above this is a significant population shift
    min_recent_windows: int = 200           # production windows needed to measure drift
    min_holdout_device_days: int = 100
    min_holdout_positive_device_days: int = 5
    max_recall_drop: float = 0.02           # absolute, device-day recall at the operating point
    max_false_alert_increase_per_10k: float = 0.0
    max_ece: float = 0.05
    require_signature: bool = True
    require_supported_improvement: bool = True
    max_evaluation_age: timedelta = timedelta(hours=24)
    bootstrap: int = 200

    @property
    def gate_id(self) -> str:
        body = {k: (v.total_seconds() if isinstance(v, timedelta) else v) for k, v in asdict(self).items()}
        return "gate-" + sha256_hex(body)[:16]

    def describe(self) -> dict[str, Any]:
        d = {k: (v.total_seconds() if isinstance(v, timedelta) else v) for k, v in asdict(self).items()}
        d["gate_id"] = self.gate_id
        return d


#: drift-related checks a human may explicitly acknowledge; everything else is a hard block
ACKNOWLEDGEABLE_PREFIXES = ("drift_detected:", "drift_unknown:")


def acknowledgeable(check: str) -> bool:
    return check.startswith(ACKNOWLEDGEABLE_PREFIXES)


# ----------------------------------------------------------------------------- records


class _Doc(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ModelRecord(_Doc):
    doc_id: str                              # = model_id
    tenant_id: str = REGISTRY_SCOPE
    model_id: str
    version: str
    calibration_id: str
    card_sha256: str
    artifact_dir: str | None = None
    signer_key_id: str | None = None
    signature_verified: bool = False
    status: ModelStatus = "candidate"
    registered_by: str
    registered_at: datetime
    promoted_by: str | None = None
    promoted_at: datetime | None = None
    promotion_reason: str | None = None
    promotion_evaluation_id: str | None = None
    drift_acknowledged: bool = False
    retired_at: datetime | None = None


class GateEvaluation(_Doc):
    doc_id: str                              # = evaluation_id
    tenant_id: str = REGISTRY_SCOPE
    evaluation_id: str
    model_id: str
    champion_id: str | None
    gate_id: str
    gate: dict[str, Any]
    evaluated_by: str
    evaluated_at: datetime
    passed: bool
    failed_checks: list[str]
    blocking_checks: list[str]               # failed checks that no acknowledgement can lift
    drift: dict[str, Any]
    holdout: dict[str, Any]
    holdout_sha256: str
    recent_sha256: str


# ----------------------------------------------------------------------------- registry


class ModelRegistry:
    """Platform model registry. Thread-safe; one per deployment."""

    def __init__(self, docstore: DocStore, ledger: Ledger, *, keyring: KeyRing | None = None,
                 gate: PromotionGate | None = None, clock: Callable[[], datetime] | None = None,
                 on_promote: Callable[[TrainedModel, ModelRecord], None] | None = None):
        self.docs = docstore
        self.ledger = ledger
        self.keyring = keyring
        self.gate = gate or PromotionGate()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.on_promote = on_promote
        self._models: dict[str, TrainedModel] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ queries
    def get(self, model_id: str) -> ModelRecord | None:
        return self.docs.get(ModelRecord, REGISTRY_SCOPE, model_id)

    def require(self, model_id: str) -> ModelRecord:
        rec = self.get(model_id)
        if rec is None:
            raise RegistryError(f"model {model_id!r} is not registered")
        return rec

    def records(self) -> list[ModelRecord]:
        return sorted(self.docs.iter_all(ModelRecord, REGISTRY_SCOPE), key=lambda r: (r.registered_at, r.model_id))

    def champion(self) -> ModelRecord | None:
        champs = [r for r in self.records() if r.status == "champion"]
        return champs[-1] if champs else None

    def evaluation(self, evaluation_id: str) -> GateEvaluation | None:
        return self.docs.get(GateEvaluation, REGISTRY_SCOPE, evaluation_id)

    def model(self, model_id: str) -> TrainedModel:
        """The registered model object (re-loaded and re-verified from its artifact if needed)."""
        with self._lock:
            m = self._models.get(model_id)
            if m is not None:
                return m
            rec = self.require(model_id)
            if not rec.artifact_dir:
                raise RegistryError(f"model {model_id!r} has no artifact to load")
            m = load(rec.artifact_dir, keyring=self.keyring, require_signature=rec.signature_verified)
            if m.model_id != model_id:
                raise ModelIntegrityError("artifact on disk no longer matches the registered model")
            self._models[model_id] = m
            return m

    def active_model(self) -> TrainedModel | None:
        champ = self.champion()
        return self.model(champ.model_id) if champ is not None else None

    def history(self) -> list[dict[str, Any]]:
        return [{"seq": e.seq, "entry_type": e.entry_type, "subject_id": e.subject_id,
                 "recorded_at": e.recorded_at, "payload": e.payload}
                for e in self.ledger.entries(REGISTRY_SCOPE)]

    # ------------------------------------------------------------------ registration
    def register_artifact(self, directory: str | Path, *, actor: str) -> ModelRecord:
        """Register a saved model directory. A signed manifest must verify against the
        registry keyring (a bad signature refuses registration outright)."""
        d = Path(directory)
        try:
            manifest = json.loads((d / "manifest.json").read_text())
        except (OSError, ValueError) as exc:
            raise RegistryError(f"cannot read model manifest in {d}: {exc}") from exc
        signed = isinstance(manifest.get("signature"), str)
        model = load(d, keyring=self.keyring, require_signature=False)  # raises on a bad signature
        verified = False
        if signed and self.keyring is not None:
            unsigned = {k: v for k, v in manifest.items() if k != "signature"}
            verified = self.keyring.verify(str(manifest.get("signer_key_id")), canonical_bytes(unsigned),
                                           manifest["signature"])
        return self._register(model, actor=actor, artifact_dir=str(d.resolve()),
                              signer_key_id=manifest.get("signer_key_id") if signed else None,
                              signature_verified=verified)

    def register(self, model: TrainedModel, *, actor: str) -> ModelRecord:
        """Register an in-memory model (no artifact: its signature cannot be verified)."""
        return self._register(model, actor=actor, artifact_dir=None, signer_key_id=None, signature_verified=False)

    def _register(self, model: TrainedModel, *, actor: str, artifact_dir: str | None, signer_key_id: str | None,
                  signature_verified: bool) -> ModelRecord:
        if not (actor or "").strip():
            raise RegistryError("an actor is required")
        with self._lock:
            existing = self.get(model.model_id)
            if existing is not None:
                self._models.setdefault(model.model_id, model)
                return existing
            now = self.clock()
            rec = ModelRecord(doc_id=model.model_id, model_id=model.model_id, version=model.version,
                              calibration_id=model.calibration_id, card_sha256=_card_digest(model.card),
                              artifact_dir=artifact_dir, signer_key_id=signer_key_id,
                              signature_verified=signature_verified, registered_by=actor.strip(),
                              registered_at=now)
            self.ledger.append(REGISTRY_SCOPE, EntryType.MODEL, model.model_id, {
                "event": "model_registered", "model_id": model.model_id, "model_version": model.version,
                "calibration_id": model.calibration_id, "card_sha256": rec.card_sha256,
                "signer_key_id": signer_key_id, "signature_verified": signature_verified, "actor": actor})
            self.docs.put(rec)
            self._models[model.model_id] = model
            return rec

    def bootstrap_champion(self, model_id: str, *, actor: str, reason: str) -> ModelRecord:
        """Install the first champion of an empty registry (deployment time, human only)."""
        if not (reason or "").strip():
            raise RegistryError("a reason is required")
        with self._lock:
            rec = self.require(model_id)
            if not _is_human(actor):
                self._refuse(model_id, actor, ["promotion_requires_human"], "bootstrap")
            if self.champion() is not None:
                self._refuse(model_id, actor, ["champion_exists"], "bootstrap")
            failed = [] if rec.signature_verified or not self.gate.require_signature else [
                "candidate_signature_unverified"]
            if failed:
                self._refuse(model_id, actor, failed, "bootstrap")
            return self._make_champion(rec, actor=actor, reason=reason, evaluation_id=None, ack=False)

    # ------------------------------------------------------------------ gate evaluation
    def evaluate(self, model_id: str, *, holdout_features: Sequence[FeatureVector], holdout_labels: Labels,
                 recent_features: Sequence[FeatureVector], actor: str) -> GateEvaluation:
        """Run the pre-registered gate for ``model_id`` against the current champion."""
        g = self.gate
        rec = self.require(model_id)
        candidate = self.model(model_id)
        champ_rec = self.champion()
        champion = self.model(champ_rec.model_id) if champ_rec is not None else None
        failed: list[str] = []

        if champ_rec is not None and champ_rec.model_id == model_id:
            failed.append("already_champion")
        if g.require_signature and not rec.signature_verified:
            failed.append("candidate_signature_unverified")
        if any(k not in candidate.card for k in REQUIRED_CARD_KEYS):
            failed.append("model_card_incomplete")

        # -- release metrics on one shared holdout
        feats = list(holdout_features)
        y_all = resolve_labels(feats, holdout_labels)
        idx = [i for i, y in enumerate(y_all) if y is not None]
        hf = [feats[i] for i in idx]
        hy = np.array([y_all[i] for i in idx], dtype=float)
        holdout: dict[str, Any] = {"windows": len(hf), "operating_point": g.operating_point}
        cand_m = compute_metrics(hf, hy, candidate.predict_many(hf), bootstrap=g.bootstrap) if hf else None
        champ_m = (compute_metrics(hf, hy, champion.predict_many(hf), bootstrap=g.bootstrap)
                   if hf and champion is not None else None)
        holdout["candidate"] = _clean(_summary(cand_m, g.operating_point))
        holdout["champion"] = _clean(_summary(champ_m, g.operating_point))
        cs = holdout["candidate"]
        if (cand_m is None or cs["device_days"] < g.min_holdout_device_days
                or cs["positive_device_days"] < g.min_holdout_positive_device_days):
            failed.append("holdout_too_small")
        else:
            if cs["ece"] is None or cs["ece"] > g.max_ece:
                failed.append("calibration_error_exceeds_limit")
            hs = holdout["champion"]
            if champ_m is not None:
                if cs["recall"] is None or (hs["recall"] is not None and cs["recall"] < hs["recall"] - g.max_recall_drop):
                    failed.append("recall_regression")
                if cs["false_alerts_per_10k"] > hs["false_alerts_per_10k"] + g.max_false_alert_increase_per_10k:
                    failed.append("false_alert_regression")
                improvements = _supported_improvements(cs, hs)
                holdout["supported_improvements"] = improvements
                if g.require_supported_improvement and not improvements:
                    failed.append("no_statistically_supported_improvement")

        # -- drift on recent production windows
        recent = list(recent_features)
        drift: dict[str, Any] = {"recent_windows": len(recent), "max_score_psi": g.max_score_psi}
        if len(recent) < g.min_recent_windows:
            failed.append("drift_unknown:insufficient_recent_windows")
        else:
            for role, m in (("candidate", candidate), ("champion", champion)):
                if m is None:
                    continue
                psi = m.population_stability(recent)
                if psi is None or not math.isfinite(psi):
                    drift[f"{role}_score_psi"] = None
                    failed.append(f"drift_unknown:{role}_score_reference")
                else:
                    drift[f"{role}_score_psi"] = round(float(psi), 6)
                    if psi > g.max_score_psi:
                        failed.append(f"drift_detected:{role}_score_psi")

        failed = list(dict.fromkeys(failed))
        now = self.clock()
        ev = GateEvaluation(
            doc_id="", evaluation_id="", model_id=model_id,
            champion_id=champ_rec.model_id if champ_rec else None, gate_id=g.gate_id, gate=g.describe(),
            evaluated_by=actor, evaluated_at=now, passed=not failed, failed_checks=failed,
            blocking_checks=[c for c in failed if not acknowledgeable(c)], drift=drift, holdout=holdout,
            holdout_sha256=_fv_digest(hf, hy), recent_sha256=_fv_digest(recent, None))
        eid = str(uuid.uuid4())
        ev = ev.model_copy(update={"doc_id": eid, "evaluation_id": eid})
        self.ledger.append(REGISTRY_SCOPE, "model_gate_evaluation", model_id, {
            "event": "gate_evaluated", "evaluation_id": eid, "model_id": model_id,
            "champion_id": ev.champion_id, "gate_id": g.gate_id, "passed": ev.passed,
            "failed_checks": failed, "drift": drift, "holdout": holdout,
            "holdout_sha256": ev.holdout_sha256, "recent_sha256": ev.recent_sha256, "actor": actor})
        self.docs.put(ev)
        return ev

    # ------------------------------------------------------------------ promotion
    def promote(self, model_id: str, *, evaluation_id: str, actor: str, reason: str,
                acknowledge_drift: bool = False) -> ModelRecord:
        """Promote a candidate. Refusals raise :class:`PromotionRefused` and are ledgered."""
        with self._lock:
            failed: list[str] = []
            if not _is_human(actor):
                failed.append("promotion_requires_human")
            if not (reason or "").strip():
                failed.append("reason_missing")
            rec = self.require(model_id)
            ev = self.evaluation(evaluation_id)
            champ = self.champion()
            if ev is None or ev.model_id != model_id:
                failed.append("evaluation_missing")
            else:
                if ev.gate_id != self.gate.gate_id:
                    failed.append("evaluation_gate_changed")
                if ev.champion_id != (champ.model_id if champ else None):
                    failed.append("champion_changed_since_evaluation")
                if self.clock() - ev.evaluated_at > self.gate.max_evaluation_age:
                    failed.append("evaluation_stale")
                failed += ev.blocking_checks
                drift_checks = [c for c in ev.failed_checks if acknowledgeable(c)]
                if drift_checks:
                    if not acknowledge_drift:
                        failed.append("drift_requires_acknowledged_human_promotion")
                    elif actor.strip() == rec.registered_by:
                        failed.append("drift_acknowledger_is_registrant")
            failed = list(dict.fromkeys(failed))
            if failed:
                self._refuse(model_id, actor, failed, "promote", evaluation_id=evaluation_id)
            assert ev is not None
            return self._make_champion(rec, actor=actor, reason=reason, evaluation_id=evaluation_id,
                                       ack=bool([c for c in ev.failed_checks if acknowledgeable(c)]))

    def _refuse(self, model_id: str, actor: str, failed: list[str], op: str, *,
                evaluation_id: str | None = None) -> None:
        self.ledger.append(REGISTRY_SCOPE, "model_promotion_refused", model_id, {
            "event": "promotion_refused", "operation": op, "model_id": model_id,
            "evaluation_id": evaluation_id, "actor": actor, "failed_checks": failed})
        raise PromotionRefused(f"promotion of {model_id} refused: {', '.join(failed)}", failed)

    def _make_champion(self, rec: ModelRecord, *, actor: str, reason: str, evaluation_id: str | None,
                       ack: bool) -> ModelRecord:
        model = self.model(rec.model_id)
        now = self.clock()
        previous = self.champion()
        self.ledger.append(REGISTRY_SCOPE, EntryType.MODEL, rec.model_id, {
            "event": "model_promoted", "model_id": rec.model_id, "model_version": rec.version,
            "previous_model_id": previous.model_id if previous else None, "evaluation_id": evaluation_id,
            "drift_acknowledged": ack, "actor": actor, "reason": reason.strip()[:2000]})
        if previous is not None and previous.model_id != rec.model_id:
            self.docs.put(previous.model_copy(update={"status": "retired", "retired_at": now}))
        champ = rec.model_copy(update={"status": "champion", "promoted_by": actor, "promoted_at": now,
                                       "promotion_reason": reason.strip()[:2000],
                                       "promotion_evaluation_id": evaluation_id, "drift_acknowledged": ack})
        self.docs.put(champ)
        if self.on_promote is not None:
            self.on_promote(model, champ)
        return champ


# ----------------------------------------------------------------------------- helpers


def _summary(m: Mapping[str, Any] | None, op: str) -> dict[str, Any]:
    if m is None:
        return {"device_days": 0, "positive_device_days": 0, "device_day_pr_auc": None, "recall": None,
                "false_alerts_per_10k": 0.0, "ece": None, "ci95": {}}
    point = m["operating_points"].get(op)
    if point is None:
        raise RegistryError(f"operating point {op} is not computed")
    ci = m.get("bootstrap_ci95", {})
    return {"device_days": m["device_days"], "positive_device_days": m["positive_device_days"],
            "device_day_pr_auc": m["device_day_pr_auc"], "recall": point["device_day"]["recall"],
            "precision": point["device_day"]["precision"],
            "false_alerts_per_10k": point["false_alerts_per_10k_device_days"], "ece": m["ece"],
            "ci95": {"device_day_pr_auc": ci.get("device_day_pr_auc"), "recall": ci.get(f"recall@{op}"),
                     "false_alerts_per_10k": ci.get(f"false_alerts_per_10k@{op}")}}


def _supported_improvements(cand: Mapping[str, Any], champ: Mapping[str, Any]) -> list[str]:
    """Metrics whose candidate 95% CI lies entirely on the better side of the champion's point estimate."""
    out: list[str] = []
    ci = cand["ci95"]
    pr = ci.get("device_day_pr_auc")
    if pr and champ["device_day_pr_auc"] is not None and pr[0] > champ["device_day_pr_auc"]:
        out.append("device_day_pr_auc")
    rc = ci.get("recall")
    if rc and champ["recall"] is not None and rc[0] > champ["recall"]:
        out.append("recall")
    fa = ci.get("false_alerts_per_10k")
    if fa and fa[1] < champ["false_alerts_per_10k"]:
        out.append("false_alerts_per_10k")
    return out


def _clean(obj: Any) -> Any:
    """JSON-safe copy: non-finite floats become None (canonical JSON has no NaN/Infinity)."""
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def _card_digest(card: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(card, sort_keys=True, default=str).encode()).hexdigest()


def _fv_digest(fvs: Sequence[FeatureVector], y: np.ndarray | None) -> str:
    rows = [[fv.entity_pseudonym, fv.window_end.isoformat()] for fv in fvs]
    return sha256_hex({"windows": rows, "labels": [] if y is None else [int(v) for v in y]})


__all__ = [
    "ACKNOWLEDGEABLE_PREFIXES", "GateEvaluation", "ModelRecord", "ModelRegistry", "PromotionGate",
    "PromotionRefused", "REGISTRY_SCOPE", "RegistryError", "acknowledgeable",
]
