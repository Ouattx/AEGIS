# aegis.assurance: integration guide

Model assurance for SENTINEL. Pure library: no I/O besides `save`/`load`, no LLM,
no network. Nothing here changes policy, models or enforcement; outputs are advisory
and can only route work to a human. Not yet wired into `aegis/service.py`, the API,
the web console or the CLI; this file lists the exact calls to wire it.

## Components

| Module | Public API | Purpose |
|---|---|---|
| `conformal` | `MondrianConformal.fit / fit_model / predict / predict_many / coverage_report / to_dict / from_dict` | Label- and device-class-conditional split conformal sets over calibrated scores; outcome `benign` / `malicious` / `ambiguous` / `empty` (the last two abstain) |
| `novelty` | `NoveltyDetector.fit / score / score_many / novelty_rate / threshold / to_dict / from_dict` | Distance to the training manifold (entity-split kNN, conformal p-value). Behavior never seen before is `novel` |
| `drift` | `DriftReference.build / from_model`, `DriftMonitor(reference, DriftThresholds()).evaluate(fvs, scores=, labels=) -> DriftReport`, `psi` | Feature PSI / KS / missingness, score PSI / KS, calibration ECE drift |
| `gate` | `AssuranceGate(config).evaluate(PromotionInputs) / evaluate_models(...) -> GateDecision`, `PromotionBlocked`, `acknowledgeable` | Blocks promotion on regression, broken coverage, artifact mismatch; drift is blocking but acknowledgeable |
| `explain` | `Explainer(model, FeatureProfile).attributions / attributions_many / reasons / counterfactual`, `FeatureProfile.build` | TreeSHAP (LightGBM `pred_contrib`) merged per feature, top-k sentences, bounded counterfactuals over actionable features |
| `display` | `display_score(score, calibration_id) -> ScoreDisplay`, `format_score` | Never show exactly 1 or 0 (`>0.99` / `<0.01`); state the calibration id; uncalibrated scores are not called probabilities |
| `assess` | `ModelAssurance.build / assess / assess_many / assess_finding / save / load / describe`, `AssuranceReport` | Facade bound to one model (`model_id` + `calibration_id`), signed JSON artifacts |

## 1. Build the assurance artifact (offline, next to model training)

In `aegis/sentinel/training.py` main (or an `aegis assurance build` CLI command):

```python
from aegis.assurance import ModelAssurance
from aegis.sentinel.training import build_lab_dataset

train_ds = build_lab_dataset(seeds)                    # the model's training population
cal_ds = build_lab_dataset([CAL_SEED])                 # labelled windows NOT used for training
assurance = ModelAssurance.build(
    model,
    calibration=cal_ds.features, calibration_labels=cal_ds.labels,   # conformal calibration
    reference=train_ds.features, reference_labels=train_ds.labels,   # novelty, drift, benign profile
    alpha=0.05, novelty_alpha=0.01,
)
assurance.save("models/sentinel-default/assurance", signer=model_signer)
```

The calibration windows must be disjoint from the training windows, otherwise the
coverage guarantee does not hold. Record the artifact in the platform ledger:
`ledger.append("_platform", ENTRY_TYPE_ASSURANCE, assurance.assurance_id, assurance.describe())`.

## 2. Load at service start (`aegis/service.py`, after `_load_model`)

```python
from aegis.assurance import AssuranceIntegrityError, AssuranceMismatch, ModelAssurance
try:
    self.assurance = ModelAssurance.load(model_dir / "assurance", self.model,
                                         keyring=self.ledger_keyring,
                                         require_signature=self.settings.model_require_signature)
except (FileNotFoundError, AssuranceIntegrityError, AssuranceMismatch) as exc:
    log.error("model assurance not loaded (%s): findings carry no assurance block", exc)
    self.assurance = None
```

`load` refuses an artifact built for another model or calibration (fail closed).
Rebuild assurance whenever a new model is promoted (`ModelRegistry.on_promote`).

## 3. Per finding (SENTINEL output -> evidence)

The window behind a finding is `Decision.fv` (`aegis/sentinel/detector.py`: `Sentinel.evaluate(fvs)
-> list[Decision]`, and `Sentinel._emit(d: Decision) -> Finding` builds the finding). The simplest
wiring is an optional `on_finding(finding, decision)` callback in `Sentinel._emit`, or calling the
assurance from `_handle` right after `_emit`. For an emitted finding:

```python
report = service.assurance.assess_finding(finding, decision.fv)   # AssuranceReport
evidence = Evidence(tenant_id=finding.tenant_id, kind=EvidenceKind.MODEL_SCORE,
                    origin_source="model:" + report.model_id,
                    source_independence_group="model:" + report.model_id,
                    collected_at=finding.created_at, summary=report.summary(),
                    payload=report.evidence_payload(), authorization_id=...)
evidence_store.append(evidence)        # hash + ledger entry; cite evidence.evidence_id on the finding
```

Routing rule (advisory, can only add caution, never escalate):
- `report.outcome in ("abstain", "novel")` -> keep `requires_review=True`, surface in the
  triage queue as "uncertain" / "novel behavior"; never upgrade a fusion verdict because of it.
- `report.outcome == "malicious"` does not by itself create or escalate a finding; the
  fusion policy and case state machine still decide.

## 4. API (`aegis/api/routes.py`)

- `GET /api/v1/findings/{id}/assurance` -> `AssuranceReport.model_dump(mode="json")`
  (tenant-scoped like every read; recompute from the stored window, or store the evidence payload).
- `GET /api/v1/models/assurance` (admin) -> `assurance.describe()` + latest `DriftReport.to_dict()`.
- Every place that renders `Finding.score` should use `format_score(score, calibration_id)`.

## 5. Web console

Show `report.score_display` verbatim (never format the float yourself), `report.reasons[*].text`,
the conformal outcome and `report.counterfactual.text` with its caveat
("model-level what-if; not evidence and not a remediation instruction").

## 6. Drift monitoring (scheduled job, per tenant)

```python
from aegis.assurance import DriftMonitor
rep = DriftMonitor(service.assurance.drift_reference).evaluate(
    recent_windows, scores=model.predict_many(recent_windows), labels=confirmed_labels_or_None)
if rep.status == "alert":
    ledger.append(tenant_id, ENTRY_TYPE_ASSURANCE, "drift", rep.to_dict())   # plus metrics/alerting
nov = service.assurance.novelty.novelty_rate(recent_windows)
```

## 7. Promotion (`ModelRegistry.promote` path)

Run the assurance gate in addition to the registry's own gate, before `promote`:

```python
from aegis.assurance import AssuranceGate
decision = AssuranceGate().evaluate_models(candidate, champion, holdout_fvs, holdout_labels, recent_fvs,
                                           reference=candidate_assurance.drift_reference,
                                           conformal=candidate_assurance.conformal,
                                           novelty=candidate_assurance.novelty)
ledger.append("_platform", ENTRY_TYPE_ASSURANCE, candidate.model_id, decision.to_dict())
decision.raise_if_blocked(acknowledge_drift=acknowledge_drift)   # PromotionBlocked(failed=[...])
```

Failed checks use the registry's convention: `drift_detected:*` / `drift_unknown:*` are the
only acknowledgeable ones (second human via `acknowledge_drift`), everything else is a hard block.

## Dependencies

numpy, scipy (KS test), lightgbm (TreeSHAP via `pred_contrib`), pydantic: all already
required by the repository. No new dependency.
