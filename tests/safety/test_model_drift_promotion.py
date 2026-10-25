"""Spec section 15: model drift prevents silent promotion (and the spec 14 release gate).

Real models only: a champion trained on lab corpora, the shipped default model as
the candidate (both saved as signed artifacts), a labelled holdout corpus the gate
scores both on, and recent production windows that are either representative or
drifted (a corpus with a very different infection prevalence). The registry is
wired to a running :class:`AegisService`, whose detection model must change only
after a gated, human promotion.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import pytest

from aegis.contracts.models import FeatureVector
from aegis.lab.corpus import generate_corpus
from aegis.provenance.ledger import EntryType
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.model import ModelIntegrityError, TrainedModel, load_default, train
from aegis.sentinel.registry import REGISTRY_SCOPE, ModelRegistry, PromotionGate, PromotionRefused
from aegis.sentinel.training import build_lab_dataset, extract_windows, lab_window_labels
from aegis.service import AegisService

from safety_kit import build_service

pytestmark = pytest.mark.safety

RELEASE_MANAGER = "ml.release-manager"
REVIEWER = "secops.reviewer"


@dataclass
class Models:
    champion_dir: Path
    candidate_dir: Path
    champion: TrainedModel
    candidate: TrainedModel
    signer: Signer
    holdout: list[FeatureVector]
    holdout_labels: list[int | None]
    recent_normal: list[FeatureVector]
    recent_drifted: list[FeatureVector]


@pytest.fixture(scope="module")
def models(tmp_path_factory: pytest.TempPathFactory) -> Models:
    tmp = tmp_path_factory.mktemp("models")
    signer = Signer.generate("model-release-key")
    ds = build_lab_dataset((111, 222), n_devices=(60, 50), days=2, malicious_fraction=0.2)
    champion = train(ds.features, ds.labels, 7, groups=ds.groups, dataset_info=ds.info, version="pilot-0.9",
                     rounds=150)
    candidate = load_default()
    champion.save(tmp / "champion", signer=signer)
    candidate.save(tmp / "candidate", signer=signer)
    hold = generate_corpus(seed=333, days=2, n_devices=50, malicious_fraction=0.12, tenant_id="holdout")
    holdout = extract_windows(hold.events, flush_at=hold.end)
    drift = generate_corpus(seed=444, days=2, n_devices=20, malicious_fraction=0.6, tenant_id="drifted")
    return Models(champion_dir=tmp / "champion", candidate_dir=tmp / "candidate", champion=champion,
                  candidate=candidate, signer=signer, holdout=holdout,
                  holdout_labels=lab_window_labels(hold, holdout), recent_normal=holdout,
                  recent_drifted=extract_windows(drift.events, flush_at=drift.end))


@dataclass
class Deployment:
    svc: AegisService
    registry: ModelRegistry
    champion_id: str
    candidate_id: str


@pytest.fixture()
def deployment(tmp_path: Path, models: Models) -> Iterator[Deployment]:
    svc, _ = build_service(tmp_path)
    ring = KeyRing()
    ring.add_signer(models.signer)
    registry = ModelRegistry(svc.docs, svc.ledger, keyring=ring, clock=svc.clock,
                             on_promote=lambda m, rec: svc.activate_model(
                                 m, actor=rec.promoted_by or "unknown", reason=rec.promotion_reason or "promotion"))
    svc.ledger.append("pilot-isp", "configuration", "tenant", {"event": "tenant_created"})  # a tenant to notify
    champ = registry.register_artifact(models.champion_dir, actor=RELEASE_MANAGER)
    cand = registry.register_artifact(models.candidate_dir, actor=RELEASE_MANAGER)
    assert champ.signature_verified and cand.signature_verified
    registry.bootstrap_champion(champ.model_id, actor="ops.installer", reason="pilot installation")
    assert svc.model is not None and svc.model.model_id == champ.model_id
    yield Deployment(svc=svc, registry=registry, champion_id=champ.model_id, candidate_id=cand.model_id)
    svc.close()


def _refusals(d: Deployment) -> list[dict[str, object]]:
    return [e.payload for e in d.svc.ledger.entries(REGISTRY_SCOPE, entry_type="model_promotion_refused")]


def test_model_drift_prevents_silent_promotion(deployment: Deployment, models: Models) -> None:
    d = deployment
    ev = d.registry.evaluate(d.candidate_id, holdout_features=models.holdout, holdout_labels=models.holdout_labels,
                             recent_features=models.recent_drifted, actor="system:nightly-retrain")
    assert not ev.passed
    assert "drift_detected:candidate_score_psi" in ev.failed_checks
    assert ev.drift["candidate_score_psi"] > PromotionGate().max_score_psi
    assert ev.blocking_checks == []  # the candidate is better on the holdout: only drift stops it

    attempts = [("system:nightly-retrain", False, "promotion_requires_human"),
                ("agent:response_planner", True, "promotion_requires_human"),
                (REVIEWER, False, "drift_requires_acknowledged_human_promotion"),
                (RELEASE_MANAGER, True, "drift_acknowledger_is_registrant")]
    for actor, ack, reason in attempts:
        with pytest.raises(PromotionRefused) as pi:
            d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor=actor,
                               reason="better holdout metrics", acknowledge_drift=ack)
        assert reason in pi.value.failed
        assert d.svc.model is not None and d.svc.model.model_id == d.champion_id  # nothing changed
        assert d.registry.champion().model_id == d.champion_id  # type: ignore[union-attr]
    assert len(_refusals(d)) == len(attempts)
    assert d.champion_id in d.svc.detector_version("pilot-isp")

    # only an explicit, acknowledged promotion by a second human goes through - and it is loud
    rec = d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor=REVIEWER,
                             reason="drift reviewed: prevalence shift from new campaign; holdout gain verified",
                             acknowledge_drift=True)
    assert rec.status == "champion" and rec.drift_acknowledged
    assert d.svc.model is not None and d.svc.model.model_id == d.candidate_id
    promoted = [e.payload for e in d.svc.ledger.entries(REGISTRY_SCOPE, entry_type=EntryType.MODEL)
                if e.payload.get("event") == "model_promoted" and e.payload["model_id"] == d.candidate_id]
    assert promoted and promoted[-1]["drift_acknowledged"] is True and promoted[-1]["actor"] == REVIEWER
    activated = [e.payload for e in d.svc.ledger.entries("pilot-isp", entry_type=EntryType.MODEL)]
    assert activated[-1]["model_id"] == d.candidate_id and activated[-1]["previous_model_id"] == d.champion_id
    assert d.registry.get(d.champion_id).status == "retired"  # type: ignore[union-attr]
    assert d.svc.verify_ledger(REGISTRY_SCOPE)["ok"] is True


def test_gate_passes_supported_improvement_without_drift(deployment: Deployment, models: Models) -> None:
    d = deployment
    ev = d.registry.evaluate(d.candidate_id, holdout_features=models.holdout, holdout_labels=models.holdout_labels,
                             recent_features=models.recent_normal, actor=RELEASE_MANAGER)
    assert ev.passed, ev.failed_checks
    assert ev.drift["candidate_score_psi"] <= PromotionGate().max_score_psi
    assert ev.holdout["supported_improvements"]
    cand, champ = ev.holdout["candidate"], ev.holdout["champion"]
    assert cand["false_alerts_per_10k"] <= champ["false_alerts_per_10k"] and cand["recall"] >= champ["recall"]
    with pytest.raises(PromotionRefused) as pi:  # even a passing gate never promotes automatically
        d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor="system:ci", reason="green")
    assert pi.value.failed == ["promotion_requires_human"]
    rec = d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor=RELEASE_MANAGER,
                             reason="release gate passed")
    assert rec.status == "champion" and not rec.drift_acknowledged
    assert d.svc.model is not None and d.svc.model.model_id == d.candidate_id
    # an evaluation is bound to the champion it was run against
    with pytest.raises(PromotionRefused) as pi:
        d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor=REVIEWER, reason="again")
    assert "champion_changed_since_evaluation" in pi.value.failed


def test_gate_blocks_regression_unsigned_and_tampered_models(deployment: Deployment, models: Models,
                                                             tmp_path: Path) -> None:
    d = deployment
    # promote the stronger model first, then try to "promote" the weaker one back over it
    ev = d.registry.evaluate(d.candidate_id, holdout_features=models.holdout, holdout_labels=models.holdout_labels,
                             recent_features=models.recent_normal, actor=RELEASE_MANAGER)
    d.registry.promote(d.candidate_id, evaluation_id=ev.evaluation_id, actor=RELEASE_MANAGER, reason="upgrade")
    back = d.registry.evaluate(d.champion_id, holdout_features=models.holdout,
                               holdout_labels=models.holdout_labels, recent_features=models.recent_normal,
                               actor=RELEASE_MANAGER)
    assert not back.passed and back.blocking_checks
    assert {"no_statistically_supported_improvement", "false_alert_regression",
            "recall_regression"} & set(back.blocking_checks)
    with pytest.raises(PromotionRefused):  # hard blocks cannot be acknowledged away
        d.registry.promote(d.champion_id, evaluation_id=back.evaluation_id, actor=REVIEWER, reason="rollback model",
                           acknowledge_drift=True)
    assert d.svc.model is not None and d.svc.model.model_id == d.candidate_id

    # an unsigned in-memory model is never promotable
    unsigned = train(models.holdout, models.holdout_labels, 11, rounds=40, version="unsigned-experiment")
    rec = d.registry.register(unsigned, actor=RELEASE_MANAGER)
    assert not rec.signature_verified
    ev_u = d.registry.evaluate(rec.model_id, holdout_features=models.holdout, holdout_labels=models.holdout_labels,
                               recent_features=models.recent_normal, actor=RELEASE_MANAGER)
    assert "candidate_signature_unverified" in ev_u.blocking_checks

    # a tampered artifact (or one signed by an untrusted key) cannot even be registered
    models.champion.save(tmp_path / "tampered", signer=models.signer)
    booster = tmp_path / "tampered" / "booster.txt"
    booster.write_text(booster.read_text().replace("learning_rate", "learning_rate ", 1))
    with pytest.raises(ModelIntegrityError):
        d.registry.register_artifact(tmp_path / "tampered", actor=RELEASE_MANAGER)
    models.champion.save(tmp_path / "foreign", signer=Signer.generate("unknown-key"))
    with pytest.raises(ModelIntegrityError):
        d.registry.register_artifact(tmp_path / "foreign", actor=RELEASE_MANAGER)
