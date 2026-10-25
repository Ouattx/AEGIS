"""Unit tests for the model registry and its promotion gate (aegis.sentinel.registry).

The end-to-end behaviour (drift on real corpora, promotion into a running service)
is covered by ``tests/safety/test_model_drift_promotion.py``; these tests pin the
refusal paths and helpers quickly.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.model import ModelIntegrityError, TrainedModel, load_default
from aegis.sentinel.registry import (
    REGISTRY_SCOPE,
    ModelRegistry,
    PromotionGate,
    PromotionRefused,
    RegistryError,
    _clean,
    _supported_improvements,
    acknowledgeable,
)
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture(scope="module")
def model() -> TrainedModel:
    return load_default()


@pytest.fixture()
def env(tmp_path: Path):
    engine = make_engine(f"sqlite:///{tmp_path / 'r.db'}")
    init_db(engine)
    sf = make_session_factory(engine)
    signer = Signer.generate("model-key")
    ring = KeyRing()
    ring.add_signer(signer)
    clock = Clock()
    promoted: list[str] = []
    reg = ModelRegistry(DocStore(sf), Ledger(sf), keyring=ring, clock=clock,
                        on_promote=lambda m, rec: promoted.append(m.model_id))
    yield reg, signer, clock, promoted, tmp_path
    engine.dispose()


def test_gate_identity_is_stable_and_config_bound() -> None:
    a, b = PromotionGate(), PromotionGate()
    assert a.gate_id == b.gate_id and a.gate_id.startswith("gate-")
    assert PromotionGate(max_score_psi=0.1).gate_id != a.gate_id
    assert a.describe()["gate_id"] == a.gate_id and a.describe()["max_evaluation_age"] == 86400.0


def test_only_drift_checks_are_acknowledgeable() -> None:
    assert acknowledgeable("drift_detected:candidate_score_psi")
    assert acknowledgeable("drift_unknown:insufficient_recent_windows")
    for check in ("recall_regression", "candidate_signature_unverified", "false_alert_regression", "drift"):
        assert not acknowledgeable(check)


def test_register_is_idempotent_and_unsigned(env, model) -> None:
    reg, *_ = env
    rec = reg.register(model, actor="ml.eng")
    assert rec.status == "candidate" and not rec.signature_verified and rec.artifact_dir is None
    assert reg.register(model, actor="someone.else").registered_by == "ml.eng"
    assert [r.model_id for r in reg.records()] == [model.model_id]
    with pytest.raises(RegistryError):
        reg.require("missing")
    with pytest.raises(RegistryError):
        reg.register(model, actor=" ")
    assert reg.history()[0]["payload"]["event"] == "model_registered"


def test_bootstrap_requires_human_signature_and_empty_registry(env, model) -> None:
    reg, signer, _, promoted, tmp = env
    reg.register(model, actor="ml.eng")
    with pytest.raises(PromotionRefused) as pi:
        reg.bootstrap_champion(model.model_id, actor="agent:response_planner", reason="x")
    assert pi.value.failed == ["promotion_requires_human"]
    with pytest.raises(PromotionRefused) as pi:
        reg.bootstrap_champion(model.model_id, actor="ops.installer", reason="install")
    assert pi.value.failed == ["candidate_signature_unverified"]
    assert reg.champion() is None and promoted == []

    model.save(tmp / "signed", signer=signer)
    reg2 = ModelRegistry(reg.docs, reg.ledger, keyring=reg.keyring, clock=reg.clock,
                         on_promote=lambda m, rec: promoted.append(m.model_id))
    # same model id is already registered unsigned: a re-registration returns the existing record
    assert not reg2.register_artifact(tmp / "signed", actor="ml.eng").signature_verified
    lax = ModelRegistry(reg.docs, reg.ledger, gate=PromotionGate(require_signature=False), clock=reg.clock,
                        on_promote=lambda m, rec: promoted.append(m.model_id))
    lax._models[model.model_id] = model
    champ = lax.bootstrap_champion(model.model_id, actor="ops.installer", reason="install")
    assert champ.status == "champion" and promoted == [model.model_id]
    with pytest.raises(PromotionRefused) as pi:
        lax.bootstrap_champion(model.model_id, actor="ops.installer", reason="again")
    assert pi.value.failed == ["champion_exists"]
    refusals = [e for e in reg.history() if e["entry_type"] == "model_promotion_refused"]
    assert len(refusals) == 3


def test_signed_artifact_registration_and_reload(env, model) -> None:
    reg, signer, *_rest, tmp = env
    model.save(tmp / "art", signer=signer)
    rec = reg.register_artifact(tmp / "art", actor="ml.eng")
    assert rec.signature_verified and rec.signer_key_id == "model-key"
    fresh = ModelRegistry(reg.docs, reg.ledger, keyring=reg.keyring, clock=reg.clock)
    assert fresh.model(rec.model_id).model_id == rec.model_id  # re-loaded and re-verified from disk
    (tmp / "art" / "calibration.json").write_text("{}")
    other = ModelRegistry(reg.docs, reg.ledger, keyring=reg.keyring, clock=reg.clock)
    with pytest.raises(ModelIntegrityError):
        other.model(rec.model_id)
    with pytest.raises(RegistryError):
        reg.register_artifact(tmp / "nowhere", actor="ml.eng")
    unknown = Signer.generate("rogue")
    model.save(tmp / "rogue", signer=unknown)
    with pytest.raises(ModelIntegrityError):
        reg.register_artifact(tmp / "rogue", actor="ml.eng")


def test_evaluation_refusal_paths(env, model) -> None:
    reg, signer, clock, promoted, tmp = env
    model.save(tmp / "art", signer=signer)
    rec = reg.register_artifact(tmp / "art", actor="ml.eng")
    ev = reg.evaluate(rec.model_id, holdout_features=[], holdout_labels=[], recent_features=[],
                      actor="ml.eng")
    assert not ev.passed
    assert {"holdout_too_small", "drift_unknown:insufficient_recent_windows"} <= set(ev.failed_checks)
    assert ev.blocking_checks == ["holdout_too_small"]
    assert reg.evaluation(ev.evaluation_id) == ev

    with pytest.raises(PromotionRefused) as pi:
        reg.promote(rec.model_id, evaluation_id="nope", actor="ml.lead", reason="x")
    assert "evaluation_missing" in pi.value.failed
    with pytest.raises(PromotionRefused) as pi:
        reg.promote(rec.model_id, evaluation_id=ev.evaluation_id, actor="ml.lead", reason=" ",
                    acknowledge_drift=True)
    assert {"reason_missing", "holdout_too_small"} <= set(pi.value.failed)
    clock.now += timedelta(hours=25)
    reg.gate = PromotionGate(max_score_psi=0.1)
    with pytest.raises(PromotionRefused) as pi:
        reg.promote(rec.model_id, evaluation_id=ev.evaluation_id, actor="ml.lead", reason="x",
                    acknowledge_drift=True)
    assert {"evaluation_stale", "evaluation_gate_changed"} <= set(pi.value.failed)
    assert promoted == [] and reg.champion() is None
    assert reg.ledger.verify_chain(REGISTRY_SCOPE)[0] is True


def test_already_champion_is_reported(env, model) -> None:
    reg, signer, _, _, tmp = env
    model.save(tmp / "art", signer=signer)
    rec = reg.register_artifact(tmp / "art", actor="ml.eng")
    reg.bootstrap_champion(rec.model_id, actor="ops.installer", reason="install")
    assert reg.active_model() is not None
    ev = reg.evaluate(rec.model_id, holdout_features=[], holdout_labels=[], recent_features=[], actor="ml.eng")
    assert "already_champion" in ev.blocking_checks


def test_helpers() -> None:
    champ = {"device_day_pr_auc": 0.9, "recall": 0.8, "false_alerts_per_10k": 20.0}
    cand = {"ci95": {"device_day_pr_auc": [0.95, 1.0], "recall": [0.7, 1.0], "false_alerts_per_10k": [0.0, 10.0]}}
    assert _supported_improvements(cand, champ) == ["device_day_pr_auc", "false_alerts_per_10k"]
    assert _supported_improvements({"ci95": {}}, champ) == []
    assert _clean({"a": float("nan"), "b": [1.0, float("inf")], "c": "x"}) == {"a": None, "b": [1.0, None], "c": "x"}
