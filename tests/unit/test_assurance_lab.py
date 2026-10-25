"""Empirical validation of model assurance on the AEGIS lab corpus (synthetic data).

The shipped default Sentinel model was trained on lab seeds 101..909. Here seed 31
supplies calibration / reference windows and seed 7 is an unseen evaluation corpus
(new devices, topology and campaigns). All results are synthetic.
"""
from __future__ import annotations

import json
from collections import Counter

import numpy as np
import pytest

from aegis.assurance import (
    AssuranceGate,
    AssuranceIntegrityError,
    AssuranceMismatch,
    DriftMonitor,
    ModelAssurance,
    MondrianConformal,
    NoveltyDetector,
)
from aegis.lab.corpus import generate_corpus
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.model import load_default
from aegis.sentinel.training import extract_windows, lab_window_labels
from test_assurance_helpers import small_model


def _windows(seed: int):
    corpus = generate_corpus(seed=seed, days=2, n_devices=120, tenant_id="lab-assurance")
    fvs = extract_windows(corpus.events, flush_at=corpus.end)
    labels = lab_window_labels(corpus, fvs)
    family = {d.entity_pseudonym: d.malicious_label for d in corpus.devices if d.malicious}
    return fvs, labels, family


@pytest.fixture(scope="module")
def lab():
    model = load_default()
    cal = _windows(31)
    test = _windows(7)
    return {"model": model, "cal": cal, "test": test,
            "cal_scores": model.predict_many(cal[0]), "test_scores": model.predict_many(test[0])}


@pytest.fixture(scope="module")
def assurance(lab):
    fvs, labels, _ = lab["cal"]
    return ModelAssurance.build(lab["model"], calibration=fvs, calibration_labels=labels, reference=fvs,
                                reference_labels=labels, alpha=0.05, novelty_alpha=0.01)


@pytest.mark.parametrize("alpha", [0.05, 0.1])
def test_conformal_coverage_on_unseen_corpus(lab, alpha):
    m = lab["model"]
    cfvs, clabels, _ = lab["cal"]
    tfvs, tlabels, _ = lab["test"]
    cp = MondrianConformal.fit(lab["cal_scores"], clabels, [f.device_class for f in cfvs], alpha=alpha,
                               model_id=m.model_id, calibration_id=m.calibration_id)
    rep = cp.coverage_report(lab["test_scores"], tlabels, [f.device_class for f in tfvs])
    for lab_name in ("benign", "malicious"):
        cell = rep["label_conditional"][lab_name]
        assert cell["n"] > 100
        assert cell["coverage"] >= 1 - alpha - 0.02, (lab_name, cell)
    for dc, cells in rep["per_device_class"].items():
        for lab_name, cell in cells.items():
            if cell["n"] >= 200:
                assert cell["coverage"] >= 1 - alpha - 0.05, (dc, lab_name, cell)
    assert rep["abstain_rate"] <= 2 * alpha + 0.02


def test_conformal_guarantee_under_exchangeable_splits(lab):
    """Random window-level splits of pooled labelled windows: mean coverage >= 1 - alpha."""
    fvs = lab["cal"][0] + lab["test"][0]
    labels = np.array([-1 if v is None else v for v in lab["cal"][1] + lab["test"][1]])
    scores = np.r_[lab["cal_scores"], lab["test_scores"]]
    dcs = [f.device_class for f in fvs]
    keep = np.flatnonzero(labels >= 0)
    rng = np.random.default_rng(5)
    alpha = 0.1
    covs = []
    for _ in range(10):
        idx = rng.permutation(keep)
        c, t = idx[: len(idx) // 2], idx[len(idx) // 2:]
        cp = MondrianConformal.fit(scores[c], labels[c], [dcs[i] for i in c], alpha=alpha)
        rep = cp.coverage_report(scores[t], labels[t], [dcs[i] for i in t])
        covs.append([rep["label_conditional"][k]["coverage"] for k in ("benign", "malicious")])
    mean = np.mean(covs, axis=0)
    assert np.all(mean >= 1 - alpha - 0.01), mean


@pytest.mark.parametrize("held_out", ["dga_activity", "ddos_bot"])
def test_unseen_malware_family_is_flagged_novel(lab, held_out):
    cfvs, clabels, cfam = lab["cal"]
    tfvs, tlabels, tfam = lab["test"]
    ref = [f for f, y in zip(cfvs, clabels) if y is not None and cfam.get(f.entity_pseudonym) != held_out]
    det = NoveltyDetector.fit(ref, alpha=0.01, seed=7)
    unseen = [f for f, y in zip(tfvs, tlabels) if y == 1 and tfam.get(f.entity_pseudonym) == held_out]
    known = [f for f, y in zip(tfvs, tlabels) if y is not None and tfam.get(f.entity_pseudonym) != held_out]
    assert len(unseen) >= 10
    assert det.novelty_rate(unseen) >= 0.9
    # new devices of known behavior: false novelty stays near alpha
    assert det.novelty_rate(known) <= 0.03


def test_assessment_reports_on_unseen_corpus(lab, assurance):
    tfvs, tlabels, _ = lab["test"]
    pos = [f for f, y in zip(tfvs, tlabels) if y == 1][::6]
    neg = [f for f, y in zip(tfvs, tlabels) if y == 0][::40]
    reps = assurance.assess_many(pos + neg)
    pos_out = Counter(r.outcome for r in reps[: len(pos)])
    neg_out = Counter(r.outcome for r in reps[len(pos):])
    # the reference holds only 16 infected devices (4 per family), so some windows of new campaigns sit
    # outside its manifold and are routed to a human as "novel" rather than labelled: never called benign
    assert pos_out["malicious"] >= 0.6 * len(pos), pos_out
    assert pos_out["malicious"] + pos_out["novel"] + pos_out["abstain"] >= 0.95 * len(pos), pos_out
    assert neg_out["benign"] >= 0.85 * len(neg), neg_out
    assert pos_out["benign"] <= 0.05 * len(pos)
    for r in reps:
        assert r.score_display.split(" ")[0] not in ("1.00", "0.00")
        assert r.calibration_id in r.score_display
        assert r.requires_review == (r.outcome != "benign")
        assert any("not evidence" in n for n in r.notes)
        json.dumps(r.model_dump(mode="json"))
        assert r.evidence_payload()["assurance"]["assurance_id"] == assurance.assurance_id
    with_cf = [r for r in reps[: len(pos)] if r.counterfactual is not None]
    found = [r for r in with_cf if r.counterfactual["found"]]
    assert len(found) >= 0.9 * len(with_cf)
    for r in found:
        assert r.counterfactual["new_score"] < 0.5 and 1 <= len(r.counterfactual["changes"]) <= 3
    mal = next(r for r in reps if r.outcome == "malicious")
    assert mal.reasons and mal.reasons[0]["direction"] == "raised"
    assert "known malicious" in mal.summary()


def test_save_load_sign_and_tamper(lab, assurance, tmp_path):
    signer = Signer.generate("assurance-test")
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    d = assurance.save(tmp_path / "a", signer=signer)
    loaded = ModelAssurance.load(d, lab["model"], keyring=ring, require_signature=True)
    assert loaded.assurance_id == assurance.assurance_id
    probe = lab["test"][0][:30]
    assert [r.model_dump() for r in loaded.assess_many(probe)] == [r.model_dump() for r in assurance.assess_many(probe)]
    with pytest.raises(AssuranceMismatch):
        ModelAssurance.load(d, small_model())
    with pytest.raises(AssuranceIntegrityError):
        ModelAssurance.load(d, lab["model"], keyring=KeyRing(), require_signature=True)
    unsigned = assurance.save(tmp_path / "b")
    with pytest.raises(AssuranceIntegrityError):
        ModelAssurance.load(unsigned, lab["model"], require_signature=True)
    raw = json.loads((unsigned / "conformal.json").read_text())
    raw["alpha"] = 0.5
    (unsigned / "conformal.json").write_text(json.dumps(raw))
    with pytest.raises(AssuranceIntegrityError):
        ModelAssurance.load(unsigned, lab["model"])
    with pytest.raises(AssuranceIntegrityError):
        ModelAssurance.load(tmp_path / "missing", lab["model"])


def test_binding_refuses_other_model(lab, assurance):
    with pytest.raises(AssuranceMismatch):
        ModelAssurance(small_model(), assurance.conformal)


def test_drift_and_gate_on_lab(lab, assurance):
    m = lab["model"]
    cfvs, clabels, _ = lab["cal"]
    tfvs, tlabels, _ = lab["test"]
    # same corpus (the reference itself): score and calibration do not drift
    rep = DriftMonitor(assurance.drift_reference).evaluate(cfvs, scores=lab["cal_scores"], labels=clabels)
    assert rep.status == "ok" and not rep.alerts
    # unseen corpus: model scores and calibration stay stable; population-relative features may move
    rep2 = DriftMonitor(assurance.drift_reference).evaluate(tfvs, scores=lab["test_scores"], labels=tlabels)
    assert rep2.score["status"] == "ok" and rep2.calibration["status"] == "ok"
    # promotion gate: the same model as candidate and champion has no hard blocks
    dec = AssuranceGate().evaluate_models(m, m, tfvs, tlabels, tfvs, reference=assurance.drift_reference,
                                          conformal=assurance.conformal, novelty=assurance.novelty)
    assert dec.blocking_checks == (), dec.blocking_checks
    assert all(c.startswith(("drift_detected:", "drift_unknown:")) for c in dec.failed_checks)
    cov = dec.metrics["conformal"]["label_conditional"]
    assert cov["malicious"]["coverage"] >= 0.93 and cov["benign"]["coverage"] >= 0.93
