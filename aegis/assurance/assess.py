"""Model assurance facade: one call per finding, one artifact per model.

:class:`ModelAssurance` binds the assurance components to exactly one
:class:`~aegis.sentinel.model.TrainedModel` (by ``model_id`` and
``calibration_id``) and refuses to run against any other model (fail closed).

``assess(fv)`` returns an :class:`AssuranceReport` with:

* the conformal prediction set and its outcome (``benign`` / ``malicious`` /
  ``abstain``) at the configured ``alpha``;
* the novelty verdict; a novel window gets the outcome ``novel`` rather than a
  known label, whatever the model says;
* TreeSHAP attributions, top-k readable reasons and, for windows the model scores
  at or above the counterfactual target, a bounded counterfactual;
* the safe display form of the score (never exactly 1 or 0, calibration id stated).

The assurance outcome is advisory and can only add caution: an integrator must
never use it to escalate a fusion verdict, only to route a finding to review
(``abstain`` / ``novel``). It never changes policy, models or enforcement.

Artifacts are saved as JSON files with a SHA-256 manifest, optionally Ed25519
signed, in the same style as the model itself (no pickle).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

from aegis.assurance._common import AssuranceError, AssuranceMismatch
from aegis.assurance.conformal import MondrianConformal
from aegis.assurance.display import display_score
from aegis.assurance.drift import DriftReference
from aegis.assurance.explain import Explainer, FeatureProfile
from aegis.assurance.novelty import NoveltyDetector
from aegis.contracts.canonical import canonical_bytes, sha256_hex
from aegis.contracts.models import FeatureVector, Finding
from aegis.provenance.signing import KeyRing, Signer

ASSURANCE_FORMAT = "aegis.assurance/1"
AssuranceOutcome = Literal["benign", "malicious", "abstain", "novel"]
#: ledger entry type an integrator should use when recording assurance artifacts / gate decisions
ENTRY_TYPE_ASSURANCE = "model_assurance"


class AssuranceIntegrityError(RuntimeError):
    """Saved assurance files do not match their manifest (or its signature)."""


class AssuranceReport(BaseModel):
    """Assurance result for one window / finding (JSON-serializable)."""
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    entity_pseudonym: str
    device_class: str
    window_end: datetime
    finding_id: str | None = None
    model_id: str
    calibration_id: str
    assurance_id: str
    score: float
    score_display: str
    outcome: AssuranceOutcome
    requires_review: bool
    conformal: dict[str, Any]
    novelty: dict[str, Any] | None = None
    attributions: dict[str, Any]
    reasons: list[dict[str, Any]] = Field(default_factory=list)
    counterfactual: dict[str, Any] | None = None
    notes: list[str] = Field(default_factory=list)

    def evidence_payload(self) -> dict[str, Any]:
        """Payload for an ``Evidence(kind=MODEL_SCORE)`` record citing this assessment."""
        return {"assurance": self.model_dump(mode="json")}

    def summary(self) -> str:
        """One readable line for analysts (no probability shown as certain)."""
        head = {"benign": "Consistent with benign behavior",
                "malicious": "Consistent with known malicious behavior",
                "abstain": "Uncertain: the model's calibration cannot support a single label",
                "novel": "Novel behavior: unlike anything in the reference data; needs a human"}[self.outcome]
        return f"{head}. Model score {self.score_display}."


class ModelAssurance:
    """Assurance components bound to one model."""

    def __init__(self, model: Any, conformal: MondrianConformal, *, novelty: NoveltyDetector | None = None,
                 profile: FeatureProfile | None = None, drift_reference: DriftReference | None = None,
                 counterfactual_target: float = 0.5, top_k: int = 3, info: Mapping[str, Any] | None = None):
        self.model = model
        self.conformal = conformal
        self.novelty = novelty
        self.profile = profile
        self.drift_reference = drift_reference
        self.counterfactual_target = float(counterfactual_target)
        self.top_k = int(top_k)
        self.info = dict(info or {})
        self._check_binding()
        self.explainer = Explainer(model, profile)

    def _check_binding(self) -> None:
        mid, cid = self.model.model_id, self.model.calibration_id
        for name, art_mid, art_cid in (
                ("conformal", self.conformal.model_id, self.conformal.calibration_id),
                ("drift_reference", getattr(self.drift_reference, "model_id", None),
                 getattr(self.drift_reference, "calibration_id", None))):
            if art_mid is not None and art_mid != mid:
                raise AssuranceMismatch(f"{name} was built for model {art_mid}, not {mid}")
            if art_cid is not None and art_cid != cid:
                raise AssuranceMismatch(f"{name} was built for calibration {art_cid}, not {cid}")
        if self.conformal.model_id is None or self.conformal.calibration_id is None:
            raise AssuranceMismatch("conformal predictor is not bound to a model and calibration")

    # ------------------------------------------------------------------ construction
    @classmethod
    def build(cls, model: Any, *, calibration: Sequence[FeatureVector], calibration_labels: Iterable[Any],
              reference: Sequence[FeatureVector], reference_labels: Iterable[Any] | None = None,
              alpha: float = 0.05, novelty_alpha: float = 0.01, min_stratum: int = 50, seed: int = 7,
              **kwargs: Any) -> "ModelAssurance":
        """Build every component.

        ``calibration`` must be labelled windows the model was **not** trained on
        (e.g. its test split or a separate corpus); ``reference`` is the training
        population (novelty manifold, drift reference and benign profile).
        """
        cal_labels = list(calibration_labels)
        ref_labels = None if reference_labels is None else list(reference_labels)
        conformal = MondrianConformal.fit_model(model, calibration, cal_labels, alpha=alpha,
                                                min_stratum=min_stratum)
        novelty = NoveltyDetector.fit(reference, alpha=novelty_alpha, seed=seed)
        profile = FeatureProfile.build(reference, ref_labels)
        drift = DriftReference.from_model(model, reference, ref_labels, seed=seed)
        return cls(model, conformal, novelty=novelty, profile=profile, drift_reference=drift, **kwargs)

    # ------------------------------------------------------------------ identity
    @property
    def assurance_id(self) -> str:
        body = {"model_id": self.model.model_id, "calibration_id": self.model.calibration_id,
                "conformal": self.conformal.conformal_id,
                "novelty": None if self.novelty is None else self.novelty.novelty_id,
                "profile": None if self.profile is None else self.profile.profile_id,
                "drift_reference": None if self.drift_reference is None else self.drift_reference.reference_id,
                "counterfactual_target": self.counterfactual_target, "top_k": self.top_k}
        return "asr-" + sha256_hex(body)[:16]

    def describe(self) -> dict[str, Any]:
        """Ledger-ready description of the artifact (no raw data)."""
        return {"assurance_id": self.assurance_id, "model_id": self.model.model_id,
                "calibration_id": self.model.calibration_id, "conformal_id": self.conformal.conformal_id,
                "alpha": self.conformal.alpha, "conformal_strata": self.conformal.strata_summary(),
                "novelty_id": None if self.novelty is None else self.novelty.novelty_id,
                "novelty_alpha": None if self.novelty is None else self.novelty.alpha,
                "profile_id": None if self.profile is None else self.profile.profile_id,
                "drift_reference_id": None if self.drift_reference is None else self.drift_reference.reference_id,
                "info": self.info}

    # ------------------------------------------------------------------ assessment
    def assess_many(self, fvs: Sequence[FeatureVector], *, counterfactuals: bool = True,
                    finding_ids: Sequence[str | None] | None = None) -> list[AssuranceReport]:
        if finding_ids is not None and len(finding_ids) != len(fvs):
            raise AssuranceError("finding_ids and fvs must have the same length")
        if not fvs:
            return []
        scores = self.model.predict_many(list(fvs))
        cid = str(self.model.calibration_id)
        preds = self.conformal.predict_many(scores, [fv.device_class for fv in fvs])
        nov = self.novelty.score_many(list(fvs)) if self.novelty is not None else [None] * len(fvs)
        attrs = self.explainer.attributions_many(list(fvs))
        aid = self.assurance_id
        out: list[AssuranceReport] = []
        for i, fv in enumerate(fvs):
            s, pr, nv = float(scores[i]), preds[i], nov[i]
            notes: list[str] = []
            outcome: AssuranceOutcome
            if nv is not None and nv.novel:
                outcome = "novel"
                notes.append(f"novelty p-value {nv.p_value:.4f} <= {nv.alpha} against the "
                             f"{'pooled' if nv.stratum == '*' else nv.stratum} baseline")
            elif pr.abstain:
                outcome = "abstain"
                notes.append("conformal set is " + ("ambiguous (both labels plausible)" if pr.outcome == "ambiguous"
                                                   else "empty (score conforms to neither label's calibration)"))
            else:
                outcome = pr.outcome  # type: ignore[assignment]
            if self.novelty is None:
                notes.append("novelty detection not configured")
            attr = attrs[i]
            reasons = self.explainer.reasons(fv, self.top_k, attr)
            cf = None
            if counterfactuals and s >= self.counterfactual_target:
                cf = self.explainer.counterfactual(fv, target=self.counterfactual_target).to_dict()
            notes.append(f"device class '{fv.device_class}' selects the calibration stratum only and is not evidence")
            out.append(AssuranceReport(
                tenant_id=fv.tenant_id, entity_pseudonym=fv.entity_pseudonym, device_class=fv.device_class,
                window_end=fv.window_end, finding_id=None if finding_ids is None else finding_ids[i],
                model_id=self.model.model_id, calibration_id=cid, assurance_id=aid, score=s,
                score_display=str(display_score(s, cid)), outcome=outcome,
                requires_review=outcome != "benign", conformal=pr.to_dict(),
                novelty=None if nv is None else nv.to_dict(), attributions=attr.to_dict(self.top_k * 2),
                reasons=[r.to_dict() for r in reasons], counterfactual=cf, notes=notes))
        return out

    def assess(self, fv: FeatureVector, *, counterfactual: bool = True) -> AssuranceReport:
        return self.assess_many([fv], counterfactuals=counterfactual)[0]

    def assess_finding(self, finding: Finding, fv: FeatureVector, *, counterfactual: bool = True
                       ) -> AssuranceReport:
        """Assess the window behind ``finding`` (tenant, entity and window must match)."""
        if finding.tenant_id != fv.tenant_id or finding.entity_pseudonym != fv.entity_pseudonym:
            raise AssuranceError("feature vector does not belong to the finding's tenant / entity")
        if finding.observed_window_end != fv.window_end:
            raise AssuranceError("feature vector window does not match the finding's observed window")
        if finding.calibration_id is not None and finding.calibration_id != self.model.calibration_id:
            raise AssuranceMismatch("finding was scored under a different calibration")
        return self.assess_many([fv], counterfactuals=counterfactual, finding_ids=[finding.finding_id])[0]

    # ------------------------------------------------------------------ persistence
    def save(self, directory: str | Path, *, signer: Signer | None = None) -> Path:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        files: dict[str, bytes] = {"conformal.json": _json_bytes(self.conformal.to_dict()),
                                   "settings.json": _json_bytes({"counterfactual_target": self.counterfactual_target,
                                                                 "top_k": self.top_k, "info": self.info})}
        if self.novelty is not None:
            files["novelty.json"] = _json_bytes(self.novelty.to_dict())
        if self.profile is not None:
            files["profile.json"] = _json_bytes(self.profile.to_dict())
        if self.drift_reference is not None:
            files["drift_reference.json"] = _json_bytes(self.drift_reference.to_dict())
        for name, data in files.items():
            (d / name).write_bytes(data)
        manifest: dict[str, Any] = {"format": ASSURANCE_FORMAT, "assurance_id": self.assurance_id,
                                    "model_id": self.model.model_id, "calibration_id": self.model.calibration_id,
                                    "files": {n: sha256_hex(b) for n, b in sorted(files.items())}}
        if signer is not None:
            manifest["signer_key_id"] = signer.key_id
            manifest["signature"] = signer.sign(canonical_bytes(manifest))
        (d / "manifest.json").write_bytes(_json_bytes(manifest))
        return d

    @classmethod
    def load(cls, directory: str | Path, model: Any, *, keyring: KeyRing | None = None,
             require_signature: bool = False) -> "ModelAssurance":
        """Load and integrity-check saved assurance for ``model`` (refuses another model)."""
        d = Path(directory)
        try:
            manifest = json.loads((d / "manifest.json").read_text())
        except FileNotFoundError as exc:
            raise AssuranceIntegrityError(f"no manifest in {d}") from exc
        if manifest.get("format") != ASSURANCE_FORMAT:
            raise AssuranceIntegrityError(f"unsupported assurance format {manifest.get('format')!r}")
        sig = manifest.get("signature")
        if sig is not None or require_signature:
            unsigned = {k: v for k, v in manifest.items() if k != "signature"}
            ok = (sig is not None and keyring is not None
                  and keyring.verify(str(manifest.get("signer_key_id")), canonical_bytes(unsigned), sig))
            if require_signature and not ok:
                raise AssuranceIntegrityError("assurance manifest signature missing or not trusted")
            if sig is not None and keyring is not None and not ok:
                raise AssuranceIntegrityError("assurance manifest signature does not verify")
        if manifest.get("model_id") != model.model_id or manifest.get("calibration_id") != model.calibration_id:
            raise AssuranceMismatch("saved assurance belongs to a different model or calibration")
        contents: dict[str, Any] = {}
        for name, digest in manifest.get("files", {}).items():
            if "/" in name or "\\" in name or name.startswith("."):
                raise AssuranceIntegrityError(f"invalid file name in manifest: {name!r}")
            try:
                data = (d / name).read_bytes()
            except FileNotFoundError as exc:
                raise AssuranceIntegrityError(f"{name} listed in the manifest is missing") from exc
            if sha256_hex(data) != digest:
                raise AssuranceIntegrityError(f"{name} does not match the manifest")
            contents[name] = json.loads(data)
        if "conformal.json" not in contents or "settings.json" not in contents:
            raise AssuranceIntegrityError("conformal.json / settings.json missing from manifest")
        st = contents["settings.json"]
        obj = cls(model, MondrianConformal.from_dict(contents["conformal.json"]),
                  novelty=NoveltyDetector.from_dict(contents["novelty.json"]) if "novelty.json" in contents else None,
                  profile=FeatureProfile.from_dict(contents["profile.json"]) if "profile.json" in contents else None,
                  drift_reference=DriftReference.from_dict(contents["drift_reference.json"])
                  if "drift_reference.json" in contents else None,
                  counterfactual_target=float(st["counterfactual_target"]), top_k=int(st["top_k"]),
                  info=st.get("info"))
        if obj.assurance_id != manifest.get("assurance_id"):
            raise AssuranceIntegrityError("assurance id does not match the manifest")
        return obj


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()


__all__ = ["ASSURANCE_FORMAT", "AssuranceIntegrityError", "AssuranceOutcome", "AssuranceReport",
           "ENTRY_TYPE_ASSURANCE", "ModelAssurance"]
