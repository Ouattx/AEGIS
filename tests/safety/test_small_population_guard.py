"""Spec section 15 (benign IPTV untouched) and section 17 G (false-alert budget) on small tenants.

The shipped model's population-relative features were learned on tenants of 90-260
devices. On smaller tenants they do not transfer and the model alone can score benign
IPTV / streaming boxes as malicious. The fusion policy's population guard (F2c) keeps
model-only verdicts out of tenants below the model card's validated minimum, so no
benign device on these lab corpora is alerted.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from aegis.contracts.models import Finding, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.sentinel import Sentinel, load_default
from aegis.sentinel.fusion import FusionPolicy
from aegis.sentinel.model import TrainedModel
from aegis.sentinel.training import lab_bundle

pytestmark = pytest.mark.safety

ALERT = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
#: 30-device corpora on which the unguarded model false-alerts on a benign IPTV / TV box
SMALL_SEEDS = (1, 2, 5, 17)
IPTV_PROFILES = frozenset({"android_tv_iptv", "iptv_busy_box"})


@dataclass
class Run:
    corpus: Corpus
    findings: list[Finding]
    sentinel: Sentinel

    def benign_alerts(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict in ALERT and not self.corpus.device(f.entity_pseudonym).malicious]


def detect(corpus: Corpus, model: TrainedModel, policy: FusionPolicy | None = None) -> Run:
    s = Sentinel(model, lab_bundle(corpus), record_decisions=True,
                 **({"policy": policy} if policy is not None else {}))
    return Run(corpus, s.process_batch(corpus.events) + s.flush(corpus.end), s)


@pytest.fixture(scope="module")
def model() -> TrainedModel:
    return load_default()


@pytest.fixture(scope="module", params=SMALL_SEEDS, ids=lambda seed: f"seed{seed}")
def small(request: pytest.FixtureRequest) -> Corpus:
    return generate_corpus(seed=request.param, days=2, n_devices=30, malicious_fraction=0.15,
                           tenant_id="small-isp")


def test_small_tenants_are_below_the_validated_population(model: TrainedModel, small: Corpus) -> None:
    validated = model.validated_min_population
    assert validated is not None and len(small.devices) < validated
    assert Sentinel(model, None).policy.min_model_population == validated


def test_no_benign_alert_on_small_tenants(model: TrainedModel, small: Corpus) -> None:
    run = detect(small, model)
    assert run.benign_alerts() == []
    # the guard engaged: model-only windows abstain (signal-bearing ABSTAIN findings go to review)
    assert run.sentinel.stats.rules["F2c_population_unvalidated"] > 0
    assert all(f.requires_review for f in run.findings if f.verdict is Verdict.ABSTAIN)
    # indicator-backed detection is untouched: compromised devices with a signed IOC contact still alert
    assert any(f.verdict is Verdict.MALICIOUS and run.corpus.device(f.entity_pseudonym).malicious
               for f in run.findings)


def test_guard_is_what_removes_the_false_alerts(model: TrainedModel) -> None:
    """Without the guard (validated minimum of one device) the same model does false-alert on seed 17."""
    corpus = generate_corpus(seed=17, days=2, n_devices=30, malicious_fraction=0.15, tenant_id="small-isp")
    unguarded = detect(corpus, model, FusionPolicy(min_model_population=1)).benign_alerts()
    assert any(corpus.device(f.entity_pseudonym).profile in IPTV_PROFILES for f in unguarded)
    assert all(f.verdict is Verdict.SUSPICIOUS for f in unguarded)   # model-only is never MALICIOUS (F3)
