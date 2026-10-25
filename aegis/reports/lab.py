"""End-to-end lab pilot that populates real stores for a demonstration PoV report.

``run_lab_pilot`` drives the production modules exactly as a shadow deployment would,
on the deterministic synthetic lab corpus:

1. :func:`aegis.lab.generate_corpus` produces telemetry plus independent ground truth;
2. :class:`aegis.sentinel.Sentinel` (signed IOC bundle + calibrated model + anomaly +
   change point + fusion) writes evidence and finding entries to the signed ledger;
3. findings are stored, and :class:`aegis.oracle.CaseService` opens a case for every
   alert;
4. each case is triaged and investigated by the bounded :class:`aegis.oracle.Investigator`
   (deterministic mode, no LLM), and a *simulated analyst* records the disposition
   using the lab's ground truth (verified, or rejected as a false alert). The guards
   of the state machine still apply: a verification the evidence cannot support is
   refused and the case is marked INCONCLUSIVE instead.

The simulated analyst is clearly labelled in the report (actor ``analyst:lab-simulated``
and the validation section names the lab as the label source).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Callable

from aegis.contracts.models import CaseState, Finding, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.lab.iocs import lab_signer
from aegis.oracle.investigation import Investigator
from aegis.oracle.state_machine import CaseService, GuardError
from aegis.oracle.tools import build_default_toolset
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.reports.inputs import CoverageStats, ReportPeriod
from aegis.reports.pov import device_day_of
from aegis.sentinel.detector import Sentinel
from aegis.sentinel.model import TrainedModel
from aegis.sentinel.rules import load_bundle
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory

ANALYST = "analyst:lab-simulated"
LAB_LABEL_SOURCE = "AEGIS lab ground truth (synthetic corpus, simulated analyst)"


@dataclass
class LabPilot:
    """Populated stores and the inputs the PoV report needs."""
    tenant_id: str
    corpus: Corpus
    docstore: DocStore
    ledger: Ledger
    evidence_store: EvidenceStore
    keyring: KeyRing
    period: ReportPeriod
    coverage: CoverageStats
    onsets: dict[str, datetime]
    ground_truth: dict[tuple[str, date], str]
    findings: list[Finding] = field(default_factory=list)
    cases_opened: int = 0
    dispositions: dict[str, int] = field(default_factory=dict)


def run_lab_pilot(*, seed: int = 7, n_devices: int = 120, days: int = 3, malicious_fraction: float = 0.08,
                  tenant_id: str = "lab-pilot", model: TrainedModel | None = None, database_url: str = "sqlite://",
                  ledger_signer: Signer | None = None, investigate: bool = True,
                  clock: Callable[[], datetime] | None = None) -> LabPilot:
    """Run the shadow pipeline on a lab corpus and disposition its cases. See module docstring.

    ``model`` defaults to no supervised model (rules + abstain); pass
    ``aegis.sentinel.load_default()`` for the full ensemble. ``database_url`` defaults
    to an in-memory SQLite database.
    """
    corpus = generate_corpus(seed=seed, days=days, n_devices=n_devices, malicious_fraction=malicious_fraction,
                             tenant_id=tenant_id)
    engine = make_engine(database_url)
    init_db(engine)
    sf = make_session_factory(engine)
    signer = ledger_signer or Signer.generate(f"{tenant_id}-ledger")
    keyring = KeyRing()
    keyring.add(signer.key_id, signer.public_pem())
    ledger = Ledger(sf, signer=signer)
    docstore = DocStore(sf)
    evidence = EvidenceStore(docstore, ledger)

    ioc_signer = lab_signer(corpus.seed)
    ioc_ring = KeyRing()
    ioc_ring.add(ioc_signer.key_id, ioc_signer.public_pem())
    bundle = load_bundle(corpus.ioc_bundle(ioc_signer), ioc_ring)

    sentinel = Sentinel(model, bundle, evidence, tenant_id=tenant_id)
    findings = sentinel.process_batch(corpus.events)
    findings += sentinel.flush(corpus.end)
    for f in findings:
        docstore.put(f)

    cases = CaseService(docstore, evidence, ledger, clock=clock)
    investigator = Investigator(None, build_default_toolset(docstore=docstore, evidence_store=evidence,
                                                            ledger=ledger, clock=clock),
                                case_service=cases, clock=clock) if investigate else None
    truth = dict(corpus.labels)
    counts: dict[str, int] = {"verified": 0, "rejected": 0, "inconclusive": 0}
    alerts = [f for f in findings if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
    order: list[str] = []
    for f in alerts:  # one incident, one case: findings of a device join its open case
        case = cases.open_case(f)
        if case.case_id not in order:
            order.append(case.case_id)
    opened = len(order)
    finding_of = {f.finding_id: f for f in findings}
    for case_id in order:
        cases.transition(tenant_id, case_id, CaseState.TRIAGE, ANALYST, "alert triaged in shadow pilot")
        case = cases.transition(tenant_id, case_id, CaseState.INVESTIGATING, ANALYST,
                                "bounded investigation started")
        alternatives = ["benign high-volume streaming or IPTV workload",
                        "shared CDN infrastructure co-hosting the indicator"]
        if investigator is not None:
            report = investigator.investigate(case)
            alternatives = [h.title for h in report.alternative_hypotheses] or alternatives
        malicious = any(truth.get(device_day_of(finding_of[fid]), "benign") != "benign"
                        for fid in case.finding_ids if fid in finding_of)
        cases.record_counter_hypothesis_review(
            tenant_id, case_id, reviewer=ANALYST, alternatives=alternatives,
            notes=("alternatives reviewed against device history and indicator provenance; "
                   + ("activity confirmed by lab ground truth" if malicious else
                      "activity explained by benign behaviour per lab ground truth")))
        if malicious:
            try:
                cases.transition(tenant_id, case_id, CaseState.VERIFIED, ANALYST,
                                 "compromise confirmed (lab ground truth)")
                counts["verified"] += 1
            except GuardError:
                cases.transition(tenant_id, case_id, CaseState.INCONCLUSIVE, ANALYST,
                                 "confirmed by ground truth but evidence insufficient for verification guard")
                counts["inconclusive"] += 1
        else:
            cases.transition(tenant_id, case_id, CaseState.REJECTED, ANALYST,
                             "false alert: benign per lab ground truth")
            counts["rejected"] += 1

    period = ReportPeriod(corpus.start, corpus.end)
    onsets = {d.entity_pseudonym: d.infected_at for d in corpus.devices if d.malicious and d.infected_at}
    return LabPilot(tenant_id=tenant_id, corpus=corpus, docstore=docstore, ledger=ledger, evidence_store=evidence,
                    keyring=keyring, period=period, coverage=CoverageStats.from_events(corpus.events, period),
                    onsets=onsets, ground_truth=truth, findings=findings, cases_opened=opened, dispositions=counts)


__all__ = ["ANALYST", "LAB_LABEL_SOURCE", "LabPilot", "run_lab_pilot"]
