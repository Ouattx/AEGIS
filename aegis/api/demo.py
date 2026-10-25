"""Seed a demonstration tenant from the synthetic lab corpus, end to end.

:func:`seed_lab_demo` drives the production service exactly as a shadow pilot would:

1. generate the deterministic lab corpus (dated so it ends at today's midnight UTC)
   and write it as collector files (NetFlow CSV + resolver DNS JSONL);
2. configure the tenant: authorized sources, its pseudonymization key, the signed
   IOC bundle (lab signer trusted on disk), the hosting topology and a **shadow-mode**
   operator policy signed by a generated demo operator key;
3. ingest the files through the real pipeline (parse, pseudonymize, validate,
   bus) into SENTINEL, which writes evidence and findings to the signed ledger;
   ORACLE opens a case for every alert;
4. triage and investigate every case with the bounded investigator (deterministic
   without an LLM), then let a clearly labelled *simulated analyst*
   (``analyst:lab-simulated``) disposition the cases from the lab's independent
   ground truth, except the ``leave_open`` most severe confirmed cases, which stay
   in INVESTIGATING for a live walk-through (review, verify, propose, simulate,
   authorize: the shadow policy then refuses enforcement).

Nothing touches a real network: lab addresses and names come from reserved ranges.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from aegis.contracts.models import ActionType, CaseState, OperatorPolicy, Verdict
from aegis.lab.corpus import Corpus, generate_corpus
from aegis.lab.iocs import lab_signer
from aegis.oracle.state_machine import GuardError
from aegis.provenance.signing import Signer, sign_model
from aegis.reports.inputs import ReportPeriod
from aegis.reports.lab import ANALYST, LAB_LABEL_SOURCE
from aegis.reports.pov import device_day_of
from aegis.service import AegisService, ConflictError, LabContext, _write_secret

ORCHESTRATOR = "system:demo-orchestrator"
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


@dataclass
class DemoSummary:
    tenant_id: str
    period_start: datetime
    period_end: datetime
    devices: int
    malicious_devices: int
    events: int
    findings: int
    alerts: int
    cases: int
    dispositions: dict[str, int] = field(default_factory=dict)
    open_case_ids: list[str] = field(default_factory=list)
    raw_files: dict[str, str] = field(default_factory=dict)
    policy_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in self.__dict__.items()}


def demo_start(days: int, now: datetime | None = None) -> datetime:
    today = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(hour=0, minute=0, second=0,
                                                                               microsecond=0)
    return today - timedelta(days=days)


def _operator_signer(service: AegisService, tenant_id: str) -> Signer:
    key_id = f"demo-operator-{tenant_id}"
    path = service.settings.keys_dir / f"{key_id}.pem"
    if path.is_file():
        signer = Signer.from_private_pem(key_id, path.read_bytes())
    else:
        signer = Signer.generate(key_id)
        _write_secret(path, signer.private_pem())
    service.trust_key("policy", key_id, signer.public_pem())
    return signer


def _configure(service: AegisService, corpus: Corpus, tenant_id: str) -> str:
    service.set_tenant_pseudonym_key(tenant_id, corpus.tenant_key)
    existing = {c.source_id for c in service.list_sources(tenant_id)}
    for cfg in corpus.sources.values():
        if cfg.source_id in existing:
            continue
        service.register_source(tenant_id, ORCHESTRATOR, source_id=cfg.source_id, source_kind=cfg.source_kind,
                                vantage=cfg.vantage, collection_authorization_id=cfg.collection_authorization_id,
                                retention_days=cfg.retention_days, format=cfg.format,
                                entity_field=cfg.entity_field)
    ioc = lab_signer(corpus.seed)
    service.trust_key("ioc", ioc.key_id, ioc.public_pem())
    service.load_ioc_bundle(tenant_id, ORCHESTRATOR, corpus.ioc_bundle(ioc))
    service.load_topology(tenant_id, ORCHESTRATOR, corpus.topology.to_dict(include_ground_truth=False))

    signer = _operator_signer(service, tenant_id)
    now = service.clock()
    policy_id = f"{tenant_id}-shadow-{corpus.start:%Y%m%d}"
    policy = OperatorPolicy(
        policy_id=policy_id, tenant_id=tenant_id, mode="shadow",
        allowed_actions=[ActionType.DNS_SINKHOLE, ActionType.NOTIFY_SUBSCRIBER], max_targets_per_action=5,
        max_ttl_hours=72, approved_scope={"max_entities": 5, "legal_bases": ["operator_tos_security_clause"],
                                          "max_affected_entities": 5},
        legal_signoff_ref=None, valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=90),
        signer_key_id=signer.key_id, signature="")
    try:
        service.load_policy(tenant_id, ORCHESTRATOR, sign_model(policy, signer).model_dump(mode="json"))
    except ConflictError:
        pass  # the same day's demo policy already exists
    return policy_id


def seed_lab_demo(service: AegisService, *, tenant_id: str = "demo", seed: int = 7, n_devices: int = 120,
                  days: int = 3, malicious_fraction: float = 0.08, leave_open: int = 4,
                  raw_dir: Path | None = None, start: datetime | None = None,
                  log: Callable[[str], None] = lambda _msg: None) -> DemoSummary:
    """Populate ``tenant_id`` with a fully processed lab pilot. See the module docstring."""
    start = start or demo_start(days)
    log(f"generating lab corpus: {n_devices} devices, {days} days, seed {seed}")
    corpus = generate_corpus(seed=seed, days=days, n_devices=n_devices, malicious_fraction=malicious_fraction,
                             tenant_id=tenant_id, start=start)
    out_dir = raw_dir or (service.settings.raw_dir / tenant_id)
    paths = corpus.write_raw(out_dir, zeek=False)
    log("configuring tenant: sources, pseudonym key, signed IOC bundle, topology, shadow policy")
    policy_id = _configure(service, corpus, tenant_id)

    log(f"ingesting {len(corpus.events)} telemetry records through the pipeline and SENTINEL")
    outcome = service.ingest_files(tenant_id, [(paths["netflow"], "lab-netflow"), (paths["dns"], "lab-dns")],
                                   flush_at=corpus.end)
    alerts = [f for f in outcome.findings if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
    log(f"{len(outcome.findings)} findings ({len(alerts)} alerts), {len(outcome.cases_opened)} cases opened")

    truth = dict(corpus.labels)
    finding_of = {f.finding_id: f for f in outcome.findings}
    cases = [service.cases.require(tenant_id, cid) for cid in dict.fromkeys(outcome.cases_opened)]

    def malicious(case_finding_ids: list[str]) -> bool:
        for fid in case_finding_ids:
            f = finding_of.get(fid)
            if f is not None and truth.get(device_day_of(f), "benign") != "benign":
                return True
        return False

    confirmed = sorted((c for c in cases if malicious(c.finding_ids)),
                       key=lambda c: (-SEVERITY_RANK.get(c.severity, 0), c.created_at, c.case_id))
    keep_open = {c.case_id for c in confirmed[:max(0, leave_open)]}
    counts = {"verified": 0, "rejected": 0, "inconclusive": 0, "open": 0}
    log(f"investigating {len(cases)} cases (bounded agents, "
        f"{'LLM' if service.llm is not None else 'deterministic mode'})")
    for case in cases:
        service.cases.transition(tenant_id, case.case_id, CaseState.TRIAGE, ORCHESTRATOR, "alert queued for triage")
        case = service.cases.transition(tenant_id, case.case_id, CaseState.INVESTIGATING, ORCHESTRATOR,
                                        "bounded investigation started")
        report = service.investigator.investigate(case)
        if case.case_id in keep_open:
            counts["open"] += 1
            continue
        is_mal = malicious(case.finding_ids)
        alternatives = [h.title for h in report.alternative_hypotheses] or [
            "benign high-volume streaming or IPTV workload", "shared CDN infrastructure co-hosting the indicator"]
        service.cases.record_counter_hypothesis_review(
            tenant_id, case.case_id, reviewer=ANALYST, alternatives=alternatives,
            notes=("alternatives reviewed against device history and indicator provenance; "
                   + ("activity confirmed by lab ground truth" if is_mal
                      else "activity explained by benign behaviour per lab ground truth")))
        if is_mal:
            try:
                service.cases.transition(tenant_id, case.case_id, CaseState.VERIFIED, ANALYST,
                                         "compromise confirmed (lab ground truth)")
                counts["verified"] += 1
            except GuardError:
                service.cases.transition(tenant_id, case.case_id, CaseState.INCONCLUSIVE, ANALYST,
                                         "confirmed by ground truth but evidence insufficient for verification")
                counts["inconclusive"] += 1
        else:
            service.cases.transition(tenant_id, case.case_id, CaseState.REJECTED, ANALYST,
                                     "false alert: benign per lab ground truth")
            counts["rejected"] += 1

    period = ReportPeriod(corpus.start, corpus.end)
    onsets = {d.entity_pseudonym: d.infected_at for d in corpus.devices if d.malicious and d.infected_at}
    service.register_lab_context(tenant_id, LabContext(onsets=onsets, ground_truth=truth, source=LAB_LABEL_SOURCE,
                                                       period=period))
    return DemoSummary(tenant_id=tenant_id, period_start=corpus.start, period_end=corpus.end,
                       devices=len(corpus.devices), malicious_devices=len(corpus.malicious_devices()),
                       events=outcome.events, findings=len(outcome.findings), alerts=len(alerts), cases=len(cases),
                       dispositions=counts, open_case_ids=sorted(keep_open),
                       raw_files={k: str(v) for k, v in paths.items()}, policy_id=policy_id)


__all__ = ["DemoSummary", "demo_start", "seed_lab_demo"]
