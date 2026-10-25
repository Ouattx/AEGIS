"""Shadow proof-of-value (PoV) report (spec sections 13, 14, 17, 19).

``build_pov_report`` reads a tenant's findings, cases, evidence, operator policies and
provenance ledger and renders a single self-contained HTML document (inline CSS and
SVG, no external assets) that an ISP security director can forward to a CISO:

- executive summary, devices observed, findings by threat class with evidence counts;
- top cases with their full evidence trail (content hashes, integrity status, every
  decision with its ledger entry hash);
- false alerts per 10k device-days (measured from analyst dispositions, with an upper
  bound for unresolved alerts), detection delay and alert latency;
- estimated analyst minutes per case (transparent effort model) and cost per protected
  device-month from operator-configurable inputs;
- a zero-enforcement attestation derived from the verified ledger, and the ledger
  integrity verification result;
- methodology and limitations, written to claim only what was measured.

Everything is deterministic and works without an LLM. Data that cannot be measured
from what was supplied is reported as "not measurable", never as zero.

Definitions used throughout:

* **alert** - a MALICIOUS or SUSPICIOUS finding whose window ends inside the period;
* **device-day** of a finding - (entity pseudonym, UTC date of the window's last instant);
* **disposition** of a finding - from the case opened for it: *verified* once the case
  reached VERIFIED (or any later enforcement state), *rejected* once it reached
  REJECTED, *inconclusive* for INCONCLUSIVE, *pending* otherwise (or no case yet).
  A device-day takes its strongest disposition: verified > rejected > inconclusive > pending;
* **false alert** - an alerting device-day whose alerts were all rejected by analysts.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any, Iterable, Mapping, Sequence

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import (
    Case,
    CaseState,
    Evidence,
    Finding,
    OperatorPolicy,
    Verdict,
)
from aegis.provenance.evidence import EvidenceStore, evidence_hash, independent_origins
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing
from aegis.provenance.snapshot import snapshot
from aegis.reports import charts
from aegis.reports.inputs import AnalystEffortModel, CostInputs, CoverageStats, ReportPeriod
from aegis.reports.model import (
    AlertSummary,
    Attestation,
    CaseView,
    CostLine,
    CostSummary,
    DailyRow,
    DecisionView,
    DetectionTiming,
    DeviceClassRow,
    Dispositions,
    EffortSummary,
    EvidenceCoverage,
    EvidenceView,
    FalseAlertRates,
    LedgerVerification,
    PovReport,
    ThreatClassRow,
    Validation,
)
from aegis.reports.theme import BASE_CSS, SERIES, STATUS
from aegis.storage.db import DocStore

DAYS_PER_MONTH = 30.4375
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

_ALERT = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
_VERIFIED_STATES = frozenset({CaseState.VERIFIED, CaseState.PROPOSED, CaseState.APPROVED, CaseState.DENIED,
                              CaseState.EXECUTED, CaseState.ROLLED_BACK})
_DISPOSITION_RANK = {"verified": 3, "rejected": 2, "inconclusive": 1, "pending": 0}
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_EXEC_TYPES = (EntryType.EXECUTION,)
#: executor outcomes in which nothing was enforced
_NOT_ENFORCED_STATUSES = frozenset({"refused", "failed"})


def device_day_of(f: Finding) -> tuple[str, date]:
    """Device-day a finding is attributed to (same rule as the Sentinel model card)."""
    return f.entity_pseudonym, (f.observed_window_end - timedelta(microseconds=1)).date()


def _quantile(values: Sequence[float], q: float) -> float | None:
    if not values:
        return None
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


def _per_10k(n: int, d: int | None) -> float | None:
    return None if not d else 1e4 * n / d


def _case_disposition(case: Case | None) -> str:
    if case is None:
        return "pending"
    reached = {d.to_state for d in case.decisions} | {case.state}
    if reached & _VERIFIED_STATES:
        return "verified"
    if CaseState.REJECTED in reached:
        return "rejected"
    if CaseState.INCONCLUSIVE in reached:
        return "inconclusive"
    return "pending"


def _is_human(actor: str) -> bool:
    a = actor.strip().lower()
    return bool(a) and not a.startswith("agent:") and a != "system"


# ---------------------------------------------------------------------------- collection

class _EvidenceIndex:
    """Bulk evidence lookup with integrity status (document hash + ledger record)."""

    def __init__(self, tenant_id: str, docstore: DocStore, ledger: Ledger):
        self._tenant = tenant_id
        self._docs = docstore
        self._ledger = ledger
        self._cache: dict[str, tuple[Evidence | None, str]] = {}

    def load(self, ids: Iterable[str]) -> None:
        todo = [i for i in dict.fromkeys(ids) if i and i not in self._cache]
        if not todo:
            return
        recorded: dict[str, set[str]] = defaultdict(set)
        for e in self._ledger.entries_for_subjects(self._tenant, todo):
            if e.entry_type == EntryType.EVIDENCE:
                recorded[e.subject_id].add(str(e.payload.get("sha256", "")))
        for i in todo:
            ev = self._docs.get(Evidence, self._tenant, i)
            if ev is None:
                self._cache[i] = (None, "missing")
                continue
            ok = evidence_hash(ev) == ev.sha256 and recorded.get(i) == {ev.sha256}
            self._cache[i] = (ev, "verified" if ok else "tampered")

    def get(self, evidence_id: str) -> tuple[Evidence | None, str]:
        self.load([evidence_id])
        return self._cache[evidence_id]


def collect_pov_report(tenant_id: str, docstore: DocStore, ledger: Ledger,
                       period: ReportPeriod | tuple[datetime, datetime], *,
                       evidence_store: EvidenceStore | None = None, keyring: KeyRing | None = None,
                       coverage: CoverageStats | None = None, cost: CostInputs | None = None,
                       effort: AnalystEffortModel | None = None,
                       onsets: Mapping[str, datetime] | None = None,
                       ground_truth: Mapping[tuple[str, date], str] | None = None,
                       ground_truth_source: str = "independent ground truth",
                       false_alert_budget_per_10k: float | None = None,
                       operator_name: str | None = None, generated_at: datetime | None = None,
                       top_cases: int = 5, evidence_per_case: int = 12) -> PovReport:
    """Collect every metric of the PoV report for one tenant (all reads tenant-scoped).

    ``coverage`` is the observed population (see :class:`CoverageStats`); without it,
    rates per device-day are reported as not measurable. ``onsets`` maps entity
    pseudonyms to confirmed compromise onset times (red-team injection or analyst
    confirmation) for detection delay. ``ground_truth`` (device-day labels, lab or
    injected) adds an independent validation section. ``evidence_store`` is accepted
    for API symmetry; integrity is checked directly against the ledger.
    """
    del evidence_store  # integrity is verified in bulk against the ledger below
    per = ReportPeriod.coerce(period)
    cost = cost or CostInputs()
    effort = effort or AnalystEffortModel()
    now = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if not tenant_id or not tenant_id.strip():
        raise ValueError("tenant_id is required")

    findings = [f for f in docstore.iter_all(Finding, tenant_id) if per.contains(f.observed_window_end)]
    findings.sort(key=lambda f: (f.observed_window_end, f.finding_id))
    alerts = [f for f in findings if f.verdict in _ALERT]
    abstains = [f for f in findings if f.verdict == Verdict.ABSTAIN]

    cases = list(docstore.iter_all(Case, tenant_id))
    case_of: dict[str, Case] = {}
    for c in cases:
        for fid in c.finding_ids:
            case_of[fid] = c
    disp_of = {f.finding_id: _case_disposition(case_of.get(f.finding_id)) for f in findings}

    # ------------------------------------------------------------- alerts and dispositions
    dd_disp: dict[tuple[str, date], str] = {}
    for f in alerts:
        k = device_day_of(f)
        d = disp_of[f.finding_id]
        if k not in dd_disp or _DISPOSITION_RANK[d] > _DISPOSITION_RANK[dd_disp[k]]:
            dd_disp[k] = d
    disp_counts = Counter(dd_disp.values())
    alert_summary = AlertSummary(
        findings_total=len(findings), alerts=len(alerts),
        malicious=sum(1 for f in alerts if f.verdict == Verdict.MALICIOUS),
        suspicious=sum(1 for f in alerts if f.verdict == Verdict.SUSPICIOUS),
        abstain_for_review=len(abstains), alerted_devices=len({f.entity_pseudonym for f in alerts}),
        alerted_device_days=len(dd_disp))
    dispositions = Dispositions(verified=disp_counts["verified"], rejected=disp_counts["rejected"],
                                inconclusive=disp_counts["inconclusive"], pending=disp_counts["pending"])

    device_days = coverage.device_days if coverage is not None else None
    rejected_dd = disp_counts["rejected"]
    unresolved_dd = disp_counts["pending"] + disp_counts["inconclusive"]
    class_of_entity = {f.entity_pseudonym: f.device_class for f in findings}
    rej_by_class: Counter[str] = Counter(class_of_entity.get(ent, "unknown")
                                         for (ent, _d), v in dd_disp.items() if v == "rejected")
    per_class_fa: dict[str, float | None] = {}
    if coverage is not None:
        for klass, n in sorted(coverage.device_days_by_class.items()):
            per_class_fa[klass] = _per_10k(rej_by_class.get(klass, 0), n)
    fa_rate = _per_10k(rejected_dd, device_days)
    fa = FalseAlertRates(
        device_days=device_days, rejected_device_days=rejected_dd, unresolved_device_days=unresolved_dd,
        per_10k=fa_rate, per_10k_upper=_per_10k(rejected_dd + unresolved_dd, device_days),
        per_device_class=per_class_fa, budget_per_10k=false_alert_budget_per_10k,
        within_budget=(None if false_alert_budget_per_10k is None or fa_rate is None
                       else fa_rate <= false_alert_budget_per_10k))

    # ------------------------------------------------------------- evidence
    index = _EvidenceIndex(tenant_id, docstore, ledger)
    index.load(i for f in findings for i in (f.evidence_ids + f.counterevidence_ids))
    checked = failures = missing = with_ev = with_two = 0
    origins_of: dict[str, int] = {}
    for f in findings:
        evs: list[Evidence] = []
        for eid in f.evidence_ids + f.counterevidence_ids:
            ev, status = index.get(eid)
            checked += 1
            if status == "missing":
                missing += 1
            elif status == "tampered":
                failures += 1
            if ev is not None and status == "verified":
                evs.append(ev)
        origins_of[f.finding_id] = independent_origins(evs, supporting_only=True)
        if f.verdict in _ALERT:
            with_ev += bool(f.evidence_ids)
            with_two += origins_of[f.finding_id] >= 2
    evidence_cov = EvidenceCoverage(alerts_with_evidence=with_ev, alerts_with_two_origins=with_two,
                                    evidence_items_checked=checked, evidence_integrity_failures=failures,
                                    evidence_missing=missing)

    # ------------------------------------------------------------- threat classes
    by_label: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_label[f.label].append(f)
    classes: list[ThreatClassRow] = []
    for label, fs in by_label.items():
        al = [f for f in fs if f.verdict in _ALERT]
        scores = [f.score for f in al]
        classes.append(ThreatClassRow(
            label=label, malicious=sum(1 for f in fs if f.verdict == Verdict.MALICIOUS),
            suspicious=sum(1 for f in fs if f.verdict == Verdict.SUSPICIOUS),
            abstain=sum(1 for f in fs if f.verdict == Verdict.ABSTAIN),
            devices=len({f.entity_pseudonym for f in al}),
            evidence_items=sum(len(f.evidence_ids) + len(f.counterevidence_ids) for f in fs),
            max_independent_origins=max((origins_of[f.finding_id] for f in fs), default=0),
            verified=sum(1 for f in al if disp_of[f.finding_id] == "verified"),
            rejected=sum(1 for f in al if disp_of[f.finding_id] == "rejected"),
            pending=sum(1 for f in al if disp_of[f.finding_id] in ("pending", "inconclusive")),
            median_score=round(median(scores), 4) if scores else None))
    classes.sort(key=lambda r: (-(r.malicious + r.suspicious), -r.abstain, r.label))

    # ------------------------------------------------------------- device classes
    alerted_by_class: dict[str, set[str]] = defaultdict(set)
    for f in alerts:
        alerted_by_class[f.device_class].add(f.entity_pseudonym)
    all_classes = set(alerted_by_class) | set(coverage.devices_by_class if coverage else {})
    device_rows = []
    for klass in sorted(all_classes):
        observed = coverage.devices_by_class.get(klass) if coverage is not None else None
        n_al = len(alerted_by_class.get(klass, ()))
        device_rows.append(DeviceClassRow(device_class=klass, devices_observed=observed, alerted_devices=n_al,
                                          alert_rate=(n_al / observed) if observed else None))

    # ------------------------------------------------------------- daily
    daily_counts: dict[date, Counter[str]] = {d: Counter() for d in per.dates()}
    for f in findings:
        fday = device_day_of(f)[1]
        if fday in daily_counts:
            daily_counts[fday][f.verdict.value] += 1
    daily = [DailyRow(day=day, malicious=c["malicious"], suspicious=c["suspicious"], abstain=c["abstain"])
             for day, c in sorted(daily_counts.items())]

    # ------------------------------------------------------------- top cases
    finding_by_id = {f.finding_id: f for f in findings}
    period_cases = [c for c in cases if any(fid in finding_by_id for fid in c.finding_ids)]

    def case_key(c: Case) -> tuple[Any, ...]:
        f = max((finding_by_id[i] for i in c.finding_ids if i in finding_by_id), key=lambda x: x.score)
        return (-_SEVERITY_RANK.get(c.severity, 0), -_DISPOSITION_RANK[_case_disposition(c)], -f.score,
                c.created_at, c.case_id)

    views: list[CaseView] = []
    for c in sorted(period_cases, key=case_key)[:max(0, top_cases)]:
        f = max((finding_by_id[i] for i in c.finding_ids if i in finding_by_id), key=lambda x: x.score)
        ev_ids = list(dict.fromkeys(c.evidence_ids or (f.evidence_ids + f.counterevidence_ids)))
        index.load(ev_ids)
        ev_views: list[EvidenceView] = []
        for eid in ev_ids[:evidence_per_case]:
            ev, status = index.get(eid)
            ev_views.append(EvidenceView(
                evidence_id=eid, kind=ev.kind.value if ev else "unknown",
                summary=(ev.summary if ev else "evidence record not found")[:400],
                origin_source=ev.origin_source if ev else "", independence_group=(
                    ev.source_independence_group if ev else ""),
                collected_at=ev.collected_at if ev else None, supports=ev.supports if ev else True,
                sha256=ev.sha256 if ev else "", integrity=status))  # type: ignore[arg-type]
        views.append(CaseView(
            case_id=c.case_id, title=c.title, state=c.state.value, severity=c.severity, created_at=c.created_at,
            label=f.label, verdict=f.verdict.value, score=f.score, calibrated=f.calibration_id is not None,
            entity_pseudonym=f.entity_pseudonym, device_class=f.device_class,
            window_start=f.observed_window_start, window_end=f.observed_window_end,
            explanation=f.explanation[:1200], independent_origins=origins_of.get(f.finding_id, 0),
            counter_evidence=len(f.counterevidence_ids), evidence=ev_views, evidence_total=len(ev_ids),
            decisions=[DecisionView(from_state=d.from_state.value, to_state=d.to_state.value, actor=d.actor,
                                    reason=d.reason[:400], at=d.at, ledger_entry_hash=d.ledger_entry_hash)
                       for d in c.decisions],
            snapshot_hash=c.snapshot_hash))

    # ------------------------------------------------------------- timing
    latencies = [max(0.0, (f.created_at - f.observed_window_end).total_seconds()) for f in alerts]
    first_alert: dict[str, datetime] = {}
    for f in alerts:
        if f.entity_pseudonym not in first_alert or f.observed_window_end < first_alert[f.entity_pseudonym]:
            first_alert[f.entity_pseudonym] = f.observed_window_end
    delays: list[float] = []
    onset_map = {k: v.astimezone(timezone.utc) for k, v in (onsets or {}).items()
                 if v.astimezone(timezone.utc) < per.end}
    for ent, t0 in onset_map.items():
        t1 = first_alert.get(ent)
        if t1 is not None and t1 >= t0:
            delays.append((t1 - t0).total_seconds() / 3600.0)
    timing = DetectionTiming(
        alert_latency_p50_s=_round(_quantile(latencies, 0.5), 1),
        alert_latency_p95_s=_round(_quantile(latencies, 0.95), 1),
        onsets_supplied=len(onset_map), onsets_detected=len(delays),
        detection_delay_median_h=_round(_quantile(delays, 0.5), 2),
        detection_delay_p90_h=_round(_quantile(delays, 0.9), 2))

    # ------------------------------------------------------------- effort
    est: list[float] = []
    est_disp: list[float] = []
    elapsed: list[float] = []
    investigations = 0
    for c in period_cases:
        reached = {d.to_state for d in c.decisions}
        investigated = CaseState.INVESTIGATING in reached
        investigations += investigated
        dispositioned = _case_disposition(c) != "pending"
        m = effort.estimate(evidence_items=len(set(c.evidence_ids)), investigated=investigated,
                            counter_reviewed=c.counter_hypothesis_reviewed, dispositioned=dispositioned)
        est.append(m)
        if dispositioned:
            est_disp.append(m)
        human = sorted(d.at for d in c.decisions if _is_human(d.actor))
        if len(human) >= 2:
            elapsed.append((human[-1] - human[0]).total_seconds() / 3600.0)
    effort_summary = EffortSummary(
        cases=len(period_cases), dispositioned_cases=len(est_disp),
        est_minutes_per_case=_round(sum(est) / len(est), 1) if est else None,
        est_minutes_per_dispositioned_case=_round(sum(est_disp) / len(est_disp), 1) if est_disp else None,
        est_total_hours=round(sum(est) / 60.0, 2), measured_elapsed_median_h=_round(_quantile(elapsed, 0.5), 2),
        model={k: float(v) for k, v in effort.__dict__.items()})

    # ------------------------------------------------------------- cost
    scale = DAYS_PER_MONTH / per.days
    analyst_monthly = sum(est) / 60.0 * cost.analyst_hourly_rate * scale
    llm_monthly = investigations * cost.llm_cost_per_investigation * scale
    protected = cost.protected_devices if cost.protected_devices is not None else (
        coverage.devices_observed if coverage is not None else None)
    lines = [
        CostLine(item="AEGIS license / pilot fee", monthly=cost.license_monthly, basis="operator input"),
        CostLine(item="Infrastructure", monthly=cost.infrastructure_monthly,
                 basis="operator input (hosting or amortized on-prem)"),
        CostLine(item="Other operating cost", monthly=cost.other_monthly, basis="operator input"),
        CostLine(item="Analyst time", monthly=round(analyst_monthly, 2),
                 basis=f"{sum(est) / 60.0:.1f} estimated hours in {per.days:.1f} days x "
                       f"{cost.analyst_hourly_rate:g} {cost.currency}/h, scaled to a month"),
        CostLine(item="LLM-assisted investigation", monthly=round(llm_monthly, 2),
                 basis=f"{investigations} investigations x {cost.llm_cost_per_investigation:g} {cost.currency}"
                       f", scaled to a month"),
    ]
    total = round(sum(line.monthly for line in lines), 2)
    cost_summary = CostSummary(currency=cost.currency, protected_devices=protected, lines=lines, monthly_total=total,
                               per_device_month=(round(total / protected, 4) if protected else None),
                               operator_inputs_configured=cost.configured)

    # ------------------------------------------------------------- ledger + attestation
    report = ledger.verify_report(tenant_id, keyring)
    snap = snapshot(tenant_id, ledger, now) if report.ok else None
    ledger_view = LedgerVerification(
        ok=report.ok, entries_checked=report.entries_checked, signed_entries=report.signed_entries,
        signatures_verified=keyring is not None and report.ok and report.signed_entries == report.entries_checked
        and report.entries_checked > 0,
        head_hash=report.head_hash, first_bad_seq=report.first_bad_seq, reason=report.reason,
        snapshot_id=snap["snapshot_id"] if snap else None, snapshot_hash=snap["snapshot_hash"] if snap else None,
        snapshot_as_of=snap["as_of"] if snap else None)
    attestation = _attest(tenant_id, docstore, ledger, per, now, report.ok)

    # ------------------------------------------------------------- validation
    validation = _validate(ground_truth, dd_disp, ground_truth_source, per) if ground_truth else None

    detector_versions = sorted({f.detector_version for f in findings})
    operator = operator_name or tenant_id
    pov = PovReport(
        tenant_id=tenant_id, operator_name=operator, period_start=per.start, period_end=per.end,
        period_days=round(per.days, 3), generated_at=now, headline="", summary=[],
        coverage=coverage.to_dict() if coverage is not None else None, alerts=alert_summary,
        dispositions=dispositions, false_alerts=fa, threat_classes=classes, device_classes=device_rows,
        daily=daily, top_cases=views, evidence=evidence_cov, timing=timing, effort=effort_summary,
        cost=cost_summary, attestation=attestation, ledger=ledger_view, validation=validation,
        detector_versions=detector_versions, methodology=[], limitations=[])
    pov.headline, pov.summary = _executive_summary(pov)
    pov.methodology = _methodology(pov)
    pov.limitations = _limitations(pov)
    pov.fingerprint = report_fingerprint(pov)
    return pov


def report_fingerprint(pov: PovReport) -> str:
    """SHA-256 of the report content (canonical JSON, fingerprint field excluded)."""
    body = pov.model_dump(mode="json", by_alias=True)
    body.pop("fingerprint", None)
    return sha256_hex(body)


def _round(v: float | None, digits: int) -> float | None:
    return None if v is None else round(v, digits)


def _attest(tenant_id: str, docstore: DocStore, ledger: Ledger, per: ReportPeriod, now: datetime,
            ledger_ok: bool) -> Attestation:
    entries = ledger.entries(tenant_id, as_of=now)
    live = dry = refused = rolled_back = proposed = authz = executed = 0
    for e in entries:
        p = e.payload
        if e.entry_type in _EXEC_TYPES:
            # MIRROR executor convention: an "intent" entry precedes every adapter call and an
            # "outcome" entry records its status. Anything unrecognised counts as live (fail closed).
            if p.get("phase") == "intent":
                continue
            status = str(p.get("status", "")).lower()
            if p.get("dry_run") is True or status == "dry_run":
                dry += 1
            elif status in _NOT_ENFORCED_STATUSES:
                refused += 1
            elif status == "rolled_back":
                rolled_back += 1
            else:
                live += 1
        elif e.entry_type == EntryType.ACTION:
            proposed += 1
        elif e.entry_type == EntryType.AUTHORIZATION:
            authz += 1
        elif e.entry_type == EntryType.CASE_TRANSITION and p.get("to_state") == CaseState.EXECUTED.value:
            executed += 1
    active: list[str] = []
    shadow = 0
    for pol in docstore.iter_all(OperatorPolicy, tenant_id):
        overlaps = pol.valid_from < now and pol.valid_until > per.start
        if pol.mode == "active" and overlaps:
            active.append(pol.policy_id)
        elif pol.mode == "shadow":
            shadow += 1
    scope = (f"entire provenance ledger of tenant {tenant_id} from genesis to "
             f"{now.strftime('%Y-%m-%d %H:%M UTC')} ({len(entries)} entries)")
    if not ledger_ok:
        status, statement = "unverifiable", (
            "The provenance ledger failed integrity verification, so absence of enforcement cannot be attested. "
            "Investigate the ledger before relying on this report.")
    elif live or executed:
        status, statement = "enforcement_recorded", (
            f"The ledger records {live} live enforcement execution(s) and {executed} case(s) moved to EXECUTED. "
            "Each is listed in the ledger with its signed operator policy, authorization and MIRROR result.")
    else:
        status, statement = "attested", (
            "No enforcement action was executed: the verified ledger contains no live execution record and no "
            "case reached EXECUTED. AEGIS operated read-only (alerts and reports only)"
            + (", and no active-mode operator policy was loaded." if not active else
               "; note that an active-mode operator policy was loaded but never used."))
    return Attestation(status=status, statement=statement, scope=scope, live_executions=live,  # type: ignore[arg-type]
                       dry_run_executions=dry, refused_or_failed_executions=refused, rollbacks=rolled_back,
                       actions_proposed=proposed, authorization_decisions=authz,
                       executed_case_transitions=executed, active_policies=sorted(active), shadow_policies=shadow)


def _validate(truth: Mapping[tuple[str, date], str], dd_disp: Mapping[tuple[str, date], str], source: str,
              per: ReportPeriod) -> Validation:
    tp = fp = fn = tn = 0
    period_dates = set(per.dates())
    for key, label in truth.items():
        if key[1] not in period_dates:
            continue
        pos = label != "benign"
        flagged = key in dd_disp
        tp += pos and flagged
        fn += pos and not flagged
        fp += (not pos) and flagged
        tn += (not pos) and not flagged
    n = tp + fp + fn + tn
    return Validation(source=source, device_days=n, positive_device_days=tp + fn, tp=tp, fp=fp, fn=fn, tn=tn,
                      precision=tp / (tp + fp) if tp + fp else None, recall=tp / (tp + fn) if tp + fn else None,
                      false_alerts_per_10k=_per_10k(fp, n))


# ---------------------------------------------------------------------------- narrative

def _fmt(v: float | None, digits: int = 1, unit: str = "") -> str:
    if v is None:
        return "not measurable"
    return f"{v:,.{digits}f}{unit}"


def _money(v: float | None, currency: str) -> str:
    if v is None:
        return "not measurable"
    return f"{currency} {v:,.4f}" if v < 1 else f"{currency} {v:,.2f}"


def _executive_summary(p: PovReport) -> tuple[str, list[str]]:
    cov = p.coverage
    a, d = p.alerts, p.dispositions
    out: list[str] = []
    if cov:
        out.append(f"Over {p.period_days:g} days AEGIS observed {cov['devices_observed']:,} devices "
                   f"({cov['device_days']:,} device-days) strictly in read-only shadow mode.")
    else:
        out.append(f"Over {p.period_days:g} days AEGIS analysed the operator's telemetry in read-only shadow mode "
                   "(observed device counts were not supplied to this report).")
    if a.alerts:
        out.append(f"{a.alerts:,} alerts on {a.alerted_devices:,} devices ({a.malicious:,} malicious, "
                   f"{a.suspicious:,} suspicious); {a.abstain_for_review:,} further signals were held as ABSTAIN "
                   "for analyst review instead of being guessed.")
        out.append(f"Analyst outcomes per alerting device-day: {d.verified:,} verified, {d.rejected:,} rejected as "
                   f"false, {d.inconclusive:,} inconclusive, {d.pending:,} awaiting review.")
    else:
        out.append(f"No alerts were raised; {a.abstain_for_review:,} uncertain signals were held for review.")
    if p.false_alerts.per_10k is not None:
        txt = (f"False alerts: {p.false_alerts.per_10k:,.1f} per 10,000 device-days (analyst-rejected)")
        if p.false_alerts.unresolved_device_days:
            txt += f", at most {p.false_alerts.per_10k_upper:,.1f} if every unresolved alert proved false"
        if p.false_alerts.budget_per_10k is not None:
            txt += ("; within" if p.false_alerts.within_budget else "; above") + \
                f" the agreed budget of {p.false_alerts.budget_per_10k:g}"
        out.append(txt + ".")
    att = {"attested": "Zero enforcement actions were executed",
           "enforcement_recorded": "Enforcement actions are recorded in the ledger (see attestation)",
           "unverifiable": "Absence of enforcement could not be attested"}[p.attestation.status]
    led = (f"the provenance ledger verified intact across {p.ledger.entries_checked:,} entries"
           if p.ledger.ok else f"the provenance ledger FAILED verification at entry {p.ledger.first_bad_seq}")
    out.append(f"{att}; {led}.")
    eff = p.effort.est_minutes_per_case
    if eff is not None:
        out.append(f"Estimated analyst effort {eff:.0f} minutes per case; cost per protected device-month "
                   f"{_money(p.cost.per_device_month, p.cost.currency)}"
                   + ("" if p.cost.operator_inputs_configured else " (analyst time only; no platform costs entered)")
                   + ".")
    if p.validation is not None:
        v = p.validation
        out.append(f"Against {v.source}: precision {_fmt(v.precision, 3)}, recall {_fmt(v.recall, 3)}, "
                   f"{_fmt(v.false_alerts_per_10k)} false alerts per 10k device-days "
                   f"({v.positive_device_days:,} positive of {v.device_days:,} device-days).")
    if not p.ledger.ok:
        headline = "Ledger integrity failure: treat every figure in this report as unverified"
    elif a.alerts == 0:
        headline = "No compromised-device alerts in the shadow period"
    else:
        headline = (f"{a.alerted_devices:,} devices flagged with cited evidence, "
                    f"{d.verified:,} device-days verified by analysts, zero enforcement"
                    if p.attestation.status == "attested" else
                    f"{a.alerted_devices:,} devices flagged with cited evidence")
    return headline, out


def _methodology(p: PovReport) -> list[str]:
    m = [
        "Telemetry: flow (NetFlow/IPFIX/Zeek) and resolver DNS metadata only. No packet payloads, no TLS "
        "decryption; devices are identified by tenant-keyed pseudonyms, never subscriber identity.",
        "Detection: signed and freshness-checked IOC rules, a calibrated gradient-boosted model, per-device-class "
        "anomaly scoring and change-point detection, combined by a pre-registered fusion policy. Scores are never "
        "averaged across detectors; insufficient context yields ABSTAIN rather than a guess.",
        "Device class, vendor, IPTV app usage and geography are never sufficient to flag a device.",
        "Alerting unit: a device-day (pseudonymous device x UTC calendar day). A device-day is a false alert when "
        "every alert on it was rejected by an analyst in the case workflow.",
        "False alerts per 10k device-days = rejected alerting device-days / observed device-days x 10,000. "
        "The upper bound additionally counts every pending or inconclusive device-day as false.",
        "Alert latency = finding creation time minus the end of the evidence window. Detection delay = first alert "
        "minus a confirmed compromise onset, and is only reported where onsets were supplied.",
        "Analyst minutes per case are estimated with the effort model shown in the report (triage, evidence review, "
        "investigation, counter-hypothesis review, disposition), not measured with a stopwatch.",
        "Every finding cites evidence ids. Evidence integrity is re-verified for this report: each record's content "
        "hash must match both the stored document and its provenance ledger entry.",
        "The provenance ledger is hash-chained per tenant"
        + (" and Ed25519-signed; signatures were verified against the trusted keyring." if p.ledger.signatures_verified
           else "; signatures were not verified for this report (no trusted keyring supplied or entries unsigned)."),
    ]
    if p.detector_versions:
        m.append("Detector versions in this period: " + ", ".join(p.detector_versions[:6])
                 + (" ..." if len(p.detector_versions) > 6 else ""))
    return m


def _limitations(p: PovReport) -> list[str]:
    lim = [
        "Shadow-mode results describe this network, this period and these detector versions only. They are not a "
        "claim of superiority over any other product and do not predict performance on other networks.",
        "Recall cannot be measured from shadow operation alone: compromised devices that raised no alert are, by "
        "construction, not in the case workflow. Use red-team injection or an independent label source to measure it.",
    ]
    if p.false_alerts.unresolved_device_days:
        lim.append(f"{p.false_alerts.unresolved_device_days:,} alerting device-days were not yet resolved by "
                   "analysts, so the measured false-alert rate is a lower bound; the upper bound is shown alongside.")
    if p.coverage is None:
        lim.append("Observed device and device-day counts were not supplied, so per-device-day rates and cost per "
                   "device-month are not measurable in this report.")
    if p.timing.onsets_supplied == 0:
        lim.append("No confirmed compromise onset times were supplied, so detection delay is not reported; alert "
                   "latency (pipeline time) is reported instead.")
    if not p.cost.operator_inputs_configured:
        lim.append("No platform, infrastructure or other operating costs were entered; cost per protected "
                   "device-month reflects estimated analyst time only.")
    if p.validation is not None:
        lim.append(f"The validation section uses {p.validation.source}. Synthetic or injected activity is easier to "
                   "separate than real-world compromise; treat those figures as a functional check, not field accuracy.")
    if p.evidence.evidence_integrity_failures or p.evidence.evidence_missing:
        lim.append(f"{p.evidence.evidence_integrity_failures} evidence record(s) failed integrity verification and "
                   f"{p.evidence.evidence_missing} were missing; findings relying on them must be re-reviewed.")
    lim.append("Base rates matter: at low prevalence even a small false-positive rate can outnumber true detections. "
               "Rates here are per device-day so they can be compared with the operator's own false-alert budget.")
    return lim


# ---------------------------------------------------------------------------- rendering

def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html", "j2"]),
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    env.filters["num"] = lambda v, d=0: "n/a" if v is None else (f"{v:,.{d}f}")
    env.filters["pct"] = lambda v, d=1: "n/a" if v is None else f"{100 * v:.{d}f}%"
    env.filters["short"] = lambda h, n=12: (h or "")[:n]
    env.filters["dt"] = lambda v: "n/a" if v is None else v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    env.filters["d"] = lambda v: v.strftime("%Y-%m-%d")
    env.filters["label"] = lambda s: str(s).replace("_", " ")
    env.filters["money"] = _money
    return env


def render_pov_html(pov: PovReport) -> str:
    """Render a collected :class:`PovReport` to self-contained HTML."""
    rows = [charts.BarRow(
        label=r.label.replace("_", " "),
        segments=(charts.Segment("verified", r.verified, STATUS["good"]),
                  charts.Segment("rejected (false)", r.rejected, STATUS["critical"]),
                  charts.Segment("pending / inconclusive", r.pending, STATUS["neutral"])))
        for r in pov.threat_classes if r.malicious + r.suspicious > 0]
    classes_svg = charts.hbar_chart(rows, aria_label="alerts by threat class and analyst outcome",
                                    empty_message="No alerts in this period")
    daily_svg = charts.column_chart(
        [d.day.strftime("%b %d") for d in pov.daily],
        [("malicious", [d.malicious for d in pov.daily], SERIES[7]),
         ("suspicious", [d.suspicious for d in pov.daily], SERIES[3]),
         ("abstain (held for review)", [d.abstain for d in pov.daily], "#b9b7ae")],
        aria_label="findings per day by verdict", empty_message="No findings in this period")
    dev_rows = [charts.BarRow(label=r.device_class.replace("_", " "),
                              segments=(charts.Segment("alerted devices", r.alerted_devices, SERIES[0]),),
                              note=(f"of {r.devices_observed:,}" if r.devices_observed is not None else ""))
                for r in pov.device_classes]
    devices_svg = charts.hbar_chart(dev_rows, aria_label="alerted devices by device class",
                                    empty_message="No device classes observed")
    html = _env().get_template("pov.html.j2").render(
        p=pov, css=BASE_CSS, classes_svg=classes_svg, daily_svg=daily_svg, devices_svg=devices_svg,
        series=SERIES, status=STATUS)
    return html


def build_pov_report(tenant_id: str, docstore: DocStore, ledger: Ledger,
                     period: ReportPeriod | tuple[datetime, datetime], **kwargs: Any) -> str:
    """Collect and render the shadow proof-of-value report (self-contained HTML).

    Keyword arguments are those of :func:`collect_pov_report` (``keyring``, ``coverage``,
    ``cost``, ``effort``, ``onsets``, ``ground_truth``, ``false_alert_budget_per_10k``,
    ``operator_name``, ``generated_at``, ``top_cases`` ...).
    """
    return render_pov_html(collect_pov_report(tenant_id, docstore, ledger, period, **kwargs))


__all__ = ["DAYS_PER_MONTH", "build_pov_report", "collect_pov_report", "device_day_of", "render_pov_html",
           "report_fingerprint"]
