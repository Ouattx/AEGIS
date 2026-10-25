from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from aegis.contracts.models import (
    ActionType,
    CaseState,
    Evidence,
    EvidenceKind,
    Finding,
    OperatorPolicy,
    Verdict,
)
from aegis.oracle.state_machine import CaseService
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import ChainReport, EntryType, Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.reports import (
    AnalystEffortModel,
    CostInputs,
    CoverageStats,
    PovReport,
    ReportPeriod,
    build_pov_report,
    collect_pov_report,
    device_day_of,
    render_pov_html,
)
from aegis.storage.db import DocRow, DocStore, init_db, make_engine, make_session_factory

T = "isp-a"
START = datetime(2026, 10, 1, tzinfo=timezone.utc)
PERIOD = ReportPeriod(START, START + timedelta(days=3))
GEN = datetime(2026, 10, 10, tzinfo=timezone.utc)
ANALYST = "analyst:alice"


class Env:
    def __init__(self, signed: bool = True):
        engine = make_engine("sqlite://")
        init_db(engine)
        self.sf = make_session_factory(engine)
        self.signer = Signer.generate("ledger-key") if signed else None
        self.keyring = KeyRing()
        if self.signer is not None:
            self.keyring.add(self.signer.key_id, self.signer.public_pem())
        self.ledger = Ledger(self.sf, signer=self.signer)
        self.docs = DocStore(self.sf)
        self.evidence = EvidenceStore(self.docs, self.ledger)
        self.cases = CaseService(self.docs, self.evidence, self.ledger)

    def finding(self, entity: str, end: datetime, *, tenant: str = T, verdict: Verdict = Verdict.MALICIOUS,
                label: str = "c2_beaconing", device_class: str = "android_tv", score: float = 0.95,
                groups: tuple[str, ...] = ("operator-telemetry", "grp:alpha"), explanation: str = "test finding",
                created_at: datetime | None = None) -> Finding:
        evs = []
        for g in groups:
            kind = EvidenceKind.IOC_MATCH if g.startswith("grp:") else EvidenceKind.OBSERVATION
            evs.append(self.evidence.append(Evidence(
                tenant_id=tenant, kind=kind, origin_source=f"src:{g}", source_independence_group=g,
                collected_at=end, summary=f"{kind.value} for {entity}", authorization_id="auth-1",
                payload={"entity_pseudonym": entity, "verified_contact": True, "effective_confidence": 0.9,
                         "signed_bundle_verified": True})))
        f = Finding(tenant_id=tenant, entity_pseudonym=entity, device_class=device_class, detector_version="sentinel/test",
                    label=label, verdict=verdict, score=score, calibration_id="iso-1",
                    observed_window_start=end - timedelta(hours=24), observed_window_end=end,
                    evidence_ids=[e.evidence_id for e in evs], explanation=explanation,
                    created_at=created_at or end + timedelta(seconds=40), expires_at=end + timedelta(days=3))
        self.docs.put(f)
        return f

    def disposition(self, f: Finding, to: CaseState) -> None:
        case = self.cases.open_case(f)
        self.cases.transition(f.tenant_id, case.case_id, CaseState.TRIAGE, ANALYST, "triage")
        self.cases.transition(f.tenant_id, case.case_id, CaseState.INVESTIGATING, ANALYST, "investigate")
        if to is CaseState.INVESTIGATING:
            return
        self.cases.record_counter_hypothesis_review(f.tenant_id, case.case_id, reviewer=ANALYST,
                                                    alternatives=["benign streaming"], notes="reviewed")
        self.cases.transition(f.tenant_id, case.case_id, to, ANALYST, f"decided {to.value}")


def cov(devices: int = 100, days: int = 3, by_class: dict[str, int] | None = None) -> CoverageStats:
    by_class = by_class or {"android_tv": devices}
    return CoverageStats(devices_observed=devices, device_days=devices * days, events=devices * 1000,
                         devices_by_class=by_class,
                         device_days_by_class={k: v * days for k, v in by_class.items()}, sources=("netflow",))


def collect(env: Env, **kw) -> PovReport:
    kw.setdefault("keyring", env.keyring)
    kw.setdefault("generated_at", GEN)
    return collect_pov_report(T, env.docs, env.ledger, PERIOD, **kw)


# ---------------------------------------------------------------------------- basics

def test_empty_tenant_report_is_honest():
    env = Env()
    p = collect(env, coverage=cov())
    assert p.alerts.alerts == 0
    assert p.headline == "No compromised-device alerts in the shadow period"
    assert p.false_alerts.per_10k == 0.0
    assert p.attestation.status == "attested"
    assert p.ledger.ok and p.ledger.entries_checked == 0
    assert p.effort.est_minutes_per_case is None
    html = render_pov_html(p)
    assert "No alerts in this period" in html


def test_device_day_attribution_uses_last_instant_of_window():
    env = Env()
    f = env.finding("p_a", START + timedelta(days=1))  # ends exactly at midnight
    assert device_day_of(f) == ("p_a", date(2026, 10, 1))


def test_period_and_tenant_scoping():
    env = Env()
    env.finding("p_in", START + timedelta(hours=30))
    env.finding("p_late", START + timedelta(days=5))
    env.finding("p_other", START + timedelta(hours=30), tenant="isp-b")
    p = collect(env, coverage=cov())
    assert p.alerts.alerts == 1
    assert p.alerts.alerted_devices == 1
    assert all(c.entity_pseudonym == "p_in" for c in p.top_cases)


def test_false_alert_rates_lower_and_upper_bound_and_budget():
    env = Env()
    f1 = env.finding("p_true", START + timedelta(hours=10))
    f2 = env.finding("p_false", START + timedelta(hours=12), label="dga_activity", device_class="smart_tv",
                     verdict=Verdict.SUSPICIOUS, score=0.7)
    env.finding("p_pending", START + timedelta(hours=40))
    env.disposition(f1, CaseState.VERIFIED)
    env.disposition(f2, CaseState.REJECTED)
    coverage = cov(by_class={"android_tv": 60, "smart_tv": 40})
    p = collect(env, coverage=coverage, false_alert_budget_per_10k=50)
    assert (p.dispositions.verified, p.dispositions.rejected, p.dispositions.pending) == (1, 1, 1)
    assert p.false_alerts.device_days == 300
    assert p.false_alerts.per_10k == pytest.approx(1e4 * 1 / 300)
    assert p.false_alerts.per_10k_upper == pytest.approx(1e4 * 2 / 300)
    assert p.false_alerts.per_device_class["smart_tv"] == pytest.approx(1e4 * 1 / 120)
    assert p.false_alerts.per_device_class["android_tv"] == 0.0
    assert p.false_alerts.within_budget is True
    assert any("lower bound" in lim for lim in p.limitations)
    p2 = collect(env, coverage=coverage, false_alert_budget_per_10k=10)
    assert p2.false_alerts.within_budget is False


def test_device_day_takes_strongest_disposition():
    env = Env()
    a = env.finding("p_x", START + timedelta(hours=5))
    b = env.finding("p_x", START + timedelta(hours=9), label="dga_activity")
    env.disposition(a, CaseState.REJECTED)
    env.disposition(b, CaseState.VERIFIED)
    p = collect(env, coverage=cov())
    assert p.alerts.alerted_device_days == 1
    assert p.dispositions.verified == 1 and p.dispositions.rejected == 0
    assert p.false_alerts.rejected_device_days == 0


def test_abstain_findings_are_not_alerts():
    env = Env()
    env.finding("p_ab", START + timedelta(hours=5), verdict=Verdict.ABSTAIN, score=0.4)
    p = collect(env, coverage=cov())
    assert p.alerts.alerts == 0 and p.alerts.abstain_for_review == 1
    assert p.threat_classes[0].abstain == 1


def test_threat_classes_and_evidence_coverage():
    env = Env()
    f = env.finding("p_1", START + timedelta(hours=5))
    env.finding("p_2", START + timedelta(hours=6), groups=("operator-telemetry",))
    env.disposition(f, CaseState.VERIFIED)
    p = collect(env, coverage=cov())
    row = next(r for r in p.threat_classes if r.label == "c2_beaconing")
    assert row.malicious == 2 and row.devices == 2 and row.verified == 1 and row.pending == 1
    assert row.evidence_items == 3
    assert row.max_independent_origins == 2
    assert p.evidence.alerts_with_evidence == 2
    assert p.evidence.alerts_with_two_origins == 1
    assert p.evidence.evidence_integrity_failures == 0 and p.evidence.evidence_missing == 0


def test_tampered_and_missing_evidence_detected():
    env = Env()
    f = env.finding("p_t", START + timedelta(hours=5))
    env.disposition(f, CaseState.VERIFIED)
    with env.sf.begin() as s:
        row = s.get(DocRow, ("Evidence", f.evidence_ids[0]))
        body = dict(row.body)
        body["summary"] = "rewritten after the fact"
        s.execute(update(DocRow).where(DocRow.kind == "Evidence", DocRow.id == f.evidence_ids[0]).values(body=body))
    ghost = f.model_copy(update={"finding_id": "ghost", "evidence_ids": ["does-not-exist"],
                                 "entity_pseudonym": "p_g"})
    env.docs.put(ghost)
    p = collect(env, coverage=cov())
    assert p.evidence.evidence_integrity_failures == 1
    assert p.evidence.evidence_missing == 1
    case = next(c for c in p.top_cases if c.entity_pseudonym == "p_t")
    assert {e.integrity for e in case.evidence} == {"tampered", "verified"}
    assert any("integrity" in lim for lim in p.limitations)
    assert "tampered" in render_pov_html(p)


# ---------------------------------------------------------------------------- top cases

def test_top_cases_order_and_trail():
    env = Env()
    low = env.finding("p_low", START + timedelta(hours=5), verdict=Verdict.SUSPICIOUS, score=0.4)
    high = env.finding("p_high", START + timedelta(hours=6), score=0.99)
    env.disposition(low, CaseState.REJECTED)
    env.disposition(high, CaseState.VERIFIED)
    p = collect(env, coverage=cov(), top_cases=1)
    assert len(p.top_cases) == 1
    c = p.top_cases[0]
    assert c.entity_pseudonym == "p_high" and c.state == "VERIFIED" and c.severity == "critical"
    assert [d.to_state for d in c.decisions] == ["TRIAGE", "INVESTIGATING", "VERIFIED"]
    assert all(d.ledger_entry_hash and len(d.ledger_entry_hash) == 64 for d in c.decisions)
    assert c.snapshot_hash is not None
    assert c.calibrated is True and c.independent_origins == 2


# ---------------------------------------------------------------------------- timing, effort, cost

def test_alert_latency_and_detection_delay():
    env = Env()
    env.finding("p_1", START + timedelta(hours=10), created_at=START + timedelta(hours=10, seconds=30))
    env.finding("p_2", START + timedelta(hours=20), created_at=START + timedelta(hours=20, seconds=90))
    onsets = {"p_1": START + timedelta(hours=8), "p_2": START + timedelta(hours=16), "p_3": START}
    p = collect(env, coverage=cov(), onsets=onsets)
    assert p.timing.alert_latency_p50_s == pytest.approx(60.0)
    assert p.timing.onsets_supplied == 3 and p.timing.onsets_detected == 2
    assert p.timing.detection_delay_median_h == pytest.approx(3.0)
    p2 = collect(env, coverage=cov())
    assert p2.timing.detection_delay_median_h is None
    assert any("detection delay is not reported" in lim for lim in p2.limitations)


def test_effort_estimate_matches_model():
    env = Env()
    f = env.finding("p_1", START + timedelta(hours=5))
    env.disposition(f, CaseState.VERIFIED)
    pending = env.finding("p_2", START + timedelta(hours=6))
    env.cases.open_case(pending)
    model = AnalystEffortModel(triage_minutes=5, minutes_per_evidence_item=1, investigation_minutes=10,
                               counter_hypothesis_minutes=4, disposition_minutes=1)
    p = collect(env, coverage=cov(), effort=model)
    full = 5 + 2 * 1 + 10 + 4 + 1
    bare = 5 + 2 * 1
    assert p.effort.cases == 2 and p.effort.dispositioned_cases == 1
    assert p.effort.est_minutes_per_case == pytest.approx((full + bare) / 2)
    assert p.effort.est_minutes_per_dispositioned_case == pytest.approx(full)
    assert p.effort.est_total_hours == pytest.approx(round((full + bare) / 60, 2))
    assert p.effort.model["triage_minutes"] == 5.0


def test_cost_per_protected_device_month():
    env = Env()
    f = env.finding("p_1", START + timedelta(hours=5))
    env.disposition(f, CaseState.VERIFIED)
    effort = AnalystEffortModel(triage_minutes=30, minutes_per_evidence_item=0, investigation_minutes=30,
                                counter_hypothesis_minutes=0, disposition_minutes=0)
    cost = CostInputs(currency="EUR", license_monthly=1000, infrastructure_monthly=200, other_monthly=50,
                      analyst_hourly_rate=60, llm_cost_per_investigation=0.5, protected_devices=500)
    p = collect(env, coverage=cov(), cost=cost, effort=effort)
    scale = 30.4375 / 3
    analyst = 1.0 * 60 * scale
    llm = 1 * 0.5 * scale
    total = 1000 + 200 + 50 + round(analyst, 2) + round(llm, 2)
    assert p.cost.monthly_total == pytest.approx(total, abs=0.01)
    assert p.cost.per_device_month == pytest.approx(total / 500, abs=1e-3)
    assert p.cost.currency == "EUR" and p.cost.operator_inputs_configured
    p2 = collect(env, coverage=None)
    assert p2.cost.per_device_month is None
    assert p2.false_alerts.per_10k is None
    assert any("not supplied" in lim for lim in p2.limitations)


# ---------------------------------------------------------------------------- attestation + ledger

def test_attestation_counts_dry_runs_but_flags_live_execution():
    env = Env()
    env.ledger.append(T, EntryType.ACTION, "act-1", {"action_id": "act-1"})
    env.ledger.append(T, EntryType.AUTHORIZATION, "act-1", {"action_id": "act-1", "allowed": False})
    env.ledger.append(T, EntryType.EXECUTION, "act-1", {"action_id": "act-1", "dry_run": True})
    env.ledger.append(T, EntryType.EXECUTION, "act-2", {"action_id": "act-2", "status": "dry_run"})
    later = datetime.now(timezone.utc) + timedelta(minutes=1)
    p = collect(env, coverage=cov(), generated_at=later)
    # a report generated before these entries were recorded does not see them
    assert collect(env, coverage=cov(), generated_at=GEN).attestation.dry_run_executions == 0
    a = p.attestation
    assert a.status == "attested" and a.dry_run_executions == 2 and a.live_executions == 0
    assert a.actions_proposed == 1 and a.authorization_decisions == 1
    env.ledger.append(T, EntryType.EXECUTION, "act-3", {"action_id": "act-3", "status": "applied"})
    p2 = collect(env, coverage=cov(), generated_at=datetime.now(timezone.utc) + timedelta(minutes=1))
    assert p2.attestation.status == "enforcement_recorded" and p2.attestation.live_executions == 1
    assert "Enforcement actions are recorded" in " ".join(p2.summary)


def test_attestation_reports_active_policy():
    env = Env()
    env.docs.put(OperatorPolicy(policy_id="pol-active", tenant_id=T, mode="active",
                                allowed_actions=[ActionType.DNS_SINKHOLE], legal_signoff_ref="legal-1",
                                valid_from=START - timedelta(days=1), valid_until=START + timedelta(days=30),
                                signer_key_id="k", signature="s"))
    env.docs.put(OperatorPolicy(policy_id="pol-shadow", tenant_id=T, valid_from=START,
                                valid_until=START + timedelta(days=30), signer_key_id="k", signature="s"))
    p = collect(env, coverage=cov())
    assert p.attestation.active_policies == ["pol-active"]
    assert p.attestation.shadow_policies == 1
    assert p.attestation.status == "attested"
    assert "active-mode operator policy was loaded but never used" in p.attestation.statement


class BrokenLedger(Ledger):
    def verify_report(self, tenant_id, keyring=None, **kw):  # type: ignore[override]
        return ChainReport(False, 3, "entry_hash mismatch", 2, "ab" * 32, 2)


def test_broken_ledger_makes_attestation_unverifiable():
    env = Env()
    env.finding("p_1", START + timedelta(hours=5))
    broken = BrokenLedger(env.sf, signer=env.signer)
    p = collect_pov_report(T, env.docs, broken, PERIOD, keyring=env.keyring, coverage=cov(), generated_at=GEN)
    assert not p.ledger.ok and p.ledger.first_bad_seq == 3
    assert p.attestation.status == "unverifiable"
    assert p.headline.startswith("Ledger integrity failure")
    assert p.ledger.snapshot_hash is None
    html = render_pov_html(p)
    assert "Hash chain broken" in html and "Cannot attest" in html


def test_signature_verification_flag():
    env = Env()
    env.finding("p_1", START + timedelta(hours=5))
    assert collect(env, coverage=cov()).ledger.signatures_verified is True
    assert collect(env, coverage=cov(), keyring=None).ledger.signatures_verified is False
    unsigned = Env(signed=False)
    unsigned.finding("p_1", START + timedelta(hours=5))
    p = collect(unsigned, coverage=cov(), keyring=None)
    assert p.ledger.ok and p.ledger.signed_entries == 0 and not p.ledger.signatures_verified


def test_validation_against_ground_truth():
    env = Env()
    env.finding("p_tp", START + timedelta(hours=5))
    env.finding("p_fp", START + timedelta(hours=6))
    truth = {("p_tp", date(2026, 10, 1)): "c2_beaconing", ("p_fp", date(2026, 10, 1)): "benign",
             ("p_fn", date(2026, 10, 2)): "dga_activity", ("p_tn", date(2026, 10, 2)): "benign",
             ("p_out", date(2026, 11, 1)): "benign"}
    p = collect(env, coverage=cov(), ground_truth=truth, ground_truth_source="red-team injection")
    v = p.validation
    assert v is not None and (v.tp, v.fp, v.fn, v.tn) == (1, 1, 1, 1)
    assert v.precision == 0.5 and v.recall == 0.5 and v.false_alerts_per_10k == 2500.0
    assert v.source == "red-team injection"
    assert "Comparison with independent labels" in render_pov_html(p)


# ---------------------------------------------------------------------------- rendering

def test_html_is_self_contained_print_ready_and_escaped():
    env = Env()
    f = env.finding("p_1", START + timedelta(hours=5), label="c2_beaconing",
                    explanation="<script>alert('x')</script> beaconing")
    env.disposition(f, CaseState.VERIFIED)
    html = build_pov_report(T, env.docs, env.ledger, PERIOD, keyring=env.keyring, coverage=cov(),
                            generated_at=GEN, operator_name="Example <ISP>")
    assert html.startswith("<!doctype html>")
    assert "<script" not in html.lower()
    assert "&lt;script&gt;" in html
    assert "Example &lt;ISP&gt;" in html
    assert not re.search(r"(src|href)\s*=\s*[\"']?(https?:)?//", html)
    assert "<link" not in html.lower() and "@import" not in html
    assert "@media print" in html and "<svg" in html
    for section in ("Executive summary", "Devices observed", "Findings by threat class", "Top cases",
                    "False alerts per 10k device-days", "Detection delay", "Estimated minutes per case",
                    "Cost per protected device-month", "Zero-enforcement attestation", "Ledger integrity verification",
                    "Methodology", "Limitations"):
        assert section in html, section


def test_fingerprint_is_deterministic_and_content_bound():
    env = Env()
    env.finding("p_1", START + timedelta(hours=5))
    a = collect(env, coverage=cov())
    b = collect(env, coverage=cov())
    assert a.fingerprint == b.fingerprint and len(a.fingerprint) == 64
    c = collect(env, coverage=cov(devices=101))
    assert c.fingerprint != a.fingerprint
    assert f'content="{a.fingerprint}"' in render_pov_html(a)


def test_report_json_roundtrip():
    env = Env()
    f = env.finding("p_1", START + timedelta(hours=5))
    env.disposition(f, CaseState.VERIFIED)
    p = collect(env, coverage=cov())
    data = p.model_dump(mode="json", by_alias=True)
    assert data["schema"] == "aegis.pov_report/1"
    again = PovReport.model_validate(data)
    assert again == p


def test_no_superiority_claims_in_narrative():
    env = Env()
    env.finding("p_1", START + timedelta(hours=5))
    p = collect(env, coverage=cov())
    text = " ".join(p.summary + p.methodology + p.limitations).lower()
    for banned in ("better than", "outperform", "superior to", "best-in-class", "99.5% accuracy"):
        assert banned not in text
    assert "not a claim of superiority" in text


def test_rejects_blank_tenant():
    env = Env()
    with pytest.raises(ValueError):
        collect_pov_report(" ", env.docs, env.ledger, PERIOD)
