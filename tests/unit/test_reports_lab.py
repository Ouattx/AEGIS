"""The lab pilot drives the real pipeline end to end and feeds the PoV report."""
from __future__ import annotations

import json

import pytest

from aegis.contracts.models import CaseState, Finding, Verdict
from aegis.reports import CostInputs, collect_pov_report, render_pov_html
from aegis.reports.__main__ import load_keyring, main, parse_when
from aegis.reports.lab import ANALYST, LAB_LABEL_SOURCE, run_lab_pilot
from aegis.oracle.state_machine import CaseService
from aegis.sentinel.model import load_default


@pytest.fixture(scope="module")
def pilot():
    return run_lab_pilot(seed=21, n_devices=50, days=2, malicious_fraction=0.12, model=load_default())


def test_pilot_populates_stores(pilot):
    stored = list(pilot.docstore.iter_all(Finding, pilot.tenant_id))
    assert len(stored) == len(pilot.findings) > 0
    alerts = [f for f in pilot.findings if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
    # one incident, one case: every alerting device has exactly one case
    assert pilot.cases_opened == len({f.entity_pseudonym for f in alerts})
    assert sum(pilot.dispositions.values()) == pilot.cases_opened
    cases = CaseService(pilot.docstore, pilot.evidence_store, pilot.ledger).list_cases(pilot.tenant_id)
    assert all(c.state in (CaseState.VERIFIED, CaseState.REJECTED, CaseState.INCONCLUSIVE) for c in cases)
    assert all(d.actor == ANALYST for c in cases for d in c.decisions)
    assert pilot.ledger.verify_chain(pilot.tenant_id, pilot.keyring) == (True, None)
    assert pilot.coverage.devices_observed == 50


def test_pilot_report_end_to_end(pilot):
    p = collect_pov_report(pilot.tenant_id, pilot.docstore, pilot.ledger, pilot.period, keyring=pilot.keyring,
                           coverage=pilot.coverage, cost=CostInputs(license_monthly=500), onsets=pilot.onsets,
                           ground_truth=pilot.ground_truth, ground_truth_source=LAB_LABEL_SOURCE,
                           false_alert_budget_per_10k=25)
    assert p.ledger.ok and p.ledger.signatures_verified
    assert p.attestation.status == "attested" and p.attestation.live_executions == 0
    assert p.alerts.alerts > 0 and p.top_cases
    assert p.evidence.evidence_integrity_failures == 0 and p.evidence.evidence_missing == 0
    assert p.evidence.alerts_with_evidence == p.alerts.alerts
    assert p.validation is not None and p.validation.device_days == len(pilot.ground_truth)
    assert p.timing.onsets_supplied > 0
    assert p.effort.cases == pilot.cases_opened
    assert all(e.integrity == "verified" for c in p.top_cases for e in c.evidence)
    html = render_pov_html(p)
    assert "simulated analyst" in html


def test_cli_lab_and_render(tmp_path, pilot, monkeypatch):
    import aegis.reports.lab as lab_mod
    monkeypatch.setattr(lab_mod, "run_lab_pilot", lambda **kw: pilot)
    out, js = tmp_path / "pov.html", tmp_path / "pov.json"
    cost = tmp_path / "cost.json"
    cost.write_text(json.dumps({"license_monthly": 900, "currency": "EUR"}))
    assert main(["lab", "--out", str(out), "--json", str(js), "--cost", str(cost)]) == 0
    assert out.read_text().startswith("<!doctype html>")
    data = json.loads(js.read_text())
    assert data["schema"] == "aegis.pov_report/1" and data["cost"]["currency"] == "EUR"


def test_cli_render_from_database(tmp_path):
    db = tmp_path / "aegis.db"
    url = f"sqlite:///{db}"
    p = run_lab_pilot(seed=22, n_devices=30, days=1, malicious_fraction=0.1, model=None, database_url=url,
                      investigate=False)
    keys = tmp_path / "keys"
    keys.mkdir()
    signer_key = next(iter(p.ledger.entries(p.tenant_id))).signer_key_id
    (keys / f"{signer_key}.pem").write_bytes(p.ledger.signer.public_pem())
    cov = tmp_path / "cov.json"
    cov.write_text(json.dumps(p.coverage.to_dict()))
    out = tmp_path / "r.html"
    assert main(["render", "--db", url, "--tenant", p.tenant_id, "--start", p.period.start.isoformat(),
                 "--end", p.period.end.date().isoformat(), "--coverage", str(cov), "--keyring-dir", str(keys),
                 "--out", str(out)]) == 0
    html = out.read_text()
    assert "Hash chain intact" in html and "signature verified" in html.lower()


def test_cli_helpers(tmp_path):
    assert parse_when("2026-10-01").tzinfo is not None
    assert parse_when("2026-10-01T05:00:00Z").hour == 5
    with pytest.raises(SystemExit):
        load_keyring(tmp_path)
