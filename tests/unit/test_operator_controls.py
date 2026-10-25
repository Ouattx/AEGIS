"""Operator safety controls reachable in a deployment: action health samples (circuit
breaker auto-rollback), breaker reset, key revocation CLI and the benchmark entry point."""
from __future__ import annotations

import shutil
import subprocess
from datetime import timedelta

import pytest

from aegis.cli import main as cli_main
from aegis.contracts.models import CaseState
from aegis.service import AegisService
from test_api_helpers import (
    auth,
    make_client,
    make_service,
    make_settings,
    operator_signer,
    prepare_enforceable,
    propose_body,
    seed_case,
    signed_policy,
    verify_case,
)

T = "isp-a"


@pytest.fixture()
def svc(tmp_path):
    s = make_service(tmp_path)
    yield s
    s.close()


def _live_action(svc: AegisService) -> tuple[str, str]:
    prepare_enforceable(svc, T)
    svc.load_policy(T, "admin", signed_policy(svc, T, operator_signer(svc)))
    _f, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    body = propose_body(case_id)
    body.pop("expires_in_hours")
    aid = svc.propose_action(T, "ana", expires_at=svc.clock() + timedelta(hours=6), **body).action_id
    svc.simulate_action(T, "ana", aid)
    svc.authorize_action(T, "ana", aid)
    svc.decide_action(T, "bob", aid, approve=True, reason="ok")
    svc.execute_action(T, "bob", aid, reason="go")
    return case_id, aid


def test_health_endpoint_trips_breaker_and_rolls_back(svc: AegisService) -> None:
    case_id, aid = _live_action(svc)
    client = make_client(svc)
    integ = auth(svc, T, "integration", sub="resolver-feed")
    r = client.post(f"/api/v1/actions/{aid}/health", json={"requests": 500, "errors": 2}, headers=integ)
    assert r.status_code == 200 and r.json()["tripped"] is False and r.json()["live"] is True
    r = client.post(f"/api/v1/actions/{aid}/health", json={"requests": 1000, "errors": 600}, headers=integ)
    assert r.status_code == 200, r.text
    assert r.json()["tripped"] is True and r.json()["live"] is False and r.json()["breaker"] == "open"
    case = svc.get_case(T, case_id)
    assert case.state is CaseState.ROLLED_BACK and case.decisions[-1].actor == "system:circuit_breaker"
    status = client.get("/api/v1/enforcement/breaker", headers=auth(svc, T, "viewer")).json()
    assert status["state"] == "open" and status["trips"][0]["action_id"] == aid
    # viewers and analysts cannot report health or reset; approvers reset with a reason
    assert client.post(f"/api/v1/actions/{aid}/health", json={"requests": 1, "errors": 0},
                       headers=auth(svc, T, "analyst")).status_code == 403
    assert client.post("/api/v1/enforcement/breaker/reset", json={"reason": "x"},
                       headers=auth(svc, T, "analyst")).status_code == 403
    r = client.post("/api/v1/enforcement/breaker/reset", json={"reason": "resolver fixed"},
                    headers=auth(svc, T, "approver", sub="bob"))
    assert r.status_code == 200 and r.json()["state"] == "closed"
    resets = [e.payload for e in svc.ledger.entries(T, entry_type="configuration")
              if e.payload.get("event") == "circuit_breaker_reset"]
    assert resets and resets[-1]["actor"] == "bob"


def test_health_validation_and_other_tenant(svc: AegisService) -> None:
    _case_id, aid = _live_action(svc)
    client = make_client(svc)
    integ = auth(svc, T, "integration")
    assert client.post(f"/api/v1/actions/{aid}/health", json={"requests": 1, "errors": 2},
                       headers=integ).status_code == 422
    # another tenant cannot see (or trip) this action
    assert client.post(f"/api/v1/actions/{aid}/health", json={"requests": 1000, "errors": 900},
                       headers=auth(svc, "isp-b", "integration")).status_code == 404
    assert aid in svc.executor.active()


def test_keys_revoke_cli_is_applied_by_the_running_service(tmp_path, monkeypatch, capsys) -> None:
    svc = make_service(tmp_path)
    try:
        seed_case(svc, T)
        signer = operator_signer(svc, "op-key")
        svc.load_policy(T, "admin", signed_policy(svc, T, signer))
        monkeypatch.setenv("AEGIS_AUTH_MODE", "dev")
        monkeypatch.setenv("AEGIS_DEV_JWT_SECRET", "s" * 48)
        assert cli_main(["keys", "revoke", "--kind", "policy", "--key-id", "op-key", "--reason", "leaked",
                         "--data-dir", str(tmp_path)]) == 0
        assert "op-key" in capsys.readouterr().out
        # the live service picks the revocation up on its next sweep, without a restart
        assert svc.list_policies(T)[0]["signature_valid"] is True
        svc.sweep_expired()
        assert svc.policy_keyring.is_revoked("op-key")
        assert svc.list_policies(T)[0]["signature_valid"] is False
        assert svc.refresh_revocations() == []
    finally:
        svc.close()


def test_keys_revoke_cli_requires_a_reason(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_AUTH_MODE", "dev")
    with pytest.raises(SystemExit):
        cli_main(["keys", "revoke", "--kind", "policy", "--key-id", "k", "--data-dir", str(tmp_path)])


def test_demo_and_serve_bind_loopback_by_default() -> None:
    from aegis.cli import build_parser
    p = build_parser()
    assert p.parse_args(["demo"]).host == "127.0.0.1"
    assert p.parse_args(["serve"]).host == "127.0.0.1"


@pytest.mark.skipif(shutil.which("aegis") is None, reason="console script not installed")
def test_benchmark_entry_point_works_outside_the_repo(tmp_path) -> None:
    out = subprocess.run(["aegis", "benchmark", "--help"], cwd=tmp_path, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "--bootstrap" in out.stdout


def test_settings_default_anchor_path(tmp_path) -> None:
    s = make_settings(tmp_path)
    assert s.resolved_ledger_anchor_path == tmp_path / "anchors" / "ledger-heads.jsonl"


def test_model_signatures_use_their_own_trust_directory(tmp_path) -> None:
    """A model publisher key installed under trusted/ledger does not validate a model, and a
    key under trusted/model never validates ledger entries."""
    from aegis.provenance.signing import Signer
    from aegis.sentinel.model import load_default

    publisher = Signer.generate("model-pub")
    model_dir = load_default().save(tmp_path / "signed-model", signer=publisher)
    data = tmp_path / "data"
    (data / "trusted" / "ledger").mkdir(parents=True)
    (data / "trusted" / "ledger" / "model-pub.pem").write_bytes(publisher.public_pem())
    s1 = AegisService(make_settings(data, model_dir=model_dir, model_require_signature=True), use_env_llm=False)
    try:
        assert s1.model is None  # wrong trust purpose: refused, rules-only
    finally:
        s1.close()
    data2 = tmp_path / "data2"
    (data2 / "trusted" / "model").mkdir(parents=True)
    (data2 / "trusted" / "model" / "model-pub.pem").write_bytes(publisher.public_pem())
    s2 = AegisService(make_settings(data2, model_dir=model_dir, model_require_signature=True), use_env_llm=False)
    try:
        assert s2.model is not None
        assert "model-pub" in s2.model_keyring.key_ids() and "model-pub" not in s2.ledger_keyring.key_ids()
    finally:
        s2.close()
