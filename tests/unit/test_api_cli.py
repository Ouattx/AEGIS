"""The ``aegis`` command line (everything except the long-running server)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.api.auth import DevVerifier, Role
from aegis.api.settings import Settings
from aegis.cli import build_parser, main
from aegis.contracts.models import OperatorPolicy
from aegis.provenance.signing import KeyRing, verify_model


@pytest.fixture()
def dev_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_AUTH_MODE", "dev")
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("AEGIS_LLM_ENABLED", "false")
    monkeypatch.delenv("AEGIS_ENV", raising=False)
    monkeypatch.delenv("AEGIS_DATABASE_URL", raising=False)
    return tmp_path


def test_parser_has_every_architecture_command():
    sub = next(a for a in build_parser()._actions if a.dest == "cmd")
    assert {"demo", "serve", "ingest", "train", "benchmark", "report", "keys", "policy", "ledger",
            "token", "sources"} <= set(sub.choices)


def test_token_command_mints_verifiable_tokens(dev_env, capsys):
    assert main(["token", "--role", "analyst", "--role", "viewer", "--tenant", "isp-a", "--sub", "alice"]) == 0
    tok = capsys.readouterr().out.strip()
    p = DevVerifier(Settings(auth_mode="dev", data_dir=dev_env / "data")).verify(tok)
    assert p.tenant_id == "isp-a" and p.roles == frozenset({Role.ANALYST, Role.VIEWER}) and p.sub == "alice"


def test_token_command_refused_outside_dev_mode(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AEGIS_AUTH_MODE", "oidc")
    monkeypatch.setenv("AEGIS_OIDC_ISSUER", "https://idp.example")
    monkeypatch.setenv("AEGIS_OIDC_AUDIENCE", "aegis")
    monkeypatch.setenv("AEGIS_DATA_DIR", str(tmp_path))
    assert main(["token", "--role", "admin", "--tenant", "t"]) == 2
    assert "dev" in capsys.readouterr().err


def test_keys_generate_and_policy_sign_roundtrip(dev_env, capsys):
    out = dev_env / "keys"
    assert main(["keys", "generate", "--key-id", "op-2026", "--out-dir", str(out), "--trust", "policy"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["trusted_as"] == "policy"
    priv = Path(info["private_key"])
    assert (priv.stat().st_mode & 0o777) == 0o600
    assert (dev_env / "data" / "trusted" / "policy" / "op-2026.pem").is_file()
    assert main(["keys", "generate", "--key-id", "op-2026", "--out-dir", str(out)]) == 2  # no silent overwrite
    capsys.readouterr()

    policy = {"policy_id": "isp-a-active-1", "tenant_id": "isp-a", "mode": "active",
              "allowed_actions": ["dns_sinkhole"], "valid_from": "2026-01-01T00:00:00Z",
              "valid_until": "2027-01-01T00:00:00Z", "legal_signoff_ref": "LEGAL-1", "signer_key_id": "x"}
    pfile = dev_env / "policy.json"
    pfile.write_text(json.dumps(policy))
    signed_path = dev_env / "signed.json"
    assert main(["policy", "sign", str(pfile), "--key", str(priv), "--key-id", "op-2026",
                 "--out", str(signed_path)]) == 0
    signed = OperatorPolicy.model_validate_json(signed_path.read_text())
    ring = KeyRing()
    ring.add("op-2026", Path(info["public_key"]).read_bytes())
    assert signed.signer_key_id == "op-2026" and verify_model(signed, ring)


def test_sources_ingest_ledger_and_report_commands(dev_env, capsys):
    sample = Path(__file__).resolve().parents[2] / "sample_data" / "lab" / "dns.jsonl"
    assert main(["sources", "add", "--tenant", "isp-a", "--source-id", "dns-1", "--kind", "dns",
                 "--vantage", "device", "--authorization", "auth-1"]) == 0
    capsys.readouterr()
    assert main(["sources", "list", "--tenant", "isp-a"]) == 0
    assert [s["source_id"] for s in json.loads(capsys.readouterr().out)] == ["dns-1"]
    assert main(["ingest", str(sample), "--source", "dns-1", "--tenant", "isp-a"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["events"] == 1895 and result["stats"][0]["quarantined"] == 0
    assert main(["ingest", str(sample), "--source", "missing", "--tenant", "isp-a"]) == 2
    assert main(["ingest", "/no/such/file", "--source", "dns-1", "--tenant", "isp-a"]) == 2
    capsys.readouterr()
    assert main(["ledger", "verify", "--tenant", "isp-a"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    out = dev_env / "report.html"
    assert main(["report", "--tenant", "isp-a", "--out", str(out)]) == 0
    assert "<html" in out.read_text().lower()
    jout = dev_env / "report.json"
    assert main(["report", "--tenant", "isp-a", "--format", "json", "--start", "2026-10-01",
                 "--end", "2026-10-02", "--out", str(jout)]) == 0
    assert json.loads(jout.read_text())["tenant_id"] == "isp-a"
    assert main(["report", "--tenant", "isp-a", "--start", "2026-10-01", "--out", str(jout)]) == 2


def test_demo_no_serve(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("AEGIS_ENV", raising=False)
    monkeypatch.setenv("AEGIS_LLM_ENABLED", "false")
    data = tmp_path / "demo"
    assert main(["demo", "--no-serve", "--devices", "25", "--days", "1", "--data-dir", str(data)]) == 0
    out = capsys.readouterr().out
    assert "AEGIS OMEGA SHIELD demo ready" in out
    for role in ("viewer", "analyst", "approver", "admin", "integration"):
        assert f"  {role}" in out
    tokens = json.loads((data / "demo_tokens.json").read_text())
    p = DevVerifier(Settings(auth_mode="dev", data_dir=data)).verify(tokens["approver"])
    assert p.tenant_id == "demo" and p.roles == frozenset({Role.APPROVER})
    assert (data / ".aegis-demo").is_file()
    # re-running recreates the demo directory; a foreign directory is refused
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "important.txt").write_text("x")
    with pytest.raises(SystemExit):
        main(["demo", "--no-serve", "--devices", "25", "--days", "1", "--data-dir", str(foreign)])
    assert (foreign / "important.txt").is_file()


def test_benchmark_passthrough_reports_missing_harness_gracefully(monkeypatch, capsys):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name.startswith("eval"):
            raise ImportError(name)
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert main(["benchmark", "--quick"]) == 2
    assert "source checkout" in capsys.readouterr().err
