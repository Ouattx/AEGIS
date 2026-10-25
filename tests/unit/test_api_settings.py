"""Environment-driven settings and their fail-closed validation."""
from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.api.settings import ENV_VARS, Settings, SettingsError


def test_defaults_require_oidc_configuration():
    with pytest.raises(SettingsError):
        Settings.from_env({})
    s = Settings.from_env({"AEGIS_OIDC_ISSUER": "https://idp", "AEGIS_OIDC_AUDIENCE": "aegis"})
    assert s.auth_mode == "oidc" and s.oidc_algorithms == ("RS256",)


def test_env_parsing(tmp_path):
    env = {"AEGIS_AUTH_MODE": "dev", "AEGIS_DATA_DIR": str(tmp_path), "AEGIS_LLM_ENABLED": "false",
           "AEGIS_CORS_ORIGINS": "https://a.example, https://b.example", "AEGIS_RATE_LIMIT_RPS": "5.5",
           "AEGIS_RATE_LIMIT_BURST": "9", "AEGIS_RPZ_RELOAD_COMMAND": "rndc reload rpz.aegis.local",
           "AEGIS_DEMO_TENANT": "demo"}
    s = Settings.from_env(env)
    assert s.data_dir == Path(tmp_path) and s.llm_enabled is False
    assert s.cors_origins == ("https://a.example", "https://b.example")
    assert s.rate_limit_rps == 5.5 and s.rate_limit_burst == 9
    assert s.rpz_reload_command == ("rndc", "reload", "rpz.aegis.local")
    assert s.resolved_database_url.startswith("sqlite:///") and s.resolved_database_url.endswith("aegis.db")
    assert s.demo_tenant == "demo"


def test_overrides_win_over_env(tmp_path):
    s = Settings.from_env({"AEGIS_AUTH_MODE": "dev", "AEGIS_DATA_DIR": "/nope"}, data_dir=tmp_path)
    assert s.data_dir == tmp_path


@pytest.mark.parametrize("env", [
    {"AEGIS_ENV": "production", "AEGIS_AUTH_MODE": "dev"},
    {"AEGIS_AUTH_MODE": "dev", "AEGIS_LLM_ENABLED": "maybe"},
    {"AEGIS_AUTH_MODE": "dev", "AEGIS_ENFORCEMENT_ADAPTER": "rpz"},
    {"AEGIS_AUTH_MODE": "dev", "AEGIS_ENFORCEMENT_ADAPTER": "webhook", "AEGIS_WEBHOOK_URL": "https://x"},
    {"AEGIS_AUTH_MODE": "dev", "AEGIS_DEV_JWT_SECRET": "short"},
    {"AEGIS_AUTH_MODE": "oidc", "AEGIS_OIDC_ISSUER": "https://idp", "AEGIS_OIDC_AUDIENCE": "a",
     "AEGIS_OIDC_ALGORITHMS": "HS256"},
    {"AEGIS_AUTH_MODE": "oidc", "AEGIS_OIDC_ISSUER": "https://idp", "AEGIS_OIDC_AUDIENCE": "a",
     "AEGIS_DEMO_TENANT": "demo"},
    {"AEGIS_AUTH_MODE": "dev", "AEGIS_RATE_LIMIT_RPS": "0"},
    {"AEGIS_AUTH_MODE": "bogus"},
])
def test_unsafe_or_invalid_configurations_fail_at_startup(env):
    with pytest.raises(SettingsError):
        Settings.from_env(env)


def test_direct_construction_validates_too(tmp_path):
    with pytest.raises(ValidationError):
        Settings(env="production", auth_mode="dev", data_dir=tmp_path)


def test_public_summary_has_no_secrets(tmp_path):
    s = Settings(auth_mode="dev", data_dir=tmp_path, dev_jwt_secret="z" * 40, webhook_secret="w" * 40,
                 metrics_token="m" * 20)
    text = repr(s.public_summary())
    assert "z" * 40 not in text and "w" * 40 not in text and "m" * 20 not in text


def test_every_field_has_an_env_var():
    assert set(ENV_VARS) <= set(Settings.model_fields)
    assert all(v.startswith("AEGIS_") for v in ENV_VARS.values())


@pytest.mark.parametrize("env, issuer, jwks, ok", [
    ("development", "https://idp.example", None, True),
    ("development", "http://idp.example", None, False),
    ("development", "http://localhost:8080/realms/a", None, True),
    ("production", "http://localhost:8080/realms/a", None, False),
    ("production", "https://idp.example", "http://idp.example/certs", False),
    ("production", "https://idp.example", "https://idp.example/certs", True),
])
def test_oidc_urls_must_be_https(env, issuer, jwks, ok, tmp_path):
    kw = dict(env=env, auth_mode="oidc", oidc_issuer=issuer, oidc_audience="aegis", oidc_jwks_url=jwks,
              data_dir=tmp_path)
    if ok:
        Settings(**kw)
    else:
        with pytest.raises((SettingsError, ValidationError), match="https"):
            Settings(**kw)


def test_discovered_jwks_uri_must_be_https(tmp_path):
    import httpx

    from aegis.api.auth import AuthError, JWKSCache

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jwks_uri": "http://idp.example/certs"})

    s = Settings(env="production", auth_mode="oidc", oidc_issuer="https://idp.example", oidc_audience="a",
                 data_dir=tmp_path)
    cache = JWKSCache(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(AuthError):
        cache._discover()
