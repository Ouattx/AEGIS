"""Authentication: dev HS256 tokens and OIDC RS256 via a cached JWKS."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from aegis.api.auth import (
    AuthError,
    Authenticator,
    DevVerifier,
    JWKSCache,
    OIDCVerifier,
    Role,
    mint_dev_token,
    parse_roles,
    resolve_dev_secret,
)
from aegis.api.settings import Settings

from test_api_helpers import make_client, make_service

ISSUER = "https://idp.isp-a.example/realms/aegis"
AUDIENCE = "aegis-api"


# ---------------------------------------------------------------------------- dev mode


def dev_settings(tmp_path, **kw):
    return Settings(auth_mode="dev", data_dir=tmp_path, **kw)


def test_dev_token_roundtrip(tmp_path):
    s = dev_settings(tmp_path)
    tok = mint_dev_token(s, sub="alice", tenant_id="isp-a", roles=["analyst", "bogus"])
    p = DevVerifier(s).verify(tok)
    assert p.sub == "alice" and p.tenant_id == "isp-a" and p.roles == frozenset({Role.ANALYST})
    assert p.token_id and p.auth_mode == "dev"


def test_dev_secret_is_persisted_with_private_permissions(tmp_path):
    s = dev_settings(tmp_path)
    a = resolve_dev_secret(s)
    assert resolve_dev_secret(s) == a
    path = tmp_path / "keys" / "dev_jwt_secret"
    assert path.read_text() == a
    assert (path.stat().st_mode & 0o777) == 0o600


def test_dev_token_rejections(tmp_path):
    s = dev_settings(tmp_path, dev_jwt_secret="x" * 40)
    v = DevVerifier(s)
    past = datetime.now(timezone.utc) - timedelta(days=2)
    with pytest.raises(AuthError) as e:
        v.verify(mint_dev_token(s, sub="a", tenant_id="t", roles=["viewer"], ttl_s=60, now=past))
    assert e.value.reason == "token_expired"
    other = dev_settings(tmp_path / "o", dev_jwt_secret="y" * 40)
    with pytest.raises(AuthError) as e:
        v.verify(mint_dev_token(other, sub="a", tenant_id="t", roles=["viewer"]))
    assert e.value.reason == "invalid_token"
    with pytest.raises(AuthError) as e:
        v.verify(jwt.encode({"sub": "a"}, None, algorithm="none"))
    assert e.value.reason == "bad_algorithm"
    base = {"iss": s.dev_issuer, "aud": "aegis-api", "iat": int(time.time()), "exp": int(time.time()) + 60}
    for claims, reason in (({"sub": "agent:verifier", "tenant_id": "t", "roles": ["admin"]}, "invalid_subject"),
                           ({"sub": "system", "tenant_id": "t", "roles": ["admin"]}, "invalid_subject"),
                           ({"sub": "a", "tenant_id": "../etc", "roles": ["admin"]}, "invalid_tenant"),
                           ({"sub": "a", "roles": ["admin"]}, "invalid_tenant"),
                           ({"sub": "a", "tenant_id": "t", "roles": ["root"]}, "no_roles")):
        with pytest.raises(AuthError) as e:
            v.verify(jwt.encode({**base, **claims}, s.dev_jwt_secret, algorithm="HS256"))
        assert e.value.reason == reason, claims


def test_mint_refuses_outside_dev_mode(tmp_path):
    s = Settings(auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE, data_dir=tmp_path)
    with pytest.raises(AuthError):
        mint_dev_token(s, sub="a", tenant_id="t", roles=["admin"])
    with pytest.raises(ValueError):
        mint_dev_token(dev_settings(tmp_path), sub="a", tenant_id="t", roles=["nope"])


def test_parse_roles_accepts_lists_and_strings():
    assert parse_roles("analyst approver,unknown") == frozenset({Role.ANALYST, Role.APPROVER})
    assert parse_roles(["ADMIN", 3, None]) == frozenset({Role.ADMIN})
    assert parse_roles(None) == frozenset()


def test_bearer_header_parsing(tmp_path):
    a = Authenticator(dev_settings(tmp_path))
    for header, reason in ((None, "missing_token"), ("", "missing_token"), ("Basic x", "malformed_authorization"),
                           ("Bearer ", "malformed_authorization"), ("Bearer " + "x" * 20000, "malformed_token")):
        with pytest.raises(AuthError) as e:
            a.authenticate(header)
        assert e.value.reason == reason


# ---------------------------------------------------------------------------- OIDC


class FakeIdP:
    def __init__(self) -> None:
        self.keys: dict[str, rsa.RSAPrivateKey] = {}
        self.jwks_hits = 0
        self.discovery_hits = 0
        self.add_key("k1")

    def add_key(self, kid: str) -> None:
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            self.discovery_hits += 1
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": f"{ISSUER}/protocol/certs"})
        if request.url.path.endswith("/protocol/certs"):
            self.jwks_hits += 1
            keys = []
            for kid, k in self.keys.items():
                jwk = json.loads(RSAAlgorithm.to_jwk(k.public_key()))
                keys.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
            return httpx.Response(200, json={"keys": keys})
        return httpx.Response(404)

    def token(self, kid: str = "k1", **overrides) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "user-123", "tenant_id": "isp-a", "roles": ["analyst"],
                  "iat": now, "exp": now + 300}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.keys[kid], algorithm="RS256", headers={"kid": kid})


@pytest.fixture()
def idp():
    return FakeIdP()


def oidc_settings(tmp_path, **kw):
    return Settings(auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE, data_dir=tmp_path,
                    jwks_min_refresh_interval_s=0, **kw)


def make_verifier(tmp_path, idp, **kw):
    s = oidc_settings(tmp_path, **kw)
    cache = JWKSCache(s, client=httpx.Client(transport=httpx.MockTransport(idp.handler)))
    return OIDCVerifier(s, jwks=cache), cache


def test_oidc_valid_token_with_discovery_and_caching(tmp_path, idp):
    v, _ = make_verifier(tmp_path, idp)
    p = v.verify(idp.token())
    assert (p.sub, p.tenant_id, p.roles, p.auth_mode) == ("user-123", "isp-a", frozenset({Role.ANALYST}), "oidc")
    for _ in range(5):
        v.verify(idp.token())
    assert idp.discovery_hits == 1 and idp.jwks_hits == 1


def test_oidc_rejects_bad_claims(tmp_path, idp):
    v, _ = make_verifier(tmp_path, idp)
    for overrides, reason in (({"aud": "other"}, "invalid_token"), ({"iss": "https://evil.example"}, "invalid_token"),
                              ({"exp": int(time.time()) - 3600}, "token_expired"),
                              ({"tenant_id": None}, "invalid_tenant"), ({"roles": []}, "no_roles"),
                              ({"sub": "agent:planner"}, "invalid_subject")):
        with pytest.raises(AuthError) as e:
            v.verify(idp.token(**overrides))
        assert e.value.reason == reason, overrides


def test_oidc_rejects_symmetric_and_unsigned_tokens(tmp_path, idp):
    v, _ = make_verifier(tmp_path, idp)
    hs = jwt.encode({"sub": "a", "iss": ISSUER, "aud": AUDIENCE}, "secret" * 8, algorithm="HS256",
                    headers={"kid": "k1"})
    with pytest.raises(AuthError) as e:
        v.verify(hs)
    assert e.value.reason == "bad_algorithm"
    with pytest.raises(AuthError) as e:
        v.verify(jwt.encode({"sub": "a"}, None, algorithm="none"))
    assert e.value.reason == "bad_algorithm"
    no_kid = jwt.encode({"sub": "a"}, idp.keys["k1"], algorithm="RS256")
    with pytest.raises(AuthError) as e:
        v.verify(no_kid)
    assert e.value.reason == "missing_kid"


def test_oidc_key_rotation_refreshes_jwks(tmp_path, idp):
    v, _ = make_verifier(tmp_path, idp)
    v.verify(idp.token())
    idp.add_key("k2")
    assert v.verify(idp.token(kid="k2")).sub == "user-123"
    assert idp.jwks_hits == 2


def test_oidc_unknown_kid_refresh_is_rate_limited(tmp_path, idp):
    s = Settings(auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE, data_dir=tmp_path,
                 jwks_min_refresh_interval_s=60)
    clock = [1000.0]
    cache = JWKSCache(s, client=httpx.Client(transport=httpx.MockTransport(idp.handler)), monotonic=lambda: clock[0])
    v = OIDCVerifier(s, jwks=cache)
    v.verify(idp.token())
    forged = FakeIdP()
    forged.add_key("attacker")
    for _ in range(10):
        with pytest.raises(AuthError) as e:
            v.verify(forged.token(kid="attacker"))
        assert e.value.reason == "unknown_key"
    assert idp.jwks_hits == 1
    clock[0] += 61
    with pytest.raises(AuthError):
        v.verify(forged.token(kid="attacker"))
    assert idp.jwks_hits == 2


def test_oidc_jwks_outage_keeps_cached_keys_but_fails_closed_without_them(tmp_path, idp):
    s = Settings(auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE, data_dir=tmp_path,
                 oidc_jwks_url=f"{ISSUER}/protocol/certs", jwks_cache_ttl_s=30)
    clock = [0.0]
    up = [True]

    def handler(request):
        return idp.handler(request) if up[0] else httpx.Response(503)

    cache = JWKSCache(s, client=httpx.Client(transport=httpx.MockTransport(handler)), monotonic=lambda: clock[0])
    v = OIDCVerifier(s, jwks=cache)
    v.verify(idp.token())
    up[0] = False
    clock[0] += 120  # cache expired, IdP down: keep serving with the cached keys
    assert v.verify(idp.token()).sub == "user-123"
    cold = JWKSCache(s, client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(AuthError) as e:
        OIDCVerifier(s, jwks=cold).verify(idp.token())
    assert e.value.reason == "jwks_unavailable"


def test_oidc_end_to_end_through_the_api(tmp_path, idp):
    svc = make_service(tmp_path, auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE,
                       dev_jwt_secret=None, jwks_min_refresh_interval_s=0)
    client = make_client(svc)
    client.app.state.authenticator = Authenticator(
        svc.settings, jwks=JWKSCache(svc.settings, client=httpx.Client(transport=httpx.MockTransport(idp.handler))))
    r = client.get("/api/v1/me", headers={"Authorization": f"Bearer {idp.token(roles='viewer approver')}"})
    assert r.status_code == 200, r.text
    assert r.json()["roles"] == ["approver", "viewer"]
    assert client.get("/api/v1/demo/token?role=admin").status_code == 404
    assert client.get("/api/v1/auth/config").json()["auth_mode"] == "oidc"
    dev = jwt.encode({"sub": "a", "tenant_id": "isp-a", "roles": ["admin"]}, "s" * 48, algorithm="HS256")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {dev}"}).status_code == 401


# ----------------------------------------------------------------------------- console browser sign-in (PKCE)

def _login_app(tmp_path, handler):
    import httpx

    from aegis.api.auth import OIDCLogin
    from test_api_helpers import make_service, make_client

    svc = make_service(tmp_path, auth_mode="oidc", oidc_issuer=ISSUER, oidc_audience=AUDIENCE,
                       oidc_client_id="aegis-console", demo_tenant=None)
    client = make_client(svc)
    client.app.state.oidc_login = OIDCLogin(svc.settings, client=httpx.Client(transport=httpx.MockTransport(handler)))
    return svc, client


def test_console_pkce_login_config_and_token_relay(tmp_path):
    import httpx

    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={"issuer": ISSUER, "authorization_endpoint": f"{ISSUER}/auth",
                                             "token_endpoint": f"{ISSUER}/token",
                                             "end_session_endpoint": f"{ISSUER}/logout"})
        from urllib.parse import parse_qs
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        seen.append(form)
        if form.get("code") == "bad":
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt", "expires_in": 300,
                                         "token_type": "Bearer", "scope": "openid"})

    svc, client = _login_app(tmp_path, handler)
    cfg = client.get("/api/v1/auth/config").json()
    assert cfg["oidc_login"]["client_id"] == "aegis-console"
    assert cfg["oidc_login"]["authorization_endpoint"] == f"{ISSUER}/auth"
    assert "offline_access" in cfg["oidc_login"]["scopes"]
    verifier = "v" * 64
    ok = client.post("/api/v1/auth/token", json={"grant_type": "authorization_code", "code": "c1",
                                                  "code_verifier": verifier,
                                                  "redirect_uri": "http://testserver/auth/callback"})
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"access_token": "at", "refresh_token": "rt", "token_type": "Bearer", "expires_in": 300}
    assert seen[-1] == {"grant_type": "authorization_code", "code": "c1", "code_verifier": verifier,
                        "redirect_uri": "http://testserver/auth/callback", "client_id": "aegis-console"}
    r = client.post("/api/v1/auth/token", json={"grant_type": "refresh_token", "refresh_token": "rt"})
    assert r.status_code == 200 and seen[-1]["grant_type"] == "refresh_token"
    # a foreign redirect URI is refused before anything reaches the IdP
    n = len(seen)
    r = client.post("/api/v1/auth/token", json={"grant_type": "authorization_code", "code": "c1",
                                                 "code_verifier": verifier,
                                                 "redirect_uri": "https://evil.example/auth/callback"})
    assert r.status_code == 422 and len(seen) == n
    r = client.post("/api/v1/auth/token", json={"grant_type": "authorization_code", "code": "bad",
                                                 "code_verifier": verifier,
                                                 "redirect_uri": "http://testserver/auth/callback"})
    assert r.status_code == 401 and r.json()["error"] == "token_exchange_failed"
    assert client.post("/api/v1/auth/token", json={"grant_type": "password"}).status_code == 422
    svc.close()


def test_token_relay_absent_without_a_console_client(tmp_path):
    from test_api_helpers import make_client, make_service

    svc = make_service(tmp_path)
    client = make_client(svc)
    assert client.get("/api/v1/auth/config").json()["oidc_login"] is None
    assert client.post("/api/v1/auth/token", json={"grant_type": "refresh_token",
                                                    "refresh_token": "x"}).status_code == 404
    svc.close()
