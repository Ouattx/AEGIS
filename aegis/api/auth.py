"""Authentication: bearer JWTs from an OIDC provider (RS256 via JWKS) or dev HS256.

Claims contract (spec section 12, ARCHITECTURE ``aegis.api``)::

    sub        user or service identity (required)
    tenant_id  the single tenant the token may act on (claim name configurable)
    roles      subset of {viewer, analyst, approver, admin, integration}

The tenant of every request comes **only** from the verified token: no route
accepts a tenant id from the URL, query or body. Unknown roles are ignored; a
token with no known role, no tenant or no subject is rejected.

OIDC keys are fetched from the JWKS endpoint (discovered from the issuer's
``/.well-known/openid-configuration`` when not configured), cached for
``jwks_cache_ttl_s`` and refreshed early when a token names an unknown ``kid``
(at most once per ``jwks_min_refresh_interval_s``, so a flood of forged kids
cannot hammer the IdP). Symmetric algorithms are never accepted in OIDC mode.

Dev mode signs with a shared HS256 secret (``AEGIS_DEV_JWT_SECRET`` or a random
secret persisted under the data directory so the CLI and server agree). It is
refused when ``AEGIS_ENV=production``.
"""
from __future__ import annotations

import logging
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import httpx
import jwt

from aegis.api.settings import Settings, secure_idp_url

log = logging.getLogger(__name__)

DEV_AUDIENCE = "aegis-api"
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"
    INTEGRATION = "integration"


ALL_ROLES: tuple[Role, ...] = tuple(Role)


class AuthError(Exception):
    """Authentication failed (HTTP 401). ``reason`` is a stable, non-sensitive code."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason


@dataclass(frozen=True)
class Principal:
    """A verified caller. ``tenant_id`` scopes every store access of the request."""
    sub: str
    tenant_id: str
    roles: frozenset[Role]
    token_id: str | None = None
    auth_mode: str = "oidc"
    claims: dict[str, Any] = field(default_factory=dict, compare=False, hash=False, repr=False)

    def has(self, *roles: Role) -> bool:
        return any(r in self.roles for r in roles)

    @property
    def actor(self) -> str:
        """Identity written to the ledger and case decisions (never an agent identity)."""
        return self.sub

    def public(self) -> dict[str, Any]:
        return {"sub": self.sub, "tenant_id": self.tenant_id,
                "roles": sorted(r.value for r in self.roles), "auth_mode": self.auth_mode}


def parse_roles(value: Any) -> frozenset[Role]:
    """Known roles from a claim that is a list or a space/comma separated string."""
    if isinstance(value, str):
        items: list[Any] = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        return frozenset()
    out = set()
    for item in items:
        if not isinstance(item, str):
            continue
        try:
            out.add(Role(item.strip().lower()))
        except ValueError:
            continue
    return frozenset(out)


def _principal_from_claims(claims: dict[str, Any], *, tenant_claim: str, roles_claim: str,
                           mode: str) -> Principal:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip() or len(sub) > 256:
        raise AuthError("invalid_subject", "token has no valid subject")
    if sub.strip().lower().startswith(("agent:", "system")):
        raise AuthError("invalid_subject", "agent and system identities cannot authenticate to the API")
    tenant = claims.get(tenant_claim)
    if not isinstance(tenant, str) or not _TENANT_RE.match(tenant):
        raise AuthError("invalid_tenant", "token has no valid tenant claim")
    roles = parse_roles(claims.get(roles_claim))
    if not roles:
        raise AuthError("no_roles", "token grants no known role")
    jti = claims.get("jti")
    return Principal(sub=sub.strip(), tenant_id=tenant, roles=roles,
                     token_id=jti if isinstance(jti, str) else None, auth_mode=mode, claims=claims)


def _bearer(authorization: str | None) -> str:
    if not authorization:
        raise AuthError("missing_token", "missing bearer token")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthError("malformed_authorization", "authorization header must be 'Bearer <token>'")
    token = token.strip()
    if len(token) > 16_384:
        raise AuthError("malformed_token", "token too large")
    return token


# ----------------------------------------------------------------------------- dev mode


def dev_secret_path(settings: Settings) -> Path:
    return settings.keys_dir / "dev_jwt_secret"


def resolve_dev_secret(settings: Settings, *, create: bool = True) -> str:
    """The HS256 secret: from settings, else the persisted one (created on first use)."""
    if settings.auth_mode != "dev":
        raise AuthError("dev_mode_disabled", "dev tokens are only available in AEGIS_AUTH_MODE=dev")
    if settings.dev_jwt_secret:
        return settings.dev_jwt_secret
    path = dev_secret_path(settings)
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    if not create:
        raise AuthError("dev_secret_missing", f"no dev secret at {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:  # pragma: no cover - platform dependent
        pass
    value = secrets.token_urlsafe(48)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(value, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)
    return value


def mint_dev_token(settings: Settings, *, sub: str, tenant_id: str, roles: list[str] | tuple[str, ...],
                   ttl_s: int | None = None, now: datetime | None = None) -> str:
    """Mint an HS256 dev token (refused unless ``AEGIS_AUTH_MODE=dev``)."""
    secret = resolve_dev_secret(settings)
    known = parse_roles(list(roles))
    if not known:
        raise ValueError("at least one known role is required")
    if not _TENANT_RE.match(tenant_id):
        raise ValueError("invalid tenant id")
    issued = now or datetime.now(timezone.utc)
    ttl = ttl_s if ttl_s is not None else settings.dev_token_ttl_s
    claims = {
        "iss": settings.dev_issuer, "aud": DEV_AUDIENCE, "sub": sub, "tenant_id": tenant_id,
        "roles": sorted(r.value for r in known), "iat": int(issued.timestamp()),
        "nbf": int(issued.timestamp()), "exp": int((issued + timedelta(seconds=ttl)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, secret, algorithm="HS256")


class DevVerifier:
    """HS256 verifier for development and demonstrations."""

    mode = "dev"

    def __init__(self, settings: Settings):
        self._settings = settings
        self._secret = resolve_dev_secret(settings)

    def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed_token", "token is not a JWT") from exc
        if header.get("alg") != "HS256":
            raise AuthError("bad_algorithm", "dev mode accepts HS256 tokens only")
        try:
            claims = jwt.decode(token, self._secret, algorithms=["HS256"], audience=DEV_AUDIENCE,
                                issuer=self._settings.dev_issuer, leeway=self._settings.jwt_leeway_s,
                                options={"require": ["exp", "iat", "sub"]})
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token_expired", "token expired") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token", "token verification failed") from exc
        return _principal_from_claims(claims, tenant_claim="tenant_id", roles_claim="roles", mode="dev")


# ----------------------------------------------------------------------------- OIDC


class JWKSCache:
    """Thread-safe JWKS cache with TTL and rate-limited refresh on unknown ``kid``."""

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        self._settings = settings
        self._client = client or httpx.Client(timeout=10.0, follow_redirects=False)
        self._mono = monotonic
        self._lock = threading.Lock()
        self._keys: dict[str, jwt.PyJWK] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._jwks_url: str | None = settings.oidc_jwks_url

    def _discover(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        issuer = (self._settings.oidc_issuer or "").rstrip("/")
        resp = self._client.get(f"{issuer}/.well-known/openid-configuration")
        resp.raise_for_status()
        url = resp.json().get("jwks_uri")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise AuthError("jwks_unavailable", "issuer discovery document has no jwks_uri")
        if not secure_idp_url(url, production=self._settings.is_production):
            raise AuthError("jwks_unavailable", "discovered jwks_uri must use https")
        self._jwks_url = url
        return url

    def _fetch(self) -> None:
        self._last_attempt = self._mono()
        resp = self._client.get(self._discover())
        resp.raise_for_status()
        data = resp.json()
        keys: dict[str, jwt.PyJWK] = {}
        for jwk in data.get("keys", []) if isinstance(data, dict) else []:
            if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str):
                continue
            try:
                keys[kid] = jwt.PyJWK(jwk)
            except jwt.PyJWTError:
                log.warning("ignoring unusable JWKS key %s", kid)
        if not keys:
            raise AuthError("jwks_unavailable", "JWKS contains no usable signing keys")
        self._keys = keys
        self._fetched_at = self._mono()

    def get(self, kid: str) -> jwt.PyJWK:
        with self._lock:
            now = self._mono()
            expired = self._fetched_at is None or now - self._fetched_at > self._settings.jwks_cache_ttl_s
            unknown = kid not in self._keys
            may_refresh = (self._last_attempt is None
                           or now - self._last_attempt >= self._settings.jwks_min_refresh_interval_s)
            if expired or (unknown and may_refresh):
                try:
                    self._fetch()
                except AuthError:
                    if not self._keys:
                        raise
                except (httpx.HTTPError, ValueError) as exc:
                    if not self._keys:
                        raise AuthError("jwks_unavailable", "cannot fetch signing keys") from exc
                    log.warning("JWKS refresh failed (%s); using cached keys", type(exc).__name__)
            key = self._keys.get(kid)
            if key is None:
                raise AuthError("unknown_key", "token signed with an unknown key")
            return key


class OIDCLogin:
    """Browser sign-in support for the console: issuer discovery and a token relay.

    The console runs the authorization-code flow with PKCE (it generates and keeps
    the code verifier). The code-for-token exchange and refreshes go through
    :meth:`exchange` so the console needs no cross-origin access to the IdP (strict
    CSP) and a confidential client secret, when an IdP requires one, stays server-side.
    The relay adds nothing to the security decision: PKCE binds the code to the
    browser that started the flow, and every resulting access token is verified on
    each API call like any other.
    """

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        self._settings = settings
        self._client = client or httpx.Client(timeout=10.0, follow_redirects=False)
        self._mono = monotonic
        self._lock = threading.Lock()
        self._doc: dict[str, Any] | None = None
        self._fetched_at = 0.0

    @property
    def enabled(self) -> bool:
        return self._settings.auth_mode == "oidc" and bool(self._settings.oidc_client_id)

    def discovery(self) -> dict[str, Any]:
        """The issuer's OpenID configuration (cached like the JWKS)."""
        with self._lock:
            if self._doc is not None and self._mono() - self._fetched_at < self._settings.jwks_cache_ttl_s:
                return self._doc
            issuer = (self._settings.oidc_issuer or "").rstrip("/")
            try:
                resp = self._client.get(f"{issuer}/.well-known/openid-configuration")
                resp.raise_for_status()
                doc = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                if self._doc is not None:
                    return self._doc
                raise AuthError("oidc_unavailable", "identity provider discovery failed") from exc
            for key in ("authorization_endpoint", "token_endpoint"):
                url = doc.get(key) if isinstance(doc, dict) else None
                if not isinstance(url, str) or not secure_idp_url(url, production=self._settings.is_production):
                    raise AuthError("oidc_unavailable", f"discovery document has no usable {key}")
            self._doc, self._fetched_at = doc, self._mono()
            return doc

    def public_config(self) -> dict[str, Any]:
        doc = self.discovery()
        end = doc.get("end_session_endpoint")
        return {"client_id": self._settings.oidc_client_id, "scopes": self._settings.oidc_scopes,
                "authorization_endpoint": doc["authorization_endpoint"],
                "end_session_endpoint": end if isinstance(end, str) else None}

    def exchange(self, form: dict[str, str]) -> dict[str, Any]:
        """Relay an ``authorization_code`` (with PKCE verifier) or ``refresh_token`` grant."""
        grant = form.get("grant_type")
        if grant == "authorization_code":
            required = ("code", "code_verifier", "redirect_uri")
        elif grant == "refresh_token":
            required = ("refresh_token",)
        else:
            raise AuthError("unsupported_grant", "grant_type must be authorization_code or refresh_token")
        if any(not form.get(k) for k in required):
            raise AuthError("invalid_request", "missing grant parameters")
        body = {k: form[k] for k in ("grant_type",) + required}
        body["client_id"] = str(self._settings.oidc_client_id)
        if self._settings.oidc_client_secret:
            body["client_secret"] = self._settings.oidc_client_secret
        try:
            resp = self._client.post(self.discovery()["token_endpoint"], data=body,
                                     headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise AuthError("oidc_unavailable", "identity provider unreachable") from exc
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code != 200 or not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            code = data.get("error") if isinstance(data, dict) and isinstance(data.get("error"), str) else "denied"
            raise AuthError("token_exchange_failed", f"identity provider refused the grant ({code[:64]})")
        out = {k: data[k] for k in ("access_token", "refresh_token", "id_token", "token_type")
               if isinstance(data.get(k), str)}
        if isinstance(data.get("expires_in"), (int, float)):
            out["expires_in"] = int(data["expires_in"])
        return out


class OIDCVerifier:
    """Verifies RS256 (or other configured asymmetric) tokens from the operator's IdP."""

    mode = "oidc"

    def __init__(self, settings: Settings, *, jwks: JWKSCache | None = None):
        self._settings = settings
        self._jwks = jwks or JWKSCache(settings)

    def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed_token", "token is not a JWT") from exc
        alg = header.get("alg")
        if alg not in self._settings.oidc_algorithms:
            raise AuthError("bad_algorithm", "token algorithm not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthError("missing_kid", "token header has no key id")
        key = self._jwks.get(kid)
        try:
            claims = jwt.decode(token, key.key, algorithms=list(self._settings.oidc_algorithms),
                                audience=self._settings.oidc_audience, issuer=self._settings.oidc_issuer,
                                leeway=self._settings.jwt_leeway_s,
                                options={"require": ["exp", "iat", "sub", "iss", "aud"]})
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token_expired", "token expired") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token", "token verification failed") from exc
        return _principal_from_claims(claims, tenant_claim=self._settings.oidc_tenant_claim,
                                      roles_claim=self._settings.oidc_roles_claim, mode="oidc")


class Authenticator:
    """Facade selecting the verifier for the configured auth mode."""

    def __init__(self, settings: Settings, *, jwks: JWKSCache | None = None):
        self.settings = settings
        self.verifier: DevVerifier | OIDCVerifier = (
            DevVerifier(settings) if settings.auth_mode == "dev" else OIDCVerifier(settings, jwks=jwks))

    def authenticate(self, authorization_header: str | None) -> Principal:
        return self.verifier.verify(_bearer(authorization_header))


__all__ = [
    "ALL_ROLES", "AuthError", "Authenticator", "DEV_AUDIENCE", "DevVerifier", "JWKSCache", "OIDCLogin",
    "OIDCVerifier", "Principal", "Role", "mint_dev_token", "parse_roles", "resolve_dev_secret",
]
