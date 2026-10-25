"""Environment-driven runtime settings for the AEGIS API and service.

Every field maps to an ``AEGIS_*`` environment variable (see :data:`ENV_VARS`).
:meth:`Settings.from_env` parses and validates them; invalid combinations fail at
startup rather than at the first request (fail closed):

* ``AEGIS_ENV=production`` forbids ``AEGIS_AUTH_MODE=dev`` and requires an
  explicit ``AEGIS_PSEUDONYM_MASTER_KEY`` (enforced by the ingest key provider);
* ``AEGIS_AUTH_MODE=oidc`` requires an issuer and an audience; the JWKS URL is
  discovered from the issuer when not given;
* ``AEGIS_ENFORCEMENT_ADAPTER=rpz`` / ``webhook`` require their targets.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, model_validator

AuthMode = Literal["dev", "oidc"]
AdapterKind = Literal["dryrun", "rpz", "webhook"]

#: Repository root (``web/dist`` and ``models/`` live here in a source checkout).
REPO_ROOT = Path(__file__).resolve().parents[2]


class SettingsError(ValueError):
    """Raised when the configuration is invalid or unsafe."""


class Settings(BaseModel):
    """Runtime configuration. Construct directly in tests, or with :meth:`from_env`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    env: Literal["development", "production"] = "development"
    auth_mode: AuthMode = "oidc"

    # -- dev auth (HS256) --------------------------------------------------------------
    dev_jwt_secret: str | None = None
    dev_token_ttl_s: int = Field(default=8 * 3600, ge=60, le=7 * 86400)
    dev_issuer: str = "aegis-dev"

    # -- OIDC (RS256 via JWKS) ---------------------------------------------------------
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_tenant_claim: str = "tenant_id"
    oidc_roles_claim: str = "roles"
    oidc_algorithms: tuple[str, ...] = ("RS256",)
    jwks_cache_ttl_s: int = Field(default=3600, ge=30)
    jwks_min_refresh_interval_s: int = Field(default=30, ge=0)
    jwt_leeway_s: int = Field(default=60, ge=0, le=600)

    # -- storage and artifacts ---------------------------------------------------------
    data_dir: Path = Path("./aegis-data")
    database_url: str | None = None
    model_dir: Path | None = None
    model_require_signature: bool = False
    web_dist: Path = REPO_ROOT / "web" / "dist"
    ledger_key_id: str = "aegis-ledger"

    # -- enforcement -------------------------------------------------------------------
    enforcement_adapter: AdapterKind = "dryrun"
    rpz_zone_path: Path | None = None
    rpz_reload_command: tuple[str, ...] = ()
    webhook_url: str | None = None
    webhook_secret: str | None = None

    # -- HTTP behaviour ----------------------------------------------------------------
    rate_limit_rps: float = Field(default=20.0, gt=0)
    rate_limit_burst: int = Field(default=200, ge=1)
    max_ingest_bytes: int = Field(default=64 * 1024 * 1024, ge=1024)
    max_page_size: int = Field(default=500, ge=1, le=10_000)
    cors_origins: tuple[str, ...] = ()
    metrics_token: str | None = None
    log_level: str = "INFO"
    log_format: Literal["json", "text"] = "json"

    # -- runtime -----------------------------------------------------------------------
    llm_enabled: bool = True
    sweep_interval_s: float = Field(default=60.0, ge=0)
    bus_max_queue: int = Field(default=2_000_000, ge=1000)
    bus_per_tenant_quota: int | None = None
    demo_tenant: str | None = None

    @model_validator(mode="after")
    def _check(self) -> "Settings":
        if self.env == "production" and self.auth_mode == "dev":
            raise SettingsError("AEGIS_AUTH_MODE=dev is not allowed when AEGIS_ENV=production")
        if self.auth_mode == "oidc":
            if not self.oidc_issuer or not self.oidc_audience:
                raise SettingsError("OIDC auth requires AEGIS_OIDC_ISSUER and AEGIS_OIDC_AUDIENCE")
            bad = [a for a in self.oidc_algorithms if not a.startswith(("RS", "PS", "ES"))]
            if bad or not self.oidc_algorithms:
                raise SettingsError("OIDC algorithms must be asymmetric (RS*/PS*/ES*)")
        if self.dev_jwt_secret is not None and len(self.dev_jwt_secret.encode()) < 32:
            raise SettingsError("AEGIS_DEV_JWT_SECRET must be at least 32 bytes")
        if self.enforcement_adapter == "rpz" and self.rpz_zone_path is None:
            raise SettingsError("AEGIS_ENFORCEMENT_ADAPTER=rpz requires AEGIS_RPZ_ZONE_PATH")
        if self.enforcement_adapter == "webhook" and (not self.webhook_url or not self.webhook_secret):
            raise SettingsError("AEGIS_ENFORCEMENT_ADAPTER=webhook requires AEGIS_WEBHOOK_URL and "
                                "AEGIS_WEBHOOK_SECRET")
        if self.demo_tenant is not None and self.auth_mode != "dev":
            raise SettingsError("AEGIS_DEMO_TENANT is only valid with AEGIS_AUTH_MODE=dev")
        return self

    # ------------------------------------------------------------------ derived paths

    @property
    def resolved_database_url(self) -> str:
        return self.database_url or f"sqlite:///{(self.data_dir / 'aegis.db').resolve()}"

    @property
    def keys_dir(self) -> Path:
        """Private key material (ledger signer, dev JWT secret, pseudonym keys). Mode 0700."""
        return self.data_dir / "keys"

    @property
    def trusted_dir(self) -> Path:
        """Trusted public keys: ``policy/``, ``ioc/``, ``ledger/`` (``<key_id>.pem`` each)."""
        return self.data_dir / "trusted"

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    # ------------------------------------------------------------------ construction

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None, **overrides: Any) -> "Settings":
        """Build settings from ``AEGIS_*`` variables; keyword ``overrides`` win."""
        env = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        for field_name, var in ENV_VARS.items():
            raw = env.get(var)
            if raw is None or raw == "":
                continue
            values[field_name] = _parse(field_name, raw)
        values.update({k: v for k, v in overrides.items() if v is not None})
        try:
            return cls(**values)
        except SettingsError:
            raise
        except ValueError as exc:  # pydantic ValidationError is a ValueError
            raise SettingsError(str(exc)) from exc

    def public_summary(self) -> dict[str, Any]:
        """Non-secret view for logs and the readiness endpoint."""
        return {
            "env": self.env, "auth_mode": self.auth_mode, "oidc_issuer": self.oidc_issuer,
            "enforcement_adapter": self.enforcement_adapter, "llm_enabled": self.llm_enabled,
            "database": self.resolved_database_url.split("://", 1)[0],
            "web_console": (self.web_dist / "index.html").is_file(),
            "demo_tenant": self.demo_tenant,
        }


#: field name -> environment variable
ENV_VARS: dict[str, str] = {
    "env": "AEGIS_ENV",
    "auth_mode": "AEGIS_AUTH_MODE",
    "dev_jwt_secret": "AEGIS_DEV_JWT_SECRET",
    "dev_token_ttl_s": "AEGIS_DEV_TOKEN_TTL_S",
    "oidc_issuer": "AEGIS_OIDC_ISSUER",
    "oidc_audience": "AEGIS_OIDC_AUDIENCE",
    "oidc_jwks_url": "AEGIS_OIDC_JWKS_URL",
    "oidc_tenant_claim": "AEGIS_OIDC_TENANT_CLAIM",
    "oidc_roles_claim": "AEGIS_OIDC_ROLES_CLAIM",
    "oidc_algorithms": "AEGIS_OIDC_ALGORITHMS",
    "jwks_cache_ttl_s": "AEGIS_JWKS_CACHE_TTL_S",
    "jwt_leeway_s": "AEGIS_JWT_LEEWAY_S",
    "data_dir": "AEGIS_DATA_DIR",
    "database_url": "AEGIS_DATABASE_URL",
    "model_dir": "AEGIS_MODEL_DIR",
    "model_require_signature": "AEGIS_MODEL_REQUIRE_SIGNATURE",
    "web_dist": "AEGIS_WEB_DIST",
    "ledger_key_id": "AEGIS_LEDGER_KEY_ID",
    "enforcement_adapter": "AEGIS_ENFORCEMENT_ADAPTER",
    "rpz_zone_path": "AEGIS_RPZ_ZONE_PATH",
    "rpz_reload_command": "AEGIS_RPZ_RELOAD_COMMAND",
    "webhook_url": "AEGIS_WEBHOOK_URL",
    "webhook_secret": "AEGIS_WEBHOOK_SECRET",
    "rate_limit_rps": "AEGIS_RATE_LIMIT_RPS",
    "rate_limit_burst": "AEGIS_RATE_LIMIT_BURST",
    "max_ingest_bytes": "AEGIS_MAX_INGEST_BYTES",
    "max_page_size": "AEGIS_MAX_PAGE_SIZE",
    "cors_origins": "AEGIS_CORS_ORIGINS",
    "metrics_token": "AEGIS_METRICS_TOKEN",
    "log_level": "AEGIS_LOG_LEVEL",
    "log_format": "AEGIS_LOG_FORMAT",
    "llm_enabled": "AEGIS_LLM_ENABLED",
    "sweep_interval_s": "AEGIS_SWEEP_INTERVAL_S",
    "bus_max_queue": "AEGIS_BUS_MAX_QUEUE",
    "bus_per_tenant_quota": "AEGIS_BUS_PER_TENANT_QUOTA",
    "demo_tenant": "AEGIS_DEMO_TENANT",
}

_BOOL_FIELDS = {"model_require_signature", "llm_enabled"}
_TUPLE_FIELDS = {"oidc_algorithms", "cors_origins"}
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _parse(field_name: str, raw: str) -> Any:
    raw = raw.strip()
    if field_name in _BOOL_FIELDS:
        low = raw.lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
        raise SettingsError(f"{ENV_VARS[field_name]} must be a boolean, got {raw!r}")
    if field_name in _TUPLE_FIELDS:
        return tuple(p.strip() for p in raw.split(",") if p.strip())
    if field_name == "rpz_reload_command":
        import shlex
        return tuple(shlex.split(raw))
    return raw


__all__ = ["ENV_VARS", "REPO_ROOT", "AdapterKind", "AuthMode", "Settings", "SettingsError"]
