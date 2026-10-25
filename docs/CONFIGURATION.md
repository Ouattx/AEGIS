# Configuration reference

AEGIS is configured only through environment variables (`deploy/.env` for the compose deployment). Settings
are parsed and validated at start-up; an invalid or unsafe combination stops the process with an explicit
message instead of failing at the first request. Empty values mean "use the default".

"Compose" shows what `deploy/docker-compose.yml` sets when `deploy/.env` leaves the variable empty.

## Runtime mode

| Variable | Default (code) | Compose | Meaning |
|---|---|---|---|
| `AEGIS_ENV` | `development` | `production` | `production` forbids `AEGIS_AUTH_MODE=dev` and `AEGIS_DEMO_TENANT`, and requires `AEGIS_PSEUDONYM_MASTER_KEY` |
| `AEGIS_LOG_LEVEL` | `INFO` | | Python log level |
| `AEGIS_LOG_FORMAT` | `json` | | `json` (one object per line) or `text` |
| `AEGIS_DEMO_TENANT` | unset | not passed | seeds/permits the demo token endpoint; dev auth only, never in production |

## Authentication

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_AUTH_MODE` | `oidc` | `oidc` (production) or `dev` (HS256 tokens minted locally for demos and tests) |
| `AEGIS_OIDC_ISSUER` | required for `oidc` | exact `iss` of accepted tokens |
| `AEGIS_OIDC_AUDIENCE` | required for `oidc` | required `aud` value |
| `AEGIS_OIDC_JWKS_URL` | discovered | JWKS endpoint; discovered from `<issuer>/.well-known/openid-configuration` when empty |
| `AEGIS_OIDC_TENANT_CLAIM` | `tenant_id` | claim carrying the AEGIS tenant id |
| `AEGIS_OIDC_ROLES_CLAIM` | `roles` | claim carrying roles (list, or space/comma separated string) |
| `AEGIS_OIDC_ALGORITHMS` | `RS256` | comma-separated; only asymmetric `RS*`, `PS*`, `ES*` are accepted |
| `AEGIS_JWKS_CACHE_TTL_S` | `3600` | JWKS cache lifetime; an unknown `kid` triggers a rate-limited refresh (key rotation) |
| `AEGIS_JWT_LEEWAY_S` | `60` | clock-skew tolerance for `exp`/`nbf` (max 600) |
| `AEGIS_DEV_JWT_SECRET` | generated | dev mode only: HS256 secret (>= 32 bytes); generated into the data volume when unset |
| `AEGIS_DEV_TOKEN_TTL_S` | `28800` | dev mode only: lifetime of minted tokens |

## Storage, keys and artifacts

| Variable | Default | Compose | Meaning |
|---|---|---|---|
| `AEGIS_DATABASE_URL` | `sqlite:///<data dir>/aegis.db` | PostgreSQL URL built from `POSTGRES_*` | SQLAlchemy URL; PostgreSQL (`postgresql+psycopg://`) in production |
| `AEGIS_DATA_DIR` | `./aegis-data` | `/var/lib/aegis` | `keys/` (ledger signing key, dev secret, tenant pseudonym keys, mode 0700), `trusted/{policy,ioc,ledger}/` public keys |
| `AEGIS_PSEUDONYM_MASTER_KEY` | dev key (warning) | required | hex, >= 16 bytes (use 32); per-tenant HMAC keys are derived from it with HKDF |
| `AEGIS_LEDGER_KEY_ID` | `aegis-ledger` | | id of the ledger signing key; a new id generates a new key (rotation, see runbooks) |
| `AEGIS_MODEL_DIR` | shipped model | image: `/opt/aegis/models/sentinel-default` | detection model artifact directory |
| `AEGIS_MODEL_REQUIRE_SIGNATURE` | `false` | | refuse a model whose manifest is not signed by a trusted ledger key |
| `AEGIS_WEB_DIST` | `<repo>/web/dist` | image: `/opt/aegis/web/dist` | built console served at `/` |

## Enforcement (off for shadow pilots)

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_ENFORCEMENT_ADAPTER` | `dryrun` | `dryrun` (never touches the network), `rpz` or `webhook` |
| `AEGIS_RPZ_ZONE_PATH` | required for `rpz` | RPZ zone file written by the adapter (mount a volume shared with the resolver) |
| `AEGIS_RPZ_RELOAD_COMMAND` | none | command run after each zone change (shell-style quoting), e.g. `rndc reload rpz.aegis` |
| `AEGIS_WEBHOOK_URL` | required for `webhook` | operator endpoint receiving HMAC-signed apply/rollback requests |
| `AEGIS_WEBHOOK_SECRET` | required for `webhook` | HMAC key for those requests |
| `AEGIS_SWEEP_INTERVAL_S` | `60` | how often expired actions are swept and rolled back (0 disables; tests only) |

Even with a live adapter, nothing executes without a signed `active` policy carrying a legal sign-off
reference, a SAFE simulation, bounded expiry, a verified rollback plan and a second person's approval.

## HTTP behaviour

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_RATE_LIMIT_RPS` / `AEGIS_RATE_LIMIT_BURST` | `20` / `200` | token bucket per tenant for authenticated requests (429 + `Retry-After`) |
| `AEGIS_MAX_INGEST_BYTES` | `67108864` | maximum ingest request body; `aegis_push.py` chunks below it |
| `AEGIS_MAX_PAGE_SIZE` | `500` | maximum `limit` on list endpoints |
| `AEGIS_CORS_ORIGINS` | none | allowed cross-origin browser origins (the console itself is same-origin) |
| `AEGIS_METRICS_TOKEN` | none (open) | bearer token required on `/metrics`; compose requires it |
| `AEGIS_FORWARDED_ALLOW_IPS` | `127.0.0.1` | proxies whose `X-Forwarded-*` headers are trusted (read by the `aegis serve` launcher) |

## Ingest bus

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_BUS_MAX_QUEUE` | `2000000` | in-process event queue bound; beyond it producers get backpressure |
| `AEGIS_BUS_PER_TENANT_QUOTA` | none | per-tenant in-flight quota so one tenant cannot starve others |

## Optional LLM assistance

| Variable | Default | Compose | Meaning |
|---|---|---|---|
| `AEGIS_LLM_ENABLED` | `true` | `false` | allow ORACLE to use an LLM when a key is present |
| `ANTHROPIC_API_KEY` | unset | | without it no LLM is used, whatever `AEGIS_LLM_ENABLED` says |
| `AEGIS_LLM_MODEL` | `claude-sonnet-5-5` | | model id |

With an LLM, investigation summaries of pseudonymized case evidence are sent to the provider. Record the
provider as a processor in the DPIA before enabling it. Detection, case guards, authorization and
enforcement never depend on it.

## Compose-only variables

| Variable | Meaning |
|---|---|
| `AEGIS_IMAGE` | image reference for `api` (pin a digest in production) |
| `AEGIS_BIND`, `AEGIS_PORT` | address/port the API is published on (default `127.0.0.1:8000`) |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | database bootstrap (password required) |
| `GRAFANA_ADMIN_USER`, `GRAFANA_ADMIN_PASSWORD`, `GRAFANA_COOKIE_SECURE` | Grafana (monitoring profile) |
| `MONITORING_BIND`, `PROMETHEUS_PORT`, `GRAFANA_PORT`, `PROMETHEUS_RETENTION` | monitoring publication and retention |
| `REDPANDA_ADVERTISE_HOST`, `BUS_BIND` | bus profile |

Only `AEGIS_*` variables and `ANTHROPIC_API_KEY` are passed to the API container (explicit allow-list in
`deploy/docker-compose.yml`); Grafana and bus secrets never reach it.
