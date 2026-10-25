# On-prem installation guide

This guide installs AEGIS OMEGA SHIELD on a single host inside the operator's network (on-prem or sovereign
cloud) for a shadow pilot or production use. Allow half a day including identity-provider setup. Every command
below was run against the shipped compose stack; `deploy/smoke-test.sh` repeats the core of it automatically.

Contents: [1 What gets installed](#1-what-gets-installed) · [2 Host requirements](#2-host-requirements) ·
[3 Get and verify the image](#3-get-and-verify-the-image) · [4 Configure](#4-configure) ·
[5 Identity provider](#5-identity-provider-oidc) · [6 TLS reverse proxy](#6-tls-reverse-proxy) ·
[7 Start](#7-start-and-check) · [8 Onboard a tenant](#8-onboard-a-tenant) ·
[9 Send telemetry](#9-send-telemetry) · [10 Monitoring](#10-monitoring) ·
[11 Retention, backup, upgrade](#11-retention-backup-and-upgrade) · [12 End of pilot](#12-end-of-pilot-and-data-deletion) ·
[13 Troubleshooting](#13-troubleshooting)

## 1. What gets installed

| Container | Image | Role | Network |
|---|---|---|---|
| `api` | `aegis-omega:<version>` | API, analyst console, detection, ledger | backend + frontend; port 8000 published on `AEGIS_BIND` (default 127.0.0.1) |
| `postgres` | `postgres:16-alpine` | findings, cases, evidence, signed ledger, audit | backend only (internal network, no egress, not published) |
| `prometheus` (profile `monitoring`) | `prom/prometheus` | scrapes `/metrics` with a bearer token, evaluates SLO alert rules | published on `MONITORING_BIND` |
| `grafana` (profile `monitoring`) | `grafana/grafana` | provisioned "AEGIS SHIELD - Operations" dashboard | published on `MONITORING_BIND` |
| `redpanda` (profile `bus`) | `redpandadata/redpanda` | optional Kafka-API buffer, see [OPERATOR_INTEGRATION.md](OPERATOR_INTEGRATION.md#buffered-collection-optional-bus-profile) | published on `BUS_BIND` |

The `api` container runs as uid 10001 with a read-only root file system, all Linux capabilities dropped and
`no-new-privileges`. Its state lives in two named volumes: `aegis_pgdata` (PostgreSQL) and `aegis_aegis-data`
(ledger signing key, trusted public keys, tenant pseudonymization keys).

Nothing in the default configuration sends data outside the host. Outbound connections happen only for
OIDC discovery/JWKS (to your IdP) and, if you enable it, the optional LLM endpoint.

## 2. Host requirements

| | Pilot minimum | Notes |
|---|---|---|
| OS | Linux x86-64 (RHEL 9, Ubuntu 22.04/24.04, Debian 12) | any distribution with Docker Engine 24+ and Compose v2.24+ |
| CPU / RAM | 4 vCPU / 16 GB | detection state is held in memory per active device and window, and journalled (last ~26 h of normalized telemetry) so a restart rebuilds it without losing window context or re-alerting ongoing incidents |
| Disk | 100 GB SSD | PostgreSQL grows with findings, evidence and the ledger, not with raw telemetry volume |
| Network | HTTPS from collectors and analysts to the reverse proxy; HTTPS to the IdP | no inbound access from the internet is needed |

Capacity is validated with the operator's own exports during pilot onboarding (week 1): push a
representative hour of telemetry and read the ingest rate and latency panels in Grafana. Size for the peak
hour, not the daily average. Spec section 13 load tiers (1k to 1M events/s) are tested only with explicit
event sizes and an agreed infrastructure budget.

## 3. Get and verify the image

Either build from source (`make image`, or `docker build -t aegis-omega:1.0.0 .`) or pull the signed release
image. Released images are signed keylessly with Sigstore cosign by the release workflow; verify the digest
before deployment:

```bash
cosign verify ghcr.io/<org>/aegis-omega@sha256:<digest> \
  --certificate-identity-regexp 'https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation --type cyclonedx ghcr.io/<org>/aegis-omega@sha256:<digest> \
  --certificate-identity-regexp '...' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Air-gapped sites: `docker save aegis-omega:1.0.0 | gzip > aegis-omega-1.0.0.tar.gz` on a connected machine,
transfer with its SHA-256, then `docker load`. Do the same for `postgres:16-alpine` and, if used, the
monitoring images. Behind a TLS-inspecting proxy, build with
`docker build --secret id=extra_ca,src=/path/to/proxy-ca.pem .` (the CA is used for downloads only and is
not stored in the image).

## 4. Configure

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
openssl rand -hex 32    # run once per secret below
```

Fill in every value marked REQUIRED:

| Variable | Value |
|---|---|
| `POSTGRES_PASSWORD` | random hex (it is embedded in a database URL) |
| `AEGIS_PSEUDONYM_MASTER_KEY` | random hex, 32 bytes. Escrow a copy in the operator's vault: losing it breaks pseudonym continuity |
| `AEGIS_METRICS_TOKEN` | random hex; Prometheus presents it on `/metrics` |
| `GRAFANA_ADMIN_PASSWORD` | random |
| `AEGIS_OIDC_ISSUER`, `AEGIS_OIDC_AUDIENCE` | see section 5 |
| `AEGIS_IMAGE` | the verified image, preferably by digest |

Keep `AEGIS_ENV=production`: it refuses dev authentication, requires an explicit pseudonymization key and
rejects the demo tenant. Keep `AEGIS_ENFORCEMENT_ADAPTER=dryrun` for a shadow pilot. Every variable is
described in [CONFIGURATION.md](CONFIGURATION.md).

## 5. Identity provider (OIDC)

AEGIS accepts RS256/PS256/ES256 access tokens from one issuer. The tenant and roles come only from token
claims; there are no local accounts.

| Claim | Default name | Content |
|---|---|---|
| issuer | `iss` | must equal `AEGIS_OIDC_ISSUER` |
| audience | `aud` | must contain `AEGIS_OIDC_AUDIENCE` |
| tenant | `tenant_id` (`AEGIS_OIDC_TENANT_CLAIM`) | the operator's tenant id, e.g. `acme` (1-64 letters, digits, `.`, `_`, `-`; starts with a letter or digit) |
| roles | `roles` (`AEGIS_OIDC_ROLES_CLAIM`) | list (or space/comma-separated string) of `viewer`, `analyst`, `approver`, `admin`, `integration` |

Role design (separation of duties is enforced by the API, not the UI):

| Role | Can | Cannot |
|---|---|---|
| `viewer` | read findings, cases, evidence, graph, reports, ledger status | change anything |
| `analyst` | work cases, investigate, propose actions, run simulation and authorization assessment | approve, deny, execute, roll back |
| `approver` | approve or deny actions, execute and roll back authorized actions; never their own proposal | configure the tenant |
| `admin` | register sources, load signed IOC bundles, policies and topology, read the audit trail | approve or execute |
| `integration` | push telemetry | read anything |

**Keycloak.** Create a realm client `aegis-api` (audience). Add a hardcoded-claim or user-attribute mapper
`tenant_id` (token claim name `tenant_id`, add to access token), and a client-roles mapper with claim name
`roles` (multivalued, add to access token). Create client roles with the five names above and assign them to
groups. For collectors create a confidential client with service account enabled and only the `integration`
role; `aegis_push.py` uses its client credentials.

**Microsoft Entra ID.** Register an application exposing an API (`api://aegis-api`, set
`AEGIS_OIDC_AUDIENCE` to it), define app roles named exactly as above (they arrive in the `roles` claim), and
either emit a custom `tenant_id` claim through a claims-mapping policy or set `AEGIS_OIDC_TENANT_CLAIM=tid`
to use the Entra tenant id as the AEGIS tenant. Issuer: `https://login.microsoftonline.com/<tenant-guid>/v2.0`.

**Console sign-in (single sign-on).** Register a *public* client for the console and set
`AEGIS_OIDC_CLIENT_ID` (and `AEGIS_OIDC_SCOPES` if your IdP needs an API scope, e.g. Entra
`openid profile offline_access api://aegis-api/.default`). Allowed redirect URI:
`https://aegis.operator.example/auth/callback`; PKCE (S256) required; the access token audience must be
`AEGIS_OIDC_AUDIENCE`. Analysts then click **Sign in with single sign-on**: the console runs the
authorization-code flow with PKCE, the AEGIS API relays the code-for-token exchange (no cross-origin access
to the IdP is needed, and `AEGIS_OIDC_CLIENT_SECRET` stays server-side if your IdP insists on a confidential
client), and the session renews itself with the refresh token before the access token expires. Keycloak:
client `aegis-console`, *Client authentication* off, *Standard flow* on, the same `tenant_id` / `roles`
mappers as above with `aegis-api` in the audience (audience mapper). Entra ID: a *Single-page application*
platform with the redirect URI above, exposing or consuming `api://aegis-api`. An administrator fallback
(paste an access token) stays available on the sign-in screen.

Require MFA for every role at the IdP, and keep `approver` and `admin` membership small and reviewed.

## 6. TLS reverse proxy

The API speaks plain HTTP on 127.0.0.1:8000. Terminate TLS in front of it with the operator's load balancer
or a reverse proxy on the same host. Example nginx server block:

```nginx
server {
    listen 443 ssl http2;
    server_name aegis.operator.example;
    ssl_certificate     /etc/pki/tls/certs/aegis.crt;
    ssl_certificate_key /etc/pki/tls/private/aegis.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 64m;          # = AEGIS_MAX_INGEST_BYTES
    proxy_read_timeout 300s;           # large ingest batches and report rendering

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
    location = /metrics { deny all; }   # Prometheus scrapes the container directly
    # optional: the interactive API docs load assets from a public CDN
    # location /api/v1/docs { deny all; }
}
```

Docker publishes the port through the bridge gateway, so the API sees the proxy as that gateway address. Set
`AEGIS_FORWARDED_ALLOW_IPS` to it so client addresses in the audit trail are correct:

```bash
docker network inspect aegis_frontend -f '{{(index .IPAM.Config 0).Gateway}}'
```

Collectors that must use mutual TLS: enforce client certificates at the proxy (`ssl_verify_client on;`) on a
dedicated `location /api/v1/ingest` with its own server name; tokens are still required behind it.

## 7. Start and check

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps                 # api and postgres healthy
curl -s http://127.0.0.1:8000/readyz                           # {"ready": true, "checks": {...}}
docker compose -f deploy/docker-compose.yml logs api | head    # JSON logs
```

`/readyz` reports the database, the loaded detection model (or `rules-only` if the model failed integrity
checks), whether an LLM is configured, the enforcement adapter (`dry_run`) and the circuit breaker.
On first start the API generates the ledger signing key in the data volume; back it up (section 11).

## 8. Onboard a tenant

Tenants are created implicitly by the `tenant_id` claim; onboarding configures what the tenant is allowed to
collect and what it trusts. Use an `admin` token (`TOKEN` below) and `API=https://aegis.operator.example`.

**8.1 Register each telemetry source.** One source per exporter/format. `collection_authorization_id` is the
reference of the operator's internal authorization for this collection (DPIA / processing register entry);
events from sources without it are refused.

```bash
curl -fsS -X POST "$API/api/v1/sources" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "source_id": "core-ipfix", "source_kind": "netflow", "vantage": "subscriber_line",
  "collection_authorization_id": "ACME-DPIA-2026-014", "retention_days": 30, "entity_field": "src_ip" }'
```

`source_kind`: `netflow`, `dns`, `zeek_conn`, `zeek_dns`, `cpe`. `vantage`: `subscriber_line` (core, one
identity per line or NAT) or `device` (CPE/gateway, per device).

For unidirectional NetFlow/IPFIX (nfdump v5/v9 without bi-flow, the common ISP export) also declare the
subscriber address space, so return legs are not counted as devices, and say whether the exporter really
sends reply counters:

```bash
  ..., "entity_field": "src_ip", "subscriber_prefixes": ["100.64.0.0/10", "2001:db8:100::/40"],
  "flow_direction": "uniflow" }'
```

With `subscriber_prefixes`, flows whose source is outside them (server replies, transit) are counted as
`skipped` in the ingest statistics, never quarantined and never attributed. `flow_direction`: `uniflow` treats
reverse byte/packet counters as missing (never as "no reply"), `biflow` keeps them, `auto` (default) treats
a `0` in nfdump/nProbe `obyt`/`opkt` columns as missing. See
[OPERATOR_INTEGRATION.md](OPERATOR_INTEGRATION.md) for which detections each combination supports.

**8.2 Create operator signing keys (offline).** On the operator's signing workstation, not on the AEGIS host:

```bash
mkdir -p operator-keys
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/operator-keys:/keys" aegis-omega:1.0.0 \
  keys generate --key-id acme-policy-2026 --out-dir /keys
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/operator-keys:/keys" aegis-omega:1.0.0 \
  keys generate --key-id acme-ioc-2026 --out-dir /keys
```

`*.key.pem` files are private (mode 0600): keep them in the operator's vault or HSM-backed workflow.

**8.3 Trust the public keys** (then restart the API so the key rings reload):

```bash
C="docker compose -f deploy/docker-compose.yml"
$C exec -T api sh -c 'cat > /var/lib/aegis/trusted/policy/acme-policy-2026.pem' < operator-keys/acme-policy-2026.pem
$C exec -T api sh -c 'cat > /var/lib/aegis/trusted/ioc/acme-ioc-2026.pem'      < operator-keys/acme-ioc-2026.pem
$C restart api
```

**8.4 Load the shadow policy.** Start from `deploy/examples/operator-policy.shadow.json` (set `tenant_id`,
`policy_id`, validity dates and `signer_key_id`), sign it, upload it:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" -w /work aegis-omega:1.0.0 \
  policy sign policy.json --key operator-keys/acme-policy-2026.key.pem --key-id acme-policy-2026 --out policy.signed.json
curl -fsS -X POST "$API/api/v1/policies" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @policy.signed.json
```

A `shadow` policy makes every authorization assessment fail the "policy mode is active" check: analysts can
rehearse the full propose / simulate / authorize / approve workflow, and nothing is executed.

**8.5 Load a signed IOC bundle** (optional but recommended; format in `deploy/examples/ioc-bundle.example.json`):

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/work" -w /work --entrypoint python aegis-omega:1.0.0 \
  /opt/aegis/tools/sign_ioc_bundle.py sign feed.json --key operator-keys/acme-ioc-2026.key.pem \
  --key-id acme-ioc-2026 --out feed.signed.json
curl -fsS -X POST "$API/api/v1/iocs" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @feed.signed.json
```

Indicators carry `first_seen/last_seen/expires_at` and a `source_group`: stale and expired indicators are
ignored, and several feeds syndicating the same report count as one origin.

**8.6 Load the hosting topology** (needed for impact simulation; format in
`deploy/examples/topology.example.json`). With `"complete": false` or for addresses outside the declared
prefixes, every simulation returns UNKNOWN and authorization fails closed.

```bash
curl -fsS -X POST "$API/api/v1/topology" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data-binary @topology.json
```

## 9. Send telemetry

`deploy/tools/aegis_push.py` (also at `/opt/aegis/tools/aegis_push.py` in the image) chunks collector files on
record boundaries, retries safely and moves accepted files out of the spool. Use a token or client
credentials holding only the `integration` role.

```bash
# on a collector host with Python 3.11+ and httpx, or with the image:
docker run --rm --network host -v /var/spool/aegis:/spool -e AEGIS_TOKEN_FILE=/spool/push.token \
  --entrypoint python aegis-omega:1.0.0 /opt/aegis/tools/aegis_push.py \
  --api https://aegis.operator.example --source core-ipfix --done-dir /spool/done /spool/ipfix/*.csv
```

systemd timer (every 5 minutes, after the exporter rotates files):

```ini
# /etc/systemd/system/aegis-push.service
[Service]
Type=oneshot
Environment=AEGIS_OIDC_TOKEN_URL=https://sso.operator.example/realms/soc/protocol/openid-connect/token
Environment=AEGIS_CLIENT_ID=aegis-collector
Environment=AEGIS_CLIENT_SECRET_FILE=/etc/aegis/collector.secret
# only files untouched for a minute, so files still being written are not sent
ExecStart=/bin/sh -c 'find /var/spool/aegis/ipfix -maxdepth 1 -type f -mmin +1 -print0 | sort -z | \
  xargs -0 -r /usr/bin/python3 /opt/aegis/tools/aegis_push.py --api https://aegis.operator.example \
  --source core-ipfix --done-dir /var/spool/aegis/done'

# /etc/systemd/system/aegis-push.timer
[Timer]
OnCalendar=*:0/5
[Install]
WantedBy=timers.target
```

Each run prints one JSON line per chunk with accepted, quarantined and duplicate counts.
Records that fail validation are quarantined with their original bytes (visible to `admin` at
`GET /api/v1/ingest/quarantine`), never silently dropped.

## 10. Monitoring

```bash
docker compose -f deploy/docker-compose.yml --profile monitoring up -d
```

Grafana (`http://127.0.0.1:3000`, admin password from `.env`) opens on the provisioned dashboard: readiness,
5xx ratio, latency by route, ingest valid ratio, findings and abstentions, case flow, enforcement steps, live
enforcement count (must stay 0 in shadow mode), audit write failures, authentication failures and RBAC
denials. Prometheus loads `deploy/prometheus/rules/aegis-alerts.yml` (thresholds from [SLO.md](SLO.md)); point
it at the operator's Alertmanager by adding an `alerting:` block to `deploy/prometheus/prometheus.yml`. Metric
labels never carry tenant ids, pseudonyms or indicators.

The API logs JSON to stdout (`docker compose logs api`); ship them with the host's log agent.

## 11. Retention, backup and upgrade

**Retention.** Quarantined raw records expire after their source's `retention_days`. Run the purge daily:

```cron
17 3 * * * cd /opt/aegis && deploy/purge-expired.sh >> /var/log/aegis-purge.log 2>&1
```

**Backup** (daily, and before every upgrade): `deploy/backup.sh /secure/backups/$(date -u +%F)` writes a
PostgreSQL dump, an archive of the data volume (keys) and checksums. Encrypt the output to the operator's
backup key. **Restore**: `deploy/restore.sh <dir>` (verifies checksums, asks for confirmation, restores both,
waits for readiness), then `aegis ledger verify --tenant <tenant>`. Use the same `deploy/.env` (in particular
`AEGIS_PSEUDONYM_MASTER_KEY` and the PostgreSQL credentials).

**Upgrade**: [runbooks/upgrade-backup-restore.md](runbooks/upgrade-backup-restore.md).

## 12. End of pilot and data deletion

```bash
deploy/backup.sh /secure/handover/final     # only if the SOW asks for a final export to the operator
docker compose -f deploy/docker-compose.yml --profile monitoring --profile bus down -v   # deletes all volumes
docker image rm aegis-omega:1.0.0
```

`down -v` removes the database, the data volume (signing and pseudonymization keys), Prometheus and Grafana
data. Destroy backups according to the operator's media-sanitization procedure and record the deletion in the
pilot close-out (template in [sales/PILOT_SOW_TEMPLATE.md](sales/PILOT_SOW_TEMPLATE.md)).

## 13. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `api` exits at start: `AEGIS_AUTH_MODE=dev is not allowed when AEGIS_ENV=production` | production refuses dev auth; configure OIDC |
| `OIDC auth requires AEGIS_OIDC_ISSUER and AEGIS_OIDC_AUDIENCE` | fill both in `deploy/.env` |
| `AEGIS_PSEUDONYM_MASTER_KEY must be set when AEGIS_ENV=production` | generate it (section 4) |
| `required variable ... is missing a value` from compose | a REQUIRED value in `deploy/.env` is empty |
| 401 on every call | token issuer/audience mismatch, expired token, or missing `tenant_id` / `roles` claim; `GET /api/v1/me` shows what was accepted |
| 403 | the role lacks the permission (the response names the missing permission); see the role table in section 5 |
| 404 `unknown source` on ingest | register the source for this tenant first (8.1); sources are per tenant |
| many quarantined records | wrong `source_kind`/format or clock skew; inspect `GET /api/v1/ingest/quarantine` reasons |
| policy upload rejected: signature | public key not in `trusted/policy/`, wrong `signer_key_id`, or API not restarted after 8.3 |
| `/readyz` shows `model: not_loaded (rules-only)` | the model artifact failed its integrity check; the service runs rules + abstain; reinstall the image |
| Prometheus target down | `AEGIS_METRICS_TOKEN` differs between api and prometheus; recreate both after editing `.env` |
