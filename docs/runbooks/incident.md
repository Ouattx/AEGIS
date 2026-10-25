# Runbook: incidents

For on-call engineers of the operator (NOC/SOC) and the vendor's support engineer. Each section matches an
alert in `deploy/prometheus/rules/aegis-alerts.yml`. Commands assume the repository checkout on the AEGIS
host and `C="docker compose -f deploy/docker-compose.yml"`.

## Severity and communication

| Severity | Definition | Response | Communicate |
|---|---|---|---|
| SEV1 | live enforcement that was not authorized, rollback failure with enforcement live, suspected data breach or key compromise, ledger verification failure | immediately, 24/7 | operator CISO and DPO within 1 hour; vendor security contact; GDPR Art. 33 / NIS2 Art. 23 assessment by the operator |
| SEV2 | service not ready, ingestion stalled more than 2h, audit writes failing | within 1 hour in business hours, next morning otherwise during a shadow pilot | operator pilot lead |
| SEV3 | degraded latency, elevated quarantine, auth or RBAC anomalies | next business day | ticket |

First five minutes for any alert:

```bash
$C ps                                   # container health
curl -s http://127.0.0.1:8000/readyz    # database, model, adapter, circuit breaker
$C logs --since 30m api | tail -200     # JSON logs; filter with jq '.level, .msg'
```

Record every action you take (time, command, outcome) in the incident ticket. Never edit the database or the
data volume by hand: the ledger detects it, and it destroys the evidence trail.

## API down

`AegisApiDown`: Prometheus cannot scrape the API.

1. `$C ps api`. If restarting in a loop, read the first error in `$C logs api`: configuration errors
   (`SettingsError`) name the variable to fix in `deploy/.env`.
2. If the container is healthy but Prometheus cannot reach it: check `AEGIS_METRICS_TOKEN` is the same for
   both (recreate both with `$C --profile monitoring up -d`).
3. Host resources: `df -h` (PostgreSQL volume full stops writes), `free -m`, `dmesg | tail` (OOM kills).
4. Restart once: `$C restart api`. If it does not become healthy in 2 minutes, escalate to the vendor with
   the last 500 log lines.

## Not ready

`AegisNotReady`: `/readyz` returns 503. The response body names the failing check.

* `database: error`: `$C ps postgres`, `$C logs postgres`; disk space; credentials changed in `.env` without
  recreating the API.
* After a restore: wait for `restore.sh` to finish; it brings the API up last.

## Errors

`AegisHigh5xxRatio`: more than 1% of requests fail with 5xx for 10 minutes.

1. Group by route in Grafana ("Requests by status") or Prometheus:
   `sum by (route, status) (rate(aegis_http_requests_total{status=~"5.."}[5m]))`.
2. Find the request ids in the logs (`"status": 500`) and the matching `unhandled error` traceback.
3. If one route fails consistently (e.g. report rendering), it is a defect: open a vendor ticket with the
   request id and traceback. Detection and ingestion continue independently.

## Ingest quarantine

`AegisIngestValidRatioLow`: more than 0.1% of submitted records were quarantined over the last hour.

1. `GET /api/v1/ingest/quarantine` (admin) lists records with `stage`, `reason`, `source_id`, line number.
2. Common reasons and fixes: `naive_timestamp` (exporter without offset: fix the exporter, or register the
   source with `assume_utc_for_naive` if the exporter is known to write UTC), `future_timestamp` (exporter
   clock: fix NTP), missing required fields (wrong column names: map them, see
   [OPERATOR_INTEGRATION.md](../OPERATOR_INTEGRATION.md#4-formats-and-field-mapping)), wrong `source_kind`.
3. Quarantined records keep their original bytes for the source's retention period, so they can be
   re-sent after the collector is fixed.

## Ingest stalled

`AegisIngestStalled`: nothing ingested for 2 hours while the API is up.

1. Collector side: `systemctl status aegis-push.timer`, `journalctl -u aegis-push --since -3h`. A 401 means
   the integration token expired or the client secret rotated; 404 `unknown_source` means the source id
   does not match a registered source of this tenant.
2. Exporter side: are files still being produced in the spool directory?
3. During a pilot, an agreed maintenance window on the operator side is a valid cause: note it in the pilot
   log, since coverage gaps are reported in the proof-of-value report.

## Audit failure

`AegisAuditWriteFailure` (SEV2, SEV1 if persistent): audit records could not be written to the ledger.
Requests still complete, but without their audit entry.

1. Check the database (`/readyz`, disk space).
2. Verify the chain of the affected tenants: `$C exec api aegis ledger verify --tenant <tenant>`.
3. If writes keep failing, stop state-changing work: ask analysts and approvers to pause until audit
   writes succeed again (read-only use is safe), and escalate to the vendor.

## Ledger verification failure (SEV1)

`aegis ledger verify` or `GET /api/v1/ledger/verify` returns `ok: false` with `first_bad_seq`.

1. Do not repair anything. Snapshot the database (`deploy/backup.sh /secure/forensics/<date>`) and preserve
   host logs.
2. Treat as possible tampering: review host access logs and database access around the `recorded_at` of the
   first bad entry.
3. Compare with the last good backup (`restore.sh` into an isolated host and verify there) to bound the
   window. Involve the operator CISO; the verification output is the evidence.

## Auth failures

`AegisAuthFailureSpike`: many rejected tokens.

* `reason` label in "Authentication failures by reason" tells why: expired tokens after an IdP change,
  audience mismatch after a client reconfiguration, unknown `kid` during IdP key rotation (resolves itself
  after the JWKS refresh), or invalid signatures (possible forgery attempt: escalate to SOC).

## RBAC denials

`AegisRbacDenialSpike`: many requests denied by role.

* "RBAC denials by permission" shows which permission. A new IdP group mapping that dropped a role is the
  common cause. Repeated attempts by one subject to use `approve`, `execute` or `configure` without the role
  are an insider-misuse signal: the ledger audit records (`api_audit` entries, `denied_permission`) name the
  subject.

## Latency

`AegisApiLatencyHigh`: interactive routes slower than 2 s at p95.

* Check host CPU and memory, large concurrent ingest batches (reduce `--max-bytes` in `aegis_push.py` or
  stagger collectors), PostgreSQL bloat (`VACUUM ANALYZE` in a maintenance window).

## After the incident

Write a blameless post-incident review within 5 business days: timeline, impact (including on data subjects),
root cause, what detected it, actions with owners. For SEV1, attach the `aegis ledger verify` output and the
relevant ledger entry ids.
