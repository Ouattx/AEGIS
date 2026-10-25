# Runbook: rollback of enforcement and of a release

Two different things are called rollback: removing an enforcement action from the network, and returning to
the previous AEGIS version. Both are below.

In a shadow pilot (`AEGIS_ENFORCEMENT_ADAPTER=dryrun` and a `shadow` policy) nothing is ever applied to the
network, and the `AegisEnforcementApplied` alert must never fire. If it does, treat it as SEV1: the deployment
is not configured as agreed.

## A. Roll back an enforcement action

Who: a user with the `approver` role (the API refuses anyone else). Rollback restores the enforcement point to
its state before the action (RPZ zone entry removed, or the webhook receiver told to undo) and moves the case
to `ROLLED_BACK`. Every step is in the ledger.

**Console:** Actions -> select the action -> "Roll back" -> give a reason -> confirm.

**API:**

```bash
curl -fsS -X POST "$API/api/v1/actions/<action_id>/rollback" -H "Authorization: Bearer $APPROVER_TOKEN" \
  -H 'Content-Type: application/json' -d '{"reason": "customer-care escalation: legitimate service affected"}'
```

The response contains the execution record (`status: rolled_back`) and the new case state.

Automatic rollbacks (no human needed):

* **Expiry.** Every action has an `expires_at` bounded by the policy's `max_ttl_hours`; the sweeper (every
  `AEGIS_SWEEP_INTERVAL_S`) rolls back expired live actions.
* **Circuit breaker.** Resolver / NOC telemetry feeds legitimate-traffic health samples for each live action
  (`POST /api/v1/actions/<action_id>/health` with `{"requests": N, "errors": E}`, integration or approver
  token). On an abnormal error rate the breaker trips, rolls back the affected live action (its case moves to
  ROLLED_BACK) and refuses new executions while open (`/readyz` and `GET /api/v1/enforcement/breaker` show
  `open`). Once the cause is understood an approver closes it with a reason, which is ledgered:
  `curl -X POST -H "Authorization: Bearer $APPROVER" -d '{"reason":"resolver fixed"}' .../api/v1/enforcement/breaker/reset`.

Verify after any rollback:

1. RPZ adapter: the AEGIS zone file no longer contains the owner name; the resolver reloaded
   (`AEGIS_RPZ_RELOAD_COMMAND` output in the API logs); `dig @<resolver> <domain>` returns the real answer.
2. Webhook adapter: the receiver's own log shows the undo request (HMAC-signed, same action id).
3. `GET /api/v1/actions/<action_id>` shows `rolled_back`; the case history shows `ROLLED_BACK`.

## Rollback failed

`AegisRollbackFailed` pages when a rollback request is refused (409) or the adapter could not restore the
prior state. The action stays recorded as live so it can be retried.

1. Read the refusal: `failed_checks` in the 409 response or the API log line for the request id.
   `no_live_execution` means there was nothing live to roll back (check whether it already expired or the
   breaker rolled it back). `rollback_failed` means the adapter failed.
2. Retry once from the console or API after fixing the cause (resolver unreachable, zone file permissions,
   webhook receiver down).
3. If it still fails and the enforcement is harming legitimate traffic, remove it at the enforcement point
   directly (operator-owned):
   * RPZ: remove the AEGIS RPZ zone from the resolver's `response-policy` list (or empty the AEGIS zone file)
     and reload the resolver. This removes every AEGIS entry at once.
   * Webhook: disable the corresponding rule in the receiving system.
   Then record the manual action as a note on the case (`POST /api/v1/cases/<id>/notes`) so the ledger
   shows what was done outside AEGIS, and set `AEGIS_ENFORCEMENT_ADAPTER=dryrun` until the cause is fixed.

## B. Roll back an AEGIS release

Releases are images; data lives in PostgreSQL and the data volume. Always back up before an upgrade
([upgrade-backup-restore.md](upgrade-backup-restore.md)), because a newer release may migrate the schema.

1. `deploy/backup.sh /secure/backups/pre-rollback-$(date -u +%FT%H%MZ)` (keeps the current state for analysis).
2. Set `AEGIS_IMAGE` in `deploy/.env` back to the previous image digest.
3. If the newer release changed the database (its release notes say so), restore the pre-upgrade backup:
   `deploy/restore.sh /secure/backups/<pre-upgrade>`. Otherwise just recreate the container:
   `docker compose -f deploy/docker-compose.yml up -d api`.
4. Check `/readyz`, then `aegis ledger verify --tenant <tenant>` for each tenant.
5. Anything ingested between the backup and the rollback must be re-sent from the collectors' done
   directories (de-duplication absorbs overlaps while the API stays up).
