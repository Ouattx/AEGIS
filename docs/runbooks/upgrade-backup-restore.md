# Runbook: backup, restore and upgrade

Commands assume the repository checkout on the AEGIS host and `C="docker compose -f deploy/docker-compose.yml"`.

## Backup

```bash
deploy/backup.sh /secure/backups/$(date -u +%FT%H%MZ)
```

Produces `postgres.dump` (findings, cases, evidence, signed ledger, audit), `aegis-data.tar.gz` (ledger
signing key, trusted public keys, tenant pseudonym keys) and `SHA256SUMS`. The API keeps running.

* Schedule daily (cron or systemd timer) and before every upgrade or key rotation.
* Encrypt to the operator's backup key and store off-host (`age -r <recipient> -o x.age x`, or the backup
  system's encryption). The archive contains private keys and pseudonymous security data.
* Keep `deploy/.env` in the operator's vault: a restore needs the same `AEGIS_PSEUDONYM_MASTER_KEY` and
  database credentials.
* Retention of backups follows the same retention schedule as the live data (DATA_MAP section 5).

Test the restore quarterly on a separate host (below), and record the result: a backup that has never been
restored is not a backup.

## Restore

```bash
# on the target host: same repository version, same deploy/.env, images available
$C up -d postgres                       # fresh or existing stack
deploy/restore.sh /secure/backups/2026-11-02T0300Z
for t in <tenants>; do $C exec api aegis ledger verify --tenant "$t"; done
```

`restore.sh` checks the checksums, asks for confirmation (`ASSUME_YES=1` for automation), stops the API,
restores PostgreSQL (`pg_restore --clean`), replaces the data volume, starts the API and waits until it is
healthy. Telemetry ingested after the backup must be re-sent from the collectors' done directories.

## Upgrade

Release notes state whether a release changes the database schema or configuration.

1. Read the release notes; verify the new image signature (INSTALL.md section 3).
2. Back up: `deploy/backup.sh /secure/backups/pre-upgrade-$(date -u +%FT%H%MZ)`.
3. Update the checkout to the release tag (for `deploy/` changes) and set the new `AEGIS_IMAGE` digest in
   `deploy/.env`; add any new variables from `deploy/.env.example` (`diff` the two files).
4. Recreate: `$C pull api` (or `make image`), then `$C up -d`. The API creates new tables at start.
5. Validate:
   * `curl -s http://127.0.0.1:8000/readyz` is ready and shows the new version in `/healthz`;
   * `aegis ledger verify --tenant <tenant>` is ok for each tenant;
   * push one collector file and check the ingest counters in Grafana;
   * open the console and load a case.
6. If any check fails: [rollback.md section B](rollback.md#b-roll-back-an-aegis-release).

Downtime is the container restart (seconds) plus start-up model loading. Collectors keep their files in the
spool and the next timer run sends them; nothing is lost if the window is shorter than the spool capacity.

## Disaster recovery targets (pilot)

| | Target | How |
|---|---|---|
| RPO | 24 h | daily backup; collectors' done directories allow re-sending the last day |
| RTO | 4 h | restore on a prepared host with images pre-loaded |
