#!/usr/bin/env bash
# Enforce retention on quarantined raw records (the only stored artifact that can contain
# un-pseudonymized collector bytes, kept so operators can diagnose and replay bad input).
#
#   deploy/purge-expired.sh                 # delete quarantined records whose retention_until has passed
#   deploy/purge-expired.sh --dry-run       # report what would be deleted
#   deploy/purge-expired.sh --before 2026-12-01T00:00:00Z
#
# Every quarantined record carries `retention_until` = quarantine time + the source's
# retention_days. Schedule this daily (cron or a systemd timer, docs/INSTALL.md) and keep its
# output in the operator's change log. It touches nothing else: findings, evidence and the
# signed ledger hold pseudonymous data only and follow the case retention policy
# (docs/compliance/DATA_MAP.md).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/deploy/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
PROJECT_ARGS=()
[[ -n "${PROJECT:-}" ]] && PROJECT_ARGS=(-p "$PROJECT")

DRY_RUN=0
BEFORE="now"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --before) BEFORE="${2:?--before needs an RFC 3339 timestamp}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ "$BEFORE" != "now" && ! "$BEFORE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}([T\ ][0-9:.]+)?(Z|[+-][0-9]{2}:?[0-9]{2})?$ ]]; then
  echo "--before must be an RFC 3339 timestamp" >&2
  exit 2
fi

compose() { docker compose "${PROJECT_ARGS[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

if [[ "$DRY_RUN" == "1" ]]; then
  SQL="SELECT tenant_id, count(*) AS expired FROM docs
       WHERE kind = 'Quarantined' AND (body->>'retention_until')::timestamptz < :'cutoff'::timestamptz
       GROUP BY tenant_id ORDER BY tenant_id;"
else
  SQL="WITH gone AS (
         DELETE FROM docs
         WHERE kind = 'Quarantined' AND (body->>'retention_until')::timestamptz < :'cutoff'::timestamptz
         RETURNING tenant_id)
       SELECT tenant_id, count(*) AS deleted FROM gone GROUP BY tenant_id ORDER BY tenant_id;"
fi

echo "[purge] $(date -u +%Y-%m-%dT%H:%M:%SZ) cutoff=${BEFORE} dry_run=${DRY_RUN}"
# shellcheck disable=SC2016  # expanded by the shell inside the postgres container
compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v cutoff="$1" -A -F " " -P footer=off' \
  sh "$BEFORE" <<<"$SQL"
