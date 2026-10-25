#!/usr/bin/env bash
# Restore an AEGIS OMEGA SHIELD compose deployment from deploy/backup.sh output.
#
#   deploy/restore.sh BACKUP_DIR
#
# Replaces the database contents and the data volume, then starts the API and verifies
# readiness. Run it against a stopped or freshly created stack; it asks for confirmation
# unless ASSUME_YES=1. The ledger is verified per tenant afterwards with
#   docker compose -f deploy/docker-compose.yml exec api aegis ledger verify --tenant <tenant>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/deploy/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
PROJECT_ARGS=()
[[ -n "${PROJECT:-}" ]] && PROJECT_ARGS=(-p "$PROJECT")
SRC="${1:?usage: deploy/restore.sh BACKUP_DIR}"

compose() { docker compose "${PROJECT_ARGS[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

for f in postgres.dump aegis-data.tar.gz SHA256SUMS; do
  [[ -s "$SRC/$f" ]] || { echo "[restore] missing $SRC/$f" >&2; exit 1; }
done
( cd "$SRC" && sha256sum -c SHA256SUMS ) || { echo "[restore] checksum mismatch: refusing to restore" >&2; exit 1; }

if [[ "${ASSUME_YES:-0}" != "1" ]]; then
  read -r -p "[restore] this REPLACES the database and data volume of the deployment. Type 'restore' to continue: " answer
  [[ "$answer" == "restore" ]] || { echo "[restore] aborted"; exit 1; }
fi

echo "[restore] stopping the API"
compose stop api >/dev/null
compose up -d --wait postgres >/dev/null

echo "[restore] restoring PostgreSQL"
# shellcheck disable=SC2016  # expanded by the shell inside the postgres container
compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner --exit-on-error' \
  < "$SRC/postgres.dump"

echo "[restore] restoring the data volume"
compose run --rm --no-deps -T --entrypoint sh api -c \
  'find /var/lib/aegis -mindepth 1 -delete && tar xzf - -C /var/lib/aegis' < "$SRC/aegis-data.tar.gz"

echo "[restore] starting the API"
compose up -d --wait api >/dev/null
echo "[restore] done; verify each tenant's ledger with: aegis ledger verify --tenant <tenant>"
