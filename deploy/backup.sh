#!/usr/bin/env bash
# Back up an AEGIS OMEGA SHIELD compose deployment.
#
#   deploy/backup.sh [OUTPUT_DIR]          (default ./backups/<UTC timestamp>)
#
# Produces:
#   postgres.dump        pg_dump custom format (findings, cases, evidence, signed ledger, audit)
#   aegis-data.tar.gz    the data volume: ledger signing key, trusted public keys, tenant
#                        pseudonymization keys, raw collector files kept under retention
#   SHA256SUMS           checksums of both files
#
# The archive contains private keys and pseudonymous security telemetry. Encrypt it at rest
# (e.g. `age`/`gpg` to the operator's backup key) and store it under the same access controls
# and retention limits as the live system. Restore with deploy/restore.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/deploy/docker-compose.yml}"
ENV_FILE="${ENV_FILE:-$ROOT/deploy/.env}"
PROJECT_ARGS=()
[[ -n "${PROJECT:-}" ]] && PROJECT_ARGS=(-p "$PROJECT")
OUT="${1:-$ROOT/backups/$(date -u +%Y%m%dT%H%M%SZ)}"

compose() { docker compose "${PROJECT_ARGS[@]}" -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"; }

umask 077
mkdir -p "$OUT"

echo "[backup] dumping PostgreSQL"
# shellcheck disable=SC2016  # expanded by the shell inside the postgres container
compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner' > "$OUT/postgres.dump"

echo "[backup] archiving the AEGIS data volume"
compose exec -T api tar czf - -C /var/lib/aegis . > "$OUT/aegis-data.tar.gz"

( cd "$OUT" && sha256sum postgres.dump aegis-data.tar.gz > SHA256SUMS )
[[ -s "$OUT/postgres.dump" && -s "$OUT/aegis-data.tar.gz" ]] || { echo "[backup] FAIL: empty output" >&2; exit 1; }
echo "[backup] done: $OUT"
cat "$OUT/SHA256SUMS"
