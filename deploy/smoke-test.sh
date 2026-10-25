#!/usr/bin/env bash
# End-to-end smoke test of the production compose stack (PostgreSQL + API + monitoring).
#
#   deploy/smoke-test.sh            # builds the image, starts an isolated stack, tests, tears down
#   KEEP=1 deploy/smoke-test.sh     # leave the stack running for inspection
#   AEGIS_IMAGE=registry/aegis-omega:1.0.0 NO_BUILD=1 deploy/smoke-test.sh
#
# The stack runs under its own compose project name with throwaway secrets and dev auth (so a
# token can be minted without an IdP). Everything else is the production path: PostgreSQL,
# read-only non-root container, metrics token, Prometheus scrape with the alert rules loaded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${PROJECT:-aegis-smoke}"
PORT="${PORT:-18765}"
PROM_PORT="${PROM_PORT:-19765}"
GRAFANA_PORT="${GRAFANA_PORT:-13765}"
IMAGE="${AEGIS_IMAGE:-aegis-omega:smoke}"
TENANT="smoke-tenant"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/smoke.env"
METRICS_TOKEN="$(openssl rand -hex 24)"

log() { printf '[smoke] %s\n' "$*"; }
fail() { printf '[smoke] FAIL: %s\n' "$*" >&2; exit 1; }

compose() {
  docker compose -p "$PROJECT" -f "$ROOT/deploy/docker-compose.yml" --env-file "$ENV_FILE" --profile monitoring "$@"
}

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    compose logs --no-color --tail 80 api 2>/dev/null || true
  fi
  if [[ "${KEEP:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
  else
    log "stack left running (project $PROJECT, env $ENV_FILE)"
  fi
  exit $rc
}
trap cleanup EXIT

sed -e "s|^AEGIS_IMAGE=.*|AEGIS_IMAGE=$IMAGE|" \
    -e "s|^AEGIS_PORT=.*|AEGIS_PORT=$PORT|" \
    -e "s|^PROMETHEUS_PORT=.*|PROMETHEUS_PORT=$PROM_PORT|" \
    -e "s|^GRAFANA_PORT=.*|GRAFANA_PORT=$GRAFANA_PORT|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" \
    -e "s|^AEGIS_PSEUDONYM_MASTER_KEY=.*|AEGIS_PSEUDONYM_MASTER_KEY=$(openssl rand -hex 32)|" \
    -e "s|^AEGIS_METRICS_TOKEN=.*|AEGIS_METRICS_TOKEN=$METRICS_TOKEN|" \
    -e "s|^GRAFANA_ADMIN_PASSWORD=.*|GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16)|" \
    -e "s|^AEGIS_ENV=.*|AEGIS_ENV=development|" \
    -e "s|^AEGIS_AUTH_MODE=.*|AEGIS_AUTH_MODE=dev|" \
    "$ROOT/deploy/.env.example" > "$ENV_FILE"

if [[ "${NO_BUILD:-0}" != "1" ]]; then
  log "building $IMAGE"
  docker build -q -t "$IMAGE" "$ROOT" >/dev/null
fi

log "starting postgres + api + prometheus + grafana (project $PROJECT)"
compose up -d --wait --wait-timeout 240 >/dev/null

API="http://127.0.0.1:$PORT"
ready="$(curl -fsS "$API/readyz")" || fail "readyz not 200"
grep -q '"database":"ok"' <<<"$ready" || fail "database not ok: $ready"
log "ready: $ready"

curl -fsS "$API/" | grep -qi '<!doctype html>' || fail "console not served at /"

code="$(curl -s -o /dev/null -w '%{http_code}' "$API/metrics")"
[[ "$code" == "401" ]] || fail "/metrics without token returned $code (want 401)"
curl -fsS -H "Authorization: Bearer $METRICS_TOKEN" "$API/metrics" | grep -q '^aegis_ready 1' || fail "metrics not served"

code="$(curl -s -o /dev/null -w '%{http_code}' "$API/api/v1/findings")"
[[ "$code" == "401" ]] || fail "unauthenticated API call returned $code (want 401)"

TOKEN="$(compose exec -T api aegis token --tenant "$TENANT" --sub smoke-admin --role admin --role integration --role analyst)"
AUTH=(-H "Authorization: Bearer $TOKEN")

curl -fsS "${AUTH[@]}" -H 'Content-Type: application/json' -X POST "$API/api/v1/sources" \
  -d '{"source_id":"smoke-netflow","source_kind":"netflow","vantage":"device","collection_authorization_id":"smoke-auth-001","retention_days":7}' >/dev/null \
  || fail "source registration"

out="$(curl -fsS "${AUTH[@]}" -H 'Content-Type: text/csv' -X POST \
  "$API/api/v1/ingest?source_id=smoke-netflow&flush=true&name=netflow.csv" \
  --data-binary @"$ROOT/sample_data/lab/netflow.csv")" || fail "ingest"
python3 - "$out" <<'PY' || fail "ingest stats"
import json, sys
s = json.loads(sys.argv[1])["stats"][0]
assert s["records_read"] > 0 and s["accepted"] == s["records_read"] and s["quarantined"] == 0, s
print(f"[smoke] ingested {s['accepted']} NetFlow records, 0 quarantined")
PY

out="$(curl -fsS "${AUTH[@]}" -H 'Content-Type: text/csv' -X POST "$API/api/v1/ingest?source_id=smoke-netflow" \
  --data-binary @"$ROOT/sample_data/formats/malformed_netflow.csv")" || fail "malformed ingest"
python3 - "$out" <<'PY' || fail "malformed records must be quarantined, not dropped"
import json, sys
s = json.loads(sys.argv[1])["stats"][0]
assert s["quarantined"] > 0 and s["accepted"] + s["quarantined"] + s["duplicates"] == s["records_read"], s
print(f"[smoke] malformed file: {s['quarantined']} records quarantined with original bytes")
PY

purge="$(PROJECT="$PROJECT" ENV_FILE="$ENV_FILE" "$ROOT/deploy/purge-expired.sh" --dry-run)" || fail "purge dry run"
grep -q "^$TENANT [1-9]" <<<"$(PROJECT="$PROJECT" ENV_FILE="$ENV_FILE" "$ROOT/deploy/purge-expired.sh" --dry-run --before 2999-01-01T00:00:00Z)" \
  || fail "purge dry run does not see the quarantined records"
grep -q "^$TENANT " <<<"$purge" && fail "records not yet expired were reported as expired"
PROJECT="$PROJECT" ENV_FILE="$ENV_FILE" "$ROOT/deploy/purge-expired.sh" --before 2999-01-01T00:00:00Z >/dev/null || fail "purge"
left="$(curl -fsS "${AUTH[@]}" "$API/api/v1/ingest/quarantine" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])')"
[[ "$left" == "0" ]] || fail "retention purge left $left quarantined records"
log "retention purge removed expired quarantined records"

verify="$(curl -fsS "${AUTH[@]}" "$API/api/v1/ledger/verify")" || fail "ledger verify"
grep -q '"ok":true' <<<"$verify" || fail "ledger chain did not verify: $verify"
log "ledger: $verify"

other="$(compose exec -T api aegis token --tenant other-tenant --sub intruder --role admin)"
n="$(curl -fsS -H "Authorization: Bearer $other" "$API/api/v1/sources" | python3 -c 'import json,sys; print(json.load(sys.stdin)["total"])')"
[[ "$n" == "0" ]] || fail "tenant isolation: other tenant sees $n sources"

log "restarting api to check state survives (PostgreSQL + data volume)"
compose restart api >/dev/null
compose up -d --wait --wait-timeout 120 api >/dev/null
curl -fsS "${AUTH[@]}" "$API/api/v1/sources" | grep -q smoke-netflow || fail "source lost after restart"
curl -fsS "${AUTH[@]}" "$API/api/v1/ledger/verify" | grep -q '"ok":true' || fail "ledger after restart"

for _ in $(seq 1 30); do
  health="$(curl -fsS "http://127.0.0.1:$PROM_PORT/api/v1/targets" | python3 -c \
    'import json,sys; t=[x for x in json.load(sys.stdin)["data"]["activeTargets"] if x["labels"]["job"]=="aegis-api"]; print(t[0]["health"] if t else "none")')" || health=none
  [[ "$health" == "up" ]] && break
  sleep 2
done
[[ "$health" == "up" ]] || fail "prometheus cannot scrape the api (health=$health)"
rules="$(curl -fsS "http://127.0.0.1:$PROM_PORT/api/v1/rules" | python3 -c \
  'import json,sys; print(sum(len(g["rules"]) for g in json.load(sys.stdin)["data"]["groups"]))')"
[[ "$rules" -gt 0 ]] || fail "no alert rules loaded"
log "prometheus scraping api, $rules rules loaded"

log "PASS"
