# Runbook: key and secret rotation

Schedule: rotate every key below at least yearly, at staff changes affecting key custody, and immediately on
suspected compromise (SEV1, see [incident.md](incident.md)). Back up before any rotation
(`deploy/backup.sh`). Commands assume `C="docker compose -f deploy/docker-compose.yml"`.

| Secret | Where it lives | Effect of rotation | Downtime |
|---|---|---|---|
| Ledger signing key | data volume `keys/ledger-<id>.pem`; public key in `trusted/ledger/` | new entries signed by the new key; old entries keep verifying | API restart |
| Operator policy signing key | operator vault (private); `trusted/policy/` (public; `trusted/policy/<tenant>/` binds the key to one tenant) | policies must be re-signed | API restart |
| IOC bundle signing key | operator vault (private); `trusted/ioc/` (public) | next bundles signed with the new key | API restart |
| Pseudonymization master key | `deploy/.env` `AEGIS_PSEUDONYM_MASTER_KEY` (+ vault escrow) | **all pseudonyms change**: plan carefully | API restart |
| OIDC signing keys | the IdP | automatic: unknown `kid` triggers a JWKS refresh | none |
| Metrics token | `deploy/.env` `AEGIS_METRICS_TOKEN` | Prometheus must use the new value | API + Prometheus recreate |
| PostgreSQL password | `deploy/.env` + database role | | API recreate |
| Webhook HMAC secret | `deploy/.env` `AEGIS_WEBHOOK_SECRET` + receiver | coordinate with the receiver | API recreate |
| TLS certificates | reverse proxy | | proxy reload |

## Ledger signing key

1. Pick a new key id and set it in `deploy/.env`: `AEGIS_LEDGER_KEY_ID=aegis-ledger-2027`.
2. `$C up -d api`. On start the API generates `keys/ledger-aegis-ledger-2027.pem`, installs its public key in
   `trusted/ledger/`, and signs new entries with it. The previous public key stays trusted, so older entries
   still verify.
3. Verify each tenant: `$C exec api aegis ledger verify --tenant <tenant>`; `trusted_ledger_keys` lists both
   ids and `ok` is true.
4. Retire the old private key (it is no longer used):
   `$C exec api rm /var/lib/aegis/keys/ledger-aegis-ledger.pem`. Keep its public key in `trusted/ledger/`.
5. Back up (the new private key is only in the data volume until then).

**On compromise** of the ledger key: rotate as above at once, record the rotation time and the
`head_hash` from `ledger verify` in the incident ticket and in a write-once store outside the host. Entries
signed by the old key after the suspected compromise time are not trustworthy; the hash chain and that
externally anchored head hash bound what an attacker could have rewritten. If the old key must be distrusted
entirely, remove its public key from `trusted/ledger/` and restart: verification will then report the first
entry signed by it, which is the expected, documented outcome.

## Operator policy and IOC signing keys

These private keys never live on the AEGIS host.

1. Generate the new key pair offline (INSTALL.md section 8.2) with a new id, e.g. `acme-policy-2027`.
2. Install the new public key next to the old one and restart:
   `$C exec -T api sh -c 'cat > /var/lib/aegis/trusted/policy/acme-policy-2027.pem' < acme-policy-2027.pem`
   then `$C restart api`.
3. Re-sign the current policy with the new key under a new `policy_id` (`aegis policy sign`, INSTALL.md 8.4)
   and upload it. For IOC bundles, sign the next bundle version with the new key.
4. Remove the old public key and restart:
   `$C exec api rm /var/lib/aegis/trusted/policy/acme-policy-2026.pem && $C restart api`.
   Policies signed only by the removed key no longer verify, and authorization fails closed for them; an
   action approved under such a policy is refused at execution.
5. Destroy the old private key per the operator's key-management procedure.

## Pseudonymization master key

Rotating it changes every entity pseudonym: behaviour baselines restart, and new findings cannot be linked
to earlier cases by pseudonym. Rotate at a planned boundary (e.g. between pilot and production), not in the
middle of an evaluation.

1. Escrow the current key with its validity period: the operator needs it to re-identify lines in cases
   created before the rotation, for as long as those cases are retained.
2. Set the new value (`openssl rand -hex 32`) in `deploy/.env` and `$C up -d api`.
3. Note the rotation time in the pilot or operations log; the proof-of-value report should not compare
   per-device metrics across the boundary.

## Metrics token

Set the new `AEGIS_METRICS_TOKEN` in `deploy/.env`, then `$C --profile monitoring up -d api prometheus`.
The Prometheus target returns to `up` within one scrape interval.

## PostgreSQL password

```bash
NEW=$(openssl rand -hex 32)   # hex only, so it is safe inside the SQL quotes
$C exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  <<<"ALTER ROLE CURRENT_USER PASSWORD '$NEW';"
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$NEW/" deploy/.env
$C up -d api
```

The postgres container keeps using its data directory; `POSTGRES_PASSWORD` is only read at first
initialization, so `.env` and the role must be changed together as above.

## After every rotation

* `/readyz` is ready; `aegis ledger verify` is ok for each tenant.
* Back up the data volume (`deploy/backup.sh`).
* Record who rotated what, when and why in the operator's key-management log.


## Emergency revocation (compromised key)

Revoke the key at once; no restart is needed:

```bash
$C exec api aegis keys revoke --kind policy --key-id acme-policy-2026 --reason "private key exposed" --actor secops.alice
```

`--kind` is `policy`, `ioc`, `ledger` or `model`. The revocation is written to `trusted/<kind>/revoked.txt`
and to every tenant's ledger; the running API applies it within one sweep interval (`AEGIS_SWEEP_INTERVAL_S`,
default 60 s) and on every restart, even if the public key file is still on disk. Policies signed by a revoked
key stop authorizing immediately; an IOC bundle signed by it is deactivated. The active ledger signing key
cannot be revoked: rotate it first (above), then revoke the old id.

Model artifact signatures use their own trust directory, `trusted/model/` (with
`AEGIS_MODEL_REQUIRE_SIGNATURE=true`); a model publisher key is never trusted for ledger verification.
