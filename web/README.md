# AEGIS OMEGA SHIELD — analyst console

React + TypeScript single-page app served by the AEGIS API from `web/dist` (same origin,
strict CSP: no inline scripts, no external origins; every asset is bundled).

Screens: Overview (KPIs, trends, posture), Findings, Cases, Case detail (hypothesis vs
alternatives, evidence trail with hashes and source-independence groups, decision timeline,
investigation report, ATLAS graph neighbourhood, replay-as-of), Actions (propose → MIRROR
simulation → authorization checklist → four-eyes approval → execute / roll back), Ledger,
Reports (shadow proof-of-value report) and Settings (policy and enforcement mode).

## Build

```bash
cd web
npm ci
npm run build        # type-checks, then writes web/dist (served by `aegis serve` / `aegis demo`)
```

## Develop

```bash
aegis demo --port 8000          # seeded demo tenant, dev auth with role picker
cd web && npm run dev           # http://localhost:5173, /api proxied to $AEGIS_API (default :8000)
```

## Test

```bash
npm test                        # vitest: libraries, API client, auth, and app flows against a fake API
npm run smoke                   # Playwright end-to-end against a running `aegis demo` ($AEGIS_URL)
AEGIS_URL=http://127.0.0.1:8000 node scripts/smoke.cjs --screenshots ../docs/screenshots
```

The smoke test walks the full workflow as analyst, approver, admin and viewer and fails on any
page error, console error or 5xx response. Run it against a fresh `aegis demo`: it reviews and
verifies one of the INVESTIGATING demo cases, then proposes, simulates, assesses and denies an
action.

## Authentication

* `AEGIS_AUTH_MODE=dev` with a demo tenant: role picker using `/api/v1/demo/token`.
* OIDC deployments: the sign-in screen accepts an access token issued by the configured
  identity provider (tenant and roles come only from its claims). The session ends when the
  token expires or the API answers 401. Tokens live in `sessionStorage` (per tab).

The UI gates buttons by the caller's permissions for clarity only; the API enforces every
permission, state-machine guard and authorization check itself.
