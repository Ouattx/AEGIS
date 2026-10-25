# AEGIS OMEGA — SHIELD

Evidence-first network/device security intelligence for ISPs and operators.
Source spec: `docs/spec/AEGIS_OMEGA_Engineering_Master_Spec_v3.txt` (section numbers below refer to it).
Module interfaces: `docs/ARCHITECTURE.md` — the contract every module must honor.

## Product decisions (fixed)
- v1 ships **SHIELD only**. RIGHTS is out of scope; do not build it.
- Deployable **on-prem / sovereign** (docker compose, single host) and as hosted SaaS from the same artifacts.
- Sold first as a **paid shadow-mode pilot**: read-only, alerts and reports, zero blocking.
  Active enforcement exists but is off unless a signed operator policy with `mode="active"` and legal signoff ref is loaded.

## Non-negotiables
- AI proposes; deterministic code authorizes. No LLM output ever changes policy, models, or enforcement.
- The whole detection path works with no LLM configured (`ANTHROPIC_API_KEY` unset).
- Abstain is a first-class outcome. Missing values are `None` + missingness flag, never 0.
- Never infer compromise from device class, vendor, IPTV app usage, or geography alone.
- Every finding cites evidence ids; every state change and action is written to the provenance ledger.
- Every store read is tenant-scoped. No cross-tenant query paths.
- Fail closed: unknown topology, missing/expired authorization, unverified signature => deny.
- No DPI payloads, no TLS decryption, no subscriber identity in events (pseudonyms only).

## Conventions
- Python 3.11+, package `aegis/`, contracts in `aegis/contracts/models.py` (do not change without bumping schema_version).
- Storage via `aegis/storage/db.py` (`make_engine`, `init_db`, `DocStore`). SQLite in tests, PostgreSQL in prod.
- Hashing via `aegis/contracts/canonical.py` (`sha256_hex`, RFC 8785 canonical JSON).
- Timestamps are timezone-aware UTC `datetime`.
- Tests: `pytest -q`. Unit tests in `tests/unit/`, spec §15 safety tests in `tests/safety/` (marker `safety`), end-to-end in `tests/integration/`.
- Default LLM model id: `claude-sonnet-5-5` (configurable via `AEGIS_LLM_MODEL`).
- Keep code readable and typed; docstrings where behavior is non-obvious. No placeholder `TODO` stubs in shipped code paths.
- Commit only the paths you own, with a clear message. If `.git/index.lock` exists, wait a few seconds and retry.
