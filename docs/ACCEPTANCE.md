# Acceptance evidence: spec section 17 checklist

This file maps every item of the final acceptance checklist (spec section 17) to the evidence in this
repository, and marks honestly what can only be closed with a real customer. It also maps the spec section 15
mandatory adversarial tests to executable tests.

Status legend:

- **Met (lab)**: implemented and demonstrated by automated tests on the lab corpus and the real composed system.
- **Partial**: implemented, but the item as written needs a real operator, real telemetry or an outside party.
- **Customer**: can only be closed during or after a paid pilot.

How to reproduce everything below:

```bash
pip install -e ".[dev]"
python -m pytest -q -m safety          # spec section 15 tests (also run as a separate CI step)
python -m pytest -q tests/integration   # full demo flow, end to end through the API
python -m pytest -q                     # everything
python -m eval.run_benchmark --out eval/results   # independent benchmark (section 14)
```

## Spec section 15: mandatory tests

All tests below carry the `safety` marker. They drive the **real composed system**: an `AegisService`
with its own SQLite store, the shipped calibrated detection model, a real RPZ enforcement adapter writing a
zone file, and the FastAPI app with role-scoped tokens. Lab telemetry goes in as collector files through the
production ingest pipeline. Only the language model is ever replaced, by an absent, failing or hostile client.
The shared worlds are built in `tests/safety/safety_kit.py`.

| Spec item | Test | What it proves |
|---|---|---|
| Benign IPTV untouched | `tests/safety/test_pilot_safety.py::test_benign_iptv_untouched` | On the 40-device pilot corpus, no benign IPTV box gets an alert, a case, an action or a zone entry. This includes the "busy" boxes whose flow count and volume are more than 4 times the median device. |
| Benign IPTV untouched (worst case) | `tests/safety/test_iptv_false_alert.py::test_benign_iptv_false_alert_is_never_enforceable` | On a corpus where the model **does** false-alert on a benign IPTV box, an active enforcement policy is loaded. The alert still cannot be verified: its evidence is model-only, from one origin. No action can be proposed against the device. |
| Malicious lab box detected | `test_pilot_safety.py::test_malicious_lab_box_detected` | Every emulated infection is alerted with the right label: BadBox-style C2 and proxy on TV boxes, Vo1d-style DGA, and Mirai-style DDoS. No alert comes before the infection. All evidence passes the integrity check, a case is opened and the findings are on a verified ledger. |
| Shared CDN not indiscriminately blocked | `tests/safety/test_enforcement_safety.py::test_shared_cdn_not_indiscriminately_blocked` | An IP block of the shared CDN address behind a C2 name gets the MIRROR verdict UNSAFE and lists its legitimate co-tenants. It is refused by authorize, approval, the execute API and the executor itself. The precise sinkhole of the name alone gets the verdict SAFE and is authorized. |
| Contradictory feeds downgrade finding | `tests/safety/test_contradictory_feeds.py` (2 tests) | The same telemetry is run in two tenants. When an independent feed contradicts the indicators, every IOC-backed MALICIOUS verdict is downgraded, no verdict is ever upgraded, and the counter-evidence is cited. Contested cases cannot be auto-verified, and the investigator escalates them. |
| Unavailable LLM does not disable baseline alerts | `test_pilot_safety.py::test_unavailable_llm_does_not_disable_baseline_alerts` | One deployment's LLM endpoint raises on every call. It produces exactly the same alerts, device by device, and the same case dispositions as a deployment with no LLM. Its investigations report `llm_status=failed`. |
| Expired authorization prevents action | `test_enforcement_safety.py::test_expired_authorization_prevents_action` | An approved action is refused at execution in two cases: (1) the action itself has expired, even with a fresh SAFE simulation; (2) the signed active policy has expired. A sweep then moves the expired approval to EXPIRED. Nothing reaches the zone. |
| Compromised agent cannot alter policy | `test_enforcement_safety.py::test_compromised_agent_cannot_alter_policy` | Agents cannot change case state. A forged policy, a tampered policy, or a policy posted with an integration token is refused. Tools stay read-only and scoped to their own agent. A response-planner draft is stripped of authority and fails authorization. Agents can neither approve nor execute, even a fully authorized action. Policies and trusted keys are unchanged afterwards. |
| Rollback restores service | `test_enforcement_safety.py::test_rollback_restores_service` | An executed RPZ sinkhole is removed from the zone file by an operator rollback through the API, and the case moves to ROLLED_BACK. Rollback is idempotent. The circuit breaker also rolls back automatically on legitimate-traffic errors, and the case follows. |
| Model drift prevents silent promotion | `tests/safety/test_model_drift_promotion.py` (3 tests) | When production windows have drifted, PSI blocks promotion. Automatic, agent and unacknowledged promotions are all refused and ledgered. The only way through is an explicit drift acknowledgement by a second human. A gate pass without drift still needs a human. Regressions, unsigned models and tampered models are hard blocks. Implemented in `aegis/sentinel/registry.py`. |
| Replay uses only contemporaneous evidence | `test_pilot_safety.py::test_replay_uses_only_contemporaneous_evidence` | Replay as of time T excludes evidence recorded after T and gives the same ledger head as at T. Replay before detection is empty. The API returns the same result. |

Additional adversarial tests (section 15 threat list):

| Threat | Test |
|---|---|
| Cross-tenant access | `test_pilot_safety.py::test_cross_tenant_isolation`. Every read and write by another tenant on the pilot's findings, cases, evidence, actions, graph and replay returns 404. Its lists and metrics are empty. Telemetry and policies that claim the pilot tenant are refused. A forged token returns 401. The pilot's ledger head is unchanged. |
| Compromised signing keys | `test_enforcement_safety.py::test_revoked_signing_key_rejected`. Runs on a restarted copy of the enforcement deployment. Once the policy key is revoked, an approved action cannot run. New policies signed with that key and re-trusting the key are both refused. Revoking the IOC key deactivates the active bundle and refuses reloads. Revoking a ledger key fails ledger verification. Every revocation is written to the ledger and survives a restart. |
| Spoofed telemetry | `test_pilot_safety.py::test_spoofed_telemetry_quarantined`. Nine kinds of forged events are quarantined and produce no detection: future timestamps, unknown sensor, forged authorization, raw subscriber IP, naive timestamp, smuggled payload field, bad integrity hash, unknown schema, missing authorization. Forged lines in a raw upload are quarantined too. |
| Prompt injection / malicious connector output | `test_pilot_safety.py::test_prompt_injection_in_tool_output_contained`. A compromised intel connector and an analyst note carry injected instructions, and a hostile LLM tries to obey them. The injected text reaches the model only as escaped data, and it is flagged. Out-of-contract tool and field requests are refused. The recommendation stays deterministic. Policies, models, case state, actions and the zone are unchanged. |
| Unauthorized blocking (shadow mode) | `test_pilot_safety.py::test_zero_unapproved_enforcement_in_shadow_mode`. Every verified case is driven through propose, simulate, authorize, approve and execute against a real RPZ adapter. Under the signed shadow policy everything is refused. The zone stays empty, every executor outcome is `refused`, and the PoV attestation reports `attested` with 0 live executions. |

Unit-level safety tests from the module owners also carry the `safety` marker:
`tests/unit/test_mirror_safety.py`, `test_oracle_state_machine.py`, `test_oracle_tools.py`,
`test_oracle_investigation.py`.

## Spec section 17: acceptance checklist

### A. All services have versioned contracts and owners: **Met (lab)**

- Shared contracts are in `aegis/contracts/models.py` (`SCHEMA_VERSION = "3.0"`, strict pydantic models that
  reject unknown fields). The validator rejects any other schema version
  (`test_spoofed_telemetry_quarantined`: `unsupported_schema`).
- Every module's public interface is listed in `docs/ARCHITECTURE.md`, the binding contract. Versioned artifact
  formats: the IOC bundle (`aegis.ioc_bundle/1`), model artifacts (`aegis.sentinel.model/1` with a signed
  manifest), the PoV report (`aegis.pov_report/1`) and the SENTINEL fusion policy (hashed into each
  `detector_version`).
- Owners: each module has one implementing owner, recorded in its commit history (`git log -- aegis/<module>`).
  A formal `CODEOWNERS` file depends on the customer-facing team structure and is not yet in the repository.

### B. Tests run in CI: **Met (lab)**

- `.github/workflows/ci.yml` runs lint, then the section 15 safety suite as its own step (`pytest -m safety`),
  then the full suite on Python 3.11 and 3.12 (ledger tests also on PostgreSQL), plus web, audit, SBOM and
  container jobs.
- Locally: `python -m pytest -q`. The suite includes unit, safety and integration tests.

### C. Every finding cites evidence: **Met (lab)**

- `test_malicious_lab_box_detected`: every alert has `evidence_ids`, each id resolves to stored evidence that
  passes the integrity check, and findings are on the ledger.
- `test_contradictory_feeds_downgrade_finding`: findings also cite counter-evidence (`counterevidence_ids`).
- The PoV report has an evidence-coverage section (`tests/integration/test_demo_flow.py` checks it is present).

### D. Counter-hypothesis review is implemented: **Met (lab)**

- The VERIFIED guard requires a recorded counter-hypothesis review (`aegis/oracle/state_machine.py`;
  `tests/unit/test_oracle_state_machine.py`).
- The alternative-hypothesis agent generates benign explanations, which the integration flow records in the
  review (`test_demo_flow.py`).
- When evidence is contested, a human verifier is required (`test_contested_cases_cannot_be_verified_automatically`).

### E. Model evaluation is reproducible: **Met (lab)**

- Training is deterministic (fixed seeds, single-threaded LightGBM, time-forward split, group isolation). See
  `aegis/sentinel/model.py` and the model card in `models/sentinel-default/model_card.json`.
- The benchmark harness `eval/run_benchmark.py` uses frozen datasets whose digests are pinned in
  `eval/frozen/manifest.json` (`tests/unit/test_eval_benchmark.py`).
- The promotion gate records hashes of the holdout and recent-window sets with each evaluation
  (`GateEvaluation.holdout_sha256` / `recent_sha256`) in the ledger.

### F. Zero unauthorized enforcement: **Met (lab)**

- `test_zero_unapproved_enforcement_in_shadow_mode`, `test_shared_cdn_not_indiscriminately_blocked`,
  `test_expired_authorization_prevents_action`, `test_compromised_agent_cannot_alter_policy`,
  `test_revoked_signing_key_rejected`, `test_benign_iptv_false_alert_is_never_enforceable`.
- The only executions in the suite are the deliberately authorized ones (active signed policy, legal sign-off,
  SAFE simulation, a second human approver): `test_rollback_restores_service` and `test_demo_flow.py`.
- The PoV zero-enforcement attestation is computed from executor ledger entries
  (`test_zero_unapproved_enforcement_in_shadow_mode`, `test_demo_flow.py`).

### G. Shadow pilot meets agreed false-alert budget: **Customer**

- What exists: the PoV report computes false alerts per 10k device-days against a configurable
  `false_alert_budget_per_10k` (`aegis/reports/pov.py`; `GET /api/v1/reports/pov`). Lab validation against
  independent ground truth is in the integration test.
- What is missing: the budget has to be agreed with the operator and measured on their telemetry over the pilot
  period. That cannot be done in the lab.
- **Small populations (resolved in the detector).** On lab tenants smaller than the model was trained on (about
  30 devices) the calibrated model alone scored benign IPTV boxes high: seed 11 gave a model-only alert on an
  `android_tv_iptv` box, seed 17 gave several, including an `iptv_busy_box` hard negative. Population-relative
  features (destination prevalence, rarity) learned on 90-260 device tenants do not transfer. The fusion policy
  now has a population guard (rule F2c, `min_model_population`, taken from the model card's
  `data.validated_min_population`, 47 for the shipped model, the smallest tenant window in its training corpora,
  and part of the policy hash): below it, model-only windows ABSTAIN and are held for review instead of alerting. Indicator-backed rules are unchanged. Regression:
  `tests/safety/test_small_population_guard.py` (several 30-device seeds) and `test_iptv_false_alert.py`, which
  also shows that a model-only alert let through by an overstated model card can never become enforcement.
  Trade-off: on such small tenants, compromised devices seen only by the model (no signed indicator contact)
  are ABSTAIN for review rather than SUSPICIOUS. Retraining on small tenant sizes would be needed to alert on
  them.

### H. Security/privacy review completed: **Partial**

- What exists: the threat model and controls are covered by the section 15 tests above, and pseudonymization
  is enforced at ingest (raw identifiers are quarantined: `test_spoofed_telemetry_quarantined`). Further
  material: `docs/SECURITY_ARCHITECTURE.md`, `docs/compliance/DATA_MAP.md`, a DPIA template
  (`docs/compliance/DPIA_TEMPLATE.md`) and `SECURITY.md`. CI runs dependency audits (pip-audit, npm audit)
  and builds SBOMs.
- What is missing: an independent security review, a penetration test, and a DPIA completed with the customer's
  DPO for their data flows. These need outside parties and the customer.

### I. Rollback demonstrated: **Met (lab)**

- Enforcement rollback: `test_rollback_restores_service` covers operator rollback through the API, automatic
  rollback by the circuit breaker, and idempotency. `test_demo_flow.py` covers rollback in the end-to-end flow.
- Expired actions are swept and rolled back (`AegisService.sweep_expired`, `test_expired_authorization_prevents_action`).
- Release rollback procedure: `docs/runbooks/rollback.md`.

### J. Unit economics and independent benchmark delivered: **Partial**

- Benchmark: `eval/run_benchmark.py` compares rules-only, supervised, the ensemble and external-style baselines
  on frozen datasets. It reports CIs, PR curves, per-class confusion matrices and false alerts per 10k
  device-days. The default model's model card has external-holdout results.
- Unit economics: the PoV report computes cost per monitored device-month from operator-supplied inputs
  (`CostSummary`, `operator_inputs_configured`).
- What is missing: an *independent* benchmark run by a third party (or by the customer on their data), and
  unit economics based on real infrastructure and analyst-time costs from the pilot. Both need the customer.

## Fixes made while writing these tests

These were found by the end-to-end tests above and fixed with the smallest backward-compatible change:

1. `aegis/oracle/tools.py`, `provenance_check`: the ledger chain was verified with the operator-policy keyring,
   so every investigation in a running deployment reported `ledger_chain_verification_failed` and escalated.
   `build_default_toolset` now takes `ledger_keyring`, and the service passes its ledger keyring. Regression
   checks: `test_prompt_injection_in_tool_output_contained` and `test_demo_flow.py`.
2. `aegis/oracle/tools.py`, `CandidateEdgeWriter`: re-investigating a case raised `AtlasConflictError`, which
   the API returned as HTTP 500, because the candidate-edge provenance id was reused for different content.
   The provenance id is now a digest of the observation, so identical re-deliveries are idempotent. Regression
   check: the re-investigation in `test_prompt_injection_in_tool_output_contained`.
3. `aegis/oracle/state_machine.py`: transitions that carry an authorization assessment now record a top-level
   `action_id`. A case replay therefore reaches the action, its authorization and its executions; before, these
   were missing from the replay. Regression check: `test_demo_flow.py`, replay decisions.
4. `aegis/service.py`:
   - `revoke_key()`: revocation is persisted (`trusted/<kind>/revoked.txt`) and applied before keys load on
     restart. Before, a restart re-trusted a revoked key whose `.pem` was still on disk. It deactivates IOC
     bundles signed by the revoked key and is written to the ledger.
   - After an automatic circuit-breaker rollback the case moves to ROLLED_BACK. Before, it stayed EXECUTED.
     Operators feed health samples through `report_legit_traffic()`.
   - `activate_model()`: a gated model swap that updates every tenant's SENTINEL and is written to the ledger.
     It is called by the registry's `on_promote`.
5. New `aegis/sentinel/registry.py` (model registry and pre-registered promotion gate), with unit tests in
   `tests/unit/test_sentinel_registry.py`.
