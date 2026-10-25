# Security architecture and threat model

Scope: AEGIS OMEGA SHIELD v1 as deployed with `deploy/docker-compose.yml` (single host, operator premises or
sovereign cloud). Audience: operator CISO, security architects, auditors. Every control below names the
automated test that exercises it; `pytest -q` runs all of them in CI, and `pytest -m safety` runs the spec
section 15 mandatory set.

## 1. Architecture and trust boundaries

```
 [collectors]--(1) HTTPS + integration token-->[reverse proxy, TLS/mTLS]--(2)-->[api container]--(3)-->[PostgreSQL]
 [analysts ]--(1) HTTPS + OIDC access token--->[                       ]         |  uid 10001, read-only rootfs
 [IdP      ]<--(4) OIDC discovery / JWKS --------------------------------------- |  data volume: keys, trusted keys
 [operator signing workstation]--(5) signed policies, IOC bundles (offline keys)-|
 [resolver / enforcement point]<--(6) RPZ file or signed webhook (active mode only)
 [LLM provider]<--(7) optional, pseudonymized case summaries, off by default
 [Prometheus]--(8) bearer token, /metrics (no tenant or subscriber labels)
```

| Boundary | Threat surface | Controls |
|---|---|---|
| (1) clients to proxy | interception, credential theft | TLS 1.2+ at the operator proxy; optional mTLS for collectors; short-lived OIDC tokens; MFA at the IdP |
| (2) proxy to API | header spoofing | API bound to 127.0.0.1; `X-Forwarded-*` trusted only from `AEGIS_FORWARDED_ALLOW_IPS` |
| (3) API to database | lateral movement | database on an internal Docker network with no egress, never published; SCRAM auth; per-deployment password |
| (4) IdP | forged tokens, key rollover | asymmetric algorithms only, issuer and audience pinned, JWKS cached with rate-limited refresh, fail closed when keys are unavailable |
| (5) signed artifacts | forged policy or feed | Ed25519 signatures verified against operator-trusted public keys; private keys never on the AEGIS host |
| (6) enforcement | unauthorized or harmful blocking | dry-run by default; `authorize()` conjunction; four-eyes; circuit breaker; expiry and rollback |
| (7) LLM | data disclosure, prompt injection | disabled in the compose default; pseudonymized inputs; outputs advisory only, never authoritative |
| (8) monitoring | data leakage via metrics | bearer token; metric labels are route, status, verdict, step only |

Container hardening (asserted by `tests/unit/test_deploy_artifacts.py`): multi-stage build without compilers
in the runtime image, non-root uid 10001, read-only root file system, all capabilities dropped,
`no-new-privileges`, tmpfs `/tmp`, explicit environment allow-list (no unrelated secrets in the API process),
health checks, log rotation.

## 2. Identity, access and tenancy

* Authentication: OIDC access tokens (RS/PS/ES algorithms only); dev HS256 tokens are refused when
  `AEGIS_ENV=production`. Tenant and roles come only from verified claims.
* Authorization: five roles with least privilege (viewer, analyst, approver, admin, integration). Admin is
  not an approver; analysts cannot approve; approvers cannot approve their own proposals (four-eyes); the
  collector role can only push telemetry.
* Tenancy: every store read takes a tenant id from the token; there is no cross-tenant query path. Pseudonym
  keys, ledgers, sources, policies and topology are per tenant. Requests for another tenant's objects return
  404 (no existence oracle).
* Audit: every authenticated state-changing API call, including refused ones, is appended to the tenant's
  signed ledger with actor, roles, route, status, request body SHA-256 and client address. Every request
  (reads included) is also written to the JSON request log with request id, tenant, caller subject, route,
  status and duration.

## 3. Data protection by design

* Collected: flow and DNS security metadata only. Not collected: payloads, TLS plaintext, URLs, subscriber
  identity attributes.
* Subscriber source IPs and device MACs are pseudonymized at ingest with HMAC-SHA256 under a per-tenant key
  derived (HKDF) from the master key; the source IP is then dropped from the stored event.
* Raw bytes are retained only for records that fail validation (quarantine), admin-only, for the source's
  `retention_days`, purged by `deploy/purge-expired.sh`.
* Metrics carry no tenant ids, pseudonyms or indicators. Request logs carry the tenant id and the caller's
  subject (staff identity), not subscriber pseudonyms or telemetry.
* Details: [compliance/DATA_MAP.md](compliance/DATA_MAP.md).

## 4. Integrity and provenance

* Evidence records are content-addressed (SHA-256); corrections are new evidence, never updates.
* Each tenant has an append-only, hash-chained ledger; every entry is signed with the deployment's Ed25519
  ledger key. `aegis ledger verify` / `GET /api/v1/ledger/verify` detect any edited, deleted, reordered or
  re-signed-without-key entry.
* Truncation of the end of the chain: the in-database head record is unsigned, so on its own it only catches
  accidents. Every append also writes a signed `(tenant, seq, head hash, time)` checkpoint to an append-only
  file outside the database (`AEGIS_LEDGER_ANCHOR_PATH`; put it on another volume, a WORM store or ship it to
  the SIEM). Verification refuses a chain shorter than, or diverging from, the latest valid signed
  checkpoint, so an attacker with database access alone cannot erase approvals, refusals or revocations
  recorded at the end of the chain. Residual risk: an attacker controlling both the database and the anchor
  file can roll both back to an older consistent state; an off-host copy of the anchor closes that gap.
* Execution never trusts mutable documents for its gates: MIRROR is re-run at approval and at execution, the
  human approval must exist as a signed ledger entry bound to the very action id being executed, and the
  rollback rehearsal must be in the signed ledger.
* Replay reconstructs what was known at time T (evidence, model and rule versions, decisions) from the
  ledger, so an investigator can audit a past decision without hindsight.
* The detection model artifact carries a SHA-256 manifest (optionally signed); a tampered artifact is
  refused and the service runs rules-only with abstain rather than an unverified model.

## 5. Enforcement safety (spec section 9)

`authorize(action) = signed_operator_policy AND legal_basis_valid AND evidence_quality_pass AND
mirror_result == SAFE AND action.scope <= approved_scope AND action.expires_at set AND rollback_plan_verified`

Every conjunct is evaluated and reported; none is delegated to an LLM. A `shadow` policy fails the
"policy mode is active" check by design, and the newest valid signed policy is authoritative, so issuing a
newer shadow policy switches enforcement off. Shared hosting, uncertain collateral or an incomplete topology
yields UNKNOWN and fails closed. Targets must be tied to the case evidence (an unrelated target needs a
policy-approved `allow_unlinked_targets` scope, always needs a human, and is UNSAFE on shared hosting).
`rollback_plan_verified` is set only by a rehearsal of apply + rollback on the enforcement adapter, never by
the proposer. A second human approves, and the approval binds exactly one action: a sibling action of the
same case can never be executed on it. Execution is time-boxed; expired actions are swept and rolled back.
A circuit breaker rolls back automatically on abnormal legitimate-traffic error rates fed by
`POST /api/v1/actions/{id}/health` (integration collectors or approvers); an approver resets it with a
recorded reason (`POST /api/v1/enforcement/breaker/reset`). Leaving EXECUTED requires the enforcement to be
removed first (rollback or expiry), never a bare state change. A live adapter is bound to one tenant
(`AEGIS_ENFORCEMENT_TENANT`); policy keys placed under `trusted/policy/<tenant>/` sign that tenant's
policies only.

## 6. Threat model (spec section 15)

Legend: **Covered** = control implemented and exercised by the named tests. **Partial** = control
implemented, residual risk stated. Test ids are `tests/unit/<file>::<test>`.

| # | Threat | Controls | Tests | Status |
|---|---|---|---|---|
| T1 | Spoofed telemetry | integration-only collector role; registered sources with collection authorization ids; strict schema validation and quarantine; future-timestamp rejection; per-tenant quotas; optional mTLS at the proxy. Verification needs two independent origins or a signed IOC hit, so one forged source cannot verify a case | `tests/unit/test_sentinel_detector.py::test_unauthorized_and_foreign_tenant_events_rejected`, `tests/unit/test_ingest_pipeline.py::test_unknown_source_fails_closed`, `tests/unit/test_ingest_pipeline.py::test_malformed_sample_quarantines_every_bad_line`, `tests/unit/test_sentinel_features.py::test_future_timestamp_rejected_and_does_not_advance_watermark`, `tests/unit/test_oracle_state_machine.py::test_verified_requires_two_independent_origins` | Partial: a compromised but authorized collector can still inject plausible records; it cannot verify a case alone or cause enforcement |
| T2 | Feed poisoning | signed IOC bundles from trusted keys; staleness and expiry; syndicated feeds count once; contradictions downgrade; over-broad CDN indicators dropped | `tests/unit/test_sentinel_rules.py::test_unsigned_and_untrusted_and_revoked_rejected`, `tests/unit/test_sentinel_rules.py::test_expired_stale_and_future_indicators_ignored`, `tests/unit/test_sentinel_rules.py::test_overbroad_cdn_ip_contradicted_by_allowlist_is_dropped`, `tests/unit/test_oracle_state_machine.py::test_syndicated_feeds_count_once`, `tests/unit/test_sentinel_fusion.py::test_contradicting_feed_downgrades_malicious` | Covered |
| T3 | Data leakage | pseudonymization at ingest; source IP dropped; quarantine raw bytes admin-only and never listed; metric labels without identifiers; no re-identification API | `tests/unit/test_ingest_pseudonym.py::test_pseudonym_does_not_contain_identifier`, `tests/unit/test_ingest_pseudonym.py::test_tenant_keys_isolate_pseudonyms`, `tests/unit/test_api_ingest.py::test_malformed_records_are_quarantined_not_dropped`, `tests/unit/test_api_app.py::test_prometheus_metrics` | Covered |
| T4 | Malicious connector output | tool outputs wrapped as untrusted data; registry rejects mutating tools; scoped append-only writers | `tests/unit/test_oracle_tools.py::test_wrap_untrusted_cannot_be_escaped`, `tests/unit/test_oracle_tools.py::test_registry_rejects_mutating_or_non_readonly_tools`, `tests/unit/test_oracle_tools.py::test_scope_writers_by_agent` | Covered |
| T5 | Prompt injection | injection scanning; evidence isolated from instructions; LLM output cannot change outcome or policy; deterministic fallback | `tests/unit/test_oracle_investigation.py::test_prompt_injection_in_evidence_is_isolated`, `tests/unit/test_oracle_tools.py::test_scan_for_injection`, `tests/unit/test_oracle_investigation.py::test_malicious_llm_cannot_alter_policy_or_outcome` | Covered |
| T6 | Graph over-linking | co-hosting edges never enforcement-eligible; candidate links investigative only; graph evidence never qualifies a verification | `tests/unit/test_constellation_graph.py::test_co_hosting_edges_never_enforcement_eligible`, `tests/unit/test_constellation_graph.py::test_candidate_edges_flagged_investigative_only`, `tests/unit/test_oracle_state_machine.py::test_tampered_and_stale_and_graph_evidence_do_not_qualify` | Covered |
| T7 | Model evasion | four independent detectors (signed rules, calibrated model, anomaly, change-point) with pre-registered fusion; mandatory abstain; device class never evidence | `tests/unit/test_sentinel_detector.py::test_insufficient_context_with_indicator_hit_abstains`, `tests/unit/test_sentinel_detector.py::test_device_class_alone_never_produces_a_finding`, `tests/unit/test_sentinel_model.py::test_device_class_does_not_change_model_score` | Partial: an adaptive adversary can shape traffic below thresholds; recall is measured per pilot, not assumed |
| T8 | Cross-tenant access | tenant only from the token; tenant-scoped stores; 404 for foreign objects; per-tenant ledgers and keys | `tests/unit/test_api_tenancy.py::test_other_tenant_reads_are_404`, `tests/unit/test_api_tenancy.py::test_tenant_comes_only_from_token`, `tests/unit/test_api_tenancy.py::test_other_tenant_mutations_are_404_and_change_nothing`, `tests/unit/test_provenance_ledger.py::test_tamper_in_one_tenant_does_not_affect_other` | Covered |
| T9 | Unauthorized blocking | dry-run default; full `authorize()` conjunction; shadow policy never authorizes; no policy, no execution | `tests/unit/test_mirror_safety.py::test_unauthorized_blocking_is_impossible`, `tests/unit/test_api_actions.py::test_shadow_policy_never_authorizes_and_approval_is_refused`, `tests/unit/test_api_actions.py::test_no_policy_means_no_execution` | Covered |
| T10 | Insider misuse | least-privilege roles; four-eyes; every call audited including refusals; RBAC-denial alerting | `tests/unit/test_api_actions.py::test_proposer_cannot_approve_own_action`, `tests/unit/test_api_actions.py::test_proposer_cannot_execute_even_with_approver_role`, `tests/unit/test_api_rbac.py::test_permission_matrix_is_least_privilege`, `tests/unit/test_api_app.py::test_every_mutating_call_is_audited_including_refusals` | Partial: a colluding analyst and approver can act together within a signed active policy; the ledger makes it attributable |
| T11 | Compromised signing keys | revocation; signatures over the full chain; policy re-checked at execution; asymmetric OIDC only; rotation runbook | `tests/unit/test_provenance_ledger.py::test_revoked_key_breaks_verification`, `tests/unit/test_provenance_ledger.py::test_full_rewrite_without_key_is_caught_by_signatures`, `tests/unit/test_api_actions.py::test_policy_revoked_between_approval_and_execution_blocks`, `tests/unit/test_api_auth.py::test_oidc_rejects_symmetric_and_unsigned_tokens` | Covered; procedure in [runbooks/key-rotation.md](runbooks/key-rotation.md) |
| T13 | Database-level tampering with enforcement gates | approval bound to one action id in the signed ledger; MIRROR re-run at approval and execution; action document checked against its signed proposal; rollback rehearsal in the signed ledger; signed external head anchor against truncation | `tests/unit/test_enforcement_binding.py::test_approval_of_one_action_never_executes_a_sibling`, `tests/unit/test_enforcement_binding.py::test_approval_forged_in_the_database_is_refused`, `tests/unit/test_enforcement_binding.py::test_execute_reruns_mirror_instead_of_trusting_the_stored_result`, `tests/unit/test_enforcement_binding.py::test_action_document_changed_after_approval_is_refused`, `tests/unit/test_provenance_ledger.py::test_truncation_with_rewritten_head_is_caught_by_external_anchor` | Covered; residual: an attacker holding both the database and the anchor file can roll both back (keep an off-host anchor copy) |
| T12 | False infringement claims | RIGHTS is not part of v1; SHIELD has no copyright workflow and never treats IPTV usage as evidence | `tests/unit/test_sentinel_detector.py::test_benign_iptv_and_streaming_boxes_not_flagged` | Out of scope (v1) |

### Spec section 15 mandatory tests

| Mandatory test | Implemented by |
|---|---|
| Benign IPTV untouched | `tests/unit/test_sentinel_detector.py::test_benign_iptv_and_streaming_boxes_not_flagged`, `tests/unit/test_resonance_detector.py::test_benign_iptv_and_cdn_destinations_never_yield_campaigns` |
| Malicious lab box detected | `tests/unit/test_sentinel_detector.py::test_emulated_c2_boxes_detected` |
| Shared CDN not indiscriminately blocked | `tests/unit/test_mirror_safety.py::test_shared_cdn_not_indiscriminately_blocked`, `tests/unit/test_mirror_simulate.py::test_lab_shared_cdn_never_safe` |
| Contradictory feeds downgrade finding | `tests/unit/test_oracle_investigation.py::test_contradictory_feeds_downgrade_and_escalate`, `tests/unit/test_oracle_state_machine.py::test_contradictory_feeds_downgrade` |
| Unavailable LLM does not disable baseline alerts | `tests/unit/test_sentinel_detector.py::test_works_without_any_llm`, `tests/unit/test_oracle_investigation.py::test_llm_failure_falls_back_to_deterministic` |
| Expired authorization prevents action | `tests/unit/test_mirror_safety.py::test_expired_authorization_prevents_action`, `tests/unit/test_oracle_state_machine.py::test_expired_authorization_prevents_action` |
| Compromised agent cannot alter policy | `tests/unit/test_oracle_investigation.py::test_malicious_llm_cannot_alter_policy_or_outcome`, `tests/unit/test_oracle_tools.py::test_no_tool_or_writer_can_modify_policy` |
| Rollback restores service | `tests/unit/test_mirror_safety.py::test_rollback_restores_service`, `tests/unit/test_mirror_executor.py::test_breaker_trip_auto_rolls_back_and_blocks` |
| Model drift prevents silent promotion | Partial. There is no automatic model promotion path in v1: the model changes only when the operator deploys a new image or a signed artifact (`AEGIS_MODEL_REQUIRE_SIGNATURE=true`), and tampered artifacts are refused (`tests/unit/test_sentinel_model.py::test_tampered_artifact_rejected`, `tests/unit/test_sentinel_model.py::test_signed_manifest`). Score drift is measured as PSI against the training reference (`tests/unit/test_sentinel_model.py::test_population_stability`). An automated drift gate in a promotion pipeline (spec section 10, EVOLVE) is not built. |
| Replay uses only contemporaneous evidence | `tests/unit/test_provenance_snapshot.py::test_replay_uses_only_contemporaneous_evidence` |

## 7. Supply chain and release

* Dependencies: `pip-audit` (all known vulnerabilities fail the build) and `npm audit` (high/critical in
  shipped console packages fail the build) on every CI run.
* SBOMs: CycloneDX for the Python environment, the console and the final image (syft) on every CI run.
* Releases: images built from a tag, signed keylessly with Sigstore cosign, with SBOM and SLSA build
  provenance attestations; operators verify before deployment ([INSTALL.md section 3](INSTALL.md#3-get-and-verify-the-image)).
* Base images: official `python:3.12-slim` and `node:22-slim`; the runtime image has no compiler and no
  package-manager step.

## 8. Residual risks and operator responsibilities

| Risk | Owner and mitigation |
|---|---|
| Host compromise exposes the ledger signing key and pseudonym keys | Operator: host hardening, disk encryption, restricted shell access; rotate keys after any suspected compromise |
| Pseudonymization is reversible by whoever holds the master key and the subscriber list | Operator: keep the master key in the vault, separate from subscriber databases; access-log both |
| Console sign-in uses pasted access tokens in v1 | Operator: short token lifetimes at the IdP, MFA; a redirect-based login is not part of v1 |
| Single-host deployment | Operator: backups (`deploy/backup.sh`) and a tested restore; availability target 99.5% |
| Penetration testing | An independent penetration test is recommended before production; results available to customers under NDA once performed |
