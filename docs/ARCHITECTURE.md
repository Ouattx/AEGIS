# Architecture and module contracts

Pipeline (spec §2), as implemented in v1:

```
collectors (NetFlow/IPFIX CSV, DNS JSONL, Zeek logs, CPE JSON)
  -> aegis.ingest (normalize, pseudonymize, validate, quarantine, EventBus w/ DLQ + quotas)
  -> aegis.sentinel (window features -> IOC rules + LightGBM(calibrated) + anomaly + change-point -> fusion w/ ABSTAIN)
  -> aegis.provenance (evidence store + hash-chained signed ledger + snapshots + replay)
  -> aegis.atlas (temporal infrastructure graph, as-of-T queries)
  -> aegis.oracle (case state machine w/ guards + bounded investigation agents, LLM optional)
  -> aegis.mirror (impact simulation -> authorize() -> adapters w/ circuit breaker + rollback)
  -> aegis.api (FastAPI, OIDC/RBAC, multi-tenant) + web/ (analyst console)
  -> aegis.reports (shadow proof-of-value report), eval/ (benchmark harness)
```

All shared types are in `aegis/contracts/models.py`. Below are the **public interfaces**
each module must expose. Implementers may add more, but must not change these signatures
without updating this file.

## aegis.provenance
- `signing.py`
  - `class Signer`: `generate(key_id) -> Signer`, `from_private_pem(key_id, pem: bytes)`, `.key_id`, `.sign(data: bytes) -> str` (base64 Ed25519), `.public_pem() -> bytes`
  - `class KeyRing`: `add(key_id, public_pem)`, `revoke(key_id)`, `verify(key_id, data: bytes, signature: str) -> bool` (False for unknown/revoked)
  - `sign_model(model: BaseModel, signer, field="signature") -> model copy with signature`; `verify_model(model, keyring, key_field="signer_key_id", sig_field="signature") -> bool` (signature over canonical bytes of model minus sig field)
- `ledger.py`
  - SQLAlchemy table `ledger_entries` on `aegis.storage.db.Base`
  - `class Ledger(session_factory, signer: Signer | None = None, *, anchor: HeadAnchor | None = None)`; `HeadAnchor(path, signer)` appends a signed `(tenant, seq, head_hash, recorded_at)` checkpoint per entry to a file outside the database, and `verify_report` refuses a chain shorter than / diverging from the latest valid checkpoint
    - `append(tenant_id, entry_type, subject_id, payload: dict, recorded_at: datetime | None = None) -> LedgerEntry`
    - `entries(tenant_id, *, subject_id=None, entry_type=None, as_of: datetime | None = None) -> list[LedgerEntry]`
    - `verify_chain(tenant_id, keyring: KeyRing | None = None) -> tuple[bool, int | None]` (ok, first bad seq)
    - `head(tenant_id) -> str` (latest entry_hash, genesis = "0"*64)
- `evidence.py`
  - `class EvidenceStore(docstore, ledger)`: `append(ev: Evidence) -> Evidence` (fills sha256, writes ledger; corrections are new evidence, never updates), `get(tenant_id, evidence_id)`, `list_for(tenant_id, ids)`, `independent_origins(evidences) -> int` (counts distinct `source_independence_group`)
- `snapshot.py`
  - `snapshot(tenant_id, ledger, as_of) -> dict` with `snapshot_id`, `snapshot_hash`, `as_of`, `entry_count`, `head_hash`
  - `replay(tenant_id, ledger, subject_id, as_of) -> dict` — evidence ids, model versions, rule bundle versions, and decisions visible at `as_of` only (contemporaneous evidence)

## aegis.ingest
- `pseudonym.py`: `class Pseudonymizer(tenant_key: bytes)`: `.pseudonym(identifier: str) -> str` (HMAC-SHA256, tenant keyed, prefix `p_`)
- `parsers.py`: `parse_netflow_csv(path|text)`, `parse_dns_jsonl(...)`, `parse_zeek_conn(...)`, `parse_zeek_dns(...)`, `parse_cpe_json(...)` -> iterators of raw dicts
- `normalize.py`: `normalize(raw: dict, source: SourceConfig, pseudonymizer, now) -> ObservationEvent` where `SourceConfig(tenant_id, source_id, source_kind, vantage, collection_authorization_id, retention_days, ..., subscriber_prefixes=(), flow_direction="auto")`; raises `RecordSkipped` for return legs / transit outside `subscriber_prefixes` (counted as `skipped`, not quarantined); reverse counters are `None` for uniflow exports
- `validator.py`: `validate(raw_bytes_or_dict) -> ObservationEvent | Quarantined`; `class QuarantineStore`
- `bus.py`: `class EventBus` protocol (`publish(topic, event)`, `subscribe(topic, handler)`, `drain()`), `InMemoryBus(max_queue, per_tenant_quota)` with backpressure (raise `Backpressure`), dead-letter topic `dlq`; optional `KafkaBus` if `confluent_kafka` installed
- `pipeline.py`: `class IngestPipeline(bus, validator, sources)`: `ingest_file(path, source_id) -> IngestStats`

## aegis.lab
- `corpus.py`: `generate_corpus(seed=7, days=3, n_devices=200, malicious_fraction=0.08, tenant_id="demo", start=...) -> Corpus` with `.events: list[ObservationEvent]`, `.labels: dict[(entity_pseudonym, date), label]` (device-day ground truth), `.write_raw(dir)` writing NetFlow CSV + DNS JSONL files
  - Benign profiles: android_tv w/ legit IPTV, smart_tv streaming, console gaming, phone, laptop VPN, firmware update bursts, CDN-heavy
  - Malicious emulations: periodic C2 beaconing (BadBox/Vo1d-style TV-box), residential proxy egress, DGA NXDOMAIN storms, DDoS-bot bursts
  - Includes a **benign IPTV box** whose traffic superficially resembles abuse (many destinations, high volume) — must not be flagged
- `iocs.py`: sample signed IOC bundle generator (domains/IPs used by emulated malware, plus stale and contradicted indicators)
- `topology.py`: sample hosting topology (shared CDN IPs with many legit co-tenants, dedicated C2 IPs)

## aegis.sentinel
- `features.py`: `class WindowStore`: `update(event) -> list[FeatureVector]` (emits on window close), `flush(now) -> list[FeatureVector]`; features per spec §4 (flow count, bytes in/out, unique dst, dst entropy, interval quantiles, nxdomain rate, protocol mix, ioc contacts, burstiness, baseline deviation) + missingness flags
- `rules.py`: `class IOCBundle` (signed, version, indicators with `first_seen/last_seen/expires_at/source_group`), `load_bundle(data, keyring) -> IOCBundle` (rejects bad signature), `ioc_match(fv, events, bundle, now) -> list[Evidence]` (stale/expired indicators ignored)
- `model.py`: `train(features: list[FeatureVector], labels, seed) -> TrainedModel` (LightGBM + isotonic calibration, time-forward split, group isolation), `TrainedModel.predict(fv) -> (score, calibration_id)`, `.save(dir)`, `load(dir)`, model card JSON
- `anomaly.py`: robust per-device-class anomaly (IsolationForest / robust z) and CUSUM change-point
- `fusion.py`: `fusion_policy(rule_hits, ml, anomaly, changepoint, fv, policy, *, population) -> Verdict + score + requires_review` (pre-registered rules; no uncalibrated averaging; model-only verdicts ABSTAIN when the tenant window population is below the model card's `validated_min_population`)
- `detector.py`: `class Sentinel(model, bundle, evidence_store, ...)`: `process(event) -> list[Finding]`, `process_batch(events) -> list[Finding]`; returns ABSTAIN when context insufficient; never depends on LLM
- `registry.py`: `class ModelRegistry(docstore, ledger, keyring=, gate=PromotionGate(), on_promote=)`: `register_artifact(dir, actor)`, `register(model, actor)`, `bootstrap_champion(model_id, actor, reason)`, `evaluate(model_id, holdout_features, holdout_labels, recent_features, actor) -> GateEvaluation`, `promote(model_id, evaluation_id, actor, reason, acknowledge_drift=False)` (raises `PromotionRefused`; humans only; drift blocks unless acknowledged by a second human), `champion()`, `active_model()`; ledger scope `_platform`

## aegis.atlas
- `graph.py`: tables `atlas_nodes`, `atlas_edges` on `Base`; `class Atlas(session_factory)`: `upsert_node`, `upsert_edge(tenant_id, src, dst, edge_type, observed_at, provenance_id, evidence_grade, source_group, ttl_hours)` (idempotent per provenance_id), `neighbors(tenant_id, node_id, as_of=None)`, `snapshot_hash(tenant_id, as_of)`, `candidate_links(...)` (investigative only, flagged)
- Edge types: `observed_resolves_to, verified_contacts, co_observed, attributed_to, mentioned_in_case`; `co_observed` / co-hosting edges carry `enforcement_eligible=False`

## aegis.oracle
- `state_machine.py`: `ALLOWED_TRANSITIONS`, `class CaseService(docstore, evidence_store, ledger, *, keyring=None, atlas=None, clock=None, live_execution_probe=None)`: `open_case(finding) -> Case` (one incident, one case: a finding on a device with an open case is attached to it), `case_for_finding(tenant_id, finding_id)`, `transition(tenant_id, case_id, to_state, actor, reason, *, authorization=None, mirror=None) -> Case` raising `GuardError` per spec §6 guards, `rebind_proposal(...)` (PROPOSED case re-pointed at a sibling action before approval). `CaseDecision.action_id` binds PROPOSED / APPROVED / DENIED / EXECUTED to one action; EXECUTED requires a human APPROVED decision for that exact action; leaving EXECUTED requires no live execution. Case transitions propagate to `Finding.status`
- `investigation.py`: `class Investigator(llm_client | None, tools, budget=Budget(max_tool_calls=12, deadline_s=600, max_retries=3))`: `investigate(case) -> InvestigationReport` (evidence summary, alternative hypotheses, counter-evidence, verification recommendation). Agents: evidence_collector, alternative_hypothesis, threat_correlation, policy_checker, verifier, response_planner — each with read-only tools and append-only write scope. Tool outputs wrapped as untrusted data. Deterministic fallback when LLM absent or fails.
- `llm.py`: thin Anthropic client wrapper (`AEGIS_LLM_MODEL`, default `claude-sonnet-5-5`), returns None on any failure

## aegis.mirror
- `simulate.py`: `simulate(action, topology, graph, history, *, now=None, case_indicators=(), case_entities=None) -> MirrorResult` (fail closed => UNKNOWN when topology incomplete; targets are never assumed malicious: a target not tied to the case evidence needs a human and is UNSAFE on shared infrastructure)
- `authorize.py`: `authorize(action, policy, keyring, mirror_result, evidence_quality_ok, now) -> AuthorizationDecision` implementing spec §9 exactly; human approval required for shared hosting / uncertain collateral
- `adapters.py`: `DryRunAdapter`, `RPZAdapter` (writes RPZ zone file), `WebhookAdapter`, each with `rehearse_rollback(action, now) -> RollbackRehearsal` (no change to the enforcement point); `class Executor(adapter, ledger, breaker)`: `execute(action, decision, approver) -> ExecutionRecord`, `rollback(action_id) -> ExecutionRecord`, `rehearse_rollback(action)` (ledger `rollback_rehearsal`; the only source of `rollback_verified`); `CircuitBreaker` trips on abnormal legit-traffic error rate (fed by `POST /actions/{id}/health`) and auto-rolls back; reset by an approver (`POST /enforcement/breaker/reset`)

## aegis.api
- `app.py`: `create_app(settings: Settings | None = None) -> FastAPI`
- Auth: OIDC JWT (RS256 via JWKS URL) in prod; HS256 dev secret when `AEGIS_AUTH_MODE=dev`. Claims: `sub`, `tenant_id`, `roles` ⊆ {viewer, analyst, approver, admin, integration}
- Routes under `/api/v1`: `ingest`, `findings`, `cases`, `cases/{id}/transition`, `cases/{id}/investigate`, `cases/{id}/replay`, `evidence/{id}`, `ledger/verify`, `graph/{node}`, `actions` (propose/simulate/authorize/approve/execute/rollback, `actions/{id}/health`), `enforcement/breaker` (+ `/reset`), `reports/pov`, `reports/inputs`, `metrics/summary`, `auth/config`, `auth/token` (console PKCE code / refresh relay); `/healthz`, `/readyz`, `/metrics` (Prometheus text)
- Serves `web/dist` at `/` when present

## aegis.reports
- `pov.py`: `build_pov_report(tenant_id, stores..., period) -> str` (self-contained HTML): findings by class, false alerts per 10k device-days (with exact 95% upper bound and n), detection delay, alert latency (creation minus the later of window end and `Finding.ingested_at`), analyst minutes per incident, cost per 1,000 monitored devices and per incident (operator inputs), evidence coverage, zero-enforcement attestation, ledger verification status; a synthetic-demo banner whenever a simulated analyst dispositioned any case

## eval/
- `run_benchmark.py`: frozen datasets A (malicious) / B (legit), time-forward split, group isolation, compares rules-only vs supervised vs ensemble vs external baseline; outputs JSON + HTML with CIs, PR curves, per-device-class confusion, false alerts per 10k device-days, base rates

## aegis.cli
- `aegis demo` — generate lab corpus, train, run pipeline, open cases, start API with seeded tenant
- `aegis serve`, `aegis ingest <file> --source <id>`, `aegis train`, `aegis benchmark`, `aegis report`, `aegis keys generate`, `aegis policy sign`, `aegis ledger verify`
