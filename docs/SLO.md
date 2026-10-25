# Service level objectives

Targets from spec section 13. "MVP gate" applies to shadow pilots; "production target" is to be validated
with the operator and is not a commitment until written into a contract. Each SLO has its measurement and the
alert that guards it (`deploy/prometheus/rules/aegis-alerts.yml`, dashboard "AEGIS SHIELD - Operations").

| SLO | Pilot gate | Production target (to validate) | Measured by | Alert |
|---|---|---|---|---|
| [Ingestion success](#ingestion) | >= 99.9% valid events | >= 99.99% | `aegis:ingest_valid_ratio:rate1h` (accepted / (accepted + quarantined)) | `AegisIngestValidRatioLow`, `AegisIngestStalled` |
| [Known-IOC alert latency](#known-ioc-alert-latency) | p95 <= 120 s | p95 <= 30 s | event time to finding creation, from the proof-of-value report | report section, reviewed weekly |
| [Evidence provenance](#evidence-provenance) | 100% for enforcement cases | 100% | ledger verification and evidence integrity checks in the PoV report | `AegisAuditWriteFailure`, ledger verify |
| [Unapproved enforcement](#unapproved-enforcement) | 0 | 0 | `aegis_actions_total{step="execute",outcome="applied"}` without an approved active policy; PoV zero-enforcement attestation | `AegisEnforcementApplied`, `AegisRollbackFailed` |
| [Availability](#availability) | >= 99.5% | >= 99.95% | `aegis_ready` and Prometheus `up` | `AegisApiDown`, `AegisNotReady`, `AegisAvailabilityBudgetBurn`, `AegisHigh5xxRatio` |
| [False alerts](#false-alerts) | measured per 10k device-days | customer-agreed budget | analyst dispositions in the PoV report, with confidence interval | weekly pilot review |

## Ingestion

Valid ratio = records accepted / (records accepted + records quarantined), per hour; duplicates are
excluded (they are re-sends, not loss). Quarantined records are kept, so a breach is recoverable once the
collector is fixed. Budget at 99.9%: 1 invalid record per 1,000.

## Known-IOC alert latency

Measured from the `observed_at` of the first event that contacted a fresh signed indicator to the finding's
creation. It includes the collector export interval and the push cadence, which the operator controls:
5-minute files make the 120 s pilot gate unreachable, so pilots that track this SLO push every minute.

## Evidence provenance

Every finding cites evidence ids; every evidence record is content-hashed; every state change is in the
signed ledger. The proof-of-value report recomputes evidence hashes and verifies the ledger; any failure is
shown in the report and invalidates the affected cases for enforcement.

## Unapproved enforcement

Zero, always. In a shadow pilot no enforcement is applied at all; the PoV report's zero-enforcement
attestation is computed from the ledger (dry runs counted, any live execution flagged).

## Availability

Ready time / total time per calendar month, from `aegis_ready` (1 when the API and database checks pass)
scraped every 15 s. Planned maintenance announced 48 h in advance is excluded during pilots. At 99.5% the
monthly budget is about 3 h 39 min; the burn alert fires when the last hour's readiness drops below 98.6%.
Single-host deployments cannot reach 99.95% without redundancy; the production target assumes an HA
deployment designed with the operator.

## False alerts

False alerts per 10,000 device-days = alerts an analyst dispositioned as false / device-days observed x 10,000,
with the confidence interval (zero observed false alerts still has an upper bound, which the report shows).
The budget is agreed with the operator before the pilot starts and evaluated at the end
([sales/SHADOW_PILOT_OFFER.md](sales/SHADOW_PILOT_OFFER.md)).

## Cost and capacity records (spec section 13)

Recorded for each pilot in the PoV report and the pilot log: events per second at peak (from
`aegis_ingest_records_total`), host size, cost per million events, per investigation, per protected
device-month and per retained GB. Load tiers beyond the pilot (10k, 100k, 1M events/s) are tested only with
explicit event sizes and an agreed infrastructure budget.
