# Data map and records of processing (input)

> **TEMPLATE FOR COUNSEL REVIEW.** This document describes what AEGIS OMEGA SHIELD v1 technically collects,
> derives, stores and deletes. It is an engineering input to the operator's record of processing (GDPR
> Art. 30) and DPIA (Art. 35). It is not legal advice. The operator, its DPO and qualified counsel decide the
> purposes, legal bases, retention periods and roles, and must review and complete every bracketed field.

## 1. Roles (to be confirmed by counsel)

| Deployment | Operator (ISP) | AEGIS vendor |
|---|---|---|
| On-prem / sovereign (operator runs the stack) | controller | software supplier; processor only if it accesses the deployment (support, pilot operation) |
| Hosted by the vendor | controller | processor (Art. 28 agreement required) |
| Optional LLM provider (disabled by default) | controller | sub-processor of whoever operates the stack, only if enabled |

## 2. Data subjects and categories

| Data subjects | Subscribers of the operator and users of devices on their lines (household members, guests) |
|---|---|
| Not processed | names, postal addresses, contract data, payment data, content of communications, URLs, credentials, location beyond what an IP prefix implies, special-category data |

## 3. Data inventory

| # | Data element | Source | Personal data? | Where stored | Retention (v1 technical behaviour) | Access |
|---|---|---|---|---|---|---|
| D1 | Subscriber-side IP address, device MAC, line identifier | collector records | yes (identifier) | **not stored**: replaced at ingest by an HMAC pseudonym; the source IP is validated then dropped | n/a | n/a |
| D2 | Entity pseudonym `p_<hmac>` | derived (HMAC-SHA256, per-tenant key) | yes (pseudonymous data) | PostgreSQL: findings, evidence, cases, graph, coverage tables; ledger payloads | until the deployment is deleted, see section 5 | viewer and above, own tenant |
| D3 | Flow metadata: destination IP/port, protocol, byte/packet counts, duration, timestamps | NetFlow/IPFIX, Zeek, CPE | yes when linked to D2 (traffic data, ePrivacy) | in memory for detection windows (5m/15m/24h); aggregates and contacted destinations in evidence payloads | memory: until the window closes; evidence: as D2 | viewer and above |
| D4 | DNS metadata: queried name, type, response code, answers, timestamps | resolver logs, Zeek, CPE | yes when linked to D2 | as D3 | as D3 | viewer and above |
| D5 | Device class hint (e.g. `android_tv`) | CPE / collector | yes when linked to D2 | coverage table, findings | as D2 | viewer and above |
| D6 | Quarantined raw records (original bytes of invalid input) | collector records | **yes, may contain D1 in clear** | PostgreSQL `docs` (kind `Quarantined`) | the source's `retention_days` (default 30), enforced by `deploy/purge-expired.sh` | admin only; never listed with bytes |
| D7 | Findings, evidence, cases, analyst notes and decisions | derived | yes (D2 + analyst identity) | PostgreSQL | as D2 | role-based |
| D8 | Provenance ledger entries (hashes, ids, decisions, API audit records) | derived | yes (D2 in some payloads; staff identity and client IP in audit records) | PostgreSQL `ledger_entries` | append-only, until the deployment is deleted | admin (raw entries), viewer (verification status) |
| D9 | Staff identity (OIDC subject), roles, staff client IP | IdP token, HTTP request | yes (employees) | ledger audit records, JSON request logs | ledger: as D8; logs: per the host's log policy | admin; operator's log platform |
| D10 | IOC indicators (domains, IPs of malicious infrastructure) | operator/partner feeds | generally no (infrastructure), may include individual-operated hosts | PostgreSQL | until replaced | viewer and above |
| D11 | Hosting topology (prefixes, hosts, hostnames) | operator inventory | generally no | PostgreSQL | until replaced | admin |
| D12 | Keys: ledger signing key, pseudonymization master key (env), per-tenant keys | generated / operator | no (but D12 enables re-identification of D2) | data volume (mode 0700), `deploy/.env` | life of the deployment, rotated per runbook | host administrators only |
| D13 | Operational metrics | derived | no (labels exclude tenant, pseudonyms, indicators) | Prometheus | `PROMETHEUS_RETENTION` (default 30 days) | monitoring staff |
| D14 | Optional LLM requests (case summaries with pseudonyms, indicators) | derived | yes (pseudonymous) | sent to the LLM provider when enabled; not stored by AEGIS beyond the investigation report | provider terms | n/a |

## 4. Flows

```
operator collectors --HTTPS--> AEGIS ingest --(pseudonymize, drop source IP)--> detection (memory)
                                     |                                            |
                                     +--invalid record--> quarantine (D6)         +--> findings/evidence/cases (D2-D7)
                                                                                  +--> signed ledger (D8)
operator re-identification (outside AEGIS): HMAC(tenant key, line id) == pseudonym  -> abuse / notification process
```

No transfer outside the operator's environment occurs in the default configuration. International transfer
analysis is required only if the optional LLM is enabled with a provider outside the EEA, or if the vendor
hosts the service outside the EEA: [operator to complete].

## 5. Retention and deletion: what v1 does and does not do

| Mechanism | Status in v1 |
|---|---|
| Per-source `retention_days` stamped on every event and quarantined record | implemented |
| Purge of expired quarantined raw records | implemented as `deploy/purge-expired.sh` (schedule daily) |
| Detection windows in memory | discarded as windows close and idle entities are pruned |
| Automatic expiry of findings, evidence, cases and graph data | **not implemented**; data remains until the deployment (or tenant) is deleted. For a pilot this is bounded by the pilot end and the deletion step in the SOW. For production, the operator sets a case retention period [e.g. 12 months, counsel to confirm] and the vendor provides a supervised purge; the signed ledger is append-only by design, so purging it requires closing the chain with a signed snapshot first |
| Deletion at end of pilot | `docker compose ... down -v` removes all volumes; backups destroyed per the operator's procedure; deletion recorded in the close-out |

## 6. Data subject rights (input for counsel)

AEGIS cannot identify a subscriber by itself. Access, rectification or erasure requests are handled by the
operator, which can compute the pseudonym of the requester's line(s) and ask the vendor or its own
administrators to export or delete matching records. Whether Art. 11 GDPR (processing not requiring
identification) applies, and how Art. 21 objections interact with the security purpose, is for counsel.

## 7. Security measures (Art. 32 summary)

Pseudonymization at ingest; tenant isolation; least-privilege roles with four-eyes approval; signed,
hash-chained audit ledger; TLS at the operator proxy; database on an isolated network; non-root, read-only
containers; secrets outside the image; encrypted backups (operator); vulnerability audits and SBOMs in CI;
signed releases. Details: [../SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md).
