# Security questionnaire: pre-answers

Answers for AEGIS OMEGA SHIELD v1 as deployed on the customer's premises with `deploy/docker-compose.yml`.
They follow the usual sections of operator vendor-security questionnaires (SIG Lite / CAIQ style). Each answer
points to the evidence. Items marked **[FOUNDER TO SET]** depend on company policies to be finalized before
sending; never answer "yes" to a control that is not in place.

## 1. Company and governance

| Question | Answer |
|---|---|
| Information security policy and owner | [FOUNDER TO SET: policy document, named owner] |
| Certifications (ISO 27001, SOC 2, HDS, SecNumCloud) | None held for v1. The product is deployed in the customer's environment, under the customer's certifications. |
| Vulnerability disclosure | Yes: [SECURITY.md](../../SECURITY.md), acknowledgement in 2 business days, fix targets by severity. |
| Independent penetration test | Not yet performed on v1; planned before general availability; results shared under NDA when available. |
| Sub-processors | None in the default deployment. Optional LLM provider only if the customer enables it. |
| Staff screening and security training | [FOUNDER TO SET] |
| Cyber insurance | [FOUNDER TO SET] |

## 2. Hosting and data location

| Question | Answer |
|---|---|
| Where is data stored and processed? | On the customer's host (on-prem or the customer's sovereign cloud). Nothing is sent to the vendor. |
| Multi-tenancy | Tenant isolation enforced on every read (tenant only from the verified token); per-tenant ledgers and pseudonymization keys. A pilot normally runs a single tenant. |
| Does the vendor have access? | Only if the SOW grants it (supervised remote session); no standing access, no phone-home, no telemetry to the vendor. |
| Internet access required? | Only to the customer's IdP (OIDC discovery/JWKS). The optional LLM endpoint is disabled by default. Air-gapped installation is supported (INSTALL.md section 3). |

## 3. Data protection

| Question | Answer |
|---|---|
| Personal data processed | Network flow and DNS metadata linked to pseudonymous line or device identifiers. No content, no URLs, no names or contract data. [DATA_MAP.md](../compliance/DATA_MAP.md). |
| Pseudonymization / anonymization | HMAC-SHA256 pseudonyms with per-tenant keys derived from a customer-held master key; subscriber IP dropped after pseudonymization. Pseudonymous data remains personal data under GDPR. |
| Re-identification | Not possible within AEGIS (no API returns identities). The customer re-identifies in its own systems when its process requires it. |
| Retention | Per-source retention stamped on every record; quarantined raw records purged by a scheduled job; pilot data deleted at close-out. Automatic expiry of findings and evidence is not in v1 (DATA_MAP section 5). |
| DPIA support | DPIA template and data map provided for the customer's DPO and counsel. |
| Data subject rights | Supported through the customer (pseudonym computation and export/deletion by the operator). |
| Automated decision-making | None with legal or similarly significant effect: analysts review every finding; a second person approves any action; shadow mode never acts. |

## 4. Application security

| Question | Answer |
|---|---|
| Authentication | OIDC access tokens (RS/PS/ES algorithms only), issuer and audience pinned; MFA enforced at the customer's IdP. No local passwords. |
| Authorization | Five least-privilege roles; four-eyes approval (no self-approval); admin cannot approve. Enforced server-side on every call. |
| Session handling | Console keeps the access token in `sessionStorage` per tab; it ends at token expiry or on 401. Sign-in uses a pasted IdP token in v1 (no redirect login yet). |
| Input validation | Strict schemas; invalid telemetry is quarantined with its original bytes, never coerced; request size limits; rate limiting per tenant. |
| Web security headers | Content-Security-Policy with scripts and connections restricted to the same origin and `frame-ancestors 'none'`; `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`; `Cache-Control: no-store` on API responses; request ids for tracing. The interactive API docs (`/api/v1/docs`) load assets from a public CDN and are exempt from the CSP: block that path at the reverse proxy if browsers must not reach external origins. |
| Secure development | Code review; automated tests including the spec's mandatory safety tests; lint gate; dependency audit (`pip-audit`, `npm audit`) and SBOMs in CI. |
| AI / LLM risks | LLM optional, off by default; outputs advisory only; untrusted tool outputs are isolated; tested: a malicious model cannot alter policy or case outcome. |
| Secrets | Supplied via environment (`deploy/.env`, mode 0600) or the customer's secrets tooling; none in the image; API container receives an explicit allow-list only. |

## 5. Infrastructure and operations

| Question | Answer |
|---|---|
| Container hardening | Multi-stage build, slim base, non-root uid 10001, read-only root file system, all capabilities dropped, `no-new-privileges`, health checks. |
| Network exposure | API on 127.0.0.1 behind the customer's TLS proxy; database on an internal network with no egress; metrics behind a bearer token. |
| Encryption in transit | TLS 1.2+ at the customer's reverse proxy or load balancer; optional mTLS for collectors. |
| Encryption at rest | Customer-provided (disk / volume encryption); backups encrypted to the customer's key. |
| Logging and monitoring | JSON request logs; Prometheus metrics without subscriber data; provisioned Grafana dashboard; alert rules for availability, ingestion, audit failures, enforcement, auth anomalies. |
| Audit trail | Signed (Ed25519), hash-chained, append-only ledger per tenant covering evidence, findings, case transitions, actions and every state-changing API call; independently verifiable. |
| Backup and recovery | `deploy/backup.sh` / `deploy/restore.sh` (checksummed, tested); pilot RPO 24 h, RTO 4 h. |
| Patch management | Signed releases; customer-controlled upgrades with backup and rollback runbooks. |

## 6. Supply chain

| Question | Answer |
|---|---|
| SBOM | CycloneDX for the Python environment, the console and the container image, on every build; attached to releases. |
| Signed artifacts | Release images signed with Sigstore cosign (keyless), with SBOM and build-provenance attestations; verification commands in INSTALL.md. |
| Open-source licenses | Listed in the SBOM; no copyleft component is linked into the application code [FOUNDER TO SET: confirm with a license scan before sending]. |
| Third-party components with known vulnerabilities | CI fails on known Python vulnerabilities and on high/critical vulnerabilities in shipped console packages. |

## 7. Enforcement safety (operator-specific)

| Question | Answer |
|---|---|
| Can the product block traffic? | Not in a shadow pilot (dry-run adapter, shadow policy). In production only with a customer-signed active policy, legal sign-off reference, SAFE impact simulation, bounded expiry, verified rollback plan and second-person approval. |
| Protection against collateral blocking | Impact simulation against the customer's hosting topology; shared hosting/CDN or unknown topology fails closed. |
| Rollback | Every action expires automatically; manual rollback by approvers; circuit breaker auto-rollback on abnormal legitimate-traffic errors. |
| Who decides? | The customer's staff, always. No AI output authorizes anything. |
