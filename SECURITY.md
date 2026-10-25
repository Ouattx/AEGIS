# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately to **security@[company-domain]** (founder to set before
distribution; until then use the contact named in your pilot agreement). Please include the affected version
(`GET /healthz` returns it), the deployment mode, reproduction steps and the impact you observed. Do not
include real subscriber data in a report; synthetic reproductions are preferred.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | 2 business days |
| Initial assessment and severity (CVSS v4) | 5 business days |
| Fix or mitigation for critical / high | 14 / 30 days, earlier when exploited |
| Advisory to affected customers | with the fix, or earlier with a mitigation when exposure warrants |

We will not pursue legal action against good-faith research that respects this policy, avoids privacy
violations and service disruption, and gives us reasonable time to fix before disclosure. Testing against a
customer's production deployment requires that customer's written permission.

## Supported versions

| Version | Security fixes |
|---|---|
| 1.x (current) | yes |
| pre-release builds | no |

Fixes ship as new signed images; see [docs/runbooks/upgrade-backup-restore.md](docs/runbooks/upgrade-backup-restore.md).

## Security model in one page

* **Shadow by default.** The enforcement adapter defaults to `dryrun`. Live enforcement needs a signed
  operator policy in `active` mode with a legal sign-off reference, a fresh SAFE impact simulation, a bounded
  expiry, a verified rollback plan and approval by a second person. A role alone is never sufficient.
* **AI proposes, code decides.** No LLM output can change policy, models, case outcomes or enforcement. The
  detection path works with no LLM configured. Tool outputs given to the LLM are wrapped as untrusted data.
* **Tenant isolation.** The tenant comes only from the verified token. Every store read is tenant-scoped;
  there is no cross-tenant query API. Pseudonymization keys are per tenant.
* **Data minimization.** Security metadata only: no payloads, no TLS decryption. Subscriber IPs and device
  MACs are replaced by HMAC pseudonyms at ingest; raw collector bytes are kept only for records that fail
  validation, under the source's retention period.
* **Integrity.** Evidence is content-hashed; every state change and every state-changing API call is appended to a
  per-tenant, hash-chained ledger signed with Ed25519; any tampering is detected by `aegis ledger verify`.
* **Fail closed.** Unknown topology, missing or expired authorization, unverified signatures and incomplete
  configuration deny rather than allow.
* **Supply chain.** CI runs `pip-audit`, `npm audit` and produces CycloneDX SBOMs; release images are signed
  with Sigstore cosign, carry SBOM and build-provenance attestations, run as non-root with a read-only root
  file system.

Details, the threat model and the test that covers each threat:
[docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).
Pre-answered customer security questionnaire: [docs/sales/SECURITY_QUESTIONNAIRE.md](docs/sales/SECURITY_QUESTIONNAIRE.md).
