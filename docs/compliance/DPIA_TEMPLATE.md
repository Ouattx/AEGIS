# Data protection impact assessment (DPIA): AEGIS OMEGA SHIELD

> **TEMPLATE FOR COUNSEL REVIEW. This is not legal advice.** Prepared by the vendor to help the operator's DPO run a DPIA under
> GDPR Art. 35 and the CNIL method. Pre-filled sections describe the software's technical behaviour only.
> Every legal assessment (purposes, legal basis, necessity, proportionality, risk levels, measures accepted)
> belongs to the controller and must be reviewed by qualified counsel. Bracketed fields are for the operator.

| | |
|---|---|
| Controller | [operator legal entity] |
| DPO | [name, contact] |
| Processing name | Detection of compromised subscriber devices and botnet infrastructure from network security telemetry (AEGIS OMEGA SHIELD) |
| Version / date | [v0.1, date] |
| Phase | [shadow pilot, read-only] / [production] |
| Reviewed by | [DPO], [CISO], [counsel] |

## 1. Why a DPIA

Indicators from the EDPB criteria and the CNIL list that may apply (counsel to confirm): systematic
monitoring of network traffic metadata; large scale (all or a segment of subscribers); data relating to
electronic communications (ePrivacy confidentiality); innovative use of machine learning for scoring.
[Conclusion: DPIA required / recommended.]

## 2. Description of the processing

**Purpose.** Protect the network, subscribers and third parties by detecting devices that behave like
compromised hosts (botnet C2 beaconing, residential-proxy abuse, DGA activity, DDoS participation) so the
operator's security team can investigate and, where it decides so through its own procedures, notify the
subscriber or mitigate. In the shadow pilot, the output is alerts and reports only; no traffic is blocked.

**Explicitly excluded purposes** (the software is not designed for and must not be used for): marketing,
profiling of viewing or browsing habits, copyright enforcement, identification of individuals by AEGIS,
law-enforcement requests outside the operator's legal obligations.

**Data, sources, flows, retention.** See [DATA_MAP.md](DATA_MAP.md) sections 2 to 5. Vantage points selected
for this deployment: [core NetFlow/IPFIX at BNG | resolver logs | Zeek sensor | CPE telemetry], sampling
[1:N], subscriber segment [all | region | pilot cohort of N lines].

**Recipients.** Operator SOC analysts and approvers (named roles in the IdP), vendor support staff [only
under the support/pilot agreement, access logged], LLM provider [none, LLM disabled | provider, region].

**Technology.** On-prem containers in [data centre], PostgreSQL; detection by signed rules, a calibrated
gradient-boosting model, anomaly and change-point statistics; optional LLM-written investigation summaries.

## 3. Necessity and proportionality

| Question | Pre-filled technical facts | Controller assessment |
|---|---|---|
| Legal basis | Options commonly considered for network security processing: legitimate interest (GDPR Art. 6(1)(f), recital 49 on network and information security), legal obligation where security duties apply (e.g. NIS2 measures, national telecom security obligations). Traffic data processing must also fit the ePrivacy regime as transposed (in France, CPCE art. L34-1 and related provisions) | [counsel] |
| Data minimization | metadata only; no payload; subscriber IP/MAC pseudonymized at ingest and dropped; raw bytes only for invalid records, time-limited | [assessment] |
| Accuracy | calibrated scores; mandatory abstain when context is short; counter-hypothesis review before a case can be verified; device class, vendor, IPTV app usage or geography are never evidence | [assessment] |
| Storage limitation | per-source `retention_days`; quarantine purge; pilot data deleted at close-out; production case retention [period] | [assessment] |
| Information to data subjects | [privacy notice update: security monitoring of network metadata, purposes, rights] | [assessment] |
| Rights | handled by the operator via pseudonym computation (DATA_MAP section 6) | [assessment] |
| Processors and transfers | [vendor role; LLM provider if enabled; transfer mechanism if non-EEA] | [assessment] |
| Automated decisions (Art. 22) | no decision producing legal or similarly significant effects is taken automatically: every finding is reviewed by an analyst, every action needs a second human, and shadow mode never acts | [assessment] |

## 4. Risks to data subjects

Scale: likelihood and severity from 1 (negligible) to 4 (maximum). Pre-filled values are the vendor's
technical estimate with the listed measures in place; the controller decides the final values.

| Risk | Sources | Measures in the product | Measures by the operator | L | S |
|---|---|---|---|---|---|
| Illegitimate access to pseudonymous traffic metadata | external attacker, insider | OIDC + MFA (IdP), least-privilege roles, tenant isolation, audit ledger, isolated database network, non-root read-only containers | host hardening, IdP hygiene, access reviews, log monitoring | [2] | [2] |
| Re-identification beyond the purpose | insider with master key and subscriber list | key separation, no re-identification API, audit of every state change | vault custody of the master key, separation of duties between SOC and subscriber-data teams | [1] | [3] |
| Wrongful suspicion of a subscriber (false positive) | detection error, poisoned feed | calibrated scoring, abstain, two independent origins or a signed IOC hit to verify, counter-hypothesis review, contradicting feeds downgrade, false-alert budget measured per 10k device-days | analyst training, notification wording that does not accuse, appeal path | [2] | [2] |
| Unjustified service restriction | wrong enforcement | shadow by default; signed active policy with legal sign-off; impact simulation; four-eyes; expiry; rollback and circuit breaker | change management; legal sign-off; customer-care process | [1] | [3] |
| Function creep (marketing, viewing profiling, copyright) | business pressure | metadata only, no content, no viewing-profile features; RIGHTS product excluded from v1 | purpose limitation in the processing register; DPO oversight | [1] | [3] |
| Excessive retention | lack of purge | per-source retention, quarantine purge, deletion procedure | retention schedule, purge job monitoring | [2] | [2] |
| Disclosure to an LLM provider | optional feature | disabled by default; pseudonymized inputs | keep disabled unless a processor agreement and transfer basis exist | [1] | [2] |

## 5. Action plan and sign-off

| Measure | Owner | Due | Status |
|---|---|---|---|
| [update privacy notice] | [operator] | [date] | [ ] |
| [schedule `deploy/purge-expired.sh` and monitor it] | [operator ops] | [pilot week 1] | [ ] |
| [define production case retention and purge procedure] | [operator DPO + vendor] | [before production] | [ ] |
| [processor agreement with the vendor if it accesses the deployment] | [legal] | [before pilot data flows] | [ ] |

| Opinion | Name | Date | Decision |
|---|---|---|---|
| DPO opinion | | | |
| CISO | | | |
| Controller decision | | | [accept / accept with measures / refuse] |
| Prior consultation of the CNIL needed (Art. 36)? | | | [yes/no, reasoning] |
