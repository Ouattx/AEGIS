# French and EU regulatory context

> **TEMPLATE FOR COUNSEL REVIEW. This is not legal advice.** An orientation map of the rules a French or
> EU operator's counsel will usually look at for a SHIELD deployment, and how the product's design relates
> to each. It does not state how any rule applies to a given operator, and must be validated by qualified
> counsel before it is relied on or shared with a customer. Spec section 12 requires this review before any
> live enforcement.

| Framework | Why it is relevant | Product design facts for counsel | Questions for counsel |
|---|---|---|---|
| **GDPR** (Reg. 2016/679) | subscriber-linked traffic metadata is personal data, even pseudonymized | metadata only; pseudonymization at ingest; per-source retention; DPIA and data map templates ([DATA_MAP.md](DATA_MAP.md), [DPIA_TEMPLATE.md](DPIA_TEMPLATE.md)); no automated decision with legal effect | legal basis (legitimate interest for network security, recital 49, and/or legal obligation); controller/processor roles; information to subscribers; Art. 22 analysis |
| **ePrivacy Directive** (2002/58/EC) and French transposition (CPCE, notably art. L34-1 on traffic data, and L33-1 operator obligations) | confidentiality of communications and limits on processing traffic data | no content, no payload, no TLS decryption; traffic data processed for network security; retention bounded per source | whether the processing fits the security exceptions as transposed; retention limits for traffic data; required internal authorizations |
| **NIS2** (Dir. 2022/2555) and its French transposition | many operators are essential or important entities with risk-management and incident-reporting duties | detection, evidence and audit trail support incident handling (Art. 21 measures) and reporting timelines (Art. 23); supply-chain evidence (SBOM, signed builds) | whether the operator is in scope; whether SHIELD processing can rely on NIS2 obligations as a legal basis; supplier-security clauses |
| **Open internet regulation** (Reg. 2015/2120, Art. 3(3)) | traffic management that blocks or degrades must fit the listed exceptions (e.g. preserving network integrity and security) and be proportionate, transparent, temporary | shadow by default; enforcement only with a signed active policy and legal sign-off reference; impact simulation of collateral (shared CDN co-tenants); time-boxed actions with automatic expiry and rollback; full audit | whether a given action type (DNS sinkhole of a C2 domain, IP block, walled garden) fits Art. 3(3)(b); transparency to subscribers; Arcep reporting expectations |
| **Arcom and judicial blocking regimes** | blocking related to copyright or illegal content follows specific procedures (court or authority orders) | SHIELD does not perform copyright enforcement; IPTV usage is never treated as evidence; the RIGHTS product is out of scope of v1 | confirm that SHIELD outputs are not used for Arcom/court-ordered blocking without the dedicated procedure; separation of narratives in sales and contracts (spec section 18) |
| **AI Act** (Reg. 2024/1689) | the product uses ML scoring and an optional LLM | the optional LLM only drafts investigation summaries; deterministic code authorizes; human review of every finding and action | risk classification of the system and of the operator's use; transparency and logging obligations; timeline of applicability |
| **Cybersecurity Act / certification, ANSSI guidance** | operators may require qualified or certified products or hosting (e.g. SecNumCloud for hosted variants) | on-prem deployment keeps data in the operator's environment; no certification is claimed for v1 | whether a certification or qualification is required by the customer or its regulator |
| **Lawful interception and data retention obligations** | operators have separate legal duties | SHIELD is not an interception or retention system and must not be repurposed as one | confirm separation from LI/retention systems |

## Practical consequences for a French shadow pilot

1. The DPO records the processing and runs or updates the DPIA before pilot telemetry flows.
2. The operator issues a `collection_authorization_id` per source, referencing that record; AEGIS refuses
   events without a registered authorization.
3. The pilot runs in shadow mode: no blocking, so open-internet traffic-management questions do not arise
   during the pilot; they must be answered before any active policy is signed.
4. Any future active policy carries a `legal_signoff_ref` that points to counsel's written sign-off for the
   specific action types, scopes and durations.
5. Sales and contract language follows the claims guide and keeps SHIELD (security) separate from any
   rights-protection narrative.
