# Statement of work: AEGIS OMEGA SHIELD Shadow Pilot

> **TEMPLATE FOR COUNSEL REVIEW.** This is a drafting template, not a contract and not legal advice. Both
> parties' counsel must review and adapt it (governing law, liability, data-protection clauses, procurement
> terms) before signature. Bracketed fields: **FOUNDER TO SET** (keyed, filled by `deploy/tools/render_sales_kit.py`) for vendor commercial terms, **[CUSTOMER]**
> for the operator, **[COUNSEL]** for legal drafting decisions.

**Between** [AEGIS OMEGA legal entity, registration, address] ("Vendor")
**and** [Operator legal entity, registration, address] ("Customer").
**Under** [master agreement / purchase order reference, or: this SOW incorporates the Vendor's general terms
dated [date]] [COUNSEL].

## 1. Purpose

Evaluate, in read-only shadow mode, whether AEGIS OMEGA SHIELD ("the Software") detects compromised subscriber
devices and botnet infrastructure in the Customer's network telemetry at an acceptable false-alert rate, and
produce a proof-of-value report against the success criteria in Annex A.

## 2. Mode of operation: no enforcement

2.1 The Software runs with the dry-run enforcement adapter and a Customer-signed policy in `shadow` mode.
2.2 The Software will not block, filter, redirect or modify any traffic, and will not notify subscribers.
2.3 Any change of mode requires a separate written agreement, a Customer-signed `active` policy and a legal
sign-off reference from the Customer's counsel; it is outside this SOW.

## 3. Scope

| Item | Value |
|---|---|
| Pilot duration | [2 / 4] weeks from the first day of continuous telemetry, plus kick-off and close-out |
| Vantage points | [e.g. BNG IPFIX (sampling 1:N), resolver query logs] |
| Subscriber segment | [description, approx. number of lines] |
| Hosting | [Customer host / Customer sovereign cloud VM], operated by [Customer / Vendor with remote access via ...] |
| Named users | [n] analysts, [n] approvers, [n] admins |
| Software version | AEGIS OMEGA SHIELD [1.x], image digest recorded at installation |

## 4. Responsibilities

| Vendor | Customer |
|---|---|
| Provide the signed Software image and installation support | Provide the host, network access, TLS certificate and IdP roles |
| Assist with collector configuration and source registration | Configure exports; issue a collection authorization id per source |
| Weekly review; respond to incidents per section 7 | Disposition cases (verify / reject) during the pilot |
| Produce the proof-of-value report and assessment (Annex A) | Provide feedback on cases within [2] business days |
| Provide DPIA / data-map templates | Perform the DPIA and update the processing record |

## 5. Data protection [COUNSEL]

5.1 The Customer is the controller of the telemetry and derived data. [If the Vendor accesses the deployment
or its data: the Vendor acts as processor; the data processing agreement in Annex B (GDPR Art. 28) applies.]
5.2 Data processed: network flow and DNS security metadata as described in the Software's data map;
subscriber identifiers are pseudonymized at ingest; no content of communications.
5.3 Location: all data remains in [Customer environment, country]. No transfer outside the EEA. The optional
LLM feature remains disabled unless agreed in writing.
5.4 Vendor personnel access: [none / remote session supervised by the Customer, logged], limited to the
pilot purpose.
5.5 Security incidents affecting pilot data are notified to the Customer within [24] hours of discovery.

## 6. Confidentiality and results

6.1 Pilot data and the report are Customer confidential information.
6.2 The Vendor may use aggregated, anonymized learnings to improve the Software [COUNSEL: define scope; no
Customer data leaves the Customer environment by default].
6.3 Publication of results, the Customer's name or logo requires the Customer's prior written consent.

## 7. Support during the pilot

Business hours [Mon-Fri 9:00-18:00 CET]; SEV1 per the Software's incident runbook acknowledged within [4]
business hours. No 24/7 service is provided during the pilot.

## 8. Fees

| Item | Amount |
|---|---|
| Shadow Pilot fee | [FOUNDER TO SET pilot_fee: amount, currency, excl. VAT] |
| Extension | [FOUNDER TO SET extension_fee] |
| Payment schedule | [FOUNDER TO SET payment_terms] |
| Credit towards production | [FOUNDER TO SET production_credit: amount/% if production signed within N days] |

## 9. End of pilot: deletion or handover

Within [10] business days after the read-out, at the Customer's choice:
(a) **Deletion**: all volumes deleted (`docker compose down -v`), images removed, backups destroyed per the
Customer's sanitization procedure; the Vendor confirms in writing that it holds no pilot data; or
(b) **Continuation**: the deployment continues under a production agreement.
Deletion record: date, performed by, systems, backup media, witness: [to fill at close-out].

## 10. Acceptance

The pilot is complete when the report and the Annex A assessment are delivered. Acceptance of deliverables
does not depend on the success criteria being met; the criteria inform the Customer's production decision.

## 11. Liability [COUNSEL]

[Cap, exclusions, no warranty of detection results. The Software makes no enforcement decisions in shadow
mode; the Customer remains responsible for any action it takes on the basis of pilot findings.]

## Annex A: success criteria (signed at kick-off)

| # | Criterion | Target | Measurement | Result (at close-out) |
|---|---|---|---|---|
| 1 | False alerts per 10,000 device-days | [ ] | PoV report, analyst dispositions | |
| 2 | [ ] | [ ] | [ ] | |
| 3 | [ ] | [ ] | [ ] | |
| 4 | Zero enforcement | 0 | ledger attestation | |

Signed for the Customer: ____________  Signed for the Vendor: ____________  Date: ________

## Annex B: data processing agreement [COUNSEL, if applicable]
