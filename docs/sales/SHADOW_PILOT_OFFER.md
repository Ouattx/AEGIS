# Paid Shadow Pilot: offer

> Commercial terms are keyed placeholders filled from the company's commercial configuration by
> `python deploy/tools/render_sales_kit.py --config commercial.toml --out dist/sales` (see
> `docs/sales/commercial.example.toml`). The renderer refuses to produce a document while any value is
> missing, so a placeholder can never be sent. Send only the rendered copy.

## In one paragraph

For two to four weeks, AEGIS OMEGA SHIELD runs read-only on your premises, on network telemetry you already
collect. It reports the subscriber devices that behave like compromised hosts, with the evidence for each,
and never blocks anything. Before we start, we agree in writing what success means. At the end you receive a
proof-of-value report on your network, measured against those criteria, and you decide whether to continue.

## Scope

| Included | Not included |
|---|---|
| Deployment of SHIELD on one host you provide (or a sovereign VM), shadow mode | Any blocking, filtering or subscriber notification by AEGIS |
| Up to [FOUNDER TO SET vantage_points: 2] telemetry vantage points (e.g. core IPFIX + resolver DNS) | Collection infrastructure changes on your network (we advise, your teams configure) |
| Subscriber segment of up to [FOUNDER TO SET segment_lines: e.g. 50,000 lines] | Access to subscriber identity data (AEGIS stores pseudonyms only) |
| Your signed IOC feeds, plus [FOUNDER TO SET partner_feeds: partner feeds, if licensed] | Copyright / anti-piracy use cases (separate product, not in scope) |
| Analyst console access for up to [FOUNDER TO SET named_users: 10] named users | Hosting outside your environment |
| Weekly review with your SOC lead; a final read-out to your management | 24/7 operations by our team |
| DPIA and data-map templates prepared for your DPO and counsel | Legal advice |

## Timeline

| Week | What happens | Your effort |
|---|---|---|
| 0 (before start) | Kick-off: vantage points, segment, success criteria and false-alert budget signed; DPIA / processing record updated; host provisioned | SOC lead 2 h, network architect 2 h, DPO review |
| 1 | Installation (half a day), IdP roles, source registration, first hour of telemetry pushed, quarantine reviewed until >= 99.9% valid, IOC feed and topology loaded, shadow policy signed | network engineer 1 day, IdP admin 1 h |
| 2 | Continuous telemetry; analysts triage cases daily; first weekly review | analyst 30 to 60 min per day |
| 3 to 4 (optional extension) | Continued operation over a longer window (weekly cycles, longer beacons); optional rehearsal of the action workflow in shadow (propose, simulate, assess: all refused by policy) | as week 2 |
| End | Proof-of-value report, read-out, data deletion or handover per your choice, go/no-go | management 1 h |

## Deliverables

1. A running SHIELD deployment in shadow mode for the pilot duration, with monitoring dashboards.
2. Weekly status: ingest health, findings, analyst workload, open questions.
3. **Proof-of-value report** (HTML, print to PDF): findings by threat class, devices observed, false alerts per
   10,000 device-days with confidence bounds, analyst minutes per case, detection delay, known-IOC alert
   latency, evidence coverage, cost per 1,000 monitored devices and per incident, zero-enforcement attestation, ledger
   verification.
4. Assessment against the success criteria agreed in week 0, with a clear pass / partial / fail per criterion.
5. Recommendation for production: vantage points, sizing, integration with your abuse process, open
   questions for counsel before any active enforcement.
6. Close-out: certified deletion of pilot data (or encrypted handover), per section 9 of the SOW.

## Success criteria (agreed and signed before the start)

Choose two to four, with numbers, in the kick-off. Examples:

| Criterion | Example target | How it is measured |
|---|---|---|
| False alerts | <= [CUSTOMER TO SET] per 10,000 device-days | analyst dispositions in the PoV report, upper bound reported |
| Confirmed compromised devices | >= [CUSTOMER TO SET] verified by your analysts, or confirmation that none were present | verified cases with cited evidence |
| Analyst effort | <= [CUSTOMER TO SET] minutes per case on average | PoV report effort model, checked against analyst feedback |
| Ingestion | >= 99.9% valid events over the pilot | Grafana / PoV report |
| Known-IOC alert latency | p95 <= 120 s from data receipt (or window close, whichever is later) to alert; end-to-end freshness also depends on export cadence (1-minute exports recommended) | PoV report |
| Zero enforcement | 0 actions executed | ledger-backed attestation |
| Comparison | finds what [your current tool / feed] finds on the same segment, plus [X] | side-by-side on agreed cases |

If the pilot fails its agreed criteria, you will know why: the report shows the data, the coverage gaps and
the errors.

## Pricing

| Item | Price |
|---|---|
| Shadow Pilot, 2 weeks | [FOUNDER TO SET pilot_fee: amount, currency, excl. VAT] |
| Extension to 4 weeks | [FOUNDER TO SET extension_fee] |
| Additional vantage point | [FOUNDER TO SET extra_vantage_fee] |
| Credit towards the first year of production if signed within [FOUNDER TO SET credit_window_days: 60] days | [FOUNDER TO SET production_credit: % or amount] |

Payment terms: [FOUNDER TO SET payment_terms: e.g. 50% at signature, 50% at report delivery]. Travel: [FOUNDER TO SET travel_terms].

## What we need from you

* A Linux host (4 vCPU, 16 GB RAM, 100 GB SSD minimum) with Docker, reachable by your collectors and analysts.
* Telemetry exports from the chosen vantage points, with their sampling rate and NAT position.
* An OIDC identity provider entry (Keycloak, Entra ID or similar) with the five roles.
* A named SOC lead and analysts who disposition cases (the false-alert metric depends on it).
* Your DPO's review of the DPIA template before telemetry flows.

## Why a paid pilot

Because a pilot costs both sides real effort, and because the result has to be credible to your management:
a measured outcome on your network, against criteria you set, is worth more than any vendor claim. Ours
included. See the [claims guide](CLAIMS_GUIDE.md) for what we do and do not claim.

Next step: a 45-minute scoping call to choose vantage points and draft the success criteria.
Contract: [PILOT_SOW_TEMPLATE.md](PILOT_SOW_TEMPLATE.md).
