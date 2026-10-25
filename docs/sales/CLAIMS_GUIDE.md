# Honest claims guide

Every sentence in a deck, email, proposal or conversation must survive a skeptical engineer at the
customer. This guide implements spec sections 14 and 19: superiority claims are limited to tested metrics and
scenarios; no accuracy figure without base rate and error cost; "elite" means proven at a paying customer.
When in doubt, say less and offer the pilot.

## What we can say

| Claim | Why it is true | Proof to show |
|---|---|---|
| "Read-only shadow mode by default; nothing is blocked during a pilot." | dry-run adapter default; shadow policy fails authorization by design | demo step 5:30; `tests/unit/test_api_actions.py` (shadow policy never authorizes) |
| "Every alert cites its evidence, and every evidence item is hashed." | findings carry evidence ids; evidence is content-addressed | Evidence trail tab; PoV report evidence coverage |
| "Every state change is in a signed, hash-chained ledger you can verify." | Ed25519-signed hash chain per tenant | Ledger page "Verify chain now"; `aegis ledger verify` |
| "SHIELD abstains instead of guessing when context is insufficient." | mandatory ABSTAIN in the fusion policy | Findings filter "Abstain" |
| "It never flags a device because of its brand, its type, IPTV apps or geography." | device class only selects a baseline; tested | `tests/unit/test_sentinel_detector.py` (device class alone never produces a finding) |
| "Before any block, it simulates the collateral on shared infrastructure and fails closed when it doesn't know." | MIRROR simulation with co-tenants; UNKNOWN on incomplete topology | demo simulation; `tests/unit/test_mirror_safety.py` |
| "No action without a second person and a signed operator policy with legal sign-off." | four-eyes and `authorize()` conjunction | Approve button disabled; authorization checklist |
| "The detection path works with no AI service at all." | LLM optional, deterministic fallback | demo runs with no LLM; `/readyz` shows LLM disabled |
| "Runs on your premises; no data leaves your network in the default configuration." | single-host compose, LLM off by default | INSTALL.md section 1 |
| "Subscriber identifiers are pseudonymized at ingest." | HMAC per tenant, source IP dropped | DATA_MAP.md |
| "On our synthetic lab corpus, [metric] was [value] with [CI], at a base rate of [x]%." | eval harness output | `aegis benchmark` report, with the word *synthetic* in the same sentence |

## What we must not say

| Do not say | Why | Say instead |
|---|---|---|
| "99% accuracy", "detects 100% of infected devices" | accuracy is meaningless at low base rates; lab recall is not field recall | "In the pilot we measure recall on confirmed cases and false alerts per 10,000 device-days, with confidence intervals." |
| "Zero false positives" | the lab shows zero on synthetic data; the field will not | "False alerts are measured against a budget you set before the pilot." |
| "Blocks botnets", "stops attacks automatically" | v1 is sold as shadow; enforcement is gated and operator-controlled | "Gives your team defensible findings; any action stays under your signed policy." |
| "AI-powered detection", "autonomous AI agents" | detection is rules plus a calibrated model; agents only draft investigations | "Deterministic detection with optional AI-drafted investigation summaries." |
| "Better than [competitor / vendor X]" | no head-to-head benchmark on customer data exists | "We will run the comparison in your pilot if you name the baseline." |
| "Guaranteed compliant with GDPR / NIS2 / Arcom / the AI Act" | compliance is the operator's determination with counsel | "Designed for data minimization; DPIA and data-map templates are provided for your DPO and counsel." |
| "Certified", "ANSSI qualified", "SecNumCloud" | no certification held | "No certification is claimed for v1." |
| "Detects piracy / illegal IPTV" | SHIELD is security only; IPTV use is never evidence; RIGHTS is not in v1 | "SHIELD detects compromised devices; it deliberately ignores what people watch." |
| "Identifies the infected subscriber" | AEGIS stores pseudonyms; identification happens in the operator's systems | "Your team re-identifies the line in your own systems when your process requires it." |
| "Works with any telemetry", "sees inside the home" from core NetFlow | vantage limits (NAT, CGNAT, sampling) | the vantage table in OPERATOR_INTEGRATION.md |
| "Real-time" | known-IOC latency target is p95 <= 120 s in the pilot, dependent on export cadence | "Minutes, measured in the pilot." |
| Customer names, logos, quotes | only with written permission | anonymized: "a European ISP" only after a signed reference agreement |

## Numbers: rules of use

1. Every number has a source (pilot report, benchmark JSON) and a date.
2. Lab numbers always carry the words "synthetic lab corpus" in the same sentence.
3. Rates always carry the base rate; false alerts are per 10,000 device-days with the upper bound.
4. Never round a confidence interval away; never drop the "n=" when n is small.
5. Pilot results belong to the customer; publishing them needs written consent.

## Review

Any external document (deck, website, proposal, case study) is reviewed against this guide by a second
person before it leaves the company. Regulatory statements also go to counsel.
