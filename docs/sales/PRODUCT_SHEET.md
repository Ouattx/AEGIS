# AEGIS OMEGA SHIELD

**Find the compromised devices hiding on your network, with evidence you can defend.**

Cheap pre-infected TV boxes and IoT devices are turning subscriber homes into botnet nodes and rented
residential proxies. You already collect the telemetry that reveals them. SHIELD turns it into findings your
SOC can verify and act on, without accusing the household that simply streams a lot.

## What it does

* **Detects** periodic C2 beaconing, residential-proxy egress, DGA lookups and DDoS-bot bursts from
  NetFlow/IPFIX, resolver DNS logs, Zeek or CPE telemetry you already have.
* **Explains** every alert: the evidence items, their hashes, how many independent sources agree, the benign
  explanations that were checked, and what the system knew at the time of the decision.
* **Abstains** when the data is too thin, instead of guessing. Device brand, type, IPTV apps and geography
  are never treated as evidence.
* **Protects your network from your own response:** before any block, it simulates collateral damage on
  shared hosting and CDNs and refuses when the impact is unknown. Nothing runs without your signed policy, a
  legal sign-off reference and a second person's approval.
* **Proves itself:** a proof-of-value report with false alerts per 10,000 device-days, analyst effort per
  case, detection delay, cost per protected device-month and a zero-enforcement attestation.

## Built for operators

| | |
|---|---|
| Deployment | On your premises or sovereign cloud: one container plus PostgreSQL. No data leaves your network by default. |
| Privacy | Flow and DNS metadata only. No payloads, no decryption, no URLs. Subscriber identifiers pseudonymized at ingest; re-identification stays in your systems. |
| Integration | Push files over HTTPS (NetFlow/IPFIX CSV from nfdump or pmacct, Zeek logs, resolver JSON logs, CPE agents); identities and roles from your OIDC provider (Keycloak, Entra ID); Prometheus and Grafana. |
| Assurance | Signed, hash-chained audit ledger; role separation and four-eyes approval; signed releases with SBOM. |
| AI | Optional and advisory. Detection and every decision run without it. |
| Compliance support | DPIA and data-map templates for your DPO; security architecture and threat model mapped to automated tests. |

## Start with a paid shadow pilot

Two to four weeks, read-only, on telemetry you already have. Success criteria agreed before we start.
At the end: the proof-of-value report on your network, and a decision based on your numbers.

**Contact:** [FOUNDER TO SET: name, email, phone]

*SHIELD v1 is sold in shadow mode. Performance figures from our synthetic lab are not field results; field
performance is measured in your pilot.*
