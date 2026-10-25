# CONNECTORS integration notes

`aegis/connectors/` exports AEGIS results to operator systems. It is self-contained, adds
no dependency (`httpx`, `pydantic`, `rfc8785` are already installed) and is not yet wired
into the service, API or console. This page lists the calls an integrator needs.

Ground rules, enforced in code:

* **Propose-only by default.** FlowSpec rules and DDoS-platform documents are proposals
  (`status: proposed`, `requires_operator_review: true`, `auto_apply: false`) and start with
  the same notice: not applied, requires a qualified operator's review.
* **Actions only through MIRROR.** The one connector that can change an enforcement point,
  `MitigationRequestAdapter`, is an `aegis.mirror` adapter. It runs only inside
  `aegis.mirror.Executor.execute(action, decision, approver)` after
  `aegis.mirror.authorize(...)`, with the executor's checks (signed active policy, legal
  signoff, MIRROR SAFE, scope, expiry, verified rollback, human approver, four-eyes).
* **Dry-run by default.** `ExportDelivery` and `MitigationRequestAdapter` send nothing
  unless built with `dry_run=False`. Live delivery requires an HMAC secret (>= 32 bytes) and
  an `https` URL; URLs with embedded credentials are refused.
* **Signed.** Every HTTP delivery carries `X-Aegis-Timestamp`, `X-Aegis-Delivery`
  (idempotency key, stable across retries), `X-Aegis-Event`, `X-Aegis-Content-SHA256` and
  `X-Aegis-Signature: v1=<hex HMAC-SHA256 over "<timestamp>." + body>`: the MIRROR webhook
  scheme. Receivers use `aegis.connectors.verify_export` (or
  `aegis.mirror.verify_webhook_signature`), which also rejects stale timestamps.
* **Ledgered.** With a `ledger`, every delivery (dry-run included) writes a
  `connector_export` entry with the content hash, record count, destination (without
  credentials), actor and outcome. The content itself is not copied into the ledger.

## Modules

| module | entry points | output |
|---|---|---|
| `flowspec.py` | `propose_flowspec(report, FlowSpecConfig(source_prefixes=...), context=)`, `render(proposals, "junos" \| "iosxr" \| "exabgp")`, `flowspec_export(plan, syntax)` | `FlowSpecPlan` (proposals + skipped with reasons), router text |
| `ddos.py` | `ddos_export(report, plan)`; `MitigationRequestAdapter(url, secret, source_prefixes=..., dry_run=True)` | JSON `aegis.ddos-export/1`; MIRROR adapter (`IP_BLOCK` targets) |
| `siem.py` | `siem_export(findings, "cef" \| "leef" \| "jsonl", tenant_id=, now=, campaigns=)` | CEF, LEEF 2.0, JSON lines |
| `stix.py` | `from_egress_report(report, verified)`, `build_bundle(...)`, `stix_export(...)`, `validate_bundle(bundle)` | STIX 2.1 bundle |
| `common.py` | `ExportPayload`, `ExportDelivery(url, secret=, dry_run=True, ledger=)`, `signature_headers`, `verify_export`, `record_export` | delivery results, ledger entries |

## FlowSpec proposals (RFC 8955, RFC 8956 for IPv6)

`propose_flowspec` reads an `EgressReport` and proposes, per victim and per subscriber
aggregate of the same address family:

* match: destination prefix (type 1, the victim host or a carpet-bombed /24 / /48), source
  prefix (type 2, one of `FlowSpecConfig.source_prefixes`), IP protocol (type 3) when the
  flood used tcp / udp / icmp only, destination port (type 5) when every line used the same
  few ports;
* action: `traffic-rate-bytes` (0x8006) at `rate_bytes_per_s` (default 1,250,000 B/s =
  10 Mbit/s), plus `traffic-action` sample (0x8007). A discard (rate 0) is proposed only
  with `allow_discard=True` *and* a MALICIOUS (corroborated) verdict;
* a suggested expiry (`ttl_hours`, default 4).

It abstains (`plan.skipped[*].reason`) rather than propose an unsafe rule:
`source_prefixes_not_configured`, `spoofed_source_not_matchable` (reflection requests:
the remedy is BCP 38 / uRPF at the subscriber edge), `target_on_shared_infrastructure`,
`destination_prefix_too_wide`, `not_corroborated` (SUSPICIOUS DDoS unless
`include_suspicious=True`), `verdict_abstain`, `report_abstained`,
`not_a_flowspec_use_case` (proxy, spam, stuffing), `no_rule_inputs` (onset or spoofing evidence only),
`max_rules_exceeded`.

Renderings: Junos `set routing-options flow route ...` (`rate-limit` in bits per second,
`rib inet6.0` for IPv6), IOS XR flowspec `class-map type traffic` + one
`policy-map type pbr AEGIS-PROPOSALS` (`police rate ... kbps`) attached under `flowspec
address-family`, ExaBGP `flow { route ... }` (`rate-limit` in bytes per second). These are
illustrative texts of the same rule; keywords and units vary by software release and the
operator verifies them. AEGIS never announces a route.

## DDoS-platform JSON (`aegis.ddos-export/1`)

A generic notification format. It is **not** the API of any DDoS-protection vendor; an
integrator maps it. Top-level fields:

| field | meaning | typical mapping |
|---|---|---|
| `status`, `requires_operator_review`, `auto_apply` | always `proposed`, `true`, `false` | create a ticket / pending mitigation, never an active one |
| `generator.detector_version`, `generator.config_hash` | reproducibility | attach to the ticket |
| `window.start/end/status/abstain_reason` | analysed window | alert time range |
| `attacks[]` (`scope: campaign`) | `attack_id` (campaign id), `kind`, `lines_involved`, `line_pseudonyms`, `targets`, `metrics.aggregate_peak_pps` | one "outbound attack" record per victim |
| `attacks[]` (`scope: line`) | `line_pseudonym`, `verdict`, `score`, `targets`, `protocols`, `dst_ports`, `peak_pps`, `spoofing_counters`, `alternatives` | per-subscriber detail for abuse handling |
| `mitigation_proposals[]` | `flowspec` (RFC 8955 view: `nlri[]` components by type, `extended_communities[]`), `action`, `rate_bytes_per_s`, `suggested_expiry`, `caveats` | a mitigation template awaiting operator approval |
| `not_proposed[]` | skipped proposals with reasons | show why nothing was proposed |

Line pseudonyms are the operator's own tenant-keyed identifiers, never a subscriber
identity; only send this document to the operator's own systems.

`MitigationRequestAdapter` posts `aegis.mitigation-request/1` documents (`event`
`aegis.mitigation.apply` / `aegis.mitigation.withdraw`, `action` summary, `expires_at`,
`rules[]` with `match` and `action`). It supports `ActionType.IP_BLOCK` only (target = the
victim address), turns each target into one rule per configured subscriber aggregate, and
requests a discard only when the action scope says `{"mitigation": "discard"}` (the signed
policy must approve that scope value) and the adapter was built with `allow_discard=True`.
`rehearse_rollback` builds and signs both the apply and the withdraw request locally.

## SIEM

`siem_export` accepts any `Finding` (all detectors) plus EGRESS campaigns, refuses records
of another tenant and returns one batch:

* CEF: `CEF:0|AEGIS|OMEGA SHIELD|<version>|aegis:finding:<label>|<label> <verdict>|<sev>|...`
  with `rt`, `start`, `end`, `cat`, `externalId`, `act=alert`, `cs1` entity pseudonym, `cs2`
  verdict, `cs3` detector version, `cs4` evidence ids, `cs5` device class, `cs6` tenant,
  `cfp1` score, `msg`. Campaigns add `dst` (first IPv4 target) and `cn1` lines involved.
  Severity: malicious 8, suspicious 5, abstain 2, campaign 7.
* LEEF 2.0 with `^` as the declared delimiter, `devTime` ISO 8601 + `devTimeFormat`,
  `sev`, `cat`, and the same custom keys.
* JSON lines (`application/x-ndjson`), one RFC 8785 canonical object per line, schema
  `aegis.siem/1`.

Send through `ExportDelivery` (HTTPS collector) or write `payload.body` to a file picked up
by the SIEM's file or syslog forwarder.

## STIX 2.1

Only analyst-verified material: `VerifiedCampaign` / `VerifiedIndicator` require a
`verification_ref` (the case id that reached VERIFIED). `from_egress_report(report,
{campaign_id: case_id})` exports the listed campaigns; only residential-proxy sinks become
indicators. DDoS, spam and login-attack targets and abused reflectors are victims and are
never indicators. Bundles contain no pseudonyms, tenant ids or internal (RFC 1918, CGNAT,
ULA) addresses. Objects: `identity`, the predefined TLP `marking-definition`, `campaign`,
`indicator` (`pattern_type: stix`), `relationship` (`indicates`); ids are deterministic
UUIDv5. `build_bundle` refuses to return a bundle that fails `validate_bundle`, which
checks the structural rules used here (id format, `spec_version`, timestamps, required
properties, patterns, vocabularies, references resolving inside the bundle). It is not a
complete STIX validator; run the OASIS validator in the sharing pipeline if a partner
requires it.

## Service wiring (proposal for the owner of `aegis/service.py` and the API)

```python
from aegis.connectors import (ExportDelivery, FlowSpecConfig, propose_flowspec, render, siem_export,
                              stix_export, from_egress_report)

# SIEM forwarding after each detection window (tenant-scoped findings only)
payload = siem_export(findings, settings.siem_format, tenant_id=tenant_id, now=self._now())
ExportDelivery(settings.siem_url, secret=self.secrets.siem_hmac, dry_run=not settings.siem_live,
               ledger=self.ledger).deliver(payload, actor="system:siem-forwarder")

# FlowSpec proposals for the analyst console (text only; nothing is announced)
plan = propose_flowspec(egress_report, FlowSpecConfig(source_prefixes=tenant.subscriber_prefixes),
                        context=self.destination_context(tenant_id))
text = render(plan.proposals, tenant.router_syntax)

# Mitigation request: a ProposedAction(IP_BLOCK, targets=[victim]) created by an analyst goes through
# the existing /actions propose -> simulate -> authorize -> approve -> execute routes, with an
# Executor built on MitigationRequestAdapter(url, secret, source_prefixes=..., dry_run=not policy_active).
```

New settings would be needed (`siem_url`, `siem_format`, `siem_live`, a per-destination HMAC
secret, subscriber prefixes and router syntax per tenant); none are added here.
