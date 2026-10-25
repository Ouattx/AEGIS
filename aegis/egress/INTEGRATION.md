# EGRESS integration notes

EGRESS is self-contained under `aegis/egress/`. It reads the tenant's flow
`ObservationEvent`s, never modifies another module, and needs no LLM. This page lists what
an integrator wires and what EGRESS can and cannot claim.

## What it detects

| label | line signal | needs |
|---|---|---|
| `egress_ddos_participation` | `flood` (one-way rate toward a host or a /24), `sync_burst` (sharp onset), `spoofing` (uRPF counters) | `packets_out` and `packets_in` |
| `egress_amplification_reflection` | `amplification_request`: many reflectors on a UDP amplification port, almost no replies | `packets_in` |
| `egress_abused_reflector` | the CPE answers one remote about one-for-one with a large byte amplification (never MALICIOUS: the subscriber is the victim of a misconfiguration) | bytes and packets both ways |
| `egress_residential_proxy` | `proxy_relay`: bytes from many short inbound sessions leave again toward one persistent upstream | `bytes_in`, `bytes_out`, `duration_ms` |
| `egress_spam` | direct SMTP (tcp/25) to many distinct mail exchangers | flows only |
| `egress_credential_stuffing` | storms of short, byte-uniform, irregularly timed sessions to one login service; one auth port across many hosts | `bytes_in` |

Verdict policy (pre-registered, in `detector.py`): a strong signal plus corroboration
(cross-line campaign, spoofing counters, or a second abuse family on the same line) is
MALICIOUS; a strong signal alone, or campaign membership with a weak signal, is SUSPICIOUS;
weak signals alone are counted in `report.stats["weak_signals_not_reported"]` and not
reported. Scores are rankings, not probabilities (`calibration_id=None`), and every finding
has `requires_review=True`.

Abstention: the whole report abstains below `min_flow_records` or when more than
`max_missing_packets_fraction` of records lack packet counters. Per line, a flood-rate or
reflection candidate on a uniflow exporter (no reverse counters) becomes an ABSTAIN
verdict, and a proxy candidate whose sink lacks byte counters becomes an ABSTAIN verdict.
Abstain findings cite one evidence record that states what was missing.

Device class, vendor, IPTV usage and geography are never inputs to a verdict (the device
class on a finding is descriptive only; `test_device_class_does_not_change_the_verdict`).

## Calling it

```python
from aegis.egress import EgressConfig, EgressDetector, SpoofSignal, to_findings
from aegis.resonance import DestinationContext

cfg = EgressConfig(sampling_interval=1000)            # 1:N packet sampling of the exporter (1 = unsampled)
det = EgressDetector(cfg, tenant_id=tenant_id, context=DestinationContext(topology))   # context optional
report = det.detect(events, start=window_start, end=window_end, spoof_signals=urpf_counters)
findings = to_findings(report, cfg=cfg, evidence_store=evidence_store, authorization_id=collection_auth)
```

* `events`: one tenant's flow events for the window. An event of another tenant raises
  `ValueError` (no cross-tenant path).
* `sampling_interval`: if unknown, leave it at 1. Rates are then underestimated, which only
  makes EGRESS more conservative.
* `spoof_signals` (optional): anti-spoofing drop counters per line pseudonym from the BNG /
  CMTS / OLT (BCP 38 / BCP 84 uRPF) or a CPE agent. Flow records cannot attribute spoofed
  packets to a line; these counters can. They carry their own independence group
  (`operator-urpf`).
* `context` (optional): any object with `kind(ip) -> str | None`
  (`aegis.resonance.DestinationContext` works). Used only for counter-facts (proxy sink on
  residential / VPN / cloud space, flood target on a game or VPN service). Unknown is
  reported as `sink_topology_unknown`, never assumed.

## Evidence and provenance

`to_findings` writes through `aegis.provenance.EvidenceStore`: one OBSERVATION per line
signal (the full rule inputs, so a reviewer can recompute the verdict), one ANOMALY per
campaign (written once, ledgered as `egress_campaign`), COUNTER_HYPOTHESIS evidence listing
the benign explanations to rule out, BENIGN_BASELINE evidence for concrete limiting facts,
and a `finding` ledger entry carrying `detector_version` and `config_hash`.

All EGRESS evidence shares the `operator-telemetry` independence group with SENTINEL and
RESONANCE: several EGRESS signals are not independent corroboration for the case state
machine.

## Service wiring (proposal for the owner of `aegis/service.py`)

Per detection window, after ingest and next to RESONANCE:

```python
report = EgressDetector(self.egress_config(tenant_id), tenant_id=tenant_id,
                        context=self.destination_context(tenant_id)).detect(events, start=ws, end=we,
                                                                             spoof_signals=spoof)
for f in to_findings(report, evidence_store=self.evidence, authorization_id=auth):
    self.findings.put(f)            # existing tenant-scoped finding store; cases open as usual
if report.status == "abstain":
    coverage["egress_abstain_reason"] = report.abstain_reason
```

`EgressConfig` is a frozen pydantic model; per-tenant overrides belong in the tenant
settings (sampling interval first). No enforcement path reads EGRESS output directly: a
mitigation is proposed through `aegis.connectors` and only ever executed through
`aegis.mirror` (`simulate` -> `authorize` -> `Executor`).

## Evaluation (lab corpus only)

Measured with the unchanged `aegis.lab` corpus (2 days, flow metadata only), default
config, with the lab hosting topology as context:

| seed / devices / malicious fraction | benign lines flagged | ddos_bot found | residential_proxy found |
|---|---|---|---|
| 11 / 120 / 0.12 (unit test) | 0 of 106 | 3 / 3 | 4 / 4 |
| 7 / 200 / 0.08 | 0 of 184 | 4 / 4 | 4 / 4 |
| 23 / 300 / 0.08 | 0 of 276 | 6 / 6 | 6 / 6 |
| 5 / 150 / 0.15 | 0 of 128 | 5 / 5 | 6 / 6 |

The benign population includes 24/7 IPTV boxes, consoles in matches, VPN laptops,
sustained camera uploads and firmware downloads. With reverse counters stripped
(uniflow export), no benign line is flagged and the DDoS bots become ABSTAIN.

Honest limits:

* The corpus is an emulation. These numbers say the rules behave as designed on the lab
  shapes; they are not a field false-positive rate. Pilot reporting must use the
  operator's own dispositioned findings.
* Three proxy-rule details were changed while running against this corpus, before the
  numbers above were recorded: sink persistence and rates are measured over the sink's own
  lifetime (a relay that starts mid-window was invisible), active-timeout tail slices are
  no longer counted as new inbound sessions, and the sink out/in ratio threshold is a
  config value (`relay_sink_min_out_in_ratio`, 3.0). Treat these as tuned on lab data.
* The corpus has no amplification, abused-reflector, spam or credential-stuffing
  emulation. Those rules are covered only by unit tests on hand-written records at their
  thresholds (`tests/unit/test_egress_detector.py`).
* C2 beaconing and DGA devices are not EGRESS targets and are not flagged by it.
