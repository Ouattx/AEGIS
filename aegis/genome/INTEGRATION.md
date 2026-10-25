# GENOME integration notes

GENOME is self-contained under `aegis/genome/` and does not modify any other module. This
file lists the calls other owners need to wire it in. Everything below is a proposal for the
owners of those files; none of it is implemented outside `aegis/genome/`.

## RESONANCE (reused, not modified)

GENOME calls only RESONANCE's public functions:

| GENOME step | RESONANCE function |
|---|---|
| event tables, DNS-answer join | `aegis.resonance.events.build_event_table`, `events_from_observations`, `observations_to_frames` |
| per (line, destination) series, burst coalescing, continuation removal | `aegis.resonance.events.prepare_series` |
| lab timer discovery | `aegis.resonance.periodicity.make_grid`, `periodogram`, `best_periods` |
| eligibility (popularity, shared hosting, streaming volume, history, allowlist) and weights | `aegis.resonance.population.key_stats`, `infrastructure_clusters`, `assess_unit`, `DestinationContext`, `DestinationHistory` |
| FDR | `aegis.resonance.detector.weighted_bh` |
| ISP background traffic and packet sampling (benchmark only) | `aegis.resonance.sim.generate_scenario`, `packet_sampling_keep`, `baseline_history` |

GENOME carries its own generalized-Pareto tail helper (same method as RESONANCE's private
`_tail_p`) so it does not import private names.

Suggestions for RESONANCE owners, measured while building GENOME (not changed here):

1. **Permutation floor.** A permutation p-value cannot be smaller than
   `1 / (number of distinct null configurations + 1)`. GENOME enforces this
   (`p_min = 1 / (prod_l |alternatives_l| + 1)`). With `ALT_KEEP = 6` and 3 to 5 member lines,
   RESONANCE's sequential/GPD p-values could fall below that floor. Worth checking when
   `min_lines` is lowered below 5.
2. **Harmonic campaigns in the null.** When two campaigns run at harmonic periods
   (600 s and 300 s), each one's series sit in the other's null pool and inflate it. GENOME
   runs a second pass with the series of supported pass-1 rejections removed from every null
   pool. RESONANCE may benefit from the same.

Running both detectors on one window: they share the event table.

```python
table = events_from_observations(events, start=window_start, end=window_end)
res = Resonance(rcfg, context=ctx, history=hist, tenant_id=t).detect(table)
gen = GenomeDetector(genomes, genome_keyring, gcfg, context=ctx, history=hist, tenant_id=t).detect(table)
```

Both use the same population model and history, so a destination that RESONANCE considers
ineligible (popular, shared hosting, established) is ineligible for GENOME too. When both
report a campaign on the same destination, they are **not** independent corroboration: both
come from the same operator telemetry (evidence group `operator-telemetry`). The genome's
lab provenance is a separate origin (`boxfarm-lab`).

## Service (`aegis/service.py`)

* Add a key-ring kind `"genome"` (next to policy / ioc / ledger / model) for genome signer
  public keys. Revocation follows the existing `revoke_key` flow. `load_genomes` fails closed
  on unknown, revoked or tampered signatures and on expiry.
* Genome store: persist signed `Genome` JSON per tenant (or globally for the vendor feed) and
  ledger each one with `aegis.genome.ledger_genome(ledger, tenant_id, genome)` on import.
* Per detection window (after ingest, same cadence as RESONANCE):
  `GenomeDetector(...).detect(table)` then
  `to_findings(report, genomes, evidence_store=store, authorization_id=auth)`. Findings carry
  `requires_review=True` and go through the normal case state machine. No enforcement path
  reads GENOME output directly.
* Early-warning bundles (`build_early_warning_bundle`) use the `aegis.ioc_bundle/1` format and
  load through the existing IOC import (`aegis.sentinel.rules.load_bundle`) once the lab
  signer's key is trusted in the `ioc` ring. Indicators carry tags `lab-observed` and
  `not-yet-seen-in-tenant`. Run `tenant_exposure(bundle, tenant_id, table)` inside each
  tenant's scope only. `exposure_summary` combines results already obtained tenant by tenant;
  there is no cross-tenant query path.

## API (`aegis/api/routes.py`), proposed routes

| Route | Role | Body / result |
|---|---|---|
| `POST /genomes` | admin | signed `Genome` JSON; 400 unless `verify_genome` passes; ledgered |
| `GET /genomes` | analyst | id, family, version, period, confidence, expiry, signer, status (active / expired / unverified) |
| `GET /genomes/{genome_id}` | analyst | full genome (metadata only) and provenance |
| `GET /genome/report` | analyst | last `GenomeReport` for the tenant (campaigns, abstentions, device-model hypotheses) |
| `POST /genome/early-warning/{bundle_id}/exposure` | analyst | `tenant_exposure` for the caller's tenant only |

## Web (`web/src/pages`), proposed

* Findings page: label `c2_beaconing_genome_match` shows family attribution with its share
  and confidence, the genome id, and the lab provenance (capture ids, box models, licence).
* Device-model hypotheses are shown as a ranked list titled "likely device model
  (hypothesis)", with the evidence beside each entry. Never shown as a fact.
* Early warning: list of lab-observed indicators with status
  "lab-observed, not yet seen in tenant" / "seen in tenant".

## Lab (`aegis/homelab/`, in progress elsewhere)

GENOME takes `aegis.genome.LabCapture` (one device, metadata frames, box model, firmware,
family label, licence, active periods) or canonical `ObservationEvent`s through
`capture_from_observations`. A homelab adapter needs to produce one of these. It does not need
to change GENOME.
