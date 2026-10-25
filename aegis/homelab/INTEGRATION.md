# aegis.homelab integration notes

`aegis.homelab` is self-contained: it does not modify any other module and only calls public
functions of `aegis.ingest`, `aegis.sentinel`, `aegis.resonance`, `aegis.provenance` and
`aegis.storage`. Everything below is a proposal for the owners of the service, API, web and CLI;
none of it is implemented outside `aegis/homelab/`. No new dependency: stdlib, numpy, pandas,
scipy, pydantic and sqlalchemy, all already required; HTML is generated with the stdlib.

## Public API

```python
from aegis.homelab import (HomeLabConfig, single_home_sources, import_capture, discover_capture,
                           analyze_single_home, crowd_mix, CrowdMixConfig, write_reports,
                           render_box_report, run_homelab, verify_run, open_lab_store,
                           load_usage_windows, parse_dnsmasq_log, dnsmasq_to_jsonl,
                           write_synthetic_capture, SyntheticBoxSpec)

# one call (CLI equivalent: python -m aegis.homelab analyze CAPTURE_DIR --out OUT)
run = run_homelab("captures/box1", "out/box1", cfg=HomeLabConfig(device_labels={"10.42.0.23": "box 1"}),
                  crowd=CrowdMixConfig(n_copies=20))           # crowd optional, MIXED-SYNTHETIC
run.analysis.devices[0].verdict.verdict                      # Verdict.MALICIOUS | SUSPICIOUS | ABSTAIN
run.reports                                                  # {label: Path(html), "analysis.json": Path}
verify_run("out/box1")                                       # re-verify the signed ledger

# step by step
imp = import_capture("captures/box1", cfg, pseudonymizer=Pseudonymizer(key))   # CaptureImport
store = open_lab_store("out/box1/homelab-ledger.db", signer=signer)           # LabStore (or None: in memory)
analysis = analyze_single_home(imp, usage=load_usage_windows("usage.json"), bundle=ioc_bundle,
                               local_list=(), store=store, model="default")
analysis.crowd = crowd_mix(imp.events_for(pseudonym), start=imp.start, end=imp.end)
write_reports(analysis, "out/box1")
```

| object | what it is |
|---|---|
| `HomeLabConfig` | lab subnet / gateway, tenant, authorization id, device labels, dnsmasq timezone/year, DNS source preference |
| `single_home_sources(cfg)` | the three `SourceConfig`s (`homelab-zeek-conn`, `homelab-zeek-dns`, `homelab-dnsmasq`): `Vantage.DEVICE`, `entity_field="src_ip"`, `subscriber_prefixes=(lab_subnet,)` |
| `CaptureImport` | time-ordered `ObservationEvent`s, per-file `IngestStats`, input file sha256, pre-filter counts, local chatter per device, `devices` (pseudonym -> label) |
| `HomeLabAnalysis` / `DeviceAnalysis` | timers (`TimerAnalysis`), infrastructure (`InfraSummary`), SENTINEL findings and window counts, hourly bins, `BoxVerdict`, evidence list; `to_dict()` is the `analysis.json` schema |
| `CrowdMixResult` | `data_class="mixed_synthetic"`, RESONANCE report, campaigns flagged `involves_capture`; never findings, never ledgered |

## Service (`aegis/service.py`)

1. **Sources.** A tenant that runs home labs registers the three single-home sources once:
   ```python
   for src in single_home_sources(HomeLabConfig(tenant_id=t, collection_authorization_id=auth)).values():
       svc.register_source(t, actor, source_id=src.source_id, source_kind=src.source_kind,
                           vantage=src.vantage, collection_authorization_id=auth,
                           entity_field="src_ip", subscriber_prefixes=src.subscriber_prefixes,
                           flow_direction=src.flow_direction)
   ```
2. **Ingest.** Zeek logs go through the existing `svc.ingest_files(t, [(path, "homelab-zeek-conn"), ...])`.
   dnsmasq logs are not a native collector format: convert first with
   `dnsmasq_to_jsonl(path, year=..., tz=...)` and call `svc.ingest_text(t, "homelab-dnsmasq", data)`.
   Note that the service path does not apply the importer's pre-filters (lab-local chatter,
   resolver queries not from a lab client, capture-window clipping); call
   `import_capture(...)` and `svc.ingest_events(t, [e.model_dump(mode="json") for e in imp.events])`
   to keep them.
3. **Analysis.** `analyze_single_home(imp, store=None, ...)` builds evidence objects without
   persisting them. To persist into the tenant's own provenance instead of a lab SQLite file,
   pass an object with `.evidence` (the service's `EvidenceStore`), `.ledger` and
   `.verify(tenant_id)` (a thin adapter over `svc.verify_ledger`), i.e. the `LabStore` shape.
   Verdicts are ledgered as entry type `homelab_verdict`; SENTINEL findings and their evidence are
   written by SENTINEL itself (entry type `finding`).
4. **Cases.** Box Lab verdicts are not `Finding`s and must not open cases automatically. SENTINEL
   findings produced during the analysis are ordinary findings and may go through
   `CaseService.open_case` if the operator wants them in the queue.
5. **Crowd mixing** must stay out of the tenant's findings, cases, coverage and RESONANCE history.

## API (`aegis/api`)

Suggested routes (analyst role; tenant-scoped like every route):

| route | call |
|---|---|
| `POST /api/v1/homelab/captures` (multipart: Zeek logs, dnsmasq log, capture.json, usage.json) | save to a tenant-scoped temp dir, `import_capture` + `analyze_single_home`, store `analysis.to_dict()` in `DocStore` |
| `GET /api/v1/homelab/captures/{id}` | the stored `analysis.json` |
| `GET /api/v1/homelab/captures/{id}/devices/{pseudonym}/report` | `render_box_report(analysis, pseudonym)` as `text/html` (self-contained, no script) |
| `POST /api/v1/homelab/captures/{id}/crowd-mix` | `crowd_mix(...)`, response labelled `mixed_synthetic` |

Uploads must keep the capture-size and rate limits of the existing ingest routes; `crowd_mix`
takes a few seconds to tens of seconds (simulated population + warm-up history), so run it in the
background executor.

## Web console (`web/`)

A "Box Lab" page listing uploaded captures with their verdict pill, linking to the HTML report
(iframe with `sandbox`), and showing the MIXED-SYNTHETIC banner for crowd-mix results. Copy the
verdict wording from `aegis/homelab/verdict.py` (`NO CONCLUSION`, never "clean").

## CLI (`aegis/cli.py`)

Either document `python -m aegis.homelab` or add a passthrough subcommand:
`aegis homelab <args>` -> `aegis.homelab.cli.main(args)`.

## Docs

`docs/homelab/GUIDE.md` (safety, legality, disclosure, naming) and `deploy/homelab/README.md`.
If `tests/unit/test_docs.py` should cover the guide's links, add `DOCS.glob("homelab/*.md")` to its
`OWNED` set.
