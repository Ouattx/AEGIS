# AEGIS sample data

Small, deterministic samples for demos, docs and tests. Everything here is
synthetic: addresses come from reserved documentation/benchmark ranges
(198.18.0.0/15, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 100.64.0.0/10)
and every hostname ends in `.example` or `.test`.

Regenerate with `python -m aegis.lab.samples sample_data` (a unit test fails if
the committed files drift from the generator).

| Path | Contents |
|---|---|
| `lab/netflow.csv` | 8 devices x 1 day of gateway NetFlow/IPFIX bi-flows (60 s active timeout) |
| `lab/dns.jsonl` | the same devices' DNS queries (JSON Lines) |
| `lab/labels.csv` | device-day ground truth (`benign`, `c2_beaconing`, `residential_proxy`, `dga_activity`, `ddos_bot`) |
| `lab/devices.json` | device profiles, infection times, C2 used (lab ground truth) |
| `lab/topology.json` | operator-visible hosting topology (shared CDN edges and their co-tenants) |
| `lab/lab_ground_truth.json` | malicious infrastructure and Zeek entity aliases |
| `lab/ioc_bundle.json` + `ioc_signer_public.pem` | signed IOC bundle (fresh, syndicated, stale, contradicted indicators) |
| `lab/sources.json` | the `SourceConfig`s that ingest these files |
| `lab/manifest.json` | SHA-256 of every file plus corpus summary |
| `zeek/conn.log`, `zeek/dns.log` | Zeek TSV logs of a 3-device lab day |
| `formats/nfdump.csv` | nfdump `-o csv` style export (alias mapping) |
| `formats/cpe.json` | CPE/gateway agent JSON document |
| `formats/malformed_netflow.csv` | 1 valid line + 8 lines that must each be quarantined for a different reason |

Lab pseudonyms are keyed with `aegis.lab.lab_tenant_key(tenant_id, seed)`;
register that key for the tenant to reproduce the pseudonyms in `labels.csv`.
