# deploy/

| Path | What it is |
|---|---|
| `docker-compose.yml` | production single-host stack: PostgreSQL + API; profiles `monitoring` (Prometheus, Grafana) and `bus` (Redpanda) |
| `docker-compose.demo.yml` | self-contained demo on synthetic data (dev auth, 127.0.0.1:8080 only) |
| `.env.example` | configuration template; copy to `deploy/.env` and fill in the REQUIRED values |
| `prometheus/` | scrape config, SLO alert rules and their promtool unit tests |
| `grafana/` | provisioned datasource and the "AEGIS SHIELD - Operations" dashboard |
| `tools/aegis_push.py` | collector-side uploader (chunking, retries, OIDC client credentials) |
| `tools/sign_ioc_bundle.py` | sign / verify an operator IOC bundle offline |
| `examples/` | shadow operator policy, IOC bundle and hosting topology templates |
| `smoke-test.sh` | end-to-end test of the compose stack (used by CI) |
| `backup.sh`, `restore.sh` | consistent backup and checksum-verified restore |
| `purge-expired.sh` | retention enforcement for quarantined raw records (schedule daily) |

Start with [../docs/INSTALL.md](../docs/INSTALL.md).
