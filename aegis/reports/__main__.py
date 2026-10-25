"""Generate a shadow proof-of-value report.

Two modes::

    # from a deployment's database (PostgreSQL or SQLite)
    python -m aegis.reports render --db postgresql+psycopg://... --tenant isp-a \\
        --start 2026-10-01 --end 2026-10-15 --coverage coverage.json --cost cost.json \\
        --keyring-dir keys/ --out pov.html [--json pov.json]

    # end-to-end demonstration on the synthetic lab corpus
    python -m aegis.reports lab --out pov-lab.html [--seed 7 --devices 120 --days 3]

``coverage.json`` holds :class:`~aegis.reports.inputs.CoverageStats` fields;
``cost.json`` holds :class:`~aegis.reports.inputs.CostInputs` fields; ``effort.json``
holds :class:`~aegis.reports.inputs.AnalystEffortModel` parameters. The keyring
directory contains ``<key_id>.pem`` public keys trusted for ledger signatures.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing
from aegis.reports.inputs import AnalystEffortModel, CostInputs, CoverageStats, ReportPeriod
from aegis.reports.pov import collect_pov_report, render_pov_html
from aegis.storage.db import DocStore, make_engine, make_session_factory


def parse_when(value: str) -> datetime:
    """ISO date or datetime; naive values are taken as UTC."""
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def load_keyring(directory: str | Path) -> KeyRing:
    ring = KeyRing()
    d = Path(directory)
    pems = sorted(d.glob("*.pem"))
    if not pems:
        raise SystemExit(f"no *.pem public keys in {d}")
    for pem in pems:
        ring.add(pem.stem, pem.read_bytes())
    return ring


def _read_json(path: str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"{path} must contain a JSON object")
    return data


def _write(out: str, html: str, json_out: str | None, payload: dict[str, Any]) -> None:
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(html, encoding="utf-8")
    if json_out:
        Path(json_out).write_text(json.dumps(payload, indent=1, sort_keys=True, default=str), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.reports", description="AEGIS shadow proof-of-value report")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("render", help="render from a deployment database")
    r.add_argument("--db", default=None, help="database URL (default: $AEGIS_DATABASE_URL)")
    r.add_argument("--tenant", required=True)
    r.add_argument("--start", required=True, type=parse_when)
    r.add_argument("--end", required=True, type=parse_when)
    r.add_argument("--coverage", help="CoverageStats JSON file")
    r.add_argument("--cost", help="CostInputs JSON file")
    r.add_argument("--effort", help="AnalystEffortModel JSON file")
    r.add_argument("--keyring-dir", help="directory of trusted ledger public keys (<key_id>.pem)")
    r.add_argument("--budget", type=float, default=None, help="agreed false alerts per 10k device-days")
    r.add_argument("--operator", default=None, help="operator name shown on the cover")
    r.add_argument("--top-cases", type=int, default=5)
    r.add_argument("--out", required=True)
    r.add_argument("--json", default=None, help="also write the report content as JSON")

    lab = sub.add_parser("lab", help="end-to-end demonstration on the synthetic lab corpus")
    lab.add_argument("--seed", type=int, default=7)
    lab.add_argument("--devices", type=int, default=120)
    lab.add_argument("--days", type=int, default=3)
    lab.add_argument("--malicious-fraction", type=float, default=0.08)
    lab.add_argument("--no-model", action="store_true", help="rules-only Sentinel (no supervised model)")
    lab.add_argument("--cost", help="CostInputs JSON file")
    lab.add_argument("--budget", type=float, default=25.0)
    lab.add_argument("--operator", default="Lab demonstration (synthetic data)")
    lab.add_argument("--out", required=True)
    lab.add_argument("--json", default=None)

    args = ap.parse_args(argv)
    cost_d = _read_json(args.cost)
    cost = CostInputs.from_dict(cost_d) if cost_d else None

    if args.cmd == "render":
        sf = make_session_factory(make_engine(args.db))
        cov_d = _read_json(args.coverage)
        eff_d = _read_json(args.effort)
        pov = collect_pov_report(
            args.tenant, DocStore(sf), Ledger(sf), ReportPeriod(args.start, args.end),
            keyring=load_keyring(args.keyring_dir) if args.keyring_dir else None,
            coverage=CoverageStats.from_dict(cov_d) if cov_d else None, cost=cost,
            effort=AnalystEffortModel.from_dict(eff_d) if eff_d else None,
            false_alert_budget_per_10k=args.budget, operator_name=args.operator, top_cases=args.top_cases)
    else:
        from aegis.reports.lab import LAB_LABEL_SOURCE, run_lab_pilot
        from aegis.sentinel.model import load_default
        pilot = run_lab_pilot(seed=args.seed, n_devices=args.devices, days=args.days,
                              malicious_fraction=args.malicious_fraction,
                              model=None if args.no_model else load_default())
        pov = collect_pov_report(
            pilot.tenant_id, pilot.docstore, pilot.ledger, pilot.period, keyring=pilot.keyring,
            coverage=pilot.coverage, cost=cost, onsets=pilot.onsets, ground_truth=pilot.ground_truth,
            ground_truth_source=LAB_LABEL_SOURCE, false_alert_budget_per_10k=args.budget,
            operator_name=args.operator)
    _write(args.out, render_pov_html(pov), args.json, pov.model_dump(mode="json", by_alias=True))
    print(json.dumps({"out": args.out, "fingerprint": pov.fingerprint, "alerts": pov.alerts.alerts,
                      "ledger_ok": pov.ledger.ok, "attestation": pov.attestation.status}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
