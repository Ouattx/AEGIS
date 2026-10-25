"""``python -m aegis.lab --out DIR`` — generate the lab corpus and write raw files."""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone

from aegis.lab.corpus import DEFAULT_START, generate_corpus


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.lab", description=__doc__)
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--days", type=int, default=3)
    ap.add_argument("--devices", type=int, default=200)
    ap.add_argument("--malicious-fraction", type=float, default=0.08)
    ap.add_argument("--tenant", default="demo")
    ap.add_argument("--start", default=DEFAULT_START.isoformat(), help="RFC 3339 start (UTC)")
    ap.add_argument("--no-zeek", action="store_true", help="skip Zeek conn/dns logs")
    args = ap.parse_args(argv)
    start = datetime.fromisoformat(args.start)
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    t0 = time.perf_counter()
    corpus = generate_corpus(seed=args.seed, days=args.days, n_devices=args.devices,
                             malicious_fraction=args.malicious_fraction, tenant_id=args.tenant, start=start)
    paths = corpus.write_raw(args.out, zeek=not args.no_zeek)
    summary = corpus.summary()
    summary["elapsed_s"] = round(time.perf_counter() - t0, 2)
    summary["files"] = {k: str(v) for k, v in paths.items()}
    json.dump(summary, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
