"""Command line for the AEGIS home lab: ``python -m aegis.homelab <command>``.

Commands
    analyze CAPTURE_DIR --out DIR   import + single-home analysis + Box Lab report(s)
    synthetic DIR                   write a SYNTHETIC demo capture (fictional device)
    dnsmasq-to-jsonl LOG            convert a dnsmasq query log to AEGIS DNS JSONL (stdout)
    verify DIR                      re-verify the signed ledger of a previous ``analyze`` run
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Sequence

from aegis.homelab.config import DEFAULT_GATEWAY, DEFAULT_LAB_SUBNET, HomeLabConfig
from aegis.homelab.crowd import CrowdMixConfig
from aegis.homelab.dnsmasq import dnsmasq_to_jsonl
from aegis.homelab.infra import load_local_list
from aegis.homelab.run import run_homelab, verify_run
from aegis.homelab.synthetic import SyntheticBoxSpec, write_synthetic_capture
from aegis.homelab.usage import UsageWindows, load_usage_windows
from aegis.provenance.signing import KeyRing
from aegis.sentinel.rules import BundleError, load_bundle


def _labels(items: Sequence[str]) -> dict[str, str]:
    out = {}
    for item in items:
        ip, sep, label = item.partition("=")
        if not sep:
            raise SystemExit(f"--label expects IP=NAME, got {item!r}")
        out[ip.strip()] = label.strip()
    return out


def _cmd_analyze(ns: argparse.Namespace) -> int:
    cfg = HomeLabConfig(lab_subnet=ns.subnet, gateway_ip=ns.gateway, device_labels=_labels(ns.label),
                        device_class=ns.device_class, dnsmasq_timezone=ns.dnsmasq_tz, dnsmasq_year=ns.dnsmasq_year,
                        include_local=ns.include_local)
    bundle = None
    if ns.ioc_bundle:
        if not (ns.ioc_pubkey and ns.ioc_key_id):
            raise SystemExit("--ioc-bundle needs --ioc-pubkey and --ioc-key-id (bundles are verified, fail closed)")
        ring = KeyRing()
        ring.add(ns.ioc_key_id, Path(ns.ioc_pubkey).read_bytes())
        try:
            bundle = load_bundle(Path(ns.ioc_bundle), ring)
        except BundleError as exc:
            raise SystemExit(f"IOC bundle refused: {exc}") from exc
    usage: UsageWindows | Literal["auto"] = load_usage_windows(ns.usage) if ns.usage else "auto"
    local = load_local_list(ns.local_list) if ns.local_list else ()
    crowd = CrowdMixConfig(n_copies=ns.crowd, n_lines=ns.crowd_lines, seed=ns.crowd_seed) if ns.crowd else None
    run = run_homelab(ns.capture, ns.out, cfg=cfg, usage=usage, bundle=bundle, local_list=local, crowd=crowd,
                      model=None if ns.no_model else "default")
    summary = {"events": len(run.capture.events), "devices": len(run.analysis.devices),
               "verdicts": {d.label: d.verdict.verdict.value for d in run.analysis.devices},
               "ledger": run.analysis.ledger, "reports": {k: str(v) for k, v in run.reports.items()},
               "synthetic": run.capture.synthetic}
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _cmd_synthetic(ns: argparse.Namespace) -> int:
    start = (datetime.fromisoformat(ns.start.replace("Z", "+00:00")) if ns.start
             else datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0))
    if start.tzinfo is None:
        raise SystemExit("--start needs a timezone (e.g. 2026-10-20T06:00:00Z)")
    sc = write_synthetic_capture(ns.dir, SyntheticBoxSpec(start=start, hours=ns.hours, seed=ns.seed,
                                                          beacon=not ns.no_beacon, nxdomain_burst=ns.nxdomain_burst))
    print(json.dumps({"directory": str(sc.directory), "synthetic": True, "truth": sc.truth}, indent=2))
    return 0


def _cmd_jsonl(ns: argparse.Namespace) -> int:
    sys.stdout.write(dnsmasq_to_jsonl(Path(ns.log), year=ns.year, tz=ns.tz))
    return 0


def _cmd_verify(ns: argparse.Namespace) -> int:
    res = verify_run(ns.dir)
    print(json.dumps(res, indent=2))
    return 0 if res["verified"] else 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="python -m aegis.homelab", description="AEGIS home lab (one device, at home)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="import a capture and write Box Lab report(s)")
    a.add_argument("capture", help="capture directory (capture.json, zeek/*.log, dnsmasq*.log, usage.json)")
    a.add_argument("--out", required=True, help="output directory (reports, ledger database, lab keys)")
    a.add_argument("--subnet", default=DEFAULT_LAB_SUBNET)
    a.add_argument("--gateway", default=DEFAULT_GATEWAY)
    a.add_argument("--label", action="append", default=[], metavar="IP=NAME", help="name a lab device")
    a.add_argument("--device-class", default=None, help="SENTINEL baseline hint (never used as evidence)")
    a.add_argument("--usage", help="usage windows JSON/CSV (default: usage.json in the capture, if any)")
    a.add_argument("--ioc-bundle", help="signed AEGIS IOC bundle (aegis.ioc_bundle/1)")
    a.add_argument("--ioc-pubkey", help="PEM public key of the bundle signer")
    a.add_argument("--ioc-key-id", help="key id of the bundle signer")
    a.add_argument("--local-list", help="plain-text list of domains/IPs (unverified, orientation only)")
    a.add_argument("--crowd", type=int, default=0, metavar="N", help="crowd mixing: N copies (MIXED-SYNTHETIC)")
    a.add_argument("--crowd-lines", type=int, default=600, help="simulated background lines for crowd mixing")
    a.add_argument("--crowd-seed", type=int, default=7)
    a.add_argument("--dnsmasq-tz", default=None,
                   help="timezone of dnsmasq log timestamps (default: capture.json, else UTC)")
    a.add_argument("--dnsmasq-year", type=int, default=None, help="year of the first dnsmasq log line")
    a.add_argument("--include-local", action="store_true", help="analyze lab-local/multicast flows too")
    a.add_argument("--no-model", action="store_true", help="run SENTINEL without its model (rules/anomaly only)")
    a.set_defaults(fn=_cmd_analyze)
    s = sub.add_parser("synthetic", help="write a SYNTHETIC demo capture of a fictional box")
    s.add_argument("dir")
    s.add_argument("--start", help="capture start (ISO 8601 with timezone); default: this hour")
    s.add_argument("--hours", type=float, default=24.0)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--no-beacon", action="store_true", help="omit the emulated C2 beacon")
    s.add_argument("--nxdomain-burst", action="store_true")
    s.set_defaults(fn=_cmd_synthetic)
    j = sub.add_parser("dnsmasq-to-jsonl", help="convert a dnsmasq log to DNS JSONL on stdout")
    j.add_argument("log")
    j.add_argument("--year", type=int, required=True)
    j.add_argument("--tz", default="UTC")
    j.set_defaults(fn=_cmd_jsonl)
    v = sub.add_parser("verify", help="re-verify the ledger of an analyze run")
    v.add_argument("dir")
    v.set_defaults(fn=_cmd_verify)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    return int(ns.fn(ns))


__all__ = ["build_parser", "main"]
