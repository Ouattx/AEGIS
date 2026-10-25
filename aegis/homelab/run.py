"""One call from a capture directory to Box Lab reports.

``run_homelab`` = import (single-home sources) + local provenance store + single-home
analysis + optional crowd mixing + HTML/JSON reports. Lab keys live in
``<out>/keys/`` with owner-only permissions:

* ``pseudonym.key``: the tenant pseudonymization key (hex). Reusing it keeps device
  pseudonyms stable across captures of the same lab;
* ``ledger.pem``: the Ed25519 key that signs the lab ledger (re-verify with
  ``python -m aegis.homelab verify <out>``).
"""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Sequence

from aegis.homelab.analysis import HomeLabAnalysis, analyze_single_home
from aegis.homelab.config import HomeLabConfig
from aegis.homelab.crowd import CrowdMixConfig, crowd_mix
from aegis.homelab.importer import CaptureImport, discover_capture, import_capture
from aegis.homelab.report import write_reports
from aegis.homelab.store import LAB_LEDGER_KEY_ID, open_lab_store
from aegis.homelab.usage import UsageWindows, load_usage_windows
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.provenance.signing import Signer
from aegis.sentinel.model import TrainedModel
from aegis.sentinel.rules import IOCBundle

DB_NAME = "homelab-ledger.db"


@dataclass
class HomeLabRun:
    capture: CaptureImport
    analysis: HomeLabAnalysis
    reports: dict[str, Path]
    out_dir: Path


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def lab_keys(out_dir: str | Path) -> tuple[Pseudonymizer, Signer]:
    """Load (or create once) the lab pseudonym key and ledger signing key under ``<out>/keys``."""
    keys = Path(out_dir) / "keys"
    pk = keys / "pseudonym.key"
    if not pk.exists():
        _write_secret(pk, secrets.token_hex(32).encode())
    pseudo = Pseudonymizer(bytes.fromhex(pk.read_text().strip()))
    lk = keys / "ledger.pem"
    if not lk.exists():
        _write_secret(lk, Signer.generate(LAB_LEDGER_KEY_ID).private_pem())
    signer = Signer.from_private_pem(LAB_LEDGER_KEY_ID, lk.read_bytes())
    return pseudo, signer


def run_homelab(capture_dir: str | Path, out_dir: str | Path, *, cfg: HomeLabConfig | None = None,
                usage: UsageWindows | None | Literal["auto"] = "auto", bundle: IOCBundle | None = None,
                local_list: Sequence[str] = (), crowd: CrowdMixConfig | None = None,
                model: TrainedModel | None | Literal["default"] = "default") -> HomeLabRun:
    """Import, analyze and report. ``usage="auto"`` loads ``usage.json`` / ``usage.csv`` from the capture."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pseudo, signer = lab_keys(out)
    paths = discover_capture(capture_dir)
    if usage == "auto":
        usage = load_usage_windows(paths.usage) if paths.usage is not None else None
    imp = import_capture(paths, cfg or HomeLabConfig(), pseudonymizer=pseudo)
    store = open_lab_store(out / DB_NAME, signer=signer)
    try:
        analysis = analyze_single_home(imp, usage=usage, bundle=bundle, local_list=local_list, store=store,
                                       model=model)
    finally:
        store.close()
    if crowd is not None and analysis.devices:
        target = max(analysis.devices, key=lambda d: d.n_events)
        analysis.crowd = crowd_mix(imp.events_for(target.entity_pseudonym), start=imp.start, end=imp.end, cfg=crowd)
    reports = write_reports(analysis, out)
    (out / "run.json").write_text(json.dumps({"tenant_id": imp.cfg.tenant_id, "database": DB_NAME,
                                              "ledger_key_id": signer.key_id,
                                              "reports": {k: v.name for k, v in reports.items()}}, indent=2) + "\n",
                                  encoding="utf-8")
    return HomeLabRun(capture=imp, analysis=analysis, reports=reports, out_dir=out)


def verify_run(out_dir: str | Path) -> dict[str, object]:
    """Re-verify the signed ledger chain of a previous run."""
    out = Path(out_dir)
    meta = json.loads((out / "run.json").read_text(encoding="utf-8"))
    signer = Signer.from_private_pem(meta["ledger_key_id"], (out / "keys" / "ledger.pem").read_bytes())
    store = open_lab_store(out / meta["database"], signer=signer)
    try:
        return store.verify(meta["tenant_id"])
    finally:
        store.close()


__all__ = ["DB_NAME", "HomeLabRun", "lab_keys", "run_homelab", "verify_run"]
