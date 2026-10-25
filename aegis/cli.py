"""``aegis`` command line.

    aegis demo                       lab corpus -> model -> detection -> cases -> API on 127.0.0.1:8000
    aegis serve                      run the API (configuration from AEGIS_* environment variables)
    aegis token --role analyst ...   mint a dev-mode bearer token (AEGIS_AUTH_MODE=dev only)
    aegis sources add|list           register / list authorized telemetry sources of a tenant
    aegis ingest FILE --source ID    ingest a collector file into a tenant and run detection
    aegis train                      train the SENTINEL model on the lab corpus
    aegis benchmark                  run the independent benchmark harness (source checkout)
    aegis report --tenant T          render the shadow proof-of-value report
    aegis keys generate              create an Ed25519 key pair (optionally trusted by this deployment)
    aegis keys revoke                permanently distrust a policy / IOC / ledger key (compromise response)
    aegis policy sign                sign an operator policy JSON with a private key
    aegis ledger verify --tenant T   verify a tenant's hash chain and signatures
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from aegis.api.settings import Settings, SettingsError

DEMO_MARKER = ".aegis-demo"


def _err(msg: str) -> int:
    print(f"aegis: error: {msg}", file=sys.stderr)
    return 2


def _when(value: str) -> datetime:
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _settings(args: argparse.Namespace, **overrides: Any) -> Settings:
    if getattr(args, "data_dir", None):
        overrides.setdefault("data_dir", Path(args.data_dir))
    return Settings.from_env(**overrides)


def _service(settings: Settings, *, load_model: bool = True) -> Any:
    from aegis.service import AegisService
    return AegisService(settings, load_default_model=load_model)


# ============================================================================ demo


def _prepare_demo_dir(path: Path, force: bool) -> None:
    if path.exists() and any(path.iterdir()):
        if not (path / DEMO_MARKER).exists() and not force:
            raise SystemExit(_err(f"{path} exists and is not an AEGIS demo directory; pass --force or choose "
                                  "another --data-dir"))
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)
    (path / DEMO_MARKER).write_text("created by `aegis demo`; deleted and recreated on every demo run\n")


def _demo_model(args: argparse.Namespace, data_dir: Path) -> Any:
    from aegis.sentinel.model import load_default
    if not args.train:
        try:
            model = load_default()
            print(f"[demo] loaded shipped detection model {model.model_id}")
            return model
        except Exception as exc:  # missing or tampered model: train a fresh one
            print(f"[demo] shipped model unavailable ({type(exc).__name__}); training a new one")
    from aegis.sentinel.training import train_lab_model
    print("[demo] training the SENTINEL model on independent lab corpora (time-forward, group-isolated split)")
    model = train_lab_model(workers=max(1, min(8, os.cpu_count() or 1)))
    out = model.save(data_dir / "model")
    print(f"[demo] trained model {model.model_id} saved to {out}")
    return model


def cmd_demo(args: argparse.Namespace) -> int:
    from aegis.api.auth import ALL_ROLES, mint_dev_token
    from aegis.api.demo import seed_lab_demo
    from aegis.service import AegisService

    data_dir = Path(args.data_dir).resolve()
    _prepare_demo_dir(data_dir, args.force)
    try:
        settings = Settings.from_env(env="development", auth_mode="dev", data_dir=data_dir,
                                     database_url=f"sqlite:///{data_dir / 'aegis.db'}", demo_tenant=args.tenant,
                                     log_format=args.log_format)
    except SettingsError as exc:
        return _err(str(exc))
    from aegis.api.logs import configure_logging
    configure_logging(settings.log_level, settings.log_format)
    model = _demo_model(args, data_dir)
    service = AegisService(settings, model=model)
    summary = seed_lab_demo(service, tenant_id=args.tenant, seed=args.seed, n_devices=args.devices, days=args.days,
                            leave_open=args.leave_open, log=lambda m: print(f"[demo] {m}", flush=True))
    ledger = service.verify_ledger(args.tenant)
    print("\n" + "=" * 78)
    print("AEGIS OMEGA SHIELD demo ready (synthetic lab data, shadow mode: nothing is ever blocked)")
    print("=" * 78)
    print(f"tenant            {summary.tenant_id}")
    print(f"period            {summary.period_start:%Y-%m-%d} .. {summary.period_end:%Y-%m-%d} UTC")
    print(f"devices           {summary.devices} ({summary.malicious_devices} emulated compromised)")
    print(f"telemetry events  {summary.events}")
    print(f"findings          {summary.findings} ({summary.alerts} alerts)")
    print(f"cases             {summary.cases}  {json.dumps(summary.dispositions)}")
    print(f"open for live demo {len(summary.open_case_ids)} case(s) in INVESTIGATING")
    print(f"operator policy   {summary.policy_id} (shadow mode: enforcement is refused by design)")
    print(f"ledger            {'verified' if ledger['ok'] else 'FAILED'} ({ledger['entry_count']} signed entries)")
    host_for_url = "localhost" if args.host in ("0.0.0.0", "::") else args.host
    base = f"http://{host_for_url}:{args.port}"
    print(f"\nconsole           {base}/")
    print(f"API docs          {base}/api/v1/docs")
    print(f"PoV report        {base}/api/v1/reports/pov  (bearer token required)")
    print("\nDev login tokens (valid "
          f"{settings.dev_token_ttl_s // 3600} h; also available at {base}/api/v1/demo/token?role=<role>):")
    tokens = {}
    for role in ALL_ROLES:
        tokens[role.value] = mint_dev_token(settings, sub=f"demo-{role.value}", tenant_id=args.tenant,
                                            roles=[role.value])
        print(f"  {role.value:<12} {tokens[role.value]}")
    (data_dir / "demo_tokens.json").write_text(json.dumps(tokens, indent=1))
    print(f"\n(tokens also written to {data_dir / 'demo_tokens.json'})")
    if args.no_serve:
        return 0
    from aegis.api.app import create_app
    app = create_app(settings, service=service)
    return _run_uvicorn(app, args.host, args.port)


def _run_uvicorn(app: Any, host: str, port: int) -> int:
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_config=None, access_log=False, proxy_headers=True,
                forwarded_allow_ips=os.environ.get("AEGIS_FORWARDED_ALLOW_IPS", "127.0.0.1"))
    return 0


# ============================================================================ serve / token


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        settings = _settings(args)
    except SettingsError as exc:
        return _err(str(exc))
    from aegis.api.app import create_app
    return _run_uvicorn(create_app(settings), args.host, args.port)


def cmd_token(args: argparse.Namespace) -> int:
    from aegis.api.auth import AuthError, mint_dev_token
    try:
        settings = _settings(args)
        token = mint_dev_token(settings, sub=args.sub, tenant_id=args.tenant, roles=args.role, ttl_s=args.ttl)
    except (SettingsError, AuthError, ValueError) as exc:
        return _err(str(exc))
    print(token)
    return 0


# ============================================================================ sources / ingest


def cmd_sources(args: argparse.Namespace) -> int:
    from aegis.service import ServiceError
    try:
        svc = _service(_settings(args), load_model=False)
        if args.sources_cmd == "add":
            cfg = svc.register_source(args.tenant, args.actor, source_id=args.source_id, source_kind=args.kind,
                                      vantage=args.vantage, collection_authorization_id=args.authorization,
                                      retention_days=args.retention_days, format=args.format,
                                      entity_field=args.entity_field,
                                      subscriber_prefixes=args.subscriber_prefix or (),
                                      flow_direction=args.flow_direction)
            print(json.dumps(cfg.model_dump(mode="json"), indent=1))
        else:
            print(json.dumps([c.model_dump(mode="json") for c in svc.list_sources(args.tenant)], indent=1))
    except (SettingsError, ServiceError) as exc:
        return _err(str(exc))
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from aegis.service import ServiceError
    path = Path(args.file)
    if not path.is_file():
        return _err(f"no such file: {path}")
    try:
        svc = _service(_settings(args))
        outcome = svc.ingest_files(args.tenant, [(path, args.source)],
                                   flush_at=_when(args.flush_until) if args.flush_until else None)
    except (SettingsError, ServiceError) as exc:
        return _err(str(exc))
    print(json.dumps(outcome.summary(), indent=1, default=str))
    return 0


# ============================================================================ train / benchmark / report


def cmd_train(args: argparse.Namespace, rest: list[str]) -> int:
    from aegis.sentinel.training import main as train_main
    return train_main(rest)


def cmd_benchmark(args: argparse.Namespace, rest: list[str]) -> int:
    # the harness lives in the source checkout (eval/), next to the aegis package or in the CWD
    for root in (Path.cwd(), Path(__file__).resolve().parents[1]):
        if (root / "eval" / "run_benchmark.py").is_file() and str(root) not in sys.path:
            sys.path.insert(0, str(root))
    try:
        from eval.run_benchmark import main as bench_main  # type: ignore[import-not-found]
    except ImportError:
        return _err("the benchmark harness (eval/) is only available in a source checkout; run from the repo root")
    return bench_main(rest)


def cmd_report(args: argparse.Namespace) -> int:
    from aegis.service import ServiceError
    if (args.start is None) != (args.end is None):
        return _err("give both --start and --end, or neither")
    try:
        svc = _service(_settings(args), load_model=False)
        out = svc.pov_report(args.tenant, start=_when(args.start) if args.start else None,
                             end=_when(args.end) if args.end else None, operator_name=args.operator,
                             false_alert_budget_per_10k=args.budget, fmt=args.format)
    except (SettingsError, ServiceError) as exc:
        return _err(str(exc))
    text = out if isinstance(out, str) else json.dumps(out, indent=1, default=str)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    print(args.out)
    return 0


# ============================================================================ keys / policy / ledger


def cmd_keys(args: argparse.Namespace) -> int:
    if args.keys_cmd == "revoke":
        return cmd_keys_revoke(args)
    from aegis.provenance.signing import Signer
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv, pub = out / f"{args.key_id}.key.pem", out / f"{args.key_id}.pem"
    if priv.exists() and not args.overwrite:
        return _err(f"{priv} exists (pass --overwrite to replace it)")
    signer = Signer.generate(args.key_id)
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(signer.private_pem())
    pub.write_bytes(signer.public_pem())
    result: dict[str, Any] = {"key_id": args.key_id, "private_key": str(priv), "public_key": str(pub),
                              "fingerprint": signer.fingerprint()}
    if args.trust:
        from aegis.service import ServiceError
        try:
            svc = _service(_settings(args), load_model=False)
            svc.trust_key(args.trust, args.key_id, signer.public_pem())
        except (SettingsError, ServiceError) as exc:
            return _err(str(exc))
        result["trusted_as"] = args.trust
    print(json.dumps(result, indent=1))
    return 0


def cmd_keys_revoke(args: argparse.Namespace) -> int:
    """Revoke a trusted key. A running API applies it within one sweep interval (default 60 s)."""
    from aegis.service import ServiceError
    try:
        svc = _service(_settings(args), load_model=False)
        out = svc.revoke_key(args.kind, args.key_id, actor=args.actor, reason=args.reason)
    except (SettingsError, ServiceError) as exc:
        return _err(str(exc))
    print(json.dumps(out, indent=1))
    return 0


def cmd_policy_sign(args: argparse.Namespace) -> int:
    from aegis.contracts.models import OperatorPolicy
    from aegis.provenance.signing import Signer, sign_model
    try:
        data = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        data.setdefault("signature", "")
        data["signer_key_id"] = args.key_id
        policy = OperatorPolicy.model_validate(data)
        signer = Signer.from_private_pem(args.key_id, Path(args.key).read_bytes())
    except (OSError, ValueError) as exc:
        return _err(f"cannot sign policy: {exc}")
    signed = sign_model(policy, signer).model_dump(mode="json")
    text = json.dumps(signed, indent=1)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(args.out)
    else:
        print(text)
    return 0


def cmd_ledger_verify(args: argparse.Namespace) -> int:
    try:
        svc = _service(_settings(args), load_model=False)
    except SettingsError as exc:
        return _err(str(exc))
    report = svc.verify_ledger(args.tenant)
    print(json.dumps(report, indent=1, default=str))
    return 0 if report["ok"] else 1


# ============================================================================ parser


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="aegis", description="AEGIS OMEGA SHIELD")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def data_dir(p: argparse.ArgumentParser) -> None:
        p.add_argument("--data-dir", default=None, help="data directory (default: $AEGIS_DATA_DIR or ./aegis-data)")

    d = sub.add_parser("demo", help="one-command demonstration on synthetic lab data")
    d.add_argument("--host", default="127.0.0.1",
                   help="bind address (default loopback: the demo hands out tokens without credentials)")
    d.add_argument("--port", type=int, default=8000)
    d.add_argument("--data-dir", default=".aegis-demo", help="demo data directory (recreated on every run)")
    d.add_argument("--force", action="store_true", help="allow replacing a non-demo --data-dir")
    d.add_argument("--tenant", default="demo")
    d.add_argument("--devices", type=int, default=120)
    d.add_argument("--days", type=int, default=3)
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--leave-open", type=int, default=4, help="confirmed cases left INVESTIGATING for a live demo")
    d.add_argument("--train", action="store_true", help="train a fresh model instead of loading the shipped one")
    d.add_argument("--no-serve", action="store_true", help="seed and print tokens, then exit")
    d.add_argument("--log-format", choices=("json", "text"), default="text")

    s = sub.add_parser("serve", help="run the API")
    s.add_argument("--host", default="127.0.0.1", help="bind address (pass 0.0.0.0 explicitly to expose it)")
    s.add_argument("--port", type=int, default=8000)
    data_dir(s)

    t = sub.add_parser("token", help="mint a dev-mode token")
    t.add_argument("--role", action="append", required=True,
                   choices=("viewer", "analyst", "approver", "admin", "integration"))
    t.add_argument("--tenant", required=True)
    t.add_argument("--sub", default="dev-user")
    t.add_argument("--ttl", type=int, default=None, help="lifetime in seconds")
    data_dir(t)

    so = sub.add_parser("sources", help="manage telemetry sources")
    so_sub = so.add_subparsers(dest="sources_cmd", required=True)
    sa = so_sub.add_parser("add")
    sa.add_argument("--tenant", required=True)
    sa.add_argument("--source-id", required=True)
    sa.add_argument("--kind", required=True, choices=("netflow", "dns", "zeek_conn", "zeek_dns", "cpe"))
    sa.add_argument("--vantage", required=True, choices=("subscriber_line", "device"))
    sa.add_argument("--authorization", required=True, help="collection authorization id")
    sa.add_argument("--retention-days", type=int, default=30)
    sa.add_argument("--format", default=None)
    sa.add_argument("--entity-field", default="auto", choices=("auto", "device_id", "src_ip"))
    sa.add_argument("--subscriber-prefix", action="append", default=None, metavar="CIDR",
                    help="subscriber address space (repeatable); flows from other sources are skipped")
    sa.add_argument("--flow-direction", default="auto", choices=("auto", "biflow", "uniflow"),
                    help="whether the exporter's reverse byte/packet counters are real (biflow)")
    sa.add_argument("--actor", default="cli:operator")
    data_dir(sa)
    sl = so_sub.add_parser("list")
    sl.add_argument("--tenant", required=True)
    data_dir(sl)

    i = sub.add_parser("ingest", help="ingest a collector file")
    i.add_argument("file")
    i.add_argument("--source", required=True)
    i.add_argument("--tenant", required=True)
    i.add_argument("--flush-until", default=None, help="close detection windows up to this ISO time")
    data_dir(i)

    sub.add_parser("train", help="train the SENTINEL model (arguments are passed to the trainer)", add_help=False)
    sub.add_parser("benchmark", help="run the benchmark harness (arguments are passed through)", add_help=False)

    r = sub.add_parser("report", help="render the proof-of-value report")
    r.add_argument("--tenant", required=True)
    r.add_argument("--start", default=None)
    r.add_argument("--end", default=None)
    r.add_argument("--format", choices=("html", "json"), default="html")
    r.add_argument("--operator", default=None)
    r.add_argument("--budget", type=float, default=None, help="agreed false alerts per 10k device-days")
    r.add_argument("--out", required=True)
    data_dir(r)

    k = sub.add_parser("keys", help="key management")
    k_sub = k.add_subparsers(dest="keys_cmd", required=True)
    kg = k_sub.add_parser("generate")
    kg.add_argument("--key-id", required=True)
    kg.add_argument("--out-dir", required=True)
    kg.add_argument("--trust", choices=("policy", "ioc", "ledger", "model"), default=None,
                    help="also trust the public key in this deployment")
    kg.add_argument("--overwrite", action="store_true")
    data_dir(kg)
    kr = k_sub.add_parser("revoke", help="permanently distrust a key (persisted, ledgered in every tenant)")
    kr.add_argument("--kind", required=True, choices=("policy", "ioc", "ledger", "model"))
    kr.add_argument("--key-id", required=True)
    kr.add_argument("--reason", required=True)
    kr.add_argument("--actor", default=os.environ.get("USER", "cli:operator"))
    data_dir(kr)

    p = sub.add_parser("policy", help="operator policies")
    p_sub = p.add_subparsers(dest="policy_cmd", required=True)
    ps = p_sub.add_parser("sign")
    ps.add_argument("policy", help="policy JSON (OperatorPolicy fields)")
    ps.add_argument("--key", required=True, help="private key PEM")
    ps.add_argument("--key-id", required=True)
    ps.add_argument("--out", default=None)

    lg = sub.add_parser("ledger", help="provenance ledger")
    lg_sub = lg.add_subparsers(dest="ledger_cmd", required=True)
    lv = lg_sub.add_parser("verify")
    lv.add_argument("--tenant", required=True)
    data_dir(lv)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("train", "benchmark"):
        ns = argparse.Namespace(cmd=argv[0])
        return cmd_train(ns, argv[1:]) if argv[0] == "train" else cmd_benchmark(ns, argv[1:])
    args = build_parser().parse_args(argv)
    handlers = {
        "demo": cmd_demo, "serve": cmd_serve, "token": cmd_token, "sources": cmd_sources, "ingest": cmd_ingest,
        "report": cmd_report, "keys": cmd_keys,
        "policy": cmd_policy_sign, "ledger": cmd_ledger_verify,
    }
    return handlers[args.cmd](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
