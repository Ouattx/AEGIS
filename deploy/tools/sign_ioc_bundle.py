#!/usr/bin/env python3
"""Sign (or verify) an AEGIS IOC bundle with an operator Ed25519 key.

AEGIS only activates IOC bundles signed by a key the deployment trusts
(``<data dir>/trusted/ioc/<key_id>.pem``). Operators who curate their own feed sign
each new bundle version offline with this tool, then upload it with
``POST /api/v1/iocs`` (admin role)::

    # once: create the signing key pair on the operator's signing workstation
    aegis keys generate --key-id op-ioc-2026 --out-dir ./operator-keys

    # each release of the feed
    python sign_ioc_bundle.py sign feed.json --key ./operator-keys/op-ioc-2026.key.pem \\
        --key-id op-ioc-2026 --out feed.signed.json
    python sign_ioc_bundle.py verify feed.signed.json --public-key ./operator-keys/op-ioc-2026.pem

In the container image the tool is at ``/opt/aegis/tools/sign_ioc_bundle.py``.
The bundle is validated with the same parser AEGIS uses at load time, so a bundle that
signs here also loads there (schema, timestamps, unique indicator ids, signature).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.rules import BundleError, IOCBundle, bundle_signing_bytes, load_bundle


def sign_bundle_dict(bundle: dict[str, Any], signer: Signer) -> dict[str, Any]:
    """Return a signed copy of ``bundle`` (``signer_key_id`` and ``signature`` set)."""
    out = {k: v for k, v in bundle.items() if k != "signature"}
    out["signer_key_id"] = signer.key_id
    out["signature"] = signer.sign(bundle_signing_bytes(out))
    return out


def verify_bundle_dict(bundle: dict[str, Any], key_id: str, public_pem: bytes) -> IOCBundle:
    """Parse and verify ``bundle`` exactly as AEGIS does; raises ``BundleError``."""
    ring = KeyRing()
    ring.add(key_id, public_pem)
    return load_bundle(bundle, ring)


def _summary(b: IOCBundle) -> dict[str, Any]:
    return {"bundle_id": b.bundle_id, "version": b.version, "issuer": b.issuer,
            "issued_at": b.issued_at.isoformat(), "signer_key_id": b.signer_key_id,
            "indicators": len(b.indicators), "sha256": b.sha256}


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise BundleError("bundle must be a JSON object")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sign_ioc_bundle", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sign", help="sign a bundle and check it loads")
    s.add_argument("bundle", type=Path)
    s.add_argument("--key", type=Path, required=True, help="private key PEM (from `aegis keys generate`)")
    s.add_argument("--key-id", required=True)
    s.add_argument("--out", type=Path, required=True)
    v = sub.add_parser("verify", help="verify a signed bundle against a public key")
    v.add_argument("bundle", type=Path)
    v.add_argument("--public-key", type=Path, required=True)
    v.add_argument("--key-id", default=None, help="defaults to the bundle's signer_key_id")
    args = ap.parse_args(argv)

    try:
        bundle = _read_json(args.bundle)
        if args.cmd == "sign":
            signer = Signer.from_private_pem(args.key_id, args.key.read_bytes())
            signed = sign_bundle_dict(bundle, signer)
            parsed = verify_bundle_dict(signed, signer.key_id, signer.public_pem())
            args.out.write_text(json.dumps(signed, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        else:
            key_id = args.key_id or bundle.get("signer_key_id")
            if not isinstance(key_id, str) or not key_id:
                raise BundleError("bundle has no signer_key_id; pass --key-id")
            parsed = verify_bundle_dict(bundle, key_id, args.public_key.read_bytes())
    except (OSError, ValueError) as exc:  # BundleError and JSON errors are ValueErrors
        print(f"sign_ioc_bundle: error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **_summary(parsed)}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
