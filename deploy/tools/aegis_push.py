#!/usr/bin/env python3
"""Push collector export files to the AEGIS ingest API (``POST /api/v1/ingest``).

Typical use on a collector host, from cron or a systemd timer, right after the exporter
rotates a file (nfdump, resolver log, Zeek log, CPE agent batch)::

    AEGIS_TOKEN_FILE=/etc/aegis/push.token \\
    python3 aegis_push.py --api https://aegis.operator.example --source gw-netflow \\
        --done-dir /var/spool/aegis/done /var/spool/aegis/netflow/*.csv

What it does
  * splits large files into chunks below ``--max-bytes`` on record boundaries, repeating
    the CSV header or the Zeek ``#`` header block in every chunk (JSON documents are sent
    whole); ``.gz`` files are read transparently;
  * retries 429 (honouring ``Retry-After``), 5xx and network errors with exponential
    backoff; any other 4xx stops immediately (wrong token, unknown source, bad format);
  * re-sending a chunk after a timeout is safe while the API process is up: the pipeline
    de-duplicates recently seen records by content hash (bounded in-memory window, not
    persisted across API restarts) and reports them as ``duplicates``;
  * with ``--flush`` the last chunk closes detection windows up to its last event
    (use it for backfills or when a source goes quiet);
  * moves fully accepted files to ``--done-dir`` so the next run does not resend them.

Authentication: a static bearer token (``--token-file`` / ``AEGIS_TOKEN_FILE`` /
``AEGIS_TOKEN``) or OIDC client credentials (``--oidc-token-url``, ``--client-id``,
``--client-secret-file``) for a service account holding only the ``integration`` role.

Exit status: 0 all files accepted, 1 a file failed (later files are still attempted),
2 usage error. One JSON line per chunk is printed for the operator's log.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Literal, Sequence

import httpx

FileKind = Literal["csv", "jsonl", "zeek", "json"]
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class PushError(RuntimeError):
    """A chunk was refused (non-retryable) or retries were exhausted."""


# ------------------------------------------------------------------------------- chunking


def detect_kind(path: Path, head: bytes) -> FileKind:
    """Guess the payload framing from the file name, then from its first bytes."""
    name = path.name.lower().removesuffix(".gz")
    if name.endswith(".csv"):
        return "csv"
    if name.endswith((".jsonl", ".ndjson")):
        return "jsonl"
    if name.endswith(".json"):
        return "json"
    if name.endswith(".log") and head.startswith(b"#separator"):
        return "zeek"
    stripped = head.lstrip()
    if head.startswith(b"#separator"):
        return "zeek"
    if stripped.startswith(b"{"):
        first_line = stripped.split(b"\n", 1)[0].strip()
        try:
            json.loads(first_line)
            return "jsonl"
        except ValueError:
            return "json"
    return "csv"


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as fh:
        magic = fh.read(2)
    if magic == b"\x1f\x8b":
        with gzip.open(path, "rb") as gz:
            return gz.read()
    return path.read_bytes()


def split_records(data: bytes, kind: FileKind, max_bytes: int) -> Iterator[bytes]:
    """Yield chunks of whole records, each at most ``max_bytes`` (header included).

    A single record larger than the budget is yielded alone (the server decides whether to
    accept or quarantine it) rather than being cut in the middle.
    """
    if max_bytes < 1024:
        raise ValueError("max_bytes must be at least 1024")
    if kind == "json":
        if data.strip():
            yield data
        return
    lines = data.splitlines(keepends=True)
    header: list[bytes] = []
    if kind == "csv":
        while lines and not lines[0].strip():
            lines.pop(0)
        if lines:
            header = [lines.pop(0)]
    elif kind == "zeek":
        while lines and lines[0].startswith(b"#") and not lines[0].startswith(b"#close"):
            header.append(lines.pop(0))
    head = b"".join(header)
    if head and not head.endswith(b"\n"):
        head += b"\n"
    budget = max_bytes - len(head)
    buf: list[bytes] = []
    size = 0
    for line in lines:
        if not line.strip() or (kind == "zeek" and line.startswith(b"#")):
            continue
        if not line.endswith(b"\n"):
            line += b"\n"
        if buf and size + len(line) > budget:
            yield head + b"".join(buf)
            buf, size = [], 0
        buf.append(line)
        size += len(line)
    if buf:
        yield head + b"".join(buf)


# ------------------------------------------------------------------------------- auth


@dataclass
class StaticToken:
    token: str

    def __call__(self, client: httpx.Client) -> str:
        return self.token


@dataclass
class ClientCredentials:
    """OAuth 2.0 client-credentials grant with in-memory caching until shortly before expiry."""
    token_url: str
    client_id: str
    client_secret: str
    scope: str | None = None
    clock: Callable[[], float] = time.monotonic
    _token: str | None = field(default=None, init=False, repr=False)
    _expires: float = field(default=0.0, init=False, repr=False)

    def __call__(self, client: httpx.Client) -> str:
        if self._token is not None and self.clock() < self._expires:
            return self._token
        form = {"grant_type": "client_credentials", "client_id": self.client_id,
                "client_secret": self.client_secret}
        if self.scope:
            form["scope"] = self.scope
        r = client.post(self.token_url, data=form)
        if r.status_code != 200:
            raise PushError(f"token endpoint returned {r.status_code}")
        body = r.json()
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise PushError("token endpoint returned no access_token")
        self._token = token
        self._expires = self.clock() + max(30.0, float(body.get("expires_in", 300)) - 30.0)
        return token

    def invalidate(self) -> None:
        self._token = None


# ------------------------------------------------------------------------------- push


@dataclass
class Pusher:
    client: httpx.Client
    api: str
    source_id: str
    token: Callable[[httpx.Client], str]
    max_bytes: int = DEFAULT_MAX_BYTES
    retries: int = 5
    backoff_s: float = 1.0
    sleep: Callable[[float], None] = time.sleep
    log: Callable[[dict[str, object]], None] = lambda rec: print(json.dumps(rec, default=str), flush=True)

    def _endpoint(self) -> str:
        base = self.api.rstrip("/")
        return base + ("/ingest" if base.endswith("/api/v1") else "/api/v1/ingest")

    def post_chunk(self, chunk: bytes, name: str, flush: bool) -> dict[str, object]:
        params = {"source_id": self.source_id, "name": name[:200], "flush": "true" if flush else "false"}
        attempt = 0
        while True:
            attempt += 1
            try:
                headers = {"Authorization": f"Bearer {self.token(self.client)}",
                           "Content-Type": "application/octet-stream"}
                r = self.client.post(self._endpoint(), params=params, content=chunk, headers=headers)
            except httpx.TransportError as exc:
                if attempt > self.retries:
                    raise PushError(f"network error after {attempt} attempts: {exc}") from exc
                self.sleep(self.backoff_s * 2 ** (attempt - 1))
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code == 401 and isinstance(self.token, ClientCredentials) and attempt == 1:
                self.token.invalidate()  # token revoked or rotated: fetch a fresh one once
                continue
            if r.status_code in RETRY_STATUSES and attempt <= self.retries:
                delay = self.backoff_s * 2 ** (attempt - 1)
                retry_after = r.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    delay = max(delay, float(retry_after))
                self.sleep(delay)
                continue
            detail = r.text[:300].replace("\n", " ")
            raise PushError(f"HTTP {r.status_code}: {detail}")

    def push_file(self, path: Path, *, kind: FileKind | None = None, flush: bool = False) -> dict[str, int]:
        data = read_bytes(path)
        kind = kind or detect_kind(path, data[:4096])
        chunks = list(split_records(data, kind, self.max_bytes))
        totals = {"chunks": len(chunks), "records_read": 0, "accepted": 0, "quarantined": 0, "duplicates": 0,
                  "findings": 0}
        for i, chunk in enumerate(chunks, 1):
            out = self.post_chunk(chunk, f"{path.name}#{i}", flush=flush and i == len(chunks))
            stats = out.get("stats") or [{}]
            s = stats[0] if isinstance(stats, list) and stats and isinstance(stats[0], dict) else {}
            for k in ("records_read", "accepted", "quarantined", "duplicates"):
                totals[k] += int(s.get(k) or 0)
            totals["findings"] += int(out.get("findings") or 0)
            self.log({"file": str(path), "chunk": i, "of": len(chunks), "bytes": len(chunk),
                      **{k: s.get(k) for k in ("records_read", "accepted", "quarantined", "duplicates")},
                      "findings": out.get("findings")})
        return totals


def _read_secret(path: str | None, env_value: str | None) -> str | None:
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return env_value.strip() if env_value else None


def main(argv: Sequence[str] | None = None, *, transport: httpx.BaseTransport | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aegis_push", description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--api", required=True, help="AEGIS base URL, e.g. https://aegis.operator.example")
    ap.add_argument("--source", required=True, help="registered source_id")
    ap.add_argument("--format", choices=("auto", "csv", "jsonl", "zeek", "json"), default="auto",
                    help="payload framing (default: from file name/content)")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="chunk size budget in bytes")
    ap.add_argument("--flush", action="store_true", help="close detection windows after the last file")
    ap.add_argument("--done-dir", type=Path, default=None, help="move fully accepted files here")
    ap.add_argument("--retries", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--ca-bundle", default=None, help="CA bundle for the AEGIS TLS endpoint")
    ap.add_argument("--token-file", default=os.environ.get("AEGIS_TOKEN_FILE"))
    ap.add_argument("--oidc-token-url", default=os.environ.get("AEGIS_OIDC_TOKEN_URL"))
    ap.add_argument("--client-id", default=os.environ.get("AEGIS_CLIENT_ID"))
    ap.add_argument("--client-secret-file", default=os.environ.get("AEGIS_CLIENT_SECRET_FILE"))
    ap.add_argument("--scope", default=os.environ.get("AEGIS_OIDC_SCOPE"))
    args = ap.parse_args(argv)

    if args.oidc_token_url:
        secret = _read_secret(args.client_secret_file, os.environ.get("AEGIS_CLIENT_SECRET"))
        if not args.client_id or not secret:
            print("aegis_push: --oidc-token-url needs --client-id and a client secret", file=sys.stderr)
            return 2
        token: Callable[[httpx.Client], str] = ClientCredentials(args.oidc_token_url, args.client_id, secret,
                                                                  scope=args.scope)
    else:
        static = _read_secret(args.token_file, os.environ.get("AEGIS_TOKEN"))
        if not static:
            print("aegis_push: no credentials (use --token-file, AEGIS_TOKEN or --oidc-token-url)", file=sys.stderr)
            return 2
        token = StaticToken(static)
    missing = [str(f) for f in args.files if not f.is_file()]
    if missing:
        print(f"aegis_push: no such file: {', '.join(missing)}", file=sys.stderr)
        return 2
    if args.done_dir is not None:
        args.done_dir.mkdir(parents=True, exist_ok=True)

    verify: bool | str = args.ca_bundle or True
    kind = None if args.format == "auto" else args.format
    failed = 0
    with httpx.Client(timeout=args.timeout, verify=verify, transport=transport) as client:
        pusher = Pusher(client, args.api, args.source, token, max_bytes=args.max_bytes, retries=args.retries)
        for i, path in enumerate(args.files):
            try:
                totals = pusher.push_file(path, kind=kind, flush=args.flush and i == len(args.files) - 1)
            except (PushError, OSError, ValueError) as exc:
                failed += 1
                pusher.log({"file": str(path), "error": str(exc)})
                continue
            pusher.log({"file": str(path), "done": True, **totals})
            if args.done_dir is not None:
                shutil.move(str(path), str(args.done_dir / path.name))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
