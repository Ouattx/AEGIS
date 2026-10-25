"""Optional HTTP fetching of public feeds, with on-disk caching and conditional requests.

Disabled by default: a sovereign or air-gapped deployment imports feed files
offline (``parse_feed`` on a file). A :class:`FeedFetcher` makes network requests
only when constructed with ``enabled=True``; otherwise :meth:`FeedFetcher.fetch`
raises :class:`FetchDisabled` (fail closed, no silent egress).

Behaviour when enabled:

- conditional GET with ``If-None-Match`` (ETag) and ``If-Modified-Since``; a ``304``
  serves the cached body;
- a minimum refresh interval per feed (default 15 minutes): within it the cache is
  served without any request (polite to feed operators, who rate-limit);
- responses are size-capped while streaming (``max_bytes``) and written atomically;
- on a network or HTTP error the last cached body is returned with ``stale=True`` when
  ``serve_stale_on_error`` is set, otherwise the error propagates;
- only ``https`` URLs are fetched; TLS verification is never disabled (``verify`` may
  name a CA bundle path, e.g. a corporate proxy's).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from aegis.intel.catalog import FeedSpec
from aegis.intel.models import iso, parse_iso, utc

DEFAULT_USER_AGENT = "aegis-omega-shield/1 (threat-intel importer)"


class FetchDisabled(RuntimeError):
    """Network fetching is off (the default)."""


class FetchError(RuntimeError):
    """The feed could not be fetched and no cached copy is available."""


@dataclass(frozen=True)
class FetchResult:
    feed_id: str
    body: bytes
    fetched_at: datetime            # when this body was obtained from the network
    from_cache: bool
    not_modified: bool
    stale: bool                     # served from cache after an error
    etag: str | None
    sha256: str
    status: int | None


class FeedFetcher:
    def __init__(self, cache_dir: str | Path, *, enabled: bool = False, timeout_s: float = 30.0,
                 max_bytes: int = 64 * 1024 * 1024, min_interval: timedelta = timedelta(minutes=15),
                 user_agent: str = DEFAULT_USER_AGENT, verify: bool | str = True,
                 serve_stale_on_error: bool = True, auth_keys: dict[str, str] | None = None,
                 transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], datetime] | None = None):
        if verify is False:
            raise ValueError("TLS verification cannot be disabled")
        self.cache_dir = Path(cache_dir)
        self.enabled = enabled
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.min_interval = min_interval
        self.user_agent = user_agent
        self.verify = verify
        self.serve_stale_on_error = serve_stale_on_error
        self._auth = dict(auth_keys or {})       # feed_id -> API key (never logged or cached)
        self._transport = transport
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _paths(self, spec: FeedSpec) -> tuple[Path, Path]:
        stem = hashlib.sha256(spec.feed_id.encode()).hexdigest()[:16]
        return self.cache_dir / f"{stem}.body", self.cache_dir / f"{stem}.meta.json"

    def cached(self, spec: FeedSpec) -> FetchResult | None:
        body_p, meta_p = self._paths(spec)
        if not body_p.exists() or not meta_p.exists():
            return None
        try:
            meta = json.loads(meta_p.read_text())
            body = body_p.read_bytes()
        except (OSError, json.JSONDecodeError):
            return None
        if hashlib.sha256(body).hexdigest() != meta.get("sha256"):
            return None                      # torn or tampered cache: ignore
        return FetchResult(feed_id=spec.feed_id, body=body, fetched_at=parse_iso(meta["fetched_at"]),
                           from_cache=True, not_modified=False, stale=False, etag=meta.get("etag"),
                           sha256=meta["sha256"], status=meta.get("status"))

    def _store(self, spec: FeedSpec, body: bytes, meta: dict[str, Any]) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        body_p, meta_p = self._paths(spec)
        for path, data in ((body_p, body), (meta_p, json.dumps(meta, sort_keys=True).encode())):
            fd, tmp = tempfile.mkstemp(dir=self.cache_dir, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise

    def fetch(self, spec: FeedSpec, *, force: bool = False) -> FetchResult:
        if not self.enabled:
            raise FetchDisabled("feed fetching is disabled; import feed files offline or enable the fetcher")
        if not spec.url:
            raise FetchError(f"{spec.feed_id} has no URL (delivered out of band)")
        if not spec.url.startswith("https://"):
            raise FetchError(f"{spec.feed_id}: only https URLs are fetched")
        now = utc(self._clock())
        cached = self.cached(spec)
        if cached is not None and not force and now - cached.fetched_at < self.min_interval:
            return cached
        headers = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip"}
        if cached is not None:
            if cached.etag:
                headers["If-None-Match"] = cached.etag
            headers["If-Modified-Since"] = cached.fetched_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
        if spec.auth_header and spec.feed_id in self._auth:
            headers[spec.auth_header] = self._auth[spec.feed_id]
        try:
            with httpx.Client(timeout=self.timeout_s, verify=self.verify, transport=self._transport,
                              follow_redirects=True, max_redirects=3) as client:
                with client.stream("GET", spec.url, headers=headers) as resp:
                    if resp.url.scheme != "https":
                        raise FetchError(f"{spec.feed_id}: redirected to a non-https URL")
                    if resp.status_code == 304 and cached is not None:
                        self._store(spec, cached.body, {"fetched_at": iso(now), "etag": cached.etag,
                                                        "sha256": cached.sha256, "status": 304,
                                                        "feed_id": spec.feed_id})
                        return FetchResult(feed_id=spec.feed_id, body=cached.body, fetched_at=now, from_cache=True,
                                           not_modified=True, stale=False, etag=cached.etag, sha256=cached.sha256,
                                           status=304)
                    if resp.status_code != 200:
                        raise FetchError(f"{spec.feed_id}: HTTP {resp.status_code}")
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise FetchError(f"{spec.feed_id}: body exceeds {self.max_bytes} bytes")
                        chunks.append(chunk)
                    body = b"".join(chunks)
                    etag = resp.headers.get("ETag")
        except (httpx.HTTPError, FetchError) as exc:
            if cached is not None and self.serve_stale_on_error:
                return FetchResult(feed_id=spec.feed_id, body=cached.body, fetched_at=cached.fetched_at,
                                   from_cache=True, not_modified=False, stale=True, etag=cached.etag,
                                   sha256=cached.sha256, status=None)
            raise FetchError(f"{spec.feed_id}: {exc}") from exc
        digest = hashlib.sha256(body).hexdigest()
        self._store(spec, body, {"fetched_at": iso(now), "etag": etag, "sha256": digest, "status": 200,
                                 "feed_id": spec.feed_id})
        return FetchResult(feed_id=spec.feed_id, body=body, fetched_at=now, from_cache=False, not_modified=False,
                           stale=False, etag=etag, sha256=digest, status=200)


__all__ = ["DEFAULT_USER_AGENT", "FeedFetcher", "FetchDisabled", "FetchError", "FetchResult"]
