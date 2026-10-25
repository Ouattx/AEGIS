from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from aegis.intel import FeedFetcher, FetchDisabled, FetchError, ThreatIntelHub, get_spec
from aegis.intel.catalog import FeedSpec
from test_intel_helpers import FEEDS, TENANT

BODY = (FEEDS / "feodo_ipblocklist.csv").read_bytes()


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.t


class Server:
    """httpx mock transport recording requests; serves an ETag'd body."""

    def __init__(self, body: bytes = BODY, etag: str = '"v1"') -> None:
        self.body, self.etag = body, etag
        self.requests: list[httpx.Request] = []
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            raise httpx.ConnectError("down", request=request)
        if request.headers.get("If-None-Match") == self.etag:
            return httpx.Response(304)
        return httpx.Response(200, content=self.body, headers={"ETag": self.etag})


def fetcher(tmp_path, server: Server, clock: Clock, **kw) -> FeedFetcher:
    return FeedFetcher(tmp_path / "cache", enabled=True, transport=httpx.MockTransport(server), clock=clock, **kw)


def test_fetching_is_disabled_by_default(tmp_path):
    f = FeedFetcher(tmp_path)
    with pytest.raises(FetchDisabled):
        f.fetch(get_spec("feed:feodo"))
    with pytest.raises(FetchDisabled):
        ThreatIntelHub().fetch_and_import(TENANT, "feed:feodo", now=datetime.now(timezone.utc), actor="x")
    with pytest.raises(ValueError):
        FeedFetcher(tmp_path, verify=False)


def test_etag_conditional_get_and_min_interval(tmp_path):
    server, clock = Server(), Clock()
    f = fetcher(tmp_path, server, clock)
    spec = get_spec("feed:feodo")
    r1 = f.fetch(spec)
    assert r1.status == 200 and not r1.from_cache and r1.body == BODY and r1.etag == '"v1"'
    r2 = f.fetch(spec)                                    # within min interval: no request at all
    assert r2.from_cache and len(server.requests) == 1
    clock.t += timedelta(hours=1)
    r3 = f.fetch(spec)
    assert r3.not_modified and r3.body == BODY and len(server.requests) == 2
    assert server.requests[1].headers["If-None-Match"] == '"v1"'
    assert "If-Modified-Since" in server.requests[1].headers
    assert server.requests[0].headers["User-Agent"].startswith("aegis-omega-shield")


def test_stale_on_error_size_cap_and_https_only(tmp_path):
    server, clock = Server(), Clock()
    f = fetcher(tmp_path, server, clock)
    spec = get_spec("feed:feodo")
    f.fetch(spec)
    server.fail = True
    clock.t += timedelta(hours=1)
    stale = f.fetch(spec)
    assert stale.stale and stale.body == BODY
    strict = fetcher(tmp_path / "b", server, clock, serve_stale_on_error=False)
    with pytest.raises(FetchError):
        strict.fetch(spec)
    server.fail = False
    tiny = fetcher(tmp_path / "c", server, clock, max_bytes=100)
    with pytest.raises(FetchError):
        tiny.fetch(spec)
    plain = FeedSpec("feed:plain", "x", "feodo_txt", "http://example.test/list.txt", "CC0-1.0", True, "grp:x",
                     0.5, timedelta(days=1), snapshot=True)
    with pytest.raises(FetchError):
        f.fetch(plain)
    with pytest.raises(FetchError):
        f.fetch(get_spec("feed:shadowserver"))           # out-of-band feed: no URL


def test_auth_key_header_and_tampered_cache(tmp_path):
    server, clock = Server(), Clock()
    f = fetcher(tmp_path, server, clock, auth_keys={"feed:urlhaus": "secret-key"})
    spec = get_spec("feed:urlhaus")
    f.fetch(spec)
    assert server.requests[0].headers["Auth-Key"] == "secret-key"
    cache_files = list((tmp_path / "cache").glob("*.meta.json"))
    assert cache_files and "secret-key" not in cache_files[0].read_text()
    body_file = next((tmp_path / "cache").glob("*.body"))
    body_file.write_bytes(b"tampered")
    assert f.cached(spec) is None                         # hash mismatch: cache ignored


def test_hub_fetch_and_import(tmp_path):
    server, clock = Server(), Clock()
    hub = ThreatIntelHub(fetcher=fetcher(tmp_path, server, clock))
    rep = hub.fetch_and_import(TENANT, "feed:feodo", now=clock.t, actor="scheduler")
    assert rep.added == 4
    assert hub.status(TENANT, clock.t)["fetching_enabled"] is True
