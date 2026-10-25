"""Operator tools shipped in deploy/tools (also copied into the image at /opt/aegis/tools)."""
from __future__ import annotations

import gzip
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.rules import BundleSignatureError, load_bundle
from test_api_helpers import auth, make_client, make_service

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "deploy" / "tools"
SAMPLE = ROOT / "sample_data"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"deploy_tools_{name}", TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


push = _load("aegis_push")
signtool = _load("sign_ioc_bundle")


# ================================================================== chunking


def _rows(n: int, width: int = 60) -> bytes:
    return b"".join(f"2026-10-01T00:00:{i % 60:02d}Z,dev{i},{'x' * width}\n".encode() for i in range(n))


def test_csv_chunks_repeat_header_respect_budget_and_keep_every_record():
    header = b"ts,device_id,pad\n"
    data = header + _rows(500)
    chunks = list(push.split_records(data, "csv", 4096))
    assert len(chunks) > 5
    assert all(c.startswith(header) for c in chunks)
    assert all(len(c) <= 4096 for c in chunks)
    body = b"".join(c[len(header):] for c in chunks)
    assert body == data[len(header):]


def test_zeek_header_block_repeated_and_close_line_dropped():
    data = (SAMPLE / "zeek" / "conn.log").read_bytes()
    header = [ln for ln in data.splitlines(keepends=True) if ln.startswith(b"#") and not ln.startswith(b"#close")]
    records = [ln for ln in data.splitlines(keepends=True) if not ln.startswith(b"#") and ln.strip()]
    chunks = list(push.split_records(data, "zeek", 2048))
    assert len(chunks) > 1
    for c in chunks:
        assert c.startswith(b"".join(header))
        assert b"#close" not in c
    rebuilt = [ln for c in chunks for ln in c.splitlines(keepends=True) if not ln.startswith(b"#")]
    assert rebuilt == records


def test_jsonl_and_json_framing():
    lines = b"".join(json.dumps({"ts": "2026-10-01T00:00:00Z", "qname": f"n{i}.example"}).encode() + b"\n"
                     for i in range(300))
    chunks = list(push.split_records(lines, "jsonl", 2048))
    assert len(chunks) > 1 and b"".join(chunks) == lines
    doc = (SAMPLE / "formats" / "cpe.json").read_bytes()
    assert list(push.split_records(doc, "json", 1024)) == [doc]  # documents are never cut
    assert list(push.split_records(b"  \n", "json", 1024)) == []


def test_blank_lines_skipped_missing_newline_added_and_oversize_record_alone():
    data = b"a,b\n\n1,2\n" + b"3," + b"y" * 3000 + b"\n4,5"
    chunks = list(push.split_records(data, "csv", 1024))
    assert chunks[0] == b"a,b\n1,2\n"
    assert chunks[1].startswith(b"a,b\n3,") and len(chunks[1]) > 1024
    assert chunks[2] == b"a,b\n4,5\n"
    with pytest.raises(ValueError):
        list(push.split_records(data, "csv", 100))


@pytest.mark.parametrize("rel,kind", [
    ("lab/netflow.csv", "csv"), ("formats/nfdump.csv", "csv"), ("lab/dns.jsonl", "jsonl"),
    ("zeek/conn.log", "zeek"), ("zeek/dns.log", "zeek"), ("formats/cpe.json", "json"),
])
def test_detect_kind_on_sample_formats(rel, kind):
    p = SAMPLE / rel
    assert push.detect_kind(p, p.read_bytes()[:4096]) == kind


def test_detect_kind_from_content_when_name_is_generic(tmp_path):
    assert push.detect_kind(tmp_path / "x.dat", b'{"ts": 1}\n{"ts": 2}\n') == "jsonl"
    assert push.detect_kind(tmp_path / "x.dat", b'{\n "devices": []\n}') == "json"
    assert push.detect_kind(tmp_path / "x.dat", b"#separator \\x09\n#fields\tts\n") == "zeek"
    assert push.detect_kind(tmp_path / "x.dat", b"ts,dst_ip\n") == "csv"
    assert push.detect_kind(tmp_path / "x.csv.gz", b"") == "csv"


def test_gzip_input_is_read_transparently(tmp_path):
    raw = (SAMPLE / "lab" / "netflow.csv").read_bytes()
    gz = tmp_path / "netflow.csv.gz"
    gz.write_bytes(gzip.compress(raw))
    assert push.read_bytes(gz) == raw
    plain = tmp_path / "plain.csv"
    plain.write_bytes(raw)
    assert push.read_bytes(plain) == raw


# ================================================================== HTTP behaviour (mock transport)


def _ok(records: int = 10) -> httpx.Response:
    return httpx.Response(200, json={"events": records, "findings": 1, "stats": [
        {"records_read": records, "accepted": records, "quarantined": 0, "duplicates": 0}]})


class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _pusher(rec: Recorder, **kw):
    sleeps: list[float] = []
    logs: list[dict] = []
    client = httpx.Client(transport=httpx.MockTransport(rec))
    p = push.Pusher(client, kw.pop("api", "https://aegis.test"), "gw-netflow", kw.pop("token", push.StaticToken("t0k")),
                    sleep=sleeps.append, log=logs.append, **kw)
    return p, sleeps, logs


def test_post_targets_ingest_endpoint_with_source_name_flush_and_bearer():
    rec = Recorder([_ok()])
    p, _, _ = _pusher(rec)
    p.post_chunk(b"ts,dst_ip\n", "f.csv#1", flush=True)
    req = rec.requests[0]
    assert req.url.path == "/api/v1/ingest"
    assert req.url.params["source_id"] == "gw-netflow" and req.url.params["flush"] == "true"
    assert req.url.params["name"] == "f.csv#1"
    assert req.headers["authorization"] == "Bearer t0k"
    p2, _, _ = _pusher(Recorder([_ok()]), api="https://aegis.test/api/v1/")
    assert p2._endpoint() == "https://aegis.test/api/v1/ingest"


def test_429_honours_retry_after_then_succeeds():
    rec = Recorder([httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(503), _ok()])
    p, sleeps, _ = _pusher(rec)
    assert p.post_chunk(b"x\n", "n", False)["events"] == 10
    assert sleeps == [7.0, 2.0]


def test_network_errors_retry_with_backoff_then_give_up():
    err = httpx.ConnectError("refused")
    rec = Recorder([err, err, err])
    p, sleeps, _ = _pusher(rec, retries=2)
    with pytest.raises(push.PushError, match="network error"):
        p.post_chunk(b"x\n", "n", False)
    assert sleeps == [1.0, 2.0]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_client_errors_are_not_retried(status):
    rec = Recorder([httpx.Response(status, text="nope")])
    p, sleeps, _ = _pusher(rec)
    with pytest.raises(push.PushError, match=f"HTTP {status}"):
        p.post_chunk(b"x\n", "n", False)
    assert len(rec.requests) == 1 and sleeps == []


def test_server_errors_exhaust_retries():
    rec = Recorder([httpx.Response(502)] * 4)
    p, sleeps, _ = _pusher(rec, retries=3)
    with pytest.raises(push.PushError, match="HTTP 502"):
        p.post_chunk(b"x\n", "n", False)
    assert sleeps == [1.0, 2.0, 4.0]


def test_client_credentials_cached_and_refreshed_after_401():
    now = [1000.0]
    calls = {"token": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            calls["token"] += 1
            form = dict(x.split("=") for x in request.content.decode().split("&"))
            assert form["grant_type"] == "client_credentials" and form["client_id"] == "collector"
            return httpx.Response(200, json={"access_token": f"tok{calls['token']}", "expires_in": 300})
        if request.headers["authorization"] == "Bearer tok1" and calls["token"] == 1 and now[0] > 1100:
            return httpx.Response(401)
        return _ok()

    cc = push.ClientCredentials("https://idp.test/token", "collector", "s3cret", clock=lambda: now[0])
    client = httpx.Client(transport=httpx.MockTransport(handler))
    p = push.Pusher(client, "https://aegis.test", "src", cc, sleep=lambda s: None, log=lambda r: None)
    p.post_chunk(b"x\n", "a", False)
    p.post_chunk(b"x\n", "b", False)
    assert calls["token"] == 1                      # cached
    now[0] = 1200.0                                  # still valid by clock, but the API rejects it
    p.post_chunk(b"x\n", "c", False)
    assert calls["token"] == 2                      # invalidated and refreshed once
    now[0] = 2000.0                                  # expired by clock
    p.post_chunk(b"x\n", "d", False)
    assert calls["token"] == 3


def test_token_endpoint_failure_is_a_push_error():
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(400)))
    cc = push.ClientCredentials("https://idp.test/token", "c", "s")
    with pytest.raises(push.PushError, match="token endpoint"):
        cc(client)
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(push.PushError, match="no access_token"):
        push.ClientCredentials("https://idp.test/token", "c", "s")(client)


def test_push_file_aggregates_chunks_and_flushes_only_last(tmp_path):
    f = tmp_path / "flows.csv"
    f.write_bytes(b"ts,device_id,pad\n" + _rows(400))
    rec = Recorder([_ok(100)] * 50)
    p, _, logs = _pusher(rec, max_bytes=8192)
    totals = p.push_file(f, flush=True)
    n = totals["chunks"]
    assert n == len(rec.requests) > 1
    assert totals["accepted"] == 100 * n and totals["findings"] == n
    flushes = [r.url.params["flush"] for r in rec.requests]
    assert flushes == ["false"] * (n - 1) + ["true"]
    assert [entry["chunk"] for entry in logs] == list(range(1, n + 1))


# ================================================================== CLI


def test_main_moves_accepted_files_and_reports_failures(tmp_path, monkeypatch, capsys):
    good, bad = tmp_path / "a.csv", tmp_path / "b.csv"
    good.write_bytes(b"ts,dst_ip\n2026-10-01T00:00:00Z,198.18.0.1\n")
    bad.write_bytes(b"ts,dst_ip\n2026-10-01T00:00:00Z,198.18.0.2\n")
    done = tmp_path / "done"

    def handler(request: httpx.Request) -> httpx.Response:
        return _ok(1) if request.url.params["name"].startswith("a.csv") else httpx.Response(422, text="bad")

    monkeypatch.setenv("AEGIS_TOKEN", "abc")
    rc = push.main(["--api", "https://aegis.test", "--source", "s", "--done-dir", str(done), str(good), str(bad)],
                   transport=httpx.MockTransport(handler))
    assert rc == 1
    assert (done / "a.csv").is_file() and not good.exists()
    assert bad.exists()
    out = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert any(o.get("done") and o["file"].endswith("a.csv") for o in out)
    assert any("HTTP 422" in o.get("error", "") for o in out)


def test_main_usage_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_TOKEN_FILE", raising=False)
    f = tmp_path / "x.csv"
    f.write_text("ts,dst_ip\n")
    assert push.main(["--api", "https://a", "--source", "s", str(f)]) == 2
    assert push.main(["--api", "https://a", "--source", "s", "--oidc-token-url", "https://idp/t", str(f)]) == 2
    tok = tmp_path / "tok"
    tok.write_text("abc\n")
    assert push.main(["--api", "https://a", "--source", "s", "--token-file", str(tok), str(tmp_path / "nope")]) == 2
    assert "no such file" in capsys.readouterr().err


def test_push_against_the_real_api(tmp_path):
    """The tool's requests are accepted by the actual AEGIS API, end to end."""
    svc = make_service(tmp_path / "svc")
    client = make_client(svc)
    r = client.post("/api/v1/sources", headers=auth(svc, "t1", "admin"), json={
        "source_id": "gw-netflow", "source_kind": "netflow", "vantage": "device",
        "collection_authorization_id": "auth-1"})
    assert r.status_code == 201, r.text
    token = auth(svc, "t1", "integration")["Authorization"].split()[1]
    logs: list[dict] = []
    p = push.Pusher(client, "http://testserver", "gw-netflow", push.StaticToken(token), max_bytes=64 * 1024,
                    sleep=lambda s: None, log=logs.append)
    totals = p.push_file(SAMPLE / "lab" / "netflow.csv", flush=True)
    assert totals["chunks"] > 1
    assert totals["records_read"] == totals["accepted"] == 6703 and totals["quarantined"] == 0
    # re-sending is absorbed by de-duplication instead of double counting
    again = p.push_file(SAMPLE / "lab" / "netflow.csv")
    assert again["accepted"] == 0 and again["duplicates"] == 6703
    # a collector token cannot read anything back
    assert client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"}).status_code == 403


# ================================================================== IOC bundle signing


def _bundle() -> dict:
    return json.loads((ROOT / "deploy" / "examples" / "ioc-bundle.example.json").read_text())


def test_sign_and_verify_roundtrip_matches_aegis_loader(tmp_path):
    signer = Signer.generate("op-ioc-test")
    signed = signtool.sign_bundle_dict(_bundle(), signer)
    ring = KeyRing()
    ring.add("op-ioc-test", signer.public_pem())
    parsed = load_bundle(signed, ring)                 # exactly what POST /api/v1/iocs does
    assert parsed.signer_key_id == "op-ioc-test" and len(parsed.indicators) == 2
    tampered = dict(signed, version="2026.11.01-2")
    with pytest.raises(BundleSignatureError):
        load_bundle(tampered, ring)
    other = Signer.generate("op-ioc-test")
    with pytest.raises(BundleSignatureError):
        signtool.verify_bundle_dict(signed, "op-ioc-test", other.public_pem())


def test_sign_tool_cli(tmp_path, capsys):
    signer = Signer.generate("op-ioc-cli")
    key, pub = tmp_path / "k.pem", tmp_path / "k.pub.pem"
    key.write_bytes(signer.private_pem())
    pub.write_bytes(signer.public_pem())
    src, out = tmp_path / "feed.json", tmp_path / "feed.signed.json"
    src.write_text(json.dumps(_bundle()))
    assert signtool.main(["sign", str(src), "--key", str(key), "--key-id", "op-ioc-cli", "--out", str(out)]) == 0
    assert json.loads(capsys.readouterr().out)["indicators"] == 2
    assert signtool.main(["verify", str(out), "--public-key", str(pub)]) == 0
    capsys.readouterr()
    data = json.loads(out.read_text())
    data["indicators"][0]["value"] = "evil.example"
    out.write_text(json.dumps(data))
    assert signtool.main(["verify", str(out), "--public-key", str(pub)]) == 1
    assert "does not verify" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({**_bundle(), "schema": "other/9"}))
    assert signtool.main(["sign", str(bad), "--key", str(key), "--key-id", "op-ioc-cli", "--out", str(out)]) == 1
    assert "unsupported bundle schema" in capsys.readouterr().err


def test_signed_example_bundle_is_accepted_by_the_api(tmp_path):
    svc = make_service(tmp_path / "svc")
    client = make_client(svc)
    signer = Signer.generate("op-ioc-api")
    svc.trust_key("ioc", "op-ioc-api", signer.public_pem())
    r = client.post("/api/v1/iocs", headers=auth(svc, "t1", "admin"),
                    json=signtool.sign_bundle_dict(_bundle(), signer))
    assert r.status_code == 201, r.text
    assert r.json()["bundle"]["bundle_id"] == "acme-soc-feed-20261101"
