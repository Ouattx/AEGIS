from __future__ import annotations

import json
import sys
import time
from datetime import timedelta

import httpx
import pytest
from test_mirror_helpers import C2_DOMAIN, T0, action

from aegis.contracts.models import ActionType
from aegis.mirror import (
    AdapterError,
    DryRunAdapter,
    InvalidTargetError,
    RPZAdapter,
    UnsupportedActionError,
    WebhookAdapter,
    rpz_ip_owner,
    sign_webhook,
    verify_webhook_signature,
)

SECRET = b"s" * 32


# ------------------------------------------------------------------ RPZ

def test_rpz_ip_owner_v4_v6():
    assert rpz_ip_owner("203.0.113.10") == "32.10.113.0.203.rpz-ip"
    assert rpz_ip_owner("2001:db8::1") == "128.1.zz.db8.2001.rpz-ip"
    assert rpz_ip_owner("::1") == "128.1.zz.rpz-ip"
    assert rpz_ip_owner("2001:db8::") == "128.zz.db8.2001.rpz-ip"
    assert rpz_ip_owner("2001:db8:1:2:3:4:5:6") == "128.6.5.4.3.2.1.db8.2001.rpz-ip"
    with pytest.raises(InvalidTargetError):
        rpz_ip_owner("10.0.0.0/8")


def test_rpz_apply_writes_valid_zone(tmp_path):
    zone = tmp_path / "rpz" / "aegis.rpz"
    rpz = RPZAdapter(zone, origin="rpz.isp.example")
    act = action(targets=[C2_DOMAIN, "Other.Bad.Example."])
    res = rpz.apply(act, now=T0)
    assert res.prior_state["entry"] is None
    assert res.prior_state["zone_sha256_before"] is None
    text = zone.read_text()
    assert "$ORIGIN rpz.isp.example." in text
    assert "$TTL 300" in text
    serial = int(T0.timestamp())
    assert f"@ IN SOA localhost. hostmaster.localhost. ( {serial} 3600 600 86400 300 )" in text
    assert "@ IN NS localhost." in text
    assert "c2.bad.example 300 IN CNAME ." in text
    assert "other.bad.example 300 IN CNAME ." in text
    assert f"; action={act.action_id} case=case-1 type=dns_sinkhole " \
           f"expires={act.expires_at.isoformat()} ttl=300" in text
    assert rpz.records(T0) == [("c2.bad.example", "."), ("other.bad.example", ".")]


def test_rpz_ttl_capped_by_expiry_and_expired_dropped(tmp_path):
    rpz = RPZAdapter(tmp_path / "z.rpz", default_ttl=600)
    act = action(expires_at=T0 + timedelta(seconds=90))
    rpz.apply(act, now=T0)
    assert "c2.bad.example 90 IN CNAME ." in (tmp_path / "z.rpz").read_text()
    rpz.refresh(T0 + timedelta(seconds=120))
    assert "c2.bad.example" not in (tmp_path / "z.rpz").read_text()
    assert rpz.records(T0 + timedelta(seconds=120)) == []


def test_rpz_ip_block_and_wildcard_and_policies(tmp_path):
    rpz = RPZAdapter(tmp_path / "z.rpz", policy_action="sinkhole",
                     sinkhole_host="walled-garden.isp.example")
    rpz.apply(action(ActionType.IP_BLOCK, ["203.0.113.10"]), now=T0)
    rpz.apply(action(targets=["tvbox.example"], scope={"include_subdomains": True}), now=T0)
    text = (tmp_path / "z.rpz").read_text()
    assert "32.10.113.0.203.rpz-ip 300 IN CNAME walled-garden.isp.example." in text
    assert "*.tvbox.example 300 IN CNAME walled-garden.isp.example." in text
    nodata = RPZAdapter(tmp_path / "n.rpz", policy_action="nodata")
    nodata.apply(action(), now=T0)
    assert "c2.bad.example 300 IN CNAME *." in (tmp_path / "n.rpz").read_text()


def test_rpz_rollback_restores_prior_state(tmp_path):
    zone = tmp_path / "z.rpz"
    rpz = RPZAdapter(zone)
    existing = action(targets=["old.bad.example"])
    rpz.apply(existing, now=T0)
    before_records = rpz.records(T0)
    before_entries = rpz.entries()
    act = action(targets=[C2_DOMAIN])
    res = rpz.apply(act, now=T0 + timedelta(seconds=5))
    assert ("c2.bad.example", ".") in rpz.records(T0)
    rpz.revert(act, res.prior_state, now=T0 + timedelta(seconds=10))
    assert rpz.records(T0) == before_records
    assert rpz.entries() == before_entries
    # serial strictly increases on every change so secondaries pick up the rollback
    serials = [int(line.split()[6]) for line in zone.read_text().splitlines()
               if line.startswith("@ IN SOA")]
    assert serials and serials[0] >= int(T0.timestamp()) + 2


def test_rpz_reapply_and_revert_restores_previous_entry(tmp_path):
    rpz = RPZAdapter(tmp_path / "z.rpz")
    act = action(targets=["a.example"])
    rpz.apply(act, now=T0)
    changed = act.model_copy(update={"targets": ["b.example"]})
    res = rpz.apply(changed, now=T0)
    assert res.prior_state["entry"]["records"] == [{"owner": "a.example", "rdata": "."}]
    rpz.revert(changed, res.prior_state, now=T0)
    assert rpz.records(T0) == [("a.example", ".")]


def test_rpz_duplicate_owner_across_actions(tmp_path):
    rpz = RPZAdapter(tmp_path / "z.rpz")
    a1, a2 = action(), action()
    rpz.apply(a1, now=T0)
    r2 = rpz.apply(a2, now=T0)
    text = (tmp_path / "z.rpz").read_text()
    assert text.count("c2.bad.example 300 IN CNAME .") == 1
    rpz.revert(a2, r2.prior_state, now=T0)
    assert rpz.records(T0) == [("c2.bad.example", ".")]


@pytest.mark.parametrize("target", ["bad.example\n@ IN NS evil.", "bad.example; x", "*.bad.example",
                                    "a b.example", "x.rpz-ip", "bad"])
def test_rpz_rejects_injection(tmp_path, target):
    rpz = RPZAdapter(tmp_path / "z.rpz")
    with pytest.raises(InvalidTargetError):
        rpz.apply(action(targets=[target]), now=T0)
    assert not (tmp_path / "z.rpz").exists()


def test_rpz_rejects_target_inside_origin_and_unsupported(tmp_path):
    rpz = RPZAdapter(tmp_path / "z.rpz", origin="rpz.isp.example")
    with pytest.raises(InvalidTargetError):
        rpz.apply(action(targets=["x.rpz.isp.example"]), now=T0)
    with pytest.raises(UnsupportedActionError):
        rpz.apply(action(ActionType.DEVICE_QUARANTINE, ["p_abcdef123456"]), now=T0)
    with pytest.raises(AdapterError):
        rpz.apply(action(expires_at=None), now=T0)


def test_rpz_config_validation(tmp_path):
    with pytest.raises(ValueError):
        RPZAdapter(tmp_path / "z", policy_action="sinkhole")
    with pytest.raises(ValueError):
        RPZAdapter(tmp_path / "z", default_ttl=0)
    with pytest.raises(ValueError):
        RPZAdapter(tmp_path / "z", policy_action="drop")  # type: ignore[arg-type]


def test_rpz_state_survives_new_instance_and_origin_guard(tmp_path):
    zone = tmp_path / "z.rpz"
    RPZAdapter(zone).apply(action(), now=T0)
    assert RPZAdapter(zone).records(T0) == [("c2.bad.example", ".")]
    with pytest.raises(AdapterError):
        RPZAdapter(zone, origin="other.example").records(T0)
    (tmp_path / "z.rpz.state.json").write_text("{broken")
    with pytest.raises(AdapterError):
        RPZAdapter(zone).records(T0)


def test_rpz_reload_failure_restores_files(tmp_path):
    zone = tmp_path / "z.rpz"
    ok = RPZAdapter(zone, reload_command=[sys.executable, "-c", "pass"])
    ok.apply(action(targets=["first.example"]), now=T0)
    before_zone = zone.read_bytes()
    before_state = (tmp_path / "z.rpz.state.json").read_bytes()
    bad = RPZAdapter(zone, reload_command=[sys.executable, "-c",
                                           "import sys; sys.stderr.write('boom'); sys.exit(3)"])
    with pytest.raises(AdapterError, match="boom"):
        bad.apply(action(targets=["second.example"]), now=T0)
    assert zone.read_bytes() == before_zone
    assert (tmp_path / "z.rpz.state.json").read_bytes() == before_state
    missing = RPZAdapter(zone, reload_command=["/nonexistent/rndc", "reload"])
    with pytest.raises(AdapterError):
        missing.apply(action(targets=["third.example"]), now=T0)
    assert zone.read_bytes() == before_zone


# ------------------------------------------------------------------ webhook

class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _hook(rec, **kw):
    client = httpx.Client(transport=httpx.MockTransport(rec))
    return WebhookAdapter("https://enforce.isp.example/hook", SECRET, client=client,
                          sleep=lambda s: None, **kw)


def test_webhook_signs_and_returns_prior_state():
    rec = Recorder([httpx.Response(200, json={"prior_state": {"rule": None}})])
    hook = _hook(rec)
    act = action()
    res = hook.apply(act, now=T0)
    req = rec.requests[0]
    body = req.content
    assert verify_webhook_signature(SECRET, req.headers["X-Aegis-Timestamp"], body,
                                    req.headers["X-Aegis-Signature"])
    assert req.headers["X-Aegis-Signature"].startswith("v1=")
    doc = json.loads(body)
    assert doc["event"] == "aegis.enforcement.apply"
    assert doc["action"]["action_id"] == act.action_id
    assert doc["tenant_id"] == act.tenant_id
    assert res.prior_state["remote"] == {"rule": None}
    assert res.prior_state["apply_delivery_id"] == req.headers["X-Aegis-Delivery"]


def test_webhook_revert_sends_prior_state():
    rec = Recorder([httpx.Response(204)])
    hook = _hook(rec)
    hook.revert(action(), {"remote": {"rule": 7}}, now=T0)
    doc = json.loads(rec.requests[0].content)
    assert doc["event"] == "aegis.enforcement.revert"
    assert doc["prior_state"] == {"remote": {"rule": 7}}


def test_webhook_retries_with_same_delivery_id():
    rec = Recorder([httpx.ConnectError("down"), httpx.Response(503), httpx.Response(200)])
    hook = _hook(rec)
    hook.apply(action(), now=T0)
    ids = {r.headers["X-Aegis-Delivery"] for r in rec.requests}
    assert len(rec.requests) == 3 and len(ids) == 1


def test_webhook_gives_up_and_does_not_retry_client_errors():
    rec = Recorder([httpx.Response(500)] * 3)
    with pytest.raises(AdapterError, match="after 3"):
        _hook(rec).apply(action(), now=T0)
    rec2 = Recorder([httpx.Response(403)])
    with pytest.raises(AdapterError, match="rejected"):
        _hook(rec2).apply(action(), now=T0)
    assert len(rec2.requests) == 1
    rec3 = Recorder([httpx.Response(429), httpx.Response(200, content=b"not json")])
    res = _hook(rec3).apply(action(), now=T0)
    assert res.prior_state["remote"] == {}


def test_webhook_validates_config_and_targets():
    with pytest.raises(ValueError):
        WebhookAdapter("http://enforce.isp.example/hook", SECRET)
    WebhookAdapter("http://127.0.0.1:9/hook", SECRET, allow_insecure_http=True)
    with pytest.raises(ValueError):
        WebhookAdapter("https://enforce.isp.example/hook", b"short")
    with pytest.raises(ValueError):
        WebhookAdapter("ftp://x/hook", SECRET)
    rec = Recorder([])
    with pytest.raises(InvalidTargetError):
        _hook(rec).apply(action(targets=["evil\n"]), now=T0)
    assert rec.requests == []
    limited = _hook(Recorder([]), supported_actions=frozenset({ActionType.IP_BLOCK}))
    with pytest.raises(UnsupportedActionError):
        limited.apply(action(), now=T0)
    assert "s" * 32 not in repr(limited)


def test_verify_webhook_signature_rejects_bad_input():
    body = b'{"a":1}'
    ts = int(time.time())
    sig = sign_webhook(SECRET, ts, body)
    assert verify_webhook_signature(SECRET, ts, body, sig)
    assert not verify_webhook_signature(SECRET, ts, body + b" ", sig)
    assert not verify_webhook_signature(b"x" * 32, ts, body, sig)
    assert not verify_webhook_signature(SECRET, ts - 1000, body, sign_webhook(SECRET, ts - 1000, body))
    assert not verify_webhook_signature(SECRET, "nan", body, sig)


# ------------------------------------------------------------------ dry run

def test_dry_run_records_and_reverts():
    dry = DryRunAdapter()
    act = action()
    res = dry.apply(act, now=T0)
    assert res.dry_run and res.prior_state["simulated"]
    assert dry.active()[act.action_id]["targets"] == [C2_DOMAIN]
    dry.revert(act, res.prior_state, now=T0)
    assert dry.active() == {}
    assert [o["op"] for o in dry.operations] == ["apply", "revert"]
    with pytest.raises(InvalidTargetError):
        dry.apply(action(targets=["bad target"]), now=T0)
