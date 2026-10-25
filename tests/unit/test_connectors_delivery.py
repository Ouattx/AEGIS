"""Signed export delivery (dry-run by default) and the DDoS-platform connector.

The mitigation adapter is exercised only through ``aegis.mirror.authorize`` and
``aegis.mirror.Executor``: that is the sole path from a proposal to an enforcement point.
"""
from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
from test_egress_detector import flood, run
from test_mirror_helpers import T0, TENANT, VICTIM_IP, Clock, action, ledger, policy, safe_mirror, signer_and_ring

from aegis.connectors import (
    EXPORT_ENTRY,
    ExportDelivery,
    ExportPayload,
    FlowSpecConfig,
    MitigationRequestAdapter,
    ddos_export,
    propose_flowspec,
    signature_headers,
    verify_export,
)
from aegis.contracts.models import ActionType
from aegis.mirror import ExecutionStatus, Executor, authorize, verify_webhook_signature

SECRET = b"k" * 32
URL = "https://ddos.example.net/aegis"


def _payload(body: str = '{"a":1}') -> ExportPayload:
    return ExportPayload.build("siem.jsonl", TENANT, "application/x-ndjson", body, records=1, generated_at=T0)


class Receiver:
    """In-process HTTPS endpoint (httpx.MockTransport) that verifies every request."""

    def __init__(self, statuses=(200,)):
        self.statuses = list(statuses)
        self.requests: list[httpx.Request] = []
        self.verified: list[bool] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        ts = int(request.headers["X-Aegis-Timestamp"])
        self.verified.append(verify_export(request.content, request.headers, SECRET, now=ts))
        return httpx.Response(self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0], json={})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))


def _no_network() -> httpx.Client:
    def boom(request):  # pragma: no cover - reaching it is the failure
        raise AssertionError("dry-run must not send anything")
    return httpx.Client(transport=httpx.MockTransport(boom))


# ------------------------------------------------------------------ signing / delivery

def test_signature_headers_verify_with_export_and_mirror_receivers():
    p = _payload()
    h = signature_headers(p, SECRET, timestamp=1_767_225_600, delivery_id="d-1")
    assert verify_export(p.body_bytes, h, SECRET, now=1_767_225_600)
    assert verify_webhook_signature(SECRET, h["X-Aegis-Timestamp"], p.body_bytes, h["X-Aegis-Signature"],
                                    now=1_767_225_600)
    assert not verify_export(b'{"a":2}', h, SECRET, now=1_767_225_600)               # tampered body
    assert not verify_export(p.body_bytes, h, SECRET, now=1_767_225_600 + 3_600)      # stale
    assert not verify_export(p.body_bytes, h, b"z" * 32, now=1_767_225_600)           # wrong key
    with pytest.raises(ValueError):
        signature_headers(p, b"short", timestamp=1)


def test_dry_run_is_the_default_sends_nothing_and_is_ledgered(tmp_path):
    led = ledger(tmp_path)
    d = ExportDelivery(URL, secret=SECRET, ledger=led, client=_no_network(), clock=lambda: 1_767_225_600.0)
    res = d.deliver(_payload(), actor="alice@isp")
    assert res.status == "dry_run" and res.dry_run and res.ledger_entry_hash
    assert verify_export(_payload().body_bytes, res.headers, SECRET, now=1_767_225_600)
    entries = led.entries(TENANT, entry_type=EXPORT_ENTRY)
    assert len(entries) == 1 and entries[0].payload["sha256"] == _payload().sha256
    assert entries[0].payload["destination"] == URL and "body" not in entries[0].payload
    assert "k" * 32 not in repr(d)


def test_live_delivery_is_signed_and_retried():
    rx = Receiver(statuses=(503, 200))
    d = ExportDelivery(URL, secret=SECRET, dry_run=False, client=rx.client(), sleep=lambda s: None)
    res = d.deliver(_payload(), actor="alice@isp")
    assert res.status == "delivered" and res.attempts == 2 and rx.verified == [True, True]
    assert len({r.headers["X-Aegis-Delivery"] for r in rx.requests}) == 1   # one idempotency key
    rx = Receiver(statuses=(400,))
    res = ExportDelivery(URL, secret=SECRET, dry_run=False, client=rx.client()).deliver(_payload(), actor="a")
    assert res.status == "failed" and res.attempts == 1 and res.http_status == 400


@pytest.mark.parametrize("kw", [
    dict(url="http://ddos.example.net/x", secret=SECRET),
    dict(url="https://user:pw@ddos.example.net/x", secret=SECRET),
    dict(url="ftp://ddos.example.net/x", secret=SECRET),
    dict(url=URL, secret=None, dry_run=False),
    dict(url=URL, secret=b"short"),
])
def test_delivery_fails_closed_on_unsafe_configuration(kw):
    url = kw.pop("url")
    with pytest.raises(ValueError):
        ExportDelivery(url, **kw)


def test_actor_is_required():
    with pytest.raises(ValueError):
        ExportDelivery(URL).deliver(_payload(), actor=" ")


# ------------------------------------------------------------------ DDoS-platform export

def test_ddos_export_is_a_proposal_document():
    rep = run([e for i in range(3) for e in flood(f"p_line0000{i}", range(i, i + 3), 1_500)])
    plan = propose_flowspec(rep, FlowSpecConfig(source_prefixes=("100.64.0.0/10",)))
    pl = ddos_export(rep, plan)
    doc = json.loads(pl.body)
    assert pl.proposal is True and doc["schema"] == "aegis.ddos-export/1"
    assert doc["status"] == "proposed" and doc["requires_operator_review"] is True and doc["auto_apply"] is False
    assert "NOT APPLIED" in doc["notice"]
    scopes = [a["scope"] for a in doc["attacks"]]
    assert scopes.count("campaign") == 1 and scopes.count("line") == 3
    line = next(a for a in doc["attacks"] if a["scope"] == "line")
    assert line["targets"] == ["192.0.2.10"] and line["protocols"] == ["udp"] and line["dst_ports"] == [80]
    assert doc["mitigation_proposals"][0]["flowspec"]["extended_communities"][0]["name"] == "traffic-rate-bytes"
    other = plan.model_copy(update={"tenant_id": "other"})
    with pytest.raises(ValueError):
        ddos_export(rep, other)


# ------------------------------------------------------------------ mitigation via MIRROR only

def _ip_action(**kw):
    return action(ActionType.IP_BLOCK, targets=[VICTIM_IP], rollback_plan="withdraw the rate limit", **kw)


def _env(tmp_path, adapter, *, mode="active", scope=None):
    signer, ring = signer_and_ring()
    approved = {"legal_bases": ["operator_tos_security_clause"], **(scope or {})}
    pol = policy(signer, mode=mode, approved_scope=approved)
    clock = Clock()
    led = ledger(tmp_path)
    return Executor(adapter, led, clock=clock), pol, ring, led


def test_shadow_policy_runs_the_mitigation_adapter_as_dry_run_only(tmp_path):
    adapter = MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10",), client=_no_network())
    ex, pol, ring, led = _env(tmp_path, adapter, mode="shadow")
    act = _ip_action()
    dec = authorize(act, pol, ring, safe_mirror(act), True, now=T0)
    assert dec.failed_checks == ["policy_not_active_mode"]
    rec = ex.execute(act, dec, "alice@isp")
    assert rec.status is ExecutionStatus.DRY_RUN
    sent = adapter.requests[0]
    assert sent["status"] == "dry_run" and sent["body"]["schema"] == "aegis.mitigation-request/1"
    rule = sent["body"]["rules"][0]
    assert rule["match"]["destination"] == "192.0.2.10/32" and rule["match"]["source"] == "100.64.0.0/10"
    assert rule["action"] == {"kind": "rate_limit", "rate_bytes_per_s": 1_250_000, "sample": True}


def test_without_authorization_the_adapter_is_never_called(tmp_path):
    adapter = MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10",), client=_no_network())
    ex, *_ = _env(tmp_path, adapter)
    rec = ex.execute(_ip_action(), None, "alice@isp")
    assert rec.status is ExecutionStatus.REFUSED and adapter.requests == []
    sink = action(ActionType.DNS_SINKHOLE)
    rec = ex.execute(sink, None, "alice@isp")
    assert "adapter_unsupported_action" in rec.refusal_reasons


def test_live_mitigation_with_active_policy_applies_and_withdraws(tmp_path):
    rx = Receiver()
    adapter = MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10", "2001:db8::/32"),
                                       dry_run=False, client=rx.client())
    ex, pol, ring, led = _env(tmp_path, adapter)
    act = _ip_action()
    rehearsal = ex.rehearse_rollback(act)
    assert rehearsal.ok and rehearsal.checks == {"apply_request_signed": True, "withdraw_request_signed": True}
    dec = authorize(act, pol, ring, safe_mirror(act), True, now=T0)
    assert dec.allowed, dec.failed_checks
    rec = ex.execute(act, dec, "alice@isp")
    assert rec.status is ExecutionStatus.APPLIED and rx.verified == [True]
    body = json.loads(rx.requests[0].content)
    assert body["event"] == "aegis.mitigation.apply" and len(body["rules"]) == 1   # only the IPv4 aggregate
    back = ex.rollback(act.action_id, actor="bob@isp")
    assert back.status is ExecutionStatus.ROLLED_BACK
    assert json.loads(rx.requests[1].content)["event"] == "aegis.mitigation.withdraw" and rx.verified == [True, True]
    assert led.verify_chain(TENANT)[0]


def test_discard_needs_policy_scope_and_adapter_opt_in(tmp_path):
    adapter = MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10",), client=_no_network())
    ex, pol, ring, _ = _env(tmp_path, adapter, scope={"mitigation": ["rate_limit", "discard"]})
    act = _ip_action(scope={"mitigation": "discard"})
    assert not ex.rehearse_rollback(act).ok
    dec = authorize(act, pol, ring, safe_mirror(act), True, now=T0)
    assert dec.allowed
    rec = ex.execute(act, dec, "alice@isp")
    assert rec.status is ExecutionStatus.FAILED and "only rate-limits" in rec.reason
    # a policy that does not approve discard refuses it before any adapter call
    signer, ring2 = signer_and_ring("op-key-2")
    pol2 = policy(signer, approved_scope={"legal_bases": ["operator_tos_security_clause"],
                                          "mitigation": ["rate_limit"]})
    assert "scope_exceeds_approved" in authorize(act, pol2, ring2, safe_mirror(act), True, now=T0).failed_checks
    ok = MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10",), allow_discard=True,
                                  client=_no_network())
    assert ok.rules(act)[0]["action"]["kind"] == "discard"


def test_adapter_configuration_is_validated():
    with pytest.raises(ValueError):
        MitigationRequestAdapter(URL, SECRET, source_prefixes=())
    with pytest.raises(ValueError):
        MitigationRequestAdapter(URL, SECRET, source_prefixes=("100.64.0.0/10",), rate_bytes_per_s=0)
    with pytest.raises(ValueError):
        MitigationRequestAdapter("http://x.example", SECRET, source_prefixes=("100.64.0.0/10",))
    six = MitigationRequestAdapter(URL, SECRET, source_prefixes=("2001:db8::/32",), client=_no_network())
    assert not six.rehearse_rollback(_ip_action(), now=T0).ok      # no aggregate of the target's family
    assert T0 + timedelta(hours=12) == _ip_action().expires_at
