"""Composition root: persistence across restarts, expiry sweeps, topology, coverage, config uploads."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aegis.api.topology import TopologyError, parse_topology
from aegis.contracts.models import CaseState, ObservationEvent, SourceKind, Vantage
from aegis.lab.iocs import lab_signer
from aegis.lab.topology import generate_topology
from aegis.reports.inputs import ReportPeriod
from aegis.service import AegisService, ConflictError, InvalidInputError, NotFoundError

from test_api_helpers import (
    C2_DOMAIN,
    make_service,
    make_settings,
    operator_signer,
    prepare_enforceable,
    propose_body,
    seed_case,
    signed_policy,
    verify_case,
)

T = "isp-a"


def _restart(svc: AegisService) -> AegisService:
    svc.close()
    return AegisService(svc.settings, load_default_model=False, use_env_llm=False)


def test_configuration_survives_restart(tmp_path):
    svc = make_service(tmp_path)
    svc.register_source(T, "admin", source_id="nf", source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
                        collection_authorization_id="auth-1")
    signer = lab_signer(7)
    svc.trust_key("ioc", signer.key_id, signer.public_pem())
    from aegis.lab.corpus import DEFAULT_START
    from aegis.lab.iocs import build_ioc_bundle
    bundle = build_ioc_bundle(generate_topology(7), start=DEFAULT_START, signer=signer)
    svc.load_ioc_bundle(T, "admin", bundle)
    svc.load_topology(T, "admin", generate_topology(7).to_dict())
    svc.set_tenant_pseudonym_key(T, b"k" * 32)
    pseudo = svc.key_provider.pseudonymizer(T).pseudonym("02:00:5e:00:00:01")
    ledger_key = svc.ledger_signer.public_pem()

    again = _restart(svc)
    assert [c.source_id for c in again.list_sources(T)] == ["nf"]
    assert again.ioc_status(T)["bundle_id"] == bundle["bundle_id"]
    assert again.topology_status(T)["topology_id"] == "lab-topology-7"
    assert again.key_provider.pseudonymizer(T).pseudonym("02:00:5e:00:00:01") == pseudo
    assert again.ledger_signer.public_pem() == ledger_key
    assert again.verify_ledger(T)["ok"] is True
    assert (tmp_path / "keys" / "pseudonym" / f"{T}.key").stat().st_mode & 0o777 == 0o600


def test_live_execution_recovered_and_rolled_back_after_restart(tmp_path):
    svc = make_service(tmp_path)
    _, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    body = propose_body(case_id)
    body.pop("expires_in_hours")
    action = svc.propose_action(T, "alice", expires_at=svc.clock() + timedelta(hours=2), **body)
    svc.simulate_action(T, "alice", action.action_id)
    svc.authorize_action(T, "alice", action.action_id)
    svc.decide_action(T, "bob", action.action_id, approve=True, reason="ok")
    out = svc.execute_action(T, "bob", action.action_id)
    assert out["case_state"] == "EXECUTED"

    again = _restart(svc)
    assert action.action_id in again.executor.active()
    res = again.rollback_action(T, "bob", action.action_id, reason="restore after restart")
    assert res["execution"].status.value == "rolled_back"
    assert again.get_case(T, case_id).state is CaseState.ROLLED_BACK
    again.rollback_action(T, "bob", action.action_id, reason="again")  # idempotent
    with pytest.raises(ConflictError):
        again.execute_action(T, "bob", action.action_id)
    with pytest.raises(NotFoundError):
        again.rollback_action(T, "bob", "unknown-action", reason="x")


def test_sweep_expires_stale_approvals(tmp_path):
    now = [datetime.now(timezone.utc)]
    svc = AegisService(make_settings(tmp_path), load_default_model=False, use_env_llm=False,
                       clock=lambda: now[0])
    _, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    body = propose_body(case_id)
    body.pop("expires_in_hours")
    action = svc.propose_action(T, "alice", expires_at=now[0] + timedelta(hours=1), **body)
    svc.simulate_action(T, "alice", action.action_id)
    svc.authorize_action(T, "alice", action.action_id)
    svc.decide_action(T, "bob", action.action_id, approve=True, reason="ok")
    assert svc.sweep_expired() == []
    now[0] += timedelta(hours=2)
    assert svc.sweep_expired() == [case_id]
    assert svc.get_case(T, case_id).state is CaseState.EXPIRED
    with pytest.raises(ConflictError):
        svc.execute_action(T, "bob", action.action_id)


def test_sweep_rolls_back_expired_live_enforcement(tmp_path):
    now = [datetime.now(timezone.utc)]
    svc = AegisService(make_settings(tmp_path), load_default_model=False, use_env_llm=False,
                       clock=lambda: now[0])
    _, case_id = seed_case(svc, T)
    verify_case(svc, T, case_id)
    signer = operator_signer(svc)
    svc.load_policy(T, "admin", signed_policy(svc, T, signer))
    prepare_enforceable(svc, T)
    body = propose_body(case_id)
    body.pop("expires_in_hours")
    action = svc.propose_action(T, "alice", expires_at=now[0] + timedelta(hours=1), **body)
    svc.simulate_action(T, "alice", action.action_id)
    svc.authorize_action(T, "alice", action.action_id)
    svc.decide_action(T, "bob", action.action_id, approve=True, reason="ok")
    svc.execute_action(T, "bob", action.action_id)
    now[0] += timedelta(hours=2)
    assert svc.sweep_expired() == [case_id]
    assert svc.get_case(T, case_id).state is CaseState.EXPIRED
    assert svc.executor.active() == []


def test_untrusted_or_invalid_uploads_are_rejected(tmp_path):
    svc = make_service(tmp_path)
    rogue = lab_signer(99)
    from aegis.lab.corpus import DEFAULT_START
    from aegis.lab.iocs import build_ioc_bundle
    with pytest.raises(InvalidInputError) as e:
        svc.load_ioc_bundle(T, "admin", build_ioc_bundle(generate_topology(7), start=DEFAULT_START, signer=rogue))
    assert e.value.code == "bundle_rejected"
    from aegis.provenance.signing import Signer
    untrusted = Signer.generate("not-trusted")
    with pytest.raises(InvalidInputError) as e:
        svc.load_policy(T, "admin", signed_policy(svc, T, untrusted))
    assert e.value.failed == ["policy_signature_invalid"]
    trusted = operator_signer(svc)
    doc = signed_policy(svc, T, trusted)
    doc["max_targets_per_action"] = 500  # tampered after signing
    with pytest.raises(InvalidInputError):
        svc.load_policy(T, "admin", doc)
    with pytest.raises(InvalidInputError):
        svc.load_policy(T, "admin", {"policy_id": "x"})
    svc.load_policy(T, "admin", signed_policy(svc, T, trusted))
    with pytest.raises(ConflictError):
        svc.load_policy(T, "admin", signed_policy(svc, T, trusted))
    with pytest.raises(InvalidInputError):
        svc.load_topology(T, "admin", {"topology_id": "t", "hosts": [{"ip": "nope"}]})
    with pytest.raises(InvalidInputError):
        svc.trust_key("policy", "../escape", trusted.public_pem())


def test_topology_parsing():
    topo = parse_topology(generate_topology(7).to_dict())
    lab = generate_topology(7)
    ip = next(iter(lab.hosts))
    assert topo.covers(ip) and topo.is_shared(ip) == lab.is_shared(ip)
    assert topo.resolve(lab.domains()[0]) == lab.resolve(lab.domains()[0])
    t = parse_topology({"topology_id": "x", "prefixes": ["2001:db8::/32"],
                        "hosts": [{"ip": "2001:db8::1", "hostnames": ["A.example."], "shared": False}]})
    assert t.covers("2001:db8::1") and not t.covers("198.51.100.1") and t.resolve("a.example") == ["2001:db8::1"]
    assert t.is_shared("2001:db8::1") is False and t.is_shared("2001:db8::2") is None
    for bad in ({"hosts": []}, {"topology_id": "x", "hosts": "no"},
                {"topology_id": "x", "hosts": [{"ip": "198.51.100.1"}]},
                {"topology_id": "x", "prefixes": ["bad"], "hosts": []},
                {"topology_id": "x", "complete": "yes", "hosts": []}, []):
        with pytest.raises(TopologyError):
            parse_topology(bad)


def _event(tenant, entity, ts, device_class="smart_tv", source="nf"):
    return ObservationEvent(tenant_id=tenant, observed_at=ts, ingested_at=ts, source_id=source,
                            source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE,
                            collection_authorization_id="auth-1", entity_pseudonym=entity,
                            device_class=device_class, flow={"dst_ip": "198.51.100.1"},
                            retention_until=ts + timedelta(days=30), integrity_sha256="a" * 64)


def test_coverage_is_period_scoped_and_accumulates(tmp_path):
    svc = make_service(tmp_path)
    d1 = datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
    e1, e2 = "p_" + "1" * 32, "p_" + "2" * 32
    svc._update_coverage(T, [_event(T, e1, d1), _event(T, e1, d1 + timedelta(hours=1)),
                             _event(T, e2, d1, "console")])
    svc._update_coverage(T, [_event(T, e1, d1 + timedelta(days=1))])
    svc._update_coverage("isp-b", [_event("isp-b", e1, d1)])
    cov = svc.coverage(T, ReportPeriod(d1.replace(hour=0), d1.replace(hour=0) + timedelta(days=2)))
    assert (cov.devices_observed, cov.device_days, cov.events) == (2, 3, 4)
    assert cov.devices_by_class == {"console": 1, "smart_tv": 1}
    day1 = svc.coverage(T, ReportPeriod(d1.replace(hour=0), d1.replace(hour=0) + timedelta(days=1)))
    assert (day1.devices_observed, day1.device_days, day1.events) == (2, 2, 3)


def test_not_found_and_invalid_inputs(tmp_path):
    svc = make_service(tmp_path)
    with pytest.raises(NotFoundError):
        svc.get_case(T, "nope")
    with pytest.raises(NotFoundError):
        svc.latest_investigation(T, "nope")
    with pytest.raises(InvalidInputError):
        svc.register_source("bad tenant!", "admin", source_id="x", source_kind="dns", vantage="device",
                            collection_authorization_id="a")
    _, case_id = seed_case(svc, T)
    with pytest.raises(InvalidInputError):
        svc.transition_case(T, case_id, CaseState.EXECUTED, "alice", "x")
    with pytest.raises(InvalidInputError):
        svc.add_case_note(T, case_id, "alice", "   ")
    with pytest.raises(NotFoundError):
        svc.graph_view(T, C2_DOMAIN)
