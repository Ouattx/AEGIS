"""Drafting from VERIFIED cases: deterministic generator, fake LLM, fallback and safety."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from aegis.api.topology import parse_topology
from aegis.contracts.models import CaseState
from aegis.detengine import (
    BacktestConfig,
    CaseMaterial,
    DetectionEngineering,
    DeterministicDrafter,
    DraftingError,
    LLMDrafter,
    RuleDrafter,
    RuleLifecycleError,
    RuleRegistry,
    RuleState,
    sign_approval,
    was_verified,
)
from aegis.oracle.llm import LLMResponse
from test_detengine_support import (
    T0,
    TENANT,
    Clock,
    fv,
    ioc_evidence,
    make_stores,
    synthetic_dataset,
    verified_case,
)

TOPO = parse_topology({"topology_id": "t", "complete": True, "prefixes": ["203.0.113.0/24", "198.18.0.0/16"],
                       "hosts": [{"ip": "203.0.113.9", "kind": "dedicated", "hostnames": ["cfg.badbox.example"]},
                                 {"ip": "198.18.0.10", "kind": "shared_cdn", "hostnames": ["a.example", "b.example"]}]})


class FakeLLM:
    model = "claude-sonnet-5-5"

    def __init__(self, reply: str | None):
        self.reply = reply
        self.calls: list[dict] = []

    def complete(self, *, system, messages, max_tokens):
        self.calls.append({"system": system, "messages": messages, "max_tokens": max_tokens})
        if self.reply is None:
            return None
        return LLMResponse(text=self.reply, input_tokens=10, output_tokens=10, model=self.model)


def beacon_windows(n: int = 4, entity: str = "p_case"):
    return tuple(fv(entity, T0 + timedelta(days=1, hours=h), beacon_period_log=2.778, beacon_robust_cv=0.08,
                    beacon_events=40, beacon_duty=0.9, beacon_dst_prevalence=0.01, nxdomain_rate=0.02,
                    rare_dst_frac=0.9, zero_reply_frac=0.0) for h in range(n))


def population(n: int = 200):
    return [fv(f"p_pop{i}", T0 + timedelta(hours=12), device_class="phone", beacon_period_log=1.5 + (i % 10) / 10,
               beacon_robust_cv=0.5 + (i % 5) / 10, beacon_events=10, beacon_duty=0.6,
               beacon_dst_prevalence=0.4, nxdomain_rate=0.02 + (i % 7) / 100, rare_dst_frac=0.1 + (i % 9) / 30,
               zero_reply_frac=0.0) for i in range(n)]


def material(**kw) -> CaseMaterial:
    evs = kw.pop("evidences", [ioc_evidence("cfg.badbox.example"), ioc_evidence("203.0.113.9", typ="ip"),
                               ioc_evidence("198.18.0.10", typ="ip"),
                               ioc_evidence("weak.example", confidence=0.2),
                               ioc_evidence("contra.example", contradicted=True)])
    case = kw.pop("case", None) or verified_case(evs)
    return CaseMaterial(case=case, evidences=tuple(evs), windows=kw.pop("windows", beacon_windows()), **kw)


def test_only_verified_cases_are_material():
    evs = [ioc_evidence()]
    for state in (CaseState.NEW, CaseState.INVESTIGATING, CaseState.REJECTED, CaseState.INCONCLUSIVE):
        case = verified_case(evs, state=state)
        assert not was_verified(case)
        with pytest.raises(DraftingError) as exc:
            DeterministicDrafter().draft(CaseMaterial(case=case, evidences=tuple(evs)))
        assert exc.value.failed[0].startswith("case_not_verified")
    assert was_verified(verified_case(evs, state=CaseState.CLOSED))
    # closed without ever being verified does not count
    closed = verified_case(evs, state=CaseState.CLOSED).model_copy(update={"decisions": []})
    assert not was_verified(closed)


def test_material_must_belong_to_the_case_and_tenant():
    ev = ioc_evidence()
    case = verified_case([ev])
    with pytest.raises(DraftingError) as exc:
        DeterministicDrafter().draft(CaseMaterial(case=case, evidences=(ev, ioc_evidence("x.example"))))
    assert "evidence_not_in_case" in exc.value.failed
    with pytest.raises(DraftingError) as exc:
        DeterministicDrafter().draft(CaseMaterial(case=case, evidences=(ev,), windows=(fv(tenant_id="other"),)))
    assert "window_tenant_mismatch" in exc.value.failed


def test_deterministic_destination_rule():
    props = DeterministicDrafter().draft(material(), hosting=TOPO)
    dest = [p for p in props if p.spec.destinations is not None]
    assert len(dest) == 1
    pats = {(p.kind, p.value, p.verified_contact) for p in dest[0].spec.destinations.patterns}
    # dedicated IP kept, shared CDN IP dropped, weak and contradicted indicators ignored
    assert pats == {("domain_suffix", "cfg.badbox.example", True), ("ip", "203.0.113.9", False)}
    assert dest[0].drafter_kind == "generator" and dest[0].actor.startswith("generator:")
    assert len(dest[0].evidence_ids) == 2
    # without hosting knowledge no IP is proposed at all
    no_topo = [p for p in DeterministicDrafter().draft(material()) if p.spec.destinations is not None][0]
    assert {p.kind for p in no_topo.spec.destinations.patterns} == {"domain_suffix"}


def test_deterministic_periodicity_and_envelope_rules():
    m = material()
    props = DeterministicDrafter().draft(m, population(), hosting=TOPO)
    per = [p for p in props if p.spec.periodicity is not None][0].spec
    assert per.periodicity.min_period_s < 600 < per.periodicity.max_period_s
    assert per.periodicity.max_dst_prevalence is not None and per.periodicity.max_dst_prevalence <= 0.05
    assert per.baseline.device_classes == ("android_tv",)
    env = [p for p in props if p.spec.conditions][0].spec
    feats = {c.feature for c in env.conditions}
    assert "rare_dst_frac" in feats and "nxdomain_rate" not in feats   # only separated features
    assert env.label == "c2_beaconing"
    # deterministic: same input, same rules
    again = DeterministicDrafter().draft(m, population(), hosting=TOPO)
    assert [p.spec.sha256 for p in again] == [p.spec.sha256 for p in props]


def test_no_reference_means_no_envelope_rule():
    props = DeterministicDrafter().draft(material(), hosting=TOPO)
    assert not any(p.spec.conditions for p in props)


def test_llm_proposals_are_parsed_and_reassigned():
    reply = "Here you go:\n```json\n" + json.dumps({"rules": [
        {"rule_id": "dga-nx@v1-takeover", "title": "Rare beacon", "label": "c2_beaconing",
         "periodicity": {"min_period_s": 300, "max_period_s": 1200, "max_dst_prevalence": 0.02},
         "baseline": {"device_classes": ["android_tv"]}, "rationale": "timer"},
        {"rule_id": "x", "title": "bad", "label": "c2_beaconing", "conditions": [{"feature": "nope", "op": "gt",
                                                                                   "value": 1}]},
        "not an object",
    ]}) + "\n```"
    llm = FakeLLM(reply)
    props, rejected, status = LLMDrafter(llm).draft(material(), population())
    assert status == "ok" and len(props) == 1 and len(rejected) == 2
    p = props[0]
    assert p.drafter_kind == "llm" and p.actor == "llm:claude-sonnet-5-5"
    assert p.spec.rule_id.startswith("llm-")            # a model cannot target an existing rule id
    # case data is fenced as untrusted, and the instructions say so
    user = llm.calls[0]["messages"][0]["content"]
    assert user.startswith("<case_data>") and "untrusted" in llm.calls[0]["system"]


@pytest.mark.parametrize("reply, status", [(None, "no_response"), ("I cannot help", "unparseable"),
                                           ('{"rules": []}', "empty")])
def test_llm_failure_falls_back_to_deterministic(reply, status):
    batch = RuleDrafter(FakeLLM(reply)).draft(material(), population(), hosting=TOPO)
    assert batch.llm_status == status and not batch.llm_used
    assert batch.proposals and all(p.drafter_kind == "generator" for p in batch.proposals)


def test_no_llm_configured_uses_generator():
    batch = RuleDrafter(None).draft(material(), hosting=TOPO)
    assert batch.llm_status == "not_configured" and all(p.drafter_kind == "generator" for p in batch.proposals)
    both = RuleDrafter(FakeLLM('{"rules": [{"title": "t", "label": "c2_beaconing", "destinations": '
                               '{"patterns": [{"kind": "domain_exact", "value": "cfg.badbox.example"}]}}]}'),
                       mode="both").draft(material(), hosting=TOPO)
    assert {p.drafter_kind for p in both.proposals} == {"llm", "generator"}
    det = RuleDrafter(FakeLLM("{}"), mode="deterministic").draft(material(), hosting=TOPO)
    assert det.llm_status == "disabled"


@pytest.fixture
def workbench(tmp_path):
    st = make_stores(tmp_path)
    clock = Clock()
    reg = RuleRegistry(st.docs, st.ledger, approver_keyring=st.keyring, clock=clock)
    ds = synthetic_dataset(n_benign=200, hard_negative_hits=0)
    return st, reg, ds


def test_workbench_drafts_validates_and_backtests(workbench):
    st, reg, ds = workbench
    unsafe = json.dumps({"rules": [
        {"title": "TV boxes", "label": "c2_beaconing", "baseline": {"device_classes": ["android_tv"]}},
        {"title": "CDN", "label": "c2_beaconing", "destinations": {"patterns": [{"kind": "ip",
                                                                                 "value": "198.18.0.10"}]}},
        {"title": "NX", "label": "dga_activity",
         "conditions": [{"feature": "nxdomain_rate", "op": "ge", "value": 0.6}]},
    ]})
    wb = DetectionEngineering(reg, drafter=RuleDrafter(FakeLLM(unsafe)), datasets=[ds],
                              backtest_config=BacktestConfig(min_holdout_device_days=50))
    out = wb.draft_from_case(TENANT, material(), hosting=TOPO)
    errs = sorted(e for r in out.rejected for e in r["errors"])
    assert "device_class_only" in errs and "shared_hosting_ip:198.18.0.10" in errs
    assert len(out.records) == 1 and out.llm_used
    rec = out.records[0]
    assert rec.state is RuleState.BACKTESTED and rec.drafter_kind == "llm"
    assert rec.source_case_ids == [out.as_dict()["case_id"]]
    report = out.backtests[rec.ref][0]
    assert report.metrics.recall == 1.0 and report.synthetic
    # the LLM can neither approve nor promote its own draft
    with pytest.raises(RuleLifecycleError):
        reg.approval_request(TENANT, rec.ref, purpose="approve", approver=rec.drafted_by, reason="mine")
    req = reg.approval_request(TENANT, rec.ref, purpose="approve", approver="alice", reason="reviewed")
    assert reg.approve(TENANT, sign_approval(req, st.alice)).state is RuleState.APPROVED


def test_workbench_without_datasets_leaves_drafts(workbench):
    _, reg, _ = workbench
    wb = DetectionEngineering(reg)
    out = wb.draft_from_case(TENANT, material(), hosting=TOPO)
    assert out.records and all(r.state is RuleState.DRAFT for r in out.records)
    assert out.notes and "cannot be approved" in out.notes[0]
    with pytest.raises(ValueError):
        wb.draft_from_case("other", material(), hosting=TOPO)
    with pytest.raises(ValueError):
        wb.rebacktest(TENANT, out.records[0].ref)


def test_workbench_rebacktest_and_reference(workbench):
    _, reg, ds = workbench
    wb = DetectionEngineering(reg, datasets=[ds], backtest_config=BacktestConfig(min_holdout_device_days=50))
    assert wb.reference_windows() and all(f.window_end <= ds.default_split() for f in wb.reference_windows())
    out = wb.draft_from_case(TENANT, material(), hosting=TOPO)
    rec = wb.rebacktest(TENANT, out.records[0].ref)
    assert rec.state is RuleState.BACKTESTED and rec.backtest_ids != out.records[0].backtest_ids
    assert wb.engine(TENANT).rules == ()            # nothing runs before human approval + shadow


def test_material_from_stored_sentinel_evidence():
    from aegis.contracts.models import Evidence, EvidenceKind
    from aegis.detengine import material_from_case, windows_from_evidence

    def obs(entity: str, hours: int, **feats) -> Evidence:
        return Evidence(tenant_id=TENANT, kind=EvidenceKind.OBSERVATION, origin_source="sensor:x",
                        source_independence_group="operator-telemetry", collected_at=T0, summary="window",
                        authorization_id="auth-1",
                        payload={"entity_pseudonym": entity, "device_class": "android_tv", "window": "24h",
                                 "window_end": (T0 + timedelta(hours=hours)).isoformat(), "event_count": 50,
                                 "features": feats})
    evs = [ioc_evidence(), obs("p_case", 30, nxdomain_rate=0.8, rare_dst_frac=0.9, bogus=1.0),
           obs("p_case", 26, nxdomain_rate=float("nan"), rare_dst_frac=0.85),
           Evidence(tenant_id=TENANT, kind=EvidenceKind.OBSERVATION, origin_source="x",
                    source_independence_group="g", collected_at=T0, summary="broken", authorization_id="a",
                    payload={"features": {"nxdomain_rate": 1.0}})]
    wins = windows_from_evidence(evs)
    assert [w.window_end for w in wins] == [T0 + timedelta(hours=26), T0 + timedelta(hours=30)]
    assert wins[1].values["nxdomain_rate"] == 0.8 and wins[1].values["beacon_duty"] is None
    assert wins[0].values["nxdomain_rate"] is None and wins[0].missing["nxdomain_rate"]
    m = material_from_case(verified_case(evs), evs)
    assert len(m.windows) == 2 and m.entities() == {"p_case"}
    props = DeterministicDrafter().draft(m, population(), hosting=TOPO)
    assert any(p.spec.destinations for p in props) and any(p.spec.conditions for p in props)
