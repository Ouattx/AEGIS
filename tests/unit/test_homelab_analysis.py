"""AEGIS home lab: timers, infrastructure + feed matching, verdict policy, evidence trail,
Box Lab report, crowd mixing and CLI. Synthetic fixtures only (``aegis.homelab.synthetic``).

Safety properties asserted here:
* a timer alone never produces an accusation; BENIGN is never produced;
* MALICIOUS needs two independent origins (a signed feed witness + the capture's own behavior),
  and SENTINEL's indicator-driven alerts do not count as the second witness;
* contradicted, expired, lookup-only and unverified-list matches are never witnesses;
* the device class never changes the outcome;
* crowd-mixing output is labelled mixed-synthetic and never becomes findings or ledger entries.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis.contracts.models import Finding, Verdict
from aegis.homelab import (
    CrowdMixConfig,
    HomeLabConfig,
    SyntheticBoxSpec,
    analyze_single_home,
    crowd_mix,
    import_capture,
    load_local_list,
    load_usage_windows,
    open_lab_store,
    render_box_report,
    run_homelab,
    verify_run,
    write_synthetic_capture,
)
from aegis.homelab.cli import main as cli_main
from aegis.homelab.crowd import COPY_PREFIX
from aegis.homelab.infra import analyze_infrastructure
from aegis.homelab.timers import analyze_timers
from aegis.homelab.verdict import decide
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.lab.iocs import sign_bundle
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.rules import load_bundle

START = datetime(2026, 10, 20, 6, tzinfo=timezone.utc)
KEY = b"homelab-test-key-0123456789abcdef"
BEACON = "sync.tvbox-telemetry.test"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ind(iid: str, typ: str, value: str, *, verdict: str = "malicious", group: str = "grp:alpha",
         source: str = "feed:test_alpha", conf: float = 0.9, expired: bool = False) -> dict:
    exp = START - timedelta(days=1) if expired else START + timedelta(days=60)
    first = START - timedelta(days=200) if expired else START - timedelta(days=10)
    last = START - timedelta(days=100) if expired else START - timedelta(days=1)
    return {"indicator_id": iid, "type": typ, "value": value, "verdict": verdict,
            "threat_label": "c2_beaconing" if verdict == "malicious" else None, "malware_family": None,
            "confidence": conf, "first_seen": _iso(first), "last_seen": _iso(last), "expires_at": _iso(exp),
            "source": source, "source_group": group, "tags": []}


def make_bundle(indicators: list[dict]):
    signer = Signer.generate("homelab-test-feed")
    ring = KeyRing()
    ring.add(signer.key_id, signer.public_pem())
    raw = {"schema": "aegis.ioc_bundle/1", "bundle_id": "homelab-test", "version": "1", "issuer": "test",
           "issued_at": _iso(START - timedelta(hours=1)), "indicators": indicators}
    return load_bundle(sign_bundle(raw, signer), ring)


FEED = [
    _ind("ind-beacon", "domain", BEACON),
    _ind("ind-api", "domain", "api.streaming-service.example", group="grp:beta", source="feed:test_beta", conf=0.8),
    _ind("ind-api-allow", "domain", "api.streaming-service.example", verdict="benign", group="grp:operator",
         source="feed:operator_allowlist", conf=0.95),
    _ind("ind-ntp-old", "ip", "203.0.113.123", group="grp:delta", source="feed:test_delta", expired=True),
]


@pytest.fixture(scope="module")
def infected(tmp_path_factory):
    d = tmp_path_factory.mktemp("infected")
    sc = write_synthetic_capture(d, SyntheticBoxSpec(start=START, hours=24, nxdomain_burst=True))
    imp = import_capture(d, HomeLabConfig(device_labels={"10.42.0.23": "box <one>"}), pseudonymizer=Pseudonymizer(KEY))
    store = open_lab_store(None)
    a = analyze_single_home(imp, usage=load_usage_windows(d / "usage.json"), bundle=make_bundle(FEED),
                            local_list=load_local_list("# mine\nupdates.store-platform.example\n"), store=store)
    yield sc, imp, a, store
    store.close()


@pytest.fixture(scope="module")
def clean(tmp_path_factory):
    d = tmp_path_factory.mktemp("clean")
    write_synthetic_capture(d, SyntheticBoxSpec(start=START, hours=24, beacon=False, seed=11))
    return d


def _dev(a):
    assert len(a.devices) == 1
    return a.devices[0]


# ============================================================================ timers

def test_timer_analysis_recovers_periods_and_idle_behavior(infected):
    sc, imp, a, _ = infected
    t = {c.display: c for c in _dev(a).timers.candidates}
    beacon = t[BEACON]
    assert beacon.is_timer and abs(beacon.period_s - 600) / 600 < 0.05
    assert beacon.activity.pattern == "runs_while_idle" and beacon.activity.idle_hour_coverage == 1.0
    assert t["hb.streaming-service.example"].activity.pattern == "active_only"
    assert abs(t["hb.streaming-service.example"].period_s - 60) < 5
    assert t["time.vendor-ntp.example"].is_timer and abs(t["time.vendor-ntp.example"].period_s - 1024) < 60
    assert not t["updates.store-platform.example"].is_timer                  # Poisson traffic is not a timer
    assert beacon.z_curve and len(beacon.z_curve) == len(beacon.periods) and beacon.lomb_curve
    assert sum(beacon.interarrival_counts) == beacon.n_events - 1


def test_timer_analysis_without_usage_says_so(infected):
    _, imp, _, _ = infected
    pseudo = next(iter(imp.devices))
    ta = analyze_timers(imp.events, pseudo, start=imp.start, end=imp.end)
    assert not ta.usage_available and all(c.activity is None for c in ta.candidates)
    assert any("no usage windows" in n for n in ta.notes)
    assert ta.idle_timers() == []


def test_short_capture_identifies_no_long_periods(infected):
    _, imp, _, _ = infected
    pseudo = next(iter(imp.devices))
    end = imp.start + timedelta(minutes=10)
    ta = analyze_timers([e for e in imp.events if e.observed_at < end], pseudo, start=imp.start, end=end)
    assert not ta.timers


# ============================================================================ infrastructure + feeds

def test_feed_matching_semantics(infected):
    _, _, a, _ = infected
    inf = _dev(a).infra
    by = {d.display: d for d in inf.destinations}
    [w] = inf.witness_matches
    assert w.value == BEACON and w.verified_contact and w.state == "active" and not w.contradicted
    api = [m for m in by["api.streaming-service.example"].matches if m.feed_kind == "signed_bundle"]
    assert len(api) == 1 and api[0].contradicted and not api[0].is_witness
    assert api[0].effective_confidence == pytest.approx(0.8 * 0.05)
    ntp = [m for m in by["time.vendor-ntp.example"].matches]
    assert ntp and ntp[0].state == "expired" and not ntp[0].is_witness
    local = [m for m in by["updates.store-platform.example"].matches]
    assert local and local[0].feed_kind == "unverified_local_list" and not local[0].is_witness
    assert len(inf.nxdomain_names) == 60
    assert by[BEACON].ips == {"198.51.100.77"} and by[BEACON].idle_contacts > by[BEACON].active_contacts


def test_lookup_only_match_and_hardcoded_resolver(infected):
    _, imp, _, _ = infected
    pseudo = next(iter(imp.devices))
    nx = sorted({e.dns.qname for e in imp.events if e.dns is not None and e.dns.rcode == "NXDOMAIN"})[0]
    flow = next(e for e in imp.events if e.flow is not None)
    resolver = flow.model_copy(update={"flow": flow.flow.model_copy(update={"dst_ip": "192.0.2.53", "dst_port": 53}),
                                       "event_id": "x-resolver"})
    inf = analyze_infrastructure(imp.events + [resolver], pseudo, as_of=imp.end, gateway_ip="10.42.0.1",
                                 bundle=make_bundle([_ind("ind-nx", "domain", nx)]))
    [m] = [m for d in inf.destinations for m in d.matches]
    assert m.value == nx and not m.verified_contact and not m.is_witness and m.is_weak
    assert inf.external_resolvers == ["192.0.2.53"]
    assert any(d.contacted_without_lookup and "192.0.2.53" in d.ips for d in inf.destinations)


# ============================================================================ verdict policy

def test_infected_box_is_malicious_only_with_two_independent_origins(infected):
    _, _, a, _ = infected
    v = _dev(a).verdict
    assert v.verdict == Verdict.MALICIOUS and v.requires_review
    assert v.independent_origins == 2 and set(v.origins) == {"grp:alpha", "operator-telemetry"}
    assert any(BEACON in r for r in v.reasons)
    assert any("SYNTHETIC" in c for c in v.caveats)


def test_timers_alone_never_accuse_and_benign_is_never_produced(clean):
    imp = import_capture(clean, pseudonymizer=Pseudonymizer(KEY))
    a = analyze_single_home(imp, usage=load_usage_windows(clean / "usage.json"), model=None)
    v = _dev(a).verdict
    assert _dev(a).timers.idle_timers()                                      # benign timers run while idle ...
    assert v.verdict == Verdict.ABSTAIN                                      # ... and are not an accusation
    assert v.headline.startswith("No conclusion") and any("idle" in s for s in v.signals)
    assert any("clean" in c for c in v.caveats)
    assert a.ledger is None                                                  # no store: nothing claimed as anchored


def test_feed_match_without_corroborating_behavior_is_only_suspicious(clean):
    imp = import_capture(clean, pseudonymizer=Pseudonymizer(KEY))
    bundle = make_bundle([_ind("ind-upd", "domain", "updates.store-platform.example")])
    a = analyze_single_home(imp, usage=load_usage_windows(clean / "usage.json"), bundle=bundle)
    d = _dev(a)
    assert not any(c.display == "updates.store-platform.example" for c in d.timers.timers)
    # SENTINEL's own indicator rule fires on the same feed entry: it must not count as a second witness
    assert d.verdict.verdict == Verdict.SUSPICIOUS
    assert d.verdict.independent_origins == 1


def test_device_class_never_changes_the_outcome(clean):
    out = []
    for cls in (None, "android_tv", "phone"):
        imp = import_capture(clean, HomeLabConfig(device_class=cls), pseudonymizer=Pseudonymizer(KEY))
        a = analyze_single_home(imp, usage=load_usage_windows(clean / "usage.json"), model=None)
        d = _dev(a)
        out.append((d.verdict.verdict, d.verdict.signals, [(c.key, c.period_s, c.is_timer) for c in d.timers.timers]))
    assert out[0] == out[1] == out[2]


def test_insufficient_capture_abstains(infected):
    _, imp, a, _ = infected
    d = _dev(a)
    v = decide(entity_pseudonym=d.entity_pseudonym, span_s=3600, n_events=500, timers=d.timers, infra=d.infra,
               sentinel_findings=[])
    assert v.verdict == Verdict.ABSTAIN and "below the minimum" in v.reasons[0]


def test_mostly_quarantined_capture_abstains_and_partial_quarantine_is_disclosed(infected):
    _, _, a, _ = infected
    d = _dev(a)
    common = dict(entity_pseudonym=d.entity_pseudonym, span_s=24 * 3600, n_events=500, timers=d.timers,
                  infra=d.infra, sentinel_findings=[])
    v = decide(**common, records_quarantined=900, records_total=1000, quarantine_reasons={"future_timestamp": 900})
    assert v.verdict == Verdict.ABSTAIN and "quarantined" in v.reasons[0]
    assert any("future_timestamp 900" in c for c in v.caveats)
    v2 = decide(**common, records_quarantined=10, records_total=1000, quarantine_reasons={"bad_record": 10})
    assert any("quarantined and not analysed" in c for c in v2.caveats)


def test_cli_synthetic_default_start_is_never_in_the_future(tmp_path, capsys):
    cap = tmp_path / "cap"
    assert cli_main(["synthetic", str(cap), "--hours", "7"]) == 0
    capsys.readouterr()
    manifest = json.loads((cap / "capture.json").read_text())
    assert datetime.fromisoformat(manifest["ended_at"]) <= datetime.now(timezone.utc)


def test_behavioral_sentinel_alert_corroborates_but_indicator_rule_does_not(infected):
    _, imp, a, _ = infected
    d = _dev(a)
    timers = d.timers.__class__(d.timers.entity_pseudonym, d.timers.start, d.timers.end, [], False, 0, "x")
    f = Finding(tenant_id="homelab", entity_pseudonym=d.entity_pseudonym, device_class="unknown",
                detector_version="t", label="c2_beaconing", verdict=Verdict.SUSPICIOUS, score=0.7,
                observed_window_start=imp.start, observed_window_end=imp.end, created_at=imp.end,
                expires_at=imp.end + timedelta(days=1))
    common = dict(entity_pseudonym=d.entity_pseudonym, span_s=imp.span_s, n_events=d.n_events, timers=timers,
                  infra=d.infra, sentinel_findings=[f])
    assert decide(**common, sentinel_rules={f.finding_id: "F1_ioc_corroborated"}).verdict == Verdict.SUSPICIOUS
    assert decide(**common, sentinel_rules={}).verdict == Verdict.SUSPICIOUS          # unknown rule: conservative
    assert decide(**common, sentinel_rules={f.finding_id: "F4_model_only"}).verdict == Verdict.MALICIOUS


# ============================================================================ evidence trail

def test_evidence_trail_is_hashed_ledgered_and_verifiable(infected):
    _, imp, a, store = infected
    d = _dev(a)
    assert a.ledger["verified"] and a.ledger["entries"] > 5
    assert all(len(e.sha256) == 64 for e in d.evidence)
    ids = {e.evidence_id for e in d.evidence}
    assert set(d.verdict.evidence_ids) | set(d.verdict.counterevidence_ids) <= ids
    for e in d.evidence:
        assert store.evidence.verify("homelab", e.evidence_id)
    kinds = {e.kind.value for e in d.evidence}
    assert {"observation", "ioc_match", "counter_hypothesis", "benign_baseline", "analyst_note"} <= kinds
    capture_ev = a.capture_evidence[0]
    hashes = {f["sha256"] for f in capture_ev.payload["files"]}
    assert {f.sha256 for f in imp.files} == hashes
    verdict_entries = store.ledger.entries("homelab", entry_type="homelab_verdict")
    assert len(verdict_entries) == 1 and verdict_entries[0].payload["verdict"] == "malicious"
    assert verdict_entries[0].payload["synthetic"] is True


def test_tampering_with_the_lab_ledger_is_detected(tmp_path):
    cap = tmp_path / "cap"
    write_synthetic_capture(cap, SyntheticBoxSpec(start=START, hours=7, sessions=((1.0, 1.0),)))
    run = run_homelab(cap, tmp_path / "out", model=None)
    assert verify_run(tmp_path / "out")["verified"]
    db = sqlite3.connect(tmp_path / "out" / "homelab-ledger.db")
    # an attacker with file access first removes the append-only guard, then rewrites the verdict
    for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'").fetchall():
        db.execute(f'DROP TRIGGER "{name}"')
    db.execute("UPDATE ledger_entries SET payload = replace(payload, 'abstain', 'benign') "
               "WHERE entry_type = 'homelab_verdict'")
    db.commit()
    db.close()
    res = verify_run(tmp_path / "out")
    assert not res["verified"] and res["first_bad_seq"] is not None
    assert run.analysis.devices[0].verdict.verdict == Verdict.ABSTAIN


# ============================================================================ report

def test_box_lab_report_is_self_contained_honest_and_escaped(infected):
    _, imp, a, _ = infected
    html = render_box_report(a, _dev(a))
    assert html.startswith("<!doctype html>") and "</html>" in html
    assert "<script" not in html.lower() and "http://" not in html and "https://" not in html
    assert "box &lt;one&gt;" in html and "box <one>" not in html
    assert "SYNTHETIC DATA" in html and "MALICIOUS (review)" in html
    for f in imp.files:
        assert f.sha256 in html
    assert a.ledger["head_hash"] in html
    for section in ("verdict", "capture", "timeline", "heartbeats", "destinations", "sentinel", "evidence", "limits"):
        assert f'id="{section}"' in html
    assert "MIXED-SYNTHETIC" not in html                                     # no crowd section requested
    assert html.count("<svg") >= 4
    assert "prefers-color-scheme: dark" in html


def test_no_scripture_in_homelab_outputs_code_or_docs(infected):
    _, _, a, _ = infected
    root = Path(__file__).resolve().parents[2]
    texts = [render_box_report(a, _dev(a))]
    for pattern in ("aegis/homelab/*", "deploy/homelab/*", "docs/homelab/*"):
        texts += [p.read_text(encoding="utf-8") for p in root.glob(pattern) if p.is_file() and p.suffix != ".pyc"]
    banned = ("Deuteronomy", "Exodus", "Proverbs", "Matthew", "Micah", "Luke 16", "ESV", "LORD")
    for t in texts:
        for word in banned:
            assert word not in t


# ============================================================================ crowd mixing

@pytest.fixture(scope="module")
def mixed(tmp_path_factory):
    d = tmp_path_factory.mktemp("mix")
    write_synthetic_capture(d, SyntheticBoxSpec(start=START, hours=10, sessions=((1.0, 1.0), (6.0, 1.0))))
    imp = import_capture(d, pseudonymizer=Pseudonymizer(KEY))
    pseudo = next(iter(imp.devices))
    return imp, crowd_mix(imp.events_for(pseudo), start=imp.start, end=imp.end,
                          cfg=CrowdMixConfig(n_copies=10, n_lines=200, seed=3))


def test_crowd_mix_is_labelled_and_shows_the_beacon_resonating(mixed):
    imp, res = mixed
    assert res.data_class == "mixed_synthetic" and "MIXED-SYNTHETIC" in res.label
    d = res.to_dict()
    assert d["data_class"] == "mixed_synthetic" and d["label"].startswith("MIXED-SYNTHETIC")
    assert res.report.status == "ok" and res.copies == 10 and res.background_lines == 200
    beacon = [c for c in res.capture_campaigns if f"d:{BEACON}" in c.destinations]
    assert beacon and beacon[0].capture_copies >= 5
    # real capture destinations are absent from the simulated topology: never enforcement-eligible
    assert all(not c.enforcement_eligible for c in res.capture_campaigns)
    assert all(m.startswith(COPY_PREFIX) for c in res.capture_campaigns
               for m in res.report.campaigns[[x.campaign_id for x in res.report.campaigns].index(c.campaign_id)]
               .member_lines if m.startswith("p_homelab"))


def test_crowd_mix_never_writes_findings_or_ledger(mixed, tmp_path):
    imp, res = mixed
    assert not any(isinstance(x, Finding) for x in vars(res).values())
    store = open_lab_store(None)
    a = analyze_single_home(imp, store=store, model=None)
    before = store.ledger.count("homelab")
    a.crowd = res
    html = render_box_report(a, a.devices[0])
    assert store.ledger.count("homelab") == before
    assert html.count("MIXED-SYNTHETIC") >= 3 and 'id="crowd"' in html
    assert json.loads(json.dumps(a.to_dict(), default=str))["crowd_mix"]["data_class"] == "mixed_synthetic"
    store.close()


def test_crowd_mix_abstains_on_short_captures_and_validates_config(mixed):
    imp, _ = mixed
    pseudo = next(iter(imp.devices))
    end = imp.start + timedelta(hours=3)
    res = crowd_mix([e for e in imp.events_for(pseudo) if e.observed_at < end], start=imp.start, end=end,
                    cfg=CrowdMixConfig(n_copies=6, n_lines=60, warmup_history=False))
    assert res.report.status == "abstain" and not res.campaigns
    assert any("abstained" in n for n in res.notes)
    with pytest.raises(ValueError):
        CrowdMixConfig(n_copies=3)
    with pytest.raises(ValueError):
        CrowdMixConfig(n_copies=60, n_lines=100)                              # copies > 20 % of lines
    with pytest.raises(ValueError):
        crowd_mix(imp.events, start=imp.start, end=imp.end) if len(imp.devices) > 1 else crowd_mix(
            [], start=imp.start, end=imp.end)


# ============================================================================ CLI

def test_cli_synthetic_analyze_verify(tmp_path, capsys):
    cap, out = tmp_path / "cap", tmp_path / "out"
    assert cli_main(["synthetic", str(cap), "--start", "2026-10-20T06:00:00Z", "--hours", "7"]) == 0
    assert json.loads(capsys.readouterr().out)["synthetic"] is True
    assert cli_main(["analyze", str(cap), "--out", str(out), "--label", "10.42.0.23=demo", "--no-model"]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["verdicts"] == {"demo": "abstain"} and summary["synthetic"] is True
    assert (out / "box-lab-demo.html").exists() and (out / "analysis.json").exists()
    assert oct((out / "keys" / "pseudonym.key").stat().st_mode & 0o777) == "0o600"
    assert cli_main(["verify", str(out)]) == 0
    capsys.readouterr()
    assert cli_main(["dnsmasq-to-jsonl", str(cap / "dnsmasq.log"), "--year", "2026"]) == 0
    first = json.loads(capsys.readouterr().out.splitlines()[0])
    assert first["client_ip"] == "10.42.0.23" and first["ts"].startswith("2026-10-20T")


def test_cli_refuses_unsigned_or_untrusted_bundles(tmp_path):
    cap = tmp_path / "cap"
    write_synthetic_capture(cap, SyntheticBoxSpec(start=START, hours=7))
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps({"schema": "aegis.ioc_bundle/1", "indicators": []}))
    with pytest.raises(SystemExit):
        cli_main(["analyze", str(cap), "--out", str(tmp_path / "o"), "--ioc-bundle", str(bundle)])
    pem = tmp_path / "k.pem"
    pem.write_bytes(Signer.generate("other").public_pem())
    with pytest.raises(SystemExit, match="refused"):
        cli_main(["analyze", str(cap), "--out", str(tmp_path / "o"), "--ioc-bundle", str(bundle),
                  "--ioc-pubkey", str(pem), "--ioc-key-id", "other"])
