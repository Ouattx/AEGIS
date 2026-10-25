"""EGRESS against the existing lab corpus (aegis.lab), unchanged.

The corpus already emulates DDoS-bot and residential-proxy devices as flow metadata next
to benign heavy users (IPTV boxes left on 24/7, consoles, VPN laptops, cloud cameras,
firmware downloads). These tests check the two properties a pilot depends on: no benign
line is flagged, and the emulated outbound abuse is found. C2 beaconing and DGA devices
are SENTINEL / RESONANCE territory: EGRESS is expected to stay silent on them.
"""
from __future__ import annotations

from collections import Counter

import pytest

from aegis.egress import LABEL_DDOS, LABEL_PROXY, EgressDetector, to_findings
from aegis.lab.corpus import generate_corpus
from aegis.resonance import DestinationContext

HEAVY_BENIGN = {"android_tv_iptv", "iptv_busy_box", "console", "laptop_vpn", "iot_camera", "smart_tv"}


@pytest.fixture(scope="module")
def corpus():
    return generate_corpus(seed=11, days=2, n_devices=120, malicious_fraction=0.12, tenant_id="lab-egress")


@pytest.fixture(scope="module")
def report(corpus):
    return EgressDetector(tenant_id=corpus.tenant_id, context=DestinationContext(corpus.topology)).detect(corpus.events)


def _benign(corpus):
    return [d for d in corpus.devices if not d.malicious]


def test_corpus_contains_the_benign_heavy_users(corpus):
    profiles = Counter(d.profile for d in _benign(corpus))
    assert HEAVY_BENIGN <= set(profiles), profiles
    assert any(d.hard_negative for d in corpus.devices)


def test_no_benign_line_is_flagged(corpus, report):
    assert report.status == "ok"
    benign = {d.entity_pseudonym for d in _benign(corpus)}
    flagged = report.flagged_lines()
    assert not flagged & benign, Counter(corpus.device(p).profile for p in flagged & benign)
    assert not {v.entity_pseudonym for v in report.verdicts} & benign  # not even an abstention


def test_ddos_bots_are_found(corpus, report):
    bots = [d for d in corpus.malicious_devices() if d.malicious_label == "ddos_bot"]
    assert bots
    assert {d.entity_pseudonym for d in bots} <= report.flagged_lines(LABEL_DDOS)


def test_residential_proxies_are_found(corpus, report):
    proxies = [d for d in corpus.malicious_devices() if d.malicious_label == "residential_proxy"]
    assert proxies
    assert {d.entity_pseudonym for d in proxies} <= report.flagged_lines(LABEL_PROXY)


def test_c2_and_dga_devices_are_out_of_scope(corpus, report):
    other = {d.entity_pseudonym for d in corpus.malicious_devices()
             if d.malicious_label in ("c2_beaconing", "dga_activity")}
    assert not other & report.flagged_lines()


def test_every_lab_finding_has_evidence(report):
    findings = to_findings(report)
    assert findings and all(f.evidence_ids and f.requires_review for f in findings)


def test_uniflow_export_abstains_instead_of_flagging(corpus):
    """Same corpus with reverse counters stripped (a uniflow exporter): nothing benign is flagged."""
    events = [e.model_copy(update={"flow": e.flow.model_copy(update={"packets_in": None, "bytes_in": None})})
              if e.flow is not None else e for e in corpus.events]
    rep = EgressDetector(tenant_id=corpus.tenant_id).detect(events)
    benign = {d.entity_pseudonym for d in _benign(corpus)}
    assert not rep.flagged_lines() & benign
    bots = {d.entity_pseudonym for d in corpus.malicious_devices() if d.malicious_label == "ddos_bot"}
    ddos = {v.entity_pseudonym: v.verdict for v in rep.verdicts if v.label == LABEL_DDOS}
    assert bots <= set(ddos) and {ddos[b] for b in bots} == {"abstain"}
