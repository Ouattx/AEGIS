import csv
import hashlib
import json
import statistics
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pytest

from aegis.contracts.models import ObservationEvent
from aegis.ingest import InMemoryBus, IngestPipeline, Validator
from aegis.lab import BENIGN, generate_corpus, lab_signer, verify_bundle
from aegis.provenance.signing import KeyRing

LABELS = {"c2_beaconing", "residential_proxy", "dga_activity", "ddos_bot"}


@pytest.fixture(scope="module")
def corpus():
    return generate_corpus(seed=5, days=3, n_devices=40, malicious_fraction=0.2, tenant_id="lab-t")


def _flows(c, dev):
    return [e for e in c.events_for(dev.entity_pseudonym) if e.flow is not None]


def test_shape_and_population(corpus):
    s = corpus.summary()
    assert s["devices"] == 40 and s["malicious_devices"] == 8 and s["hard_negative_devices"] >= 1
    assert s["events"] == len(corpus.events) == s["flow_events"] + s["dns_events"]
    assert s["device_days"] == 120 == len(corpus.labels) == len(corpus.device_days)
    assert set(s["device_day_labels"]) == {BENIGN} | LABELS
    assert {d.profile for d in corpus.devices} >= {"android_tv_iptv", "iptv_busy_box", "smart_tv", "phone"}
    assert len({d.device_id for d in corpus.devices}) == 40 and len({d.ip for d in corpus.devices}) == 40


def test_deterministic_given_seed():
    a = generate_corpus(seed=9, days=2, n_devices=12)
    b = generate_corpus(seed=9, days=2, n_devices=12)
    assert [e.model_dump() for e in a.events] == [e.model_dump() for e in b.events]
    assert a.labels == b.labels and a._netflow_lines == b._netflow_lines and a._dns_lines == b._dns_lines
    c = generate_corpus(seed=10, days=2, n_devices=12)
    assert [e.integrity_sha256 for e in c.events] != [e.integrity_sha256 for e in a.events]


def test_events_are_valid_ordered_and_in_window(corpus):
    v = Validator(clock=lambda: corpus.end + timedelta(days=1))
    prev = None
    ids = set()
    for e in corpus.events:
        assert isinstance(v.validate(e), ObservationEvent)
        assert corpus.start <= e.observed_at < corpus.end
        assert e.tenant_id == "lab-t" and e.source_id in ("lab-netflow", "lab-dns")
        assert prev is None or prev <= e.observed_at
        prev = e.observed_at
        ids.add(e.event_id)
    assert len(ids) == len(corpus.events)
    # spot-check strict JSON round trip
    for e in corpus.events[:: max(1, len(corpus.events) // 200)]:
        assert isinstance(v.validate(e.model_dump_json().encode()), ObservationEvent)


def test_no_raw_identifiers_in_events(corpus):
    blob = "\n".join(e.model_dump_json() for e in corpus.events[::7])
    for d in corpus.devices:
        assert d.device_id not in blob
        assert f'"{d.ip}"' not in blob
    assert all(e.flow is None or e.flow.src_ip is None for e in corpus.events)


def test_labels_follow_infection_timeline(corpus):
    for d in corpus.devices:
        for k in range(corpus.days):
            day = (corpus.start + timedelta(days=k)).date()
            label = corpus.label_for(d.entity_pseudonym, day)
            if not d.malicious or k < d.infection_day:
                assert label == BENIGN
            else:
                assert label == d.malicious_label
    for d in corpus.hard_negatives():
        assert not d.malicious
    dd = {(x.entity_pseudonym, x.date): x for x in corpus.device_days}
    counts = Counter((e.entity_pseudonym, e.observed_at.date()) for e in corpus.events)
    assert all(dd[k].event_count == counts.get(k, 0) for k in dd)


def test_benign_devices_never_touch_dedicated_c2(corpus):
    dedicated = set()
    names = set()
    for fam in corpus.topology.malicious.values():
        dedicated |= {ip for ip in fam.c2_ips if corpus.topology.is_shared(ip) is False}
        dedicated |= set(fam.proxy_controllers)
        names |= set(fam.c2_domains) | set(fam.cohosted_domains)
    mal_entities = {d.entity_pseudonym for d in corpus.malicious_devices()}
    for e in corpus.events:
        if e.entity_pseudonym in mal_entities:
            continue
        if e.flow is not None:
            assert e.flow.dst_ip not in dedicated
        else:
            assert e.dns.qname not in names and not e.dns.qname.endswith(".test")


def test_no_c2_contact_before_infection(corpus):
    for d in corpus.malicious_devices():
        before = [e for e in corpus.events_for(d.entity_pseudonym)
                  if e.observed_at < d.infected_at and e.flow is not None and e.flow.dst_ip == d.c2_ip
                  and not d.c2_on_shared_infra]
        assert before == []


def test_c2_beaconing_is_periodic(corpus):
    devs = [d for d in corpus.malicious_devices() if d.malicious_label == "c2_beaconing"]
    assert devs
    for d in devs:
        small = sorted(e.observed_at.timestamp() for e in _flows(corpus, d)
                       if e.flow.dst_ip == d.c2_ip and e.observed_at >= d.infected_at and e.flow.bytes_out < 1000)
        assert len(small) >= 20
        gaps = [b - a for a, b in zip(small, small[1:]) if b - a > 30]
        med = statistics.median(gaps)
        within = sum(1 for g in gaps if abs(g - med) / med < 0.25) / len(gaps)
        assert within > 0.6, (d.c2_domain, med, within)
        assert any(e.observed_at.hour < 5 for e in _flows(corpus, d) if e.flow.dst_ip == d.c2_ip)  # 24/7


def test_dga_produces_nxdomain_storms(corpus):
    for d in corpus.malicious_devices():
        if d.malicious_label != "dga_activity":
            continue
        dns = [e for e in corpus.events_for(d.entity_pseudonym) if e.dns is not None and e.observed_at >= d.infected_at]
        nx = [e for e in dns if e.dns.rcode == "NXDOMAIN"]
        assert len(nx) > 50 and len(nx) / len(dns) > 0.5
        assert any(e.dns.rcode == "NOERROR" and e.dns.qname.endswith(".test") for e in dns)


def test_residential_proxy_and_ddos_signatures(corpus):
    for d in corpus.malicious_devices():
        fl = [e for e in _flows(corpus, d) if e.observed_at >= d.infected_at]
        if d.malicious_label == "residential_proxy":
            assert len({e.flow.dst_ip for e in fl}) > 100
            ctl = set(corpus.topology.malicious["badbox2_emu"].proxy_controllers)
            up = sum(e.flow.bytes_out or 0 for e in fl if e.flow.dst_ip in ctl)
            assert up > 10_000_000
        if d.malicious_label == "ddos_bot":
            assert max(e.flow.packets_out or 0 for e in fl) > 40_000
            scans = [e for e in fl if e.flow.dst_port in (23, 2323)]
            assert len(scans) > 50 and all(e.flow.bytes_in == 0 for e in scans)


def test_busy_iptv_box_looks_busy_but_is_benign(corpus):
    per_day = defaultdict(set)
    vol = Counter()
    for d in corpus.hard_negatives():
        for e in _flows(corpus, d):
            per_day[(d.entity_pseudonym, e.observed_at.date())].add(e.flow.dst_ip)
            vol[d.entity_pseudonym] += e.flow.bytes_in or 0
    typical = defaultdict(set)
    for d in corpus.devices:
        if d.profile == "smart_tv":
            for e in _flows(corpus, d):
                typical[(d.entity_pseudonym, e.observed_at.date())].add(e.flow.dst_ip)
    assert statistics.median(len(v) for v in per_day.values()) > 2 * statistics.median(len(v) for v in typical.values())
    assert min(vol.values()) > 10e9  # tens of GB over the window
    labels = {corpus.label_for(e, day) for (e, day) in per_day}
    assert labels == {BENIGN}


def test_write_raw_and_reingest_is_identical(tmp_path):
    c = generate_corpus(seed=21, days=1, n_devices=10, malicious_fraction=0.3)
    paths = c.write_raw(tmp_path)
    manifest = json.loads(paths["manifest"].read_text())
    for rel, digest in manifest["files"].items():
        assert hashlib.sha256((tmp_path / rel).read_bytes()).hexdigest() == digest
    rows = list(csv.DictReader(open(paths["labels"])))
    assert len(rows) == len(c.labels)
    kr = KeyRing()
    kr.add(lab_signer(21).key_id, paths["ioc_public_key"].read_bytes())
    assert verify_bundle(json.loads(paths["ioc_bundle"].read_text()), kr)

    clock = lambda: c.end + timedelta(days=1)  # noqa: E731
    bus = InMemoryBus(max_queue=1000)
    got = []
    bus.subscribe("observations", got.append)
    pl = IngestPipeline(bus, Validator(clock=clock), c.sources, pseudonymizers={c.tenant_id: c.pseudonymizer},
                        clock=clock)
    for source, key in (("lab-netflow", "netflow"), ("lab-dns", "dns"), ("lab-zeek-conn", "zeek_conn"),
                        ("lab-zeek-dns", "zeek_dns")):
        st = pl.ingest_file(paths[key], source)
        assert st.quarantined == 0 and st.duplicates == 0, st.quarantine_reasons
    bus.drain()

    def key(e):
        d = e.model_dump(mode="json")
        for k in ("event_id", "ingested_at", "raw_artifact_ref", "retention_until"):
            d.pop(k)
        return json.dumps(d, sort_keys=True)

    n = len(c.events)
    assert sorted(map(key, got[:n])) == sorted(map(key, c.events))
    aliases = c.entity_aliases()
    zeek = got[n:]
    assert len(zeek) == n and all(e.entity_pseudonym in aliases for e in zeek)
    assert Counter(aliases[e.entity_pseudonym] for e in zeek) == Counter(e.entity_pseudonym for e in c.events)


def test_argument_validation():
    with pytest.raises(ValueError):
        generate_corpus(days=0)
    with pytest.raises(ValueError):
        generate_corpus(n_devices=0)
    with pytest.raises(ValueError):
        generate_corpus(malicious_fraction=1.5)
    with pytest.raises(ValueError):
        generate_corpus(start=datetime(2026, 10, 1))


def test_zero_malicious_and_tiny_populations():
    c = generate_corpus(seed=1, days=1, n_devices=3, malicious_fraction=0.0)
    assert not c.malicious_devices() and set(c.labels.values()) == {BENIGN}
    c1 = generate_corpus(seed=1, days=1, n_devices=1, malicious_fraction=1.0)
    assert len(c1.malicious_devices()) == 1


def test_start_offset_respected():
    start = datetime(2026, 3, 29, 6, 30, tzinfo=timezone.utc)
    c = generate_corpus(seed=2, days=1, n_devices=4, start=start, malicious_fraction=0.5)
    assert all(start <= e.observed_at < start + timedelta(days=1) for e in c.events)
    # a window that is not midnight-aligned touches two UTC dates: both are labelled
    assert {day for _, day in c.labels} == {start.date(), start.date() + timedelta(days=1)}
    assert all(c.label_for(e.entity_pseudonym, e.observed_at.date()) is not None for e in c.events)


def test_full_size_generation_under_30_seconds():
    t0 = time.perf_counter()
    c = generate_corpus(seed=7, days=3, n_devices=200)
    elapsed = time.perf_counter() - t0
    assert elapsed < 30.0, f"generation took {elapsed:.1f}s"
    s = c.summary()
    assert s["devices"] == 200 and s["malicious_devices"] == 16 and s["device_days"] == 600
