"""Deterministic synthetic lab corpus (spec section 7).

``generate_corpus`` simulates a population of household devices behind CPE
gateways for ``days`` days, injects controlled malware emulations into a
fraction of them, and produces:

- ``events``: canonical :class:`ObservationEvent` objects, built by running every
  generated raw record through the *real* ingest parsers and ``normalize`` (so the
  corpus is byte-for-byte what ingest yields from ``write_raw`` output);
- ``labels``: independent device-day ground truth ``{(entity_pseudonym, date): label}``
  (``"benign"`` or the malicious behavior label);
- raw collector files via ``write_raw`` (NetFlow CSV, DNS JSONL, Zeek conn/dns TSV),
  plus the topology, the signed IOC bundle, labels and a hash manifest.

Everything is a pure function of ``seed`` (and the other arguments).
"""
from __future__ import annotations

import csv
import hashlib
import json
import random
import gc
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from datetime import time as dtime
from pathlib import Path
from typing import Any, Iterator

from aegis.contracts.models import ObservationEvent, SourceKind, Vantage
from aegis.ingest.normalize import SourceConfig, normalize
from aegis.ingest.parsers import NetflowCsvParser, parse_dns_line
from aegis.ingest.pseudonym import Pseudonymizer
from aegis.lab import profiles as P
from aegis.lab import writers as W
from aegis.lab.iocs import SignerLike, build_ioc_bundle, lab_signer
from aegis.lab.topology import RESOLVER_IP, Endpoint, HostingTopology, generate_topology

DEFAULT_START = datetime(2026, 10, 1, tzinfo=timezone.utc)
BENIGN = "benign"
LAB_AUTHORIZATION_ID = "auth-lab-synthetic-001"

SOURCE_NETFLOW = "lab-netflow"
SOURCE_DNS = "lab-dns"
SOURCE_ZEEK_CONN = "lab-zeek-conn"
SOURCE_ZEEK_DNS = "lab-zeek-dns"

NETFLOW_FILE = "netflow.csv"
DNS_FILE = "dns.jsonl"
ZEEK_CONN_FILE = "zeek/conn.log"
ZEEK_DNS_FILE = "zeek/dns.log"


@dataclass
class DeviceSpec:
    index: int
    device_id: str                 # synthetic MAC (raw identifier, lab only)
    ip: str                        # CGNAT address behind the gateway
    device_class: str
    profile: str
    entity_pseudonym: str
    hard_negative: bool = False    # benign but superficially abuse-like (busy IPTV box)
    vendor: str | None = None
    always_on: bool = False
    malicious_label: str | None = None
    malware_family: str | None = None
    infection_day: int | None = None
    infected_at: datetime | None = None
    c2_domain: str | None = None
    c2_ip: str | None = None
    c2_in_ioc_feed: bool | None = None
    c2_on_shared_infra: bool | None = None

    @property
    def malicious(self) -> bool:
        return self.malicious_label is not None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["infected_at"] = self.infected_at.isoformat() if self.infected_at else None
        return d


@dataclass
class DeviceDayLabel:
    entity_pseudonym: str
    date: date
    label: str
    device_class: str
    profile: str
    malware_family: str | None
    hard_negative: bool
    event_count: int


def lab_tenant_key(tenant_id: str, seed: int) -> bytes:
    """Pseudonymization key of the lab tenant (register it to reproduce lab pseudonyms)."""
    return hashlib.sha256(f"aegis-lab-pseudonym:{tenant_id}:{seed}".encode()).digest()


def lab_sources(tenant_id: str) -> dict[str, SourceConfig]:
    common = dict(tenant_id=tenant_id, collection_authorization_id=LAB_AUTHORIZATION_ID, retention_days=30)
    return {
        SOURCE_NETFLOW: SourceConfig(source_id=SOURCE_NETFLOW, source_kind=SourceKind.NETFLOW,
                                     vantage=Vantage.DEVICE, **common),
        SOURCE_DNS: SourceConfig(source_id=SOURCE_DNS, source_kind=SourceKind.DNS, vantage=Vantage.DEVICE,
                                 **common),
        # Zeek sees addresses only: entities are pseudonyms of the device IP
        SOURCE_ZEEK_CONN: SourceConfig(source_id=SOURCE_ZEEK_CONN, source_kind=SourceKind.ZEEK_CONN,
                                       vantage=Vantage.SUBSCRIBER_LINE, entity_field="src_ip", **common),
        SOURCE_ZEEK_DNS: SourceConfig(source_id=SOURCE_ZEEK_DNS, source_kind=SourceKind.ZEEK_DNS,
                                      vantage=Vantage.SUBSCRIBER_LINE, entity_field="src_ip", **common),
    }


@dataclass
class Corpus:
    seed: int
    tenant_id: str
    start: datetime
    days: int
    devices: list[DeviceSpec]
    events: list[ObservationEvent]
    labels: dict[tuple[str, date], str]
    device_days: list[DeviceDayLabel]
    topology: HostingTopology
    sources: dict[str, SourceConfig]
    tenant_key: bytes
    _records: list[tuple[float, int, tuple]] = field(default_factory=list, repr=False)
    _netflow_lines: list[str] = field(default_factory=list, repr=False)
    _dns_lines: list[str] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------ accessors
    @property
    def pseudonymizer(self) -> Pseudonymizer:
        return Pseudonymizer(self.tenant_key)

    @property
    def end(self) -> datetime:
        return self.start + timedelta(days=self.days)

    def device(self, entity_pseudonym: str) -> DeviceSpec | None:
        for d in self.devices:
            if d.entity_pseudonym == entity_pseudonym:
                return d
        return None

    def malicious_devices(self) -> list[DeviceSpec]:
        return [d for d in self.devices if d.malicious]

    def hard_negatives(self) -> list[DeviceSpec]:
        return [d for d in self.devices if d.hard_negative]

    def events_for(self, entity_pseudonym: str) -> Iterator[ObservationEvent]:
        return (e for e in self.events if e.entity_pseudonym == entity_pseudonym)

    def label_for(self, entity_pseudonym: str, day: date) -> str | None:
        return self.labels.get((entity_pseudonym, day))

    def entity_aliases(self) -> dict[str, str]:
        """Zeek/line-level pseudonym (of the device IP) -> device pseudonym."""
        p = self.pseudonymizer
        return {p.pseudonym(d.ip): d.entity_pseudonym for d in self.devices}

    def ioc_bundle(self, signer: SignerLike | None = None) -> dict[str, Any]:
        return build_ioc_bundle(self.topology, start=self.start, days=self.days, seed=self.seed,
                                signer=signer or lab_signer(self.seed))

    def summary(self) -> dict[str, Any]:
        lab_counts = Counter(self.labels.values())
        return {
            "seed": self.seed, "tenant_id": self.tenant_id, "start": self.start.isoformat(), "days": self.days,
            "devices": len(self.devices), "malicious_devices": len(self.malicious_devices()),
            "hard_negative_devices": len(self.hard_negatives()), "events": len(self.events),
            "flow_events": len(self._netflow_lines), "dns_events": len(self._dns_lines),
            "device_days": len(self.labels), "device_day_labels": dict(sorted(lab_counts.items())),
            "profiles": dict(sorted(Counter(d.profile for d in self.devices).items())),
        }

    # ------------------------------------------------------------------ raw files
    def write_raw(self, out_dir: str | Path, *, zeek: bool = True, extras: bool = True,
                  signer: SignerLike | None = None) -> dict[str, Path]:
        """Write collector-format files (+ labels, topology, IOC bundle, manifest).

        Returns ``{logical_name: path}``. ``manifest.json`` lists the SHA-256 of
        every written file so a frozen dataset can be verified later.
        """
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}

        def write_lines(rel: str, lines: list[str]) -> Path:
            p = out / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                for line in lines:
                    fh.write(line)
                    fh.write("\n")
            return p

        written["netflow"] = write_lines(NETFLOW_FILE, [W.netflow_header_line()] + self._netflow_lines)
        written["dns"] = write_lines(DNS_FILE, self._dns_lines)
        if zeek:
            conn, dns = self._zeek_lines()
            written["zeek_conn"] = write_lines(ZEEK_CONN_FILE, conn)
            written["zeek_dns"] = write_lines(ZEEK_DNS_FILE, dns)
        if extras:
            written["labels"] = self._write_labels(out / "labels.csv")
            written["devices"] = _write_json(out / "devices.json", [d.to_dict() for d in self.devices])
            written["topology"] = self.topology.save(out / "topology.json")
            written["ground_truth"] = _write_json(out / "lab_ground_truth.json", {
                "malicious_infrastructure": self.topology.to_dict(include_ground_truth=True)["lab_ground_truth"],
                "entity_aliases": self.entity_aliases(),
            })
            sig = signer or lab_signer(self.seed)
            written["ioc_bundle"] = _write_json(out / "ioc_bundle.json", self.ioc_bundle(sig))
            pem = out / "ioc_signer_public.pem"
            pem.write_bytes(sig.public_pem())
            written["ioc_public_key"] = pem
            written["sources"] = _write_json(out / "sources.json",
                                             {k: v.model_dump(mode="json") for k, v in self.sources.items()})
        manifest = {
            "generator": "aegis.lab.corpus", "summary": self.summary(),
            "lab_tenant_key_sha256": hashlib.sha256(self.tenant_key).hexdigest(),
            "files": {str(p.relative_to(out)): _file_sha256(p) for p in written.values()},
        }
        written["manifest"] = _write_json(out / "manifest.json", manifest)
        return written

    def _write_labels(self, path: Path) -> Path:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(["entity_pseudonym", "date", "label", "device_class", "profile", "malware_family",
                        "hard_negative", "event_count"])
            for dd in self.device_days:
                w.writerow([dd.entity_pseudonym, dd.date.isoformat(), dd.label, dd.device_class, dd.profile,
                            dd.malware_family or "", int(dd.hard_negative), dd.event_count])
        return path

    def _zeek_lines(self) -> tuple[list[str], list[str]]:
        start_ts, end_ts = self.start.timestamp(), self.end.timestamp()
        conn = W.zeek_header("conn", W.ZEEK_CONN_FIELDS, W.ZEEK_CONN_TYPES, start_ts)
        dns = W.zeek_header("dns", W.ZEEK_DNS_FIELDS, W.ZEEK_DNS_TYPES, start_ts)
        for n, (t, di, rec) in enumerate(self._records):
            dev = self.devices[di]
            t = round(t, 3)
            uid = W.zeek_uid(self.seed, n)
            if rec[1] == 0:
                _, _, ip, port, proto, bo, bi, po, pi, dur, sport = rec
                conn.append(W.zeek_conn_line(t, uid, dev.ip, sport, ip, port, proto, dur, bo, bi, po, pi))
            else:
                _, _, qname, qtype, rcode, answers = rec
                dns.append(W.zeek_dns_line(t, uid, dev.ip, 40000 + n % 20000, RESOLVER_IP, n % 65536, qname,
                                           qtype, rcode, answers))
        conn.append(W.zeek_close(end_ts))
        dns.append(W.zeek_close(end_ts))
        return conn, dns


def _uuid4_from(h: str) -> str:
    """Deterministic RFC 4122 version-4-shaped UUID text from a hex digest."""
    variant = "89ab"[int(h[16], 16) & 3]
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{variant}{h[17:20]}-{h[20:32]}"


def _write_json(path: Path, obj: Any) -> Path:
    path.write_text(json.dumps(obj, indent=1, sort_keys=True, default=str), encoding="utf-8")
    return path


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------- planning

def _allocate_profiles(n: int, rng: random.Random) -> list[str]:
    """Largest-remainder allocation of profiles, shuffled deterministically."""
    weights = P.PROFILE_WEIGHTS
    raw = {k: w * n for k, w in weights.items()}
    counts = {k: int(v) for k, v in raw.items()}
    for k in sorted(raw, key=lambda k: (raw[k] - counts[k], k), reverse=True)[: n - sum(counts.values())]:
        counts[k] += 1
    if n >= 4 and counts["iptv_busy_box"] == 0:  # always include the hard negative
        top = max(counts, key=lambda k: counts[k])
        counts[top] -= 1
        counts["iptv_busy_box"] = 1
    out = [k for k in sorted(counts) for _ in range(counts[k])]
    rng.shuffle(out)
    return out


def _mac(rng: random.Random) -> str:
    return "02:" + ":".join(f"{rng.randrange(256):02x}" for _ in range(5))  # locally administered


def _plan_devices(seed: int, n: int, malicious_fraction: float, days: int, start: datetime,
                  topo: HostingTopology, pseudo: Pseudonymizer) -> list[DeviceSpec]:
    rng = random.Random(f"plan:{seed}")
    profiles = _allocate_profiles(n, rng)
    devices: list[DeviceSpec] = []
    used_macs: set[str] = set()
    for i, prof in enumerate(profiles):
        mac = _mac(rng)
        while mac in used_macs:
            mac = _mac(rng)
        used_macs.add(mac)
        ip = f"100.{64 + i // 64516}.{(i // 254) % 254}.{i % 254 + 1}"
        d = DeviceSpec(index=i, device_id=mac, ip=ip, device_class=P.BENIGN_PROFILES[prof], profile=prof,
                       entity_pseudonym=pseudo.pseudonym(mac), hard_negative=prof == "iptv_busy_box")
        if prof == "smart_tv":
            d.vendor = rng.choice(("tvvendor-a", "tvvendor-b"))
        if prof == "iptv_busy_box":
            d.always_on = rng.random() < 0.4
        devices.append(d)

    n_mal = 0 if malicious_fraction <= 0 else max(1, round(n * malicious_fraction))
    n_mal = min(n_mal, sum(1 for d in devices if not d.hard_negative))
    order = list(P.MALICIOUS_BEHAVIORS)
    preferred = {"c2_beaconing": ["android_tv_iptv", "smart_tv"],
                 "residential_proxy": ["android_tv_iptv", "smart_tv"],
                 "dga_activity": ["android_tv_iptv", "smart_tv"],
                 "ddos_bot": ["iot_camera", "smart_tv", "android_tv_iptv"]}
    bb, vo, mi = (topo.malicious[f] for f in ("badbox2_emu", "vo1d_emu", "mirai_emu"))
    shared_dom = bb.cohosted_domains[0]
    shared_ip = topo.resolve(shared_dom)[0]
    for k in range(n_mal):
        label = order[k % len(order)]
        pool = [d for prof in preferred[label] for d in devices if d.profile == prof and not d.malicious]
        if not pool:
            pool = [d for d in devices if not d.malicious and not d.hard_negative]
        d = pool[rng.randrange(min(len(pool), max(1, len(pool))))]
        d.malicious_label = label
        d.malware_family = P.MALICIOUS_BEHAVIORS[label]
        d.infection_day = 0 if days == 1 or rng.random() < 0.5 else rng.randint(1, days - 1)
        offset = 0.0 if d.infection_day == 0 and rng.random() < 0.5 else rng.uniform(0, 20 * 3600)
        d.infected_at = start + timedelta(days=d.infection_day, seconds=offset)
        if label in ("c2_beaconing", "residential_proxy"):
            roll = rng.random() if label == "c2_beaconing" else 0.0
            if roll < 0.4:
                j = rng.randrange(2)
                d.c2_domain, d.c2_ip, d.c2_in_ioc_feed, d.c2_on_shared_infra = bb.c2_domains[j], bb.c2_ips[j], True, False
            elif roll < 0.7:
                d.c2_domain, d.c2_ip, d.c2_in_ioc_feed, d.c2_on_shared_infra = bb.c2_domains[2], bb.novel_ips[0], False, False
            else:
                d.c2_domain, d.c2_ip, d.c2_in_ioc_feed, d.c2_on_shared_infra = shared_dom, shared_ip, True, True
        elif label == "dga_activity":
            d.c2_domain, d.c2_ip, d.c2_in_ioc_feed, d.c2_on_shared_infra = vo.c2_domains[0], vo.c2_ips[0], True, False
        else:
            novel = rng.random() < 0.5
            j = 1 if novel else 0
            d.c2_domain, d.c2_ip, d.c2_in_ioc_feed, d.c2_on_shared_infra = mi.c2_domains[j], mi.c2_ips[j], not novel, False
    return devices


# ---------------------------------------------------------------------------- simulation

def _simulate_device(dev: DeviceSpec, seed: int, start: datetime, days: int,
                     topo: HostingTopology) -> list[tuple]:
    rng = random.Random(f"device:{seed}:{dev.index}")
    ws = start.timestamp()
    we = ws + days * P.DAY
    sim = P.DeviceSim(rng=rng, topo=topo, window_start=ws, window_end=we)
    parallel = rng.choice((1, 1, 2)) if dev.profile == "iptv_busy_box" else 1
    for d in range(days):
        day0 = ws + d * P.DAY
        prof = dev.profile
        if prof == "android_tv_iptv":
            P.android_tv_iptv(sim, day0)
        elif prof == "iptv_busy_box":
            P.iptv_busy_box(sim, day0, dev.always_on, parallel)
        elif prof == "smart_tv":
            P.smart_tv(sim, day0, dev.vendor or "tvvendor-a")
        elif prof == "console":
            P.console(sim, day0)
        elif prof == "phone":
            P.phone(sim, day0)
        elif prof == "laptop":
            P.laptop(sim, day0, vpn=False)
        elif prof == "laptop_vpn":
            P.laptop(sim, day0, vpn=True)
        elif prof == "iot_camera":
            P.iot_camera(sim, day0)
        else:  # pragma: no cover - guarded by _allocate_profiles
            raise ValueError(f"unknown profile {prof}")
        if dev.device_class in ("android_tv", "smart_tv", "console", "camera") and rng.random() < 0.07:
            P.firmware_update(sim, day0, dev.vendor)

    if dev.malicious and dev.infected_at is not None:
        t0 = max(ws, dev.infected_at.timestamp())
        _overlay_malware(sim, dev, t0, we, topo)
    return sim.records


def _overlay_malware(sim: P.DeviceSim, dev: DeviceSpec, t0: float, t1: float, topo: HostingTopology) -> None:
    r = sim.rng
    assert dev.c2_domain is not None and dev.c2_ip is not None
    fam = topo.malicious[dev.malware_family or ""]
    c2 = P.C2Choice(dev.c2_domain, dev.c2_ip, fam.c2_port, P.PROTO_TCP)
    if dev.malicious_label == "c2_beaconing":
        P.c2_beaconing(sim, t0, t1, c2, P.lognormal_period(r), r.uniform(0.05, 0.2), r.choice((300.0, 3600.0)))
    elif dev.malicious_label == "residential_proxy":
        P.c2_beaconing(sim, t0, t1, c2, r.uniform(600, 900), r.uniform(0.05, 0.2), 3600.0)
        ctl_ip = fam.proxy_controllers[r.randrange(len(fam.proxy_controllers))]
        host = topo.host(ctl_ip)
        name = host.hostnames[0] if host else ctl_ip
        P.residential_proxy(sim, t0, t1, Endpoint(name, ctl_ip, 443), r.uniform(30, 150))
    elif dev.malicious_label == "dga_activity":
        P.c2_beaconing(sim, t0, t1, c2, r.uniform(1500, 2100), r.uniform(0.05, 0.15), 3600.0)
        P.dga_activity(sim, t0, t1, fam.dga_seed or 0, fam.c2_ips[-1], fam.c2_port)
    elif dev.malicious_label == "ddos_bot":
        P.ddos_bot(sim, t0, t1, c2)


# ---------------------------------------------------------------------------- entry point

def generate_corpus(seed: int = 7, days: int = 3, n_devices: int = 200, malicious_fraction: float = 0.08,
                    tenant_id: str = "demo", start: datetime = DEFAULT_START) -> Corpus:
    """Generate the lab corpus. Deterministic for identical arguments."""
    if days < 1:
        raise ValueError("days must be >= 1")
    if n_devices < 1:
        raise ValueError("n_devices must be >= 1")
    if not 0.0 <= malicious_fraction <= 1.0:
        raise ValueError("malicious_fraction must be within [0, 1]")
    if start.tzinfo is None:
        raise ValueError("start must be timezone-aware")
    start = start.astimezone(timezone.utc)

    gc_was_enabled = gc.isenabled()
    gc.disable()  # hundreds of thousands of acyclic objects: cyclic GC passes are pure overhead
    try:
        return _generate(seed, days, n_devices, malicious_fraction, tenant_id, start)
    finally:
        if gc_was_enabled:
            gc.enable()


def _generate(seed: int, days: int, n_devices: int, malicious_fraction: float, tenant_id: str,
              start: datetime) -> Corpus:
    topo = generate_topology(seed)
    key = lab_tenant_key(tenant_id, seed)
    pseudo = Pseudonymizer(key)
    devices = _plan_devices(seed, n_devices, malicious_fraction, days, start, topo, pseudo)

    records: list[tuple[float, int, tuple]] = []
    for dev in devices:
        records.extend((rec[0], dev.index, rec) for rec in _simulate_device(dev, seed, start, days, topo))
    records.sort(key=lambda x: (x[0], x[1]))

    sources = lab_sources(tenant_id)
    nf_src, dns_src = sources[SOURCE_NETFLOW], sources[SOURCE_DNS]
    nf_parser = NetflowCsvParser(list(W.NETFLOW_HEADER))
    lag_rng = random.Random(f"lag:{seed}")
    netflow_lines: list[str] = []
    dns_lines: list[str] = []
    events: list[ObservationEvent] = []
    counts: Counter[tuple[str, date]] = Counter()
    id_prefix = f"{seed}|{tenant_id}|".encode()
    for n, (t, di, rec) in enumerate(records):
        dev = devices[di]
        ts = W.rfc3339_ms(t)
        if rec[1] == 0:
            _, _, ip, port, proto, bo, bi, po, pi, dur, sport = rec
            line = W.netflow_line(ts, dev.device_id, dev.device_class, dev.ip, sport, ip, port, proto, po, bo,
                                  pi, bi, dur)
            netflow_lines.append(line)
            raw = nf_parser.parse_line(line.encode("utf-8"), len(netflow_lines) + 1)
            src, ref = nf_src, f"lab://{tenant_id}/{seed}/{NETFLOW_FILE}#L{len(netflow_lines) + 1}"
        else:
            _, _, qname, qtype, rcode, answers = rec
            line = W.dns_line(ts, dev.device_id, dev.device_class, dev.ip, qname, qtype, rcode, answers)
            dns_lines.append(line)
            raw = parse_dns_line(line.encode("utf-8"), len(dns_lines))
            src, ref = dns_src, f"lab://{tenant_id}/{seed}/{DNS_FILE}#L{len(dns_lines)}"
        now = datetime.fromtimestamp(t + lag_rng.uniform(5.0, 90.0), tz=timezone.utc)
        eid = _uuid4_from(hashlib.sha256(id_prefix + str(n).encode()).hexdigest())
        ev = normalize(raw, src, pseudo, now, event_id=eid, raw_artifact_ref=ref)
        events.append(ev)
        counts[(dev.entity_pseudonym, ev.observed_at.date())] += 1

    # device-days are the UTC calendar dates the window touches; a device-day is
    # malicious when the device was infected before that date ended
    end = start + timedelta(days=days)
    dates: list[date] = []
    d0 = start.date()
    while datetime.combine(d0, dtime.min, tzinfo=timezone.utc) < end:
        dates.append(d0)
        d0 += timedelta(days=1)
    labels: dict[tuple[str, date], str] = {}
    device_days: list[DeviceDayLabel] = []
    for dev in devices:
        for day in dates:
            day_end = datetime.combine(day + timedelta(days=1), dtime.min, tzinfo=timezone.utc)
            infected = dev.malicious and dev.infected_at is not None and dev.infected_at < day_end
            label = dev.malicious_label if infected and dev.malicious_label else BENIGN
            labels[(dev.entity_pseudonym, day)] = label
            device_days.append(DeviceDayLabel(
                entity_pseudonym=dev.entity_pseudonym, date=day, label=label, device_class=dev.device_class,
                profile=dev.profile, malware_family=dev.malware_family if infected else None,
                hard_negative=dev.hard_negative, event_count=counts.get((dev.entity_pseudonym, day), 0)))

    return Corpus(seed=seed, tenant_id=tenant_id, start=start, days=days, devices=devices, events=events,
                  labels=labels, device_days=device_days, topology=topo, sources=sources, tenant_key=key,
                  _records=records, _netflow_lines=netflow_lines, _dns_lines=dns_lines)
