"""Synthetic hosting topology for the lab (spec section 7 / 9).

Models what an operator can know about destination infrastructure: which IPs are
shared CDN edges hosting many legitimate co-tenants, which are dedicated, which
ASN/provider owns them, and which hostnames resolve where. MIRROR uses it to
compute collateral impact (blocking a shared CDN IP hits every co-tenant).

All addresses come from ranges reserved for documentation/benchmarking
(198.18.0.0/15, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and all names end
in reserved suffixes (.example, .test), so nothing in the lab ever points at a
real network.

The malicious infrastructure is lab ground truth; it is kept apart from the
operator-facing topology (``to_dict(include_ground_truth=False)``).
"""
from __future__ import annotations

import ipaddress
import json
import random
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal

HostKind = Literal["shared_cdn", "dedicated", "cloud", "game", "vpn", "resolver", "victim", "residential"]

RESOLVER_IP = "198.18.255.53"
DGA_TLD = "test"


@dataclass(frozen=True)
class Endpoint:
    hostname: str
    ip: str
    port: int
    protocol: Literal["tcp", "udp"] = "tcp"


@dataclass
class HostRecord:
    ip: str
    asn: int
    provider: str
    kind: HostKind
    hostnames: list[str] = field(default_factory=list)

    @property
    def shared(self) -> bool:
        return self.kind == "shared_cdn" or len(self.hostnames) > 1


@dataclass
class MaliciousInfra:
    """Ground truth for one emulated malware family."""
    family: str
    c2_domains: list[str]
    c2_ips: list[str]
    c2_port: int
    c2_protocol: Literal["tcp", "udp"]
    cohosted_domains: list[str] = field(default_factory=list)  # malicious names on shared CDN IPs
    proxy_controllers: list[str] = field(default_factory=list)
    novel_ips: list[str] = field(default_factory=list)         # never published in any feed
    dga_seed: int | None = None


ASNS: dict[int, tuple[str, str, HostKind]] = {
    64600: ("StreamCDN Global", "198.18.0.0/20", "shared_cdn"),
    64601: ("EdgeFabric CDN", "198.18.16.0/20", "shared_cdn"),
    64610: ("TV Vendor A Cloud", "198.18.32.0/24", "dedicated"),
    64611: ("TV Vendor B Cloud", "198.18.33.0/24", "dedicated"),
    64620: ("GameNet Hosting", "198.18.40.0/22", "game"),
    64630: ("Hyperscale Cloud", "198.18.64.0/18", "cloud"),
    64640: ("SecureTunnel VPN", "198.18.48.0/24", "vpn"),
    64650: ("Licensed IPTV Operator", "198.18.52.0/24", "dedicated"),
    64660: ("CamCloud", "198.18.56.0/24", "dedicated"),
    64670: ("ISP Core Services", "198.18.255.0/24", "resolver"),
    64700: ("BulletHost VPS", "203.0.113.0/24", "dedicated"),
    64701: ("Offshore Proxy Net", "198.51.100.0/24", "dedicated"),
    64710: ("Victim Hosting", "192.0.2.0/24", "victim"),
}

_BRANDS = ["newsdaily", "shopmart", "kidsflix", "sportlive", "musicbox", "travelnow", "recipehub",
           "weatherpro", "bankwise", "learnly", "photoshare", "chatterly", "mapquestor", "gamerzone",
           "fitlife", "podwave", "docusign-demo", "cloudnotes", "streamhub", "citynews", "autotrader-x",
           "booknook", "petcare", "homedecor", "jobboard", "ticketline", "fooddeliv", "carshare",
           "marketwatch", "techreview", "fashionista", "kidslearn", "medinfo", "govportal", "sciencedaily",
           "artgallery", "radiofm", "comicverse", "outdoorgear", "localmarket"]
_CDNS = {64600: "streamcdn", 64601: "edgefabric"}


class HostingTopology:
    """Operator-visible hosting knowledge plus (separately) lab ground truth."""

    def __init__(self, topology_id: str, hosts: Iterable[HostRecord], services: dict[str, list[Endpoint]],
                 malicious: Iterable[MaliciousInfra] = (), complete: bool = True):
        self.topology_id = topology_id
        self.hosts: dict[str, HostRecord] = {h.ip: h for h in hosts}
        self.services = services
        self.malicious: dict[str, MaliciousInfra] = {m.family: m for m in malicious}
        self.complete = complete
        self._prefixes = [ipaddress.ip_network(p) for _, p, _ in ASNS.values()]
        self._domains: dict[str, list[str]] = {}
        for h in self.hosts.values():
            for name in h.hostnames:
                self._domains.setdefault(name, []).append(h.ip)

    # ------------------------------------------------------------------ queries
    def host(self, ip: str) -> HostRecord | None:
        return self.hosts.get(ip)

    def covers(self, ip: str) -> bool:
        """True when ``ip`` lies in a prefix the topology claims to know (fail closed otherwise)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._prefixes)

    def is_shared(self, ip: str) -> bool | None:
        """Shared hosting? ``None`` when unknown (callers must treat unknown as unsafe)."""
        h = self.hosts.get(ip)
        return None if h is None else h.shared

    def cotenants(self, ip: str, exclude: Iterable[str] = ()) -> list[str]:
        h = self.hosts.get(ip)
        if h is None:
            return []
        ex = set(exclude)
        return [n for n in h.hostnames if n not in ex]

    def resolve(self, domain: str) -> list[str]:
        return list(self._domains.get(domain.lower().rstrip("."), []))

    def domains(self) -> list[str]:
        return sorted(self._domains)

    def asn_of(self, ip: str) -> int | None:
        h = self.hosts.get(ip)
        return None if h is None else h.asn

    def all_malicious_domains(self) -> set[str]:
        out: set[str] = set()
        for m in self.malicious.values():
            out.update(m.c2_domains)
            out.update(m.cohosted_domains)
        return out

    # ------------------------------------------------------------------ serialization
    def to_dict(self, include_ground_truth: bool = False) -> dict[str, Any]:
        d: dict[str, Any] = {
            "topology_id": self.topology_id,
            "complete": self.complete,
            "asns": {str(a): {"provider": n, "prefix": p, "kind": k} for a, (n, p, k) in ASNS.items()},
            "hosts": [asdict(h) for h in sorted(self.hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))],
            "services": {k: [asdict(e) for e in v] for k, v in sorted(self.services.items())},
        }
        if include_ground_truth:
            d["lab_ground_truth"] = {"malicious": [asdict(m) for m in self.malicious.values()]}
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "HostingTopology":
        hosts = [HostRecord(**h) for h in d["hosts"]]
        services = {k: [Endpoint(**e) for e in v] for k, v in d.get("services", {}).items()}
        mal = [MaliciousInfra(**m) for m in d.get("lab_ground_truth", {}).get("malicious", [])]
        return cls(d["topology_id"], hosts, services, mal, complete=bool(d.get("complete", True)))

    def save(self, path: str | Path, include_ground_truth: bool = False) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(include_ground_truth), separators=(",", ":"), sort_keys=True))
        return p

    @classmethod
    def load(cls, path: str | Path) -> "HostingTopology":
        return cls.from_dict(json.loads(Path(path).read_text()))


# ---------------------------------------------------------------------------- generator

class _Alloc:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.used: set[str] = {RESOLVER_IP}

    def ip(self, asn: int) -> str:
        net = ipaddress.ip_network(ASNS[asn][1])
        hosts = net.num_addresses - 2
        for _ in range(10_000):
            cand = str(net.network_address + 1 + self.rng.randrange(hosts))
            if cand not in self.used:
                self.used.add(cand)
                return cand
        raise RuntimeError(f"address space exhausted in AS{asn}")


def dga_domains(seed: int, day_ordinal: int, count: int) -> list[str]:
    """Deterministic DGA (Vo1d-style emulation): ``count`` names for one day."""
    r = random.Random(f"dga:{seed}:{day_ordinal}")
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ["".join(r.choice(alphabet) for _ in range(r.randint(12, 18))) + "." + DGA_TLD
            for _ in range(count)]


def generate_topology(seed: int = 7) -> HostingTopology:
    """Deterministic lab topology for ``seed``."""
    rng = random.Random(f"topology:{seed}")
    alloc = _Alloc(rng)
    hosts: dict[str, HostRecord] = {}
    services: dict[str, list[Endpoint]] = {}

    def add(ip: str, asn: int, names: list[str], kind: HostKind | None = None) -> HostRecord:
        h = hosts.get(ip)
        if h is None:
            h = HostRecord(ip=ip, asn=asn, provider=ASNS[asn][0], kind=kind or ASNS[asn][2])
            hosts[ip] = h
        for n in names:
            if n not in h.hostnames:
                h.hostnames.append(n)
        return h

    def svc(name: str, ep: Endpoint) -> None:
        services.setdefault(name, []).append(ep)

    # shared CDN edges: each edge serves media names plus 20-80 unrelated co-tenant sites
    cdn_edges: list[tuple[int, str]] = []
    for asn, cdn in _CDNS.items():
        for i in range(24):
            ip = alloc.ip(asn)
            n_co = rng.randint(20, 80)
            co = [f"www.{b}{rng.randint(1, 99)}.example" for b in rng.sample(_BRANDS, min(n_co, len(_BRANDS)))]
            co += [f"static{j}.{rng.choice(_BRANDS)}.example" for j in range(max(0, n_co - len(co)))]
            add(ip, asn, [f"edge{i:02d}.{cdn}.example"] + co)
            cdn_edges.append((asn, ip))
            svc("web", Endpoint(co[0], ip, 443))
    for i, (asn, ip) in enumerate(cdn_edges):
        name = f"vod{i:02d}.{_CDNS[asn]}.example"
        add(ip, asn, [name])
        svc("video_cdn", Endpoint(name, ip, 443))

    # licensed IPTV operator: middleware/EPG dedicated, channel origins fronted by CDN edges
    for name in ("mw.iptv-operator.example", "epg.iptv-operator.example", "drm.iptv-operator.example"):
        ip = alloc.ip(64650)
        add(ip, 64650, [name])
        svc("iptv_middleware", Endpoint(name, ip, 443))
    for ch in range(90):
        asn, ip = cdn_edges[rng.randrange(len(cdn_edges))]
        name = f"ch{ch:03d}.live.iptv-operator.example"
        add(ip, asn, [name])
        svc("iptv_origins", Endpoint(name, ip, 443))

    # TV vendors: API, ACR telemetry, firmware (firmware served from CDN)
    for vendor, asn in (("tvvendor-a", 64610), ("tvvendor-b", 64611)):
        for role in ("api", "acr", "connectivity"):
            ip = alloc.ip(asn)
            name = f"{role}.{vendor}.example"
            add(ip, asn, [name])
            svc(f"{vendor}_{role}", Endpoint(name, ip, 443 if role != "connectivity" else 80))
        asn_c, ip_c = cdn_edges[rng.randrange(len(cdn_edges))]
        fw = f"fw.{vendor}.example"
        add(ip_c, asn_c, [fw])
        svc("firmware", Endpoint(fw, ip_c, 443))

    # gaming
    for i in range(16):
        ip = alloc.ip(64620)
        name = f"match{i:02d}.gamenet.example"
        add(ip, 64620, [name])
        svc("game_servers", Endpoint(name, ip, 3074 + (i % 4), "udp"))
    for i in range(3):
        asn, ip = cdn_edges[rng.randrange(len(cdn_edges))]
        name = f"patch{i}.gamenet.example"
        add(ip, asn, [name])
        svc("game_cdn", Endpoint(name, ip, 443))
    ip = alloc.ip(64620)
    add(ip, 64620, ["presence.gamenet.example"])
    svc("game_presence", Endpoint("presence.gamenet.example", ip, 443))

    # general cloud: apps, push, ntp, android connectivity check
    for i in range(400):
        ip = alloc.ip(64630)
        name = f"{rng.choice(_BRANDS)}-api{i}.cloudapp.example"
        add(ip, 64630, [name])
        svc("web", Endpoint(name, ip, 443))
    for name, svcname, port, proto in (("push.mobile-os.example", "push", 5228, "tcp"),
                                       ("time.ntp-pool.example", "ntp", 123, "udp"),
                                       ("connectivitycheck.mobile-os.example", "connectivity", 80, "tcp"),
                                       ("play.appstore-os.example", "appstore", 443, "tcp"),
                                       ("telemetry.mobile-os.example", "os_telemetry", 443, "tcp")):
        ip = alloc.ip(64630)
        add(ip, 64630, [name])
        svc(svcname, Endpoint(name, ip, port, proto))  # type: ignore[arg-type]

    # VPN and camera cloud
    for i in range(4):
        ip = alloc.ip(64640)
        name = f"gw{i}.securetunnel.example"
        add(ip, 64640, [name])
        svc("vpn", Endpoint(name, ip, 51820, "udp"))
    for i in range(3):
        ip = alloc.ip(64660)
        name = f"ingest{i}.camcloud.example"
        add(ip, 64660, [name])
        svc("cam_cloud", Endpoint(name, ip, 443))
    add(RESOLVER_IP, 64670, ["resolver.isp.example"])

    # victims for DDoS emulation (benign third parties; never enforcement targets)
    for i in range(6):
        ip = alloc.ip(64710)
        add(ip, 64710, [f"shop{i}.victim-hosting.example"])
        svc("ddos_victims", Endpoint(f"shop{i}.victim-hosting.example", ip, 80))

    # ---------------------------------------------------------------- malicious infrastructure
    malicious: list[MaliciousInfra] = []

    def dedicated_c2(names: list[str], asn: int = 64700) -> list[str]:
        ips = []
        for n in names:
            ip = alloc.ip(asn)
            add(ip, asn, [n], kind="dedicated")
            ips.append(ip)
        return ips

    bb_domains = ["api.tvsync-update.example", "cfg.boxhelper.example"]
    bb_ips = dedicated_c2(bb_domains)
    bb_novel = dedicated_c2(["upd2.tvsync-cdn.example"])
    asn_s, shared_ip = cdn_edges[rng.randrange(len(cdn_edges))]
    add(shared_ip, asn_s, ["img.tvsync-update.example"])          # malicious co-tenant on shared CDN
    proxy_ctl = dedicated_c2(["bc1.proxyhub.example", "bc2.proxyhub.example"], asn=64701)
    malicious.append(MaliciousInfra(
        family="badbox2_emu", c2_domains=bb_domains + ["upd2.tvsync-cdn.example"], c2_ips=bb_ips + bb_novel,
        c2_port=443, c2_protocol="tcp", cohosted_domains=["img.tvsync-update.example"],
        proxy_controllers=proxy_ctl, novel_ips=bb_novel))

    vo_domains = ["ntp.voidsync.example"]
    vo_ips = dedicated_c2(vo_domains)
    dga_seed = rng.randrange(1 << 30)
    vo_dga_ip = dedicated_c2(["dga-sink.voidsync.example"])
    malicious.append(MaliciousInfra(
        family="vo1d_emu", c2_domains=vo_domains, c2_ips=vo_ips + vo_dga_ip, c2_port=55600,
        c2_protocol="tcp", dga_seed=dga_seed))

    mi_domains = ["cnc.botnet-ctl.test"]
    mi_ips = dedicated_c2(mi_domains)
    mi_novel = dedicated_c2(["cnc2.botnet-ctl.test"])
    malicious.append(MaliciousInfra(
        family="mirai_emu", c2_domains=mi_domains + ["cnc2.botnet-ctl.test"], c2_ips=mi_ips + mi_novel,
        c2_port=48101, c2_protocol="tcp", novel_ips=mi_novel))

    # residential-proxy egress targets: a broad slice of the cloud (benign third parties)
    return HostingTopology(f"lab-topology-{seed}", hosts.values(), services, malicious)
