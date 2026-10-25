"""Operator hosting topology used by MIRROR impact simulation.

An operator uploads what it knows about destination hosting (IPAM / CDN inventory)
as JSON. The same shape the lab topology serializes to is accepted::

    {
      "topology_id": "isp-a-2026-10",
      "complete": true,                      # false => every IP/DNS simulation is UNKNOWN
      "prefixes": ["198.51.100.0/24"],       # address space the inventory claims to cover
      "asns": {"64500": {"provider": "...", "prefix": "203.0.113.0/24", "kind": "..."}},
      "hosts": [{"ip": "198.51.100.7", "asn": 64500, "provider": "cdn-x",
                 "kind": "shared_cdn", "hostnames": ["a.example", "b.example"], "shared": true}]
    }

``prefixes`` and the ``prefix`` of every ``asns`` entry together define coverage:
an address outside them is unknown and simulation fails closed. ``kind`` values
``resolver`` (critical) and ``victim`` (DDoS target) are never enforcement targets.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Iterable

MAX_HOSTS = 2_000_000
MAX_PREFIXES = 100_000


class TopologyError(ValueError):
    """The uploaded topology document is invalid."""


@dataclass(frozen=True)
class OperatorHost:
    ip: str
    kind: str | None
    hostnames: tuple[str, ...]
    asn: int | None = None
    provider: str | None = None
    explicit_shared: bool | None = None

    @property
    def shared(self) -> bool:
        if self.explicit_shared is not None:
            return self.explicit_shared
        return self.kind == "shared_cdn" or len(self.hostnames) > 1


@dataclass
class OperatorTopology:
    """:class:`aegis.mirror.simulate.TopologyView` over an operator inventory."""
    topology_id: str
    complete: bool
    prefixes: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    hosts: dict[str, OperatorHost]
    _domains: dict[str, list[str]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for h in self.hosts.values():
            for name in h.hostnames:
                self._domains.setdefault(name, []).append(h.ip)

    # -- TopologyView -------------------------------------------------------------------
    def covers(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.prefixes)

    def host(self, ip: str) -> OperatorHost | None:
        return self.hosts.get(_canon_ip(ip))

    def is_shared(self, ip: str) -> bool | None:
        h = self.host(ip)
        return None if h is None else h.shared

    def cotenants(self, ip: str, exclude: Iterable[str] = ()) -> list[str]:
        h = self.host(ip)
        if h is None:
            return []
        ex = set(exclude)
        return [n for n in h.hostnames if n not in ex]

    def resolve(self, domain: str) -> list[str]:
        return list(self._domains.get(domain.lower().rstrip("."), []))

    def domains(self) -> list[str]:
        return sorted(self._domains)

    def summary(self) -> dict[str, Any]:
        return {"topology_id": self.topology_id, "complete": self.complete,
                "prefixes": len(self.prefixes), "hosts": len(self.hosts),
                "shared_hosts": sum(1 for h in self.hosts.values() if h.shared),
                "domains": len(self._domains)}


def _canon_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return str(value).strip()


def parse_topology(doc: Any) -> OperatorTopology:
    """Validate and build an :class:`OperatorTopology` (raises :class:`TopologyError`)."""
    if not isinstance(doc, dict):
        raise TopologyError("topology must be a JSON object")
    tid = doc.get("topology_id")
    if not isinstance(tid, str) or not tid.strip() or len(tid) > 128:
        raise TopologyError("topology_id must be a non-empty string (<= 128 chars)")
    complete = doc.get("complete", True)
    if not isinstance(complete, bool):
        raise TopologyError("complete must be a boolean")

    raw_prefixes: list[Any] = list(doc.get("prefixes") or [])
    asns = doc.get("asns") or {}
    if not isinstance(asns, dict):
        raise TopologyError("asns must be an object")
    for entry in asns.values():
        if isinstance(entry, dict) and entry.get("prefix"):
            raw_prefixes.append(entry["prefix"])
    if len(raw_prefixes) > MAX_PREFIXES:
        raise TopologyError(f"too many prefixes (max {MAX_PREFIXES})")
    prefixes = []
    for p in raw_prefixes:
        try:
            prefixes.append(ipaddress.ip_network(str(p), strict=False))
        except ValueError as exc:
            raise TopologyError(f"invalid prefix {p!r}") from exc

    raw_hosts = doc.get("hosts")
    if not isinstance(raw_hosts, list):
        raise TopologyError("hosts must be a list")
    if len(raw_hosts) > MAX_HOSTS:
        raise TopologyError(f"too many hosts (max {MAX_HOSTS})")
    hosts: dict[str, OperatorHost] = {}
    for i, h in enumerate(raw_hosts):
        if not isinstance(h, dict):
            raise TopologyError(f"hosts[{i}] must be an object")
        try:
            ip = str(ipaddress.ip_address(str(h.get("ip", "")).strip()))
        except ValueError as exc:
            raise TopologyError(f"hosts[{i}].ip is not an IP address") from exc
        names = h.get("hostnames") or []
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise TopologyError(f"hosts[{i}].hostnames must be a list of strings")
        kind = h.get("kind")
        if kind is not None and not isinstance(kind, str):
            raise TopologyError(f"hosts[{i}].kind must be a string")
        shared = h.get("shared")
        if shared is not None and not isinstance(shared, bool):
            raise TopologyError(f"hosts[{i}].shared must be a boolean")
        asn = h.get("asn")
        if asn is not None and (not isinstance(asn, int) or isinstance(asn, bool)):
            raise TopologyError(f"hosts[{i}].asn must be an integer")
        provider = h.get("provider")
        hosts[ip] = OperatorHost(ip=ip, kind=kind, asn=asn,
                                 provider=provider if isinstance(provider, str) else None,
                                 hostnames=tuple(dict.fromkeys(n.strip().lower().rstrip(".")
                                                               for n in names if n.strip())),
                                 explicit_shared=shared)
    if hosts and not prefixes:
        raise TopologyError("a topology with hosts must declare the prefixes it covers")
    return OperatorTopology(topology_id=tid.strip(), complete=complete, prefixes=prefixes, hosts=hosts)


__all__ = ["OperatorHost", "OperatorTopology", "TopologyError", "parse_topology"]
