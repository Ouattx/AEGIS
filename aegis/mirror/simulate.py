"""MIRROR impact simulation (spec section 9).

Given a proposed DNS / IP / device control, compute the affected entities, known
legitimate co-tenants (from the hosting topology and the CONSTELLATION graph), the
historic aggregate impact, reversibility and unknowns, and classify the action:

* ``SAFE``    - the footprint is fully known and contains no legitimate collateral;
* ``UNSAFE``  - legitimate collateral, critical infrastructure, a known legitimate
                service or an invalid target would be hit;
* ``UNKNOWN`` - the footprint cannot be established (incomplete topology, target
                outside the known topology, graph failure). UNKNOWN is treated as
                UNSAFE everywhere downstream (fail closed).

Unknowns come in two kinds. *Blocking* unknowns (the footprint itself is unknown)
force ``UNKNOWN``. *Advisory* unknowns (no traffic history, no graph attached,
households behind a line) leave the verdict alone but always set
``requires_human_approval`` because collateral impact is uncertain.

The simulation is deterministic and read-only: it never changes topology, graph
or history, and it never consults a language model.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Protocol, runtime_checkable

from aegis.contracts.models import (
    ActionType,
    MirrorResult,
    MirrorVerdict,
    ProposedAction,
)
from aegis.mirror.base import InvalidTargetError, normalize_domain, normalize_target
from aegis.mirror.history import TrafficHistory

#: Host kinds whose blocking would disrupt core service for everybody.
CRITICAL_HOST_KINDS = frozenset({"resolver"})
#: Host kinds that are attack victims (DDoS targets): never enforcement targets.
VICTIM_HOST_KINDS = frozenset({"victim"})
#: Default number of affected entities above which a human must approve.
DEFAULT_MAX_AFFECTED_ENTITIES = 500

Reversibility = Literal["instant", "minutes", "manual", "unknown"]

_REVERSIBILITY: dict[ActionType, Reversibility] = {
    # RPZ / resolver policy reload is immediate, but cached answers live up to the record TTL.
    ActionType.DNS_SINKHOLE: "minutes",
    ActionType.IP_BLOCK: "minutes",
    ActionType.DEVICE_QUARANTINE: "minutes",
    # A notification cannot be unsent.
    ActionType.NOTIFY_SUBSCRIBER: "manual",
}

_SUBSCRIBER_FACING = frozenset({ActionType.DEVICE_QUARANTINE, ActionType.NOTIFY_SUBSCRIBER})


@runtime_checkable
class TopologyView(Protocol):
    """What the operator knows about destination hosting.

    :class:`aegis.lab.topology.HostingTopology` implements this protocol; a
    production deployment adapts its IPAM / CDN inventory to it.
    """

    complete: bool

    def covers(self, ip: str) -> bool: ...
    def host(self, ip: str) -> Any | None: ...
    def is_shared(self, ip: str) -> bool | None: ...
    def cotenants(self, ip: str, exclude: Iterable[str] = ()) -> list[str]: ...
    def resolve(self, domain: str) -> list[str]: ...
    def domains(self) -> list[str]: ...


@dataclass
class _Acc:
    """Accumulator for one simulation."""
    blocking: list[str] = field(default_factory=list)
    advisory: list[str] = field(default_factory=list)
    unsafe: list[str] = field(default_factory=list)
    cotenants: dict[str, None] = field(default_factory=dict)   # ordered set
    shared: bool = False
    legit_indicators: dict[str, None] = field(default_factory=dict)  # for flow estimate
    footprint: dict[str, None] = field(default_factory=dict)         # for entity estimate
    notes: list[str] = field(default_factory=list)
    unrelated: set[str] = field(default_factory=set)                 # targets with no case link

    def cotenant(self, name: str) -> None:
        self.cotenants[name] = None


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _is_ip(value: str) -> bool:
    try:
        normalize_target(ActionType.IP_BLOCK, value)
        return True
    except InvalidTargetError:
        return False


def _canon_indicator(value: str) -> str | None:
    """Best-effort canonical form of a case indicator (domain or IP); None if invalid."""
    for t in (ActionType.IP_BLOCK, ActionType.DNS_SINKHOLE):
        try:
            return normalize_target(t, value)
        except InvalidTargetError:
            continue
    return None


class _Graph:
    """Thin, failure-tolerant facade over :class:`aegis.constellation.graph.Constellation`."""

    def __init__(self, constellation: Any, tenant_id: str, as_of: datetime | None, acc: _Acc):
        self.constellation = constellation
        self.tenant_id = tenant_id
        self.as_of = as_of
        self.acc = acc

    def _call(self, what: str, fn: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # any graph failure means the footprint is not known
            self.acc.blocking.append(f"graph_query_failed:{what}:{type(exc).__name__}")
            return None

    def resolving_domains(self, ip: str) -> list[str]:
        """Domains with an active ``observed_resolves_to`` edge into ``ip``."""
        from aegis.constellation.graph import EdgeType

        nbrs = self._call("neighbors", self.constellation.neighbors, self.tenant_id, f"ip:{ip}",
                          self.as_of, edge_types=[EdgeType.OBSERVED_RESOLVES_TO])
        return [n.node_id.partition(":")[2] for n in nbrs or []
                if n.direction == "in" and n.node_id.startswith("domain:")]

    def dependents(self, domain: str) -> list[str]:
        """Domains that resolve *through* ``domain`` (CNAME-style resolves edges into it)."""
        from aegis.constellation.graph import EdgeType

        nbrs = self._call("neighbors", self.constellation.neighbors, self.tenant_id, f"domain:{domain}",
                          self.as_of, edge_types=[EdgeType.OBSERVED_RESOLVES_TO])
        return [n.node_id.partition(":")[2] for n in nbrs or []
                if n.direction == "in" and n.node_id.startswith("domain:")]

    def resolved_ips(self, domain: str) -> list[str]:
        from aegis.constellation.graph import EdgeType

        nbrs = self._call("neighbors", self.constellation.neighbors, self.tenant_id, f"domain:{domain}",
                          self.as_of, edge_types=[EdgeType.OBSERVED_RESOLVES_TO])
        return [n.node_id.partition(":")[2] for n in nbrs or []
                if n.direction == "out" and n.node_id.startswith("ip:")]

    def is_shared(self, ip: str) -> bool:
        shared = self._call("is_shared_hosting", self.constellation.is_shared_hosting,
                            self.tenant_id, f"ip:{ip}", self.as_of)
        node = self._call("get_node", self.constellation.get_node, self.tenant_id, f"ip:{ip}", self.as_of)
        flagged = bool(node is not None and (node.attrs or {}).get("shared_hosting") is True)
        return bool(shared) or flagged

    def knows_domain(self, domain: str) -> bool:
        node = self._call("get_node", self.constellation.get_node, self.tenant_id,
                          f"domain:{domain}", self.as_of)
        return node is not None

    def attributed_to_threat(self, domain_or_ip: str, kind: str) -> bool:
        """True if an enforcement-eligible ``attributed_to`` edge links it to a malware family."""
        from aegis.constellation.graph import EdgeType

        nbrs = self._call("neighbors", self.constellation.neighbors, self.tenant_id,
                          f"{kind}:{domain_or_ip}", self.as_of,
                          edge_types=[EdgeType.ATTRIBUTED_TO])
        return any(n.direction == "out" and n.node_id.startswith("malware_family:")
                   and n.edge.enforcement_eligible for n in nbrs or [])

    def known_domains(self) -> list[str]:
        from aegis.constellation.graph import NodeType

        nodes = self._call("nodes", self.constellation.nodes, self.tenant_id, self.as_of)
        return [n.value for n in nodes or [] if n.node_type is NodeType.DOMAIN]


def simulate(action: ProposedAction, topology: TopologyView | None, graph: Any | None,
             history: TrafficHistory | None, *, now: datetime | None = None,
             case_indicators: Iterable[str] = (),
             case_entities: Iterable[str] | None = None,
             max_affected_entities: int = DEFAULT_MAX_AFFECTED_ENTITIES) -> MirrorResult:
    """Simulate the impact of ``action``. Never raises for bad input: it fails closed.

    ``topology``      operator hosting knowledge (``None`` => UNKNOWN for DNS/IP actions)
    ``graph``         an :class:`~aegis.constellation.graph.Constellation` or ``None`` (advisory unknown)
    ``history``       historic aggregates (``None`` => impact unknown, human approval)
    ``now``           evaluation time; also the ``as_of`` for graph queries when given
    ``case_indicators`` domains/IPs that the case evidence ties to the threat; names
                      in this set hosted on a target IP are not counted as legitimate
                      co-tenants. Names attributed to a malware family in CONSTELLATION
                      (enforcement-eligible ``attributed_to`` edge) are excluded too.
                      Targets themselves are *not* assumed malicious: a DNS / IP target
                      that is neither a case indicator nor threat-attributed is treated
                      as a legitimate name (its traffic counts as collateral, a human
                      must approve) and is ``UNSAFE`` when it sits on shared
                      infrastructure or is a known legitimate service.
    ``case_entities`` pseudonyms of the devices the case is about; when given, a device
                      or subscriber control on any other entity is ``UNSAFE``.
    """
    computed_at = _utc(now) if now is not None else datetime.now(timezone.utc)
    as_of = computed_at if now is not None else None
    acc = _Acc()

    targets: list[str] = []
    for raw in action.targets:
        try:
            t = normalize_target(action.action_type, raw)
        except InvalidTargetError:
            acc.unsafe.append(f"invalid_target:{str(raw)[:100]}")
            continue
        if t not in targets:
            targets.append(t)
    if not action.targets:
        acc.unsafe.append("no_targets")

    # only case evidence (and signed CONSTELLATION attribution, checked per name) ties a name to
    # the threat; the proposer's choice of target never does
    threat: set[str] = set()
    for ind in case_indicators:
        c = _canon_indicator(ind)
        if c is not None:
            threat.add(c)

    gfacade = _Graph(graph, action.tenant_id, as_of, acc) if graph is not None else None
    affected: int | None = None

    if action.action_type in (ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK):
        kind = "ip" if action.action_type is ActionType.IP_BLOCK else "domain"
        linked = set(threat)
        if kind == "ip":
            # an address that a case-indicator domain resolves to is tied to the case too
            for dom in [x for x in threat if not _is_ip(x)]:
                if topology is not None:
                    linked.update(topology.resolve(dom))
                if gfacade is not None:
                    linked.update(gfacade.resolved_ips(dom))
        for t in targets:
            if t in linked or (gfacade is not None and gfacade.attributed_to_threat(t, kind)):
                continue
            acc.advisory.append(f"target_not_in_case_evidence:{t}")
            acc.unrelated.add(t)
            acc.legit_indicators[t] = None
    elif case_entities is not None:
        allowed = {e.strip() for e in case_entities if isinstance(e, str)}
        for t in targets:
            if t not in allowed:
                acc.unsafe.append(f"target_not_a_case_entity:{t}")

    if action.action_type in (ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK):
        if topology is None:
            acc.blocking.append("topology_unavailable")
        elif not getattr(topology, "complete", False):
            acc.blocking.append("topology_incomplete")
        if gfacade is None:
            acc.advisory.append("graph_unavailable")
        if topology is not None:
            if action.action_type is ActionType.IP_BLOCK:
                for ip in targets:
                    _simulate_ip(ip, topology, gfacade, threat, acc)
            else:
                include_subdomains = bool(action.scope.get("include_subdomains", False))
                for dom in targets:
                    _simulate_domain(dom, topology, gfacade, threat, include_subdomains, acc)
        affected = _affected_from_history(action.tenant_id, list(acc.footprint), history, acc)
    else:
        # device / line controls: the footprint is the pseudonymous entities themselves
        affected = len(targets) if targets else None
        if action.scope.get("vantage") != "device":
            acc.advisory.append("entities_behind_line_unknown")
        acc.advisory.append("device_legitimate_traffic_unknown")
        acc.notes.append("subscriber-facing control: always needs a human approver")

    legit_flows = _legit_flows(action, history, acc)

    if affected is not None and affected > max_affected_entities:
        acc.advisory.append(f"large_blast_radius:{affected}>{max_affected_entities}")

    if acc.unsafe:
        verdict = MirrorVerdict.UNSAFE
    elif acc.blocking:
        verdict = MirrorVerdict.UNKNOWN
    else:
        verdict = MirrorVerdict.SAFE

    unknowns = list(dict.fromkeys(acc.blocking + acc.advisory))
    cotenants = sorted(acc.cotenants)
    requires_human = (verdict is not MirrorVerdict.SAFE or acc.shared or bool(cotenants)
                      or bool(unknowns) or action.action_type in _SUBSCRIBER_FACING)

    rationale = _rationale(verdict, action, targets, acc, cotenants, affected, legit_flows)
    return MirrorResult(
        action_id=action.action_id,
        verdict=verdict,
        affected_entities=affected,
        legitimate_cotenants=cotenants,
        shared_infrastructure=acc.shared,
        historic_daily_legit_flows=legit_flows,
        reversibility=_REVERSIBILITY.get(action.action_type, "unknown"),
        unknowns=unknowns,
        requires_human_approval=requires_human,
        rationale=rationale,
        computed_at=computed_at,
    )


# --------------------------------------------------------------------------- per target

def _host_kind(host: Any) -> str | None:
    kind = getattr(host, "kind", None)
    return kind if isinstance(kind, str) else None


def _simulate_ip(ip: str, topology: TopologyView, g: _Graph | None, threat: set[str],
                 acc: _Acc) -> None:
    acc.footprint[ip] = None
    host = topology.host(ip)
    if not topology.covers(ip) or host is None:
        acc.blocking.append(f"ip_not_in_topology:{ip}")
        return
    kind = _host_kind(host)
    if kind in CRITICAL_HOST_KINDS:
        acc.unsafe.append(f"critical_infrastructure:{ip}")
    if kind in VICTIM_HOST_KINDS:
        acc.unsafe.append(f"attack_victim_not_a_target:{ip}")

    shared = topology.is_shared(ip)
    if shared is None:
        acc.blocking.append(f"ip_sharing_unknown:{ip}")
    names = list(topology.cotenants(ip))
    if g is not None:
        names += g.resolving_domains(ip)
        if g.is_shared(ip):
            shared = True
    legit: list[str] = []
    for n in dict.fromkeys(names):
        try:
            dn = normalize_domain(n)
        except InvalidTargetError:
            dn = n.strip().lower()
        if dn in threat:
            continue
        if g is not None and g.attributed_to_threat(dn, "domain"):
            continue
        legit.append(dn)
    if shared:
        acc.shared = True
        if ip in acc.unrelated:
            acc.unsafe.append(f"unrelated_target_on_shared_infrastructure:{ip}")
    if legit:
        acc.shared = acc.shared or len(legit) > 1
        for n in legit:
            acc.cotenant(n)
        acc.legit_indicators[ip] = None
        acc.unsafe.append(f"legitimate_cotenants_on_ip:{ip}:{len(legit)}")
    elif shared:
        # shared hosting but every known name is threat-attributed: still collateral-prone
        acc.legit_indicators[ip] = None
        acc.advisory.append(f"shared_hosting_without_known_legit_names:{ip}")


def _simulate_domain(dom: str, topology: TopologyView, g: _Graph | None, threat: set[str],
                     include_subdomains: bool, acc: _Acc) -> None:
    acc.footprint[dom] = None
    topo_ips = topology.resolve(dom)
    topo_domains = set(topology.domains())
    known = bool(topo_ips) or dom in topo_domains
    graph_ips: list[str] = []
    if g is not None:
        known = known or g.knows_domain(dom)
        graph_ips = g.resolved_ips(dom)
    if not known:
        acc.blocking.append(f"domain_footprint_unknown:{dom}")

    services = getattr(topology, "services", None)
    if isinstance(services, dict):
        legit_service_names = {getattr(ep, "hostname", "").lower()
                               for eps in services.values() for ep in eps}
        if dom in legit_service_names:
            acc.unsafe.append(f"known_legitimate_service:{dom}")
            acc.cotenant(dom)
            acc.legit_indicators[dom] = None

    for ip in dict.fromkeys(topo_ips + graph_ips):
        host = topology.host(ip)
        if host is not None and _host_kind(host) in CRITICAL_HOST_KINDS:
            acc.unsafe.append(f"resolves_to_critical_infrastructure:{dom}")
        if topology.is_shared(ip) or (g is not None and g.is_shared(ip)):
            if dom in acc.unrelated:
                acc.shared = True
                acc.cotenant(dom)
                acc.unsafe.append(f"unrelated_target_on_shared_infrastructure:{dom}@{ip}")
            else:
                acc.notes.append(f"{dom} is hosted on shared infrastructure {ip}; "
                                 "a DNS-level control affects only the listed name(s)")

    if g is not None:
        for dep in g.dependents(dom):
            if dep not in threat:
                acc.cotenant(dep)
                acc.legit_indicators[dep] = None
                acc.unsafe.append(f"dependent_domain:{dep}->{dom}")

    if include_subdomains:
        candidates = set(topo_domains)
        if g is not None:
            candidates |= set(g.known_domains())
        subs = sorted(c for c in candidates if c.endswith("." + dom))
        for s in subs:
            acc.footprint[s] = None
            if s in threat or (g is not None and g.attributed_to_threat(s, "domain")):
                continue
            acc.cotenant(s)
            acc.legit_indicators[s] = None
            acc.unsafe.append(f"legitimate_subdomain:{s}")
        if subs:
            acc.shared = True
        if not getattr(topology, "complete", False):
            acc.blocking.append(f"subdomain_inventory_incomplete:{dom}")


# --------------------------------------------------------------------------- impact

def _affected_from_history(tenant_id: str, footprint: list[str], history: TrafficHistory | None,
                           acc: _Acc) -> int | None:
    if history is None:
        acc.advisory.append("traffic_history_unavailable")
        return None
    if not footprint:
        return None
    union = getattr(history, "entities_for", None)
    if callable(union):
        ents = union(tenant_id, footprint)
        if ents is None:
            acc.advisory.append("traffic_history_does_not_cover_tenant")
            return None
        return len(ents)
    total = 0
    for ind in footprint:
        n = history.distinct_entities(tenant_id, ind)
        if n is None:
            acc.advisory.append(f"history_missing:{ind}")
            return None
        total += n          # upper bound: entities may overlap across indicators
    return total


def _legit_flows(action: ProposedAction, history: TrafficHistory | None,
                 acc: _Acc) -> int | None:
    """Upper bound of legitimate daily flows the control would disrupt."""
    if action.action_type in _SUBSCRIBER_FACING:
        return None
    if acc.blocking and set(acc.legit_indicators) <= acc.unrelated:
        return None  # footprint unknown and no known legitimate name in it: unknown, not zero
    if not acc.legit_indicators:
        return 0     # footprint fully known and no legitimate name in it: a known zero
    if history is None:
        return None
    total = 0.0
    for ind in acc.legit_indicators:
        f = history.daily_flows(action.tenant_id, ind)
        if f is None:
            acc.advisory.append(f"history_missing:{ind}")
            return None
        total += f
    return int(round(total))


def _rationale(verdict: MirrorVerdict, action: ProposedAction, targets: list[str], acc: _Acc,
               cotenants: list[str], affected: int | None, legit_flows: int | None) -> str:
    parts = [f"{verdict.value}: {action.action_type.value} on {len(targets)} target(s)."]
    if acc.unsafe:
        parts.append("Unsafe because: " + "; ".join(dict.fromkeys(acc.unsafe)) + ".")
    if acc.blocking:
        parts.append("Footprint unknown (fail closed): "
                     + "; ".join(dict.fromkeys(acc.blocking)) + ".")
    if cotenants:
        shown = ", ".join(cotenants[:10]) + (" ..." if len(cotenants) > 10 else "")
        parts.append(f"{len(cotenants)} legitimate co-tenant(s) affected: {shown}.")
    parts.append("Affected entities: " + ("unknown" if affected is None else str(affected)) + ".")
    parts.append("Legitimate daily flows disrupted (upper bound): "
                 + ("unknown" if legit_flows is None else str(legit_flows)) + ".")
    if acc.advisory:
        parts.append("Uncertainties: " + "; ".join(dict.fromkeys(acc.advisory)) + ".")
    parts.extend(dict.fromkeys(acc.notes))
    return " ".join(parts)
