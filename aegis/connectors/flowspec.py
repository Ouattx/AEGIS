"""BGP FlowSpec rule *proposals* for outbound abuse seen by EGRESS (RFC 8955 / RFC 8956).

Nothing here talks BGP or touches a router. :func:`propose_flowspec` turns an
:class:`~aegis.egress.models.EgressReport` into reviewed-by-a-human proposals, and the
renderers print them as text for common syntaxes. Every rendering starts with
:data:`~aegis.connectors.common.PROPOSAL_NOTICE`.

Semantics (RFC 8955 section 4 for IPv4, RFC 8956 for IPv6):

* match components, in type order: destination prefix (1), source prefix (2), IP protocol
  / next header (3), destination port (5), packet length (10). A rule always has a
  destination prefix *and* one of the operator's subscriber source prefixes, so it can only
  touch traffic leaving the operator's own customers toward one victim;
* action: ``traffic-rate-bytes`` (extended community type 0x8006) with a non-zero rate,
  i.e. a rate limit, by default. A rate of 0 (discard) is only proposed when the config
  allows it *and* the evidence is corroborated (MALICIOUS);
* optional ``traffic-action`` (0x8007) sample bit, so the operator can watch what matches.

When the evidence cannot support a safe rule the proposal is skipped with a reason
(abstention): spoofed reflection requests (a source-prefix rule cannot match spoofed
packets; BCP 38 / uRPF at the subscriber edge is the remedy), no subscriber source prefix
configured, a target on shared hosting, an abstained verdict, or a label FlowSpec does not
address (proxy relaying, spam, credential stuffing).

The router texts are illustrative renderings of the same rule for Junos (``set`` commands),
Cisco IOS XR (flowspec class-map / policy-map) and ExaBGP (configuration ``flow`` block).
Keywords and units vary between software releases: the operator verifies them.
"""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Any, Iterable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.connectors.common import PROPOSAL_NOTICE, ExportPayload, utc
from aegis.egress.config import LABEL_AMPLIFICATION, LABEL_DDOS, LABEL_REFLECTOR
from aegis.egress.detector import MAX_LISTED_PORTS
from aegis.egress.models import EgressReport, LineSignal, LineVerdict

Syntax = Literal["junos", "iosxr", "exabgp"]
SYNTAXES: tuple[Syntax, ...] = ("junos", "iosxr", "exabgp")

PROTOCOL_NUMBERS = {"icmp": 1, "tcp": 6, "udp": 17}
_PROTO_NAMES = {v: k for k, v in PROTOCOL_NUMBERS.items()}

#: Host kinds (``HostingContext.kind``) a destination rule must never target.
SHARED_KINDS = frozenset({"shared_cdn"})


class ComponentType(IntEnum):
    """FlowSpec NLRI component types (RFC 8955 section 4.2.2; RFC 8956 for IPv6)."""

    DESTINATION_PREFIX = 1
    SOURCE_PREFIX = 2
    IP_PROTOCOL = 3
    PORT = 4
    DESTINATION_PORT = 5
    SOURCE_PORT = 6
    ICMP_TYPE = 7
    ICMP_CODE = 8
    TCP_FLAGS = 9
    PACKET_LENGTH = 10
    DSCP = 11
    FRAGMENT = 12


class HostingContext(Protocol):
    def kind(self, ip: str) -> str | None: ...


class Range(BaseModel):
    """Inclusive numeric range; ``lo == hi`` is an equality match."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    lo: int = Field(ge=0, le=65535)
    hi: int = Field(ge=0, le=65535)

    @model_validator(mode="after")
    def _order(self) -> "Range":
        if self.lo > self.hi:
            raise ValueError("range lo must be <= hi")
        return self

    def numeric_op(self) -> str:
        """RFC 8955 numeric-operator notation (``=80`` or ``>=1000&<=2000``)."""
        return f"={self.lo}" if self.lo == self.hi else f">={self.lo}&<={self.hi}"

    def dash(self) -> str:
        return str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"


class FlowSpecMatch(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    afi: Literal["ipv4", "ipv6"]
    destination: str
    source: str
    protocols: tuple[int, ...] = ()
    destination_ports: tuple[Range, ...] = ()
    packet_lengths: tuple[Range, ...] = ()

    @field_validator("destination", "source")
    @classmethod
    def _prefix(cls, v: str) -> str:
        return str(ipaddress.ip_network(v, strict=False))

    @field_validator("protocols")
    @classmethod
    def _protos(cls, v: tuple[int, ...]) -> tuple[int, ...]:
        if any(not 0 <= p <= 255 for p in v):
            raise ValueError("protocol numbers are 0..255")
        return tuple(sorted(set(v)))

    @model_validator(mode="after")
    def _family(self) -> "FlowSpecMatch":
        d = ipaddress.ip_network(self.destination)
        s = ipaddress.ip_network(self.source)
        want = 4 if self.afi == "ipv4" else 6
        if d.version != want or s.version != want:
            raise ValueError("destination and source must both match the address family")
        if d.prefixlen == 0:
            raise ValueError("a default-route destination is never proposed")
        if self.destination_ports and not set(self.protocols) <= {6, 17}:
            raise ValueError("destination ports need protocol tcp and/or udp")
        return self


class FlowSpecAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["rate_limit", "discard"] = "rate_limit"
    rate_bytes_per_s: int = Field(default=1_250_000, ge=0)
    sample: bool = True

    @model_validator(mode="after")
    def _rate(self) -> "FlowSpecAction":
        if self.kind == "rate_limit" and self.rate_bytes_per_s <= 0:
            raise ValueError("a rate limit needs a positive rate (0 means discard)")
        if self.kind == "discard" and self.rate_bytes_per_s != 0:
            raise ValueError("discard is traffic-rate-bytes 0")
        return self


class FlowSpecProposal(BaseModel):
    """One proposed rule. ``status`` is always ``proposed``: AEGIS never announces it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal_id: str
    name: str
    tenant_id: str
    status: Literal["proposed"] = "proposed"
    requires_operator_review: Literal[True] = True
    label: str
    verdict: Literal["malicious", "suspicious"]
    lines_involved: int = Field(ge=1)
    campaign_ids: tuple[str, ...] = ()
    match: FlowSpecMatch
    action: FlowSpecAction
    rationale: str
    caveats: tuple[str, ...] = ()
    created_at: datetime
    suggested_expiry: datetime

    def rfc8955(self) -> dict[str, Any]:
        """Protocol-level view: NLRI components in type order plus extended communities."""
        m = self.match
        comps: list[dict[str, Any]] = [
            {"type": int(ComponentType.DESTINATION_PREFIX), "name": "destination-prefix", "value": m.destination},
            {"type": int(ComponentType.SOURCE_PREFIX), "name": "source-prefix", "value": m.source},
        ]
        if m.protocols:
            comps.append({"type": int(ComponentType.IP_PROTOCOL),
                          "name": "ip-protocol" if m.afi == "ipv4" else "next-header",
                          "value": [f"={p}" for p in m.protocols]})
        if m.destination_ports:
            comps.append({"type": int(ComponentType.DESTINATION_PORT), "name": "destination-port",
                          "value": [r.numeric_op() for r in m.destination_ports]})
        if m.packet_lengths:
            comps.append({"type": int(ComponentType.PACKET_LENGTH), "name": "packet-length",
                          "value": [r.numeric_op() for r in m.packet_lengths]})
        communities: list[dict[str, Any]] = [{
            "type": "0x8006", "name": "traffic-rate-bytes", "as": 0,
            "rate_bytes_per_s": float(self.action.rate_bytes_per_s)}]
        if self.action.sample:
            communities.append({"type": "0x8007", "name": "traffic-action", "sample": True, "terminal": True})
        return {"afi": m.afi, "safi": 133, "rfc": "RFC 8955" if m.afi == "ipv4" else "RFC 8956",
                "nlri": comps, "extended_communities": communities}


class SkippedProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    label: str
    reason: str
    target: str | None = None
    entity_pseudonym: str | None = None
    detail: str = ""


class FlowSpecPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    generated_at: datetime
    detector_version: str
    config_hash: str
    proposals: list[FlowSpecProposal] = Field(default_factory=list)
    skipped: list[SkippedProposal] = Field(default_factory=list)


class FlowSpecConfig(BaseModel):
    """Operator inputs for proposals (nothing here is learned)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    #: the operator's subscriber aggregates; without one of the right family no rule is proposed
    source_prefixes: tuple[str, ...] = ()
    rate_bytes_per_s: int = Field(default=1_250_000, gt=0)       # 10 Mbit/s aggregate
    allow_discard: bool = False
    include_suspicious: bool = False
    include_reflectors: bool = True
    sample: bool = True
    ttl_hours: int = Field(default=4, ge=1, le=72)
    max_rules: int = Field(default=50, ge=1)
    #: a carpet-bombed prefix must not be wider than this (IPv4 / IPv6)
    max_prefix_v4: int = Field(default=24, ge=8, le=32)
    max_prefix_v6: int = Field(default=48, ge=16, le=128)

    @field_validator("source_prefixes")
    @classmethod
    def _sources(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        out = []
        for p in v:
            net = ipaddress.ip_network(p, strict=False)
            if net.prefixlen == 0:
                raise ValueError("a source prefix of /0 matches every source; give the subscriber aggregates")
            out.append(str(net))
        return tuple(dict.fromkeys(out))


# ---------------------------------------------------------------------------- building

def _dest_prefix(target: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(target, strict=False) if "/" in target \
            else ipaddress.ip_network(ipaddress.ip_address(target))
    except ValueError:
        return None


def _kind(context: HostingContext | None, ip: str) -> str | None:
    if context is None:
        return None
    try:
        return context.kind(ip)
    except Exception:  # foreign context objects: unknown, never a crash
        return None


def _ranges(ports: Iterable[Any]) -> tuple[Range, ...]:
    vals = sorted({int(p) for p in ports if isinstance(p, int) and not isinstance(p, bool)})
    return tuple(Range(lo=p, hi=p) for p in vals)


def propose_flowspec(report: EgressReport, cfg: FlowSpecConfig | None = None, *, now: datetime | None = None,
                     context: HostingContext | None = None) -> FlowSpecPlan:
    """Rate-limit proposals for DDoS participation and abused reflectors in ``report``."""
    cfg = cfg or FlowSpecConfig()
    now = utc(now) if now is not None else report.window_end
    plan = FlowSpecPlan(tenant_id=report.tenant_id, generated_at=now, detector_version=report.detector_version,
                        config_hash=report.config_hash)
    if report.status == "abstain":
        plan.skipped.append(SkippedProposal(label="*", reason="report_abstained", detail=report.abstain_reason or ""))
        return plan

    # (target, label) -> accumulated rule inputs
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for v in report.verdicts:
        if v.verdict == "abstain":
            plan.skipped.append(SkippedProposal(label=v.label, reason="verdict_abstain",
                                                entity_pseudonym=v.entity_pseudonym))
            continue
        if v.label == LABEL_AMPLIFICATION:
            plan.skipped.append(SkippedProposal(
                label=v.label, reason="spoofed_source_not_matchable", entity_pseudonym=v.entity_pseudonym,
                detail="reflection requests carry the victim's spoofed source address: a FlowSpec source-prefix "
                       "rule cannot match them; enforce BCP 38 / uRPF at the subscriber edge instead"))
            continue
        if v.label not in (LABEL_DDOS, LABEL_REFLECTOR):
            plan.skipped.append(SkippedProposal(label=v.label, reason="not_a_flowspec_use_case",
                                                entity_pseudonym=v.entity_pseudonym))
            continue
        if v.label == LABEL_REFLECTOR and not cfg.include_reflectors:
            plan.skipped.append(SkippedProposal(label=v.label, reason="reflectors_excluded_by_config",
                                                entity_pseudonym=v.entity_pseudonym))
            continue
        if v.verdict == "suspicious" and v.label == LABEL_DDOS and not cfg.include_suspicious:
            plan.skipped.append(SkippedProposal(label=v.label, reason="not_corroborated",
                                                entity_pseudonym=v.entity_pseudonym,
                                                detail="only MALICIOUS (corroborated) DDoS verdicts are proposed"))
            continue
        usable = [s for s in v.signals if s.kind in ("flood", "abused_reflector") and s.targets]
        if not usable:
            plan.skipped.append(SkippedProposal(
                label=v.label, reason="no_rule_inputs", entity_pseudonym=v.entity_pseudonym,
                detail="no flood or reflector signal with a target (onset or spoofing evidence only)"))
        for s in usable:
            _accumulate(groups, v, s)

    for (target, label), g in sorted(groups.items()):
        _build(plan, cfg, context, now, target, label, g)
    return plan


def _accumulate(groups: dict[tuple[str, str], dict[str, Any]], v: LineVerdict, s: LineSignal) -> None:
    target = s.targets[0]
    g = groups.setdefault((target, v.label), {"lines": set(), "campaigns": set(), "protocols": set(),
                                              "ports": set(), "ports_known": True, "verdicts": set(),
                                              "peak": 0.0})
    g["lines"].add(v.entity_pseudonym)
    g["campaigns"].update(v.campaign_ids)
    g["verdicts"].add(v.verdict)
    if s.kind == "abused_reflector":
        g["protocols"].add("udp")
        g["ports_known"] = False         # the reflected service port is a source port: not in flow records
    else:
        g["protocols"].update(s.metrics.get("protocols") or ["other"])
        ports = s.metrics.get("dst_ports") or []
        if ports:
            g["ports"].update(ports)
        else:
            g["ports_known"] = False
    g["peak"] += float(s.metrics.get("peak_pps") or 0.0)


def _build(plan: FlowSpecPlan, cfg: FlowSpecConfig, context: HostingContext | None, now: datetime,
           target: str, label: str, g: dict[str, Any]) -> None:
    def skip(reason: str, detail: str = "") -> None:
        plan.skipped.append(SkippedProposal(label=label, reason=reason, target=target, detail=detail))

    dest = _dest_prefix(target)
    if dest is None:
        return skip("target_not_an_address")
    afi: Literal["ipv4", "ipv6"] = "ipv4" if dest.version == 4 else "ipv6"
    if dest.prefixlen < (cfg.max_prefix_v4 if afi == "ipv4" else cfg.max_prefix_v6):
        return skip("destination_prefix_too_wide", f"{dest} is wider than the configured maximum")
    if _kind(context, str(dest.network_address)) in SHARED_KINDS:
        return skip("target_on_shared_infrastructure",
                    "a destination rule would also limit traffic to unrelated co-hosted services")
    sources = [p for p in cfg.source_prefixes if ipaddress.ip_network(p).version == dest.version]
    if not sources:
        return skip("source_prefixes_not_configured",
                    f"configure the subscriber {afi} aggregates so a rule only touches this operator's customers")
    protos = g["protocols"]
    protocols = () if "other" in protos else tuple(PROTOCOL_NUMBERS[p] for p in protos if p in PROTOCOL_NUMBERS)
    # ports narrow the rule only when every line used the same few (randomized ports => none)
    port_ok = g["ports_known"] and 0 < len(g["ports"]) <= MAX_LISTED_PORTS
    ports = _ranges(g["ports"]) if port_ok and protocols and set(protocols) <= {6, 17} else ()
    malicious = "malicious" in g["verdicts"]
    if cfg.allow_discard and malicious and label == LABEL_DDOS:
        action = FlowSpecAction(kind="discard", rate_bytes_per_s=0, sample=cfg.sample)
    else:
        action = FlowSpecAction(rate_bytes_per_s=cfg.rate_bytes_per_s, sample=cfg.sample)
    caveats = [
        "The rate limit applies to the aggregate of all matching subscriber traffic: legitimate customers "
        "reaching this destination share it.",
        "Withdraw the rule when the flood stops; it is proposed with a suggested expiry, not a permanent block.",
    ]
    if not protocols:
        caveats.append("No protocol component: the flood mixed protocols or used one FlowSpec cannot name.")
    if not ports:
        caveats.append("No port component: ports were randomized or unknown, so the rule is not port-scoped.")
    if label == LABEL_REFLECTOR:
        caveats.append("The subscriber is likely the victim of an open service on the CPE: contact them and close "
                       "the service; the rule only protects the third party meanwhile.")
    if _kind(context, str(dest.network_address)) is None:
        caveats.append("Destination hosting is unknown to AEGIS: check it is not shared infrastructure.")
    verdict: Literal["malicious", "suspicious"] = "malicious" if malicious else "suspicious"
    for src in sources:
        if len(plan.proposals) >= cfg.max_rules:
            return skip("max_rules_exceeded", f"max_rules={cfg.max_rules}")
        match = FlowSpecMatch(afi=afi, destination=str(dest), source=src, protocols=protocols,
                              destination_ports=ports)
        key = f"{plan.tenant_id}|{label}|{match.model_dump_json()}|{action.model_dump_json()}"
        pid = "fsp_" + hashlib.sha256(key.encode()).hexdigest()[:16]
        plan.proposals.append(FlowSpecProposal(
            proposal_id=pid, name=f"AEGIS-{pid[4:12]}", tenant_id=plan.tenant_id, label=label, verdict=verdict,
            lines_involved=len(g["lines"]), campaign_ids=tuple(sorted(g["campaigns"])), match=match, action=action,
            rationale=(f"{len(g['lines'])} subscriber line(s) sent one-way traffic toward {dest} "
                       f"(aggregate peak {g['peak']:,.0f} pps); EGRESS verdict {verdict}."
                       if label == LABEL_DDOS else
                       f"{len(g['lines'])} subscriber line(s) reflect amplified UDP toward {dest}; EGRESS verdict "
                       f"{verdict}."),
            caveats=tuple(caveats), created_at=now, suggested_expiry=now + timedelta(hours=cfg.ttl_hours)))


# ---------------------------------------------------------------------------- rendering

def _proto_word(p: int) -> str:
    return _PROTO_NAMES.get(p, str(p))


def _junos(p: FlowSpecProposal) -> list[str]:
    m = p.match
    base = "set routing-options flow" if m.afi == "ipv4" else "set routing-options rib inet6.0 flow"
    pre = f"{base} route {p.name}"
    out = [f"{pre} match destination {m.destination}", f"{pre} match source {m.source}"]
    out += [f"{pre} match protocol {_proto_word(x)}" for x in m.protocols]
    out += [f"{pre} match destination-port {r.dash()}" for r in m.destination_ports]
    out += [f"{pre} match packet-length {r.dash()}" for r in m.packet_lengths]
    if p.action.kind == "discard":
        out.append(f"{pre} then discard")
    else:
        out.append(f"{pre} then rate-limit {p.action.rate_bytes_per_s * 8}")   # Junos: bits per second
    if p.action.sample:
        out.append(f"{pre} then sample")
    return out


def _iosxr_class(p: FlowSpecProposal) -> list[str]:
    m = p.match
    out = [f"class-map type traffic match-all {p.name}"]
    for kw, prefix in (("destination-address", m.destination), ("source-address", m.source)):
        net = ipaddress.ip_network(prefix)
        if m.afi == "ipv4":
            out.append(f" match {kw} ipv4 {net.network_address} {net.netmask}")
        else:
            out.append(f" match {kw} ipv6 {net}")
    if m.protocols:
        out.append(" match protocol " + " ".join(_proto_word(x) for x in m.protocols))
    if m.destination_ports:
        out.append(" match destination-port " + " ".join(r.dash() for r in m.destination_ports))
    if m.packet_lengths:
        out.append(" match packet length " + " ".join(r.dash() for r in m.packet_lengths))
    out.append(" end-class-map")
    return out


def _iosxr_policy_class(p: FlowSpecProposal) -> list[str]:
    out = [f" class type traffic {p.name}"]
    if p.action.kind == "discard":
        out.append("  drop")
    else:
        out.append(f"  police rate {max(1, p.action.rate_bytes_per_s * 8 // 1000)} kbps")
    return out


def _exabgp(p: FlowSpecProposal) -> list[str]:
    m = p.match
    out = [f"    route {p.name} {{", "        match {", f"            source {m.source};",
           f"            destination {m.destination};"]
    if m.protocols:
        out.append(f"            protocol [ {' '.join(_proto_word(x) for x in m.protocols)} ];")
    if m.destination_ports:
        out.append(f"            destination-port [ {' '.join(r.numeric_op() for r in m.destination_ports)} ];")
    if m.packet_lengths:
        out.append(f"            packet-length [ {' '.join(r.numeric_op() for r in m.packet_lengths)} ];")
    out += ["        }", "        then {"]
    if p.action.kind == "discard":
        out.append("            discard;")
    else:
        out.append(f"            rate-limit {p.action.rate_bytes_per_s};")   # traffic-rate in bytes per second
    out += ["        }", "    }"]
    return out


def _header(proposals: list[FlowSpecProposal], comment: str) -> list[str]:
    lines = [f"{comment} {PROPOSAL_NOTICE}"]
    for p in proposals:
        exp = p.suggested_expiry.isoformat()
        lines.append(f"{comment} {p.name}: {p.label} ({p.verdict}), {p.lines_involved} line(s); "
                     f"suggested expiry {exp}; proposal {p.proposal_id}")
        lines += [f"{comment}   caveat: {c}" for c in p.caveats]
    return lines


def render(proposals: Iterable[FlowSpecProposal], syntax: Syntax) -> str:
    """Router-syntax text for ``proposals`` (each block labelled as a proposal)."""
    props = list(proposals)
    if syntax not in SYNTAXES:
        raise ValueError(f"unknown syntax {syntax!r}; expected one of {SYNTAXES}")
    if not props:
        return ""
    if syntax == "junos":
        body = [line for p in props for line in _junos(p)]
        return "\n".join(_header(props, "#") + body) + "\n"
    if syntax == "iosxr":
        body = [line for p in props for line in _iosxr_class(p)]
        body.append("policy-map type pbr AEGIS-PROPOSALS")
        body += [line for p in props for line in _iosxr_policy_class(p)]
        body += [" class type traffic class-default", " end-policy-map"]
        body += ["flowspec"]
        for afi in sorted({p.match.afi for p in props}):
            body += [f" address-family {afi}", "  service-policy type pbr AEGIS-PROPOSALS"]
        note = ["! traffic-action sample is not rendered for IOS XR: enable flow sampling separately if wanted"]
        return "\n".join(_header(props, "!") + note + body) + "\n"
    note = ["# traffic-action sample is not rendered for ExaBGP: enable flow sampling separately if wanted"]
    body = ["flow {"] + [line for p in props for line in _exabgp(p)] + ["}"]
    return "\n".join(_header(props, "#") + note + body) + "\n"


def flowspec_export(plan: FlowSpecPlan, syntax: Syntax) -> ExportPayload:
    """The rendered proposals as an :class:`ExportPayload` (``proposal=True``)."""
    return ExportPayload.build(f"flowspec.{syntax}", plan.tenant_id, "text/plain; charset=utf-8",
                               render(plan.proposals, syntax), records=len(plan.proposals),
                               generated_at=plan.generated_at, proposal=True)


__all__ = [
    "ComponentType", "FlowSpecAction", "FlowSpecConfig", "FlowSpecMatch", "FlowSpecPlan", "FlowSpecProposal",
    "PROTOCOL_NUMBERS", "Range", "SYNTAXES", "SkippedProposal", "flowspec_export", "propose_flowspec", "render",
]
