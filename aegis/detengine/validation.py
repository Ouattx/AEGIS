"""Static validation of detection rules (run on every draft, whoever wrote it).

A rule that fails any *error* check is refused before it is stored. The checks:

* **behavioral evidence required** - a device-class selector is a baseline, never a
  detection: a rule must contain at least one behavioral element (a condition on a
  behavioral feature, a destination pattern or a periodicity constraint)
  (``device_class_only``, ``no_behavioral_element``). Conditions on coverage alone
  are context, not behavior;
* **meaningful conditions** - no tautology over the feature's domain (``tcp_frac >= 0``
  matches everything), no unsatisfiable condition, no contradictory pair on one
  feature;
* **no shared-hosting IP targets** - an IP (or CIDR) destination must be known to the
  operator topology as dedicated hosting. Shared CDN edges serve many legitimate
  co-tenants (``shared_hosting_ip``); an address the topology does not know is
  refused too (``ip_hosting_unknown``, fail closed). Reserved addresses are refused;
* **no overly broad destinations** - domain suffixes need at least two labels and
  may not be a public suffix; CIDR blocks are bounded (/24 IPv4, /48 IPv6);
* **allowlist** - a destination that is (or covers) an allowlisted benign value is
  refused;
* **periodicity needs rarity** - a timer alone is not malicious (NTP, push keepalives,
  TV telemetry); periodicity as the only behavioral element must bound destination
  prevalence;
* **bounded complexity** - limits on conditions, destinations and device classes.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

from aegis.detengine.language import Condition, RuleSpec
from aegis.sentinel.features import normalize_name

#: features that describe sensor coverage, not device behavior
CONTEXT_FEATURES = frozenset({"coverage_h"})

_FRACTIONS = ("out_ratio", "max_dst_share", "tcp_frac", "udp_frac", "small_flow_frac", "zero_reply_frac",
              "long_flow_frac", "active_bin_frac", "out_heavy_bin_frac", "nxdomain_rate", "beacon_duty",
              "beacon_dst_prevalence", "rare_dst_frac", "rare_qname_frac", "periodic_qname_prevalence",
              "beacon_robust_cv")

#: closed domain of each bounded feature (anything not listed is only known to be finite)
FEATURE_DOMAINS: dict[str, tuple[float | None, float | None]] = {
    **{f: (0.0, 1.0) for f in _FRACTIONS},
    "beacon_robust_cv": (0.0, None),
    "burstiness": (-1.0, 1.0),
    "coverage_h": (0.0, 24.0),
    "baseline_dev_flows": (-50.0, 50.0),
    "baseline_dev_bytes_out": (-50.0, 50.0),
    **{f: (0.0, None) for f in ("flow_rate_h", "dns_rate_h", "bytes_out_rate_log", "bytes_in_rate_log",
                                "unique_dst_ip", "unique_dst_port", "dst_entropy", "peak_out_pps_log",
                                "nx_unique", "nx_name_entropy", "qname_unique", "beacon_events",
                                "beacon_bytes_log", "periodic_qnames", "recent_flows_log",
                                "recent_bytes_out_log", "recent_unique_dst", "ioc_contacts")},
}

#: suffixes too broad to target (public suffixes and reserved TLDs); not exhaustive, the
#: two-label minimum catches every bare TLD
BROAD_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "co.nz", "com.br",
    "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.sg", "com.hk", "co.kr", "com.ar", "blogspot.com",
    "github.io", "herokuapp.com", "cloudfront.net", "amazonaws.com", "azurewebsites.net", "appspot.com",
    "googleusercontent.com", "akamaiedge.net", "fastly.net", "cdn.cloudflare.net", "workers.dev", "pages.dev",
    "ngrok.io", "duckdns.org", "no-ip.org", "dyndns.org",
})


@runtime_checkable
class HostingContext(Protocol):
    """Operator hosting knowledge (:class:`aegis.api.topology.OperatorTopology` and the lab topology fit)."""

    def is_shared(self, ip: str) -> bool | None: ...

    def covers(self, ip: str) -> bool: ...


@dataclass(frozen=True)
class ValidationLimits:
    max_conditions: int = 12           # conditions + any_of
    max_destinations: int = 64
    max_device_classes: int = 16
    min_ipv4_prefix: int = 24
    min_ipv6_prefix: int = 48
    max_period_ratio: float = 50.0     # max_period_s / min_period_s
    min_period_s: float = 10.0


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "errors": list(self.errors), "warnings": list(self.warnings)}


class RuleValidationError(ValueError):
    """A rule failed static validation. ``errors`` lists the machine-readable reasons."""

    def __init__(self, errors: Iterable[str]):
        self.errors = list(errors)
        super().__init__("rule failed validation: " + ", ".join(self.errors))


# ----------------------------------------------------------------------------- checks


def _interval(c: Condition) -> list[tuple[float, float, bool, bool]]:
    """Set of values satisfying ``c`` as closed/open intervals (lo, hi, lo_closed, hi_closed)."""
    inf = float("inf")
    v = c.value if c.value is not None else 0.0
    if c.op == "gt":
        return [(v, inf, False, False)]
    if c.op == "ge":
        return [(v, inf, True, False)]
    if c.op == "lt":
        return [(-inf, v, False, False)]
    if c.op == "le":
        return [(-inf, v, False, True)]
    if c.op == "eq":
        return [(v, v, True, True)]
    if c.op == "between":
        return [(float(c.low), float(c.high), True, True)]  # type: ignore[arg-type]
    if c.op == "ne":
        return [(-inf, v, False, False), (v, inf, False, False)]
    return [(-inf, float(c.low), False, False), (float(c.high), inf, False, False)]  # type: ignore[arg-type]


def _intersect(a: tuple[float, float, bool, bool], b: tuple[float, float, bool, bool]
               ) -> tuple[float, float, bool, bool] | None:
    lo, lo_c = (a[0], a[2]) if a[0] > b[0] else (b[0], b[2]) if b[0] > a[0] else (a[0], a[2] and b[2])
    hi, hi_c = (a[1], a[3]) if a[1] < b[1] else (b[1], b[3]) if b[1] < a[1] else (a[1], a[3] and b[3])
    if lo > hi or (lo == hi and not (lo_c and hi_c)):
        return None
    return lo, hi, lo_c, hi_c


def _domain_interval(feature: str) -> tuple[float, float, bool, bool]:
    lo, hi = FEATURE_DOMAINS.get(feature, (None, None))
    inf = float("inf")
    return (lo if lo is not None else -inf, hi if hi is not None else inf, lo is not None, hi is not None)


def _satisfiable(intervals: list[tuple[float, float, bool, bool]], feature: str) -> bool:
    dom = _domain_interval(feature)
    return any(_intersect(iv, dom) is not None for iv in intervals)


def _tautological(c: Condition) -> bool:
    """True when every value in the feature's domain satisfies ``c``."""
    lo, hi = FEATURE_DOMAINS.get(c.feature, (None, None))
    if c.op in ("ge", "gt") and lo is not None and c.value is not None:
        return c.value < lo or (c.op == "ge" and c.value == lo)
    if c.op in ("le", "lt") and hi is not None and c.value is not None:
        return c.value > hi or (c.op == "le" and c.value == hi)
    if c.op == "between" and lo is not None and hi is not None:
        return c.low is not None and c.high is not None and c.low <= lo and c.high >= hi
    return False


def _check_conditions(spec: RuleSpec, errors: list[str]) -> None:
    for c in spec.conditions + spec.any_of:
        if _tautological(c):
            errors.append(f"tautological_condition:{c.feature}")
        elif not _satisfiable(_interval(c), c.feature):
            errors.append(f"unsatisfiable_condition:{c.feature}")
    by_feature: dict[str, list[Condition]] = {}
    for c in spec.conditions:
        by_feature.setdefault(c.feature, []).append(c)
    for feature, conds in sorted(by_feature.items()):
        if len(conds) < 2:
            continue
        current = [_domain_interval(feature)]
        for c in conds:
            nxt = [r for a in current for b in _interval(c) if (r := _intersect(a, b)) is not None]
            current = nxt
        if not current:
            errors.append(f"contradictory_conditions:{feature}")


def _behavioral(spec: RuleSpec) -> bool:
    if spec.destinations is not None or spec.periodicity is not None:
        return True
    return any(c.feature not in CONTEXT_FEATURES for c in spec.conditions + spec.any_of)


def _check_ip(ip: str, hosting: HostingContext | None, errors: list[str]) -> None:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
        errors.append(f"reserved_address:{ip}")
        return
    if hosting is None:
        errors.append(f"ip_hosting_unknown:{ip}")
        return
    shared = hosting.is_shared(ip)
    if shared is True:
        errors.append(f"shared_hosting_ip:{ip}")
    elif shared is None:
        errors.append(f"ip_hosting_unknown:{ip}")


def _hosts_of(hosting: HostingContext | None) -> Mapping[str, Any]:
    hosts = getattr(hosting, "hosts", None)
    return hosts if isinstance(hosts, Mapping) else {}


def _check_cidr(cidr: str, hosting: HostingContext | None, limits: ValidationLimits, errors: list[str]) -> None:
    net = ipaddress.ip_network(cidr)
    min_prefix = limits.min_ipv4_prefix if net.version == 4 else limits.min_ipv6_prefix
    if net.prefixlen < min_prefix:
        errors.append(f"cidr_too_broad:{cidr}")
        return
    if net.is_loopback or net.is_multicast or net.is_unspecified or net.is_link_local:
        errors.append(f"reserved_address:{cidr}")
        return
    if hosting is None or not hosting.covers(str(net.network_address)):
        errors.append(f"cidr_hosting_unknown:{cidr}")
        return
    hosts = _hosts_of(hosting)
    shared = [ip for ip, h in hosts.items() if _in(ip, net) and bool(getattr(h, "shared", False))]
    if shared:
        errors.append(f"shared_hosting_cidr:{cidr}")
    if not any(_in(ip, net) for ip in hosts):
        errors.append(f"cidr_hosting_unknown:{cidr}")


def _in(ip: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == net.version and addr in net


def _covers_name(pattern_kind: str, pattern: str, name: str) -> bool:
    if pattern_kind == "domain_exact":
        return name == pattern
    return name == pattern or name.endswith("." + pattern)


def _check_destinations(spec: RuleSpec, hosting: HostingContext | None, allowlist: frozenset[str],
                        limits: ValidationLimits, errors: list[str], warnings: list[str]) -> None:
    if spec.destinations is None:
        return
    if len(spec.destinations.patterns) > limits.max_destinations:
        errors.append("too_many_destinations")
    allow_names = {normalize_name(a) for a in allowlist if not _is_ip(a)}
    allow_ips = {str(ipaddress.ip_address(a)) for a in allowlist if _is_ip(a)}
    for p in spec.destinations.patterns:
        if p.kind == "ip":
            _check_ip(p.value, hosting, errors)
            if p.value in allow_ips:
                errors.append(f"allowlisted_destination:{p.value}")
        elif p.kind == "cidr":
            _check_cidr(p.value, hosting, limits, errors)
            net = ipaddress.ip_network(p.value)
            if any(_in(ip, net) for ip in allow_ips):
                errors.append(f"allowlisted_destination:{p.value}")
        else:
            labels = p.value.split(".")
            if p.kind == "domain_suffix" and (len(labels) < 2 or p.value in BROAD_SUFFIXES):
                errors.append(f"domain_too_broad:{p.value}")
            if p.value in BROAD_SUFFIXES and p.kind == "domain_exact":
                errors.append(f"domain_too_broad:{p.value}")
            if any(_covers_name(p.kind, p.value, a) or _covers_name("domain_suffix", a, p.value)
                   for a in allow_names):
                errors.append(f"allowlisted_destination:{p.value}")
            resolve = getattr(hosting, "resolve", None)
            if callable(resolve):
                ips = resolve(p.value) or []
                if any(hosting.is_shared(ip) for ip in ips):  # type: ignore[union-attr]
                    warnings.append(f"domain_on_shared_hosting:{p.value}")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def validate_rule(spec: RuleSpec, *, hosting: HostingContext | None = None, allowlist: Iterable[str] = (),
                  limits: ValidationLimits | None = None) -> ValidationResult:
    """Run every static check; return errors (blocking) and warnings (informational)."""
    lim = limits or ValidationLimits()
    errors: list[str] = []
    warnings: list[str] = []
    has_elements = bool(spec.conditions or spec.any_of or spec.destinations or spec.periodicity)
    if not has_elements:
        errors.append("device_class_only" if spec.baseline is not None else "empty_rule")
    elif not _behavioral(spec):
        errors.append("no_behavioral_element")
    if len(spec.conditions) + len(spec.any_of) > lim.max_conditions:
        errors.append("too_many_conditions")
    if spec.baseline is not None and len(spec.baseline.device_classes) > lim.max_device_classes:
        errors.append("too_many_device_classes")
    _check_conditions(spec, errors)
    _check_destinations(spec, hosting, frozenset(allowlist), lim, errors, warnings)
    per = spec.periodicity
    if per is not None:
        if per.min_period_s < lim.min_period_s:
            errors.append("periodicity_period_too_short")
        if per.max_period_s / per.min_period_s > lim.max_period_ratio:
            errors.append("periodicity_range_too_broad")
        only_timer = (spec.destinations is None
                      and not any(c.feature not in CONTEXT_FEATURES for c in spec.conditions + spec.any_of))
        if only_timer and per.max_dst_prevalence is None:
            errors.append("periodicity_needs_rarity")
        if per.max_robust_cv > 0.5:
            warnings.append("periodicity_loose_cv")
    if spec.baseline is None:
        warnings.append("no_baseline_selector")
    return ValidationResult(tuple(dict.fromkeys(errors)), tuple(dict.fromkeys(warnings)))


def require_valid(spec: RuleSpec, **kwargs: Any) -> ValidationResult:
    """:func:`validate_rule`, raising :class:`RuleValidationError` on any error."""
    res = validate_rule(spec, **kwargs)
    if not res.ok:
        raise RuleValidationError(res.errors)
    return res


__all__ = [
    "BROAD_SUFFIXES", "CONTEXT_FEATURES", "FEATURE_DOMAINS", "HostingContext", "RuleValidationError",
    "ValidationLimits", "ValidationResult", "require_valid", "validate_rule",
]
