"""A small, safe, declarative detection-rule language.

A rule is plain data (frozen dataclasses that round-trip through JSON / YAML). It has
no expressions, no code, no regular expressions and no loops, so evaluating one is
bounded, side-effect free and cannot be abused by whoever wrote it (a human or a
language model). A rule is made of:

* ``conditions``: all must hold. Each compares one :class:`FeatureVector` value
  (see :data:`aegis.sentinel.features.FEATURE_DOCS`) with a constant;
* ``any_of`` / ``min_any``: at least ``min_any`` of these conditions must hold;
* ``destinations``: destination patterns (exact domain, domain suffix, IP, CIDR)
  matched against the window's contacts, at least ``min_matches`` of them;
* ``periodicity``: a beaconing constraint on the window's reported periodic channel
  (period range, maximum robust CV, minimum check-ins, duty cycle, rarity);
* ``baseline``: a device-class *selector*. It only narrows where the rule applies;
  it is never a condition by itself (enforced by :mod:`aegis.detengine.validation`).

Evaluation is three-valued. A rule **fires** only when every element is satisfied.
A missing feature value (``None``) or missing contacts make an element *unknown*:
if nothing else is false, the rule **abstains** instead of guessing (missing is
never treated as zero).
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Mapping

from aegis.contracts.canonical import sha256_hex
from aegis.contracts.models import FeatureVector
from aegis.sentinel.features import FEATURE_NAMES, ContactSummary, normalize_name

RULE_SCHEMA = "aegis.detection_rule/1"
DETENGINE_VERSION = "1.0.0"

Op = Literal["gt", "ge", "lt", "le", "eq", "ne", "between", "outside"]
OPS: tuple[str, ...] = ("gt", "ge", "lt", "le", "eq", "ne", "between", "outside")
DestinationKind = Literal["domain_exact", "domain_suffix", "ip", "cidr"]
DESTINATION_KINDS: tuple[str, ...] = ("domain_exact", "domain_suffix", "ip", "cidr")
Severity = Literal["low", "medium", "high"]
SEVERITIES: tuple[str, ...] = ("low", "medium", "high")
Window = Literal["5m", "15m", "24h"]
Outcome = Literal["fired", "no_match", "abstain", "not_applicable"]

RULE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,47}$")
LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{2,47}$")
DEVICE_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
_DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

#: features the periodicity constraint reads
PERIODICITY_FEATURES = ("beacon_period_log", "beacon_robust_cv", "beacon_events", "beacon_duty",
                        "beacon_dst_prevalence")

Truth = bool | None  # None = unknown (missing data)


class RuleSpecError(ValueError):
    """A rule document is malformed. ``errors`` lists every problem found."""

    def __init__(self, errors: Iterable[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors) or "invalid rule")


def _finite(x: Any) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(float(x))


def _f(x: Any) -> float:
    """``float(x)`` for a value already checked by :func:`_finite`."""
    return float(x)


# ----------------------------------------------------------------------------- contacts


@dataclass(frozen=True)
class Contacts:
    """Destinations an entity reached during one window (input to destination patterns).

    ``answers`` maps a looked-up name to the addresses the resolver returned, so a
    domain pattern can require a *verified contact* (traffic to a resolved address)
    rather than a lookup alone.
    """
    dst_ips: frozenset[str] = frozenset()
    qnames: frozenset[str] = frozenset()
    answers: Mapping[str, frozenset[str]] = field(default_factory=dict)
    source_ids: frozenset[str] = frozenset()
    authorization_ids: frozenset[str] = frozenset()

    @classmethod
    def from_summary(cls, cs: ContactSummary) -> "Contacts":
        return cls(dst_ips=frozenset(cs.dst_ips), qnames=frozenset(cs.qnames),
                   answers={q: frozenset(v) for q, v in cs.answers.items()},
                   source_ids=frozenset(cs.source_ids), authorization_ids=frozenset(cs.authorization_ids))

    @classmethod
    def coerce(cls, value: "Contacts | ContactSummary | None") -> "Contacts | None":
        if value is None or isinstance(value, Contacts):
            return value
        if isinstance(value, ContactSummary):
            return cls.from_summary(value)
        raise TypeError(f"contacts must be Contacts or ContactSummary, got {type(value).__name__}")


# ----------------------------------------------------------------------------- elements


@dataclass(frozen=True)
class Condition:
    """``values[feature] <op> value`` (or ``low``/``high`` for ``between``/``outside``)."""
    feature: str
    op: Op
    value: float | None = None
    low: float | None = None
    high: float | None = None

    def evaluate(self, values: Mapping[str, float | None]) -> Truth:
        x = values.get(self.feature)
        if x is None or not _finite(x):
            return None
        x = float(x)
        if self.op == "between":
            return bool(self.low is not None and self.high is not None and self.low <= x <= self.high)
        if self.op == "outside":
            return bool(self.low is not None and self.high is not None and (x < self.low or x > self.high))
        v = self.value
        if v is None:
            return None
        return {"gt": x > v, "ge": x >= v, "lt": x < v, "le": x <= v,
                "eq": math.isclose(x, v, rel_tol=1e-9, abs_tol=1e-12),
                "ne": not math.isclose(x, v, rel_tol=1e-9, abs_tol=1e-12)}[self.op]

    def describe(self) -> str:
        if self.op in ("between", "outside"):
            return f"{self.feature} {self.op} [{self.low:g}, {self.high:g}]"
        sym = {"gt": ">", "ge": ">=", "lt": "<", "le": "<=", "eq": "==", "ne": "!="}[self.op]
        return f"{self.feature} {sym} {self.value:g}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"feature": self.feature, "op": self.op}
        if self.op in ("between", "outside"):
            d["low"], d["high"] = self.low, self.high
        else:
            d["value"] = self.value
        return d

    @classmethod
    def from_dict(cls, d: Any, where: str, errors: list[str]) -> "Condition | None":
        if not isinstance(d, dict):
            errors.append(f"{where}: condition must be an object")
            return None
        _unknown_keys(d, {"feature", "op", "value", "low", "high"}, where, errors)
        feature, op = d.get("feature"), d.get("op")
        ok = True
        if not isinstance(feature, str) or feature not in FEATURE_NAMES:
            errors.append(f"{where}: unknown feature {feature!r}")
            ok = False
        if op not in OPS:
            errors.append(f"{where}: op must be one of {', '.join(OPS)}")
            return None
        if op in ("between", "outside"):
            low, high = d.get("low"), d.get("high")
            if not (_finite(low) and _finite(high)):
                errors.append(f"{where}: {op} needs finite numeric low and high")
                return None
            if _f(low) >= _f(high):
                errors.append(f"{where}: low must be below high")
                return None
            if "value" in d:
                errors.append(f"{where}: {op} takes low/high, not value")
                return None
            return cls(str(feature), op, low=_f(low), high=_f(high)) if ok else None
        value = d.get("value")
        if not _finite(value):
            errors.append(f"{where}: {op} needs a finite numeric value")
            return None
        if "low" in d or "high" in d:
            errors.append(f"{where}: {op} takes value, not low/high")
            return None
        return cls(str(feature), op, value=_f(value)) if ok else None


@dataclass(frozen=True)
class DestinationPattern:
    """One destination: an exact name, a name suffix, an address, or a CIDR block."""
    kind: DestinationKind
    value: str
    verified_contact: bool = False   # domains: require traffic to an address the name resolved to

    def matches(self, c: Contacts) -> bool:
        if self.kind == "ip":
            return self.value in c.dst_ips
        if self.kind == "cidr":
            net = ipaddress.ip_network(self.value, strict=False)
            for ip in c.dst_ips:
                try:
                    if ipaddress.ip_address(ip) in net:
                        return True
                except ValueError:
                    continue
            return False
        names = [q for q in c.qnames if self._name_match(q)]
        if not names:
            return False
        if not self.verified_contact:
            return True
        return any(ip in c.dst_ips for q in names for ip in c.answers.get(q, ()))

    def _name_match(self, qname: str) -> bool:
        q = normalize_name(qname)
        if self.kind == "domain_exact":
            return q == self.value
        return q == self.value or q.endswith("." + self.value)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind, "value": self.value}
        if self.kind in ("domain_exact", "domain_suffix"):
            d["verified_contact"] = self.verified_contact
        return d

    @classmethod
    def from_dict(cls, d: Any, where: str, errors: list[str]) -> "DestinationPattern | None":
        if not isinstance(d, dict):
            errors.append(f"{where}: destination must be an object")
            return None
        _unknown_keys(d, {"kind", "value", "verified_contact"}, where, errors)
        kind, value = d.get("kind"), d.get("value")
        if kind not in DESTINATION_KINDS:
            errors.append(f"{where}: kind must be one of {', '.join(DESTINATION_KINDS)}")
            return None
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{where}: value must be a non-empty string")
            return None
        verified = d.get("verified_contact", False)
        if not isinstance(verified, bool):
            errors.append(f"{where}: verified_contact must be a boolean")
            return None
        value = value.strip()
        if kind in ("domain_exact", "domain_suffix"):
            name = normalize_name(value)
            if not _DOMAIN_RE.match(name):
                errors.append(f"{where}: {value!r} is not a valid domain name")
                return None
            return cls(kind, name, verified)
        if verified:
            errors.append(f"{where}: verified_contact applies to domain patterns only")
            return None
        try:
            if kind == "ip":
                return cls(kind, str(ipaddress.ip_address(value)))
            return cls(kind, str(ipaddress.ip_network(value, strict=True)))
        except ValueError:
            errors.append(f"{where}: {value!r} is not a valid {'address' if kind == 'ip' else 'CIDR block'}")
            return None


@dataclass(frozen=True)
class DestinationClause:
    patterns: tuple[DestinationPattern, ...]
    min_matches: int = 1

    def evaluate(self, contacts: Contacts | None) -> tuple[Truth, tuple[str, ...]]:
        if contacts is None:
            return None, ()
        hit = tuple(f"{p.kind}:{p.value}" for p in self.patterns if p.matches(contacts))
        return len(hit) >= self.min_matches, hit

    def to_dict(self) -> dict[str, Any]:
        return {"patterns": [p.to_dict() for p in self.patterns], "min_matches": self.min_matches}

    @classmethod
    def from_dict(cls, d: Any, errors: list[str]) -> "DestinationClause | None":
        if not isinstance(d, dict):
            errors.append("destinations: must be an object")
            return None
        _unknown_keys(d, {"patterns", "min_matches"}, "destinations", errors)
        raw = d.get("patterns")
        if not isinstance(raw, list) or not raw:
            errors.append("destinations.patterns: must be a non-empty list")
            return None
        pats = [DestinationPattern.from_dict(p, f"destinations.patterns[{i}]", errors) for i, p in enumerate(raw)]
        mm = d.get("min_matches", 1)
        if not isinstance(mm, int) or isinstance(mm, bool) or mm < 1:
            errors.append("destinations.min_matches: must be a positive integer")
            return None
        if any(p is None for p in pats):
            return None
        keys = [(p.kind, p.value) for p in pats if p is not None]
        if len(set(keys)) != len(keys):
            errors.append("destinations.patterns: duplicate pattern")
            return None
        if mm > len(pats):
            errors.append("destinations.min_matches: exceeds the number of patterns")
            return None
        return cls(tuple(p for p in pats if p is not None), mm)


@dataclass(frozen=True)
class PeriodicityConstraint:
    """Beaconing on the window's reported periodic channel (sentinel ``beacon_*`` features)."""
    min_period_s: float
    max_period_s: float
    max_robust_cv: float = 0.35
    min_events: int = 6
    min_duty: float = 0.5
    max_dst_prevalence: float | None = 0.05

    def evaluate(self, values: Mapping[str, float | None]) -> tuple[Truth, dict[str, Truth]]:
        parts: dict[str, Truth] = {}

        def get(name: str) -> float | None:
            v = values.get(name)
            return float(v) if v is not None and _finite(v) else None

        period_log = get("beacon_period_log")
        parts["period"] = (None if period_log is None
                           else self.min_period_s <= 10.0 ** period_log <= self.max_period_s)
        cv = get("beacon_robust_cv")
        parts["robust_cv"] = None if cv is None else cv <= self.max_robust_cv
        ev = get("beacon_events")
        parts["events"] = None if ev is None else ev >= self.min_events
        duty = get("beacon_duty")
        parts["duty"] = None if duty is None else duty >= self.min_duty
        if self.max_dst_prevalence is not None:
            prev = get("beacon_dst_prevalence")
            parts["dst_prevalence"] = None if prev is None else prev <= self.max_dst_prevalence
        return _all(parts.values()), parts

    def to_dict(self) -> dict[str, Any]:
        return {"min_period_s": self.min_period_s, "max_period_s": self.max_period_s,
                "max_robust_cv": self.max_robust_cv, "min_events": self.min_events, "min_duty": self.min_duty,
                "max_dst_prevalence": self.max_dst_prevalence}

    @classmethod
    def from_dict(cls, d: Any, errors: list[str]) -> "PeriodicityConstraint | None":
        if not isinstance(d, dict):
            errors.append("periodicity: must be an object")
            return None
        allowed = {"min_period_s", "max_period_s", "max_robust_cv", "min_events", "min_duty", "max_dst_prevalence"}
        _unknown_keys(d, allowed, "periodicity", errors)
        lo, hi = d.get("min_period_s"), d.get("max_period_s")
        n0 = len(errors)
        if not (_finite(lo) and _finite(hi)) or _f(lo) <= 0 or _f(hi) <= _f(lo):
            errors.append("periodicity: need 0 < min_period_s < max_period_s")
        cv = d.get("max_robust_cv", 0.35)
        if not _finite(cv) or not 0.0 < _f(cv) <= 1.0:
            errors.append("periodicity.max_robust_cv: must be in (0, 1]")
        ev = d.get("min_events", 6)
        if not isinstance(ev, int) or isinstance(ev, bool) or ev < 3:
            errors.append("periodicity.min_events: must be an integer >= 3")
        duty = d.get("min_duty", 0.5)
        if not _finite(duty) or not 0.0 <= _f(duty) <= 1.0:
            errors.append("periodicity.min_duty: must be in [0, 1]")
        prev = d.get("max_dst_prevalence", 0.05)
        if prev is not None and (not _finite(prev) or not 0.0 < _f(prev) <= 1.0):
            errors.append("periodicity.max_dst_prevalence: must be in (0, 1] or null")
        if len(errors) > n0:
            return None
        return cls(_f(lo), _f(hi), _f(cv), int(ev), _f(duty), None if prev is None else _f(prev))


@dataclass(frozen=True)
class BaselineSelector:
    """Device classes the rule applies to. A selector, never a sole condition."""
    device_classes: tuple[str, ...]

    def applies(self, device_class: str) -> bool:
        return device_class in self.device_classes

    def to_dict(self) -> dict[str, Any]:
        return {"device_classes": list(self.device_classes)}

    @classmethod
    def from_dict(cls, d: Any, errors: list[str]) -> "BaselineSelector | None":
        if not isinstance(d, dict):
            errors.append("baseline: must be an object")
            return None
        _unknown_keys(d, {"device_classes"}, "baseline", errors)
        dc = d.get("device_classes")
        if not isinstance(dc, list) or not dc or not all(isinstance(x, str) and DEVICE_CLASS_RE.match(x) for x in dc):
            errors.append("baseline.device_classes: must be a non-empty list of device class names")
            return None
        if len(set(dc)) != len(dc):
            errors.append("baseline.device_classes: duplicate device class")
            return None
        return cls(tuple(sorted(dc)))


# ----------------------------------------------------------------------------- rule


@dataclass(frozen=True)
class RuleSpec:
    """The logic and documentation of one detection rule (versioned by the registry)."""
    rule_id: str
    title: str
    label: str
    description: str = ""
    window: Window = "24h"
    conditions: tuple[Condition, ...] = ()
    any_of: tuple[Condition, ...] = ()
    min_any: int = 1
    destinations: DestinationClause | None = None
    periodicity: PeriodicityConstraint | None = None
    baseline: BaselineSelector | None = None
    severity: Severity = "medium"
    rationale: str = ""

    # -------------------------------------------------------------- serialization
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RULE_SCHEMA, "rule_id": self.rule_id, "title": self.title, "label": self.label,
            "description": self.description, "window": self.window,
            "conditions": [c.to_dict() for c in self.conditions],
            "any_of": [c.to_dict() for c in self.any_of], "min_any": self.min_any,
            "destinations": self.destinations.to_dict() if self.destinations else None,
            "periodicity": self.periodicity.to_dict() if self.periodicity else None,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "severity": self.severity, "rationale": self.rationale,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @property
    def sha256(self) -> str:
        return spec_sha256(self)

    @classmethod
    def from_dict(cls, d: Any) -> "RuleSpec":
        """Strict parse: unknown keys, wrong types and unknown features are all errors."""
        errors: list[str] = []
        if not isinstance(d, dict):
            raise RuleSpecError(["rule must be an object"])
        allowed = {"schema", "rule_id", "title", "label", "description", "window", "conditions", "any_of",
                   "min_any", "destinations", "periodicity", "baseline", "severity", "rationale"}
        _unknown_keys(d, allowed, "rule", errors)
        schema = d.get("schema", RULE_SCHEMA)
        if schema != RULE_SCHEMA:
            errors.append(f"rule.schema: unsupported schema {schema!r}")
        rule_id = d.get("rule_id")
        if not isinstance(rule_id, str) or not RULE_ID_RE.match(rule_id):
            errors.append("rule.rule_id: 3-48 chars of a-z, 0-9, '_', '.', '-' starting alphanumeric")
        title = d.get("title")
        if not isinstance(title, str) or not title.strip() or len(title) > 160:
            errors.append("rule.title: non-empty string of at most 160 characters")
        label = d.get("label")
        if not isinstance(label, str) or not LABEL_RE.match(label):
            errors.append("rule.label: 3-48 chars of a-z, 0-9, '_' starting with a letter")
        description = d.get("description", "")
        rationale = d.get("rationale", "")
        for name, txt in (("description", description), ("rationale", rationale)):
            if not isinstance(txt, str) or len(txt) > 4000:
                errors.append(f"rule.{name}: string of at most 4000 characters")
        window = d.get("window", "24h")
        if window not in ("5m", "15m", "24h"):
            errors.append("rule.window: one of 5m, 15m, 24h")
        severity = d.get("severity", "medium")
        if severity not in SEVERITIES:
            errors.append(f"rule.severity: one of {', '.join(SEVERITIES)}")
        conds = _conditions(d.get("conditions", []), "conditions", errors)
        any_of = _conditions(d.get("any_of", []), "any_of", errors)
        min_any = d.get("min_any", 1)
        if not isinstance(min_any, int) or isinstance(min_any, bool) or min_any < 1:
            errors.append("rule.min_any: positive integer")
        elif any_of and min_any > len(any_of):
            errors.append("rule.min_any: exceeds the number of any_of conditions")
        dest = DestinationClause.from_dict(d["destinations"], errors) if d.get("destinations") is not None else None
        per = PeriodicityConstraint.from_dict(d["periodicity"], errors) if d.get("periodicity") is not None else None
        base = BaselineSelector.from_dict(d["baseline"], errors) if d.get("baseline") is not None else None
        if errors:
            raise RuleSpecError(errors)
        return cls(rule_id=str(rule_id), title=str(title).strip(), label=str(label), description=description,
                   window=window,
                   conditions=tuple(conds), any_of=tuple(any_of), min_any=min_any, destinations=dest,
                   periodicity=per, baseline=base, severity=severity, rationale=rationale)

    def with_rule_id(self, rule_id: str) -> "RuleSpec":
        return RuleSpec.from_dict({**self.to_dict(), "rule_id": rule_id})

    # -------------------------------------------------------------- introspection
    def features_used(self) -> set[str]:
        out = {c.feature for c in self.conditions} | {c.feature for c in self.any_of}
        if self.periodicity is not None:
            out.update(PERIODICITY_FEATURES if self.periodicity.max_dst_prevalence is not None
                       else PERIODICITY_FEATURES[:-1])
        return out

    def element_count(self) -> int:
        return (len(self.conditions) + len(self.any_of) + (len(self.destinations.patterns) if self.destinations else 0)
                + (1 if self.periodicity else 0))


def _unknown_keys(d: dict[str, Any], allowed: set[str], where: str, errors: list[str]) -> None:
    extra = sorted(str(k) for k in d if k not in allowed)
    if extra:
        errors.append(f"{where}: unknown field(s) {', '.join(extra)}")


def _conditions(raw: Any, where: str, errors: list[str]) -> list[Condition]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append(f"rule.{where}: must be a list")
        return []
    out = [Condition.from_dict(c, f"{where}[{i}]", errors) for i, c in enumerate(raw)]
    return [c for c in out if c is not None]


def spec_sha256(spec: RuleSpec) -> str:
    """Content hash of a rule (RFC 8785 canonical JSON)."""
    return sha256_hex(spec.to_dict())


def parse_rule(source: str | bytes | Mapping[str, Any]) -> RuleSpec:
    """Parse a rule from a dict, JSON text, or YAML text (YAML needs PyYAML; safe loader only)."""
    if isinstance(source, Mapping):
        return RuleSpec.from_dict(dict(source))
    text = source.decode("utf-8") if isinstance(source, bytes) else source
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml  # optional; never the unsafe loader
        except ImportError as exc:
            raise RuleSpecError(["rule text is not JSON and PyYAML is not installed"]) from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise RuleSpecError([f"rule text is neither JSON nor YAML: {exc}"]) from exc
    return RuleSpec.from_dict(data)


# ----------------------------------------------------------------------------- evaluation


def _all(truths: Iterable[Truth]) -> Truth:
    seen_unknown = False
    for t in truths:
        if t is False:
            return False
        if t is None:
            seen_unknown = True
    return None if seen_unknown else True


@dataclass(frozen=True)
class RuleEvaluation:
    """Outcome of one rule on one window, with the reasons."""
    outcome: Outcome
    satisfied: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()
    matched_destinations: tuple[str, ...] = ()
    observed: Mapping[str, float | None] = field(default_factory=dict)

    @property
    def fired(self) -> bool:
        return self.outcome == "fired"


def evaluate_rule(spec: RuleSpec, fv: FeatureVector,
                  contacts: "Contacts | ContactSummary | None" = None) -> RuleEvaluation:
    """Evaluate ``spec`` on one window. Pure function; never raises on data content."""
    if fv.window != spec.window:
        return RuleEvaluation("not_applicable", failed=(f"window {fv.window} != {spec.window}",))
    if spec.baseline is not None and not spec.baseline.applies(fv.device_class):
        return RuleEvaluation("not_applicable", failed=(f"device_class {fv.device_class} not selected",))
    c = Contacts.coerce(contacts)
    satisfied: list[str] = []
    failed: list[str] = []
    unknown: list[str] = []
    values = fv.values

    def record(name: str, t: Truth) -> None:
        (satisfied if t is True else failed if t is False else unknown).append(name)

    for cond in spec.conditions:
        record(cond.describe(), cond.evaluate(values))
    if spec.any_of:
        truths = [cond.evaluate(values) for cond in spec.any_of]
        n_true = sum(1 for t in truths if t is True)
        n_unknown = sum(1 for t in truths if t is None)
        name = f"at least {spec.min_any} of [{'; '.join(x.describe() for x in spec.any_of)}]"
        if n_true >= spec.min_any:
            record(name, True)
        elif n_true + n_unknown >= spec.min_any:
            record(name, None)
        else:
            record(name, False)
    matched: tuple[str, ...] = ()
    if spec.destinations is not None:
        t, matched = spec.destinations.evaluate(c)
        record(f"destinations (>= {spec.destinations.min_matches} of {len(spec.destinations.patterns)})", t)
    if spec.periodicity is not None:
        t, parts = spec.periodicity.evaluate(values)
        for part, pt in parts.items():
            record(f"periodicity.{part}", pt)
    observed = {f: values.get(f) for f in sorted(spec.features_used())}
    if failed:
        outcome: Outcome = "no_match"
    elif unknown:
        outcome = "abstain"
    else:
        outcome = "fired"
    return RuleEvaluation(outcome, tuple(satisfied), tuple(failed), tuple(unknown), matched, observed)


__all__ = [
    "BaselineSelector", "Condition", "Contacts", "DESTINATION_KINDS", "DETENGINE_VERSION", "DestinationClause",
    "DestinationPattern", "OPS", "PERIODICITY_FEATURES", "PeriodicityConstraint", "RULE_SCHEMA", "RuleEvaluation",
    "RuleSpec", "RuleSpecError", "SEVERITIES", "evaluate_rule", "parse_rule", "spec_sha256",
]
