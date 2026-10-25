"""Opt-in cross-operator sharing: keyed-hash indicators and differentially private aggregates.

Privacy model
-------------
* **Opt-in.** Nothing is shared unless the tenant's :class:`SharingPolicy` has
  ``enabled=True`` (default ``False``). Indicator sharing and aggregate release are
  separately switchable.
* **Indicators as keyed hashes.** A shared indicator is ``HMAC-SHA256(K_epoch, type|value)``
  truncated to 128 bits, where ``K_epoch`` is derived (HKDF) from the consortium secret
  and a rotation epoch. A party without the consortium key learns nothing about the
  values. A key holder can only test values it already has (private-set-intersection
  style matching: it hashes its own values and looks them up). *Limitation:* a key holder
  can also test guesses, and the IPv4 space is small enough to enumerate, so the
  consortium key protects against outsiders, not against a dishonest member. For
  member-versus-member privacy use the two-party DH-PSI in :mod:`aegis.intel.psi`.
* **What is never shared:** line pseudonyms, victim reports, subscriber addresses (any IP
  or CIDR inside the tenant's ``own_networks``; when ``own_networks`` is not configured,
  operator-originated IP indicators are withheld entirely: fail closed), indicators whose
  license forbids redistribution, benign/allowlist entries, and unverified local
  detections unless the policy explicitly allows them.
* **Aggregates only with differential privacy.** Per-campaign infected-line counts are
  released through :func:`release_campaign_counts`: each line's contribution is bounded,
  noise is exact discrete Laplace or Gaussian, the ``(ε, δ)`` cost is charged to the
  tenant budget *before* release (refused when exhausted), and a count is published only
  when its true value is at least ``k_min`` **and** its noisy value is at least
  ``k_min`` + a tail margin (k-anonymity gate in addition to DP). The gates change only
  outcomes of probability at most ``threshold_beta``, so a release is
  ``(ε, δ + threshold_beta)``-DP and the accountant is charged that full δ.

Every package and release is signed (Ed25519, RFC 8785 canonical bytes) by the
publishing member, so a receiver can verify origin and integrity with a
:class:`~aegis.provenance.signing.KeyRing`.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, Field

from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import ObservationEvent
from aegis.intel.dp import (
    Mechanism,
    PrivacyAccountant,
    RandomSource,
    SecureRandom,
    gaussian_noise,
    laplace_noise,
    noise_tail_bound,
)
from aegis.intel.formats import classify_host, normalize_cidr
from aegis.intel.models import IntelIndicator, utc
from aegis.intel.store import OPERATOR_GROUP, IntelStore
from aegis.provenance.signing import KeyRing
from aegis.resonance.models import Campaign

SHARE_SCHEMA = "aegis.intel_share/1"
RELEASE_SCHEMA = "aegis.intel_dp_release/1"
TOKEN_PREFIX = "t1:"
MIN_CONSORTIUM_SECRET = 32
_PSEUDONYM_RE = re.compile(r"p_[0-9a-f]{32}")
#: Public feed groups that may be named in shared entries (everything else becomes "member").
PUBLIC_GROUPS = frozenset({"grp:abuse.ch", "grp:spamhaus"})


class SharingDisabled(PermissionError):
    """The tenant has not opted in to this kind of sharing."""


class SharingError(ValueError):
    """A package or release failed verification or validation."""


class SignerLike(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> str: ...


# ---------------------------------------------------------------------------- keys and tokens

class ConsortiumKey:
    """A consortium secret plus rotation epoch; derives the per-epoch HMAC key.

    The secret is held by each opted-in member (distributed out of band, e.g. from the
    consortium's KMS). ``repr`` never shows key material.
    """

    def __init__(self, key_id: str, secret: bytes, epoch: str):
        if not key_id or not epoch:
            raise ValueError("key_id and epoch are required")
        if len(secret) < MIN_CONSORTIUM_SECRET:
            raise ValueError(f"consortium secret must be at least {MIN_CONSORTIUM_SECRET} bytes")
        self.key_id = key_id
        self.epoch = epoch
        self._k = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"aegis-intel-consortium-v1",
                       info=f"{key_id}|{epoch}".encode()).derive(bytes(secret))

    def __repr__(self) -> str:
        return f"ConsortiumKey(key_id={self.key_id!r}, epoch={self.epoch!r})"

    def token(self, typ: str, value: str) -> str:
        """Keyed hash of a *normalized* indicator value."""
        mac = hmac.new(self._k, f"{typ}|{value}".encode(), hashlib.sha256).hexdigest()
        return TOKEN_PREFIX + mac[:32]

    def token_for_raw(self, raw: str) -> tuple[str, str]:
        """Normalize ``raw`` (domain, IP or CIDR) and return ``(type, token)``."""
        typ, value = normalize_cidr(raw) if "/" in raw else classify_host(raw)
        return typ, self.token(typ, value)

    def observation_tokens(self, *, ip: str | None = None, qname: str | None = None,
                           cidr_prefixes: Sequence[int] = ()) -> list[str]:
        """Tokens a receiver computes for one observed destination (exact IP, containing
        prefixes of the given lengths, the domain and each parent domain)."""
        out: list[str] = []
        if ip is not None:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None:
                out.append(self.token("ip", str(addr)))
                for plen in cidr_prefixes:
                    if plen < addr.max_prefixlen:
                        out.append(self.token("cidr", str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))))
        if qname is not None:
            parts = qname.strip().lower().rstrip(".").split(".")
            for i in range(len(parts) - 1):
                out.append(self.token("domain", ".".join(parts[i:])))
        return out


# ---------------------------------------------------------------------------- policy

@dataclass(frozen=True)
class SharingPolicy:
    """Per-tenant sharing consent and limits. Defaults share nothing."""
    tenant_id: str
    enabled: bool = False
    share_indicators: bool = False
    share_aggregates: bool = False
    member_id: str = ""                                   # consortium-facing pseudonymous id of this operator
    own_networks: tuple[str, ...] = ()                    # subscriber address space: never shared
    share_unverified_detections: bool = False
    min_confidence: float = 0.5
    allowed_licenses: tuple[str, ...] = ("CC0-1.0", "operator-shared")
    mechanism: Mechanism = "laplace"
    epsilon_per_release: float = 0.5
    delta_per_release: float = 1e-6                       # Gaussian only; Laplace charges delta = 0
    k_min: int = 10
    threshold_beta: float = 1e-6                          # P(noise pushes a sub-k count over the noisy gate)
    max_contributions_per_line: int = 1

    def __post_init__(self) -> None:
        if self.k_min < 2:
            raise ValueError("k_min must be >= 2")
        if self.epsilon_per_release <= 0:
            raise ValueError("epsilon_per_release must be > 0")
        if self.mechanism == "gaussian" and not 0 < self.delta_per_release < 1:
            raise ValueError("gaussian releases need 0 < delta_per_release < 1")
        if self.max_contributions_per_line < 1:
            raise ValueError("max_contributions_per_line must be >= 1")
        for n in self.own_networks:
            ipaddress.ip_network(n, strict=False)

    def require(self, what: Literal["indicators", "aggregates"]) -> None:
        if not self.enabled:
            raise SharingDisabled(f"tenant {self.tenant_id!r} has not opted in to consortium sharing")
        if what == "indicators" and not self.share_indicators:
            raise SharingDisabled(f"tenant {self.tenant_id!r} does not share indicators")
        if what == "aggregates" and not self.share_aggregates:
            raise SharingDisabled(f"tenant {self.tenant_id!r} does not share aggregates")
        if not self.member_id or _PSEUDONYM_RE.search(self.member_id):
            raise SharingDisabled("a consortium member_id (not a pseudonym) must be configured")

    def in_own_space(self, ind: IntelIndicator) -> bool:
        net = ind.network()
        if net is None:
            return False
        return any(net.version == o.version and net.overlaps(o)  # type: ignore[arg-type]
                   for o in (ipaddress.ip_network(n, strict=False) for n in self.own_networks))


# ---------------------------------------------------------------------------- indicator packages

class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SharedIndicator(_M):
    token: str
    type: Literal["domain", "ip", "cidr"]
    threat_label: str | None
    confidence_band: Literal["low", "medium", "high"]
    first_seen_day: str                  # YYYY-MM-DD (coarsened)
    expires_day: str
    origin_groups: list[str]             # public feed groups or "member" (independence accounting)


class SharedIndicatorPackage(_M):
    schema_: Literal["aegis.intel_share/1"] = Field(SHARE_SCHEMA, alias="schema")
    package_id: str
    publisher: str
    consortium_key_id: str
    epoch: str
    created_at: datetime
    entries: list[SharedIndicator]
    signer_key_id: str = ""
    signature: str = ""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _band(conf: float) -> Literal["low", "medium", "high"]:
    return "high" if conf >= 0.8 else "medium" if conf >= 0.5 else "low"


def _signing_bytes(model: BaseModel) -> bytes:
    body = model.model_dump(mode="json", by_alias=True)
    body.pop("signature", None)
    return canonical_bytes(body)


def _sign(model: Any, signer: SignerLike) -> Any:
    model = model.model_copy(update={"signer_key_id": signer.key_id, "signature": ""})
    return model.model_copy(update={"signature": signer.sign(_signing_bytes(model))})


def verify_signed(model: SharedIndicatorPackage | AggregateRelease, keyring: KeyRing) -> bool:
    return keyring.verify(model.signer_key_id, _signing_bytes(model), model.signature)


@dataclass
class ShareReport:
    shared: int
    withheld: dict[str, int] = field(default_factory=dict)


def build_indicator_package(store: IntelStore, policy: SharingPolicy, key: ConsortiumKey, signer: SignerLike, *,
                            now: datetime, verified_local: Iterable[tuple[str, str]] = ()
                            ) -> tuple[SharedIndicatorPackage, ShareReport]:
    """Blind and sign the tenant's shareable indicators.

    ``verified_local`` lists ``(type, value)`` of operator-originated indicators that an
    analyst verified; other operator-originated indicators are withheld unless
    ``policy.share_unverified_detections``.
    """
    if policy.tenant_id != store.tenant_id:
        raise PermissionError("policy and store belong to different tenants")
    policy.require("indicators")
    now = utc(now)
    verified = {(t, v) for t, v in verified_local}
    withheld: dict[str, int] = {}
    entries: dict[str, SharedIndicator] = {}

    def skip(reason: str) -> None:
        withheld[reason] = withheld.get(reason, 0) + 1

    for ind in store.indicators(states=("active",), now=now):
        local = not (set([ind.source_group, *ind.syndicated_groups]) & PUBLIC_GROUPS)
        if ind.verdict != "malicious":
            skip("benign")
            continue
        if ind.confidence < policy.min_confidence:
            skip("below_min_confidence")
            continue
        if not ind.redistributable or not _license_ok(ind.license, policy.allowed_licenses):
            skip("license")
            continue
        if ind.type in ("ip", "cidr"):
            if policy.in_own_space(ind):
                skip("own_address_space")
                continue
            if local and not policy.own_networks:
                skip("own_networks_unconfigured")
                continue
        if local and (ind.type, ind.value) not in verified and not policy.share_unverified_detections:
            skip("unverified_local_detection")
            continue
        tok = key.token(ind.type, ind.value)
        groups = sorted({g if g in PUBLIC_GROUPS else "member" for g in (ind.source_group, *ind.syndicated_groups)})
        prev = entries.get(tok)
        if prev is not None:
            groups = sorted(set(groups) | set(prev.origin_groups))
        entries[tok] = SharedIndicator(
            token=tok, type=ind.type, threat_label=ind.threat_label,
            confidence_band=_band(max(ind.confidence, 0.0 if prev is None else
                                      {"low": 0.0, "medium": 0.5, "high": 0.8}[prev.confidence_band])),
            first_seen_day=ind.first_seen.strftime("%Y-%m-%d"), expires_day=ind.expires_at.strftime("%Y-%m-%d"),
            origin_groups=groups)
    pkg = SharedIndicatorPackage(
        package_id=f"share-{secrets.token_hex(8)}", publisher=policy.member_id, consortium_key_id=key.key_id,
        epoch=key.epoch, created_at=now, entries=[entries[k] for k in sorted(entries)])
    pkg = _sign(pkg, signer)
    assert_no_leak(pkg, store)
    return pkg, ShareReport(shared=len(pkg.entries), withheld=dict(sorted(withheld.items())))


def _license_ok(license_: str, allowed: Sequence[str]) -> bool:
    return all(part.strip() in allowed for part in license_.split("+"))


def assert_no_leak(obj: BaseModel, store: IntelStore | None = None, *,
                   raw_values: Iterable[str] = (), pseudonyms: Iterable[str] = ()) -> None:
    """Defense in depth before anything leaves: no pseudonym-shaped string, no raw value.

    Raises :class:`SharingError` when the serialized object contains a line pseudonym or
    any raw indicator value of the store (or of ``raw_values``), including as the suffix of a
    longer host name or as the address part of a prefix. Linear in the output size.
    """
    text = obj.model_dump_json(by_alias=True).lower()
    if _PSEUDONYM_RE.search(text):
        raise SharingError("refusing to share: output contains a pseudonym")
    values = {v.lower() for v in raw_values}
    plist = {p.lower() for p in pseudonyms if p}
    if store is not None:
        values |= {i.value.lower() for i in store.indicators()}
        plist |= {v.line_pseudonym.lower() for v in store.victims()}
    for tok in _HOSTLIKE.findall(text):
        if tok in plist:
            raise SharingError("refusing to share: output contains a pseudonym")
        candidates = {tok, tok.split("/", 1)[0]}
        parts = tok.split(".")
        candidates.update(".".join(parts[i:]) for i in range(1, len(parts) - 1))
        if candidates & values:
            raise SharingError("refusing to share: output contains a raw indicator value")


_HOSTLIKE = re.compile(r"[0-9a-z_][0-9a-z.\-_:/]*[0-9a-z]")


def verify_package(pkg: SharedIndicatorPackage | dict[str, Any], keyring: KeyRing,
                   key: ConsortiumKey) -> SharedIndicatorPackage:
    """Parse and verify a received package (signature, schema, key id and epoch)."""
    p = pkg if isinstance(pkg, SharedIndicatorPackage) else SharedIndicatorPackage.model_validate(pkg)
    if not verify_signed(p, keyring):
        raise SharingError(f"package {p.package_id} signature does not verify")
    if p.consortium_key_id != key.key_id or p.epoch != key.epoch:
        raise SharingError("package was blinded under a different consortium key or epoch")
    if any(not e.token.startswith(TOKEN_PREFIX) for e in p.entries):
        raise SharingError("malformed token")
    return p


class ConsortiumSighting(_M):
    type: str
    value: str                          # the receiver's *own* value (never received from the network)
    publishers: list[str]
    origin_groups: list[str]
    independent_origins: int            # distinct origin groups; every "member" publisher counts once
    threat_labels: list[str]


class ConsortiumIndex:
    """Receiver-side index of verified packages from *other* members."""

    def __init__(self, key: ConsortiumKey, own_member_id: str):
        self.key = key
        self.own = own_member_id
        self._by_token: dict[str, list[tuple[str, SharedIndicator]]] = {}

    def add(self, pkg: SharedIndicatorPackage) -> int:
        if pkg.publisher == self.own:
            return 0
        for e in pkg.entries:
            lst = self._by_token.setdefault(e.token, [])
            lst[:] = [x for x in lst if x[0] != pkg.publisher] + [(pkg.publisher, e)]
        return len(pkg.entries)

    def _sighting(self, typ: str, value: str, tok: str) -> ConsortiumSighting | None:
        hits = self._by_token.get(tok)
        if not hits:
            return None
        origins: set[str] = set()
        for pub, e in hits:
            for g in e.origin_groups:
                origins.add(f"member:{pub}" if g == "member" else g)
        return ConsortiumSighting(type=typ, value=value, publishers=sorted({p for p, _ in hits}),
                                  origin_groups=sorted(origins), independent_origins=len(origins),
                                  threat_labels=sorted({e.threat_label for _, e in hits if e.threat_label}))

    def match_indicators(self, store: IntelStore, now: datetime) -> list[ConsortiumSighting]:
        """Which of the receiver's own active indicators other members also hold."""
        out: dict[tuple[str, str], ConsortiumSighting] = {}
        for ind in store.indicators(states=("active",), now=now, verdict="malicious"):
            s = self._sighting(ind.type, ind.value, self.key.token(ind.type, ind.value))
            if s is not None:
                out[(ind.type, ind.value)] = s
        return [out[k] for k in sorted(out)]

    def match_observations(self, observations: Iterable[ObservationEvent], tenant_id: str, *,
                           cidr_prefixes: Sequence[int] = (24, 22, 20, 16)) -> list[ConsortiumSighting]:
        """Which destinations in the receiver's own traffic other members flagged."""
        out: dict[tuple[str, str], ConsortiumSighting] = {}
        for ev in observations:
            if ev.tenant_id != tenant_id:
                raise ValueError(f"observation {ev.event_id} belongs to another tenant")
            cands: list[tuple[str, str, str]] = []
            if ev.flow is not None:
                ip = ev.flow.dst_ip
                cands.append(("ip", ip, self.key.token("ip", ip)))
                try:
                    addr = ipaddress.ip_address(ip)
                    for plen in cidr_prefixes:
                        if plen < addr.max_prefixlen:
                            net = str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
                            cands.append(("cidr", net, self.key.token("cidr", net)))
                except ValueError:
                    pass
            if ev.dns is not None:
                parts = ev.dns.qname.strip().lower().rstrip(".").split(".")
                for i in range(len(parts) - 1):
                    d = ".".join(parts[i:])
                    cands.append(("domain", d, self.key.token("domain", d)))
            for typ, val, tok in cands:
                if (typ, val) in out:
                    continue
                s = self._sighting(typ, val, tok)
                if s is not None:
                    out[(typ, val)] = s
        return [out[k] for k in sorted(out)]


# ---------------------------------------------------------------------------- local detections -> indicators

def campaign_indicators(campaigns: Sequence[Campaign], tenant_id: str, *, now: datetime,
                        ttl: timedelta = timedelta(days=14), license_: str = "operator-shared"
                        ) -> list[IntelIndicator]:
    """Turn RESONANCE campaign destinations into operator-originated indicators.

    Shared-hosting IPs are never emitted (domain only), campaigns on unknown topology are
    skipped, and the indicators carry no line information at all.
    """
    now = utc(now)
    out: list[IntelIndicator] = []
    for c in campaigns:
        if c.tenant_id != tenant_id:
            raise ValueError(f"campaign {c.campaign_id} belongs to another tenant")
        if c.topology_unknown:
            continue
        conf = 0.9 if c.q_value <= 0.001 else 0.7
        vals: list[tuple[str, str]] = []
        for d in c.destinations:
            kind, _, v = d.partition(":")
            if kind == "d":
                vals.append(("domain", v))
            elif kind == "ip" and not c.shared_hosting_domain:
                vals.append(("ip", v))
        if not c.shared_hosting_domain:
            vals.extend(("ip", ip) for ip in c.destination_ips)
        for _typ, v in vals:
            try:
                typ2, norm = classify_host(v)
            except ValueError:
                continue
            first = utc(c.onset_at or c.window_start)
            out.append(IntelIndicator(
                type=typ2, value=norm, verdict="malicious", threat_label="c2_beaconing",  # type: ignore[arg-type]
                malware_family=None, confidence=conf, first_seen=first, last_seen=max(first, utc(c.window_end)),
                expires_at=max(now, utc(c.window_end)) + ttl, source_group=f"{OPERATOR_GROUP}:{tenant_id}",
                sources=("aegis:resonance",), license=license_, redistributable=True,
                tags=("resonance", "local_detection"), references=(f"campaign:{c.campaign_id}",)))
    return out


# ---------------------------------------------------------------------------- DP aggregate release

class ReleasedCount(_M):
    destination_tokens: list[str]
    noisy_count: int


class AggregateRelease(_M):
    schema_: Literal["aegis.intel_dp_release/1"] = Field(RELEASE_SCHEMA, alias="schema")
    release_id: str
    publisher: str
    consortium_key_id: str
    epoch: str
    created_at: datetime
    statistic: str
    mechanism: Mechanism
    epsilon: float
    delta: float
    l1_sensitivity: int
    l2_sensitivity: float
    max_contributions_per_line: int
    k_min: int
    noisy_threshold: int
    entries: list[ReleasedCount]
    signer_key_id: str = ""
    signature: str = ""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _bound_contributions(groups: Mapping[str, Iterable[str]], max_per_member: int) -> dict[str, int]:
    """Count distinct members per group, keeping at most ``max_per_member`` groups per member.

    The kept groups are chosen by a deterministic hash of (member, group), so one member's
    choice never depends on any other member's data (required for the sensitivity bound).
    """
    member_groups: dict[str, list[str]] = {}
    for g, members in groups.items():
        for m in set(members):
            member_groups.setdefault(m, []).append(g)
    counts = {g: 0 for g in groups}
    for m, gs in member_groups.items():
        ranked = sorted(gs, key=lambda g: hashlib.sha256(f"{m}|{g}".encode()).digest())
        for g in ranked[:max_per_member]:
            counts[g] += 1
    return counts


def release_counts(tenant_id: str, groups: Mapping[str, Sequence[str]], members: Mapping[str, Iterable[str]],
                   policy: SharingPolicy, accountant: PrivacyAccountant, key: ConsortiumKey, signer: SignerLike, *,
                   now: datetime, statistic: str, rng: RandomSource | None = None) -> AggregateRelease:
    """DP release of distinct-member counts per group.

    ``groups`` maps a local group id to its *raw* destination values (blinded here);
    ``members`` maps the same group id to member ids (line pseudonyms). Member ids are
    used only to bound contributions and count; they never appear in the output.
    """
    if policy.tenant_id != tenant_id:
        raise PermissionError("policy belongs to another tenant")
    policy.require("aggregates")
    if set(groups) != set(members):
        raise ValueError("groups and members must have the same keys")
    now = utc(now)
    rng = rng or SecureRandom()
    c = policy.max_contributions_per_line
    l1, l2 = c, float(c) ** 0.5
    mech = policy.mechanism
    eps = policy.epsilon_per_release
    delta = policy.delta_per_release if mech == "gaussian" else 0.0
    # The k-anonymity gates only change outcomes whose probability is at most threshold_beta
    # (a count at the boundary passes the noisy gate with probability <= beta), so the
    # release is (eps, delta + beta)-DP; the accountant is charged that full delta.
    charged_delta = delta + policy.threshold_beta
    release_id = f"rel-{secrets.token_hex(8)}"
    # charge first: if the budget is exhausted nothing is computed or released
    accountant.charge(tenant_id, epsilon=eps, delta=charged_delta, mechanism=mech, release_id=release_id,
                      purpose=statistic, now=now)
    counts = _bound_contributions(members, c)
    margin = noise_tail_bound(mech, eps, delta or 1e-9, l1 if mech == "laplace" else l2, policy.threshold_beta)
    threshold = policy.k_min + int(margin)
    entries: list[ReleasedCount] = []
    for g in sorted(groups):
        true = counts[g]
        noise = laplace_noise(eps, l1, rng) if mech == "laplace" else gaussian_noise(eps, delta, l2, rng)
        noisy = true + noise
        if true < policy.k_min or noisy < threshold:
            continue
        toks = sorted({key.token_for_raw(v)[1] for v in groups[g]})
        if toks:
            entries.append(ReleasedCount(destination_tokens=toks, noisy_count=int(noisy)))
    entries.sort(key=lambda e: e.destination_tokens)
    rel = AggregateRelease(
        release_id=release_id, publisher=policy.member_id, consortium_key_id=key.key_id, epoch=key.epoch,
        created_at=now, statistic=statistic, mechanism=mech, epsilon=eps, delta=charged_delta, l1_sensitivity=l1,
        l2_sensitivity=l2, max_contributions_per_line=c, k_min=policy.k_min, noisy_threshold=threshold,
        entries=entries)
    rel = _sign(rel, signer)
    pseudos = {m for ms in members.values() for m in ms}
    raw = {v for vs in groups.values() for v in vs}
    assert_no_leak(rel, raw_values=raw, pseudonyms=pseudos)
    return rel


def release_campaign_counts(campaigns: Sequence[Campaign], policy: SharingPolicy, accountant: PrivacyAccountant,
                            key: ConsortiumKey, signer: SignerLike, *, now: datetime,
                            rng: RandomSource | None = None) -> AggregateRelease:
    """DP release of infected-line counts per RESONANCE campaign (destinations blinded)."""
    groups: dict[str, list[str]] = {}
    members: dict[str, list[str]] = {}
    for c in campaigns:
        if c.tenant_id != policy.tenant_id:
            raise ValueError(f"campaign {c.campaign_id} belongs to another tenant")
        vals = []
        for d in c.destinations:
            kind, _, v = d.partition(":")
            if kind == "d" or (kind == "ip" and not c.shared_hosting_domain):
                vals.append(v)
        if not vals:
            continue
        groups[c.campaign_id] = vals
        members[c.campaign_id] = list(c.member_lines)
    return release_counts(policy.tenant_id, groups, members, policy, accountant, key, signer, now=now,
                          statistic="infected_lines_per_campaign", rng=rng)


def verify_release(rel: AggregateRelease | dict[str, Any], keyring: KeyRing) -> AggregateRelease:
    r = rel if isinstance(rel, AggregateRelease) else AggregateRelease.model_validate(rel)
    if not verify_signed(r, keyring):
        raise SharingError(f"release {r.release_id} signature does not verify")
    if any(e.noisy_count < r.k_min for e in r.entries):
        raise SharingError("release contains a count below its k-anonymity threshold")
    return r


__all__ = [
    "AggregateRelease", "ConsortiumIndex", "ConsortiumKey", "ConsortiumSighting", "PUBLIC_GROUPS",
    "RELEASE_SCHEMA", "ReleasedCount", "SHARE_SCHEMA", "ShareReport", "SharedIndicator", "SharedIndicatorPackage",
    "SharingDisabled", "SharingError", "SharingPolicy", "assert_no_leak", "build_indicator_package",
    "campaign_indicators", "release_campaign_counts", "release_counts", "verify_package", "verify_release",
    "verify_signed",
]
