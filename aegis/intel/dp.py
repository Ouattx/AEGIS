"""Differential privacy for shared aggregates: exact integer mechanisms and per-tenant budgets.

Mechanisms (both release integers, so the floating-point attacks on textbook
Laplace samplers (Mironov 2012) do not apply):

- **discrete Laplace** (two-sided geometric) with scale ``Δ₁/ε``: pure ε-DP for a
  query with L1 sensitivity ``Δ₁``;
- **discrete Gaussian** with variance ``σ²``: ``ρ = Δ₂²/(2σ²)``-zCDP for L2 sensitivity
  ``Δ₂`` (Canonne, Kamath & Steinke 2020), hence ``(ρ + 2·sqrt(ρ·ln(1/δ)), δ)``-DP for
  every δ > 0 (Bun & Steinke 2016, Prop. 1.3). :func:`gaussian_sigma` inverts this
  conversion to get σ from a target ``(ε, δ)``.

Both samplers are the exact rejection samplers of Canonne, Kamath & Steinke (2020,
Algorithms 1-3), driven by integer randomness only (``secrets.randbelow`` by default)
and rational arithmetic.

Budget accounting (:class:`PrivacyAccountant`) uses basic sequential composition:
every release charges its ``(ε, δ)``; the sums must stay within the tenant's
budget, otherwise the release is refused *before* any noise is drawn or any
value leaves. Charges are persisted through a :class:`BudgetStore` so a restart
does not reset the budget, and optionally written to the provenance ledger.
"""
from __future__ import annotations

import math
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime
from fractions import Fraction
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from aegis.intel.models import iso, utc

Mechanism = Literal["laplace", "gaussian"]
_DENOM_LIMIT = 1_000_000


class RandomSource(Protocol):
    def randbelow(self, n: int) -> int: ...


class SecureRandom:
    """Cryptographic randomness (default)."""

    def randbelow(self, n: int) -> int:
        return secrets.randbelow(n)


class SeededRandom:
    """Deterministic randomness for tests and reproducible simulations only. Never for releases."""

    def __init__(self, seed: int):
        import random
        self._r = random.Random(seed)

    def randbelow(self, n: int) -> int:
        return self._r.randrange(n)


# ---------------------------------------------------------------------------- exact samplers

def _bernoulli(p: Fraction, rng: RandomSource) -> bool:
    if p <= 0:
        return False
    if p >= 1:
        return True
    return rng.randbelow(p.denominator) < p.numerator


def _bernoulli_exp_le1(gamma: Fraction, rng: RandomSource) -> bool:
    """Bernoulli(exp(-γ)) for γ in [0, 1] (CKS Algorithm 1, first part)."""
    k = 1
    while _bernoulli(gamma / k, rng):
        k += 1
    return k % 2 == 1


def bernoulli_exp(gamma: Fraction, rng: RandomSource) -> bool:
    """Exact Bernoulli(exp(-γ)) for rational γ >= 0."""
    if gamma < 0:
        raise ValueError("gamma must be >= 0")
    whole = math.floor(gamma)
    for _ in range(whole):
        if not _bernoulli_exp_le1(Fraction(1), rng):
            return False
    return _bernoulli_exp_le1(gamma - whole, rng)


def sample_discrete_laplace(scale: Fraction, rng: RandomSource) -> int:
    """Exact sample of the discrete Laplace distribution P(x) ∝ exp(-|x|/scale) (CKS Algorithm 2)."""
    if scale <= 0:
        raise ValueError("scale must be > 0")
    s, t = scale.denominator, scale.numerator        # scale = t / s
    while True:
        u = rng.randbelow(t)
        if not bernoulli_exp(Fraction(u, t), rng):
            continue
        v = 0
        while bernoulli_exp(Fraction(1), rng):
            v += 1
        x = u + t * v
        y = x // s
        b = rng.randbelow(2)
        if b == 1 and y == 0:
            continue
        return (1 - 2 * b) * y


def sample_discrete_gaussian(sigma2: Fraction, rng: RandomSource) -> int:
    """Exact sample of the discrete Gaussian P(x) ∝ exp(-x²/(2σ²)) (CKS Algorithm 3)."""
    if sigma2 <= 0:
        raise ValueError("sigma2 must be > 0")
    t = math.isqrt(math.floor(sigma2)) + 1
    while True:
        y = sample_discrete_laplace(Fraction(t), rng)
        gamma = (abs(y) - sigma2 / t) ** 2 / (2 * sigma2)
        if bernoulli_exp(gamma, rng):
            return y


def gaussian_sigma(epsilon: float, delta: float, l2_sensitivity: float) -> float:
    """σ such that the discrete Gaussian satisfies (ε, δ)-DP via the zCDP conversion."""
    if epsilon <= 0 or not 0 < delta < 1 or l2_sensitivity <= 0:
        raise ValueError("need epsilon > 0, 0 < delta < 1, sensitivity > 0")
    log_inv = math.log(1.0 / delta)
    sqrt_rho = math.sqrt(log_inv + epsilon) - math.sqrt(log_inv)
    rho = sqrt_rho * sqrt_rho
    return l2_sensitivity / math.sqrt(2.0 * rho)


def laplace_noise(epsilon: float, l1_sensitivity: int, rng: RandomSource) -> int:
    if epsilon <= 0 or l1_sensitivity <= 0:
        raise ValueError("need epsilon > 0 and sensitivity > 0")
    scale = Fraction(l1_sensitivity) / Fraction(epsilon).limit_denominator(_DENOM_LIMIT)
    return sample_discrete_laplace(scale, rng)


def gaussian_noise(epsilon: float, delta: float, l2_sensitivity: float, rng: RandomSource) -> int:
    sigma = gaussian_sigma(epsilon, delta, l2_sensitivity)
    # round σ² *up* so the realized privacy loss is never worse than requested
    sigma2 = Fraction(sigma * sigma).limit_denominator(_DENOM_LIMIT)
    if float(sigma2) < sigma * sigma:
        sigma2 += Fraction(1, _DENOM_LIMIT)
    return sample_discrete_gaussian(sigma2, rng)


def noise_tail_bound(mechanism: Mechanism, epsilon: float, delta: float, sensitivity: float,
                     beta: float) -> float:
    """``τ`` with ``P(noise >= τ) <= beta`` (one-sided), for choosing release thresholds."""
    if not 0 < beta < 1:
        raise ValueError("beta must be in (0, 1)")
    if mechanism == "laplace":
        scale = sensitivity / epsilon
        # discrete Laplace: P(X >= k) = e^{-k/scale} / (1 + e^{-1/scale}) <= e^{-k/scale}
        return math.ceil(scale * math.log(1.0 / beta))
    sigma = gaussian_sigma(epsilon, delta, sensitivity)
    # discrete Gaussian tails are dominated by the continuous ones plus one (CKS Prop. 25)
    return math.ceil(sigma * math.sqrt(2.0 * math.log(1.0 / beta))) + 1


# ---------------------------------------------------------------------------- accounting

class BudgetExceeded(PermissionError):
    """The release would exceed the tenant's privacy budget; nothing was released."""


class DPCharge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    charge_id: str
    release_id: str
    epsilon: float
    delta: float
    mechanism: Mechanism
    purpose: str
    at: datetime


class PrivacyBudgetDoc(BaseModel):
    """Persisted budget state of one tenant (DocStore-compatible: ``doc_id`` + ``tenant_id``)."""
    model_config = ConfigDict(extra="forbid")
    doc_id: str
    tenant_id: str
    epsilon_total: float
    delta_total: float
    charges: list[DPCharge] = Field(default_factory=list)

    @property
    def epsilon_spent(self) -> float:
        return math.fsum(c.epsilon for c in self.charges)

    @property
    def delta_spent(self) -> float:
        return math.fsum(c.delta for c in self.charges)


class BudgetStore(Protocol):
    def load(self, tenant_id: str) -> PrivacyBudgetDoc | None: ...

    def save(self, doc: PrivacyBudgetDoc) -> None: ...


class InMemoryBudgetStore:
    def __init__(self) -> None:
        self._docs: dict[str, PrivacyBudgetDoc] = {}

    def load(self, tenant_id: str) -> PrivacyBudgetDoc | None:
        d = self._docs.get(tenant_id)
        return d.model_copy(deep=True) if d else None

    def save(self, doc: PrivacyBudgetDoc) -> None:
        self._docs[doc.tenant_id] = doc.model_copy(deep=True)


class DocStoreBudgetStore:
    """Persists budgets in :class:`aegis.storage.db.DocStore` (``doc_id = <tenant>:intel_dp_budget``)."""

    def __init__(self, docstore: Any):
        self._docs = docstore

    @staticmethod
    def doc_id(tenant_id: str) -> str:
        return f"{tenant_id}:intel_dp_budget"

    def load(self, tenant_id: str) -> PrivacyBudgetDoc | None:
        doc: PrivacyBudgetDoc | None = self._docs.get(PrivacyBudgetDoc, tenant_id, self.doc_id(tenant_id))
        return doc

    def save(self, doc: PrivacyBudgetDoc) -> None:
        self._docs.put(doc)


class LedgerLike(Protocol):
    def append(self, tenant_id: str, entry_type: str, subject_id: str, payload: dict[str, Any],
               recorded_at: datetime | None = None) -> Any: ...


DP_LEDGER_ENTRY = "intel_dp_charge"


@dataclass
class PrivacyAccountant:
    """Per-tenant (ε, δ) budget with basic sequential composition.

    The budget is set the first time a tenant is seen (``configure``) and can only be
    raised by an explicit ``configure(..., allow_increase=True)``, which is ledgered.
    """
    store: BudgetStore = field(default_factory=InMemoryBudgetStore)
    ledger: LedgerLike | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def configure(self, tenant_id: str, *, epsilon_total: float, delta_total: float,
                  allow_increase: bool = False, actor: str = "system") -> PrivacyBudgetDoc:
        if epsilon_total <= 0 or not 0 <= delta_total < 1:
            raise ValueError("epsilon_total must be > 0 and 0 <= delta_total < 1")
        with self._lock:
            doc = self.store.load(tenant_id)
            if doc is None:
                doc = PrivacyBudgetDoc(doc_id=DocStoreBudgetStore.doc_id(tenant_id), tenant_id=tenant_id,
                                       epsilon_total=epsilon_total, delta_total=delta_total)
            elif (epsilon_total > doc.epsilon_total or delta_total > doc.delta_total):
                if not allow_increase:
                    raise PermissionError("raising a privacy budget requires allow_increase=True")
                if self.ledger is not None:
                    self.ledger.append(tenant_id, "intel_dp_budget_change", doc.doc_id,
                                       {"actor": actor, "from": [doc.epsilon_total, doc.delta_total],
                                        "to": [epsilon_total, delta_total]})
                doc = doc.model_copy(update={"epsilon_total": epsilon_total, "delta_total": delta_total})
            else:
                doc = doc.model_copy(update={"epsilon_total": epsilon_total, "delta_total": delta_total})
            self.store.save(doc)
            return doc

    def remaining(self, tenant_id: str) -> tuple[float, float]:
        doc = self.store.load(tenant_id)
        if doc is None:
            return 0.0, 0.0
        return max(0.0, doc.epsilon_total - doc.epsilon_spent), max(0.0, doc.delta_total - doc.delta_spent)

    def charge(self, tenant_id: str, *, epsilon: float, delta: float, mechanism: Mechanism, release_id: str,
               purpose: str, now: datetime) -> DPCharge:
        """Atomically record a charge or raise :class:`BudgetExceeded` (fail closed when unconfigured)."""
        if epsilon <= 0 or delta < 0:
            raise ValueError("epsilon must be > 0 and delta >= 0")
        with self._lock:
            doc = self.store.load(tenant_id)
            if doc is None:
                raise BudgetExceeded(f"no privacy budget configured for tenant {tenant_id!r}")
            eps_after = doc.epsilon_spent + epsilon
            delta_after = doc.delta_spent + delta
            if eps_after > doc.epsilon_total + 1e-12 or delta_after > doc.delta_total + 1e-15:
                raise BudgetExceeded(
                    f"release needs (eps={epsilon}, delta={delta}); remaining "
                    f"(eps={max(0.0, doc.epsilon_total - doc.epsilon_spent):.6g}, "
                    f"delta={max(0.0, doc.delta_total - doc.delta_spent):.3g})")
            ch = DPCharge(charge_id=f"dp-{secrets.token_hex(8)}", release_id=release_id, epsilon=epsilon,
                          delta=delta, mechanism=mechanism, purpose=purpose[:200], at=utc(now))
            doc = doc.model_copy(update={"charges": [*doc.charges, ch]})
            self.store.save(doc)
            if self.ledger is not None:
                self.ledger.append(tenant_id, DP_LEDGER_ENTRY, release_id,
                                   {"charge_id": ch.charge_id, "epsilon": epsilon, "delta": delta,
                                    "mechanism": mechanism, "purpose": ch.purpose, "at": iso(ch.at),
                                    "epsilon_spent": eps_after, "delta_spent": delta_after,
                                    "epsilon_total": doc.epsilon_total, "delta_total": doc.delta_total})
            return ch


__all__ = [
    "BudgetExceeded", "BudgetStore", "DPCharge", "DP_LEDGER_ENTRY", "DocStoreBudgetStore", "InMemoryBudgetStore",
    "Mechanism", "PrivacyAccountant", "PrivacyBudgetDoc", "RandomSource", "SecureRandom", "SeededRandom",
    "bernoulli_exp", "gaussian_noise", "gaussian_sigma", "laplace_noise", "noise_tail_bound",
    "sample_discrete_gaussian", "sample_discrete_laplace",
]
