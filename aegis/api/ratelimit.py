"""Per-key token-bucket rate limiter (per tenant for authenticated calls, per client
address for unauthenticated endpoints). In-process; a multi-replica deployment
puts the same limits at its ingress as well."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket: ``rate`` tokens per second, at most ``burst`` stored.

    ``acquire(key, cost)`` returns ``(allowed, retry_after_s)``. Idle buckets are
    evicted so the table cannot grow without bound.
    """

    def __init__(self, rate: float, burst: int, *, monotonic: Callable[[], float] = time.monotonic,
                 max_keys: int = 100_000):
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be > 0 and burst >= 1")
        self.rate = float(rate)
        self.burst = float(burst)
        self._mono = monotonic
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._buckets: dict[str, _Bucket] = {}

    def acquire(self, key: str, cost: float = 1.0) -> tuple[bool, float]:
        cost = max(0.0, min(float(cost), self.burst))
        with self._lock:
            now = self._mono()
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self._max_keys:
                    self._evict(now)
                b = self._buckets[key] = _Bucket(tokens=self.burst, updated=now)
            else:
                b.tokens = min(self.burst, b.tokens + (now - b.updated) * self.rate)
                b.updated = now
            if b.tokens >= cost:
                b.tokens -= cost
                return True, 0.0
            return False, (cost - b.tokens) / self.rate

    def _evict(self, now: float) -> None:
        full_after = self.burst / self.rate
        stale = [k for k, b in self._buckets.items() if now - b.updated >= full_after]
        for k in stale:
            del self._buckets[k]
        if len(self._buckets) >= self._max_keys:  # still full: drop the oldest half
            for k, _ in sorted(self._buckets.items(), key=lambda kv: kv[1].updated)[: self._max_keys // 2]:
                del self._buckets[k]


__all__ = ["RateLimiter"]
