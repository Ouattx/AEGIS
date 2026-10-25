"""Circuit breaker on legitimate-traffic health (spec section 9).

While an enforcement action is live, the operator's probes report how much
*legitimate* traffic (connectivity checks, synthetic transactions, resolver
SERVFAIL/NXDOMAIN rates for allow-listed names, support-ticket signals...) is
failing. For each watched action the breaker keeps a sliding window of samples
and trips when the error rate is abnormal compared with the pre-action baseline:

    error_rate > threshold = min(max_error_rate,
                                 max(baseline * relative_factor, baseline + absolute_margin))

provided the window holds at least ``min_requests`` requests (no tripping on
noise). A trip notifies every subscriber (the executor rolls the action back) and
opens the breaker: no new enforcement runs until a human resets it.
"""
from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable

from aegis.mirror.base import is_human

TripCallback = Callable[[str, str], None]


class BreakerState(str, Enum):
    CLOSED = "closed"   # enforcement allowed
    OPEN = "open"       # tripped: enforcement blocked until a human resets


@dataclass(frozen=True)
class HealthSample:
    action_id: str
    requests: int
    errors: int
    at: datetime


@dataclass
class TripEvent:
    action_id: str
    reason: str
    error_rate: float
    threshold: float
    requests: int
    at: datetime
    callback_errors: list[str] = field(default_factory=list)


@dataclass
class _Watch:
    baseline: float
    samples: deque[HealthSample] = field(default_factory=deque)
    tripped: bool = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CircuitBreaker:
    """Trips on abnormal legitimate-traffic error rates and triggers auto-rollback."""

    def __init__(self, *, baseline_error_rate: float = 0.01, relative_factor: float = 3.0,
                 absolute_margin: float = 0.02, max_error_rate: float = 0.25,
                 min_requests: int = 50, window: timedelta = timedelta(minutes=5),
                 clock: Callable[[], datetime] | None = None):
        if not 0.0 <= baseline_error_rate < 1.0:
            raise ValueError("baseline_error_rate must be in [0, 1)")
        if relative_factor < 1.0:
            raise ValueError("relative_factor must be >= 1")
        if absolute_margin < 0.0:
            raise ValueError("absolute_margin must be >= 0")
        if not 0.0 < max_error_rate <= 1.0:
            raise ValueError("max_error_rate must be in (0, 1]")
        if min_requests < 1:
            raise ValueError("min_requests must be >= 1")
        if window <= timedelta(0):
            raise ValueError("window must be positive")
        self.default_baseline = baseline_error_rate
        self.relative_factor = relative_factor
        self.absolute_margin = absolute_margin
        self.max_error_rate = max_error_rate
        self.min_requests = min_requests
        self.window = window
        self._clock = clock or _utc_now
        self._lock = threading.RLock()
        self._watches: dict[str, _Watch] = {}
        self._subscribers: list[TripCallback] = []
        self._state = BreakerState.CLOSED
        self.trips: list[TripEvent] = []
        self.resets: list[tuple[str, str, datetime]] = []

    # ------------------------------------------------------------------ config
    def subscribe(self, callback: TripCallback) -> None:
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def watch(self, action_id: str, baseline_error_rate: float | None = None) -> None:
        """Start monitoring legit-traffic health for a live action."""
        base = self.default_baseline if baseline_error_rate is None else baseline_error_rate
        if not 0.0 <= base < 1.0:
            raise ValueError("baseline_error_rate must be in [0, 1)")
        with self._lock:
            self._watches[action_id] = _Watch(baseline=base)

    def unwatch(self, action_id: str) -> None:
        with self._lock:
            self._watches.pop(action_id, None)

    def watching(self) -> list[str]:
        with self._lock:
            return list(self._watches)

    def threshold(self, action_id: str) -> float:
        with self._lock:
            w = self._watches.get(action_id)
            base = w.baseline if w is not None else self.default_baseline
        return min(self.max_error_rate,
                   max(base * self.relative_factor, base + self.absolute_margin))

    # ------------------------------------------------------------------ state
    @property
    def state(self) -> BreakerState:
        with self._lock:
            return self._state

    @property
    def is_open(self) -> bool:
        return self.state is BreakerState.OPEN

    def reset(self, actor: str, reason: str) -> None:
        """Close the breaker. Only a human may do this, with a recorded reason."""
        if not is_human(actor):
            raise PermissionError("only a human operator may reset the circuit breaker")
        if not reason or not reason.strip():
            raise ValueError("a reset reason is required")
        with self._lock:
            self._state = BreakerState.CLOSED
            self.resets.append((actor, reason, self._clock()))

    # ------------------------------------------------------------------ samples
    def error_rate(self, action_id: str) -> tuple[float | None, int]:
        """Windowed ``(error_rate, requests)``; rate is None with no requests."""
        with self._lock:
            w = self._watches.get(action_id)
            if w is None:
                return None, 0
            self._expire(w, self._clock())
            req = sum(s.requests for s in w.samples)
            err = sum(s.errors for s in w.samples)
        return (err / req if req else None), req

    def record(self, action_id: str, requests: int, errors: int,
               at: datetime | None = None) -> bool:
        """Add a health sample; returns True if this sample tripped the breaker."""
        if requests < 0 or errors < 0 or errors > requests:
            raise ValueError("need 0 <= errors <= requests")
        ts = at or self._clock()
        with self._lock:
            w = self._watches.get(action_id)
            if w is None or w.tripped:
                return False
            w.samples.append(HealthSample(action_id, requests, errors, ts))
            self._expire(w, ts)
            req = sum(s.requests for s in w.samples)
            err = sum(s.errors for s in w.samples)
            if req < self.min_requests:
                return False
            rate = err / req
            thr = min(self.max_error_rate,
                      max(w.baseline * self.relative_factor, w.baseline + self.absolute_margin))
            if rate <= thr:
                return False
            w.tripped = True
            self._state = BreakerState.OPEN
            event = TripEvent(action_id=action_id,
                              reason=(f"legitimate traffic error rate {rate:.4f} exceeded "
                                      f"threshold {thr:.4f} over {req} requests"),
                              error_rate=rate, threshold=thr, requests=req, at=ts)
            self.trips.append(event)
            subscribers = list(self._subscribers)
        for cb in subscribers:  # outside the lock: callbacks may call back into us
            try:
                cb(action_id, event.reason)
            except Exception as exc:
                event.callback_errors.append(f"{type(exc).__name__}: {exc}")
        return True

    def _expire(self, w: _Watch, now: datetime) -> None:
        cutoff = now - self.window
        while w.samples and w.samples[0].at < cutoff:
            w.samples.popleft()
