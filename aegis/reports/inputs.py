"""Operator-supplied inputs of the proof-of-value report.

- :class:`ReportPeriod`: the reporting window (timezone-aware, half-open ``[start, end)``);
- :class:`CoverageStats` / :class:`CoverageAccumulator`: what the sensors actually saw
  (devices, device-days, events). Rates such as *false alerts per 10k device-days*
  need the observed denominator; it is computed from the event stream, never guessed;
- :class:`CostInputs`: the operator's own cost figures (everything configurable);
- :class:`AnalystEffortModel`: the transparent per-case effort model used to
  *estimate* analyst minutes per case (shown in the report with its parameters).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from aegis.contracts.models import ObservationEvent


def _aware(dt: datetime, name: str) -> datetime:
    if dt.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ReportPeriod:
    """Half-open reporting window ``[start, end)`` in UTC."""
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", _aware(self.start, "start"))
        object.__setattr__(self, "end", _aware(self.end, "end"))
        if self.end <= self.start:
            raise ValueError("period end must be after start")

    @classmethod
    def coerce(cls, value: "ReportPeriod | tuple[datetime, datetime]") -> "ReportPeriod":
        if isinstance(value, ReportPeriod):
            return value
        start, end = value
        return cls(start, end)

    @property
    def days(self) -> float:
        return (self.end - self.start).total_seconds() / 86_400.0

    def contains(self, ts: datetime) -> bool:
        return self.start <= _aware(ts, "timestamp") < self.end

    def dates(self) -> list[date]:
        """UTC calendar dates the period touches."""
        out: list[date] = []
        d = self.start.date()
        last = (self.end - timedelta(microseconds=1)).date()
        while d <= last:
            out.append(d)
            d += timedelta(days=1)
        return out


@dataclass(frozen=True)
class CoverageStats:
    """Observed population of the period (the denominator of every rate)."""
    devices_observed: int
    device_days: int
    events: int | None = None
    devices_by_class: dict[str, int] = field(default_factory=dict)
    device_days_by_class: dict[str, int] = field(default_factory=dict)
    sources: tuple[str, ...] = ()
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.devices_observed < 0 or self.device_days < 0:
            raise ValueError("coverage counts must be non-negative")
        if self.device_days < self.devices_observed:
            raise ValueError("device_days cannot be smaller than devices_observed")

    @classmethod
    def from_events(cls, events: Iterable[ObservationEvent],
                    period: ReportPeriod | None = None) -> "CoverageStats":
        acc = CoverageAccumulator()
        for ev in events:
            if period is None or period.contains(ev.observed_at):
                acc.add(ev)
        return acc.result()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["sources"] = list(self.sources)
        d["first_event_at"] = self.first_event_at.isoformat() if self.first_event_at else None
        d["last_event_at"] = self.last_event_at.isoformat() if self.last_event_at else None
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CoverageStats":
        def ts(v: Any) -> datetime | None:
            return None if v in (None, "") else _aware(datetime.fromisoformat(str(v)), "timestamp")
        return cls(devices_observed=int(d["devices_observed"]), device_days=int(d["device_days"]),
                   events=None if d.get("events") is None else int(d["events"]),
                   devices_by_class={str(k): int(v) for k, v in dict(d.get("devices_by_class") or {}).items()},
                   device_days_by_class={str(k): int(v)
                                         for k, v in dict(d.get("device_days_by_class") or {}).items()},
                   sources=tuple(str(s) for s in d.get("sources") or ()),
                   first_event_at=ts(d.get("first_event_at")), last_event_at=ts(d.get("last_event_at")))


class CoverageAccumulator:
    """Streaming coverage counter: feed events as they are ingested, read :meth:`result`.

    A device is identified by its entity pseudonym; a device-day is a (pseudonym, UTC
    date) with at least one event. A device's class is its most frequent reported class.
    Events without a pseudonym are counted as events but cannot form device-days.
    """

    def __init__(self) -> None:
        self._days: dict[str, set[date]] = defaultdict(set)
        self._classes: dict[str, Counter[str]] = defaultdict(Counter)
        self._events = 0
        self._sources: set[str] = set()
        self._first: datetime | None = None
        self._last: datetime | None = None

    def add(self, ev: ObservationEvent) -> None:
        self._events += 1
        self._sources.add(ev.source_id)
        t = _aware(ev.observed_at, "observed_at")
        if self._first is None or t < self._first:
            self._first = t
        if self._last is None or t > self._last:
            self._last = t
        if ev.entity_pseudonym is None:
            return
        self._days[ev.entity_pseudonym].add(t.date())
        self._classes[ev.entity_pseudonym][ev.device_class or "unknown"] += 1

    def result(self) -> CoverageStats:
        by_class: Counter[str] = Counter()
        dd_by_class: Counter[str] = Counter()
        for ent, days in self._days.items():
            klass = self._classes[ent].most_common(1)[0][0] if self._classes[ent] else "unknown"
            by_class[klass] += 1
            dd_by_class[klass] += len(days)
        return CoverageStats(devices_observed=len(self._days),
                             device_days=sum(len(v) for v in self._days.values()), events=self._events,
                             devices_by_class=dict(sorted(by_class.items())),
                             device_days_by_class=dict(sorted(dd_by_class.items())),
                             sources=tuple(sorted(self._sources)), first_event_at=self._first,
                             last_event_at=self._last)


@dataclass(frozen=True)
class CostInputs:
    """Operator cost inputs (monthly figures in ``currency``). All default to zero except the
    analyst rate, so an unconfigured report shows analyst cost only and says so."""
    currency: str = "USD"
    license_monthly: float = 0.0              # AEGIS subscription / pilot fee per month
    infrastructure_monthly: float = 0.0       # hosting, or amortized on-prem hardware + power
    other_monthly: float = 0.0                # support, storage, connectivity...
    analyst_hourly_rate: float = 85.0         # fully loaded SOC analyst cost per hour
    llm_cost_per_investigation: float = 0.0   # optional LLM-assisted investigation cost
    protected_devices: int | None = None      # defaults to devices observed

    def __post_init__(self) -> None:
        for k in ("license_monthly", "infrastructure_monthly", "other_monthly", "analyst_hourly_rate",
                  "llm_cost_per_investigation"):
            v = getattr(self, k)
            if not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"{k} must be a non-negative number")
        if self.protected_devices is not None and self.protected_devices < 0:
            raise ValueError("protected_devices must be non-negative")
        if not self.currency or len(self.currency) > 8:
            raise ValueError("currency must be a short code such as USD or EUR")

    @property
    def configured(self) -> bool:
        return any((self.license_monthly, self.infrastructure_monthly, self.other_monthly,
                    self.llm_cost_per_investigation))

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CostInputs":
        known = set(cls.__dataclass_fields__)
        unknown = set(d) - known
        if unknown:
            raise ValueError(f"unknown cost inputs: {sorted(unknown)}")
        return cls(**dict(d))


@dataclass(frozen=True)
class AnalystEffortModel:
    """Transparent estimate of analyst minutes spent on one case.

    minutes = triage + min(evidence items, cap) x per-item review
              + investigation (if the case went beyond triage)
              + counter-hypothesis review (if recorded) + disposition write-up (if closed out)
    """
    triage_minutes: float = 4.0
    minutes_per_evidence_item: float = 0.5
    max_evidence_items: int = 20
    investigation_minutes: float = 12.0
    counter_hypothesis_minutes: float = 5.0
    disposition_minutes: float = 2.0

    def __post_init__(self) -> None:
        for k, v in asdict(self).items():
            if v < 0:
                raise ValueError(f"{k} must be non-negative")

    def estimate(self, *, evidence_items: int, investigated: bool, counter_reviewed: bool,
                 dispositioned: bool) -> float:
        return (self.triage_minutes
                + min(max(evidence_items, 0), self.max_evidence_items) * self.minutes_per_evidence_item
                + (self.investigation_minutes if investigated else 0.0)
                + (self.counter_hypothesis_minutes if counter_reviewed else 0.0)
                + (self.disposition_minutes if dispositioned else 0.0))

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "AnalystEffortModel":
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown effort model parameters: {sorted(unknown)}")
        return cls(**dict(d))


__all__ = ["AnalystEffortModel", "CostInputs", "CoverageAccumulator", "CoverageStats", "ReportPeriod"]
