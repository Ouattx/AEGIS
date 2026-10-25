"""Minimal, dependency-free Prometheus instrumentation (text exposition format 0.0.4).

Labels never include tenant ids, subjects or indicators: metrics are scraped by
the operator's monitoring stack and must not leak tenant or subscriber data.
"""
from __future__ import annotations

import math
import threading
from typing import Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt(v: float) -> str:
    if math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    if math.isnan(v):
        return "NaN"
    if float(v).is_integer():
        return str(int(v))
    return repr(float(v))


def _labels(names: tuple[str, ...], values: tuple[str, ...], extra: dict[str, str] | None = None) -> str:
    pairs = list(zip(names, values, strict=True))
    if extra:
        pairs += list(extra.items())
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{_escape(str(v))}"' for k, v in pairs) + "}"


class _Metric:
    kind = "untyped"

    def __init__(self, name: str, doc: str, labelnames: Iterable[str] = ()):
        self.name = name
        self.doc = doc
        self.labelnames = tuple(labelnames)
        self._lock = threading.Lock()

    def _key(self, labels: dict[str, str]) -> tuple[str, ...]:
        if set(labels) != set(self.labelnames):
            raise ValueError(f"{self.name} expects labels {self.labelnames}, got {sorted(labels)}")
        return tuple(str(labels[n]) for n in self.labelnames)

    def header(self) -> list[str]:
        return [f"# HELP {self.name} {self.doc}", f"# TYPE {self.name} {self.kind}"]

    def render(self) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError


class Counter(_Metric):
    kind = "counter"

    def __init__(self, name: str, doc: str, labelnames: Iterable[str] = ()):
        super().__init__(name, doc, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        if amount < 0:
            raise ValueError("counters only increase")
        key = self._key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def value(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def render(self) -> list[str]:
        with self._lock:
            items = sorted(self._values.items())
        return self.header() + [f"{self.name}{_labels(self.labelnames, k)} {_fmt(v)}" for k, v in items]


class Gauge(_Metric):
    kind = "gauge"

    def __init__(self, name: str, doc: str, labelnames: Iterable[str] = ()):
        super().__init__(name, doc, labelnames)
        self._values: dict[tuple[str, ...], float] = {}

    def set(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            self._values[key] = float(value)

    def value(self, **labels: str) -> float:
        with self._lock:
            return self._values.get(self._key(labels), 0.0)

    def render(self) -> list[str]:
        with self._lock:
            items = sorted(self._values.items())
        return self.header() + [f"{self.name}{_labels(self.labelnames, k)} {_fmt(v)}" for k, v in items]


class Histogram(_Metric):
    kind = "histogram"

    def __init__(self, name: str, doc: str, labelnames: Iterable[str] = (),
                 buckets: Iterable[float] = DEFAULT_BUCKETS):
        super().__init__(name, doc, labelnames)
        self.buckets = tuple(sorted(float(b) for b in buckets))
        self._data: dict[tuple[str, ...], tuple[list[int], float, int]] = {}

    def observe(self, value: float, **labels: str) -> None:
        key = self._key(labels)
        with self._lock:
            counts, total, n = self._data.get(key, ([0] * len(self.buckets), 0.0, 0))
            for i, b in enumerate(self.buckets):
                if value <= b:
                    counts[i] += 1
            self._data[key] = (counts, total + value, n + 1)

    def count(self, **labels: str) -> int:
        with self._lock:
            entry = self._data.get(self._key(labels))
            return entry[2] if entry else 0

    def render(self) -> list[str]:
        out = self.header()
        with self._lock:
            items = sorted((k, (list(c), s, n)) for k, (c, s, n) in self._data.items())
        for key, (counts, total, n) in items:
            for b, c in zip(self.buckets, counts, strict=True):
                out.append(f"{self.name}_bucket{_labels(self.labelnames, key, {'le': _fmt(b)})} {c}")
            out.append(f"{self.name}_bucket{_labels(self.labelnames, key, {'le': '+Inf'})} {n}")
            out.append(f"{self.name}_sum{_labels(self.labelnames, key)} {_fmt(total)}")
            out.append(f"{self.name}_count{_labels(self.labelnames, key)} {n}")
        return out


class Registry:
    def __init__(self) -> None:
        self._metrics: list[_Metric] = []

    def register(self, metric: _Metric) -> _Metric:
        if any(m.name == metric.name for m in self._metrics):
            raise ValueError(f"duplicate metric {metric.name}")
        self._metrics.append(metric)
        return metric

    def render(self) -> str:
        lines: list[str] = []
        for m in self._metrics:
            lines.extend(m.render())
        return "\n".join(lines) + "\n"


class ApiMetrics:
    """The metric set exported at ``/metrics`` (one instance per application)."""

    def __init__(self, version: str):
        self.registry = Registry()
        r = self.registry
        self.build_info = r.register(Gauge("aegis_build_info", "AEGIS build information", ["version"]))
        self.build_info.set(1, version=version)  # type: ignore[attr-defined]
        self.http_requests = r.register(Counter(
            "aegis_http_requests_total", "HTTP requests by route and status", ["method", "route", "status"]))
        self.http_latency = r.register(Histogram(
            "aegis_http_request_duration_seconds", "HTTP request latency", ["method", "route"]))
        self.auth_failures = r.register(Counter(
            "aegis_auth_failures_total", "Rejected authentications by reason", ["reason"]))
        self.forbidden = r.register(Counter(
            "aegis_rbac_denied_total", "Requests denied by RBAC", ["permission"]))
        self.rate_limited = r.register(Counter(
            "aegis_rate_limited_total", "Requests rejected by the rate limiter", ["scope"]))
        self.ingest_records = r.register(Counter(
            "aegis_ingest_records_total", "Ingested telemetry records by outcome", ["outcome"]))
        self.findings = r.register(Counter(
            "aegis_findings_total", "Findings produced by verdict", ["verdict"]))
        self.cases_opened = r.register(Counter("aegis_cases_opened_total", "Cases opened"))
        self.case_transitions = r.register(Counter(
            "aegis_case_transitions_total", "Case transitions by target state and outcome",
            ["to_state", "outcome"]))
        self.actions = r.register(Counter(
            "aegis_actions_total", "Enforcement workflow operations by step and outcome",
            ["step", "outcome"]))
        self.audit_failures = r.register(Counter(
            "aegis_audit_write_failures_total", "Audit records that could not be written"))
        self.ready = r.register(Gauge("aegis_ready", "1 when the service reports ready"))

    def render(self) -> str:
        return self.registry.render()


__all__ = ["ApiMetrics", "CONTENT_TYPE", "Counter", "Gauge", "Histogram", "Registry"]
