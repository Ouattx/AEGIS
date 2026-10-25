"""User-provided usage windows: when the device under test was actively used.

A TV box that keeps contacting the same destination on a timer while nobody uses it
(screen off, standby, overnight) behaves differently from one whose heartbeats follow
viewing sessions. The lab owner can note when they used the device; the analysis then
compares behavior in *active* and *idle* periods. Without usage windows that comparison
is reported as unavailable (never guessed from the traffic itself).

Accepted formats
    JSON: ``{"active": [["2026-10-25T18:00:00Z", "2026-10-25T20:30:00Z"], ...],
             "idle": [[start, end], ...]}``  (``idle`` optional)
          or a list of ``{"start": ..., "end": ..., "state": "active" | "idle"}`` objects
    CSV:  header ``start,end,state`` (``state`` optional, default ``active``)

When ``idle`` is not given, idle = the capture span minus the active windows.
Timestamps must carry a timezone (``Z`` or an offset): ambiguous input is refused.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Sequence

import numpy as np

Span = tuple[float, float]   # epoch seconds [start, end)


class UsageWindowError(ValueError):
    """Usage windows are malformed (bad timestamp, end before start, unknown state)."""


def _ts(value: Any) -> float:
    if not isinstance(value, str):
        raise UsageWindowError(f"timestamp must be an ISO 8601 string, got {value!r}")
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise UsageWindowError(f"invalid timestamp {value!r}") from exc
    if dt.tzinfo is None:
        raise UsageWindowError(f"timestamp {value!r} has no timezone (add Z or an offset)")
    return dt.astimezone(timezone.utc).timestamp()


def _merge(spans: Iterable[Span]) -> list[Span]:
    out: list[Span] = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _clip(spans: Iterable[Span], lo: float, hi: float) -> list[Span]:
    return [(max(s, lo), min(e, hi)) for s, e in spans if min(e, hi) > max(s, lo)]


def _complement(spans: list[Span], lo: float, hi: float) -> list[Span]:
    out: list[Span] = []
    cur = lo
    for s, e in _merge(_clip(spans, lo, hi)):
        if s > cur:
            out.append((cur, s))
        cur = max(cur, e)
    if cur < hi:
        out.append((cur, hi))
    return out


@dataclass(frozen=True)
class UsageWindows:
    """Active / idle spans as given by the user (epoch seconds, merged, non-overlapping)."""
    active: tuple[Span, ...]
    idle: tuple[Span, ...] | None = None          # None = complement of active within the capture
    source_note: str = "user-provided"

    def __post_init__(self) -> None:
        for s, e in list(self.active) + list(self.idle or ()):
            if not e > s:
                raise UsageWindowError("every window needs end > start")
        if self.idle is not None:
            a = _merge(self.active)
            for s, e in _merge(self.idle):
                for s2, e2 in a:
                    if min(e, e2) > max(s, s2):
                        raise UsageWindowError("active and idle windows overlap")

    def resolved(self, start: float, end: float) -> "ResolvedUsage":
        """Clip to the capture span; idle defaults to the complement of active."""
        active = _merge(_clip(self.active, start, end))
        idle = _merge(_clip(self.idle, start, end)) if self.idle is not None else _complement(active, start, end)
        return ResolvedUsage(active=tuple(active), idle=tuple(idle), start=start, end=end,
                             idle_explicit=self.idle is not None)

    def to_dict(self) -> dict[str, Any]:
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).isoformat()  # noqa: E731
        return {"active": [[iso(s), iso(e)] for s, e in self.active],
                "idle": None if self.idle is None else [[iso(s), iso(e)] for s, e in self.idle],
                "source_note": self.source_note}


@dataclass(frozen=True)
class ResolvedUsage:
    active: tuple[Span, ...]
    idle: tuple[Span, ...]
    start: float
    end: float
    idle_explicit: bool = False

    @property
    def active_s(self) -> float:
        return float(sum(e - s for s, e in self.active))

    @property
    def idle_s(self) -> float:
        return float(sum(e - s for s, e in self.idle))

    def state_of(self, t: np.ndarray | Sequence[float]) -> np.ndarray:
        """Per timestamp: 1 = active, 0 = idle, -1 = neither (outside both window sets)."""
        t = np.asarray(t, dtype=np.float64)
        out = np.full(len(t), -1, dtype=np.int8)
        for spans, code in ((self.idle, 0), (self.active, 1)):
            for s, e in spans:
                out[(t >= s) & (t < e)] = code
        return out

    def hours(self, state: Literal["active", "idle"]) -> list[tuple[float, float]]:
        """Hour-aligned blocks (start, covered seconds) of one state, for hourly coverage measures."""
        spans = self.active if state == "active" else self.idle
        blocks: dict[float, float] = {}
        for s, e in spans:
            h = np.floor(s / 3600.0) * 3600.0
            while h < e:
                cov = min(e, h + 3600.0) - max(s, h)
                if cov > 0:
                    blocks[h] = blocks.get(h, 0.0) + cov
                h += 3600.0
        return sorted(blocks.items())


def load_usage_windows(src: str | Path | dict[str, Any] | list[Any]) -> UsageWindows:
    """Load usage windows from a JSON/CSV file path, JSON text, or an already parsed object."""
    obj: Any = src
    if isinstance(src, Path) or (isinstance(src, str) and "\n" not in src and Path(src).exists()):
        path = Path(src)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() == ".csv":
            return _from_csv(text)
        obj = json.loads(text)
    elif isinstance(src, str):
        stripped = src.lstrip()
        obj = json.loads(src) if stripped.startswith(("{", "[")) else None
        if obj is None:
            return _from_csv(src)
    return _from_obj(obj)


def _from_obj(obj: Any) -> UsageWindows:
    active: list[Span] = []
    idle: list[Span] | None = None
    if isinstance(obj, dict):
        for pair in obj.get("active") or []:
            active.append(_pair(pair))
        if obj.get("idle") is not None:
            idle = [_pair(p) for p in obj["idle"]]
    elif isinstance(obj, list):
        for row in obj:
            if not isinstance(row, dict):
                raise UsageWindowError("list entries must be objects with start/end/state")
            state = str(row.get("state", "active")).strip().lower()
            span = (_ts(row.get("start")), _ts(row.get("end")))
            if state == "active":
                active.append(span)
            elif state == "idle":
                idle = (idle or []) + [span]
            else:
                raise UsageWindowError(f"unknown state {state!r} (use active or idle)")
    else:
        raise UsageWindowError("usage windows must be a JSON object or list")
    return UsageWindows(active=tuple(_merge(active)), idle=None if idle is None else tuple(_merge(idle)))


def _pair(pair: Any) -> Span:
    if not isinstance(pair, (list, tuple)) or len(pair) != 2:
        raise UsageWindowError("each window must be a [start, end] pair")
    return _ts(pair[0]), _ts(pair[1])


def _from_csv(text: str) -> UsageWindows:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise UsageWindowError("usage CSV is empty (header start,end[,state] required)")
    objs = [{"start": r.get("start"), "end": r.get("end"), "state": (r.get("state") or "active")} for r in rows]
    return _from_obj(objs)


__all__ = ["ResolvedUsage", "UsageWindowError", "UsageWindows", "load_usage_windows"]
