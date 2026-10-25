"""Input adapter for Box Farm lab captures (metadata only).

GENOME does not depend on any particular lab package API. A :class:`LabCapture` is a
small, explicit structure: one lab device, its observation window, flow and DNS
metadata frames, and lab bookkeeping (box model, firmware, family label when known).
Use :func:`capture_from_observations` to build one from canonical ObservationEvents.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

import pandas as pd

from aegis.contracts.models import ObservationEvent
from aegis.resonance.events import observations_to_frames


@dataclass
class LabCapture:
    capture_id: str
    box_model: str
    start: datetime
    end: datetime
    flows: pd.DataFrame                       # t, dst_ip, bytes, dur_s
    dns: pd.DataFrame                         # t, qname, answer_ip
    family: str | None = None                 # analyst label when known
    firmware: str | None = None
    licence: str = "operator-internal"
    active_periods: list[tuple[float, float]] = field(default_factory=list)   # epoch-s spans the box was in use
    lab_id: str = "boxfarm-lab"

    @property
    def span_s(self) -> float:
        return (self.end - self.start).total_seconds()

    def frames_with_line(self) -> tuple[pd.DataFrame, pd.DataFrame]:
        f = self.flows.copy()
        d = self.dns.copy()
        f["line"] = self.capture_id
        d["line"] = self.capture_id
        return f, d


def capture_from_observations(events: Iterable[ObservationEvent], *, capture_id: str, box_model: str,
                              start: datetime, end: datetime, family: str | None = None,
                              firmware: str | None = None, licence: str = "operator-internal") -> LabCapture:
    """Adapter from canonical events of one lab device (all events must share one pseudonym)."""
    evs = list(events)
    names = {e.entity_pseudonym for e in evs if e.entity_pseudonym}
    if len(names) > 1:
        raise ValueError("a lab capture must contain events of exactly one device")
    flows, dns = observations_to_frames(evs)
    return LabCapture(capture_id=capture_id, box_model=box_model, start=start, end=end,
                      flows=flows.drop(columns=["line"]), dns=dns.drop(columns=["line"]), family=family,
                      firmware=firmware, licence=licence)
