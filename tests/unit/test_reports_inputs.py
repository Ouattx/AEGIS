from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from aegis.contracts.models import FlowObservation, ObservationEvent, SourceKind, Vantage
from aegis.reports.inputs import AnalystEffortModel, CostInputs, CoverageAccumulator, CoverageStats, ReportPeriod

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ev(entity: str | None, t: datetime, klass: str = "phone", source: str = "nf") -> ObservationEvent:
    return ObservationEvent(tenant_id="t", observed_at=t, ingested_at=t, source_id=source,
                            source_kind=SourceKind.NETFLOW, vantage=Vantage.DEVICE, collection_authorization_id="a",
                            entity_pseudonym=entity, device_class=klass, flow=FlowObservation(dst_ip="192.0.2.1"),
                            retention_until=t + timedelta(days=30), integrity_sha256="0" * 64)


def test_period_validation_and_dates():
    p = ReportPeriod(T0, T0 + timedelta(days=2, hours=1))
    assert p.days == pytest.approx(2 + 1 / 24)
    assert p.dates() == [date(2026, 10, 1), date(2026, 10, 2), date(2026, 10, 3)]
    assert p.contains(T0) and not p.contains(T0 + timedelta(days=3))
    assert ReportPeriod(T0, T0 + timedelta(days=1)).dates() == [date(2026, 10, 1)]
    with pytest.raises(ValueError):
        ReportPeriod(T0, T0)
    with pytest.raises(ValueError):
        ReportPeriod(datetime(2026, 10, 1), datetime(2026, 10, 2))
    assert ReportPeriod.coerce((T0, T0 + timedelta(days=1))).end == T0 + timedelta(days=1)


def test_period_normalizes_to_utc():
    cet = timezone(timedelta(hours=2))
    p = ReportPeriod(datetime(2026, 10, 1, 2, tzinfo=cet), datetime(2026, 10, 2, 2, tzinfo=cet))
    assert p.start == T0 and p.start.tzinfo == timezone.utc


def test_coverage_accumulator_counts_device_days_and_classes():
    acc = CoverageAccumulator()
    acc.add(ev("a", T0 + timedelta(hours=1), "phone"))
    acc.add(ev("a", T0 + timedelta(hours=2), "phone"))
    acc.add(ev("a", T0 + timedelta(days=1, hours=1), "laptop", source="dns"))
    acc.add(ev("a", T0 + timedelta(days=1, hours=2), "phone"))
    acc.add(ev("b", T0 + timedelta(hours=3), "android_tv"))
    acc.add(ev(None, T0 + timedelta(hours=4)))
    c = acc.result()
    assert c.devices_observed == 2 and c.device_days == 3 and c.events == 6
    assert c.devices_by_class == {"android_tv": 1, "phone": 1}
    assert c.device_days_by_class == {"android_tv": 1, "phone": 2}
    assert c.sources == ("dns", "nf")
    assert c.first_event_at == T0 + timedelta(hours=1)
    assert c.last_event_at == T0 + timedelta(days=1, hours=2)


def test_coverage_from_events_respects_period_and_roundtrips():
    events = [ev("a", T0 + timedelta(hours=1)), ev("b", T0 + timedelta(days=5))]
    c = CoverageStats.from_events(events, ReportPeriod(T0, T0 + timedelta(days=1)))
    assert c.devices_observed == 1
    again = CoverageStats.from_dict(c.to_dict())
    assert again == c


def test_coverage_validation():
    with pytest.raises(ValueError):
        CoverageStats(devices_observed=-1, device_days=0)
    with pytest.raises(ValueError):
        CoverageStats(devices_observed=5, device_days=4)


def test_cost_inputs_validation_and_parsing():
    c = CostInputs.from_dict({"currency": "EUR", "license_monthly": 10})
    assert c.configured and c.currency == "EUR"
    assert not CostInputs().configured
    with pytest.raises(ValueError):
        CostInputs(analyst_hourly_rate=-1)
    with pytest.raises(ValueError):
        CostInputs.from_dict({"bogus": 1})
    with pytest.raises(ValueError):
        CostInputs(currency="")
    with pytest.raises(ValueError):
        CostInputs(monitored_devices=-3)


def test_effort_model():
    m = AnalystEffortModel()
    base = m.estimate(evidence_items=0, investigated=False, counter_reviewed=False, dispositioned=False)
    assert base == m.triage_minutes
    capped = m.estimate(evidence_items=500, investigated=True, counter_reviewed=True, dispositioned=True)
    assert capped == pytest.approx(4 + 20 * 0.5 + 12 + 5 + 2)
    assert AnalystEffortModel.from_dict({"triage_minutes": 1}).triage_minutes == 1
    with pytest.raises(ValueError):
        AnalystEffortModel(triage_minutes=-1)
    with pytest.raises(ValueError):
        AnalystEffortModel.from_dict({"nope": 1})
