"""RESONANCE: cross-subscriber harmonic resonance for low-and-slow C2 campaign detection.

Public API::

    from aegis.resonance import (ResonanceConfig, Resonance, ResonanceStream, DestinationContext,
                                 DestinationHistory, build_event_table, events_from_observations,
                                 to_findings, pair_periodicities)

    table = events_from_observations(events)                      # or build_event_table(flows_df, dns_df)
    det = Resonance(ResonanceConfig(q=0.01), context=DestinationContext(topology),
                    history=history, tenant_id=tenant)
    report = det.detect(table)                                    # ResonanceReport (campaigns, q-values, abstentions)
    findings = to_findings(report, evidence_store=store)          # per-line Finding objects, evidence persisted

See docs/RESONANCE.md for the method, guarantees and limitations.
"""
from aegis.resonance.config import FINDING_LABEL, RESONANCE_VERSION, ResonanceConfig
from aegis.resonance.detector import Resonance, campaign_id_for, pair_periodicities, weighted_bh
from aegis.resonance.events import EventTable, Vocab, build_event_table, events_from_observations
from aegis.resonance.findings import to_findings
from aegis.resonance.models import Abstention, Campaign, LineSupport, ResonanceReport, TestedUnit
from aegis.resonance.periodicity import PairPeriodicity, lomb_scargle_power, phase_rayleigh
from aegis.resonance.population import DestinationContext, DestinationHistory
from aegis.resonance.stream import ResonanceStream, StreamUpdate

__all__ = [
    "FINDING_LABEL", "RESONANCE_VERSION", "ResonanceConfig", "Resonance", "ResonanceStream", "StreamUpdate",
    "DestinationContext", "DestinationHistory", "EventTable", "Vocab", "build_event_table",
    "events_from_observations", "to_findings", "pair_periodicities", "campaign_id_for", "weighted_bh",
    "Campaign", "LineSupport", "ResonanceReport", "TestedUnit", "Abstention", "PairPeriodicity",
    "lomb_scargle_power", "phase_rayleigh",
]
