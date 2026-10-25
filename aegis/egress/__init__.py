"""EGRESS: outbound abuse detection on subscriber lines.

Detects lines taking part in DDoS floods, sending spoofed reflection requests, hosting an
abused amplifier, relaying residential-proxy traffic, sending spam or running credential
stuffing, from the operator's own flow telemetry. Deterministic, pre-registered rules; no
LLM, no payloads; abstains when counters are missing.

Public API::

    from aegis.egress import EgressConfig, EgressDetector, SpoofSignal, to_findings

    det = EgressDetector(EgressConfig(sampling_interval=1000), tenant_id=tenant,
                         context=DestinationContext(topology))      # context optional
    report = det.detect(events, start=window_start, end=window_end,
                        spoof_signals=urpf_counters)                  # EgressReport
    findings = to_findings(report, evidence_store=store)             # Finding objects, evidence persisted

See ``aegis/egress/INTEGRATION.md`` for wiring, evaluation and limitations.
"""
from aegis.egress.config import (
    ALL_LABELS,
    AMPLIFICATION_PORTS,
    EGRESS_VERSION,
    LABEL_AMPLIFICATION,
    LABEL_DDOS,
    LABEL_PROXY,
    LABEL_REFLECTOR,
    LABEL_SPAM,
    LABEL_STUFFING,
    EgressConfig,
)
from aegis.egress.detector import ALTERNATIVES, EgressDetector, HostingContext
from aegis.egress.findings import CAMPAIGN_ENTRY, INDEPENDENCE_GROUP, ORIGIN, SPOOF_INDEPENDENCE_GROUP, to_findings
from aegis.egress.models import Abstention, EgressCampaign, EgressReport, LineSignal, LineVerdict, SpoofSignal

__all__ = [
    "ALL_LABELS", "ALTERNATIVES", "AMPLIFICATION_PORTS", "Abstention", "CAMPAIGN_ENTRY", "EGRESS_VERSION",
    "EgressCampaign", "EgressConfig", "EgressDetector", "EgressReport", "HostingContext", "INDEPENDENCE_GROUP",
    "LABEL_AMPLIFICATION", "LABEL_DDOS", "LABEL_PROXY", "LABEL_REFLECTOR", "LABEL_SPAM", "LABEL_STUFFING",
    "LineSignal", "LineVerdict", "ORIGIN", "SPOOF_INDEPENDENCE_GROUP", "SpoofSignal", "to_findings",
]
