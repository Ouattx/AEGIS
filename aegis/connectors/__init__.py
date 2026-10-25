"""CONNECTORS: defensive exports of AEGIS results to operator systems.

Propose-only by default. Nothing here announces a route, changes a device or mitigates
traffic on its own:

* :mod:`~aegis.connectors.flowspec`: BGP FlowSpec rule *proposals* (RFC 8955 / 8956
  semantics, rate-limit by default) rendered for Junos, IOS XR and ExaBGP, each labelled as
  a proposal requiring operator review;
* :mod:`~aegis.connectors.ddos`: a generic DDoS-platform JSON notification
  (``aegis.ddos-export/1``) and :class:`MitigationRequestAdapter`, a MIRROR adapter that
  only runs through ``aegis.mirror.authorize`` + ``aegis.mirror.Executor`` (dry-run by
  default);
* :mod:`~aegis.connectors.siem`: CEF, LEEF 2.0 and JSON-lines batches of findings;
* :mod:`~aegis.connectors.stix`: validated STIX 2.1 bundles of analyst-verified campaigns
  and indicators, without pseudonyms or tenant data;
* :mod:`~aegis.connectors.common`: :class:`ExportPayload`, HMAC-signed
  :class:`ExportDelivery` (dry-run unless ``dry_run=False``) and ledger records.

See ``aegis/connectors/INTEGRATION.md``.
"""
from aegis.connectors.common import (
    EXPORT_ENTRY,
    PROPOSAL_NOTICE,
    DeliveryResult,
    ExportDelivery,
    ExportPayload,
    record_export,
    signature_headers,
    verify_export,
)
from aegis.connectors.ddos import MitigationRequestAdapter, ddos_export
from aegis.connectors.flowspec import (
    FlowSpecAction,
    FlowSpecConfig,
    FlowSpecMatch,
    FlowSpecPlan,
    FlowSpecProposal,
    SkippedProposal,
    flowspec_export,
    propose_flowspec,
    render,
)
from aegis.connectors.siem import siem_export, to_cef, to_leef
from aegis.connectors.stix import (
    VerifiedCampaign,
    VerifiedIndicator,
    build_bundle,
    from_egress_report,
    stix_export,
    validate_bundle,
)

__all__ = [
    "DeliveryResult", "EXPORT_ENTRY", "ExportDelivery", "ExportPayload", "FlowSpecAction", "FlowSpecConfig",
    "FlowSpecMatch", "FlowSpecPlan", "FlowSpecProposal", "MitigationRequestAdapter", "PROPOSAL_NOTICE",
    "SkippedProposal", "VerifiedCampaign", "VerifiedIndicator", "build_bundle", "ddos_export", "flowspec_export",
    "from_egress_report", "propose_flowspec", "record_export", "render", "siem_export", "signature_headers",
    "stix_export", "to_cef", "to_leef", "validate_bundle", "verify_export",
]
