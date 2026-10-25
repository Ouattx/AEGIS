"""Generic DDoS-protection-platform export and a MIRROR adapter for mitigation requests.

Two pieces, with different trust levels:

* :func:`ddos_export` builds a JSON *notification* (schema ``aegis.ddos-export/1``) of
  outbound attacks seen by EGRESS plus the FlowSpec proposals for them. Every document
  says ``status: proposed``, ``requires_operator_review: true`` and ``auto_apply: false``;
  a receiver must not mitigate from it automatically. It is a generic, documented format
  (see ``aegis/connectors/INTEGRATION.md`` for the field mapping), not any vendor's API.
* :class:`MitigationRequestAdapter` is an :class:`~aegis.mirror.base.EnforcementAdapter`:
  it asks a platform to rate-limit traffic from the operator's subscribers toward one
  victim address (``ActionType.IP_BLOCK`` targets). It only runs inside
  ``aegis.mirror.Executor`` after ``aegis.mirror.authorize`` allowed the action, and it is
  dry-run by default (records the signed request, sends nothing).
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any, Callable

import httpx

from aegis.connectors.common import (
    PROPOSAL_NOTICE,
    ExportDelivery,
    ExportPayload,
    product_version,
    signature_headers,
    utc,
    verify_export,
)
from aegis.connectors.flowspec import FlowSpecAction, FlowSpecMatch, FlowSpecPlan
from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import ActionType, ProposedAction
from aegis.egress.config import LABEL_AMPLIFICATION, LABEL_DDOS, LABEL_REFLECTOR
from aegis.egress.models import EgressReport
from aegis.mirror.base import (
    AdapterError,
    AdapterResult,
    EnforcementAdapter,
    RollbackRehearsal,
    action_summary,
    normalized_targets,
)

SCHEMA = "aegis.ddos-export/1"
REQUEST_SCHEMA = "aegis.mitigation-request/1"

_KIND = {"flood": "outbound_flood", "sync_burst": "outbound_flood", "spoofing": "spoofed_source",
         "amplification_request": "reflection_requests", "abused_reflector": "abused_reflector"}


def ddos_export(report: EgressReport, plan: FlowSpecPlan | None = None, *, now: datetime | None = None,
                include_suspicious: bool = True) -> ExportPayload:
    """JSON notification of outbound DDoS activity and its mitigation proposals.

    Line pseudonyms are included (the operator's own tenant-scoped identifiers, never a
    subscriber identity); targets are the external victim / reflector addresses.
    """
    now = utc(now) if now is not None else report.window_end
    if plan is not None and plan.tenant_id != report.tenant_id:
        raise ValueError("plan and report belong to different tenants")
    labels = (LABEL_DDOS, LABEL_AMPLIFICATION, LABEL_REFLECTOR)
    attacks: list[dict[str, Any]] = []
    for c in report.campaigns:
        if c.label in labels:
            attacks.append({
                "attack_id": c.campaign_id, "scope": "campaign", "kind": c.kind, "label": c.label,
                "lines_involved": c.n_lines, "line_pseudonyms": c.member_lines, "targets": c.targets[:200],
                "start": c.start.isoformat(), "end": c.end.isoformat(), "metrics": c.metrics,
                "explanation": c.explanation})
    for v in report.verdicts:
        if v.label not in labels or v.verdict == "abstain":
            continue
        if v.verdict == "suspicious" and not include_suspicious:
            continue
        sigs = [s for s in v.signals if s.kind != "spoofing"]
        protos = sorted({p for s in sigs for p in (s.metrics.get("protocols") or [])})
        ports = sorted({p for s in sigs for p in (s.metrics.get("dst_ports") or [])})
        attacks.append({
            "attack_id": f"{v.entity_pseudonym}:{v.label}", "scope": "line", "label": v.label,
            "kind": sorted({_KIND.get(s.kind, s.kind) for s in sigs}),
            "verdict": v.verdict, "score": v.score, "line_pseudonym": v.entity_pseudonym,
            "targets": sorted({t for s in sigs for t in s.targets})[:200], "protocols": protos, "dst_ports": ports,
            "peak_pps": max((float(s.metrics.get("peak_pps") or 0.0) for s in sigs), default=None),
            "spoofing_counters": any(s.kind == "spoofing" for s in v.signals),
            "campaign_ids": v.campaign_ids, "start": v.start.isoformat(), "end": v.end.isoformat(),
            "alternatives": v.alternatives})
    doc = {
        "schema": SCHEMA, "notice": PROPOSAL_NOTICE, "status": "proposed", "requires_operator_review": True,
        "auto_apply": False, "generator": {"product": "AEGIS OMEGA SHIELD", "version": product_version(),
                                           "detector_version": report.detector_version,
                                           "config_hash": report.config_hash},
        "tenant_id": report.tenant_id, "generated_at": now.isoformat(),
        "window": {"start": report.window_start.isoformat(), "end": report.window_end.isoformat(),
                   "status": report.status, "abstain_reason": report.abstain_reason},
        "attacks": attacks,
        "mitigation_proposals": [] if plan is None else [
            {"proposal_id": p.proposal_id, "name": p.name, "label": p.label, "verdict": p.verdict,
             "lines_involved": p.lines_involved, "campaign_ids": list(p.campaign_ids),
             "action": p.action.kind, "rate_bytes_per_s": p.action.rate_bytes_per_s,
             "suggested_expiry": p.suggested_expiry.isoformat(), "rationale": p.rationale,
             "caveats": list(p.caveats), "flowspec": p.rfc8955()} for p in plan.proposals],
        "not_proposed": [] if plan is None else [s.model_dump(mode="json") for s in plan.skipped],
    }
    body = canonical_bytes(doc).decode("utf-8")
    return ExportPayload.build("ddos.json", report.tenant_id, "application/json", body,
                               records=len(attacks), generated_at=now, proposal=True)


class MitigationRequestAdapter(EnforcementAdapter):
    """Signed rate-limit requests to a DDoS platform, executed only by ``aegis.mirror.Executor``.

    Each ``IP_BLOCK`` target (a victim address) becomes one FlowSpec-shaped rule per
    configured subscriber source prefix: destination = target /32 (/128), source =
    subscriber aggregate, action = rate limit at ``rate_bytes_per_s``. ``discard`` is only
    requested when the action's scope says ``{"mitigation": "discard"}`` (which the signed
    operator policy must approve) *and* the adapter was built with ``allow_discard=True``.

    ``dry_run=True`` (default): requests are built, signed and kept in :attr:`requests`;
    nothing is sent and the executor records a DRY_RUN execution.
    """

    name = "ddos_mitigation_request"
    supported_actions = frozenset({ActionType.IP_BLOCK})

    def __init__(self, url: str, secret: bytes, *, source_prefixes: tuple[str, ...], dry_run: bool = True,
                 rate_bytes_per_s: int = 1_250_000, allow_discard: bool = False,
                 client: httpx.Client | None = None, allow_insecure_http: bool = False,
                 max_attempts: int = 3, backoff_s: float = 0.5, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time):
        if not source_prefixes:
            raise ValueError("source_prefixes (the subscriber aggregates) are required")
        FlowSpecAction(rate_bytes_per_s=rate_bytes_per_s)  # validates the rate
        self.dry_run = dry_run
        self.source_prefixes = tuple(source_prefixes)
        self.rate_bytes_per_s = rate_bytes_per_s
        self.allow_discard = allow_discard
        self._secret = bytes(secret)
        self._clock = clock
        self._delivery = ExportDelivery(url, secret=secret, dry_run=dry_run, client=client,
                                        allow_insecure_http=allow_insecure_http, max_attempts=max_attempts,
                                        backoff_s=backoff_s, sleep=sleep, clock=clock)
        self.requests: list[dict[str, Any]] = []

    def __repr__(self) -> str:
        return f"MitigationRequestAdapter(delivery={self._delivery!r})"

    # ------------------------------------------------------------------ rules
    def rules(self, action: ProposedAction) -> list[dict[str, Any]]:
        """FlowSpec-shaped rules for ``action`` (raises on invalid targets or a refused discard)."""
        self.check_supported(action)
        targets = normalized_targets(action)
        mitigation = action.scope.get("mitigation", "rate_limit")
        if mitigation not in ("rate_limit", "discard"):
            raise AdapterError(f"unsupported mitigation {mitigation!r}")
        if mitigation == "discard" and not self.allow_discard:
            raise AdapterError("discard requested but this adapter only rate-limits (allow_discard=False)")
        act = (FlowSpecAction(kind="discard", rate_bytes_per_s=0) if mitigation == "discard"
               else FlowSpecAction(rate_bytes_per_s=self.rate_bytes_per_s))
        out: list[dict[str, Any]] = []
        for t in targets:
            v6 = ":" in t
            for src in self.source_prefixes:
                if (":" in src) != v6:
                    continue
                m = FlowSpecMatch(afi="ipv6" if v6 else "ipv4", destination=t, source=src)
                out.append({"match": m.model_dump(mode="json"), "action": act.model_dump(mode="json")})
        if not out:
            raise AdapterError("no subscriber source prefix of the target's address family")
        return out

    def _doc(self, op: str, action: ProposedAction, now: datetime, prior: dict[str, Any] | None) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "schema": REQUEST_SCHEMA, "event": f"aegis.mitigation.{op}", "tenant_id": action.tenant_id,
            "sent_at": utc(now).isoformat(), "action": action_summary(action),
            "expires_at": action.expires_at.isoformat() if action.expires_at else None,
            "rules": self.rules(action)}
        if prior is not None:
            doc["prior_state"] = prior
        return doc

    def _payload(self, op: str, action: ProposedAction, now: datetime,
                 prior: dict[str, Any] | None) -> ExportPayload:
        body = canonical_bytes(self._doc(op, action, now, prior)).decode("utf-8")
        return ExportPayload.build(f"mitigation.{op}", action.tenant_id, "application/json", body,
                                   records=len(action.targets), generated_at=now)

    def _send(self, op: str, action: ProposedAction, now: datetime,
              prior: dict[str, Any] | None) -> dict[str, Any]:
        payload = self._payload(op, action, now, prior)
        res = self._delivery.deliver(payload, actor=f"mirror:{self.name}")
        self.requests.append({"op": op, "action_id": action.action_id, "status": res.status,
                              "sha256": payload.sha256, "body": json.loads(payload.body), "headers": res.headers})
        if res.status == "failed":
            raise AdapterError(f"mitigation {op} failed: {res.error}")
        return {"delivery_id": res.delivery_id, "status": res.status, "sha256": payload.sha256}

    # ------------------------------------------------------------------ adapter interface
    def apply(self, action: ProposedAction, *, now: datetime) -> AdapterResult:
        info = self._send("apply", action, now, None)
        return AdapterResult(adapter=self.name, operation="apply", dry_run=self.dry_run,
                             prior_state={"apply_delivery_id": info["delivery_id"], "simulated": self.dry_run},
                             details=info)

    def revert(self, action: ProposedAction, prior_state: dict[str, Any], *, now: datetime) -> AdapterResult:
        info = self._send("withdraw", action, now, prior_state)
        return AdapterResult(adapter=self.name, operation="revert", dry_run=self.dry_run, details=info)

    def rehearse_rollback(self, action: ProposedAction, *, now: datetime) -> RollbackRehearsal:
        """Build and sign both the apply and the withdraw request locally (nothing is sent)."""
        checks: dict[str, bool] = {}
        try:
            ts = int(self._clock())
            for op in ("apply", "withdraw"):
                payload = self._payload(op, action, now, {"apply_delivery_id": "rehearsal"} if op == "withdraw"
                                        else None)
                headers = signature_headers(payload, self._secret, timestamp=ts)
                checks[f"{op}_request_signed"] = verify_export(payload.body_bytes, headers, self._secret, now=ts)
        except AdapterError as exc:
            return RollbackRehearsal(ok=False, method="mitigation_payload_rehearsal", detail=str(exc))
        ok = all(checks.values())
        return RollbackRehearsal(ok=ok, method="mitigation_payload_rehearsal", checks=checks,
                                 detail="apply and withdraw requests are well formed and signed; the platform must "
                                        "remove the rule on withdraw")


__all__ = ["MitigationRequestAdapter", "REQUEST_SCHEMA", "SCHEMA", "ddos_export"]
