"""Copilot tools: strictly read-only, tenant-scoped, typed.

Each tool has a pydantic argument model (``extra="forbid"``: a ``tenant_id`` or any
unexpected field is rejected), a JSON schema advertised to the model, and a handler
that reads through :class:`~aegis.copilot.datasource.CopilotDataSource` with the
session's tenant. Handlers return :class:`ToolOutput`: JSON-able data plus the
``kind:id`` refs it exposed (the ids an answer may cite).

There is deliberately no write tool. ``simulate_action_readonly`` runs the MIRROR impact
simulation on an in-memory action: nothing is proposed, stored, authorized or executed.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import median
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aegis.contracts.models import (
    ActionType,
    Case,
    CaseState,
    Finding,
    LedgerEntry,
    ProposedAction,
)
from aegis.copilot.datasource import INGEST_ENTRY, CopilotDataSource, InvalidQuery
from aegis.oracle.tools import _MUTATING_NAME, sanitize_text

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_NODE = r"^[A-Za-z0-9][A-Za-z0-9._:/\-\[\]]{0,252}$"
MAX_LIST = 50


class ToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


@dataclass
class ToolOutput:
    data: dict[str, Any]
    refs: list[tuple[str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class ToolContext:
    tenant_id: str
    ds: CopilotDataSource
    now: datetime


class ToolNotFound(LookupError):
    """The requested id does not exist in this tenant (cross-tenant ids look the same)."""


@dataclass(frozen=True)
class CopilotTool:
    name: str
    description: str
    args_model: type[ToolArgs]
    handler: Callable[[ToolContext, Any], ToolOutput]
    permission: str = "read"          # aegis.api.rbac.Permission value the caller must hold

    def schema(self) -> dict[str, Any]:
        """Anthropic tool definition (``name``/``description``/``input_schema``)."""
        js = self.args_model.model_json_schema()
        defs = js.pop("$defs", {})
        props = {k: _simplify(v, defs) for k, v in js.get("properties", {}).items()}
        schema: dict[str, Any] = {"type": "object", "properties": props, "additionalProperties": False}
        if js.get("required"):
            schema["required"] = list(js["required"])
        return {"name": self.name, "description": self.description, "input_schema": schema}

    def parse(self, raw: Any) -> ToolArgs:
        if not isinstance(raw, dict):
            raise ValueError("tool input must be a JSON object")
        return self.args_model.model_validate(raw)


# ============================================================================ helpers


def _simplify(node: Any, defs: dict[str, Any]) -> Any:
    """Plain JSON schema for the model: ``$ref`` inlined, ``Optional[X]`` as ``X``, titles and null defaults dropped.

    Optionality is expressed by leaving the property out of ``required``; the pydantic model
    still validates every call.
    """
    if isinstance(node, list):
        return [_simplify(x, defs) for x in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        return _simplify(defs.get(node["$ref"].rsplit("/", 1)[-1], {}), defs)
    out = {k: _simplify(v, defs) for k, v in node.items() if k != "title"}
    any_of = out.get("anyOf")
    if isinstance(any_of, list):
        non_null = [x for x in any_of if x != {"type": "null"}]
        if len(non_null) == 1 and len(non_null) < len(any_of):
            out.pop("anyOf")
            out = {**non_null[0], **out}
    if out.get("default", 0) is None:
        out.pop("default")
    return out


def result_ref(prefix: str, data: Any) -> str:
    body = json.dumps(data, default=str, sort_keys=True, ensure_ascii=False)
    return f"{prefix}-{hashlib.sha256(body.encode()).hexdigest()[:12]}"


def _score_kind(calibration_id: str | None) -> str:
    return "calibrated probability" if calibration_id else "ranking score (not a probability)"


def finding_digest(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id, "label": f.label, "verdict": f.verdict.value, "score": round(f.score, 4),
        "score_kind": _score_kind(f.calibration_id), "status": f.status.value,
        "entity_pseudonym": f.entity_pseudonym, "requires_review": f.requires_review,
        "observed_window_end": f.observed_window_end, "detector_version": f.detector_version,
        "evidence_ids": f.evidence_ids[:10], "counterevidence_ids": f.counterevidence_ids[:10],
        "explanation": sanitize_text(f.explanation, 400),
    }


def _finding_refs(f: Finding) -> list[tuple[str, str]]:
    refs = [("finding", f.finding_id)]
    refs += [("evidence", e) for e in f.evidence_ids[:10]]
    refs += [("evidence", e) for e in f.counterevidence_ids[:10]]
    return refs


def case_digest(c: Case) -> dict[str, Any]:
    return {"case_id": c.case_id, "title": sanitize_text(c.title, 200), "state": c.state.value,
            "severity": c.severity, "finding_ids": c.finding_ids[:10], "evidence_count": len(c.evidence_ids),
            "counter_hypothesis_reviewed": c.counter_hypothesis_reviewed, "updated_at": c.updated_at}


def ledger_digest(e: LedgerEntry) -> dict[str, Any]:
    keys = sorted(e.payload)[:20]
    preview = {k: e.payload[k] for k in keys if isinstance(e.payload[k], (str, int, float, bool, type(None)))}
    return {"seq": e.seq, "entry_type": e.entry_type, "subject_id": e.subject_id, "recorded_at": e.recorded_at,
            "entry_hash": e.entry_hash[:16], "signed": e.signature is not None,
            "payload_keys": keys, "payload_preview": {k: (sanitize_text(v, 160) if isinstance(v, str) else v)
                                                       for k, v in preview.items()}}


# ============================================================================ argument models


class SearchFindingsArgs(ToolArgs):
    verdict: Literal["malicious", "suspicious", "benign", "abstain"] | None = None
    label: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")
    status: Literal["candidate", "triage", "verified", "rejected", "expired"] | None = None
    entity_pseudonym: str | None = Field(default=None, pattern=_ID)
    since_hours: float | None = Field(default=None, gt=0, le=24 * 365)
    limit: int = Field(default=10, ge=1, le=MAX_LIST)


class ListCasesArgs(ToolArgs):
    state: CaseState | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    limit: int = Field(default=10, ge=1, le=MAX_LIST)


class CaseIdArgs(ToolArgs):
    case_id: str = Field(pattern=_ID)


class FindingIdArgs(ToolArgs):
    finding_id: str = Field(pattern=_ID)


class EvidenceIdArgs(ToolArgs):
    evidence_id: str = Field(pattern=_ID)


class ListCampaignsArgs(ToolArgs):
    limit: int = Field(default=10, ge=1, le=MAX_LIST)


class GraphArgs(ToolArgs):
    node: str = Field(pattern=_NODE, description="graph node id (e.g. 'domain:x.example', 'ip:203.0.113.5') "
                                                 "or a bare domain / IP")
    limit: int = Field(default=20, ge=1, le=MAX_LIST)


class LedgerArgs(ToolArgs):
    subject_id: str | None = Field(default=None, pattern=_ID)
    entry_type: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")
    seq: int | None = Field(default=None, ge=1)
    limit: int = Field(default=10, ge=1, le=MAX_LIST)


class NoArgs(ToolArgs):
    pass


class IngestArgs(ToolArgs):
    batches: int = Field(default=60, ge=4, le=500)


class SimulateArgs(ToolArgs):
    action_id: str | None = Field(default=None, pattern=_ID)
    case_id: str | None = Field(default=None, pattern=_ID)
    action_type: Literal["dns_sinkhole", "ip_block", "device_quarantine", "notify_subscriber"] | None = None
    targets: list[str] | None = Field(default=None, max_length=20)

    @field_validator("targets")
    @classmethod
    def _targets(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        out = [t.strip() for t in v if isinstance(t, str) and t.strip()]
        if any(len(t) > 253 for t in out):
            raise ValueError("target too long")
        return out


# ============================================================================ handlers


def _search_findings(ctx: ToolContext, a: SearchFindingsArgs) -> ToolOutput:
    since = ctx.now - timedelta(hours=a.since_hours) if a.since_hours else None
    items, total = ctx.ds.find_findings(ctx.tenant_id, verdict=a.verdict, label=a.label, status=a.status,
                                        entity=a.entity_pseudonym, since=since, limit=a.limit)
    data: dict[str, Any] = {"filters": a.model_dump(mode="json", exclude_none=True), "total_matching": total,
                            "returned": len(items), "findings": [finding_digest(f) for f in items]}
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)]
    for f in items:
        refs += _finding_refs(f)
    return ToolOutput(data, refs)


def _list_cases(ctx: ToolContext, a: ListCasesArgs) -> ToolOutput:
    items, total = ctx.ds.find_cases(ctx.tenant_id, state=a.state.value if a.state else None, severity=a.severity, limit=a.limit)
    data: dict[str, Any] = {"filters": a.model_dump(mode="json", exclude_none=True), "total_matching": total,
                            "returned": len(items), "cases": [case_digest(c) for c in items]}
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)] + [("case", c.case_id) for c in items]
    return ToolOutput(data, refs)


def _get_case(ctx: ToolContext, a: CaseIdArgs) -> ToolOutput:
    d = ctx.ds.get_case_detail(ctx.tenant_id, a.case_id)
    if d is None:
        raise ToolNotFound("case not found in this tenant")
    c: Case = d["case"]
    findings: list[Finding] = list(d.get("findings") or [])
    actions: list[ProposedAction] = list(d.get("actions") or [])
    data: dict[str, Any] = {
        **case_digest(c),
        "hypothesis": sanitize_text(c.hypothesis, 400),
        "alternative_hypotheses": [sanitize_text(h, 200) for h in c.alternative_hypotheses[:8]],
        "evidence_ids": c.evidence_ids[:25], "reviewer": c.reviewer,
        "decisions": [{"from": x.from_state.value, "to": x.to_state.value, "actor": x.actor,
                       "reason": sanitize_text(x.reason, 200), "at": x.at} for x in c.decisions[-10:]],
        "findings": [finding_digest(f) for f in findings[:10]],
        "evidence_assessment": d.get("evidence_assessment"),
        "allowed_transitions": d.get("allowed_transitions"),
        "actions": [{"action_id": x.action_id, "action_type": x.action_type.value, "targets": x.targets[:10],
                     "created_by": x.created_by, "created_at": x.created_at} for x in actions[:10]],
        "investigation": d.get("investigation"),
    }
    refs: list[tuple[str, str]] = [("case", c.case_id)]
    refs += [("evidence", e) for e in c.evidence_ids[:25]]
    for f in findings[:10]:
        refs += _finding_refs(f)
    refs += [("action", x.action_id) for x in actions[:10]]
    return ToolOutput(data, refs)


def _get_finding(ctx: ToolContext, a: FindingIdArgs) -> ToolOutput:
    f = ctx.ds.get_finding(ctx.tenant_id, a.finding_id)
    if f is None:
        raise ToolNotFound("finding not found in this tenant")
    data = {**finding_digest(f), "component_scores": f.component_scores, "calibration_id": f.calibration_id,
            "observed_window_start": f.observed_window_start, "expires_at": f.expires_at}
    return ToolOutput(json.loads(json.dumps(data, default=str)), _finding_refs(f))


def _get_evidence(ctx: ToolContext, a: EvidenceIdArgs) -> ToolOutput:
    d = ctx.ds.get_evidence(ctx.tenant_id, a.evidence_id)
    if d is None:
        raise ToolNotFound("evidence not found in this tenant")
    ev = d["evidence"]
    payload_keys = sorted(ev.payload)[:30]
    data = {"evidence_id": ev.evidence_id, "kind": ev.kind.value, "origin_source": ev.origin_source,
            "source_independence_group": ev.source_independence_group, "collected_at": ev.collected_at,
            "supports": ev.supports, "summary": sanitize_text(ev.summary, 400), "sha256": ev.sha256,
            "integrity_verified": bool(d.get("integrity_verified")), "superseded_by": d.get("superseded_by"),
            "payload_keys": payload_keys,
            "payload": {k: ev.payload[k] for k in payload_keys}}
    refs = [("evidence", ev.evidence_id)]
    if isinstance(d.get("superseded_by"), str):
        refs.append(("evidence", d["superseded_by"]))
    return ToolOutput(data, refs)


def _list_campaigns(ctx: ToolContext, a: ListCampaignsArgs) -> ToolOutput:
    rows = ctx.ds.list_campaigns(ctx.tenant_id, limit=a.limit)
    for r in rows:
        if isinstance(r.get("explanation"), str):
            r["explanation"] = sanitize_text(r["explanation"], 400)
    data: dict[str, Any] = {
        "returned": len(rows), "campaigns": rows,
        "interpretation": ("q-values certify that unrelated lines share a timer toward the destination; they do "
                           "not establish maliciousness. RESONANCE findings require analyst review and its "
                           "evidence is not independent of SENTINEL (same operator telemetry)."),
    }
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)]
    for r in rows:
        refs.append(("campaign", r["campaign_id"]))
        refs.append(("ledger", str(r["ledger_seq"])))
        if r.get("evidence_id"):
            refs.append(("evidence", r["evidence_id"]))
        refs += [("evidence", e) for e in r.get("counterevidence_ids", [])]
    return ToolOutput(data, refs)


def _graph_neighbors(ctx: ToolContext, a: GraphArgs) -> ToolOutput:
    g = ctx.ds.graph(ctx.tenant_id, a.node)
    if g is None:
        raise ToolNotFound("node not found in this tenant's graph")
    node = g["node"]
    neigh = list(g.get("neighbors") or [])[:a.limit]
    data: dict[str, Any] = {
        "node_id": node.node_id, "node_type": node.node_type.value, "first_seen": node.first_seen,
        "last_seen": node.last_seen, "shared_hosting": bool(g.get("shared_hosting")),
        "degree": g.get("degree"), "truncated": bool(g.get("truncated")) or len(g.get("neighbors") or []) > a.limit,
        "neighbors": [{"node_id": n.node_id, "direction": n.direction, "edge_type": n.edge.edge_type.value,
                       "evidence_grade": n.edge.evidence_grade.value, "active": n.edge.active,
                       "independent_sources": n.edge.independent_source_count,
                       "enforcement_eligible": n.edge.enforcement_eligible,
                       "last_seen": n.edge.last_seen} for n in neigh],
        "candidate_links_note": "candidate links are investigative only and never enforcement-eligible",
        "candidate_links": len(g.get("candidate_links") or []),
    }
    refs = [("node", node.node_id)] + [("node", n.node_id) for n in neigh]
    return ToolOutput(data, refs)


def _ledger_query(ctx: ToolContext, a: LedgerArgs) -> ToolOutput:
    if a.seq is not None:
        e = ctx.ds.ledger_entry(ctx.tenant_id, a.seq)
        entries = [e] if e is not None else []
    else:
        entries = ctx.ds.ledger_entries(ctx.tenant_id, subject_id=a.subject_id, entry_type=a.entry_type,
                                        limit=a.limit)
    data: dict[str, Any] = {"filters": a.model_dump(exclude_none=True),
                            "returned": len(entries), "entries": [ledger_digest(e) for e in entries]}
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)] + [("ledger", str(e.seq)) for e in entries]
    return ToolOutput(data, refs)


def _verify_ledger(ctx: ToolContext, a: NoArgs) -> ToolOutput:
    v = ctx.ds.verify_ledger(ctx.tenant_id)
    data: dict[str, Any] = {k: v.get(k) for k in ("ok", "first_bad_seq", "reason", "entries_checked",
                                                 "signed_entries", "entry_count") if k in v}
    data = json.loads(json.dumps(data, default=str))
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)]
    if isinstance(data.get("first_bad_seq"), int):
        refs.append(("ledger", str(data["first_bad_seq"])))
    return ToolOutput(data, refs)


def _metrics_summary(ctx: ToolContext, a: NoArgs) -> ToolOutput:
    m = ctx.ds.metrics(ctx.tenant_id)
    data = json.loads(json.dumps(m, default=str))
    ref = result_ref("m", data)
    data["result_ref"] = f"metrics:{ref}"
    return ToolOutput(data, [("metrics", ref)])


def _health_status(ctx: ToolContext, a: NoArgs) -> ToolOutput:
    h = ctx.ds.health(ctx.tenant_id)
    data = json.loads(json.dumps(h, default=str))
    ref = result_ref("h", data)
    data["result_ref"] = f"health:{ref}"
    return ToolOutput(data, [("health", ref)])


def _ratio(num: float, den: float) -> float | None:
    return None if den <= 0 else num / den


def analyze_ingest(entries: list[LedgerEntry]) -> dict[str, Any]:
    """Compare the recent half of ``ingest_batch`` ledger entries with the earlier half.

    Derived only from what the ledger records per batch (records read, accepted,
    quarantined, duplicates, event-time range, recorded time). AEGIS does not record
    per-batch processing duration in the ledger, so "slowness" is inferred from
    observation-to-record lag, batch cadence and batch volume, and said so.
    """
    rows = sorted(entries, key=lambda e: e.seq)
    batches: list[dict[str, Any]] = []
    for e in rows:
        p = e.payload
        srcs = [s for s in p.get("sources") or [] if isinstance(s, dict)]
        read = sum(int(s.get("records_read") or 0) for s in srcs)
        quarantined = sum(int(s.get("quarantined") or 0) for s in srcs)
        dups = sum(int(s.get("duplicates") or 0) for s in srcs)
        elapsed = [float(s["elapsed_s"]) for s in srcs if isinstance(s.get("elapsed_s"), (int, float))]
        last_ev = _parse_dt(p.get("last_event_at"))
        lag = (e.recorded_at - last_ev).total_seconds() if last_ev is not None else None
        batches.append({"seq": e.seq, "recorded_at": e.recorded_at, "events": int(p.get("events") or 0),
                        "records_read": read, "quarantined": quarantined, "duplicates": dups,
                        "elapsed_s": sum(elapsed) if elapsed else None, "lag_s": lag})
    out: dict[str, Any] = {"batches_analyzed": len(batches),
                           "method": ("recent half vs earlier half of ingest_batch ledger entries; per-batch "
                                      "processing time is not recorded in the ledger, so lag (record time minus "
                                      "last observed event) and cadence are used as proxies")}
    if len(batches) < 4:
        out["status"] = "insufficient_history"
        out["observations"] = []
        out["batch_seqs"] = [b["seq"] for b in batches]
        return out
    half = len(batches) // 2
    base, recent = batches[:half], batches[half:]

    def stats(bs: list[dict[str, Any]]) -> dict[str, Any]:
        read = sum(b["records_read"] for b in bs)
        lags = [b["lag_s"] for b in bs if b["lag_s"] is not None]
        el = [b["elapsed_s"] for b in bs if b["elapsed_s"] is not None]
        gaps = [(bs[i]["recorded_at"] - bs[i - 1]["recorded_at"]).total_seconds() for i in range(1, len(bs))]
        return {"batches": len(bs), "first_seq": bs[0]["seq"], "last_seq": bs[-1]["seq"],
                "records_per_batch": read / len(bs), "events_per_batch": sum(b["events"] for b in bs) / len(bs),
                "quarantine_rate": _ratio(sum(b["quarantined"] for b in bs), read),
                "duplicate_rate": _ratio(sum(b["duplicates"] for b in bs), read),
                "median_lag_s": median(lags) if lags else None,
                "median_gap_s": median(gaps) if gaps else None,
                "median_elapsed_s": median(el) if el else None}

    b, r = stats(base), stats(recent)
    obs: list[dict[str, Any]] = []
    recent_seqs = [x["seq"] for x in recent]

    def worse(key: str, factor: float, floor: float, code: str, text: str) -> None:
        bv, rv = b.get(key), r.get(key)
        if bv is None or rv is None:
            return
        if rv > max(bv * factor, bv + floor):
            obs.append({"code": code, "baseline": bv, "recent": rv, "detail": text,
                        "evidence_seqs": [b["last_seq"], r["last_seq"]]})

    worse("median_elapsed_s", 1.5, 1.0, "processing_time_up", "per-batch processing time increased")
    worse("median_lag_s", 1.5, 60.0, "lag_up", "delay between observed events and ledger recording increased")
    worse("median_gap_s", 1.5, 60.0, "cadence_down", "batches arrive less often")
    worse("records_per_batch", 1.5, 100.0, "volume_up", "more records per batch (larger batches take longer)")
    worse("quarantine_rate", 2.0, 0.02, "quarantine_up", "more records are quarantined as invalid")
    worse("duplicate_rate", 2.0, 0.02, "duplicates_up", "more duplicate records are re-sent by collectors")
    out.update({"status": "ok", "baseline": b, "recent": r, "observations": obs,
                "recent_batch_seqs": recent_seqs[-10:]})
    return out


def _parse_dt(v: Any) -> datetime | None:
    if isinstance(v, datetime):
        return v
    if isinstance(v, str):
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _ingest_activity(ctx: ToolContext, a: IngestArgs) -> ToolOutput:
    entries = ctx.ds.ledger_entries(ctx.tenant_id, entry_type=INGEST_ENTRY, limit=a.batches)
    data = json.loads(json.dumps(analyze_ingest(entries), default=str))
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref)] + [("ledger", str(e.seq)) for e in entries]
    return ToolOutput(data, refs)


def _simulate(ctx: ToolContext, a: SimulateArgs) -> ToolOutput:
    if a.action_id:
        existing = ctx.ds.get_action(ctx.tenant_id, a.action_id)
        if existing is None:
            raise ToolNotFound("action not found in this tenant")
        action = existing
        hypothetical = False
    else:
        if not (a.case_id and a.action_type and a.targets):
            raise InvalidQuery("give action_id, or case_id + action_type + targets")
        if ctx.ds.get_case_detail(ctx.tenant_id, a.case_id) is None:
            raise ToolNotFound("case not found in this tenant")
        action = ProposedAction(tenant_id=ctx.tenant_id, case_id=a.case_id, action_type=ActionType(a.action_type),
                                targets=list(a.targets), created_by="copilot:readonly-simulation",
                                created_at=ctx.now)
        hypothetical = True
    res = ctx.ds.simulate(ctx.tenant_id, action)
    data = {"simulation_only": True,
            "note": "read-only impact simulation: nothing was proposed, stored, authorized or executed",
            "hypothetical": hypothetical, "action_id": action.action_id if not hypothetical else None,
            "case_id": action.case_id, "action_type": action.action_type.value, "targets": action.targets,
            "verdict": res.verdict.value, "affected_entities": res.affected_entities,
            "legitimate_cotenants": res.legitimate_cotenants[:20], "shared_infrastructure": res.shared_infrastructure,
            "historic_daily_legit_flows": res.historic_daily_legit_flows, "reversibility": res.reversibility,
            "unknowns": res.unknowns[:20], "requires_human_approval": res.requires_human_approval,
            "rationale": sanitize_text(res.rationale, 600)}
    data = json.loads(json.dumps(data, default=str))
    ref = result_ref("q", data)
    data["result_ref"] = f"query:{ref}"
    refs: list[tuple[str, str]] = [("query", ref), ("case", action.case_id)]
    if not hypothetical:
        refs.append(("action", action.action_id))
    return ToolOutput(data, refs)


# ============================================================================ registry


def _t(name: str, desc: str, model: type[ToolArgs], fn: Callable[[ToolContext, Any], ToolOutput],
       permission: str = "read") -> CopilotTool:
    if _MUTATING_NAME.search(name):
        raise ValueError(f"tool name {name!r} looks mutating; copilot tools are read-only")
    return CopilotTool(name, desc, model, fn, permission)


DEFAULT_TOOLS: tuple[CopilotTool, ...] = (
    _t("search_findings", "Search this tenant's detection findings (newest first) by verdict, label, status, "
       "device pseudonym or recency. Returns finding ids, evidence ids and a query result_ref.",
       SearchFindingsArgs, _search_findings),
    _t("get_finding", "One finding in full: label, verdict, score and whether it is calibrated, component "
       "scores, evidence and counter-evidence ids, explanation.", FindingIdArgs, _get_finding),
    _t("list_cases", "List this tenant's cases (most recently updated first), optionally by state or severity.",
       ListCasesArgs, _list_cases),
    _t("get_case", "Full detail of one case: state, hypothesis and alternatives, findings, evidence ids, "
       "evidence assessment (independent origins, verification blockers), decisions, proposed actions.",
       CaseIdArgs, _get_case),
    _t("get_evidence", "One evidence record: kind, origin, independence group, summary, integrity check, payload.",
       EvidenceIdArgs, _get_evidence),
    _t("list_campaigns", "RESONANCE cross-subscriber C2 campaigns recorded in this tenant's ledger "
       "(destinations, lines, period, p/q values, enforcement eligibility).", ListCampaignsArgs, _list_campaigns),
    _t("graph_neighbors", "CONSTELLATION infrastructure graph: a node and its current neighbors with edge type, "
       "evidence grade and enforcement eligibility.", GraphArgs, _graph_neighbors),
    _t("verify_ledger", "Verify the tenant's provenance ledger hash chain and signatures.", NoArgs, _verify_ledger),
    _t("ledger_query", "Read raw provenance ledger entries (newest first) by subject id, entry type or sequence "
       "number. Available to audit-privileged users only.", LedgerArgs, _ledger_query, "read_audit"),
    _t("metrics_summary", "Tenant metrics: findings by verdict/label, cases by state, actions, coverage, "
       "ingest quarantine, detector/model/IOC/topology status. Returns a metrics result_ref.", NoArgs,
       _metrics_summary),
    _t("ingest_activity", "Ingestion trend analysis from the ledger: recent vs earlier batches (lag, cadence, "
       "volume, quarantine and duplicate rates). Use for 'why did ingestion slow down' questions.", IngestArgs,
       _ingest_activity),
    _t("health_status", "Platform health: database, model, LLM, enforcement adapter, circuit breaker, plus this "
       "tenant's sources, IOC bundle, topology, quarantine and bus backlog. Returns a health result_ref.",
       NoArgs, _health_status),
    _t("simulate_action_readonly", "MIRROR impact simulation WITHOUT execution, for an existing action_id or a "
       "hypothetical action (case_id + action_type + targets). Nothing is proposed, stored or executed.",
       SimulateArgs, _simulate),
)


def tool_map(tools: tuple[CopilotTool, ...] = DEFAULT_TOOLS) -> dict[str, CopilotTool]:
    return {t.name: t for t in tools}


def validation_message(exc: ValidationError) -> str:
    """Short, data-free description of argument errors (field names and error types only)."""
    parts = []
    for err in exc.errors()[:5]:
        loc = ".".join(str(x) for x in err.get("loc", ())) or "input"
        parts.append(f"{re.sub(r'[^A-Za-z0-9_.]', '_', loc)[:40]}: {err.get('type', 'invalid')}")
    return "invalid arguments (" + "; ".join(parts) + ")"


__all__ = ["CopilotTool", "DEFAULT_TOOLS", "ToolArgs", "ToolContext", "ToolNotFound", "ToolOutput",
           "analyze_ingest", "finding_digest", "result_ref", "tool_map", "validation_message"]
