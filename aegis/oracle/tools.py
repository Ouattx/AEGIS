"""Typed, read-only investigation tools and append-only agent write scopes (spec section 6).

Security model
--------------
* Every tool is a :class:`ReadTool`. :class:`Toolset` refuses anything else and
  refuses names that look like mutations, so no registered tool can modify
  policies, models or enforcement state. Tool functions receive the case and
  validated arguments and return JSON-serializable data.
* Each agent gets an :class:`AgentScope` containing only its own tools and its
  own append-only writer (evidence collector -> evidence; alternative
  hypothesis -> counterarguments; threat correlation -> candidate edges; policy
  checker -> advisory; verifier -> recommendation; response planner -> draft
  proposal). Writers expose no update or delete method.
* Tool output is untrusted. :func:`wrap_untrusted` serializes it as escaped JSON
  inside a delimited data block that is placed in the *user* turn of an LLM
  request, never in the system instructions, and :func:`scan_for_injection`
  flags instruction-like content for the analyst.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Iterable, Literal, Protocol, runtime_checkable

from aegis.contracts.models import (
    Case,
    Evidence,
    EvidenceKind,
    Finding,
    MirrorResult,
    OperatorPolicy,
    ProposedAction,
)
from aegis.oracle.state_machine import AGENT_APPENDED_KEY
from aegis.provenance.evidence import EvidenceIntegrityError, EvidenceStore
from aegis.provenance.ledger import EntryType, Ledger
from aegis.provenance.signing import KeyRing, verify_model
from aegis.storage.db import DocStore


class AgentName(str, Enum):
    EVIDENCE_COLLECTOR = "evidence_collector"
    ALTERNATIVE_HYPOTHESIS = "alternative_hypothesis"
    THREAT_CORRELATION = "threat_correlation"
    POLICY_CHECKER = "policy_checker"
    VERIFIER = "verifier"
    RESPONSE_PLANNER = "response_planner"

    @property
    def actor(self) -> str:
        return f"agent:{self.value}"


class ToolError(RuntimeError):
    """A tool failed; the workflow may retry it."""


class ScopeViolation(PermissionError):
    """An agent tried to act outside its declared tools or write scope."""


_MUTATING_NAME = re.compile(
    r"(^|_)(update|delete|remove|write|modify|set|put|create|approve|deny|execute|enforce|"
    r"block|sinkhole|quarantine|rollback|promote|train|deploy|sign|grant|revoke|disable|"
    r"enable|activate|transition)(_|$)")

MAX_TOOL_OUTPUT_CHARS = 20_000


# ----------------------------------------------------------------------------- untrusted data

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.IGNORECASE)) for name, rx in (
        ("ignore_instructions", r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier)\b"
                                r".{0,40}\b(instruction|prompt|rule|direction)s?"),
        ("role_override", r"\b(you are now|act as|new instructions|system prompt|developer mode)\b"),
        ("fake_role_tag", r"(^|\n)\s*(system|assistant|developer)\s*:"),
        ("tag_escape", r"</?\s*(untrusted_data|system|instructions?)\b"),
        ("policy_tamper", r"\b(set|change|switch|update)\b.{0,30}\b(policy|mode|enforcement)\b.{0,30}"
                          r"\b(active|disable|off|on)\b"),
        ("action_request", r"\b(approve|execute|block|sinkhole|quarantine|whitelist|allowlist)\b.{0,40}"
                           r"\b(immediately|now|this case|all)\b"),
        ("verdict_coercion", r"\b(mark|classify|label|declare)\b.{0,30}\b(benign|safe|verified|malicious|"
                             r"false positive)\b"),
    ))


def scan_for_injection(data: Any) -> list[str]:
    """Names of instruction-like patterns found anywhere in ``data`` (strings, nested)."""
    found: set[str] = set()
    for text in _strings(data):
        found.update(name for name, rx in _INJECTION_PATTERNS if rx.search(text))
    return sorted(found)


def _strings(data: Any, depth: int = 0) -> Iterable[str]:
    if depth > 20:
        return
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for k, v in data.items():
            yield str(k)
            yield from _strings(v, depth + 1)
    elif isinstance(data, (list, tuple, set)):
        for v in data:
            yield from _strings(v, depth + 1)


def _escape_json(text: str) -> str:
    # valid JSON escapes that make it impossible to close or open a delimiter tag
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def wrap_untrusted(source: str, data: Any) -> str:
    """Serialize tool output as an inert, escaped data block.

    The block contains only JSON with ``<``/``>``/``&`` escaped, so content can
    never terminate the block or impersonate instructions; the source label is
    restricted to ``[A-Za-z0-9_.:-]``.
    """
    label = re.sub(r"[^A-Za-z0-9_.:-]", "_", source)[:64] or "tool"
    body = json.dumps(data, default=str, ensure_ascii=False, sort_keys=True)
    if len(body) > MAX_TOOL_OUTPUT_CHARS:
        body = json.dumps({"truncated": True, "prefix": body[:MAX_TOOL_OUTPUT_CHARS]},
                          ensure_ascii=False)
    return f'<untrusted_data source="{label}">\n{_escape_json(body)}\n</untrusted_data>'


def sanitize_text(value: Any, max_len: int = 1000) -> str:
    """Plain single-paragraph text: control chars removed, whitespace collapsed, capped."""
    if not isinstance(value, str):
        return ""
    cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]


def clip_text(value: Any, max_len: int = 160) -> str:
    """Sanitized text shortened at a word boundary with an ellipsis, never mid-token.

    A parenthesis or bracket left open by the cut is dropped together with its
    partial contents, so evidence summaries never read as truncated identifiers.
    """
    text = sanitize_text(value, 100_000)
    if len(text) <= max_len:
        return text
    cut = text[: max_len - 1]
    space = cut.rfind(" ")
    if space >= max_len // 2:
        cut = cut[:space]
    for open_, close in (("(", ")"), ("[", "]")):
        if cut.count(open_) > cut.count(close):
            cut = cut[: cut.rfind(open_)]
    return cut.rstrip(" ,;:-(") + "\u2026"


def _jsonable(data: Any) -> Any:
    return json.loads(json.dumps(data, default=str))


# ----------------------------------------------------------------------------- tools


@dataclass(frozen=True)
class ReadTool:
    """A read-only tool owned by exactly one agent."""
    name: str
    agent: AgentName
    description: str
    fn: Callable[[Case, dict[str, Any]], Any]
    read_only: Literal[True] = True

    def run(self, case: Case, args: dict[str, Any] | None = None) -> Any:
        return _jsonable(self.fn(case, dict(args or {})))


class Toolset:
    """Registry of read-only tools plus the stores backing the agent write scopes."""

    def __init__(self, *, evidence_store: EvidenceStore | None = None,
                 ledger: Ledger | None = None, docstore: DocStore | None = None,
                 atlas: Any | None = None):
        self._tools: dict[str, ReadTool] = {}
        self.evidence_store = evidence_store
        self.ledger = ledger
        self.docstore = docstore
        self.atlas = atlas

    def register(self, tool: ReadTool) -> None:
        if not isinstance(tool, ReadTool) or tool.read_only is not True:
            raise ScopeViolation("only read-only tools can be registered")
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,48}", tool.name):
            raise ValueError(f"invalid tool name {tool.name!r}")
        if _MUTATING_NAME.search(tool.name):
            raise ScopeViolation(f"tool name {tool.name!r} looks like a mutation; refused")
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name!r} already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ReadTool | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return sorted(self._tools)

    def for_agent(self, agent: AgentName) -> list[ReadTool]:
        return [t for t in self._tools.values() if t.agent is agent]

    def scope(self, agent: AgentName, case: Case) -> "AgentScope":
        return AgentScope(agent, case, self)


# ----------------------------------------------------------------------------- write scopes


class AgentScope:
    """What one agent may do for one case: its own tools plus one append-only writer."""

    def __init__(self, agent: AgentName, case: Case, toolset: Toolset):
        self.agent = agent
        self.case = case
        self._toolset = toolset

    def tool(self, name: str) -> ReadTool:
        t = self._toolset.get(name)
        if t is None:
            raise ScopeViolation(f"unknown tool {name!r}")
        if t.agent is not self.agent:
            raise ScopeViolation(f"tool {name!r} belongs to {t.agent.value}, not {self.agent.value}")
        return t

    def writer(self) -> Any:
        ts = self._toolset
        if self.agent is AgentName.EVIDENCE_COLLECTOR:
            return EvidenceAppender(ts.evidence_store, self.case, self.agent,
                                    allowed_kinds={EvidenceKind.THREAT_FEED})
        if self.agent is AgentName.ALTERNATIVE_HYPOTHESIS:
            return EvidenceAppender(ts.evidence_store, self.case, self.agent,
                                    allowed_kinds={EvidenceKind.COUNTER_HYPOTHESIS})
        if self.agent is AgentName.THREAT_CORRELATION:
            return CandidateEdgeWriter(ts.atlas, self.case)
        if self.agent is AgentName.POLICY_CHECKER:
            return LedgerNoteWriter(ts.ledger, self.case, self.agent, "oracle_advisory")
        if self.agent is AgentName.VERIFIER:
            return LedgerNoteWriter(ts.ledger, self.case, self.agent, "oracle_recommendation")
        return ProposalWriter(ts.docstore, ts.ledger, self.case)


class EvidenceAppender:
    """Append-only evidence writer restricted to given kinds; tags records as agent-made."""

    def __init__(self, store: EvidenceStore | None, case: Case, agent: AgentName,
                 allowed_kinds: set[EvidenceKind]):
        self._store = store
        self._case = case
        self._agent = agent
        self._kinds = frozenset(allowed_kinds)
        self.appended: list[str] = []

    def append(self, *, kind: EvidenceKind, origin_source: str, source_group: str,
               summary: str, payload: dict[str, Any], authorization_id: str, supports: bool,
               license: str = "operator-internal", collected_at: datetime | None = None,
               dedupe_key: str | None = None) -> Evidence:
        """Append one evidence record.

        With ``dedupe_key`` the evidence id is derived from (tenant, case, key), so
        re-running an investigation does not duplicate the same finding; the
        already-stored record is returned instead.
        """
        if self._store is None:
            raise ScopeViolation("no evidence store configured")
        if kind not in self._kinds:
            raise ScopeViolation(f"{self._agent.value} may not append {kind.value} evidence")
        evidence_id = None
        if dedupe_key is not None:
            evidence_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"aegis:oracle:{self._case.tenant_id}:"
                                                             f"{self._case.case_id}:{dedupe_key}"))
            existing = self._store.get(self._case.tenant_id, evidence_id)
            if existing is not None:
                if existing.evidence_id not in self.appended:
                    self.appended.append(existing.evidence_id)
                return existing
        body = dict(_jsonable(payload))
        body.pop("signed_bundle_verified", None)  # an agent can never claim a signed hit
        body[AGENT_APPENDED_KEY] = self._agent.actor
        body["case_id"] = self._case.case_id
        extra = {"evidence_id": evidence_id} if evidence_id else {}
        ev = Evidence(**extra, tenant_id=self._case.tenant_id, kind=kind, origin_source=origin_source,
                      source_independence_group=source_group,
                      collected_at=collected_at or datetime.now(timezone.utc),
                      summary=sanitize_text(summary, 500), payload=body, license=license,
                      authorization_id=authorization_id, supports=supports)
        stored = self._store.append(ev)
        self.appended.append(stored.evidence_id)
        return stored


class CandidateEdgeWriter:
    """Threat-correlation scope: candidate (grade E, investigative-only) edges only."""

    def __init__(self, atlas: Any | None, case: Case):
        self._atlas = atlas
        self._case = case
        self.written: list[str] = []

    def add(self, src: str, dst: str, edge_type: str, rationale: str,
            observed_at: datetime | None = None) -> str | None:
        if self._atlas is None:
            return None
        at = observed_at or datetime.now(timezone.utc)
        # The provenance id identifies this exact observation (content digest), so re-running
        # an investigation is idempotent for identical content and appends a new observation
        # otherwise; it never collides with an earlier observation of the same link.
        digest = hashlib.sha256(json.dumps([src, dst, edge_type, at.isoformat(), rationale],
                                           ensure_ascii=False).encode("utf-8")).hexdigest()[:32]
        prov = f"oracle:{self._case.case_id}:{digest}"
        edge = self._atlas.add_candidate_edge(self._case.tenant_id, src, dst, edge_type, at, prov,
                                              rationale=rationale)
        self.written.append(edge.edge_id)
        return edge.edge_id


class LedgerNoteWriter:
    """Advisory / recommendation scope: one append-only ledger note per call."""

    def __init__(self, ledger: Ledger | None, case: Case, agent: AgentName, entry_type: str):
        self._ledger = ledger
        self._case = case
        self._agent = agent
        self._type = entry_type

    def note(self, payload: dict[str, Any]) -> str | None:
        if self._ledger is None:
            return None
        entry = self._ledger.append(self._case.tenant_id, self._type, self._case.case_id,
                                    {"agent": self._agent.actor, "case_id": self._case.case_id,
                                     **_jsonable(payload)})
        return entry.entry_hash


class ProposalWriter:
    """Response-planner scope: store a *draft* proposed action, nothing else.

    Drafts are never authorized: ``authorization_id`` is cleared and
    ``rollback_verified`` forced to False; MIRROR and the signed policy decide later.
    """

    def __init__(self, docstore: DocStore | None, ledger: Ledger | None, case: Case):
        self._docs = docstore
        self._ledger = ledger
        self._case = case
        self.proposed: list[str] = []

    def propose(self, action: ProposedAction) -> ProposedAction:
        if self._docs is None:
            raise ScopeViolation("no document store configured")
        if action.tenant_id != self._case.tenant_id or action.case_id != self._case.case_id:
            raise ScopeViolation("proposal must target the investigated case")
        draft = action.model_copy(update={"authorization_id": None, "rollback_verified": False,
                                          "created_by": AgentName.RESPONSE_PLANNER.actor},
                                  deep=True)
        if self._docs.get(ProposedAction, draft.tenant_id, draft.action_id) is not None:
            raise ScopeViolation("proposals are append-only; action id already exists")
        if self._ledger is not None:
            self._ledger.append(draft.tenant_id, EntryType.ACTION, draft.action_id, {
                "event": "draft_proposed", "action_id": draft.action_id,
                "case_id": draft.case_id, "action_type": draft.action_type.value,
                "targets": draft.targets, "created_by": draft.created_by})
        self._docs.put(draft)
        self.proposed.append(draft.action_id)
        return draft


# ----------------------------------------------------------------------------- connectors


@runtime_checkable
class IntelConnector(Protocol):
    """Approved read-only intelligence connector (configured by the operator).

    ``source_group`` and ``authorization_id`` come from configuration, never from
    the connector's output, so a feed cannot claim independence it does not have.
    """
    name: str
    source_group: str
    authorization_id: str
    license: str

    def lookup(self, indicators: list[str]) -> list[dict[str, Any]]: ...


@dataclass
class StaticIntelConnector:
    """Connector backed by an in-memory table (lab, tests, offline mirrors)."""
    name: str
    source_group: str
    authorization_id: str
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    license: str = "operator-internal"

    def lookup(self, indicators: list[str]) -> list[dict[str, Any]]:
        return [dict(self.records[i], indicator=i) for i in indicators if i in self.records]


# ----------------------------------------------------------------------------- default tools


def _evidence_digest(ev: Evidence, verified: bool) -> dict[str, Any]:
    return {
        "evidence_id": ev.evidence_id, "kind": ev.kind.value, "origin_source": ev.origin_source,
        "source_group": ev.source_independence_group, "supports": ev.supports,
        "collected_at": ev.collected_at.isoformat(), "summary": ev.summary,
        "integrity_verified": verified, "agent_appended": AGENT_APPENDED_KEY in ev.payload,
        "payload": ev.payload,
        "record": ev.model_dump(mode="json"),
    }


def indicators_from_evidence(evidences: Iterable[dict[str, Any] | Evidence]) -> list[str]:
    """Domains/IPs referenced by evidence payloads (keys: indicator, value, domain, ip, ...)."""
    keys = ("indicator", "indicator_value", "matched", "domain", "qname", "ip", "dst_ip", "destination")
    out: list[str] = []
    for ev in evidences:
        payload = ev.payload if isinstance(ev, Evidence) else (ev.get("payload") or {})
        for k in keys:
            v = payload.get(k)
            if isinstance(v, str) and v.strip() and len(v) <= 253:
                out.append(v.strip().rstrip(".").lower())
            elif isinstance(v, list):
                out.extend(x.strip().rstrip(".").lower() for x in v
                           if isinstance(x, str) and x.strip() and len(x) <= 253)
    return list(dict.fromkeys(out))


def build_default_toolset(*, docstore: DocStore, evidence_store: EvidenceStore, ledger: Ledger,
                          atlas: Any | None = None, keyring: KeyRing | None = None,
                          connectors: Iterable[IntelConnector] = (),
                          simulator: Callable[[ProposedAction], MirrorResult] | None = None,
                          clock: Callable[[], datetime] | None = None,
                          ledger_keyring: KeyRing | None = None) -> Toolset:
    """Standard ORACLE toolset over the platform stores. Every tool is read-only.

    ``intel_lookup`` returns connector answers; the evidence collector agent (not
    the tool) decides what to append through its write scope. ``keyring`` holds the
    trusted operator-policy keys; ``ledger_keyring`` the ledger signing keys used by
    ``provenance_check`` (falls back to ``keyring`` when not given).
    """
    now = clock or (lambda: datetime.now(timezone.utc))
    ts = Toolset(evidence_store=evidence_store, ledger=ledger, docstore=docstore, atlas=atlas)
    connectors = list(connectors)

    def load(case: Case) -> list[tuple[Evidence, bool]]:
        out: list[tuple[Evidence, bool]] = []
        for eid in dict.fromkeys(case.evidence_ids):
            try:
                ev = evidence_store.get(case.tenant_id, eid)
            except EvidenceIntegrityError:
                raw = docstore.get(Evidence, case.tenant_id, eid)
                if raw is not None:
                    out.append((raw, False))  # tampered content is shown, flagged unverified
                continue
            if ev is not None:
                out.append((ev, evidence_store.verify(case.tenant_id, eid)))
        return out

    def case_evidence(case: Case, args: dict[str, Any]) -> list[dict[str, Any]]:
        return [_evidence_digest(e, ok) for e, ok in load(case)]

    def case_findings(case: Case, args: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for fid in case.finding_ids:
            f = docstore.get(Finding, case.tenant_id, fid)
            if f is not None:
                out.append(f.model_dump(mode="json"))
        return out

    def intel_lookup(case: Case, args: dict[str, Any]) -> list[dict[str, Any]]:
        indicators = [i for i in args.get("indicators", []) if isinstance(i, str)][:50]
        results: list[dict[str, Any]] = []
        for c in connectors:
            try:
                answers = c.lookup(indicators)
            except Exception as exc:
                raise ToolError(f"connector {c.name} failed: {type(exc).__name__}") from exc
            for a in answers if isinstance(answers, list) else []:
                if isinstance(a, dict):
                    results.append({"connector": c.name, "source_group": c.source_group,
                                    "authorization_id": c.authorization_id, "license": c.license,
                                    "answer": a})
        return results

    def benign_context(case: Case, args: dict[str, Any]) -> dict[str, Any]:
        benign = [_evidence_digest(e, ok) for e, ok in load(case)
                  if e.kind is EvidenceKind.BENIGN_BASELINE or not e.supports]
        findings = case_findings(case, {})
        return {"benign_or_counter_evidence": benign,
                "device_classes": sorted({f.get("device_class", "unknown") for f in findings}),
                "labels": sorted({f.get("label", "") for f in findings} - {""})}

    def graph_context(case: Case, args: dict[str, Any]) -> dict[str, Any]:
        if atlas is None:
            return {"available": False, "indicators": []}
        from aegis.atlas.graph import indicator_node_id, parse_node_id

        out = []
        for ind in [i for i in args.get("indicators", []) if isinstance(i, str)][:20]:
            try:
                nid = indicator_node_id(ind)
            except ValueError:
                continue
            nbrs = atlas.neighbors(case.tenant_id, nid)
            shared = (atlas.is_shared_hosting(case.tenant_id, nid)
                      if parse_node_id(nid)[0].value == "ip" else False)
            resolved_shared = sorted({n.node_id for n in nbrs
                                      if n.node_type.value == "ip"
                                      and atlas.is_shared_hosting(case.tenant_id, n.node_id)})
            node = atlas.get_node(case.tenant_id, nid)
            out.append({
                "indicator": ind, "node_id": nid, "known": node is not None,
                "node_attrs": node.attrs if node else {},
                "shared_hosting": shared, "resolves_to_shared_hosting": resolved_shared,
                "degree": len(nbrs),
                "neighbors": [{"node_id": n.node_id, "edge_type": n.edge.edge_type.value,
                               "grade": n.edge.evidence_grade.value,
                               "independent_sources": n.edge.independent_source_count,
                               "enforcement_eligible": n.edge.enforcement_eligible,
                               "reasons": n.edge.eligibility_reasons} for n in nbrs[:25]],
                "candidate_links": [c.model_dump(mode="json")
                                    for c in atlas.candidate_links(case.tenant_id, nid, limit=5)],
            })
        return {"available": True, "indicators": out}

    def timeline(case: Case, args: dict[str, Any]) -> list[dict[str, Any]]:
        subjects = [case.case_id, *case.finding_ids, *case.evidence_ids]
        return [{"seq": e.seq, "entry_type": e.entry_type, "subject_id": e.subject_id,
                 "recorded_at": e.recorded_at.isoformat()}
                for e in ledger.entries_for_subjects(case.tenant_id, subjects)][-200:]

    def policy_status(case: Case, args: dict[str, Any]) -> dict[str, Any]:
        t = now()
        policies = docstore.list(OperatorPolicy, case.tenant_id)
        rows = []
        for p in policies:
            sig_ok = keyring is not None and verify_model(p, keyring)
            valid = p.valid_from <= t < p.valid_until
            rows.append({"policy_id": p.policy_id, "mode": p.mode, "signature_valid": sig_ok,
                         "valid_now": valid, "legal_signoff": bool(p.legal_signoff_ref),
                         "allowed_actions": [a.value for a in p.allowed_actions],
                         "max_targets_per_action": p.max_targets_per_action,
                         "max_ttl_hours": p.max_ttl_hours})
        return {"policies": rows, "evaluated_at": t.isoformat()}

    def provenance_check(case: Case, args: dict[str, Any]) -> dict[str, Any]:
        per = {}
        for eid in case.evidence_ids:
            entries = ledger.entries(case.tenant_id, subject_id=eid, entry_type=EntryType.EVIDENCE)
            per[eid] = {"hash_verified": evidence_store.verify(case.tenant_id, eid),
                        "ledger_recorded_at": entries[0].recorded_at.isoformat() if entries else None,
                        "superseded_by": evidence_store.superseded_by(case.tenant_id, eid)}
        # ledger entries are signed by the ledger key, not by operator policy keys
        ok, bad = ledger.verify_chain(case.tenant_id, ledger_keyring if ledger_keyring is not None else keyring)
        return {"evidence": per, "ledger_chain_ok": ok, "ledger_first_bad_seq": bad}

    def impact_simulation(case: Case, args: dict[str, Any]) -> dict[str, Any]:
        if simulator is None:
            return {"available": False}
        raw = args.get("action")
        if not isinstance(raw, dict):
            raise ToolError("impact_simulation requires an action")
        action = ProposedAction.model_validate(raw)
        if action.tenant_id != case.tenant_id or action.case_id != case.case_id:
            raise ToolError("action does not belong to this case")
        return {"available": True, "result": simulator(action).model_dump(mode="json")}

    for name, agent, desc, fn in (
        ("case_evidence", AgentName.EVIDENCE_COLLECTOR, "Evidence attached to the case", case_evidence),
        ("case_findings", AgentName.EVIDENCE_COLLECTOR, "Findings that opened the case", case_findings),
        ("intel_lookup", AgentName.EVIDENCE_COLLECTOR, "Approved intel connectors (read-only)", intel_lookup),
        ("benign_context", AgentName.ALTERNATIVE_HYPOTHESIS, "Benign baselines and counter-evidence",
         benign_context),
        ("graph_context", AgentName.THREAT_CORRELATION, "ATLAS neighbourhood of indicators", graph_context),
        ("timeline", AgentName.THREAT_CORRELATION, "Ledger timeline of the case", timeline),
        ("policy_status", AgentName.POLICY_CHECKER, "Operator policies and signature status", policy_status),
        ("provenance_check", AgentName.VERIFIER, "Evidence hashes and ledger chain", provenance_check),
        ("impact_simulation", AgentName.RESPONSE_PLANNER, "MIRROR impact simulation (read-only)",
         impact_simulation),
    ):
        ts.register(ReadTool(name=name, agent=agent, description=desc, fn=fn))
    return ts


__all__ = [
    "AgentName", "AgentScope", "CandidateEdgeWriter", "EvidenceAppender",
    "IntelConnector", "LedgerNoteWriter", "ProposalWriter", "ReadTool", "ScopeViolation",
    "StaticIntelConnector", "ToolError", "Toolset", "build_default_toolset",
    "indicators_from_evidence", "sanitize_text", "scan_for_injection", "wrap_untrusted",
]
