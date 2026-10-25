"""SIEM export of findings and EGRESS campaigns: CEF, LEEF 2.0 and JSON lines.

Works on any :class:`~aegis.contracts.models.Finding` (SENTINEL, RESONANCE, GENOME,
EGRESS...) plus optional :class:`~aegis.egress.models.EgressCampaign` records. Records
carry pseudonyms and evidence ids only: no subscriber identity, no payload.

Formats:

* **CEF** (``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension``): header
  fields escape ``\\`` and ``|``; extension values escape ``\\``, ``=``, CR and LF. Custom
  fields use the ``csN`` / ``csNLabel`` and ``cfp1`` / ``cfp1Label`` pairs.
* **LEEF 2.0** (``LEEF:2.0|Vendor|Product|Version|EventID|^|key=value^...``): ``^`` is the
  declared attribute delimiter; values have the delimiter, CR and LF replaced by a space
  (LEEF defines no escape for them). ``devTime`` is ISO 8601 with ``devTimeFormat``.
* **JSON lines**: one canonical (RFC 8785) JSON object per line.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Iterable, Literal

from aegis.connectors.common import PRODUCT_NAME, PRODUCT_VENDOR, ExportPayload, product_version, utc
from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import Finding, Verdict
from aegis.egress.models import EgressCampaign

Format = Literal["cef", "leef", "jsonl"]
FORMATS: tuple[Format, ...] = ("cef", "leef", "jsonl")
SCHEMA = "aegis.siem/1"
MAX_MSG = 1000
LEEF_DELIMITER = "^"

SEVERITY = {Verdict.MALICIOUS: 8, Verdict.SUSPICIOUS: 5, Verdict.ABSTAIN: 2, Verdict.BENIGN: 1}
CAMPAIGN_SEVERITY = 7
_CONTENT_TYPE = {"cef": "text/plain; charset=utf-8", "leef": "text/plain; charset=utf-8",
                 "jsonl": "application/x-ndjson"}


def _ms(dt: datetime) -> int:
    return int(utc(dt).timestamp() * 1000)


def cef_header_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def cef_value_escape(value: str) -> str:
    return (value.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n"))


def leef_clean(value: str) -> str:
    return value.replace(LEEF_DELIMITER, " ").replace("\r", " ").replace("\n", " ").replace("\t", " ")


def _leef_header(value: str) -> str:
    return leef_clean(value).replace("|", "/")


def _first_ipv4(targets: Iterable[str]) -> str | None:
    for t in targets:
        try:
            if ipaddress.ip_address(t).version == 4:
                return t
        except ValueError:
            continue
    return None


def finding_record(f: Finding) -> dict[str, Any]:
    """Normalized SIEM record for one finding (the JSON-lines object)."""
    return {
        "schema": SCHEMA, "event_type": "finding", "finding_id": f.finding_id, "tenant_id": f.tenant_id,
        "entity_pseudonym": f.entity_pseudonym, "device_class": f.device_class, "label": f.label,
        "verdict": f.verdict.value, "severity": SEVERITY[f.verdict], "score": f.score,
        "calibrated": f.calibration_id is not None, "status": f.status.value, "requires_review": f.requires_review,
        "detector_version": f.detector_version, "observed_window_start": f.observed_window_start.isoformat(),
        "observed_window_end": f.observed_window_end.isoformat(), "created_at": f.created_at.isoformat(),
        "evidence_ids": f.evidence_ids, "counterevidence_ids": f.counterevidence_ids,
        "explanation": f.explanation[:MAX_MSG]}


def campaign_record(c: EgressCampaign) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "event_type": "campaign", "campaign_id": c.campaign_id, "tenant_id": c.tenant_id,
        "label": c.label, "kind": c.kind, "severity": CAMPAIGN_SEVERITY, "n_lines": c.n_lines,
        "member_lines": c.member_lines[:200], "targets": c.targets[:200], "start": c.start.isoformat(),
        "end": c.end.isoformat(), "explanation": c.explanation[:MAX_MSG]}


def _cef(sig: str, name: str, sev: int, ext: list[tuple[str, Any]]) -> str:
    head = "|".join(cef_header_escape(x) for x in
                    ("CEF:0", PRODUCT_VENDOR, PRODUCT_NAME, product_version(), sig, name, str(sev)))
    body = " ".join(f"{k}={cef_value_escape(str(v))}" for k, v in ext if v is not None and v != "")
    return f"{head}|{body}"


def to_cef(f: Finding) -> str:
    return _cef(f"aegis:finding:{f.label}", f"{f.label} {f.verdict.value}", SEVERITY[f.verdict], [
        ("rt", _ms(f.created_at)), ("start", _ms(f.observed_window_start)), ("end", _ms(f.observed_window_end)),
        ("cat", f.label), ("externalId", f.finding_id), ("act", "alert"),
        ("cs1Label", "entityPseudonym"), ("cs1", f.entity_pseudonym),
        ("cs2Label", "verdict"), ("cs2", f.verdict.value),
        ("cs3Label", "detectorVersion"), ("cs3", f.detector_version),
        ("cs4Label", "evidenceIds"), ("cs4", ",".join(f.evidence_ids)[:1023]),
        ("cs5Label", "deviceClass"), ("cs5", f.device_class),
        ("cs6Label", "tenantId"), ("cs6", f.tenant_id),
        ("cfp1Label", "score"), ("cfp1", f"{f.score:.4f}"),
        ("msg", f.explanation[:MAX_MSG])])


def campaign_to_cef(c: EgressCampaign) -> str:
    return _cef(f"aegis:campaign:{c.label}", f"{c.label} campaign ({c.kind})", CAMPAIGN_SEVERITY, [
        ("rt", _ms(c.end)), ("start", _ms(c.start)), ("end", _ms(c.end)), ("cat", c.label),
        ("externalId", c.campaign_id), ("act", "alert"), ("dst", _first_ipv4(c.targets)),
        ("cn1Label", "linesInvolved"), ("cn1", c.n_lines),
        ("cs1Label", "campaignKind"), ("cs1", c.kind),
        ("cs2Label", "targets"), ("cs2", ",".join(c.targets[:50])[:1023]),
        ("cs6Label", "tenantId"), ("cs6", c.tenant_id),
        ("msg", c.explanation[:MAX_MSG])])


def _leef(event_id: str, attrs: list[tuple[str, Any]]) -> str:
    head = "|".join(_leef_header(x) for x in ("LEEF:2.0", PRODUCT_VENDOR, PRODUCT_NAME, product_version(), event_id))
    body = LEEF_DELIMITER.join(f"{k}={leef_clean(str(v))}" for k, v in attrs if v is not None and v != "")
    return f"{head}|{LEEF_DELIMITER}|{body}"


_DEVTIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"


def _devtime(dt: datetime) -> str:
    return utc(dt).isoformat(timespec="milliseconds")


def to_leef(f: Finding) -> str:
    return _leef(f"aegis:finding:{f.label}", [
        ("devTime", _devtime(f.created_at)), ("devTimeFormat", _DEVTIME_FORMAT), ("cat", f.label),
        ("sev", SEVERITY[f.verdict]), ("findingId", f.finding_id), ("entityPseudonym", f.entity_pseudonym),
        ("verdict", f.verdict.value), ("score", f"{f.score:.4f}"), ("deviceClass", f.device_class),
        ("detectorVersion", f.detector_version), ("evidenceIds", ",".join(f.evidence_ids)),
        ("tenantId", f.tenant_id), ("msg", f.explanation[:MAX_MSG])])


def campaign_to_leef(c: EgressCampaign) -> str:
    return _leef(f"aegis:campaign:{c.label}", [
        ("devTime", _devtime(c.end)), ("devTimeFormat", _DEVTIME_FORMAT), ("cat", c.label),
        ("sev", CAMPAIGN_SEVERITY), ("campaignId", c.campaign_id), ("campaignKind", c.kind),
        ("dst", _first_ipv4(c.targets)), ("linesInvolved", c.n_lines), ("targets", ",".join(c.targets[:50])),
        ("tenantId", c.tenant_id), ("msg", c.explanation[:MAX_MSG])])


def siem_export(findings: Iterable[Finding], fmt: Format, *, tenant_id: str, now: datetime,
                campaigns: Iterable[EgressCampaign] = (), include_abstain: bool = True) -> ExportPayload:
    """One SIEM batch for ``tenant_id``; a record of another tenant raises ``ValueError``."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; expected one of {FORMATS}")
    fs = [f for f in findings if include_abstain or f.verdict is not Verdict.ABSTAIN]
    cs = list(campaigns)
    for rec in [*fs, *cs]:
        if rec.tenant_id != tenant_id:
            raise ValueError("record belongs to a different tenant (no cross-tenant export)")
    if fmt == "cef":
        lines = [to_cef(f) for f in fs] + [campaign_to_cef(c) for c in cs]
    elif fmt == "leef":
        lines = [to_leef(f) for f in fs] + [campaign_to_leef(c) for c in cs]
    else:
        lines = [canonical_bytes(finding_record(f)).decode("utf-8") for f in fs] + \
                [canonical_bytes(campaign_record(c)).decode("utf-8") for c in cs]
    body = "".join(line + "\n" for line in lines)
    return ExportPayload.build(f"siem.{fmt}", tenant_id, _CONTENT_TYPE[fmt], body, records=len(lines),
                               generated_at=now)


def parse_cef_extension(ext: str) -> dict[str, str]:
    """Inverse of the CEF extension encoding used here (for receivers and tests)."""
    out: dict[str, str] = {}
    key: str | None = None
    buf: list[str] = []
    i = 0
    tokens: list[tuple[str, str]] = []
    # split on unescaped "key=" boundaries: a space followed by \w+= starts a new pair
    while i < len(ext):
        ch = ext[i]
        if ch == "\\" and i + 1 < len(ext):
            buf.append(ext[i:i + 2])
            i += 2
            continue
        if ch == "=" and key is None:
            key = "".join(buf)
            buf = []
        elif ch == " " and key is not None:
            j = i + 1
            while j < len(ext) and (ext[j].isalnum() or ext[j] == "_"):
                j += 1
            if j < len(ext) and ext[j] == "=" and j > i + 1:
                tokens.append((key, "".join(buf)))
                key, buf = None, []
            else:
                buf.append(ch)
        else:
            buf.append(ch)
        i += 1
    if key is not None:
        tokens.append((key, "".join(buf)))
    for k, raw in tokens:
        out[k] = (raw.replace("\\n", "\n").replace("\\r", "\r").replace("\\=", "=").replace("\\\\", "\\"))
    return out


__all__ = [
    "CAMPAIGN_SEVERITY", "FORMATS", "LEEF_DELIMITER", "SCHEMA", "SEVERITY", "campaign_record", "campaign_to_cef",
    "campaign_to_leef", "cef_header_escape", "cef_value_escape", "finding_record", "leef_clean",
    "parse_cef_extension", "siem_export", "to_cef", "to_leef",
]
