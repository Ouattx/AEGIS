"""SIEM export: CEF / LEEF 2.0 escaping, JSON lines, tenant scoping."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from test_egress_detector import TENANT, flood, run

from aegis.connectors.siem import (
    CAMPAIGN_SEVERITY,
    LEEF_DELIMITER,
    cef_header_escape,
    parse_cef_extension,
    siem_export,
    to_cef,
    to_leef,
)
from aegis.contracts.canonical import canonical_bytes
from aegis.contracts.models import Finding, Verdict
from aegis.egress import to_findings

NOW = datetime(2026, 10, 1, 2, tzinfo=timezone.utc)


def _finding(**kw) -> Finding:
    d = dict(tenant_id=TENANT, entity_pseudonym="p_line00001", device_class="android_tv", detector_version="egress-1",
             label="egress_ddos_participation", verdict=Verdict.MALICIOUS, score=0.87,
             observed_window_start=NOW - timedelta(hours=1), observed_window_end=NOW, evidence_ids=["ev1", "ev2"],
             explanation="flood toward 192.0.2.10", created_at=NOW, expires_at=NOW + timedelta(hours=24))
    d.update(kw)
    return Finding(**d)


def test_cef_header_and_extension_escaping_round_trip():
    f = _finding(label="odd|label\\x", explanation="a=b\nnext line \\ end")
    line = to_cef(f)
    assert line.startswith("CEF:0|AEGIS|OMEGA SHIELD|")
    assert "odd\\|label\\\\x" in line
    # split the header on unescaped pipes: 7 header fields + extension
    parts, cur, i = [], "", 0
    while i < len(line):
        if line[i] == "\\":
            cur += line[i:i + 2]
            i += 2
            continue
        if line[i] == "|" and len(parts) < 7:
            parts.append(cur)
            cur = ""
        else:
            cur += line[i]
        i += 1
    parts.append(cur)
    assert len(parts) == 8 and parts[6] == "8"
    ext = parse_cef_extension(parts[7])
    assert ext["msg"] == "a=b\nnext line \\ end"
    assert ext["cs1Label"] == "entityPseudonym" and ext["cs1"] == "p_line00001"
    assert ext["cs4"] == "ev1,ev2" and ext["cfp1"] == "0.8700"
    assert ext["rt"] == str(int(NOW.timestamp() * 1000))
    assert "\n" not in line
    assert cef_header_escape("a|b\\") == "a\\|b\\\\"


def test_leef_uses_declared_delimiter_and_strips_it_from_values():
    line = to_leef(_finding(explanation=f"x{LEEF_DELIMITER}y\nz"))
    head, delim, body = line.split("|", 6)[:5], line.split("|")[5], line.split("|", 6)[6]
    assert head[0] == "LEEF:2.0" and head[1] == "AEGIS" and delim == LEEF_DELIMITER
    attrs = dict(kv.split("=", 1) for kv in body.split(LEEF_DELIMITER))
    assert attrs["msg"] == "x y z" and attrs["sev"] == "8" and attrs["cat"] == "egress_ddos_participation"
    assert attrs["devTime"].startswith("2026-10-01T02:00:00.000") and "devTimeFormat" in attrs


def test_jsonl_lines_are_canonical_json_with_campaigns():
    rep = run([e for i in range(3) for e in flood(f"p_line0000{i}", range(i, i + 3), 1_500)])
    fs = to_findings(rep)
    pl = siem_export(fs, "jsonl", tenant_id=TENANT, now=NOW, campaigns=rep.campaigns)
    lines = pl.body.splitlines()
    assert pl.records == len(lines) == 4 and pl.content_type == "application/x-ndjson"
    recs = [json.loads(x) for x in lines]
    assert all(canonical_bytes(r).decode() == x for r, x in zip(recs, lines))
    assert [r["event_type"] for r in recs] == ["finding"] * 3 + ["campaign"]
    assert recs[-1]["severity"] == CAMPAIGN_SEVERITY and recs[0]["calibrated"] is False


def test_campaign_cef_and_leef_carry_target():
    rep = run([e for i in range(3) for e in flood(f"p_line0000{i}", range(i, i + 3), 1_500)])
    cef = siem_export([], "cef", tenant_id=TENANT, now=NOW, campaigns=rep.campaigns).body
    assert "dst=192.0.2.10" in cef and "cn1=3" in cef
    leef = siem_export([], "leef", tenant_id=TENANT, now=NOW, campaigns=rep.campaigns).body
    assert "dst=192.0.2.10" in leef


def test_tenant_scope_abstain_filter_and_unknown_format():
    with pytest.raises(ValueError):
        siem_export([_finding(tenant_id="other")], "cef", tenant_id=TENANT, now=NOW)
    fs = [_finding(), _finding(verdict=Verdict.ABSTAIN, score=0.0)]
    assert siem_export(fs, "cef", tenant_id=TENANT, now=NOW).records == 2
    assert siem_export(fs, "cef", tenant_id=TENANT, now=NOW, include_abstain=False).records == 1
    with pytest.raises(ValueError):
        siem_export(fs, "syslog", tenant_id=TENANT, now=NOW)  # type: ignore[arg-type]
