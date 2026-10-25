"""Documentation integrity: links, anchors, referenced tests, CLI commands, API routes,
configuration coverage, legal-template banners and the sales claims rules.

The docs are part of the product (operators install from them, buyers read them), so
they are tested like code: anything they reference must exist.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from aegis.api.settings import ENV_VARS

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

#: operator, security, compliance and sales documentation checked here (module design docs such as
#: ARCHITECTURE.md and RESONANCE.md, the charter and the spec are maintained with their modules)
TOP_LEVEL_DOCS = ("INSTALL.md", "CONFIGURATION.md", "OPERATOR_INTEGRATION.md", "SECURITY_ARCHITECTURE.md", "SLO.md")
OWNED = sorted({ROOT / "README.md", ROOT / "SECURITY.md", *[DOCS / n for n in TOP_LEVEL_DOCS],
                *DOCS.glob("compliance/*.md"), *DOCS.glob("runbooks/*.md"), *DOCS.glob("sales/*.md")})
COUNSEL_TEMPLATES = sorted([*DOCS.glob("compliance/*.md"), DOCS / "sales" / "PILOT_SOW_TEMPLATE.md"])
CUSTOMER_FACING = [DOCS / "sales" / n for n in ("PRODUCT_SHEET.md", "PRODUCT_SHEET_FR.md", "SHADOW_PILOT_OFFER.md",
                                                "SECURITY_QUESTIONNAIRE.md")]

_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
_IMAGE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)\)")


def _id(p: Path) -> str:
    return str(p.relative_to(ROOT))


def _anchors(doc: Path) -> set[str]:
    out = set()
    for heading in re.findall(r"^#{1,6}\s+(.+?)\s*$", doc.read_text(encoding="utf-8"), re.M):
        out.add(re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-"))
    return out


def _code(doc: Path) -> str:
    """Text inside fenced code blocks and inline code spans."""
    text = doc.read_text(encoding="utf-8")
    fenced = re.findall(r"```[^\n]*\n(.*?)```", text, re.S)
    inline = re.findall(r"`([^`\n]+)`", re.sub(r"```.*?```", "", text, flags=re.S))
    return "\n".join(fenced + inline)


def test_owned_docs_exist():
    names = {_id(p) for p in OWNED}
    for required in ("README.md", "SECURITY.md", "docs/INSTALL.md", "docs/CONFIGURATION.md",
                     "docs/OPERATOR_INTEGRATION.md", "docs/SECURITY_ARCHITECTURE.md", "docs/SLO.md",
                     "docs/compliance/DATA_MAP.md", "docs/compliance/DPIA_TEMPLATE.md",
                     "docs/compliance/REGULATORY_CONTEXT_FR_EU.md", "docs/runbooks/incident.md",
                     "docs/runbooks/rollback.md", "docs/runbooks/key-rotation.md",
                     "docs/runbooks/upgrade-backup-restore.md", "docs/sales/PRODUCT_SHEET.md",
                     "docs/sales/PRODUCT_SHEET_FR.md", "docs/sales/SHADOW_PILOT_OFFER.md",
                     "docs/sales/PILOT_SOW_TEMPLATE.md", "docs/sales/SECURITY_QUESTIONNAIRE.md",
                     "docs/sales/DEMO_SCRIPT.md", "docs/sales/OBJECTION_HANDLING.md", "docs/sales/CLAIMS_GUIDE.md"):
        assert required in names, required


@pytest.mark.parametrize("doc", OWNED, ids=_id)
def test_relative_links_and_anchors_resolve(doc):
    text = doc.read_text(encoding="utf-8")
    for target in _LINK.findall(text) + _IMAGE.findall(text):
        if re.match(r"^[a-z]+:", target):
            continue  # external URL / mailto
        path, _, anchor = target.partition("#")
        dest = (doc.parent / path).resolve() if path else doc
        assert dest.exists(), f"{_id(doc)}: broken link {target}"
        if anchor and dest.suffix == ".md":
            assert anchor in _anchors(dest), f"{_id(doc)}: no heading #{anchor} in {dest.name}"


@pytest.mark.parametrize("doc", OWNED, ids=_id)
def test_referenced_tests_exist(doc):
    for file, test in re.findall(r"(tests/[\w/]+\.py)::(\w+)", doc.read_text(encoding="utf-8")):
        path = ROOT / file
        assert path.is_file(), f"{_id(doc)}: {file}"
        assert re.search(rf"^\s*def {test}\(", path.read_text(), re.M), f"{_id(doc)}: {file}::{test}"


@pytest.mark.parametrize("doc", OWNED, ids=_id)
def test_cli_commands_in_docs_exist(doc):
    from aegis.cli import build_parser
    parser = build_parser()
    sub = {a.dest: a for a in parser._subparsers._group_actions}["cmd"].choices  # type: ignore[union-attr]
    for cmd, rest in re.findall(r"(?:^|[\s`(])aegis(?:-omega:[\w.]+)? ([a-z]+)((?: [a-z]+)?)", _code(doc)):
        assert cmd in sub, f"{_id(doc)}: unknown command 'aegis {cmd}'"
        second = rest.strip()
        nested = [a for a in sub[cmd]._actions if getattr(a, "choices", None) and isinstance(a.choices, dict)]
        if nested and second and not second.startswith("-"):
            assert second in nested[0].choices, f"{_id(doc)}: unknown command 'aegis {cmd} {second}'"


def _route_patterns() -> list[re.Pattern[str]]:
    from aegis.api.routes import router
    pats = []
    for r in router.routes:
        path = getattr(r, "path", "")
        pats.append(re.compile("^" + re.sub(r"\\\{[^}]+\\\}", r"[^/]+", re.escape(path)) + "$"))
    return pats


@pytest.mark.parametrize("doc", OWNED, ids=_id)
def test_api_paths_in_docs_exist(doc):
    pats = _route_patterns()
    for raw in re.findall(r"/api/v1/[A-Za-z0-9_{}<>./-]*[A-Za-z0-9_}>]", doc.read_text(encoding="utf-8")):
        path = re.sub(r"<[^>]+>|\{[^}]+\}", "x", raw)
        if path.startswith(("/api/v1/docs", "/api/v1/redoc")):
            continue
        assert any(p.match(path) for p in pats), f"{_id(doc)}: no API route for {raw}"


def test_every_setting_is_documented_in_configuration_reference():
    text = (DOCS / "CONFIGURATION.md").read_text(encoding="utf-8")
    missing = [v for v in ENV_VARS.values() if f"`{v}`" not in text]
    assert not missing, missing
    for extra in ("AEGIS_PSEUDONYM_MASTER_KEY", "AEGIS_FORWARDED_ALLOW_IPS", "AEGIS_LLM_MODEL", "ANTHROPIC_API_KEY"):
        assert f"`{extra}`" in text


@pytest.mark.parametrize("doc", COUNSEL_TEMPLATES, ids=_id)
def test_legal_documents_are_marked_as_templates_for_counsel(doc):
    head = doc.read_text(encoding="utf-8")[:1200]
    assert "TEMPLATE FOR COUNSEL REVIEW" in head
    assert "not legal advice" in head.lower()


def test_pricing_is_placeholder_only():
    offer = (DOCS / "sales" / "SHADOW_PILOT_OFFER.md").read_text(encoding="utf-8")
    sow = (DOCS / "sales" / "PILOT_SOW_TEMPLATE.md").read_text(encoding="utf-8")
    pricing = offer[offer.index("## Pricing"):offer.index("## What we need from you")]
    assert pricing.count("[FOUNDER TO SET") >= 4
    assert "[FOUNDER TO SET" in sow
    for doc in sorted(DOCS.glob("sales/*.md")):
        text = doc.read_text(encoding="utf-8")
        assert not re.search(r"(?:[€$£]\s?\d|\d[\d,.]*\s?(?:€|EUR|USD|GBP)\b|\bk€)", text), f"{doc.name}: concrete price"


@pytest.mark.parametrize("doc", CUSTOMER_FACING, ids=_id)
def test_customer_facing_docs_avoid_forbidden_claims(doc):
    text = doc.read_text(encoding="utf-8").lower()
    forbidden = [r"\bguarantee", r"\bgaranti", r"ai-powered", r"zero false positive", r"\baccuracy\b",
                 r"best[- ]in[- ]class", r"military[- ]grade", r"unhackable", r"blocks? all\b", r"100\s?% detection",
                 r"real[- ]time", r"temps réel", r"better than", r"meilleur que"]
    for pat in forbidden:
        assert not re.search(pat, text), f"{doc.name}: forbidden claim /{pat}/ (see CLAIMS_GUIDE.md)"


def test_product_sheets_disclose_lab_results_are_not_field_results():
    en = (DOCS / "sales" / "PRODUCT_SHEET.md").read_text(encoding="utf-8")
    fr = (DOCS / "sales" / "PRODUCT_SHEET_FR.md").read_text(encoding="utf-8")
    assert "synthetic lab" in en and "not field results" in en
    assert "laboratoire synthétique" in fr and "ne sont pas des résultats terrain" in fr


@pytest.mark.parametrize("doc", OWNED, ids=_id)
def test_no_unfinished_markers(doc):
    text = doc.read_text(encoding="utf-8")
    assert not re.search(r"\b(TODO|FIXME|TBD|XXX)\b|lorem ipsum", text, re.I), _id(doc)


def test_demo_script_ui_labels_exist_in_the_console():
    src = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "web" / "src").rglob("*.tsx"))
    for label in ("Verify chain now", "Generate report", "Open full report", "Run simulation", "Re-run investigation",
                  "Update review", "Propose action", "Evidence trail", "Investigation report",
                  "Graph neighbourhood", "Replay as of", "Authorization did not allow this action",
                  "Independent supporting origins", "Signed IOC hits", "Legitimate co-tenants",
                  "Device class selects a comparison baseline only"):
        assert label in src, f"DEMO_SCRIPT.md label not found in web/src: {label}"
    script = (DOCS / "sales" / "DEMO_SCRIPT.md").read_text(encoding="utf-8")
    assert "synthetic" in script.lower() and "10 minutes" in script


def test_threat_model_covers_every_spec_section_15_test():
    text = (DOCS / "SECURITY_ARCHITECTURE.md").read_text(encoding="utf-8")
    for mandatory in ("Benign IPTV untouched", "Malicious lab box detected", "Shared CDN not indiscriminately blocked",
                      "Contradictory feeds downgrade finding", "Unavailable LLM does not disable baseline alerts",
                      "Expired authorization prevents action", "Compromised agent cannot alter policy",
                      "Rollback restores service", "Model drift prevents silent promotion",
                      "Replay uses only contemporaneous evidence"):
        assert mandatory in text, mandatory
    for threat in ("Spoofed telemetry", "Feed poisoning", "Data leakage", "Malicious connector output",
                   "Prompt injection", "Graph over-linking", "Model evasion", "Cross-tenant access",
                   "Unauthorized blocking", "Insider misuse", "Compromised signing keys", "False infringement claims"):
        assert threat in text, threat
