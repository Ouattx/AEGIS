"""Citation parsing, sentence splitting and post-validation."""
from __future__ import annotations

from aegis.copilot.citations import CitationValidator, is_exempt, parse_citations, split_segments
from aegis.copilot.models import AnswerSentence, Citation


class _DS:
    """Minimal data source: only ``exists`` is used by the validator."""

    def __init__(self, known: set[tuple[str, str]]):
        self.known = known
        self.calls = 0

    def exists(self, tenant_id: str, kind: str, entity_id: str) -> bool:
        self.calls += 1
        return tenant_id == "t" and (kind, entity_id) in self.known


def test_parse_single_multiple_and_foreign_brackets():
    clean, cites, bad = parse_citations("Beacon seen [finding:f1] [evidence:e1; evidence:e2], see [note: x].")
    assert clean == "Beacon seen, see [note: x]."
    assert [c.ref for c in cites] == ["finding:f1", "evidence:e1", "evidence:e2"]
    assert bad == []
    clean, cites, bad = parse_citations("Node [node:domain:c2.example.org] and ledger [ledger:42].")
    assert [c.ref for c in cites] == ["node:domain:c2.example.org", "ledger:42"]
    _, cites, bad = parse_citations("x [case: bad id with spaces]")
    assert cites == [] and bad


def test_split_keeps_trailing_citations_and_ids_with_dots():
    text = ("Case c1 is NEW [case:c1]. It targets c2.badbox.example, e.g. a TV box. [evidence:e1]\n"
            "- Score is 0.97 [finding:f1].\n- Is it real?")
    segs = split_segments(text)
    assert segs == ["Case c1 is NEW [case:c1].", "It targets c2.badbox.example, e.g. a TV box. [evidence:e1]",
                    "Score is 0.97 [finding:f1].", "Is it real?"]


def test_exempt_rules():
    assert is_exempt("## Summary")
    assert is_exempt("Key facts:")
    assert is_exempt("Do you want the evidence list?")
    assert is_exempt("I could not find that case.")
    assert is_exempt("Je n'ai pas pu trouver ce dossier.")
    assert not is_exempt("I could not find 3 cases.")          # numbers make it a claim
    assert not is_exempt("No malicious findings exist.")        # negative facts need a query ref
    assert not is_exempt("The device is compromised.")


def test_validator_strict_requires_seen_and_existing():
    ds = _DS({("finding", "f1"), ("finding", "f2"), ("case", "c1")})
    v = CitationValidator(ds, "t", {"finding:f1", "case:c1", "query:q-1"})
    res = v.validate_text("A [finding:f1]. B [finding:f2]. C [case:zz]. D [query:q-1]. E [metrics:m-9]. F.")
    assert [s.text for s in res.sentences] == ["A.", "D."]
    assert res.invalid_citations == ["finding:f2", "case:zz", "metrics:m-9"]
    assert res.removed_claims == ["B.", "C.", "E.", "F."]
    v2 = CitationValidator(ds, "t", set(), require_seen=False)
    assert v2.validate_text("B [finding:f2].").sentences[0].citations == [Citation(kind="finding", id="f2")]


def test_validator_caches_and_scopes_tenant():
    ds = _DS({("finding", "f1")})
    v = CitationValidator(ds, "other", {"finding:f1"})
    res = v.validate_text("A [finding:f1]. Again [finding:f1].")
    assert res.sentences == [] and ds.calls == 1


def test_validate_sentences_keeps_exempt_guidance():
    ds = _DS({("case", "c1")})
    v = CitationValidator(ds, "t", {"case:c1"})
    res = v.validate_sentences([
        AnswerSentence(text="Case is NEW.", citations=[Citation(kind="case", id="c1")]),
        AnswerSentence(text="Name a domain to explore the graph.", status="exempt"),
        AnswerSentence(text="Forged.", citations=[Citation(kind="case", id="c9")]),
    ])
    assert [s.status for s in res.sentences] == ["cited", "exempt"]
    assert res.invalid_citations == ["case:c9"] and res.removed_claims == ["Forged."]
