"""Citation parsing and post-validation of answers.

Answers cite ids inline as ``[kind:id]`` (several per bracket allowed, separated by
``,`` or ``;``). After generation every sentence is checked:

* a citation is **valid** only if its id exists *in the session's tenant* (resolved
  through the tenant-scoped data source) and, in strict mode, was exposed by a tool
  result earlier in the session (so the model cannot cite ids it never read);
  ``query``/``metrics``/``health`` refs must name a tool result of the session;
* invalid citations are removed and reported;
* a sentence left with no valid citation is a claim without evidence: it is
  stripped (default) or kept and flagged, unless it is not a factual claim at all
  (a heading, a question, or an explicit statement of uncertainty without numbers).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from aegis.copilot.datasource import CopilotDataSource
from aegis.copilot.models import ALL_KINDS, ENTITY_KINDS, AnswerSentence, Citation

UncitedPolicy = Literal["strip", "flag"]

_BRACKET = re.compile(r"\[([A-Za-z_]+\s*:[^\[\]\n]{1,800})\]")
_TOKEN = re.compile(r"^\s*([a-z_]+)\s*:\s*([A-Za-z0-9][A-Za-z0-9._:/\-]{0,252})\s*$")
_ABBREV = re.compile(r"(?:\b(?:e\.g|i\.e|vs|cf|approx|etc|no|nr|n°|ca|env|p\.ex)\.)$", re.IGNORECASE)
_BULLET = re.compile(r"^\s*(?:[-*•]|\d{1,3}[.)])\s+")
_HEDGE = re.compile(
    r"^(?:i (?:do not|don't|cannot|can't|could not|couldn't|did not|didn't) "
    r"(?:know|answer|determine|find|verify|confirm|tell)|i am unable|i'm unable|unable to "
    r"(?:answer|determine|verify|confirm)|there is not enough|insufficient (?:data|evidence|information)|"
    r"not enough (?:data|evidence|information)|je ne (?:sais|peux) pas|je n'ai pas pu|je n’ai pas pu|"
    r"impossible de (?:répondre|déterminer|vérifier|confirmer)|données insuffisantes|"
    r"pas assez de (?:données|preuves|informations)|les données ne permettent pas)", re.IGNORECASE)
_IDLIKE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-|\brc-[0-9a-f]{6,}|\bp_[0-9a-f]{8,}", re.IGNORECASE)


def parse_citations(text: str) -> tuple[str, list[Citation], list[str]]:
    """Remove citation brackets from ``text``. Returns (clean text, citations, malformed refs).

    Brackets whose first token is not a known citation kind are left untouched.
    """
    cites: list[Citation] = []
    bad: list[str] = []

    def repl(m: re.Match[str]) -> str:
        tokens = re.split(r"[,;]", m.group(1))
        parsed: list[tuple[str, str] | None] = []
        for tok in tokens:
            tm = _TOKEN.match(tok)
            parsed.append((tm.group(1), tm.group(2)) if tm else None)
        first = parsed[0]
        if first is None or first[0] not in ALL_KINDS:
            if first is None and m.group(1).split(":", 1)[0].strip().lower() in ALL_KINDS:
                bad.append(m.group(0)[:120])
                return ""
            return m.group(0)
        for tok, p in zip(tokens, parsed):
            if p is None or p[0] not in ALL_KINDS:
                bad.append(tok.strip()[:120])
            else:
                cites.append(Citation(kind=p[0], id=p[1]))  # type: ignore[arg-type]
        return ""

    clean = _BRACKET.sub(repl, text)
    clean = re.sub(r"[ \t]+([.,;:!?])", r"\1", clean)
    clean = re.sub(r"[ \t]{2,}", " ", clean).strip()
    return clean, cites, bad


def split_segments(text: str) -> list[str]:
    """Split an answer into sentence-like segments, keeping trailing citations attached."""
    out: list[str] = []
    for line in text.splitlines():
        line = _BULLET.sub("", line).strip()
        if not line:
            continue
        for p in _split_line(line):
            if out and _only_citations(p):
                out[-1] = f"{out[-1]} {p}"
            else:
                out.append(p)
    return out


def _split_line(line: str) -> list[str]:
    protected: list[str] = []

    def hold(m: re.Match[str]) -> str:
        protected.append(m.group(0))
        return f"\x00{len(protected) - 1}\x00"

    def restore(m: re.Match[str]) -> str:
        return protected[int(m.group(1))]

    work = _BRACKET.sub(hold, line)
    pieces: list[str] = []
    start = 0
    for m in re.finditer(r"[.!?](?=\s+\S)", work):
        end = m.end()
        if _ABBREV.search(work[start:end]):
            continue
        pieces.append(work[start:end])
        start = end
    pieces.append(work[start:])
    restored = (re.sub(r"\x00(\d+)\x00", restore, p).strip() for p in pieces)
    return [p for p in restored if p]


def _only_citations(seg: str) -> bool:
    clean, cites, bad = parse_citations(seg)
    return bool(cites or bad) and not re.sub(r"[\s.,;:!?]", "", clean)


def is_exempt(text: str) -> bool:
    """Not a factual claim: heading, question, or explicit uncertainty without numbers or ids."""
    t = text.strip().lstrip("#").strip()
    if not t:
        return True
    if text.lstrip().startswith("#") or (t.endswith(":") and len(t.split()) <= 8 and not re.search(r"\d", t)):
        return True
    if t.endswith("?"):
        return True
    return bool(_HEDGE.match(t)) and not re.search(r"\d", t) and not _IDLIKE.search(t)


@dataclass
class ValidationResult:
    sentences: list[AnswerSentence] = field(default_factory=list)
    removed_claims: list[str] = field(default_factory=list)
    invalid_citations: list[str] = field(default_factory=list)

    @property
    def has_cited_fact(self) -> bool:
        return any(s.status == "cited" for s in self.sentences)


class CitationValidator:
    """Checks citations against the tenant's stores and the session's seen refs."""

    def __init__(self, ds: CopilotDataSource, tenant_id: str, seen_refs: set[str], *, require_seen: bool = True):
        self._ds = ds
        self._tenant = tenant_id
        self._seen = seen_refs
        self._require_seen = require_seen
        self._cache: dict[str, bool] = {}

    def is_valid(self, c: Citation) -> bool:
        ref = c.ref
        if ref in self._cache:
            return self._cache[ref]
        if c.kind in ENTITY_KINDS:
            ok = (ref in self._seen or not self._require_seen) and self._ds.exists(self._tenant, c.kind, c.id)
        else:
            ok = ref in self._seen   # result refs exist only as tool results of this session
        self._cache[ref] = ok
        return ok

    def validate_text(self, text: str, *, policy: UncitedPolicy = "strip") -> ValidationResult:
        res = ValidationResult()
        for seg in split_segments(text):
            clean, cites, bad = parse_citations(seg)
            res.invalid_citations.extend(bad)
            valid: list[Citation] = []
            for c in cites:
                if self.is_valid(c):
                    if c not in valid:
                        valid.append(c)
                else:
                    res.invalid_citations.append(c.ref[:160])
            if not clean:
                continue
            self._place(res, clean, valid, policy)
        return res

    def validate_sentences(self, sentences: list[AnswerSentence], *,
                           policy: UncitedPolicy = "strip") -> ValidationResult:
        """Re-check already structured sentences (used for deterministic answers: defense in depth)."""
        res = ValidationResult()
        for s in sentences:
            valid = []
            for c in s.citations:
                if self.is_valid(c):
                    valid.append(c)
                else:
                    res.invalid_citations.append(c.ref[:160])
            if s.status == "exempt" and not valid:
                res.sentences.append(AnswerSentence(text=s.text, status="exempt"))
                continue
            self._place(res, s.text, valid, policy)
        return res

    @staticmethod
    def _place(res: ValidationResult, clean: str, valid: list[Citation], policy: UncitedPolicy) -> None:
        if valid:
            res.sentences.append(AnswerSentence(text=clean, citations=valid, status="cited"))
        elif is_exempt(clean):
            res.sentences.append(AnswerSentence(text=clean, status="exempt"))
        elif policy == "flag":
            res.sentences.append(AnswerSentence(text=clean, status="flagged"))
        else:
            res.removed_claims.append(clean[:500])
