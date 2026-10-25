"""Deterministic Copilot: intent classification and templated, cited answers (English / French).

Used when no LLM is configured, when the LLM fails or refuses, when budgets run out
before a usable answer, or when post-validation leaves no cited fact. It calls the
same read-only tools as the LLM path (through the engine's runner, so budgets, traces
and refs are identical) and every factual sentence it writes carries citations, which
the engine validates again.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Callable

from aegis.copilot.datasource import CopilotDataSource
from aegis.copilot.models import AnswerSentence, Citation, Language
from aegis.copilot.tools import ToolOutput
from aegis.oracle.tools import sanitize_text

#: ``run(tool_name, args) -> ToolOutput | None`` (None: tool failed or budget exhausted).
ToolRunner = Callable[[str, dict[str, Any]], ToolOutput | None]

_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_CAMPAIGN = re.compile(r"\brc-[0-9a-f]{20}\b")
_SEQ = re.compile(r"(?:\bseq(?:uence)?\b|\bentry\b|\bentree\b|#)\s*(\d{1,12})\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b")
_LABEL = re.compile(r"\b([a-z0-9]+(?:_[a-z0-9]+)+)\b")
_HOURS = re.compile(r"\b(\d{1,4})\s*(h|hours?|heures?)\b")
_DAYS = re.compile(r"\b(\d{1,3})\s*(d|days?|jours?)\b")

_FR_HINTS = frozenset(
    "le la les des du une un est sont pourquoi combien quels quelles quel quelle dossier dossiers preuve preuves "
    "campagne campagnes ralenti ralentie sante etat montre donne resume appareil appareils alertes depuis dernieres "
    "derniere aujourd hui semaine que qui quoi comment avec sur pour dans registre graphe voisins simuler "
    "malveillant malveillants suspect suspects detections constat constats".split())
_EN_HINTS = frozenset(
    "the is are why how many what which show give case cases evidence campaign campaigns slow slowed down health "
    "status summary device devices alerts findings did since last today week with for about ledger graph "
    "neighbors simulate malicious suspicious overview".split())

_INTENTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ingest", re.compile(r"\b(ingest\w*|slow\w*|lent\w*|ralenti\w*|throughput|debit|latenc\w*|backlog|"
                          r"pipeline|collector\w*|collecteur\w*|retard\w*|delay\w*|quarantin\w*)\b")),
    ("health", re.compile(r"\b(health\w*|sante|status|statut|ready|readiness|etat de la plateforme|"
                          r"breaker|disjoncteur|uptime|database|base de donnees|platform|plateforme)\b")),
    ("campaigns", re.compile(r"\b(campaign\w*|campagne\w*|resonance|botnet\w*|beacon\w*|balise\w*|timer)\b")),
    ("ledger", re.compile(r"\b(ledger|registre|audit|hash chain|chaine|integrity|integrite|provenance|tamper\w*)\b")),
    ("simulate", re.compile(r"\b(simulat\w*|simuler|impact|what if|collateral|collateraux|que se passerait)\b")),
    ("graph", re.compile(r"\b(graph\w*|graphe|neighbou?rs?|voisins?|related|lie[se]?|infrastructure|hosting|"
                         r"hebergement|resolves?|constellation)\b")),
    ("cases", re.compile(r"\b(cases?|dossiers?|investigation\w*|enquete\w*|verified|verifie\w*)\b")),
    ("findings", re.compile(r"\b(findings?|alerts?|alertes?|detections?|constats?|malicious|malveillant\w*|"
                            r"suspicious|suspect\w*|devices?|appareils?|abstain\w*|benign|benin\w*)\b")),
    ("overview", re.compile(r"\b(metrics?|metriques?|summary|resume|overview|apercu|statistics?|statistiques?|"
                            r"how many|combien|kpi)\b")),
)

_VERDICT_WORDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("malicious", re.compile(r"\b(malicious|malveillant\w*)\b")),
    ("suspicious", re.compile(r"\b(suspicious|suspect\w*)\b")),
    ("abstain", re.compile(r"\b(abstain\w*|abstention\w*)\b")),
    ("benign", re.compile(r"\b(benign|benin\w*)\b")),
)


def _fold(text: str) -> str:
    """Lowercase, accents removed, typographic apostrophes normalized."""
    t = unicodedata.normalize("NFKD", text.replace("’", "'"))
    return "".join(c for c in t if not unicodedata.combining(c)).lower()


def detect_language(question: str) -> Language:
    folded = _fold(question)
    words = re.findall(r"[a-z]+", folded)
    fr = sum(w in _FR_HINTS for w in words) + 2 * len(re.findall(r"[àâçéèêëîïôûùüÿœ]", question.lower()))
    fr += 2 * len(re.findall(r"\b(?:qu|l|d|n|j|c)'", folded))
    en = sum(w in _EN_HINTS for w in words)
    return "fr" if fr > en else "en"


@dataclass
class Intent:
    name: str
    language: Language
    ids: dict[str, list[str]] = field(default_factory=dict)       # resolved kind -> ids
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    verdict: str | None = None
    label: str | None = None
    since_hours: float | None = None
    seq: int | None = None


def classify(question: str, ds: CopilotDataSource, tenant_id: str) -> Intent:
    """Deterministic intent + entities. Ids are resolved only within ``tenant_id``."""
    lang = detect_language(question)
    folded = _fold(question)
    ids: dict[str, list[str]] = {}
    for raw in dict.fromkeys(m.lower() for m in _UUID.findall(question)):
        for kind in ("case", "finding", "evidence", "action"):
            if ds.exists(tenant_id, kind, raw):
                ids.setdefault(kind, []).append(raw)
                break
        else:
            ids.setdefault("unknown", []).append(raw)
    for cid in dict.fromkeys(_CAMPAIGN.findall(folded)):
        ids.setdefault("campaign", []).append(cid)
    ips = [ip for ip in dict.fromkeys(_IPV4.findall(folded)) if _valid_ip(ip)]
    domains = [d for d in dict.fromkeys(_DOMAIN.findall(_CAMPAIGN.sub(" ", _UUID.sub(" ", folded))))
               if not _IPV4.fullmatch(d) and not re.fullmatch(r"(?:e\.g|i\.e|p\.ex)", d)]
    seq_m = _SEQ.search(folded)
    verdict = next((v for v, rx in _VERDICT_WORDS if rx.search(folded)), None)
    label_m = _LABEL.search(folded)
    since: float | None = None
    if (m := _HOURS.search(folded)) is not None:
        since = float(m.group(1))
    elif (m := _DAYS.search(folded)) is not None:
        since = float(m.group(1)) * 24
    elif re.search(r"\b(today|aujourd'hui|24h)\b", folded):
        since = 24.0
    elif re.search(r"\b(this week|cette semaine|7 ?days|7 ?jours)\b", folded):
        since = 168.0

    name = "overview"
    keyword = next((n for n, rx in _INTENTS if rx.search(folded)), None)
    if keyword == "simulate" and (ids.get("action") or ids.get("case")):
        name = "simulate"
    elif ids.get("case"):
        name = "case"
    elif ids.get("finding"):
        name = "finding"
    elif ids.get("evidence"):
        name = "evidence"
    elif ids.get("action"):
        name = "simulate"
    elif ids.get("campaign"):
        name = "campaigns"
    elif keyword is not None:
        name = keyword
    elif seq_m is not None:
        name = "ledger"
    elif domains or ips:
        name = "graph"
    if name == "graph" and not (domains or ips) and keyword != "graph":
        name = "overview"
    return Intent(name=name, language=lang, ids=ids, domains=domains, ips=ips, verdict=verdict,
                  label=label_m.group(1) if label_m else None, since_hours=since,
                  seq=int(seq_m.group(1)) if seq_m else None)


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return False
    return True


# ============================================================================ templates

_T: dict[str, dict[Language, str]] = {
    "overview": {"en": "This tenant has {findings} findings ({verdicts}) and {cases} cases, {open} of them open.",
                 "fr": "Ce tenant compte {findings} constats ({verdicts}) et {cases} dossiers, dont {open} ouverts."},
    "coverage": {"en": "Coverage in the current period: {devices} devices observed over {dd} device-days.",
                 "fr": "Couverture sur la période en cours : {devices} appareils observés sur {dd} appareils-jours."},
    "platform": {"en": "Detector {dv}; ML model {model}; enforcement adapter {adapter}; live enforcements: {live}.",
                 "fr": "Détecteur {dv} ; modèle ML {model} ; adaptateur d'application {adapter} ; "
                       "mesures actives : {live}."},
    "top": {"en": "Most recent alert findings:", "fr": "Constats d'alerte les plus récents :"},
    "finding": {"en": "Finding {id}: {label} on device {entity}, verdict {verdict}, score {score} ({kind}), "
                      "status {status}.",
                "fr": "Constat {id} : {label} sur l'appareil {entity}, verdict {verdict}, score {score} ({kind}), "
                      "statut {status}."},
    "finding_expl": {"en": "Detector explanation: \"{text}\".", "fr": "Explication du détecteur : « {text} »."},
    "findings_total": {"en": "{total} findings match{filters}; showing {shown}.",
                       "fr": "{total} constats correspondent{filters} ; {shown} affichés."},
    "findings_none": {"en": "No findings match{filters}.", "fr": "Aucun constat ne correspond{filters}."},
    "cases_total": {"en": "{total} cases match{filters}; showing {shown}.",
                    "fr": "{total} dossiers correspondent{filters} ; {shown} affichés."},
    "cases_none": {"en": "No cases match{filters}.", "fr": "Aucun dossier ne correspond{filters}."},
    "case_line": {"en": "Case {id} \"{title}\": state {state}, severity {severity}.",
                  "fr": "Dossier {id} « {title} » : état {state}, sévérité {severity}."},
    "case_hyp": {"en": "Hypothesis on record: \"{text}\".", "fr": "Hypothèse enregistrée : « {text} »."},
    "case_alts": {"en": "Alternative hypotheses on record: {text}.",
                  "fr": "Hypothèses alternatives enregistrées : {text}."},
    "case_origins": {"en": "Qualifying evidence comes from {n} independent origin(s); {c} contradicting origin(s).",
                     "fr": "Les preuves recevables proviennent de {n} origine(s) indépendante(s) ; "
                           "{c} origine(s) contradictoire(s)."},
    "case_blockers": {"en": "Blockers to verification: {text}.", "fr": "Obstacles à la vérification : {text}."},
    "case_ready": {"en": "The evidence alone meets the verification evidence rule; a human review is still required.",
                   "fr": "Les preuves seules satisfont la règle de vérification ; une revue humaine reste requise."},
    "case_inv": {"en": "Latest investigation recommendation: {rec}.",
                 "fr": "Dernière recommandation d'investigation : {rec}."},
    "case_action": {"en": "Proposed action {id}: {type} on {targets}.",
                    "fr": "Action proposée {id} : {type} sur {targets}."},
    "evidence": {"en": "Evidence {id} (kind {kind}) comes from {origin} (independence group {group}), {dir}.",
                 "fr": "La preuve {id} (type {kind}) provient de {origin} (groupe d'indépendance {group}), {dir}."},
    "ev_support": {"en": "supporting the hypothesis", "fr": "à l'appui de l'hypothèse"},
    "ev_counter": {"en": "counter-evidence", "fr": "contre-preuve"},
    "ev_summary": {"en": "Its summary reads: \"{text}\".", "fr": "Son résumé indique : « {text} »."},
    "ev_integrity_ok": {"en": "Its integrity hash verifies.", "fr": "Son empreinte d'intégrité est vérifiée."},
    "ev_integrity_bad": {"en": "Its integrity check FAILED; do not rely on it.",
                         "fr": "Son contrôle d'intégrité a ÉCHOUÉ ; ne pas s'y fier."},
    "ev_superseded": {"en": "It has been superseded by evidence {id}.", "fr": "Elle a été remplacée par la preuve {id}."},
    "camp_none": {"en": "No RESONANCE campaigns are recorded for this tenant.",
                  "fr": "Aucune campagne RESONANCE n'est enregistrée pour ce tenant."},
    "camp": {"en": "Campaign {id}: {n} lines toward {dest}, period {period}, q = {q} (target {qt}).",
             "fr": "Campagne {id} : {n} lignes vers {dest}, période {period}, q = {q} (cible {qt})."},
    "camp_elig": {"en": "Enforcement eligible: {elig}{extra}.", "fr": "Éligible à l'application : {elig}{extra}."},
    "camp_caveat": {"en": "A q-value shows that unrelated lines share a timer toward a destination, not that it is "
                          "malicious; these findings require analyst review.",
                    "fr": "Une valeur q montre que des lignes indépendantes partagent une minuterie vers une "
                          "destination, pas qu'elle est malveillante ; ces constats exigent une revue d'analyste."},
    "graph": {"en": "Node {id} ({type}) has {deg} neighbors; shared hosting: {shared}.",
              "fr": "Le nœud {id} ({type}) a {deg} voisins ; hébergement partagé : {shared}."},
    "edge": {"en": "{src} -{edge}-> {dst} (grade {grade}, enforcement eligible: {elig}).",
             "fr": "{src} -{edge}-> {dst} (niveau {grade}, éligible à l'application : {elig})."},
    "graph_missing": {"en": "I could not find {node} in this tenant's graph.",
                      "fr": "Je n'ai pas pu trouver {node} dans le graphe de ce tenant."},
    "ledger_ok": {"en": "Ledger chain verification passed: {n} entries checked, {s} signed.",
                  "fr": "La vérification de la chaîne du registre a réussi : {n} entrées vérifiées, {s} signées."},
    "ledger_bad": {"en": "Ledger chain verification FAILED at entry {seq} ({reason}).",
                   "fr": "La vérification de la chaîne du registre a ÉCHOUÉ à l'entrée {seq} ({reason})."},
    "ledger_entry": {"en": "Entry #{seq}: {type} for {subject}, recorded {at}.",
                     "fr": "Entrée n°{seq} : {type} pour {subject}, enregistrée le {at}."},
    "ledger_audit_only": {"en": "Raw ledger entries are available to audit-privileged users only.",
                          "fr": "Les entrées brutes du registre sont réservées aux utilisateurs habilités à l'audit."},
    "ingest_insufficient": {"en": "There is not enough ingest history to compare trends ({n} batches recorded).",
                            "fr": "L'historique d'ingestion est insuffisant pour comparer les tendances "
                                  "({n} lots enregistrés)."},
    "ingest_none": {"en": "Compared with earlier batches, the last {n} batches show no rise in lag, batch interval, "
                          "volume, quarantine or duplicate rates.",
                    "fr": "Par rapport aux lots précédents, les {n} derniers lots ne montrent aucune hausse du "
                          "retard, de l'intervalle entre lots, du volume, de la quarantaine ou des doublons."},
    "ingest_method": {"en": "Per-batch processing time is not recorded in the ledger, so lag and cadence are proxies.",
                      "fr": "La durée de traitement par lot n'est pas enregistrée dans le registre ; le retard et "
                            "la cadence servent d'indicateurs."},
    "ingest_live": {"en": "Right now {inflight} events are in flight for this tenant and {q} records have been "
                          "quarantined{reasons}.",
                    "fr": "Actuellement {inflight} événements sont en cours pour ce tenant et {q} enregistrements "
                          "ont été mis en quarantaine{reasons}."},
    "health": {"en": "Platform ready: {ready}; database {db}; model {model}; LLM {llm}; adapter {adapter}; "
                     "circuit breaker {breaker}.",
               "fr": "Plateforme prête : {ready} ; base de données {db} ; modèle {model} ; LLM {llm} ; "
                     "adaptateur {adapter} ; disjoncteur {breaker}."},
    "health_tenant": {"en": "This tenant has {sources} source(s), IOC bundle {ioc}, topology {topo}, {q} quarantined "
                            "records and {inflight} events in flight.",
                      "fr": "Ce tenant a {sources} source(s), lot d'IOC {ioc}, topologie {topo}, {q} enregistrements "
                            "en quarantaine et {inflight} événements en cours."},
    "sim": {"en": "Read-only simulation of {type} on {targets}: verdict {verdict}, affected entities {aff}, shared "
                  "infrastructure {shared}, reversibility {rev}, human approval {approval}.",
            "fr": "Simulation en lecture seule de {type} sur {targets} : verdict {verdict}, entités affectées {aff}, "
                  "infrastructure partagée {shared}, réversibilité {rev}, approbation humaine {approval}."},
    "sim_unknowns": {"en": "Open unknowns: {text}.", "fr": "Inconnues : {text}."},
    "sim_note": {"en": "Nothing was proposed, stored, authorized or executed.",
                 "fr": "Rien n'a été proposé, enregistré, autorisé ni exécuté."},
    "sim_need": {"en": "To simulate, give an action id, or a case id with a domain or IP target.",
                 "fr": "Pour simuler, indiquez un identifiant d'action, ou un identifiant de dossier avec un "
                       "domaine ou une IP cible."},
    "graph_need": {"en": "Name a domain or IP address to explore the infrastructure graph.",
                   "fr": "Indiquez un domaine ou une adresse IP pour explorer le graphe d'infrastructure."},
    "unavailable": {"en": "I could not retrieve this information within the available budget.",
                    "fr": "Je n'ai pas pu obtenir cette information dans le budget disponible."},
    "unknown_ids": {"en": "I could not find these ids in this tenant: {ids}.",
                    "fr": "Je n'ai pas pu trouver ces identifiants dans ce tenant : {ids}."},
    "required": {"en": "required", "fr": "requise"},
    "not_required": {"en": "not required", "fr": "non requise"},
    "yes": {"en": "yes", "fr": "oui"},
    "no": {"en": "no", "fr": "non"},
    "none": {"en": "none", "fr": "aucun"},
    "domain_only": {"en": "; domain only (shared hosting, never the IPs)",
                    "fr": "; domaine uniquement (hébergement partagé, jamais les IP)"},
    "topo_unknown": {"en": "; topology unknown, so not eligible (fail closed)",
                     "fr": "; topologie inconnue, donc non éligible (échec fermé)"},
}

_CODES: dict[str, dict[Language, str]] = {
    "processing_time_up": {"en": "Median per-batch processing time rose from {b} s to {r} s.",
                           "fr": "La durée médiane de traitement par lot est passée de {b} s à {r} s."},
    "lag_up": {"en": "Median delay between observed events and recording rose from {b} s to {r} s.",
               "fr": "Le retard médian entre les événements observés et leur enregistrement est passé de {b} s à "
                     "{r} s."},
    "cadence_down": {"en": "Batches arrive less often: median interval rose from {b} s to {r} s.",
                     "fr": "Les lots arrivent moins souvent : l'intervalle médian est passé de {b} s à {r} s."},
    "volume_up": {"en": "Batches are larger: median records per batch rose from {b} to {r}, which takes longer to "
                        "process.",
                  "fr": "Les lots sont plus gros : le nombre moyen d'enregistrements par lot est passé de {b} à {r}, "
                        "ce qui allonge le traitement."},
    "quarantine_up": {"en": "The quarantine rate rose from {b} to {r} of records (invalid input from collectors).",
                      "fr": "Le taux de quarantaine est passé de {b} à {r} des enregistrements (entrées invalides "
                            "des collecteurs)."},
    "duplicates_up": {"en": "The duplicate rate rose from {b} to {r} of records (collectors re-sending data).",
                      "fr": "Le taux de doublons est passé de {b} à {r} des enregistrements (collecteurs qui "
                            "renvoient des données)."},
}


class _Builder:
    def __init__(self, lang: Language, run: ToolRunner, allowed: frozenset[str]):
        self.lang = lang
        self.run = run
        self.allowed = allowed
        self.out: list[AnswerSentence] = []

    def t(self, key: str, **kw: Any) -> str:
        return _T[key][self.lang].format(**kw)

    def fact(self, text: str, *refs: tuple[str, str] | None) -> None:
        cites = []
        for r in refs:
            if r is not None and Citation(kind=r[0], id=r[1]) not in cites:  # type: ignore[arg-type]
                cites.append(Citation(kind=r[0], id=r[1]))  # type: ignore[arg-type]
        self.out.append(AnswerSentence(text=text, citations=cites, status="cited"))

    def note(self, text: str) -> None:
        self.out.append(AnswerSentence(text=text, status="exempt"))

    def yn(self, v: Any) -> str:
        return self.t("yes") if v else self.t("no")


def _ref(out: ToolOutput, kind: str) -> tuple[str, str] | None:
    return next((r for r in out.refs if r[0] == kind), None)


def _quote(v: Any, n: int) -> str:
    """Untrusted text shown as a quotation: sanitized, capped, trailing punctuation removed."""
    return sanitize_text(v, n).rstrip(" .;:")


def _fmt_num(v: Any, digits: int = 2) -> str:
    if isinstance(v, float):
        if v != 0 and (abs(v) < 0.01 or abs(v) >= 1e6):
            return f"{v:.1e}"
        out = f"{v:.{digits}f}"
        return out.rstrip("0").rstrip(".") if "." in out else out
    return "n/a" if v is None else str(v)


def build_answer(intent: Intent, question: str, run: ToolRunner, *,
                 allowed: frozenset[str] | None = None) -> list[AnswerSentence]:
    """Templated answer for ``intent``. Tools are called through ``run`` (budgeted and traced).

    ``allowed`` names the tools the caller may use (``None``: all); handlers skip the others.
    """
    from aegis.copilot.tools import DEFAULT_TOOLS

    b = _Builder(intent.language, run, allowed if allowed is not None else
                 frozenset(t.name for t in DEFAULT_TOOLS))
    if intent.ids.get("unknown"):
        b.note(b.t("unknown_ids", ids=", ".join(intent.ids["unknown"][:5])))
    handler = _HANDLERS.get(intent.name, _overview)
    handler(b, intent)
    if not b.out:
        b.note(b.t("unavailable"))
    return b.out


def _filters_text(b: _Builder, args: dict[str, Any]) -> str:
    parts = [f"{k}={v}" for k, v in args.items() if k != "limit" and v is not None]
    if not parts:
        return ""
    return (" (" if b.lang == "en" else " (") + ", ".join(parts) + ")"


def _finding_lines(b: _Builder, findings: list[dict[str, Any]], limit: int = 5) -> None:
    for f in findings[:limit]:
        ev = f.get("evidence_ids") or []
        b.fact(b.t("finding", id=f["finding_id"], label=f["label"], entity=f["entity_pseudonym"],
                   verdict=f["verdict"], score=_fmt_num(f["score"]), kind=f["score_kind"], status=f["status"]),
               ("finding", f["finding_id"]), ("evidence", ev[0]) if ev else None)


def _overview(b: _Builder, it: Intent) -> None:
    m = b.run("metrics_summary", {})
    if m is not None:
        d, ref = m.data, _ref(m, "metrics")
        fd, cd = d.get("findings", {}), d.get("cases", {})
        verdicts = ", ".join(f"{k} {v}" for k, v in (fd.get("by_verdict") or {}).items()) or b.t("none")
        b.fact(b.t("overview", findings=fd.get("total", 0), verdicts=verdicts, cases=cd.get("total", 0),
                   open=cd.get("open", 0)), ref)
        cov = d.get("coverage") or {}
        if cov:
            b.fact(b.t("coverage", devices=cov.get("devices_observed", 0), dd=cov.get("device_days", 0)), ref)
        b.fact(b.t("platform", dv=d.get("detector_version", "n/a"), model=b.yn(d.get("model_loaded")),
                   adapter=d.get("enforcement_adapter", "n/a"),
                   live=(d.get("actions") or {}).get("live_enforcements", 0)), ref)
    shown: list[dict[str, Any]] = []
    for verdict in ("malicious", "suspicious"):
        if len(shown) >= 3:
            break
        r = b.run("search_findings", {"verdict": verdict, "limit": 3 - len(shown)})
        if r is not None:
            shown += r.data.get("findings", [])
    if shown:
        b.note(b.t("top"))
        _finding_lines(b, shown, 3)


def _findings(b: _Builder, it: Intent) -> None:
    args: dict[str, Any] = {"limit": 5}
    if it.verdict:
        args["verdict"] = it.verdict
    if it.label:
        args["label"] = it.label
    if it.since_hours:
        args["since_hours"] = it.since_hours
    r = b.run("search_findings", args)
    if r is None:
        return
    q = _ref(r, "query")
    flt = _filters_text(b, {k: v for k, v in args.items() if k != "limit"})
    items = r.data.get("findings", [])
    if not items:
        b.fact(b.t("findings_none", filters=flt), q)
        return
    b.fact(b.t("findings_total", total=r.data.get("total_matching"), filters=flt, shown=len(items)), q)
    _finding_lines(b, items)


def _cases(b: _Builder, it: Intent) -> None:
    r = b.run("list_cases", {"limit": 5})
    if r is None:
        return
    q = _ref(r, "query")
    items = r.data.get("cases", [])
    if not items:
        b.fact(b.t("cases_none", filters=""), q)
        return
    b.fact(b.t("cases_total", total=r.data.get("total_matching"), filters="", shown=len(items)), q)
    for c in items:
        b.fact(b.t("case_line", id=c["case_id"], title=c["title"], state=c["state"], severity=c["severity"]),
               ("case", c["case_id"]))


def _case(b: _Builder, it: Intent) -> None:
    cid = it.ids["case"][0]
    r = b.run("get_case", {"case_id": cid})
    if r is None:
        return
    d = r.data
    ref = ("case", d["case_id"])
    b.fact(b.t("case_line", id=d["case_id"], title=d["title"], state=d["state"], severity=d["severity"]), ref)
    if d.get("hypothesis"):
        b.fact(b.t("case_hyp", text=_quote(d["hypothesis"], 240)), ref)
    if d.get("alternative_hypotheses"):
        b.fact(b.t("case_alts", text="; ".join(d["alternative_hypotheses"][:4])), ref)
    ea = d.get("evidence_assessment") or {}
    if ea:
        qual = ea.get("qualifying_evidence_ids") or []
        b.fact(b.t("case_origins", n=len(ea.get("supporting_origins") or []),
                   c=len(ea.get("contradicting_origins") or [])), ref, ("evidence", qual[0]) if qual else None)
        blockers = ea.get("verification_blockers") or []
        b.fact(b.t("case_blockers", text=", ".join(blockers)) if blockers else b.t("case_ready"), ref)
    inv = d.get("investigation")
    if isinstance(inv, dict) and inv.get("recommendation"):
        b.fact(b.t("case_inv", rec=inv["recommendation"]), ref)
    for a in d.get("actions", [])[:3]:
        b.fact(b.t("case_action", id=a["action_id"], type=a["action_type"], targets=", ".join(a["targets"][:3])),
               ("action", a["action_id"]), ref)
    for eid in (d.get("evidence_ids") or [])[:2]:
        _evidence_lines(b, eid, brief=True)


def _finding(b: _Builder, it: Intent) -> None:
    r = b.run("get_finding", {"finding_id": it.ids["finding"][0]})
    if r is None:
        return
    _finding_lines(b, [r.data])
    if r.data.get("explanation"):
        b.fact(b.t("finding_expl", text=_quote(r.data["explanation"], 300)), ("finding", r.data["finding_id"]))
    for eid in (r.data.get("evidence_ids") or [])[:2]:
        _evidence_lines(b, eid, brief=True)


def _evidence_lines(b: _Builder, eid: str, *, brief: bool = False) -> None:
    r = b.run("get_evidence", {"evidence_id": eid})
    if r is None:
        return
    d = r.data
    ref = ("evidence", d["evidence_id"])
    b.fact(b.t("evidence", id=d["evidence_id"], kind=d["kind"], origin=d["origin_source"],
               group=d["source_independence_group"], dir=b.t("ev_support") if d["supports"] else b.t("ev_counter")),
           ref)
    b.fact(b.t("ev_summary", text=_quote(d.get("summary"), 200)), ref)
    if not brief or not d.get("integrity_verified"):
        b.fact(b.t("ev_integrity_ok") if d.get("integrity_verified") else b.t("ev_integrity_bad"), ref)
    if isinstance(d.get("superseded_by"), str):
        b.fact(b.t("ev_superseded", id=d["superseded_by"]), ref, ("evidence", d["superseded_by"]))


def _evidence(b: _Builder, it: Intent) -> None:
    _evidence_lines(b, it.ids["evidence"][0])


def _campaigns(b: _Builder, it: Intent) -> None:
    r = b.run("list_campaigns", {"limit": 10})
    if r is None:
        return
    q = _ref(r, "query")
    rows = r.data.get("campaigns", [])
    wanted = set(it.ids.get("campaign", []))
    if wanted:
        rows = [c for c in rows if c["campaign_id"] in wanted]
    if not rows:
        b.fact(b.t("camp_none"), q)
        return
    for c in rows[:5]:
        cref = ("campaign", c["campaign_id"])
        ev = ("evidence", c["evidence_id"]) if c.get("evidence_id") else None
        dest = ", ".join(d.split(":", 1)[-1] for d in (c.get("destinations") or [])[:3]) or "n/a"
        period = f"~{_fmt_num(c['period_s'], 0)} s" if isinstance(c.get("period_s"), (int, float)) else "n/a"
        b.fact(b.t("camp", id=c["campaign_id"], n=c.get("n_lines", "n/a"), dest=dest, period=period,
                   q=_fmt_num(c.get("q_value")), qt=_fmt_num(c.get("q_target"))), cref, ev)
        extra = (b.t("domain_only") if c.get("shared_hosting_domain") else "") + (
            b.t("topo_unknown") if c.get("topology_unknown") else "")
        b.fact(b.t("camp_elig", elig=b.yn(c.get("enforcement_eligible")), extra=extra), cref)
    b.fact(b.t("camp_caveat"), q)


def _graph(b: _Builder, it: Intent) -> None:
    candidates = it.domains or it.ips
    if not candidates:
        b.note(b.t("graph_need"))
        return
    node = candidates[0]
    r = b.run("graph_neighbors", {"node": node, "limit": 10})
    if r is None:
        b.note(b.t("graph_missing", node=node))
        return
    d = r.data
    nref = ("node", d["node_id"])
    b.fact(b.t("graph", id=d["node_id"], type=d["node_type"], deg=d.get("degree", 0),
               shared=b.yn(d.get("shared_hosting"))), nref)
    for n in d.get("neighbors", [])[:5]:
        src, dst = (d["node_id"], n["node_id"]) if n["direction"] == "out" else (n["node_id"], d["node_id"])
        b.fact(b.t("edge", src=src, edge=n["edge_type"], dst=dst, grade=n["evidence_grade"],
                   elig=b.yn(n["enforcement_eligible"])), nref, ("node", n["node_id"]))


def _ledger(b: _Builder, it: Intent) -> None:
    v = b.run("verify_ledger", {})
    if v is not None:
        q = _ref(v, "query")
        if v.data.get("ok"):
            b.fact(b.t("ledger_ok", n=v.data.get("entries_checked", "n/a"), s=v.data.get("signed_entries", "n/a")), q)
        else:
            bad = v.data.get("first_bad_seq")
            b.fact(b.t("ledger_bad", seq=bad, reason=v.data.get("reason")), q,
                   ("ledger", str(bad)) if isinstance(bad, int) else None)
    if "ledger_query" not in b.allowed:
        b.note(b.t("ledger_audit_only"))
        return
    args: dict[str, Any] = {"limit": 5}
    if it.seq is not None:
        args["seq"] = it.seq
    r = b.run("ledger_query", args)
    if r is None:
        return
    for e in r.data.get("entries", [])[:5]:
        b.fact(b.t("ledger_entry", seq=e["seq"], type=e["entry_type"], subject=e["subject_id"],
                   at=str(e["recorded_at"])[:19]), ("ledger", str(e["seq"])))


def _ingest(b: _Builder, it: Intent) -> None:
    r = b.run("ingest_activity", {"batches": 60})
    if r is not None:
        d = r.data
        q = _ref(r, "query")
        if d.get("status") != "ok":
            b.fact(b.t("ingest_insufficient", n=d.get("batches_analyzed", 0)), q)
        else:
            obs = d.get("observations") or []
            if not obs:
                b.fact(b.t("ingest_none", n=(d.get("recent") or {}).get("batches", 0)), q)
            for o in obs:
                tmpl = _CODES.get(o.get("code", ""))
                if tmpl is None:
                    continue
                seqs = [("ledger", str(s)) for s in (o.get("evidence_seqs") or [])[:2]]
                rate = o["code"] in ("quarantine_up", "duplicates_up")
                fmt = (lambda v: f"{v:.1%}") if rate else (lambda v: _fmt_num(v, 0))
                b.fact(tmpl[b.lang].format(b=fmt(o["baseline"]), r=fmt(o["recent"])), q, *seqs)
            b.fact(b.t("ingest_method"), q)
    h = b.run("health_status", {})
    if h is not None:
        t = h.data.get("tenant") or {}
        reasons = t.get("quarantine_reasons") or {}
        top = sorted(reasons.items(), key=lambda kv: -kv[1])[:3]
        rs = (" (" + ", ".join(f"{k}: {v}" for k, v in top) + ")") if top else ""
        b.fact(b.t("ingest_live", inflight=_fmt_num(t.get("bus_inflight")), q=_fmt_num(t.get("quarantined")),
                   reasons=rs), _ref(h, "health"))


def _health(b: _Builder, it: Intent) -> None:
    h = b.run("health_status", {})
    if h is None:
        return
    ref = _ref(h, "health")
    c = h.data.get("checks") or {}
    b.fact(b.t("health", ready=b.yn(h.data.get("ready")), db=c.get("database", "n/a"), model=c.get("model", "n/a"),
               llm=c.get("llm", "n/a"), adapter=c.get("enforcement_adapter", "n/a"),
               breaker=c.get("circuit_breaker", "n/a")), ref)
    t = h.data.get("tenant") or {}
    ioc = (t.get("ioc_bundle") or {}).get("bundle_id") if isinstance(t.get("ioc_bundle"), dict) else None
    topo = (t.get("topology") or {}).get("topology_id") if isinstance(t.get("topology"), dict) else None
    b.fact(b.t("health_tenant", sources=len(t.get("sources") or []), ioc=ioc or b.t("none"), topo=topo or b.t("none"),
               q=_fmt_num(t.get("quarantined")), inflight=_fmt_num(t.get("bus_inflight"))), ref)


def _simulate(b: _Builder, it: Intent) -> None:
    args: dict[str, Any]
    if it.ids.get("action"):
        args = {"action_id": it.ids["action"][0]}
    elif it.ids.get("case") and (it.domains or it.ips):
        if it.domains:
            args = {"case_id": it.ids["case"][0], "action_type": "dns_sinkhole", "targets": it.domains[:3]}
        else:
            args = {"case_id": it.ids["case"][0], "action_type": "ip_block", "targets": it.ips[:3]}
    else:
        b.note(b.t("sim_need"))
        return
    r = b.run("simulate_action_readonly", args)
    if r is None:
        return
    d = r.data
    refs = [_ref(r, "query"), ("case", d["case_id"])]
    if d.get("action_id"):
        refs.append(("action", d["action_id"]))
    b.fact(b.t("sim", type=d["action_type"], targets=", ".join(d["targets"][:3]), verdict=d["verdict"],
               aff=_fmt_num(d.get("affected_entities")), shared=b.yn(d.get("shared_infrastructure")),
               rev=d.get("reversibility"),
               approval=b.t("required") if d.get("requires_human_approval") else b.t("not_required")), *refs)
    if d.get("unknowns"):
        b.fact(b.t("sim_unknowns", text=", ".join(d["unknowns"][:5])), refs[0])
    b.fact(b.t("sim_note"), refs[0])


_HANDLERS: dict[str, Callable[[_Builder, Intent], None]] = {
    "overview": _overview, "findings": _findings, "cases": _cases, "case": _case, "finding": _finding,
    "evidence": _evidence, "campaigns": _campaigns, "graph": _graph, "ledger": _ledger, "ingest": _ingest,
    "health": _health, "simulate": _simulate,
}
