"""Box Lab verdict: a pre-registered, deterministic policy over one device's evidence.

The policy is deliberately conservative; it never declares a device clean.

* ``ABSTAIN`` (insufficient capture): shorter than ``MIN_SPAN_H`` hours or fewer than
  ``MIN_EVENTS`` events. Nothing is concluded.
* ``MALICIOUS``: at least one *witness* feed match (signed, active, malicious,
  verified contact, uncontradicted enough, see :mod:`.infra`) with confidence at least
  ``MALICIOUS_MIN_CONFIDENCE``, **and** behavior from the capture: a timer on that same
  destination, or a *behavioral* SENTINEL alert (one not produced by SENTINEL's own
  indicator rules F1/F2, which read the same feed and so are not a second witness),
  **and** at least two independent origins (the capture is one origin; feeds
  syndicating one report share one origin). This is the "two independent witnesses"
  rule.
* ``SUSPICIOUS``: one strong signal: a witness feed match, or a SENTINEL ``MALICIOUS``
  / ``SUSPICIOUS`` finding.
* ``ABSTAIN`` otherwise, listing any weak signals worth a look (timers that keep running
  while idle, NXDOMAIN bursts, addresses contacted without lookup, external resolvers,
  unverified local-list hits). A timer alone is never an accusation: benign services
  poll too.

``BENIGN`` is never produced: one capture of one device cannot show that it is clean.
Every verdict ``requires_review`` and carries its caveats. Scores are not computed:
nothing here is a probability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from aegis.contracts.models import Finding, Verdict
from aegis.homelab.infra import InfraSummary
from aegis.homelab.timers import TimerAnalysis

POLICY_VERSION = "homelab-verdict/1.0.0"
MIN_SPAN_H = 6.0
MIN_EVENTS = 20
MALICIOUS_MIN_CONFIDENCE = 0.7
NXDOMAIN_BURST = 20
CAPTURE_ORIGIN = "operator-telemetry"      # same independence group SENTINEL uses for capture-derived evidence
#: SENTINEL fusion rules driven by indicator hits (the feed itself): not behavioral corroboration
IOC_RULES = frozenset({"F1", "F2", "F7"})

STANDARD_CAVEATS = (
    "One capture of one device in one home: a single vantage point. Nothing here is proof of compromise "
    "or of who is responsible.",
    "Metadata only (headers, flow records, resolver log): payloads were not captured or inspected.",
    "Timers are common in benign software (time sync, connectivity checks, push, telemetry); "
    "a timer is a reason to look, not a finding.",
    "Device class, vendor, apps used and geography were not used as evidence.",
    "No verdict here says the device is clean: absence of evidence in one capture is not evidence of absence.",
)


@dataclass
class BoxVerdict:
    entity_pseudonym: str
    verdict: Verdict
    headline: str
    reasons: list[str]
    signals: list[str]
    caveats: list[str]
    independent_origins: int
    origins: list[str]
    requires_review: bool = True
    policy_version: str = POLICY_VERSION
    evidence_ids: list[str] = field(default_factory=list)
    counterevidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"entity_pseudonym": self.entity_pseudonym, "verdict": self.verdict.value, "headline": self.headline,
                "reasons": self.reasons, "signals": self.signals, "caveats": self.caveats,
                "independent_origins": self.independent_origins, "origins": self.origins,
                "requires_review": self.requires_review, "policy_version": self.policy_version,
                "evidence_ids": self.evidence_ids, "counterevidence_ids": self.counterevidence_ids}


def _indicator_driven(rule: str | None) -> bool:
    """SENTINEL fusion rule ids look like ``F1_ioc_corroborated``; unknown counts as indicator-driven."""
    if not rule:
        return True
    return rule.split("_", 1)[0] in IOC_RULES or rule == "unknown"


def decide(*, entity_pseudonym: str, span_s: float, n_events: int, timers: TimerAnalysis, infra: InfraSummary,
           sentinel_findings: list[Finding], sentinel_rules: Mapping[str, str] | None = None,
           sentinel_model_note: str | None = None, synthetic: bool = False) -> BoxVerdict:
    """Apply the pre-registered policy (see module docstring).

    ``sentinel_rules`` maps finding ids to the SENTINEL fusion rule that produced them; a
    finding without a known rule is treated as indicator-driven (conservative).
    """
    caveats = list(STANDARD_CAVEATS)
    if synthetic:
        caveats.insert(0, "SYNTHETIC capture: generated data of a fictional device, for demonstration only.")
    if sentinel_model_note:
        caveats.append(sentinel_model_note)
    caveats.extend(timers.notes)
    if infra.bundle is None:
        caveats.append("No signed threat feed was loaded: known-infrastructure matching was not performed.")

    signals: list[str] = []
    idle = timers.idle_timers()
    for c in idle:
        signals.append(f"timer to {c.display} (~{c.period_s:.0f} s) keeps running while the device is idle")
    if len(infra.nxdomain_names) >= NXDOMAIN_BURST:
        signals.append(f"{len(infra.nxdomain_names)} distinct non-existent names looked up (NXDOMAIN)")
    no_lookup = [d for d in infra.destinations if d.contacted_without_lookup]
    if no_lookup:
        signals.append(f"{len(no_lookup)} address(es) contacted without a lookup seen in the capture")
    if infra.external_resolvers:
        signals.append(f"DNS sent to resolver(s) other than the lab resolver: {', '.join(infra.external_resolvers)}")
    local_hits = [m for d in infra.destinations for m in d.matches if m.feed_kind == "unverified_local_list"]
    if local_hits:
        signals.append(f"{len(local_hits)} hit(s) on the unverified local list (orientation only, not evidence)")
    for m in infra.weak_matches:
        why = "contradicted" if m.contradicted else ("lookup only, no traffic" if not m.verified_contact
                                                     else "low confidence")
        signals.append(f"weak feed match on {m.value} ({m.source}, {why})")

    if span_s < MIN_SPAN_H * 3600 or n_events < MIN_EVENTS:
        return BoxVerdict(entity_pseudonym, Verdict.ABSTAIN, "Not enough data to say anything",
                          [f"capture of {span_s / 3600:.1f} h with {n_events} events is below the minimum "
                           f"({MIN_SPAN_H:g} h, {MIN_EVENTS} events)"], signals, caveats, 0, [])

    witnesses = infra.witness_matches
    alerts = [f for f in sentinel_findings if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]
    rules = sentinel_rules or {}
    behavioral = [f for f in alerts if not _indicator_driven(rules.get(f.finding_id))]
    timer_keys = {c.key for c in timers.timers}
    corroborated = []
    timer_corroborated = False
    for m in witnesses:
        on_dest = [d for d in infra.destinations if m in d.matches]
        on_timer = any(d.key in timer_keys for d in on_dest)
        timer_corroborated |= on_timer
        if (on_timer or behavioral) and (m.effective_confidence or 0.0) >= MALICIOUS_MIN_CONFIDENCE:
            corroborated.append(m)
    # origins *supporting the accusation*: the feeds behind witness matches, the capture's own behavior
    # when it corroborates, and for indicator-driven SENTINEL alerts the feeds they read
    origin_set = {m.source_group for m in witnesses}
    if behavioral or timer_corroborated:
        origin_set.add(CAPTURE_ORIGIN)
    if alerts and not behavioral and not witnesses:
        origin_set |= {m.source_group for m in infra.weak_matches}
    all_origins = sorted(origin_set)
    reasons: list[str] = []
    if corroborated and len(all_origins) >= 2:
        for m in corroborated:
            reasons.append(f"{m.value} is listed as {m.threat_label or 'malicious'} by {m.source} "
                           f"(group {m.source_group}, confidence {m.effective_confidence:.2f}) and the device "
                           "contacted it with a matching behavior in this capture")
        return BoxVerdict(entity_pseudonym, Verdict.MALICIOUS,
                          "Behavior consistent with known malicious infrastructure (needs human review)",
                          reasons, signals, caveats, len(all_origins), all_origins)
    if witnesses or alerts:
        for m in witnesses:
            reasons.append(f"verified contact with {m.value}, listed by {m.source} (group {m.source_group}, "
                           f"confidence {m.effective_confidence:.2f})")
        for f in alerts:
            rule = rules.get(f.finding_id) or "unknown rule"
            kind = "indicator-driven" if _indicator_driven(rules.get(f.finding_id)) else "behavioral"
            reasons.append(f"SENTINEL {f.verdict.value} finding '{f.label}' ({kind}, fusion rule {rule}, "
                           f"score {f.score:.2f}, {'calibrated' if f.calibration_id else 'not a probability'})")
        return BoxVerdict(entity_pseudonym, Verdict.SUSPICIOUS, "Suspicious: one strong signal, not corroborated",
                          reasons, signals, caveats, len(all_origins), all_origins)
    headline = "No conclusion: weak signals worth a look" if signals else "No conclusion: no signal in this capture"
    reasons.append("no witness feed match and no SENTINEL alert; a single capture cannot establish that the "
                   "device is clean")
    return BoxVerdict(entity_pseudonym, Verdict.ABSTAIN, headline, reasons, signals, caveats, 0, [])


__all__ = ["BoxVerdict", "MIN_EVENTS", "MIN_SPAN_H", "POLICY_VERSION", "STANDARD_CAVEATS", "decide"]
