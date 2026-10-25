"""Behavior typing and human-readable explanations for Sentinel findings.

The behavior label of a finding is assigned deterministically from the threat
labels of supporting indicators and the window's behavioral features; the most
specific candidate wins (DGA, DDoS bot, residential proxy, C2 beaconing, then
other indicator labels, then "suspicious_activity"). The device class is mentioned for context only and the
explanation states explicitly that it was not used as evidence.
"""
from __future__ import annotations

import math
from collections import Counter
from typing import Any, Sequence

from aegis.contracts.models import Evidence, FeatureVector, Verdict
from aegis.sentinel.anomaly import AnomalyScore, ChangePoint
from aegis.sentinel.features import FEATURE_DOCS
from aegis.sentinel.fusion import FusionResult

LABEL_DGA = "dga_activity"
LABEL_DDOS = "ddos_bot"
LABEL_PROXY = "residential_proxy"
LABEL_C2 = "c2_beaconing"
LABEL_GENERIC = "suspicious_activity"

_SPECIFICITY = (LABEL_DGA, LABEL_DDOS, LABEL_PROXY, LABEL_C2)

_LABEL_TEXT = {
    LABEL_DGA: "algorithmically generated domain lookups (DGA)",
    LABEL_DDOS: "DDoS-bot behavior (scanning / flooding)",
    LABEL_PROXY: "residential-proxy relaying",
    LABEL_C2: "command-and-control beaconing",
    LABEL_GENERIC: "suspicious network behavior",
}


def _v(fv: FeatureVector, name: str) -> float | None:
    x = fv.values.get(name)
    return None if x is None or fv.missing.get(name, False) else float(x)


def behavior_label(fv: FeatureVector, hits: Sequence[Evidence] = ()) -> tuple[str, list[str]]:
    """Behavior type of a window and the observations that support it."""
    labels: Counter[str] = Counter()
    for e in hits:
        if e.supports:
            for lab in e.payload.get("threat_labels", []) or []:
                labels[lab] += 1
    why: list[str] = []
    nx_u, nx_r = _v(fv, "nx_unique"), _v(fv, "nxdomain_rate")
    zero, pps = _v(fv, "zero_reply_frac"), _v(fv, "peak_out_pps_log")
    cv, prev = _v(fv, "beacon_robust_cv"), _v(fv, "beacon_dst_prevalence")
    rare_q, udst = _v(fv, "rare_qname_frac"), _v(fv, "unique_dst_ip")
    if nx_u is not None and nx_r is not None and nx_u >= 20 and nx_r >= 0.2:
        why.append(f"{int(nx_u)} distinct non-existent domains looked up ({nx_r:.0%} of queries NXDOMAIN)")
        behavior = LABEL_DGA
    elif (zero is not None and zero >= 0.1) or (pps is not None and pps >= 2.9):
        if zero is not None and zero >= 0.1:
            why.append(f"{zero:.0%} of connections got no reply (scanning)")
        if pps is not None and pps >= 2.9:
            why.append(f"outbound burst peaking at {10 ** pps - 1:,.0f} packets/s")
        behavior = LABEL_DDOS
    elif udst is not None and udst >= 60 and (rare_q is None or rare_q < 0.2):
        why.append(f"{int(udst)} distinct destinations relayed to")
        behavior = LABEL_PROXY
    elif cv is not None and cv <= 0.35 and (prev is None or prev <= 0.05):
        period = _v(fv, "beacon_period_log")
        txt = f"periodic check-ins every ~{10 ** period:,.0f}s (robust CV {cv:.2f})" if period is not None \
            else f"periodic check-ins (robust CV {cv:.2f})"
        if prev is not None:
            txt += f" to a destination only {prev:.1%} of devices contact"
        why.append(txt)
        behavior = LABEL_C2
    else:
        behavior = LABEL_GENERIC
    # the most specific of the indicator labels and the behavioral type wins:
    # a DGA bot or a proxy usually also beacons to its C2
    candidates = set(labels) | {behavior}
    for lab in _SPECIFICITY:
        if lab in candidates:
            return lab, why
    return (labels.most_common(1)[0][0] if labels else behavior), why


def _fmt_contrib(c: dict[str, Any]) -> str:
    name = str(c["feature"])
    sign = "+" if c["contribution"] > 0 else "-"
    if name.startswith("missing__"):
        return f"{sign}{name.removeprefix('missing__')} missing"
    val = c.get("value")
    if isinstance(val, float) and math.isfinite(val):
        return f"{sign}{name}={val:.3g}"
    return f"{sign}{name}"


def render_explanation(*, fv: FeatureVector, result: FusionResult, label: str, label_reasons: Sequence[str],
                       model_contrib: Sequence[dict[str, Any]] = (), anomaly: AnomalyScore | None = None,
                       changepoints: Sequence[ChangePoint] = ()) -> str:
    """One paragraph an analyst can read without opening the evidence."""
    parts: list[str] = []
    verdict = result.verdict.value.upper()
    head = (f"{verdict}: {_LABEL_TEXT.get(label, label)} on device {fv.entity_pseudonym} "
            f"({fv.event_count} events in the {fv.window} window ending {fv.window_end:%Y-%m-%d %H:%M} UTC).")
    parts.append(head)
    for e in result.strong_hits[:3]:
        parts.append(f"Indicator: {e.summary}.")
    for e in result.weak_hits[:2]:
        parts.append(f"Weak indicator: {e.summary}.")
    for e in result.counter[:2]:
        parts.append(f"Counter-evidence: {e.summary}.")
    if label_reasons:
        parts.append("Behavior: " + "; ".join(label_reasons) + ".")
    ml = result.component_scores.get("ml")
    if ml is not None:
        txt = f"Calibrated model probability {ml:.2f}"
        if model_contrib:
            txt += " (main factors: " + ", ".join(_fmt_contrib(c) for c in model_contrib[:4]) + ")"
        parts.append(txt + ".")
    if anomaly is not None and anomaly.top:
        dev = ", ".join(f"{d.feature} {d.value:.3g} vs typical {d.baseline_median:.3g}" for d in anomaly.top[:3])
        parts.append(f"Anomaly percentile {anomaly.percentile:.3f} against the {anomaly.baseline} baseline ({dev}).")
    for c in changepoints[:2]:
        parts.append(f"Change point: {c.metric} shifted {c.direction} at {c.detected_at:%Y-%m-%d %H:%M} UTC.")
    parts.append(f"Decision rule {result.rule} of policy {result.policy_id} ({result.policy_hash[:12]}): "
                 f"{result.reasons[0] if result.reasons else ''}.")
    if result.verdict == Verdict.ABSTAIN:
        parts.append("The detector abstains: an analyst should review before any conclusion.")
    else:
        parts.append("Requires analyst review; no enforcement is taken by the detector.")
    parts.append(f"Device class '{fv.device_class}' selects the comparison baseline only and is not evidence.")
    return " ".join(parts)


def feature_doc(name: str) -> str:
    return FEATURE_DOCS.get(name.removeprefix("missing__"), name)


__all__ = ["LABEL_C2", "LABEL_DDOS", "LABEL_DGA", "LABEL_GENERIC", "LABEL_PROXY", "behavior_label",
           "feature_doc", "render_explanation"]
