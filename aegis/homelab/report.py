"""Self-contained HTML "Box Lab report", one per device.

Sections: verdict with honest caveats, capture and input hashes, timeline, heartbeat
charts (contact strip, difference-fold periodogram with Lomb-Scargle overlay,
inter-arrival histogram), contacted destinations with feed matches, SENTINEL results,
crowd mixing (labelled MIXED-SYNTHETIC), evidence trail with sha256 and ledger status,
and limitations. No external resources, no script: the file opens offline and prints.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Iterable

from aegis.contracts.models import Verdict
from aegis.homelab.analysis import DeviceAnalysis, HomeLabAnalysis
from aegis.homelab.crowd import CrowdMixResult
from aegis.homelab.svg import histogram_svg, periodogram_svg, raster_svg, timeline_svg
from aegis.homelab.timers import TimerCandidate

MAX_HEARTBEAT_CARDS = 6
MAX_DEST_ROWS = 60

_CSS = """
:root{--bg:#fbfbf9;--card:#ffffff;--ink:#1d2327;--muted:#5d6670;--line:#d9dde1;--grid:#e8ebee;
--c1:#2f6db5;--c2:#c8792a;--active:rgba(46,160,90,.13);--mark:#b3261e;
--ok:#1f7a45;--warn:#9a6200;--bad:#b3261e;--neutral:#4a5560;--banner:#fff4d6;--banner-ink:#5a4300;
--mixed:#efe6ff;--mixed-ink:#4b2a87;--code:#f2f4f6}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#14171a;--card:#1c2024;--ink:#e6e8ea;
--muted:#9aa4ad;--line:#33393f;--grid:#2a2f34;--c1:#6ea8ef;--c2:#e2a15a;--active:rgba(80,200,120,.16);
--mark:#ff7a70;--ok:#5fcf8f;--warn:#f0b54a;--bad:#ff7a70;--neutral:#aab4bd;--banner:#3a3014;--banner-ink:#f3dc9a;
--mixed:#2d2342;--mixed-ink:#d9c6ff;--code:#23282d}}
:root[data-theme="dark"]{--bg:#14171a;--card:#1c2024;--ink:#e6e8ea;--muted:#9aa4ad;--line:#33393f;--grid:#2a2f34;
--c1:#6ea8ef;--c2:#e2a15a;--active:rgba(80,200,120,.16);--mark:#ff7a70;--ok:#5fcf8f;--warn:#f0b54a;--bad:#ff7a70;
--neutral:#aab4bd;--banner:#3a3014;--banner-ink:#f3dc9a;--mixed:#2d2342;--mixed-ink:#d9c6ff;--code:#23282d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:0 0 12px}h3{font-size:15px;margin:0 0 6px}
.sub{color:var(--muted);margin:0 0 16px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin:16px 0}
.banner{background:var(--banner);color:var(--banner-ink);border-radius:8px;padding:10px 14px;margin:10px 0;
font-weight:600}
.mixed{background:var(--mixed);color:var(--mixed-ink);border-radius:8px;padding:10px 14px;margin:10px 0;font-weight:600}
.pill{display:inline-block;border-radius:999px;padding:3px 12px;font-weight:700;letter-spacing:.02em;
border:2px solid currentColor}
.v-malicious{color:var(--bad)}.v-suspicious{color:var(--warn)}.v-abstain{color:var(--neutral)}
.muted{color:var(--muted);fill:var(--muted)}.small{font-size:11px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
code{background:var(--code);padding:1px 4px;border-radius:4px;word-break:break-all}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:760px){.grid2{grid-template-columns:1fr}}
.card{border:1px solid var(--line);border-radius:8px;padding:12px;margin:12px 0}
.badge{display:inline-block;font-size:11px;border-radius:4px;padding:1px 6px;margin:1px 2px;border:1px solid var(--line)}
.b-bad{color:var(--bad);border-color:var(--bad)}.b-warn{color:var(--warn);border-color:var(--warn)}
.b-ok{color:var(--ok);border-color:var(--ok)}
ul{margin:6px 0 6px 20px;padding:0}
svg.chart{width:100%;height:auto;display:block}
svg .grid{stroke:var(--grid);stroke-width:1}svg .axis{stroke:var(--muted);stroke-width:1}
svg .frame{fill:none;stroke:var(--line)}svg text{font-size:12px;fill:var(--muted)}
svg .s1{fill:var(--c1)}svg .s2{fill:var(--c2)}svg .active{fill:var(--active)}
svg .tick{stroke:var(--c1);stroke-width:1}svg .line1{fill:none;stroke:var(--c1);stroke-width:1.6}
svg .line2{fill:none;stroke:var(--c2);stroke-width:1.2;stroke-dasharray:4 3}
svg .mark{stroke:var(--mark);stroke-width:1.2;stroke-dasharray:2 2}
.legend span{display:inline-flex;align-items:center;gap:6px;margin-right:14px;font-size:12px;color:var(--muted)}
.sw{width:12px;height:12px;border-radius:2px;display:inline-block}
footer{color:var(--muted);font-size:12px;margin-top:24px}
@media print{section{break-inside:avoid}}
"""


def _ts(dt: datetime | float | None) -> str:
    if dt is None:
        return "–"
    if not isinstance(dt, datetime):
        dt = datetime.fromtimestamp(float(dt), timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _short_ts(dt: datetime | None) -> str:
    return "–" if dt is None else dt.astimezone(timezone.utc).strftime("%m-%d %H:%M:%S")


def _num(v: float | int | None, digits: int = 0) -> str:
    if v is None:
        return "–"
    if digits == 0:
        return f"{int(round(v)):,}"
    return f"{v:,.{digits}f}"


def _bytes(v: int | None) -> str:
    if v is None:
        return "–"
    for unit, div in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{v} B"


def _period(p: float | None) -> str:
    if p is None:
        return "–"
    return f"{p:.0f} s" if p < 120 else (f"{p / 60:.1f} min" if p < 7200 else f"{p / 3600:.1f} h")


def _pval(p: float | None) -> str:
    if p is None:
        return "–"
    return "< 1e-15" if p < 1e-15 else f"{p:.1e}"


def _li(items: Iterable[str]) -> str:
    items = list(items)
    if not items:
        return '<p class="muted">None.</p>'
    return "<ul>" + "".join(f"<li>{escape(i)}</li>" for i in items) + "</ul>"


_PATTERN_TEXT = {
    "runs_while_idle": "keeps running while idle",
    "active_only": "only while the device is used",
    "mixed": "both, at different rates",
    "idle_only": "only while idle",
    "insufficient": "not enough active/idle time to compare",
}


def _verdict_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    v = d.verdict
    cls = {Verdict.MALICIOUS: "v-malicious", Verdict.SUSPICIOUS: "v-suspicious"}.get(v.verdict, "v-abstain")
    word = {Verdict.MALICIOUS: "MALICIOUS (review)", Verdict.SUSPICIOUS: "SUSPICIOUS",
            Verdict.ABSTAIN: "NO CONCLUSION"}.get(v.verdict, v.verdict.value.upper())
    return (f'<section id="verdict"><h2>Verdict</h2>'
            f'<p><span class="pill {cls}">{escape(word)}</span> <strong>{escape(v.headline)}</strong></p>'
            f'<p class="muted">Pre-registered policy <code>{escape(v.policy_version)}</code>. Requires human review. '
            f'Independent origins supporting it: {v.independent_origins} '
            f'({escape(", ".join(v.origins) or "none")}). No score is shown because none of these numbers is '
            f'a probability of compromise.</p>'
            f'<h3>Why</h3>{_li(v.reasons)}<h3>Signals worth a look</h3>{_li(v.signals)}'
            f'<h3>Caveats</h3>{_li(v.caveats)}</section>')


def _capture_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    c = a.capture
    rows = "".join(f"<tr><td>{escape(f.kind)}{'' if f.used else ' (not used)'}</td><td class='mono'>"
                   f"{escape(Path(f.path).name)}</td><td class='num'>{_num(f.size_bytes)}</td>"
                   f"<td><code>{escape(f.sha256)}</code></td></tr>" for f in c.files)
    ing = "".join(f"<tr><td>{escape(s['source_id'])}</td><td class='mono'>{escape(str(s['input_ref']))}</td>"
                  f"<td class='num'>{_num(s['records_read'])}</td><td class='num'>{_num(s['published'])}</td>"
                  f"<td class='num'>{_num(s['quarantined'])}</td><td class='num'>{_num(s['skipped'])}</td></tr>"
                  for s in c.ingest)
    chatter = ""
    if d.local_chatter:
        lc = d.local_chatter
        ports = ", ".join(f"{p} ({n})" for p, n in lc["top_ports"]) or "–"
        chatter = (f"<p>Lab-local chatter (not analyzed as infrastructure): {_num(lc['flows'])} flows "
                   f"({_num(lc['multicast_flows'])} multicast) to {_num(lc['distinct_local_destinations'])} local "
                   f"address(es); ports {escape(ports)}.</p>")
    pre = ", ".join(f"{k.replace('_', ' ')}: {v:,}" for k, v in c.prefilter.items()) or "none"
    snap = c.manifest.snaplen
    return (f'<section id="capture"><h2>Capture</h2>'
            f'<table><tr><th>Window</th><td>{_ts(c.start)} → {_ts(c.end)} ({c.span_s / 3600:.1f} h)</td></tr>'
            f'<tr><th>Device</th><td>{escape(d.label)} <span class="muted mono">{escape(d.entity_pseudonym)}</span>'
            f'</td></tr><tr><th>Events</th><td>{_num(d.n_events)} ({_num(d.n_flows)} flows, {_num(d.n_dns)} DNS '
            f'queries)</td></tr><tr><th>Capture</th><td>{escape(c.manifest.capture_id or "no manifest")}; '
            f'interface {escape(c.manifest.interface or "–")}; snaplen {escape(str(snap) if snap else "–")} bytes '
            f'(headers only)</td></tr><tr><th>Quarantined</th><td>{_num(c.quarantined)} '
            f'{escape(json.dumps(c.quarantine_reasons)) if c.quarantine_reasons else ""}</td></tr>'
            f'<tr><th>Filtered before ingest</th><td>{escape(pre)}</td></tr>'
            f'<tr><th>Pseudonym key</th><td class="mono">fingerprint {escape(c.pseudonym_key_fingerprint)}</td></tr>'
            f'</table>{chatter}<h3>Input files (sha256)</h3><div class="scroll"><table><tr><th>Kind</th><th>File'
            f'</th><th class="num">Bytes</th><th>sha256</th></tr>{rows}</table></div>'
            f'<h3>Ingest</h3><div class="scroll"><table><tr><th>Source</th><th>Input</th><th class="num">Read</th>'
            f'<th class="num">Published</th><th class="num">Quarantined</th><th class="num">Skipped</th></tr>{ing}'
            f'</table></div></section>')


def _active_spans(a: HomeLabAnalysis) -> list[tuple[float, float]]:
    if a.usage is None:
        return []
    r = a.usage.resolved(a.capture.start.timestamp(), a.capture.end.timestamp())
    return list(r.active)


def _timeline_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    s, e = a.capture.start.timestamp(), a.capture.end.timestamp()
    svg = timeline_svg([h.hour.timestamp() for h in d.hourly], [h.flows for h in d.hourly],
                       [h.dns for h in d.hourly], start=s, end=e, active=_active_spans(a))
    usage = ("Shaded: periods the owner reported actively using the device."
             if a.usage is not None else "No usage windows were provided, so active and idle periods are not shown.")
    return (f'<section id="timeline"><h2>Timeline</h2><div class="legend"><span><i class="sw" '
            f'style="background:var(--c1)"></i>flows per hour</span><span><i class="sw" style="background:var(--c2)">'
            f'</i>DNS queries per hour</span><span><i class="sw" style="background:var(--active)"></i>active use</span>'
            f'</div>{svg}<p class="muted">{escape(usage)} Times in UTC.</p></section>')


def _heartbeat_card(a: HomeLabAnalysis, c: TimerCandidate) -> str:
    s, e = a.capture.start.timestamp(), a.capture.end.timestamp()
    act = c.activity
    pattern = _PATTERN_TEXT.get(act.pattern, act.pattern) if act else "usage windows not provided"
    rates = ""
    if act is not None:
        rates = (f" Active: {act.active_events} contacts in {act.active_hours:.1f} h "
                 f"({_num(act.active_rate_h, 1)}/h); idle: {act.idle_events} in {act.idle_hours:.1f} h "
                 f"({_num(act.idle_rate_h, 1)}/h); idle hours with a contact: "
                 f"{'–' if act.idle_hour_coverage is None else f'{act.idle_hour_coverage:.0%}'}.")
    head = (f"~{_period(c.period_s)} timer" if c.is_timer else "no clear timer")
    return (f'<div class="card"><h3>{escape(c.display)} <span class="muted">· {escape(head)} · '
            f'{escape(pattern)}</span></h3>'
            f'<p class="muted small">{c.n_events} contacts (after merging bursts within 5 s), z = '
            f'{_num(c.z, 1)} (nominal, not calibrated), concentration R = {_num(c.strength, 2)}, '
            f'absolute-phase coherence {_num(c.phase_coherence, 2)}.{escape(rates)}</p>'
            f'{raster_svg(c.times, start=s, end=e, active=_active_spans(a))}'
            f'<div class="grid2"><div><p class="muted small">Periodogram: difference-fold z (solid), '
            f'Lomb-Scargle power scaled (dashed), strongest period marked.</p>'
            f'{periodogram_svg(c.periods, c.z_curve, c.lomb_curve, best=c.period_s)}</div>'
            f'<div><p class="muted small">Time between consecutive contacts (log scale).</p>'
            f'{histogram_svg(c.interarrival_edges, c.interarrival_counts)}</div></div></div>')


def _heartbeat_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    ta = d.timers
    shown = (ta.timers + [c for c in ta.candidates if not c.is_timer])[:MAX_HEARTBEAT_CARDS]
    cards = "".join(_heartbeat_card(a, c) for c in shown)
    rows = "".join(
        f"<tr><td class='mono'>{escape(c.display)}</td><td class='num'>{c.n_events}</td>"
        f"<td class='num'>{escape(_period(c.period_s))}</td><td class='num'>{_num(c.z, 1)}</td>"
        f"<td class='num'>{_pval(c.p_nominal)}</td>"
        f"<td>{'yes' if c.is_timer else 'no'}</td>"
        f"<td>{escape(_PATTERN_TEXT.get(c.activity.pattern, c.activity.pattern) if c.activity else '–')}</td></tr>"
        for c in ta.candidates)
    notes = _li(ta.notes) if ta.notes else ""
    return (f'<section id="heartbeats"><h2>Heartbeats and timers</h2>'
            f'<p>Each card shows when the device contacted one destination. A regular timer shows evenly spaced '
            f'ticks, a sharp peak in the periodogram and a narrow inter-arrival histogram. <strong>Benign software '
            f'polls on timers too</strong>; what matters is where it goes, whether it keeps running while the '
            f'device is idle, and whether independent sources say anything about the destination.</p>{notes}'
            f'{cards}<h3>All destinations tested for a timer</h3><div class="scroll"><table><tr><th>Destination'
            f'</th><th class="num">Contacts</th><th class="num">Period</th><th class="num">z</th>'
            f'<th class="num">p (nominal)</th><th>Timer</th><th>Activity</th></tr>{rows}</table></div>'
            f'<p class="muted small">Timer = at least 8 contacts and z ≥ 5 at the strongest identifiable period '
            f'(pre-registered). p (nominal) is look-elsewhere corrected but not calibrated: bursty traffic '
            f'violates its assumptions.</p></section>')


def _match_badges(d: Any) -> str:
    out = []
    for m in d.matches:
        if m.feed_kind == "unverified_local_list":
            out.append('<span class="badge">local list (unverified)</span>')
            continue
        cls = "b-bad" if m.is_witness else "b-warn"
        state = m.state if m.state != "active" else ("contradicted" if m.contradicted else
                                                     ("verified contact" if m.verified_contact else "lookup only"))
        out.append(f'<span class="badge {cls}" title="{escape(m.indicator_id or "")}">'
                   f'{escape(m.source)}: {escape(m.threat_label or m.verdict)} ({escape(state)})</span>')
    return "".join(out) or '<span class="muted">–</span>'


def _destinations_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    inf = d.infra
    rows = []
    listed = [x for x in inf.destinations if x.flows or set(x.rcodes) - {"NXDOMAIN"}]
    for x in listed[:MAX_DEST_ROWS]:
        flags = []
        if x.contacted_without_lookup:
            flags.append('<span class="badge">no lookup seen</span>')
        if x.rcodes.get("NXDOMAIN"):
            flags.append(f'<span class="badge">NXDOMAIN ×{x.rcodes["NXDOMAIN"]}</span>')
        act = (f"{x.active_contacts} / {x.idle_contacts}" if a.usage is not None else "–")
        ports = ", ".join(str(p) for p, _ in x.ports.most_common(3)) or "–"
        names = ", ".join(sorted(x.names - {x.display})[:3]) if x.kind == "ip" else ", ".join(sorted(x.ips)[:3])
        rows.append(f"<tr><td class='mono'>{escape(x.display)}<div class='muted small'>{escape(names)}</div></td>"
                    f"<td class='num'>{_num(x.flows)}</td><td class='num'>{_num(x.dns_queries)}</td>"
                    f"<td class='num'>{_bytes(x.bytes_out)}</td><td class='num'>{_bytes(x.bytes_in)}</td>"
                    f"<td>{escape(ports)}</td><td class='mono'>{_short_ts(x.first_seen)}<br>{_short_ts(x.last_seen)}</td>"
                    f"<td class='num'>{escape(act)}</td><td>{''.join(flags)}{_match_badges(x)}</td></tr>")
    more = (f'<p class="muted">{len(listed) - MAX_DEST_ROWS} more destination(s) in analysis.json.</p>'
            if len(listed) > MAX_DEST_ROWS else "")
    feed = ("No signed threat feed was loaded: known-infrastructure matching was not performed."
            if inf.bundle is None else
            f"Signed feed bundle {inf.bundle['bundle_id']} version {inf.bundle['version']} "
            f"({inf.bundle['indicators']} indicators, signer {inf.bundle['signer_key_id']}), evaluated as of "
            f"{_ts(inf.as_of)}.")
    extra = []
    if inf.nxdomain_names:
        extra.append(f"{len(inf.nxdomain_names)} distinct names did not exist (NXDOMAIN), e.g. "
                     + ", ".join(inf.nxdomain_names[:5]) + ". Names that only ever failed are not listed in the "
                     "table below (all of them are in analysis.json).")
    if inf.external_resolvers:
        extra.append("DNS sent directly to resolver(s) other than the lab resolver: "
                     + ", ".join(inf.external_resolvers) + f" ({inf.dot_flows} DNS-over-TLS flows).")
    if inf.local_list_entries:
        extra.append(f"An unverified local list of {inf.local_list_entries} entries was checked for orientation only; "
                     "its hits are never evidence.")
    return (f'<section id="destinations"><h2>Contacted infrastructure</h2><p class="muted">{escape(feed)}</p>'
            f'{_li(extra) if extra else ""}<div class="scroll"><table><tr><th>Destination</th><th class="num">Flows'
            f'</th><th class="num">DNS</th><th class="num">Sent</th><th class="num">Received</th><th>Ports</th>'
            f'<th>First / last seen (UTC)</th><th class="num">Active / idle</th><th>Notes and feed matches</th></tr>'
            f'{"".join(rows)}</table></div>{more}<p class="muted small">A domain match counts as a verified contact '
            f'only when the device also sent traffic to an address that name resolved to. Contradicted, expired or '
            f'stale indicators are shown but never count as a witness.</p></section>')


def _sentinel_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    counts = ", ".join(f"{k}: {v}" for k, v in sorted(d.sentinel_windows.items())) or "no window closed"
    items = []
    for f in d.sentinel_findings:
        prob = "calibrated probability" if f.calibration_id else "ranking score, not a probability"
        rule = d.sentinel_rules.get(f.finding_id, "unknown")
        items.append(f'<div class="card"><h3>{escape(f.verdict.value.upper())} · {escape(f.label)} · '
                     f'score {f.score:.2f} <span class="muted">({escape(prob)}; fusion rule {escape(rule)})</span>'
                     f'</h3>'
                     f'<p class="muted small">Window {_ts(f.observed_window_start)} → {_ts(f.observed_window_end)}; '
                     f'evidence {len(f.evidence_ids)}, counter-evidence {len(f.counterevidence_ids)}</p>'
                     f'<p>{escape(f.explanation)}</p></div>')
    return (f'<section id="sentinel"><h2>SENTINEL per-device detectors</h2>'
            f'<p>Indicator rules, calibrated model, anomaly and change-point detectors with the production fusion '
            f'policy (which abstains when context is short). Hourly 24 h windows evaluated: {escape(counts)}. '
            f'A "benign" window only means that no detector fired for that window; it is not a statement that '
            f'the device is clean. Repeated windows of the same behavior are reported once.</p><p class="muted">'
            f'{escape(a.sentinel.get("note") or "")} Detector <code>{escape(a.sentinel["detector_version"])}</code>.'
            f'</p>{"".join(items) or "<p class=muted>No SENTINEL finding was emitted for this device.</p>"}</section>')


def _crowd_section(crowd: CrowdMixResult | None, d: DeviceAnalysis) -> str:
    if crowd is None:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{escape(', '.join(c.destinations))}</td><td>{'capture copies' if c.involves_capture else 'simulated background'}</td>"
        f"<td class='num'>{c.capture_copies}/{c.member_lines}</td><td class='num'>{escape(_period(c.period_s))}</td>"
        f"<td class='num'>{c.q_value:.1e}</td><td>{'no (fail closed)' if not c.enforcement_eligible else 'yes'}</td></tr>"
        for c in crowd.campaigns)
    timers = {t.key: t for t in d.timers.timers}
    tested = "".join(
        f"<tr><td class='mono'>{escape(', '.join(t['destinations']))}</td><td class='num'>{t['n_lines']}</td>"
        f"<td class='num'>{t['q_value']:.1e}</td><td>{'yes' if t['rejected'] else 'no'}</td>"
        f"<td class='num'>{escape(_period(timers[t['destinations'][0]].period_s) if t['destinations'][0] in timers else '–')}</td></tr>"
        for t in crowd.capture_keys_tested)
    cfg = crowd.config
    status = ("RESONANCE abstained: " + (crowd.report.abstain_reason or "")) if crowd.report.status == "abstain" else \
        f"{len(crowd.capture_campaigns)} campaign(s) on capture destinations, {len(crowd.background_campaigns)} on " \
        f"simulated background destinations, {crowd.report.n_tested} hypotheses tested at q = {cfg.q}."
    return (f'<section id="crowd"><h2>Crowd mixing (RESONANCE demonstration)</h2>'
            f'<div class="mixed">{escape(crowd.label)}</div>'
            f'<p>The capture was replicated as {crowd.copies} independent renewal-bootstrap copies and mixed into '
            f'{crowd.background_lines} simulated subscriber lines (seed {cfg.seed}, sampling 1:{cfg.sampling}, '
            f'{"with" if cfg.warmup_history else "without"} a warm-up history day). {escape(status)}</p>'
            f'{_li(crowd.notes[1:])}<h3>Campaigns</h3><div class="scroll"><table><tr><th>Destinations</th><th>Lines'
            f'</th><th class="num">Copies / members</th><th class="num">Campaign period</th><th class="num">q</th>'
            f'<th>Enforcement-eligible</th></tr>{rows or "<tr><td colspan=6 class=muted>none</td></tr>"}</table></div>'
            f'<h3>Capture destinations tested</h3><div class="scroll"><table><tr><th>Destinations</th>'
            f'<th class="num">Lines</th><th class="num">q</th><th>Rejected</th><th class="num">Device timer</th></tr>'
            f'{tested or "<tr><td colspan=5 class=muted>none</td></tr>"}</table></div>'
            f'<p class="muted small">Campaign periods come from RESONANCE\'s cross-line period lock and can differ '
            f'from the single-device timer estimate (harmonics, mixed DNS and flow events). Results here are never '
            f'findings and are not written to the ledger. Detector <code>{escape(crowd.report.detector_version)}'
            f'</code>.</p><div class="mixed">{escape(crowd.label)}</div></section>')


def _evidence_section(a: HomeLabAnalysis, d: DeviceAnalysis) -> str:
    led = a.ledger
    if led is None:
        status = ('<p class="banner">Evidence was not persisted (no lab store): hashes below are not anchored in a '
                  'ledger.</p>')
    else:
        ok = "verified" if led["verified"] else f"FAILED at entry {led['first_bad_seq']}"
        status = (f'<table><tr><th>Ledger chain</th><td>{escape(ok)} ({led["entries"]} entries, signer '
                  f'<code>{escape(led["signer_key_id"])}</code>)</td></tr><tr><th>Head hash</th><td>'
                  f'<code>{escape(led["head_hash"])}</code></td></tr><tr><th>Database</th><td class="mono">'
                  f'{escape(Path(led["database"]).name if led["database"] else "in memory")}</td></tr></table>')
    support = set(d.verdict.evidence_ids)
    rows = "".join(
        f"<tr><td class='mono'>{escape(e.evidence_id)}</td><td>{escape(e.kind.value)}</td>"
        f"<td>{'supporting' if e.evidence_id in support and e.supports else 'counter'}</td>"
        f"<td class='mono'>{escape(e.source_independence_group)}</td><td><code>{escape(e.sha256 or '–')}</code></td>"
        f"<td>{escape(e.summary)}</td></tr>" for e in d.evidence)
    return (f'<section id="evidence"><h2>Evidence trail</h2>{status}<p class="muted">Each record is stored with the '
            f'sha256 of its canonical JSON and one ledger entry; the verdict itself is a ledger entry of type '
            f'<code>homelab_verdict</code>. Records sharing an independence group are one origin, not several.</p>'
            f'<div class="scroll"><table><tr><th>Evidence id</th><th>Kind</th><th>Role</th><th>Origin group</th>'
            f'<th>sha256</th><th>Summary</th></tr>{rows}</table></div></section>')


_LIMITS = (
    "Header-only capture: no payloads, no TLS decryption, no content. Encrypted DNS (DoH) to an outside server "
    "is invisible to the lab resolver; it appears only as HTTPS flows.",
    "Lookups cached before the capture started make some addresses look contacted without a lookup.",
    "Timers are estimated with RESONANCE's line-level difference folding; z and p values are nominal, not "
    "calibrated. Benign software polls on timers.",
    "Usage windows are the owner's own notes; the idle/active comparison is only as good as those notes.",
    "SENTINEL was trained on synthetic lab data at operator vantage; scores on a home device are indicative only.",
    "Feed matches are only as good as the feed. Indicators can be stale, syndicated (one origin counted once) or "
    "over-broad (shared CDN addresses).",
    "Crowd mixing is a demonstration on mixed synthetic data, not a measurement of any network.",
    "Do not name a vendor, seller or service publicly on the basis of this report alone; see the home-lab guide "
    "on responsible disclosure.",
)


def render_box_report(analysis: HomeLabAnalysis, device: DeviceAnalysis | str) -> str:
    """Render one device's Box Lab report as a self-contained HTML string."""
    d = analysis.device(device) if isinstance(device, str) else device
    a = analysis
    banners = []
    if a.synthetic:
        banners.append('<div class="banner">SYNTHETIC DATA: this report was built from a generated capture of a '
                       'fictional device. It demonstrates the method and says nothing about any real product.</div>')
    if a.crowd is not None:
        banners.append('<div class="mixed">This report contains a MIXED-SYNTHETIC section (crowd mixing). '
                       'All other sections use the capture only.</div>')
    title = f"Box Lab report: {d.label}"
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>{escape(title)}</title><style>{_CSS}</style></head><body><main>"
            f"<h1>{escape(title)}</h1><p class=\"sub\">AEGIS home lab · {escape(a.capture.manifest.capture_id or '')} · "
            f"generated {_ts(a.generated_at)} · analysis only, nothing was blocked</p>{''.join(banners)}"
            f"{_verdict_section(a, d)}{_capture_section(a, d)}{_timeline_section(a, d)}{_heartbeat_section(a, d)}"
            f"{_destinations_section(a, d)}{_sentinel_section(a, d)}{_crowd_section(a.crowd, d)}"
            f"{_evidence_section(a, d)}<section id=\"limits\"><h2>Limitations</h2>{_li(_LIMITS)}</section>"
            f"<footer>aegis.homelab {escape(a.version)} · verdict policy {escape(d.verdict.policy_version)} · timer "
            f"config {escape(d.timers.config_hash[:12])} · times in UTC</footer></main></body></html>")


def write_reports(analysis: HomeLabAnalysis, out_dir: str | Path) -> dict[str, Path]:
    """Write ``box-lab-<label>.html`` per device and ``analysis.json``; returns the paths by device label."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for d in analysis.devices:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in d.label.lower()).strip("-") or "device"
        p = out / f"box-lab-{safe}.html"
        if p.name in {q.name for q in paths.values()}:          # two devices with the same label
            p = out / f"box-lab-{safe}-{d.entity_pseudonym[2:10]}.html"
        p.write_text(render_box_report(analysis, d), encoding="utf-8")
        paths[d.label] = p
    (out / "analysis.json").write_text(json.dumps(analysis.to_dict(), indent=2, default=str) + "\n",
                                       encoding="utf-8")
    paths["analysis.json"] = out / "analysis.json"
    return paths


__all__ = ["render_box_report", "write_reports"]
