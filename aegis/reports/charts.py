"""Dependency-free inline SVG charts for self-contained HTML reports.

Every function returns :class:`markupsafe.Markup` holding one ``<svg>`` element
(``viewBox`` based, scales to its container, prints crisply). All text is escaped.
Each mark carries a ``<title>`` so hovering shows the exact value in any browser,
with no script. Values that are ``None`` (missing) are drawn as gaps, never zero.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from markupsafe import Markup, escape

from aegis.reports.theme import INK, SERIES


def _f(x: float) -> str:
    """Compact coordinate formatting."""
    return f"{x:.1f}".rstrip("0").rstrip(".") if math.isfinite(x) else "0"


def _fmt_value(v: float, digits: int = 0) -> str:
    if digits == 0 and abs(v - round(v)) < 1e-9:
        return f"{int(round(v)):,}"
    return f"{v:,.{max(digits, 1)}f}"


def nice_max(v: float) -> float:
    """Round ``v`` up to a 1/2/2.5/5 x 10^k axis maximum (>= 1 for empty data)."""
    if not math.isfinite(v) or v <= 0:
        return 1.0
    exp = math.floor(math.log10(v))
    base = 10 ** exp
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * base + 1e-12:
            return m * base
    return 10 * base  # pragma: no cover - loop always returns


def _ticks(vmax: float, n: int = 4) -> list[float]:
    return [vmax * i / n for i in range(n + 1)]


def _empty(width: int, height: int, message: str) -> Markup:
    return Markup(
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(message)}">'
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="8" fill="#f9f9f7" '
        f'stroke="{INK["grid"]}"/>'
        f'<text x="{width / 2}" y="{height / 2 + 4}" text-anchor="middle" font-size="13" '
        f'fill="{INK["muted"]}">{escape(message)}</text></svg>')


# ---------------------------------------------------------------------------- bars

@dataclass(frozen=True)
class Segment:
    """One stacked segment of a horizontal bar."""
    name: str
    value: float
    color: str


@dataclass(frozen=True)
class BarRow:
    label: str
    segments: tuple[Segment, ...]
    note: str = ""

    @property
    def total(self) -> float:
        return sum(s.value for s in self.segments)


def hbar_chart(rows: Sequence[BarRow], *, width: int = 640, row_height: int = 30, label_width: int = 190,
               value_suffix: str = "", aria_label: str = "bar chart", empty_message: str = "No data") -> Markup:
    """Horizontal (optionally stacked) bars with the total printed at the bar end."""
    if not rows:
        return _empty(width, 80, empty_message)
    vmax = nice_max(max(r.total for r in rows))
    pad_top, pad_bottom = 6, 26
    plot_w = width - label_width - 70
    h = pad_top + row_height * len(rows) + pad_bottom
    out = [f'<svg class="chart" viewBox="0 0 {width} {h}" role="img" aria-label="{escape(aria_label)}">']
    for t in _ticks(vmax):
        x = label_width + plot_w * t / vmax
        out.append(f'<line x1="{_f(x)}" y1="{pad_top}" x2="{_f(x)}" y2="{h - pad_bottom}" '
                   f'stroke="{INK["grid"]}" stroke-width="1"/>')
        out.append(f'<text x="{_f(x)}" y="{h - pad_bottom + 16}" text-anchor="middle" font-size="11" '
                   f'fill="{INK["muted"]}">{escape(_fmt_value(t, 1 if vmax < 5 else 0))}</text>')
    bar_h = max(8, row_height - 12)
    for i, r in enumerate(rows):
        y = pad_top + i * row_height + (row_height - bar_h) / 2
        out.append(f'<text x="{label_width - 10}" y="{_f(y + bar_h / 2 + 4)}" text-anchor="end" font-size="12.5" '
                   f'fill="{INK["primary"]}">{escape(r.label)}</text>')
        x = float(label_width)
        segs = [s for s in r.segments if s.value > 0]
        for j, s in enumerate(segs):
            w = plot_w * s.value / vmax
            gap = 2 if j < len(segs) - 1 else 0
            out.append(f'<rect x="{_f(x)}" y="{_f(y)}" width="{_f(max(w - gap, 1))}" height="{bar_h}" rx="3" '
                       f'fill="{escape(s.color)}"><title>{escape(r.label)}: {escape(s.name)} '
                       f'{escape(_fmt_value(s.value, 2))}{escape(value_suffix)}</title></rect>')
            x += w
        label = _fmt_value(r.total, 2 if r.total < 10 and r.total != int(r.total) else 0) + value_suffix
        if r.note:
            label += f"  {r.note}"
        out.append(f'<text x="{_f(x + 6)}" y="{_f(y + bar_h / 2 + 4)}" font-size="12" fill="{INK["secondary"]}" '
                   f'class="num">{escape(label)}</text>')
    out.append(f'<line x1="{label_width}" y1="{pad_top}" x2="{label_width}" y2="{h - pad_bottom}" '
               f'stroke="{INK["axis"]}" stroke-width="1"/>')
    out.append("</svg>")
    return Markup("".join(out))


def column_chart(labels: Sequence[str], series: Sequence[tuple[str, Sequence[float], str]], *, width: int = 640,
                 height: int = 220, aria_label: str = "column chart", empty_message: str = "No data") -> Markup:
    """Stacked vertical columns, e.g. alerts per day split by verdict.

    ``series`` is ``[(name, values aligned with labels, color), ...]``.
    """
    if not labels or not series:
        return _empty(width, height, empty_message)
    totals = [sum(s[1][i] for s in series) for i in range(len(labels))]
    vmax = nice_max(max(totals) if totals else 0)
    left, right, top, bottom = 44, 12, 10, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    slot = plot_w / len(labels)
    bw = max(4.0, min(42.0, slot * 0.62))
    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(aria_label)}">']
    for t in _ticks(vmax):
        y = top + plot_h - plot_h * t / vmax
        out.append(f'<line x1="{left}" y1="{_f(y)}" x2="{width - right}" y2="{_f(y)}" stroke="{INK["grid"]}"/>')
        out.append(f'<text x="{left - 6}" y="{_f(y + 4)}" text-anchor="end" font-size="11" fill="{INK["muted"]}" '
                   f'class="num">{escape(_fmt_value(t, 1 if vmax < 5 else 0))}</text>')
    every = max(1, math.ceil(len(labels) / 12))
    for i, lab in enumerate(labels):
        cx = left + slot * i + slot / 2
        ybase: float = top + plot_h
        n_nonzero = sum(1 for s in series if s[1][i] > 0)
        k = 0
        for name, values, color in series:
            v = values[i]
            if v <= 0:
                continue
            k += 1
            hgt = plot_h * v / vmax
            gap = 2 if k < n_nonzero else 0
            out.append(f'<rect x="{_f(cx - bw / 2)}" y="{_f(ybase - hgt + gap)}" width="{_f(bw)}" '
                       f'height="{_f(max(hgt - gap, 1))}" rx="3" fill="{escape(color)}">'
                       f'<title>{escape(lab)}: {escape(name)} {escape(_fmt_value(v))}</title></rect>')
            ybase -= hgt
        if i % every == 0:
            out.append(f'<text x="{_f(cx)}" y="{height - bottom + 16}" text-anchor="middle" font-size="11" '
                       f'fill="{INK["muted"]}">{escape(lab)}</text>')
    out.append(f'<line x1="{left}" y1="{top + plot_h}" x2="{width - right}" y2="{top + plot_h}" '
               f'stroke="{INK["axis"]}"/>')
    out.append("</svg>")
    return Markup("".join(out))


# ---------------------------------------------------------------------------- lines

@dataclass(frozen=True)
class Curve:
    name: str
    points: tuple[tuple[float, float], ...]          # (x, y) in [0, 1]
    color: str
    marker: tuple[float, float] | None = None        # operating point
    dashed: bool = False


def pr_chart(curves: Sequence[Curve], *, width: int = 520, height: int = 380, baseline: float | None = None,
             aria_label: str = "precision-recall curves") -> Markup:
    """Precision (y) vs recall (x) curves on fixed [0, 1] axes with optional base-rate line."""
    if not curves:
        return _empty(width, height, "No curves")
    left, right, top, bottom = 48, 16, 12, 42
    pw, ph = width - left - right, height - top - bottom

    def px(x: float) -> float:
        return left + pw * min(1.0, max(0.0, x))

    def py(y: float) -> float:
        return top + ph - ph * min(1.0, max(0.0, y))

    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(aria_label)}">']
    for t in (0.0, 0.25, 0.5, 0.75, 1.0):
        out.append(f'<line x1="{_f(px(0))}" y1="{_f(py(t))}" x2="{_f(px(1))}" y2="{_f(py(t))}" '
                   f'stroke="{INK["grid"]}"/>')
        out.append(f'<line x1="{_f(px(t))}" y1="{_f(py(0))}" x2="{_f(px(t))}" y2="{_f(py(1))}" '
                   f'stroke="{INK["grid"]}"/>')
        out.append(f'<text x="{_f(px(0) - 6)}" y="{_f(py(t) + 4)}" text-anchor="end" font-size="11" '
                   f'fill="{INK["muted"]}">{t:.2f}</text>')
        out.append(f'<text x="{_f(px(t))}" y="{_f(py(0) + 16)}" text-anchor="middle" font-size="11" '
                   f'fill="{INK["muted"]}">{t:.2f}</text>')
    out.append(f'<text x="{_f(left + pw / 2)}" y="{height - 6}" text-anchor="middle" font-size="12" '
               f'fill="{INK["secondary"]}">Recall</text>')
    out.append(f'<text x="12" y="{_f(top + ph / 2)}" text-anchor="middle" font-size="12" '
               f'fill="{INK["secondary"]}" transform="rotate(-90 12 {_f(top + ph / 2)})">Precision</text>')
    if baseline is not None and 0 <= baseline <= 1:
        out.append(f'<line x1="{_f(px(0))}" y1="{_f(py(baseline))}" x2="{_f(px(1))}" y2="{_f(py(baseline))}" '
                   f'stroke="{INK["muted"]}" stroke-dasharray="4 4"><title>base rate {baseline:.4f}</title></line>')
        out.append(f'<text x="{_f(px(1) - 4)}" y="{_f(py(baseline) - 5)}" text-anchor="end" font-size="11" '
                   f'fill="{INK["muted"]}">base rate {baseline:.3f}</text>')
    for c in curves:
        if not c.points:
            continue
        d = "M" + " L".join(f"{_f(px(x))},{_f(py(y))}" for x, y in c.points)
        dash = ' stroke-dasharray="6 4"' if c.dashed else ""
        out.append(f'<path d="{d}" fill="none" stroke="{escape(c.color)}" stroke-width="2" '
                   f'stroke-linejoin="round"{dash}><title>{escape(c.name)}</title></path>')
        if c.marker is not None:
            mx, my = c.marker
            out.append(f'<circle cx="{_f(px(mx))}" cy="{_f(py(my))}" r="5" fill="{escape(c.color)}" '
                       f'stroke="{INK["surface"]}" stroke-width="2"><title>{escape(c.name)} operating point: '
                       f'recall {mx:.3f}, precision {my:.3f}</title></circle>')
    out.append(f'<rect x="{left}" y="{top}" width="{pw}" height="{ph}" fill="none" stroke="{INK["axis"]}"/>')
    out.append("</svg>")
    return Markup("".join(out))


# ---------------------------------------------------------------------------- intervals

@dataclass(frozen=True)
class Interval:
    label: str
    value: float | None
    low: float | None
    high: float | None
    color: str = SERIES[0]


def interval_chart(rows: Sequence[Interval], *, width: int = 560, row_height: int = 28, label_width: int = 170,
                   xmax: float | None = None, digits: int = 3, aria_label: str = "point estimates with 95% CI",
                   zero_line: bool = False) -> Markup:
    """Forest plot: point estimate with 95% confidence whiskers per row."""
    vals = [v for r in rows for v in (r.value, r.low, r.high) if v is not None and math.isfinite(v)]
    if not rows or not vals:
        return _empty(width, 80, "No estimates")
    lo = min(0.0, min(vals))
    hi = xmax if xmax is not None else nice_max(max(vals))
    if hi <= lo:
        hi = lo + 1.0
    top, bottom = 6, 26
    pw = width - label_width - 80
    h = top + row_height * len(rows) + bottom

    def px(v: float) -> float:
        return label_width + pw * (min(hi, max(lo, v)) - lo) / (hi - lo)

    out = [f'<svg class="chart" viewBox="0 0 {width} {h}" role="img" aria-label="{escape(aria_label)}">']
    for i in range(5):
        t = lo + (hi - lo) * i / 4
        out.append(f'<line x1="{_f(px(t))}" y1="{top}" x2="{_f(px(t))}" y2="{h - bottom}" stroke="{INK["grid"]}"/>')
        out.append(f'<text x="{_f(px(t))}" y="{h - bottom + 16}" text-anchor="middle" font-size="11" '
                   f'fill="{INK["muted"]}">{escape(_fmt_value(t, 2 if hi - lo <= 5 else 0))}</text>')
    if zero_line and lo < 0 < hi:
        out.append(f'<line x1="{_f(px(0))}" y1="{top}" x2="{_f(px(0))}" y2="{h - bottom}" '
                   f'stroke="{INK["secondary"]}" stroke-dasharray="3 3"/>')
    for i, r in enumerate(rows):
        cy = top + i * row_height + row_height / 2
        out.append(f'<text x="{label_width - 10}" y="{_f(cy + 4)}" text-anchor="end" font-size="12.5" '
                   f'fill="{INK["primary"]}">{escape(r.label)}</text>')
        if r.value is None:
            out.append(f'<text x="{label_width + 4}" y="{_f(cy + 4)}" font-size="12" fill="{INK["muted"]}">'
                       f'not estimable</text>')
            continue
        tip = f"{r.label}: {r.value:.{digits}f}"
        if r.low is not None and r.high is not None:
            tip += f" (95% CI {r.low:.{digits}f} to {r.high:.{digits}f})"
            out.append(f'<line x1="{_f(px(r.low))}" y1="{_f(cy)}" x2="{_f(px(r.high))}" y2="{_f(cy)}" '
                       f'stroke="{escape(r.color)}" stroke-width="2"/>')
            for e in (r.low, r.high):
                out.append(f'<line x1="{_f(px(e))}" y1="{_f(cy - 5)}" x2="{_f(px(e))}" y2="{_f(cy + 5)}" '
                           f'stroke="{escape(r.color)}" stroke-width="2"/>')
        out.append(f'<circle cx="{_f(px(r.value))}" cy="{_f(cy)}" r="5" fill="{escape(r.color)}" '
                   f'stroke="{INK["surface"]}" stroke-width="2"><title>{escape(tip)}</title></circle>')
        out.append(f'<text x="{width - 4}" y="{_f(cy + 4)}" text-anchor="end" font-size="12" '
                   f'fill="{INK["secondary"]}" class="num">{r.value:.{digits}f}</text>')
    out.append("</svg>")
    return Markup("".join(out))


__all__ = ["BarRow", "Curve", "Interval", "Segment", "column_chart", "hbar_chart", "interval_chart", "nice_max",
           "pr_chart"]
