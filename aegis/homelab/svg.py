"""Dependency-free inline SVG charts for the Box Lab report.

Charts are styled by the page's CSS classes (``.ink``, ``.grid``, ``.s1`` ...), so they
follow the report's light / dark theme. All text is escaped. Missing values (``None``)
are drawn as gaps, never as zero. Every mark that carries a value has a ``<title>`` so
hovering shows it without any script.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from html import escape
from typing import Sequence


def _f(x: float) -> str:
    return f"{x:.1f}".rstrip("0").rstrip(".") if math.isfinite(x) else "0"


def nice_max(v: float) -> float:
    if not math.isfinite(v) or v <= 0:
        return 1.0
    e = math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * 10 ** e + 1e-12:
            return m * 10 ** e
    return 10 ** (e + 1)


def _hhmm(ts: float) -> str:
    d = datetime.fromtimestamp(ts, timezone.utc)
    return d.strftime("%H:%M") if (d.hour or d.minute) else d.strftime("%d %b")


def _empty(w: int, h: int, msg: str) -> str:
    return (f'<svg class="chart" viewBox="0 0 {w} {h}" role="img" aria-label="{escape(msg)}">'
            f'<rect class="frame" x="0.5" y="0.5" width="{w - 1}" height="{h - 1}" rx="6"/>'
            f'<text class="muted" x="{w / 2}" y="{h / 2 + 4}" text-anchor="middle">{escape(msg)}</text></svg>')


def _time_axis(start: float, end: float, x0: float, x1: float, y: float) -> list[str]:
    span = max(1.0, end - start)
    step_h = next(s for s in (1, 2, 3, 6, 12, 24, 48, 96, 168) if span / (s * 3600) <= 12)
    out = []
    t = math.ceil(start / (step_h * 3600)) * step_h * 3600
    while t <= end:
        x = x0 + (t - start) / span * (x1 - x0)
        out.append(f'<line class="grid" x1="{_f(x)}" y1="{_f(y)}" x2="{_f(x)}" y2="{_f(y + 4)}"/>'
                   f'<text class="muted small" x="{_f(x)}" y="{_f(y + 15)}" text-anchor="middle">{_hhmm(t)}</text>')
        t += step_h * 3600
    return out


def _shading(spans: Sequence[tuple[float, float]], start: float, end: float, x0: float, x1: float, y0: float,
             y1: float) -> list[str]:
    span = max(1.0, end - start)
    out = []
    for s, e in spans:
        s, e = max(s, start), min(e, end)
        if e <= s:
            continue
        xa = x0 + (s - start) / span * (x1 - x0)
        xb = x0 + (e - start) / span * (x1 - x0)
        out.append(f'<rect class="active" x="{_f(xa)}" y="{_f(y0)}" width="{_f(max(0.5, xb - xa))}" '
                   f'height="{_f(y1 - y0)}"><title>active use (owner-provided)</title></rect>')
    return out


def timeline_svg(hours: Sequence[float], flows: Sequence[int], dns: Sequence[int], *, start: float, end: float,
                 active: Sequence[tuple[float, float]] = (), width: int = 760, height: int = 220) -> str:
    """Hourly stacked columns (flows, DNS queries) over the capture, active periods shaded."""
    if not hours:
        return _empty(width, height, "no events")
    l, r, t, b = 46, 12, 12, 30
    x0, x1, y0, y1 = l, width - r, t, height - b
    vmax = nice_max(max((f + d for f, d in zip(flows, dns)), default=0))
    span = max(1.0, end - start)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" '
             f'aria-label="Hourly flows and DNS queries">']
    parts += _shading(active, start, end, x0, x1, y0, y1)
    for i in range(5):
        v = vmax * i / 4
        y = y1 - (y1 - y0) * i / 4
        parts.append(f'<line class="grid" x1="{x0}" y1="{_f(y)}" x2="{x1}" y2="{_f(y)}"/>'
                     f'<text class="muted small" x="{x0 - 6}" y="{_f(y + 4)}" text-anchor="end">{int(v):,}</text>')
    bw = (x1 - x0) * 3600.0 / span
    for h, f, d in zip(hours, flows, dns):
        x = x0 + (h - start) / span * (x1 - x0)
        hf = (y1 - y0) * f / vmax
        hd = (y1 - y0) * d / vmax
        label = escape(datetime.fromtimestamp(h, timezone.utc).strftime("%Y-%m-%d %H:00 UTC"))
        parts.append(f'<rect class="s1" x="{_f(x + 0.5)}" y="{_f(y1 - hf)}" width="{_f(max(0.5, bw - 1))}" '
                     f'height="{_f(hf)}"><title>{label}: {f:,} flows</title></rect>')
        parts.append(f'<rect class="s2" x="{_f(x + 0.5)}" y="{_f(y1 - hf - hd)}" width="{_f(max(0.5, bw - 1))}" '
                     f'height="{_f(hd)}"><title>{label}: {d:,} DNS queries</title></rect>')
    parts.append(f'<line class="axis" x1="{x0}" y1="{y1}" x2="{x1}" y2="{y1}"/>')
    parts += _time_axis(start, end, x0, x1, y1)
    parts.append("</svg>")
    return "".join(parts)


def raster_svg(times: Sequence[float], *, start: float, end: float, active: Sequence[tuple[float, float]] = (),
               width: int = 760, height: int = 54) -> str:
    """One tick per contact over the capture (the heartbeat strip)."""
    if not times:
        return _empty(width, height, "no contacts")
    l, r = 46, 12
    x0, x1, y0, y1 = l, width - r, 6, height - 22
    span = max(1.0, end - start)
    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Contact times">']
    parts += _shading(active, start, end, x0, x1, y0, y1)
    path = []
    for t in times:
        x = x0 + (t - start) / span * (x1 - x0)
        path.append(f"M{_f(x)} {y0}V{y1}")
    parts.append(f'<path class="tick" d="{" ".join(path)}"><title>{len(times):,} contacts</title></path>')
    parts.append(f'<line class="axis" x1="{x0}" y1="{y1}" x2="{x1}" y2="{y1}"/>')
    parts += _time_axis(start, end, x0, x1, y1)
    parts.append("</svg>")
    return "".join(parts)


def _fmt_period(p: float) -> str:
    if p < 120:
        return f"{p:.0f} s"
    if p < 7200:
        return f"{p / 60:.0f} min" if p % 60 < 1 or p >= 600 else f"{p / 60:.1f} min"
    return f"{p / 3600:.1f} h"


def periodogram_svg(periods: Sequence[float], z: Sequence[float | None], lomb: Sequence[float] = (), *,
                    best: float | None = None, width: int = 370, height: int = 200) -> str:
    """Difference-fold z (solid) and scaled Lomb-Scargle power (dashed) against period (log axis)."""
    pts = [(p, v) for p, v in zip(periods, z) if v is not None]
    if not pts:
        return _empty(width, height, "no identifiable period")
    l, r, t, b = 40, 10, 12, 30
    x0, x1, y0, y1 = l, width - r, t, height - b
    lo, hi = math.log(periods[0]), math.log(periods[-1])
    zmax = nice_max(max(max(v for _, v in pts), 1.0))
    zmin = min(0.0, min(v for _, v in pts))
    zmin = -nice_max(-zmin) if zmin < 0 else 0.0

    def X(p: float) -> float:
        return x0 + (math.log(p) - lo) / (hi - lo) * (x1 - x0)

    def Y(v: float) -> float:
        return y1 - (v - zmin) / (zmax - zmin) * (y1 - y0)

    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Periodogram">']
    for v in (zmin, 0.0, zmax / 2, zmax):
        parts.append(f'<line class="grid" x1="{x0}" y1="{_f(Y(v))}" x2="{x1}" y2="{_f(Y(v))}"/>'
                     f'<text class="muted small" x="{x0 - 5}" y="{_f(Y(v) + 4)}" text-anchor="end">{v:g}</text>')
    for tick in (60.0, 300.0, 900.0, 1800.0, 3600.0, 7200.0):
        if periods[0] <= tick <= periods[-1]:
            parts.append(f'<line class="grid" x1="{_f(X(tick))}" y1="{y0}" x2="{_f(X(tick))}" y2="{y1}"/>'
                         f'<text class="muted small" x="{_f(X(tick))}" y="{y1 + 15}" '
                         f'text-anchor="middle">{_fmt_period(tick)}</text>')
    if lomb and len(lomb) == len(periods):
        lmax = max(lomb) or 1.0
        seg = [f"{'M' if i == 0 else 'L'}{_f(X(per))} {_f(Y(zmax * lv / lmax))}"
               for i, (per, lv) in enumerate(zip(periods, lomb))]
        parts.append(f'<path class="line2" d="{" ".join(seg)}"><title>Lomb-Scargle power (scaled to the z axis)'
                     f'</title></path>')
    d: list[str] = []
    pen = False
    for per, val in zip(periods, z):
        if val is None:
            pen = False
            continue
        d.append(f"{'L' if pen else 'M'}{_f(X(per))} {_f(Y(val))}")
        pen = True
    parts.append(f'<path class="line1" d="{" ".join(d)}"><title>difference-fold z by candidate period</title></path>')
    if best is not None and periods[0] <= best <= periods[-1]:
        parts.append(f'<line class="mark" x1="{_f(X(best))}" y1="{y0}" x2="{_f(X(best))}" y2="{y1}">'
                     f'<title>strongest period {_fmt_period(best)}</title></line>')
    parts.append(f'<line class="axis" x1="{x0}" y1="{y1}" x2="{x1}" y2="{y1}"/></svg>')
    return "".join(parts)


def histogram_svg(edges: Sequence[float], counts: Sequence[int], *, width: int = 370, height: int = 200) -> str:
    """Inter-arrival histogram on log-spaced bins."""
    if not counts or not edges:
        return _empty(width, height, "fewer than two contacts")
    l, r, t, b = 40, 10, 12, 30
    x0, x1, y0, y1 = l, width - r, t, height - b
    lo, hi = math.log(edges[0]), math.log(edges[-1])
    vmax = nice_max(max(counts))

    def X(v: float) -> float:
        return x0 + (math.log(v) - lo) / max(1e-9, hi - lo) * (x1 - x0)

    parts = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="Time between contacts">']
    for i in range(3):
        v = vmax * i / 2
        y = y1 - (y1 - y0) * i / 2
        parts.append(f'<line class="grid" x1="{x0}" y1="{_f(y)}" x2="{x1}" y2="{_f(y)}"/>'
                     f'<text class="muted small" x="{x0 - 5}" y="{_f(y + 4)}" text-anchor="end">{int(v)}</text>')
    for a, c, n in zip(edges[:-1], edges[1:], counts):
        xa, xb = X(a), X(c)
        hgt = (y1 - y0) * n / vmax
        parts.append(f'<rect class="s1" x="{_f(xa + 0.5)}" y="{_f(y1 - hgt)}" width="{_f(max(0.5, xb - xa - 1))}" '
                     f'height="{_f(hgt)}"><title>{_fmt_period(a)} to {_fmt_period(c)}: {n}</title></rect>')
    for tick in (1.0, 10.0, 60.0, 600.0, 3600.0, 86400.0):
        if edges[0] <= tick <= edges[-1]:
            parts.append(f'<text class="muted small" x="{_f(X(tick))}" y="{y1 + 15}" '
                         f'text-anchor="middle">{_fmt_period(tick)}</text>')
    parts.append(f'<line class="axis" x1="{x0}" y1="{y1}" x2="{x1}" y2="{y1}"/></svg>')
    return "".join(parts)


__all__ = ["histogram_svg", "nice_max", "periodogram_svg", "raster_svg", "timeline_svg"]
