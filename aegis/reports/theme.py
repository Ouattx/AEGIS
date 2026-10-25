"""Shared visual theme for AEGIS HTML reports (proof-of-value report, benchmark report).

Reports are single self-contained HTML files: no external fonts, scripts, stylesheets
or images, so they render identically when e-mailed, archived or printed to PDF.
Colors are defined once as CSS custom properties; charts reference them by role.
"""
from __future__ import annotations

from typing import Final

#: categorical series colors, fixed order (validated palette, light surface)
SERIES: Final[tuple[str, ...]] = ("#2a78d6", "#eb6834", "#1baf7a", "#c98500", "#e87ba4", "#008300",
                                  "#6250d6", "#e34948")
#: status colors (never reused as series colors); always paired with a text label
STATUS: Final[dict[str, str]] = {"good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a",
                                 "critical": "#d03b3b", "neutral": "#898781"}
INK: Final[dict[str, str]] = {"primary": "#0b0b0b", "secondary": "#52514e", "muted": "#898781",
                              "grid": "#e1e0d9", "axis": "#c3c2b7", "surface": "#fcfcfb"}

BASE_CSS: Final[str] = """
:root{
  color-scheme: light;
  --page:#f4f4f1; --surface:#ffffff; --surface-2:#f9f9f7;
  --ink:#0b0b0b; --ink-2:#52514e; --ink-3:#6f6e69; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,.10);
  --accent:#1c5cab; --accent-soft:#e8f0fb;
  --good:#0ca30c; --good-ink:#006300; --good-soft:#e7f6e7;
  --warning:#fab219; --warning-ink:#7a5200; --warning-soft:#fff5dc;
  --critical:#d03b3b; --critical-ink:#9b1f1f; --critical-soft:#fbeaea;
  --serious:#ec835a;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);
  font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.sheet{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header.cover{background:var(--surface);border:1px solid var(--ring);border-radius:14px;padding:28px 32px;
  margin-bottom:20px;position:relative;overflow:hidden}
header.cover:before{content:"";position:absolute;inset:0 auto 0 0;width:6px;background:var(--accent)}
.eyebrow{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--ink-3);font-weight:600}
h1{font-size:28px;line-height:1.2;margin:6px 0 4px;letter-spacing:-.01em}
h2{font-size:19px;margin:0 0 4px;letter-spacing:-.005em}
h3{font-size:15px;margin:18px 0 6px}
.sub{color:var(--ink-2);margin:0}
.meta{display:flex;flex-wrap:wrap;gap:8px 24px;margin-top:14px;font-size:12.5px;color:var(--ink-2)}
.meta b{color:var(--ink);font-weight:600}
section.card{background:var(--surface);border:1px solid var(--ring);border-radius:14px;padding:22px 26px;
  margin:0 0 18px;break-inside:avoid-page}
section.card > .lede{color:var(--ink-2);margin:0 0 14px;max-width:72ch}
.num{font-variant-numeric:tabular-nums}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:14px 0 4px}
.tile{background:var(--surface-2);border:1px solid var(--ring);border-radius:10px;padding:12px 14px}
.tile .label{font-size:12px;color:var(--ink-2);font-weight:600}
.tile .value{font-size:26px;font-weight:650;letter-spacing:-.01em;margin-top:2px;line-height:1.15}
.tile .note{font-size:11.5px;color:var(--ink-3);margin-top:3px}
.badge{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:2px 10px;font-size:12px;
  font-weight:600;border:1px solid transparent;white-space:nowrap}
.badge:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;flex:none}
.badge.good{background:var(--good-soft);color:var(--good-ink);border-color:#bfe5bf}
.badge.warning{background:var(--warning-soft);color:var(--warning-ink);border-color:#f3dc9f}
.badge.critical{background:var(--critical-soft);color:var(--critical-ink);border-color:#efc1c1}
.badge.neutral{background:#efeeea;color:var(--ink-2);border-color:#dedcd5}
.callout{border-radius:10px;padding:14px 16px;margin:12px 0;border:1px solid var(--ring);background:var(--surface-2)}
.callout.good{background:var(--good-soft);border-color:#bfe5bf}
.callout.warning{background:var(--warning-soft);border-color:#f3dc9f}
.callout.critical{background:var(--critical-soft);border-color:#efc1c1}
.callout h3{margin:0 0 4px}
.callout p{margin:4px 0}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0 4px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--grid);vertical-align:top}
th{font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;color:var(--ink-2);font-weight:650;
  border-bottom:1px solid var(--axis)}
td.r,th.r{text-align:right}
tbody tr:last-child td{border-bottom:none}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.hash{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;color:var(--ink-2);
  word-break:break-all}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:18px}
figure{margin:8px 0 0}
figcaption{font-size:12px;color:var(--ink-2);margin-top:4px}
svg.chart{display:block;width:100%;height:auto;overflow:visible}
svg.chart text{font-family:inherit}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12px;color:var(--ink-2);margin:6px 0}
.legend span{display:inline-flex;align-items:center;gap:6px}
.legend i{display:inline-block;width:12px;height:12px;border-radius:3px}
.case{border:1px solid var(--ring);border-radius:10px;padding:14px 16px;margin:12px 0;background:var(--surface-2);
  break-inside:avoid-page}
.case-head{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 12px;align-items:baseline}
.case-title{font-weight:650}
.trail{list-style:none;margin:8px 0 0;padding:0 0 0 14px;border-left:2px solid var(--grid)}
.trail li{margin:0 0 6px;position:relative;font-size:12.5px}
.trail li:before{content:"";position:absolute;left:-19px;top:6px;width:8px;height:8px;border-radius:50%;
  background:var(--surface);border:2px solid var(--axis)}
.small{font-size:12px;color:var(--ink-2)}
.muted{color:var(--ink-3)}
ul.tight{margin:6px 0;padding-left:20px}
ul.tight li{margin:3px 0}
footer.foot{font-size:11.5px;color:var(--ink-3);text-align:center;margin-top:24px}
.toc{display:flex;flex-wrap:wrap;gap:6px 14px;font-size:12.5px;margin-top:14px}
.toc a{color:var(--accent);text-decoration:none}
@media (max-width:640px){
  .sheet{padding:16px 16px 40px}
  header.cover,section.card{padding:18px 16px}
  h1{font-size:23px}
  .tile .value{font-size:22px}
}
@media print{
  @page{size:A4;margin:14mm 12mm}
  body{background:#fff;font-size:11.5px}
  .sheet{max-width:none;padding:0}
  header.cover,section.card{border-color:#d8d7d0;box-shadow:none}
  section.card{break-inside:auto}
  .case,.tile,figure,table{break-inside:avoid}
  .toc{display:none}
  a{color:inherit;text-decoration:none}
}
"""

__all__ = ["BASE_CSS", "INK", "SERIES", "STATUS"]
