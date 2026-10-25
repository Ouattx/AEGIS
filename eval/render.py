"""Self-contained HTML report of a benchmark run (inline CSS + SVG, no external assets)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup

from aegis.reports import charts
from aegis.reports.theme import BASE_CSS, SERIES

from eval.systems import SYSTEMS

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: fixed color per system (color follows the entity, never its rank)
SYSTEM_COLORS: dict[str, str] = {
    "ensemble": SERIES[0], "supervised": SERIES[1], "rules_only": SERIES[2], "static_blocklist": SERIES[3],
    "threshold_heuristic": SERIES[4],
}

_PLOT_METRICS = (("recall", "Recall (device-day)", 1.0, 3), ("precision", "Precision (device-day)", 1.0, 3),
                 ("pr_auc", "PR-AUC (device-day)", 1.0, 3),
                 ("false_alerts_per_10k", "False alerts per 10k device-days", None, 1))


def _fmt(v: Any, d: int = 3) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:,.{d}f}"
    return f"{v:,}" if isinstance(v, int) else str(v)


def _ci(ci: Any, d: int = 3) -> str:
    if not ci:
        return "n/a"
    return f"{ci[0]:.{d}f} to {ci[1]:.{d}f}"


def _charts_for(block: dict[str, Any]) -> dict[str, Markup]:
    systems = block["systems"]
    out: dict[str, Markup] = {}
    for key, title, xmax, digits in _PLOT_METRICS:
        rows = [charts.Interval(label=n.replace("_", " "), value=m.get(key),
                                low=(m["ci95"].get(key) or [None, None])[0] if m.get("ci95") else None,
                                high=(m["ci95"].get(key) or [None, None])[1] if m.get("ci95") else None,
                                color=SYSTEM_COLORS.get(n, SERIES[6]))
                for n, m in systems.items()]
        out[key] = charts.interval_chart(rows, xmax=xmax, digits=digits, aria_label=title)
    curves = []
    for n, m in systems.items():
        pts = tuple((float(r), float(p)) for r, p in m.get("pr_curve") or [])
        marker = (m["recall"], m["precision"]) if m.get("recall") is not None and m.get("precision") is not None \
            else None
        curves.append(charts.Curve(name=n.replace("_", " "), points=pts, color=SYSTEM_COLORS.get(n, SERIES[6]),
                                   marker=marker, dashed=n in ("static_blocklist", "threshold_heuristic")))
    out["pr"] = charts.pr_chart(curves, baseline=block.get("base_rate"))
    return out


def _ordered(block: dict[str, Any]) -> dict[str, Any]:
    """Systems in their fixed presentation order (JSON round-trips may sort keys)."""
    rank = {n: i for i, n in enumerate(SYSTEMS)}
    out = dict(block)
    out["systems"] = dict(sorted(block["systems"].items(), key=lambda kv: (rank.get(kv[0], len(rank)), kv[0])))
    if "projections" in block:
        out["projections"] = dict(sorted(block["projections"].items(),
                                         key=lambda kv: (rank.get(kv[0], len(rank)), kv[0])))
    return out


def render_benchmark_html(results: dict[str, Any]) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html", "j2"]),
                      undefined=StrictUndefined, trim_blocks=True, lstrip_blocks=True)
    env.filters["f"] = _fmt
    env.filters["ci"] = _ci
    env.filters["label"] = lambda s: str(s).replace("_", " ")
    env.filters["pct"] = lambda v, d=2: "n/a" if v is None else f"{100 * v:.{d}f}%"
    blocks = {name: _ordered(b) for name, b in {"pooled": results["pooled"], **results["scenarios"]}.items()}
    chart_sets = {name: _charts_for(b) for name, b in blocks.items()}
    ordered = dict(results)
    ordered["pooled"] = blocks["pooled"]
    return env.get_template("benchmark.html.j2").render(
        r=ordered, css=BASE_CSS, charts=chart_sets, colors=SYSTEM_COLORS, blocks=blocks)


__all__ = ["SYSTEM_COLORS", "render_benchmark_html"]
