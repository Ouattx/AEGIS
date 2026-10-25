from __future__ import annotations

import xml.etree.ElementTree as ET

from aegis.reports import charts


def parse(svg: str) -> ET.Element:
    root = ET.fromstring(str(svg))
    assert root.tag.endswith("svg")
    return root


def test_nice_max():
    assert charts.nice_max(0) == 1.0
    assert charts.nice_max(7) == 10
    assert charts.nice_max(1.3) == 2
    assert charts.nice_max(230) == 250
    assert charts.nice_max(float("nan")) == 1.0


def test_hbar_chart_is_valid_svg_and_escapes_labels():
    rows = [charts.BarRow("c2 <beacon>", (charts.Segment("verified", 3, "#0ca30c"),
                                          charts.Segment("rejected", 1, "#d03b3b"))),
            charts.BarRow("dga", (charts.Segment("verified", 0, "#0ca30c"),))]
    svg = charts.hbar_chart(rows)
    root = parse(svg)
    assert "c2 &lt;beacon&gt;" in str(svg)
    rects = [e for e in root.iter() if e.tag.endswith("rect")]
    assert len(rects) == 2  # zero-value segment is not drawn
    titles = [e.text for e in root.iter() if e.tag.endswith("title")]
    assert any("rejected 1" in (t or "") for t in titles)


def test_empty_charts_render_message():
    assert "No data" in str(charts.hbar_chart([]))
    assert "nothing" in str(charts.column_chart([], [], empty_message="nothing"))
    assert "No curves" in str(charts.pr_chart([]))
    assert "No estimates" in str(charts.interval_chart([]))


def test_column_chart():
    svg = charts.column_chart(["d1", "d2"], [("a", [1, 0], "#111111"), ("b", [2, 3], "#222222")])
    root = parse(svg)
    rects = [e for e in root.iter() if e.tag.endswith("rect")]
    assert len(rects) == 3


def test_pr_chart_with_marker_and_baseline():
    svg = charts.pr_chart([charts.Curve("ens", ((0, 1), (0.5, 0.9), (1, 0.4)), "#2a78d6", marker=(0.8, 0.9)),
                           charts.Curve("empty", (), "#000000")], baseline=0.05)
    root = parse(svg)
    assert any(e.tag.endswith("path") for e in root.iter())
    assert any(e.tag.endswith("circle") for e in root.iter())
    assert "base rate 0.050" in str(svg)


def test_interval_chart_handles_missing_values():
    rows = [charts.Interval("a", 0.5, 0.4, 0.6), charts.Interval("b", None, None, None),
            charts.Interval("c", 0.9, None, None)]
    svg = charts.interval_chart(rows, xmax=1.0)
    parse(svg)
    assert "not estimable" in str(svg)
    assert "95% CI 0.400 to 0.600" in str(svg)
    neg = charts.interval_chart([charts.Interval("d", -0.2, -0.5, 0.1)], zero_line=True)
    parse(neg)
