"""AEGIS reports: the shadow proof-of-value report (spec sections 13, 14, 17, 19).

- :func:`build_pov_report` - self-contained HTML report from a tenant's stores
- :func:`collect_pov_report` / :func:`render_pov_html` - the same in two steps (JSON-able :class:`PovReport`)
- :mod:`.inputs` - reporting period, observed coverage, operator cost inputs, analyst effort model
- :mod:`.charts` - dependency-free inline SVG charts shared with the benchmark report
- :func:`run_lab_pilot` - end-to-end lab pilot populating real stores for a demonstration report
"""
from aegis.reports.inputs import AnalystEffortModel, CostInputs, CoverageAccumulator, CoverageStats, ReportPeriod
from aegis.reports.model import REPORT_SCHEMA, PovReport
from aegis.reports.pov import build_pov_report, collect_pov_report, device_day_of, render_pov_html, report_fingerprint

__all__ = [
    "AnalystEffortModel", "CostInputs", "CoverageAccumulator", "CoverageStats", "PovReport", "REPORT_SCHEMA",
    "ReportPeriod", "build_pov_report", "collect_pov_report", "device_day_of", "render_pov_html",
    "report_fingerprint",
]
