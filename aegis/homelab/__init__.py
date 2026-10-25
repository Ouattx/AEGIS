"""AEGIS Home Lab Kit: test one streaming box at home, safely and legally (metadata only).

Pipeline (see ``docs/homelab/GUIDE.md`` and ``aegis/homelab/INTEGRATION.md``)::

    deploy/homelab (isolated AP, dnsmasq query log, header-only capture, Zeek offline)
      -> import_capture()          single-home ingest sources, regular AEGIS ingest pipeline
      -> analyze_single_home()     SENTINEL + timer/periodogram analysis + idle/active split
                                   + contacted infrastructure with signed-feed matches
                                   + pre-registered Box Lab verdict, evidence in a signed ledger
      -> crowd_mix() (optional)    RESONANCE demonstration on MIXED-SYNTHETIC data
      -> write_reports()           self-contained HTML Box Lab report per device + analysis.json

    run_homelab(capture_dir, out_dir, ...) does all of it; ``python -m aegis.homelab analyze``.
"""
from aegis.homelab.analysis import DeviceAnalysis, HomeLabAnalysis, analyze_single_home
from aegis.homelab.config import HomeLabConfig, single_home_sources
from aegis.homelab.crowd import CrowdMixConfig, CrowdMixResult, crowd_mix
from aegis.homelab.dnsmasq import dnsmasq_to_jsonl, parse_dnsmasq_log
from aegis.homelab.importer import CaptureError, CaptureImport, discover_capture, import_capture
from aegis.homelab.infra import FeedMatch, InfraSummary, analyze_infrastructure, load_local_list
from aegis.homelab.report import render_box_report, write_reports
from aegis.homelab.run import HomeLabRun, lab_keys, run_homelab, verify_run
from aegis.homelab.store import LabStore, open_lab_store
from aegis.homelab.synthetic import SyntheticBoxSpec, write_synthetic_capture
from aegis.homelab.timers import TimerAnalysis, TimerCandidate, analyze_timers
from aegis.homelab.usage import UsageWindows, load_usage_windows
from aegis.homelab.verdict import BoxVerdict, decide

__all__ = [
    "BoxVerdict", "CaptureError", "CaptureImport", "CrowdMixConfig", "CrowdMixResult", "DeviceAnalysis", "FeedMatch",
    "HomeLabAnalysis", "HomeLabConfig", "HomeLabRun", "InfraSummary", "LabStore", "SyntheticBoxSpec", "TimerAnalysis",
    "TimerCandidate", "UsageWindows", "analyze_infrastructure", "analyze_single_home", "analyze_timers", "crowd_mix",
    "decide", "discover_capture", "dnsmasq_to_jsonl", "import_capture", "lab_keys", "load_local_list",
    "load_usage_windows", "open_lab_store", "parse_dnsmasq_log", "render_box_report", "run_homelab",
    "single_home_sources", "verify_run", "write_reports", "write_synthetic_capture",
]
