"""Shared fixtures and Hypothesis profiles for the ingest fuzz suite.

Profiles: ``ci`` (default, bounded runtime) and ``deep`` (``HYPOTHESIS_PROFILE=deep``,
thousands of examples per property, for nightly runs).
"""
from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile("ci", max_examples=200, deadline=None, database=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
settings.register_profile("deep", max_examples=3000, deadline=None, database=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
