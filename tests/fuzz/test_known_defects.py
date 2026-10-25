"""Defects found by the fuzz suite in modules outside aegis/scale, pinned as strict xfails.

Each test describes the correct behaviour; it fails today and is marked ``xfail(strict=True)``,
so the suite turns red (XPASS) the moment the defect is fixed and the marker must be removed.
"""
from __future__ import annotations

import pytest

from aegis.contracts.canonical import sha256_hex
from fuzz_support import Run


@pytest.mark.xfail(strict=True, reason=(
    "aegis.ingest.normalize accepts flow counters up to 2**63-1, but RFC 8785 canonical JSON "
    "(used for provenance hashes and by Validator on dict/JSON input) only represents integers up to "
    "2**53 - 1: the accepted event can neither be hashed nor re-validated. Fix: cap counters at 2**53 - 1 in "
    "normalize._opt_int (quarantine reason bad_<field>)."))
def test_counter_above_json_safe_integer_range_is_quarantined():
    run = Run()
    stats = run.ingest("netflow", b"ts,device_id,src_ip,dst_ip,bytes_out\n"
                                  b"2026-10-01T00:00:00Z,aa:bb:cc:dd:ee:ff,10.0.0.1,198.18.0.1,9007199254740992\n")
    assert stats.accepted == 0 and stats.quarantined == 1


def test_accepted_counter_events_can_be_hashed_up_to_2_pow_53_minus_1():
    run = Run()
    stats = run.ingest("netflow", b"ts,device_id,src_ip,dst_ip,bytes_out\n"
                                  b"2026-10-01T00:00:00Z,aa:bb:cc:dd:ee:ff,10.0.0.1,198.18.0.1,9007199254740991\n")
    assert stats.accepted == 1
    assert len(sha256_hex(run.events[0].model_dump(mode="json"))) == 64
