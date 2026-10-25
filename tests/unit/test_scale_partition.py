"""aegis.scale.partition: stable, process-independent shard placement."""
from __future__ import annotations

import subprocess
import sys

import pytest

from aegis.scale.partition import (
    Partitioner,
    assign_shards,
    jump_consistent_hash,
    kafka_partition_for_destination,
    kafka_partition_for_line,
    moved_fraction,
    stable_hash64,
    LINE_NAMESPACE,
)

LINES = [f"p_{i:032x}" for i in range(4000)]


def test_jump_hash_range_and_reference_values():
    for n in (1, 2, 7, 64):
        for k in range(500):
            assert 0 <= jump_consistent_hash(k * 0x9E3779B97F4A7C15, n) < n
    # reference values of the Lamping & Veach algorithm (pinned: placement must never change silently)
    assert [jump_consistent_hash(k, 10) for k in (0, 1, 2, 3, 2**63, 2**64 - 1)] == [0, 6, 6, 8, 5, 9]
    assert [jump_consistent_hash(k, 1000) for k in (1, 123456789, 2**40)] == [549, 294, 145]
    assert jump_consistent_hash(0, 1) == 0
    with pytest.raises(ValueError):
        jump_consistent_hash(1, 0)


def test_pinned_placement_is_stable_across_releases():
    p = Partitioner(16)
    assert [p.line_shard(x) for x in LINES[:12]] == [15, 2, 3, 12, 12, 6, 2, 1, 5, 9, 11, 15]
    assert stable_hash64(LINE_NAMESPACE, "p_" + "0" * 32) == int.from_bytes(
        __import__("hashlib").sha256(LINE_NAMESPACE + b"p_" + b"0" * 32).digest()[:8], "big")


def test_placement_identical_in_a_fresh_interpreter():
    code = ("from aegis.scale.partition import Partitioner;"
            f"p=Partitioner(8);print([p.line_shard(x) for x in {LINES[:50]!r}]);"
            "print(p.destination_shard('d:c2.example'))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={"PYTHONHASHSEED": "12345", "PATH": ""}, cwd=".").stdout.split("\n")
    p = Partitioner(8)
    assert out[0] == str([p.line_shard(x) for x in LINES[:50]])
    assert out[1] == str(p.destination_shard("d:c2.example"))


def test_balance_and_minimal_movement_on_reshard():
    p = Partitioner(8)
    counts = [0] * 8
    for x in LINES:
        counts[p.line_shard(x)] += 1
    assert max(counts) / (len(LINES) / 8) < 1.15
    moved = moved_fraction(LINES, 8, 9)
    assert 0.07 < moved < 0.16                  # about 1/9 of the keys move, not ~8/9 as with modulo
    assert moved_fraction(LINES, 8, 8) == 0.0
    assert moved_fraction([], 3, 4) == 0.0
    keys = [f"d:host{i}.example" for i in range(2000)]
    assert 0.05 < moved_fraction(keys, 10, 11, kind="destination") < 0.15


def test_namespaces_are_independent():
    p = Partitioner(64)
    same = sum(p.line_shard(x) == p.destination_shard(x) for x in LINES)
    assert same < len(LINES) / 64 * 2


def test_partitioner_validation_and_helpers():
    for bad in (0, -1):
        with pytest.raises(ValueError):
            Partitioner(bad)
    with pytest.raises(ValueError):
        Partitioner(2.5)  # type: ignore[arg-type]
    p = Partitioner(4)
    split = p.split_lines(LINES[:100])
    assert sorted(split) == [0, 1, 2, 3] and sum(map(len, split.values())) == 100
    assert all(p.line_shard(x) == s for s, xs in split.items() for x in xs)
    assert 0 <= p.raw_shard(b"garbage") < 4
    assert kafka_partition_for_line(LINES[3], 4) == p.line_shard(LINES[3])
    assert kafka_partition_for_destination("ip:198.18.0.1", 4) == p.destination_shard("ip:198.18.0.1")


def test_assign_shards():
    a = assign_shards(5, ["w0", "w1"])
    assert a == {"w0": [0, 2, 4], "w1": [1, 3]}
    assert assign_shards(2, ["a", "b", "c"]) == {"a": [0], "b": [1], "c": []}
    with pytest.raises(ValueError):
        assign_shards(3, [])
    with pytest.raises(ValueError):
        assign_shards(3, ["a", "a"])
