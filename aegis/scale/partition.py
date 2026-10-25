"""Deterministic partitioning of AEGIS work across shards.

Two partition keys exist, and every executor (local processes, Kafka partitions,
Kubernetes workers) must use the functions here so that a record lands on the same
shard whatever process routes it:

* **line pseudonym** (``p_<32 hex>``) for ingestion and every per-line computation
  (normalization, deduplication, SENTINEL feature windows and scoring). Because a
  pseudonym is a deterministic function of the raw identifier, routing a raw record by
  the pseudonym of its identifier co-locates it with every event of the same line;
* **destination key** (``d:<domain>`` / ``ip:<address>``) for RESONANCE population
  statistics.

Hashing never uses Python's ``hash()`` (salted per process). The bucket of a key is
``jump_consistent_hash(sha256(namespace || key)[:8], n_shards)`` (Lamping & Veach 2014):
stable across processes, machines and Python versions, and when the shard count grows
from ``n`` to ``n + 1`` only about ``1 / (n + 1)`` of the keys move.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

LINE_NAMESPACE = b"aegis-scale/line/v1:"
DESTINATION_NAMESPACE = b"aegis-scale/destination/v1:"
RAW_NAMESPACE = b"aegis-scale/raw/v1:"

_JUMP_MULT = 2862933555777941757
_U64 = (1 << 64) - 1


def jump_consistent_hash(key: int, n_buckets: int) -> int:
    """Lamping & Veach jump consistent hash of a 64-bit integer into ``[0, n_buckets)``."""
    if n_buckets <= 0:
        raise ValueError("n_buckets must be positive")
    key &= _U64
    b, j = -1, 0
    while j < n_buckets:
        b = j
        key = (key * _JUMP_MULT + 1) & _U64
        j = int((b + 1) * ((1 << 31) / ((key >> 33) + 1)))
    return b


def stable_hash64(namespace: bytes, key: str | bytes) -> int:
    data = key if isinstance(key, (bytes, bytearray)) else key.encode("utf-8")
    return int.from_bytes(hashlib.sha256(namespace + bytes(data)).digest()[:8], "big")


@dataclass(frozen=True)
class Partitioner:
    """Maps line pseudonyms, destination keys and raw records to shard ids."""

    n_shards: int

    def __post_init__(self) -> None:
        if not isinstance(self.n_shards, int) or self.n_shards < 1:
            raise ValueError("n_shards must be a positive integer")

    def line_shard(self, line_pseudonym: str) -> int:
        return jump_consistent_hash(stable_hash64(LINE_NAMESPACE, line_pseudonym), self.n_shards)

    def destination_shard(self, destination_key: str) -> int:
        return jump_consistent_hash(stable_hash64(DESTINATION_NAMESPACE, destination_key), self.n_shards)

    def raw_shard(self, raw: bytes) -> int:
        """Shard for a record without a usable identity (it will be quarantined): by content."""
        return jump_consistent_hash(stable_hash64(RAW_NAMESPACE, raw), self.n_shards)

    def split_lines(self, lines: Iterable[str]) -> dict[int, list[str]]:
        out: dict[int, list[str]] = {s: [] for s in range(self.n_shards)}
        for ln in lines:
            out[self.line_shard(ln)].append(ln)
        return out


def assign_shards(n_shards: int, workers: Sequence[str]) -> dict[str, list[int]]:
    """Static assignment of shards to named workers (round robin by shard id).

    The same function serves local processes (``worker-0..k``), Kafka consumer group
    members (shard id == partition id when the topic has ``n_shards`` partitions) and
    Kubernetes StatefulSet ordinals (``aegis-shard-<i>``). Deterministic: the same inputs
    always give the same assignment.
    """
    if not workers:
        raise ValueError("at least one worker is required")
    if len(set(workers)) != len(workers):
        raise ValueError("worker names must be unique")
    out: dict[str, list[int]] = {w: [] for w in workers}
    for s in range(n_shards):
        out[workers[s % len(workers)]].append(s)
    return out


def kafka_partition_for_line(line_pseudonym: str, n_partitions: int) -> int:
    """Explicit Kafka partition for a line-keyed message.

    Producers must set the partition explicitly with this function instead of relying on
    the client's default key partitioner (murmur2 in Java / librdkafka "consistent_random"),
    so Kafka partitions and local shards agree on placement.
    """
    return Partitioner(n_partitions).line_shard(line_pseudonym)


def kafka_partition_for_destination(destination_key: str, n_partitions: int) -> int:
    return Partitioner(n_partitions).destination_shard(destination_key)


def moved_fraction(keys: Sequence[str], n_from: int, n_to: int, *, kind: str = "line") -> float:
    """Share of ``keys`` whose shard changes when resharding from ``n_from`` to ``n_to`` shards."""
    if not keys:
        return 0.0
    a, b = Partitioner(n_from), Partitioner(n_to)
    fn: Mapping[str, tuple] = {"line": (a.line_shard, b.line_shard),
                               "destination": (a.destination_shard, b.destination_shard)}
    fa, fb = fn[kind]
    return sum(1 for k in keys if fa(k) != fb(k)) / len(keys)
