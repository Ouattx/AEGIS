"""Bounded-memory streaming helpers.

The sharded pipelines never materialize an input: collector files are parsed lazily
(``aegis.ingest.parsers`` yields one record at a time), the coordinator holds at most one
dispatch batch, and each worker holds one request. :func:`bounded_batches` is the generic
building block; :func:`iter_text_chunks` splits a large in-memory or on-disk payload into
line-aligned chunks without copying it whole; :func:`rss_bytes` reports resident memory for
load tests and operational metrics.
"""
from __future__ import annotations

import os
import resource
import sys
from itertools import islice
from pathlib import Path
from typing import Iterable, Iterator, TypeVar

T = TypeVar("T")


def bounded_batches(items: Iterable[T], size: int) -> Iterator[list[T]]:
    """Yield lists of at most ``size`` items, consuming ``items`` lazily."""
    if size < 1:
        raise ValueError("size must be positive")
    it = iter(items)
    while True:
        batch = list(islice(it, size))
        if not batch:
            return
        yield batch


def iter_text_chunks(path: str | Path, max_bytes: int = 8 << 20, *, keep_header: bool = False) -> Iterator[bytes]:
    """Read a line-oriented file in chunks of about ``max_bytes`` that end on a newline.

    ``keep_header`` repeats the first line (a CSV header) at the start of every chunk so
    each chunk is a self-contained collector payload.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    header = b""
    with open(path, "rb") as fh:
        if keep_header:
            header = fh.readline()
        buf: list[bytes] = []
        n = 0
        for line in fh:
            buf.append(line)
            n += len(line)
            if n >= max_bytes:
                yield header + b"".join(buf)
                buf, n = [], 0
        if buf:
            yield header + b"".join(buf)


def rss_bytes() -> int:
    """Current resident set size of this process in bytes (Linux ``/proc``; else peak RSS)."""
    try:
        with open("/proc/self/statm", "rb") as fh:
            pages = int(fh.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return peak if sys.platform == "darwin" else peak * 1024


def peak_rss_bytes() -> int:
    """Peak resident set size of this process (bytes).

    Linux caveat: ``ru_maxrss`` survives fork + exec, so in a child process it can report the
    parent's high-water mark; sample :func:`rss_bytes` instead when measuring a child.
    """
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024
