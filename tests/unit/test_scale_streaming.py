"""aegis.scale.streaming helpers."""
from __future__ import annotations

import pytest

from aegis.scale.streaming import bounded_batches, iter_text_chunks, peak_rss_bytes, rss_bytes


def test_bounded_batches_is_lazy_and_bounded():
    consumed = []

    def gen():
        for i in range(10):
            consumed.append(i)
            yield i

    it = bounded_batches(gen(), 4)
    assert next(it) == [0, 1, 2, 3] and len(consumed) == 4
    assert list(it) == [[4, 5, 6, 7], [8, 9]]
    assert list(bounded_batches([], 3)) == []
    with pytest.raises(ValueError):
        list(bounded_batches([1], 0))


def test_iter_text_chunks_keeps_header_and_line_boundaries(tmp_path):
    p = tmp_path / "f.csv"
    p.write_bytes(b"h1,h2\n" + b"".join(b"%d,x\n" % i for i in range(1000)))
    chunks = list(iter_text_chunks(p, 500, keep_header=True))
    assert len(chunks) > 3
    assert all(c.startswith(b"h1,h2\n") and c.endswith(b"\n") for c in chunks)
    body = b"".join(c[len(b"h1,h2\n"):] for c in chunks)
    assert body == p.read_bytes()[len(b"h1,h2\n"):]
    assert b"".join(iter_text_chunks(p, 10**6)) == p.read_bytes()
    with pytest.raises(ValueError):
        list(iter_text_chunks(p, 0))


def test_memory_probes():
    assert rss_bytes() > 1_000_000
    assert peak_rss_bytes() >= rss_bytes() // 2
