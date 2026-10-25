from pathlib import Path

from aegis.lab.__main__ import main as lab_main
from aegis.lab.samples import write_samples

SAMPLES = Path(__file__).resolve().parents[2] / "sample_data"


def test_committed_samples_match_generator(tmp_path):
    written = write_samples(tmp_path)
    assert written
    for path in written.values():
        rel = path.relative_to(tmp_path)
        committed = SAMPLES / rel
        assert committed.exists(), f"missing committed sample {rel}"
        assert committed.read_bytes() == path.read_bytes(), f"sample drifted: {rel} (run python -m aegis.lab.samples)"


def test_samples_are_small():
    total = sum(p.stat().st_size for p in SAMPLES.rglob("*") if p.is_file())
    assert total < 2 * 1024 * 1024


def test_cli_generates_corpus(tmp_path, capsys):
    assert lab_main(["--out", str(tmp_path), "--devices", "4", "--days", "1", "--seed", "3", "--no-zeek",
                     "--start", "2026-10-01T00:00:00"]) == 0
    out = capsys.readouterr().out
    assert '"devices": 4' in out
    assert (tmp_path / "netflow.csv").exists() and not (tmp_path / "zeek").exists()
