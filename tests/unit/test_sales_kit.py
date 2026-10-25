"""The sales kit can only be sent rendered, with every commercial value set."""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("render_sales_kit", ROOT / "deploy" / "tools" / "render_sales_kit.py")
assert _spec and _spec.loader
kit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kit)


def _keys() -> set[str]:
    out: set[str] = set()
    for doc in (ROOT / "docs" / "sales").glob("*.md"):
        for key in kit.placeholders(doc.read_text(encoding="utf-8")):
            assert key is not None, f"unkeyed placeholder in {doc.name}"
            out.add(key)
    return out


def test_every_placeholder_is_keyed_and_in_the_example_config():
    import tomllib
    example = tomllib.loads((ROOT / "docs" / "sales" / "commercial.example.toml").read_text())["values"]
    assert _keys() and _keys() <= set(example)


def test_example_config_is_refused(tmp_path):
    with pytest.raises(kit.RenderError) as ei:
        kit.render_kit(ROOT / "docs" / "sales" / "commercial.example.toml", tmp_path / "out")
    assert any("still an example" in p for p in ei.value.problems)
    assert not (tmp_path / "out").exists()


def test_complete_config_renders_without_placeholders(tmp_path):
    cfg = tmp_path / "commercial.toml"
    cfg.write_text("[values]\n" + "".join(f'{k} = "value of {k}"\n' for k in sorted(_keys())))
    written = kit.render_kit(cfg, tmp_path / "out")
    assert written
    for w in written:
        text = w.read_text()
        assert "FOUNDER TO SET" not in re.sub(r"\*\*FOUNDER TO SET\*\*", "", text) or "[FOUNDER TO SET" not in text
        assert "[FOUNDER TO SET" not in text
    assert "value of pilot_fee" in (tmp_path / "out" / "SHADOW_PILOT_OFFER.md").read_text()


def test_missing_value_is_refused(tmp_path):
    keys = sorted(_keys())
    cfg = tmp_path / "commercial.toml"
    cfg.write_text("[values]\n" + "".join(f'{k} = "v"\n' for k in keys[1:]))
    with pytest.raises(kit.RenderError) as ei:
        kit.render_kit(cfg, tmp_path / "out")
    assert any(keys[0] in p for p in ei.value.problems)
    assert kit.main(["--config", str(cfg), "--out", str(tmp_path / "o2")]) == 1
