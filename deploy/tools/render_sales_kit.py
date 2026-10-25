#!/usr/bin/env python3
"""Render the sales kit with the company's commercial terms; refuse while any is missing.

Every vendor-specific value in ``docs/sales/*.md`` is a keyed placeholder::

    [FOUNDER TO SET pilot_fee: amount, currency, excl. VAT]

This tool replaces each placeholder with ``[values].<key>`` from a TOML file (start from
``docs/sales/commercial.example.toml``) and writes the rendered documents to ``--out``.
It exits non-zero, writing nothing, when a key has no value, a value is empty or still
an example, or an unkeyed placeholder remains, so a document with a placeholder can
never leave the company.

Usage::

    python deploy/tools/render_sales_kit.py --config commercial.toml --out dist/sales
"""
from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

SALES_DIR = Path(__file__).resolve().parents[2] / "docs" / "sales"
PLACEHOLDER = re.compile(r"\[FOUNDER TO SET(?: (?P<key>[a-z][a-z0-9_]*))?(?::[^\]]*)?\]")
EXAMPLE_MARK = "EXAMPLE"


class RenderError(ValueError):
    """The kit cannot be rendered safely; ``problems`` lists every reason."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


def placeholders(text: str) -> list[str | None]:
    """Keys of the placeholders in ``text`` (``None`` for an unkeyed one)."""
    return [m.group("key") for m in PLACEHOLDER.finditer(text)]


def render_text(text: str, values: dict[str, str], *, name: str = "document") -> str:
    problems: list[str] = []
    for key in placeholders(text):
        if key is None:
            problems.append(f"{name}: unkeyed placeholder")
        elif not str(values.get(key, "")).strip():
            problems.append(f"{name}: no value for {key!r}")
        elif EXAMPLE_MARK in str(values[key]):
            problems.append(f"{name}: value for {key!r} is still an example")
    if problems:
        raise RenderError(sorted(set(problems)))
    return PLACEHOLDER.sub(lambda m: str(values[m.group("key")]).strip(), text)


def render_kit(config: Path, out: Path, sales_dir: Path = SALES_DIR) -> list[Path]:
    data = tomllib.loads(config.read_text(encoding="utf-8"))
    values = {str(k): str(v) for k, v in (data.get("values") or {}).items()}
    rendered: dict[str, str] = {}
    problems: list[str] = []
    for doc in sorted(sales_dir.glob("*.md")):
        try:
            rendered[doc.name] = render_text(doc.read_text(encoding="utf-8"), values, name=doc.name)
        except RenderError as exc:
            problems.extend(exc.problems)
    if problems:
        raise RenderError(problems)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, text in rendered.items():
        target = out / name
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config", required=True, type=Path, help="TOML with a [values] table")
    ap.add_argument("--out", required=True, type=Path, help="output directory for the rendered kit")
    args = ap.parse_args(argv)
    try:
        written = render_kit(args.config, args.out)
    except RenderError as exc:
        print("refusing to render the sales kit:", file=sys.stderr)
        for p in exc.problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    for w in written:
        print(w)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
