"""Local file and stdin input helpers."""

from __future__ import annotations

import sys
from pathlib import Path


def read_lines(path: Path | None) -> tuple[list[str], str]:
    """Read a log from ``path`` or stdin.

    Files are read as UTF-8 with replacement so a stray byte in a rotated log
    never crashes triage. The returned source label is used in evidence.
    """
    if path is None:
        if sys.stdin.isatty():
            raise ValueError("no input: pass -i FILE or pipe a log on stdin")
        return sys.stdin.read().splitlines(), "<stdin>"

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines(), str(path)
