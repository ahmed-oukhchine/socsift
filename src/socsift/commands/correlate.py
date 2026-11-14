"""``socsift correlate`` command contract."""

from __future__ import annotations

from pathlib import Path

import typer

from socsift.commands._shared import unavailable


def correlate(
    input_paths: list[Path] = typer.Option(
        ...,
        "-i",
        "--input",
        help="Log source to correlate; repeat -i for each source.",
    ),
) -> None:
    """Merge alerts from several sources into incidents with a timeline."""
    unavailable(
        "correlate",
        "The incident correlation engine is not wired into this build yet.",
    )
