"""``socsift watch`` command contract."""

from __future__ import annotations

from pathlib import Path

import typer

from socsift.commands._shared import unavailable


def watch(
    input_path: Path = typer.Option(
        ...,
        "-i",
        "--input",
        help="Log file to follow with the live dashboard.",
    ),
) -> None:
    """Follow a live alert feed, severity counters, top IPs, and timeline."""
    unavailable(
        "watch",
        "The live terminal dashboard is not wired into this build yet.",
    )
