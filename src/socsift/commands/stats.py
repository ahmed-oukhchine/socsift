"""``socsift stats`` command contract."""

from __future__ import annotations

from pathlib import Path

import typer

from socsift.commands._shared import unavailable


def stats(
    input_path: Path = typer.Option(
        ...,
        "-i",
        "--input",
        help="Log file to profile.",
    ),
) -> None:
    """Show top IPs, users, and hourly activity for a log source."""
    unavailable("stats", "The log statistics engine is not wired into this build yet.")
