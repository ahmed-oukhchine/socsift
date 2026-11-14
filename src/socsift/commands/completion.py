"""``socsift completion`` command contract."""

from __future__ import annotations

import typer

from socsift.commands._shared import unavailable
from socsift.enums import Shell


def completion(
    shell: Shell = typer.Argument(
        ...,
        metavar="bash|zsh",
        help="Shell to generate completion for.",
    ),
) -> None:
    """Print a bash or zsh completion script for SOCSift."""
    unavailable(
        f"completion {shell}",
        "The shell completion generator is not wired into this build yet.",
    )
