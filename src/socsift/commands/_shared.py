"""Helpers shared by command modules."""

from __future__ import annotations

from typing import NoReturn

import typer
from rich.markup import escape

from socsift.console import err_console
from socsift.exit_codes import ExitCode


def unavailable(command: str, detail: str) -> NoReturn:
    """Explain that a reserved command is not wired into this build.

    Reserved commands keep the CLI contract stable while phases are built.
    They exit with code 2 (operational error), never print a traceback, and
    write the diagnostic to stderr so pipelines are not polluted.
    """
    err_console.print()
    err_console.print(f"[warn]![/] [bold]{escape(command)}[/] is not available in this build yet.")
    err_console.print(f"  [muted]{escape(detail)}[/]")
    err_console.print(
        "  [muted]Run[/] [bold]socsift --help[/] " "[muted]for the current command surface.[/]"
    )
    raise typer.Exit(ExitCode.ERROR)
