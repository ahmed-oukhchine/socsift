"""Shared Rich console, theme, and safe error output."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.markup import escape
from rich.theme import Theme

THEME = Theme(
    {
        "brand": "bold bright_cyan",
        "muted": "dim",
        "ok": "bold green",
        "warn": "bold yellow",
        "error": "bold red",
        "sev.info": "dim",
        "sev.low": "cyan",
        "sev.medium": "yellow",
        "sev.high": "bold red",
        "sev.critical": "bold white on red",
    }
)

# One console for the whole process: consistent width, no automatic highlighting
# of numbers/IPs, and a single place to configure colour.
console = Console(theme=THEME, highlight=False, emoji=False, soft_wrap=False)
err_console = Console(
    theme=THEME,
    highlight=False,
    emoji=False,
    soft_wrap=False,
    stderr=True,
)


def configure_output(*, no_color: bool) -> None:
    """Apply process-wide output preferences from the global CLI flags."""
    console.no_color = no_color
    err_console.no_color = no_color


def enable_utf8_output() -> None:
    """Make redirected Windows output UTF-8 safe.

    The Wordmark uses box-drawing characters. In a legacy ``cmd.exe`` pipeline
    the default ``cp1252`` text wrapper would raise ``UnicodeEncodeError`` and
    leak a traceback. Reconfiguring with ``errors="replace"`` keeps the CLI
    usable everywhere while preserving the intended glyphs in UTF-8 terminals.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError, ValueError):
            # A wrapped or detached stream may not support reconfiguration.
            continue


def print_error(message: str, *, hint: str | None = None) -> None:
    """Print a user-facing error without a traceback.

    Rich markup is escaped because messages may contain paths or log content.
    """
    err_console.print(f"[error]error[/] {escape(message)}")
    if hint:
        err_console.print(f"  [muted]{escape(hint)}[/]")
