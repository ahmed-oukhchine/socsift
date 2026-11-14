"""Kali-inspired wordmark and the no-argument landing screen."""

from __future__ import annotations

from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from socsift import __version__
from socsift.console import console

# Six-row ANSI-shadow style glyphs. Each glyph is padded to its own width; the
# renderer adds one column of spacing between letters.
_WORDMARK: dict[str, tuple[str, ...]] = {
    "S": (
        "███████╗",
        "██╔════╝",
        "███████╗",
        "╚════██║",
        "███████║",
        "╚══════╝",
    ),
    "O": (
        " ██████╗ ",
        "██╔═══██╗",
        "██║   ██║",
        "██║   ██║",
        "╚██████╔╝",
        " ╚═════╝ ",
    ),
    "C": (
        " ██████╗",
        "██╔════╝",
        "██║     ",
        "██║     ",
        "╚██████╗",
        " ╚═════╝",
    ),
    "I": (
        "██╗",
        "██║",
        "██║",
        "██║",
        "██║",
        "╚═╝",
    ),
    "F": (
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "██║     ",
        "╚═╝     ",
    ),
    "T": (
        "████████╗",
        "╚══██╔══╝",
        "   ██║   ",
        "   ██║   ",
        "   ██║   ",
        "   ╚═╝   ",
    ),
}

_BANNER_STYLES = (
    "bold #22d3ee",
    "bold #06b6d4",
    "bold #0ea5e9",
    "bold #0284c7",
    "bold #0369a1",
    "bold #075985",
)

_COMMANDS = (
    ("analyze", "Detect and qualify alerts in a log file or stdin"),
    ("watch", "Follow a live alert feed in the terminal"),
    ("correlate", "Merge related alerts from several sources into incidents"),
    ("rules", "List, inspect, validate, and test YAML detections"),
    ("parse", "Preview normalized events and ingestion coverage"),
    ("cases", "Work the local case queue"),
    ("stats", "Profile top talkers and hourly activity"),
    ("export", "Package a case for TheHive, JSON, or Markdown"),
    ("completion", "Emit shell completion for bash or zsh"),
)


def render_wordmark(word: str = "SOCSIFT") -> list[str]:
    """Render ``word`` as six aligned ASCII-art rows.

    Raises:
        ValueError: If a character has no glyph in the wordmark font.
    """
    rows = [""] * 6
    for char in word.upper():
        try:
            glyph = _WORDMARK[char]
        except KeyError as exc:
            raise ValueError(f"no banner glyph for {char!r}") from exc
        width = max(len(line) for line in glyph)
        for number, line in enumerate(glyph):
            rows[number] += line.ljust(width) + " "
    return [row.rstrip() for row in rows]


def show_banner() -> None:
    """Print the product wordmark, tagline, version, and use notice."""
    for line, style in zip(render_wordmark(), _BANNER_STYLES, strict=True):
        console.print(Text(f"  {line}", style=style))

    console.print()
    console.print("  " + "─" * 61, style="dim")
    console.print(
        "  [bold white]BLUE-TEAM TRIAGE[/]  [dim]·[/]  "
        "[bold white]ALERT QUALIFICATION[/]  [dim]·[/]  "
        "[bold white]INCIDENT SIFTING[/]"
    )
    console.print(f"  [dim]v{__version__}  ·  offline-first  ·  authorized defensive use only[/]")
    console.print()


def show_landing(*, show_logo: bool = True) -> None:
    """Print the help screen shown when SOCSift is run without a command."""
    if show_logo:
        show_banner()

    console.print(
        Padding(
            Text(
                "Turn raw logs into qualified alerts, correlated incidents, "
                "and defensible cases.",
                style="dim",
            ),
            (0, 0, 0, 2),
        )
    )
    console.print()
    console.print("  [bold]USAGE[/]  [brand]socsift[/] [cyan]<command>[/] [dim][options][/]")
    console.print()

    table = Table(
        box=None,
        show_header=True,
        header_style="muted",
        padding=(0, 2),
        pad_edge=False,
    )
    table.add_column("COMMAND", style="bold cyan", no_wrap=True, width=12)
    table.add_column("PURPOSE", style="white")
    for command, purpose in _COMMANDS:
        table.add_row(command, purpose)
    console.print(Padding(table, (0, 0, 0, 2)))

    console.print()
    console.print(
        "  [bold]GLOBAL[/]  [cyan]-q/--quiet[/] [dim]·[/] "
        "[cyan]-v/--verbose[/] [dim]·[/] [cyan]--no-color[/] [dim]·[/] "
        "[cyan]--version[/]"
    )
    console.print("  [bold]START[/]   [bold cyan]socsift analyze --help[/]")
    console.print()
    console.print(
        Padding(
            Text(
                "Authorized defensive use only. Keep evidence local; "
                "redact data before sharing.",
                style="dim",
            ),
            (0, 0, 0, 2),
        )
    )
