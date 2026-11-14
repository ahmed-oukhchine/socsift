"""Global option parsing that works before *or* after a subcommand.

Typer/Click normally only accepts group options before the subcommand. SOC
analysts type switches where they think of them, so SOCSift extracts the four
global switches from ``argv`` first and hands a clean argument list to Typer.

Options that take a value are copied with their value and skipped, so a path
such as ``-q`` passed to ``-i`` is never mistaken for a global flag. A literal
``--`` stops parsing, following normal command-line convention.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

# Options whose following token is a value, not a switch. Keep this in sync as
# new value-taking options are added to the command surface.
_VALUE_OPTIONS = frozenset(
    {
        "-i",
        "--input",
        "-t",
        "--type",
        "-f",
        "--format",
        "-o",
        "--output",
        "-s",
        "--min-severity",
        "-c",
        "--config",
        "-r",
        "--rules",
        "-p",
        "--path",
        "-n",
        "--limit",
        "--to",
        "--status",
        "--top",
        "--refresh",
        "--window",
        "--resolution",
    }
)


@dataclass(frozen=True, slots=True)
class GlobalOptions:
    """State captured by the pre-parser.

    ``verbosity`` is an integer because ``-v`` may be repeated (``-vv``).
    """

    quiet: bool = False
    verbosity: int = 0
    no_color: bool = False
    show_version: bool = False


def parse_global_options(argv: Sequence[str]) -> tuple[list[str], GlobalOptions]:
    """Split global switches out of ``argv``.

    Args:
        argv: Arguments exactly as received by the process, without the
            program name.

    Returns:
        A ``(remaining_args, options)`` pair. ``remaining_args`` is safe to
        hand to Typer.
    """
    remaining: list[str] = []
    quiet = False
    verbosity = 0
    no_color = False
    show_version = False

    index = 0
    while index < len(argv):
        token = argv[index]

        if token == "--":
            remaining.extend(argv[index:])
            break

        if token in _VALUE_OPTIONS:
            remaining.append(token)
            if index + 1 < len(argv):
                remaining.append(argv[index + 1])
                index += 2
            else:
                index += 1
            continue

        if token in ("-q", "--quiet"):
            quiet = True
        elif token in ("-v", "--verbose"):
            verbosity += 1
        elif len(token) > 2 and token.startswith("-v") and set(token[1:]) == {"v"}:
            verbosity += len(token) - 1
        elif token == "--no-color":
            no_color = True
        elif token == "--version":
            show_version = True
        else:
            remaining.append(token)

        index += 1

    return remaining, GlobalOptions(
        quiet=quiet,
        verbosity=verbosity,
        no_color=no_color,
        show_version=show_version,
    )
