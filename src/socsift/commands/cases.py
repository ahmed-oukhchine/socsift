"""``socsift cases`` command group."""

from __future__ import annotations

import typer

from socsift.commands._shared import unavailable
from socsift.enums import EscalationLevel

cases_app = typer.Typer(
    name="cases",
    help="Work the local SQLite case queue.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


@cases_app.command("list")
def list_cases() -> None:
    """List open and recent cases."""
    unavailable("cases list", "The SQLite case store is not wired into this build yet.")


@cases_app.command("show")
def show_case(
    case_id: str = typer.Argument(..., help="Case identifier."),
) -> None:
    """Show a case, its evidence, notes, and current status."""
    unavailable(
        f"cases show {case_id}",
        "The SQLite case store is not wired into this build yet.",
    )


@cases_app.command("note")
def note_case(
    case_id: str = typer.Argument(..., help="Case identifier."),
    text: str = typer.Argument(..., help="Analyst note to append."),
) -> None:
    """Append a timestamped analyst note to a case."""
    unavailable(
        f"cases note {case_id}",
        "The SQLite case store is not wired into this build yet.",
    )


@cases_app.command("escalate")
def escalate_case(
    case_id: str = typer.Argument(..., help="Case identifier."),
    to: EscalationLevel = typer.Option(
        ...,
        "--to",
        metavar="N2|N3",
        help="Tier that should take over the case.",
        case_sensitive=False,
    ),
) -> None:
    """Escalate a case to N2 or N3 with an audit trail."""
    unavailable(
        f"cases escalate {case_id}",
        "The SQLite case store is not wired into this build yet.",
    )


@cases_app.command("close")
def close_case(
    case_id: str = typer.Argument(..., help="Case identifier."),
) -> None:
    """Close a case after documenting the resolution."""
    unavailable(
        f"cases close {case_id}",
        "The SQLite case store is not wired into this build yet.",
    )
