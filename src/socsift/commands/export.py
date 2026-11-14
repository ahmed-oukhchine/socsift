"""``socsift export`` command contract."""

from __future__ import annotations

import typer

from socsift.commands._shared import unavailable
from socsift.enums import ExportTarget


def export_case(
    case_id: str = typer.Argument(..., help="Case identifier to export."),
    target: ExportTarget = typer.Option(
        ...,
        "--to",
        metavar="TARGET",
        help="Payload format: thehive, json, or md.",
        case_sensitive=False,
    ),
) -> None:
    """Export a case as a TheHive, JSON, or Markdown payload."""
    unavailable(
        f"export {case_id}",
        "The report and TheHive exporters are not wired into this build yet.",
    )
