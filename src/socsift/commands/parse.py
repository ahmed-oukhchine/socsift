"""``socsift parse`` — parser diagnostics for analysts and rule authors."""

from __future__ import annotations

from pathlib import Path

import typer
from rich import box
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from socsift.console import console, print_error
from socsift.enums import LogType
from socsift.events import Event
from socsift.exit_codes import ExitCode
from socsift.parsers import UnsupportedLogTypeError, parse_events
from socsift.parsers.base import ParseResult
from socsift.sources import read_lines


def _event_style(event: Event) -> str:
    if event.event_type in {"invalid_user", "identification_failure", "timeout"}:
        return "warn"
    if event.outcome == "success":
        return "ok"
    if event.outcome == "failure":
        return "error"
    return "muted"


def _print_summary(result: ParseResult, format_label: str) -> None:
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="muted", no_wrap=True)
    meta.add_column(style="white")
    meta.add_row("source", result.source)
    meta.add_row("format", format_label)
    meta.add_row("lines", str(result.total_lines))
    meta.add_row("events", str(len(result.events)))
    meta.add_row(
        "skipped",
        f"{result.skipped_lines} non-SSH or unparsed line(s)",
    )
    meta.add_row("coverage", f"{result.coverage:.1f}%")
    console.print(Padding(meta, (0, 0, 0, 2)))


def _print_events(result: ParseResult, limit: int) -> None:
    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="muted",
        pad_edge=False,
        expand=False,
    )
    table.add_column("LINE", justify="right", style="dim", no_wrap=True)
    table.add_column("UTC", no_wrap=True)
    table.add_column("EVENT", no_wrap=True, max_width=22, overflow="ellipsis")
    table.add_column("USER", no_wrap=True, max_width=14, overflow="ellipsis")
    table.add_column("SOURCE", no_wrap=True, max_width=20, overflow="ellipsis")

    shown = result.events[:limit]
    for event in shown:
        user = event.username or "-"
        source = event.source_ip or "-"
        table.add_row(
            str(event.line_number),
            event.timestamp.strftime("%m-%d %H:%M:%S"),
            Text(event.event_type, style=_event_style(event)),
            Text(user, style="cyan" if event.username else "muted"),
            Text(source, style="white"),
        )

    console.print(Padding(table, (0, 0, 0, 2)))
    if len(result.events) > limit:
        console.print(
            f"  [muted]Showing {limit} of {len(result.events)} events; "
            "use --limit to see more.[/]"
        )


def _print_issues(result: ParseResult) -> None:
    if not result.issues:
        return
    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="muted",
        pad_edge=False,
        expand=False,
    )
    table.add_column("LINE", justify="right", style="dim", no_wrap=True)
    table.add_column("REASON", style="warn", no_wrap=True)
    table.add_column("EXCERPT", style="muted", overflow="ellipsis", max_width=60)
    for issue in result.issues:
        table.add_row(str(issue.line_number), issue.reason, issue.excerpt)
    console.print()
    console.print("  [bold]PARSE ISSUES[/]")
    console.print(Padding(table, (0, 0, 0, 2)))


def parse_logs(
    input_path: Path | None = typer.Option(
        None,
        "-i",
        "--input",
        help="Log file to inspect. Omit to read stdin.",
        show_default=False,
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    log_type: LogType = typer.Option(
        LogType.AUTO,
        "-t",
        "--type",
        metavar="TYPE",
        help="Log source: auto, ssh, windows, web, or syslog.",
        case_sensitive=False,
    ),
    limit: int = typer.Option(
        20,
        "-n",
        "--limit",
        min=1,
        max=500,
        help="Maximum events to display.",
    ),
    show_skipped: bool = typer.Option(
        False,
        "--show-skipped",
        help="Show malformed SSH lines and their diagnostics.",
    ),
) -> None:
    """Preview normalized events and ingestion coverage for one log source."""
    try:
        lines, source = read_lines(input_path)
    except ValueError as exc:
        print_error(str(exc), hint="Pass -i FILE or pipe a log into stdin.")
        raise typer.Exit(ExitCode.ERROR) from exc
    except OSError as exc:
        print_error(f"cannot read input: {exc}", hint="Check the path and permissions.")
        raise typer.Exit(ExitCode.ERROR) from exc

    try:
        result = parse_events(lines, log_type, source=source)
    except UnsupportedLogTypeError as exc:
        print_error(str(exc), hint="Use -t ssh for OpenSSH auth.log evidence.")
        raise typer.Exit(ExitCode.ERROR) from exc

    format_label = "ssh (auto)" if log_type is LogType.AUTO else "ssh"
    console.print()
    console.print(f"[brand]INGESTION PREVIEW[/]  [muted]normalized {format_label} events[/]")
    console.print()
    _print_summary(result, format_label)

    if not result.events:
        print_error(
            "no SSH events were parsed",
            hint="Check the log format, or pass -t ssh explicitly.",
        )
        raise typer.Exit(ExitCode.ERROR)

    console.print()
    _print_events(result, limit)
    if result.issues:
        if show_skipped:
            _print_issues(result)
        else:
            console.print(
                f"  [muted]{len(result.issues)} malformed SSH line(s); "
                "run with --show-skipped for details.[/]"
            )
    console.print()
    console.print("  [ok]✓[/] [muted]Parser completed without aborting the file.[/]")
    console.print()
