"""``socsift rules`` — inspect, validate, and explain YAML detections."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import typer
from rich import box
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from socsift.console import console, print_error
from socsift.detection.engine import detect
from socsift.enums import LogType, Severity, SortOrder
from socsift.exit_codes import ExitCode
from socsift.parsers import UnsupportedLogTypeError, parse_events
from socsift.reporting.text import AnalysisReport, render_analysis
from socsift.risk.scoring import base_score, score_alert, sort_alerts
from socsift.rules.loader import (
    RuleError,
    find_rule,
    load_builtin_rules,
    load_rules_path,
)
from socsift.rules.models import DetectionRule, format_duration
from socsift.sources import read_lines

rules_app = typer.Typer(
    name="rules",
    help="Inspect, validate, and test YAML detection rules.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)


def _severity_text(severity: Severity) -> Text:
    return Text(severity.value.upper(), style=f"sev.{severity.value}")


def _rule_source(path: Path | None) -> str:
    return "built-in" if path is None else str(path)


def _load_rules(path: Path | None) -> list[DetectionRule]:
    """Load custom rules when a path is given, otherwise the built-ins."""
    if path is None:
        return list(load_builtin_rules())
    return load_rules_path(path)


def _condition_label(rule: DetectionRule) -> str:
    if rule.condition.value == "selection":
        return "selection"
    threshold = rule.threshold
    if threshold is None:  # Defensive: the loader rejects this shape.
        return rule.condition.value
    count = f"{threshold.count} event{'s' if threshold.count != 1 else ''}"
    window = format_duration(threshold.window)
    grouped = f" per {', '.join(threshold.group_by)}"
    if rule.condition.value == "sequence":
        followup = format_duration(rule.followup_window) if rule.followup_window else "-"
        return f"sequence · {count} / {window}{grouped} · follow-up within {followup}"
    return f"threshold · {count} / {window}{grouped}"


def _format_value(value: object) -> str:
    """Render a selection value the way an analyst would write it."""
    if isinstance(value, list):
        return ", ".join(_format_value(item) for item in value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _print_selection(selection: dict[str, object]) -> None:
    """Print one selection block as escaped ``field == value`` lines."""
    for field, value in selection.items():
        console.print(
            Padding(
                Text.assemble(
                    (f"{field}", "cyan"),
                    (" == ", "muted"),
                    (_format_value(value), "white"),
                ),
                (0, 0, 0, 4),
            )
        )


def _load_or_fail(path: Path | None) -> list[DetectionRule]:
    try:
        return _load_rules(path)
    except RuleError as exc:
        print_error(str(exc), hint="Fix the rule file, then re-run the command.")
        raise typer.Exit(ExitCode.ERROR) from exc


@rules_app.command("list")
def list_rules(
    path: Path | None = typer.Option(
        None,
        "-p",
        "--path",
        help="Rule file or directory to list instead of the built-in library.",
        show_default=False,
    ),
) -> None:
    """List detection rules and their metadata."""
    rules = _load_or_fail(path)
    ordered = sorted(rules, key=lambda rule: (-rule.severity.rank, rule.id))

    counts = Counter(rule.severity for rule in rules)
    console.print()
    console.print(
        f"[brand]RULE LIBRARY[/]  [muted]{_rule_source(path)} · "
        f"{len(rules)} detection{'s' if len(rules) != 1 else ''}[/]"
    )
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="muted",
        pad_edge=False,
        expand=False,
    )
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("TYPE", no_wrap=True)
    table.add_column("TITLE", overflow="fold")

    for rule in ordered:
        table.add_row(
            rule.id,
            _severity_text(rule.severity),
            rule.condition.value,
            Text(rule.title),
        )

    console.print(Padding(table, (0, 0, 0, 2)))

    summary = " · ".join(
        f"{counts[severity]} {severity.value}"
        for severity in reversed(Severity)
        if counts[severity]
    )
    console.print()
    console.print(f"  [muted]{summary}[/]")
    console.print("  [muted]Inspect one rule with[/] [bold]socsift rules show <ID>[/]")
    console.print()


@rules_app.command("show")
def show_rule(
    rule_id: str = typer.Argument(..., help="Rule id, for example SSH-BRUTE-001."),
    path: Path | None = typer.Option(
        None,
        "-p",
        "--path",
        help="Rule file or directory to search instead of the built-in library.",
        show_default=False,
    ),
) -> None:
    """Show the full definition of one detection rule."""
    rules = _load_or_fail(path)
    try:
        rule = find_rule(rules, rule_id)
    except LookupError as exc:
        print_error(
            f"no rule with id {rule_id}",
            hint="Run socsift rules list to see the available ids.",
        )
        raise typer.Exit(ExitCode.ERROR) from exc

    console.print()
    console.print(
        Text.assemble(
            (rule.id, "brand"),
            ("  ·  ", "muted"),
            (rule.title, "bold white"),
        )
    )
    status = f"  ·  {rule.status}" if rule.status else ""
    console.print(
        Text.assemble(
            ("severity ", "muted"),
            (rule.severity.value, f"sev.{rule.severity.value}"),
            (status, "muted"),
            ("  ·  ", "muted"),
            (rule.condition.value, "cyan"),
        )
    )
    console.print()
    console.print(Padding(Text(rule.description, style="dim"), (0, 0, 0, 2)))

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="muted", no_wrap=True, width=14)
    meta.add_column(style="white")
    meta.add_row("log source", f"{rule.logsource['product']}/{rule.logsource['service']}")
    meta.add_row("detection", _condition_label(rule))
    meta.add_row(
        "risk base",
        f"{base_score(rule.severity)}/100 from severity {rule.severity.value}",
    )
    meta.add_row(
        "MITRE ATT&CK",
        f"{rule.mitre.technique_id} · {rule.mitre.technique_name} " f"({rule.mitre.tactic})",
    )
    meta.add_row("author", rule.author or "-")
    meta.add_row("date", rule.date or "-")
    meta.add_row("source", rule.source)

    console.print()
    console.print("  [bold]DETECTION[/]")
    console.print(Padding(meta, (0, 0, 0, 2)))

    console.print()
    console.print("  [muted]selection[/]")
    _print_selection(dict(rule.selection))
    if rule.followup:
        console.print("  [muted]follow-up[/]")
        _print_selection(dict(rule.followup))

    console.print()
    console.print("  [bold]FALSE POSITIVES[/]")
    for item in rule.falsepositives:
        console.print(Padding(Text(f"· {item}", style="muted"), (0, 0, 0, 4)))

    console.print()
    console.print("  [bold]RECOMMENDED ACTIONS[/]")
    for index, item in enumerate(rule.recommended_actions, start=1):
        console.print(Padding(Text(f"{index}. {item}"), (0, 0, 0, 4)))

    if rule.references:
        console.print()
        console.print("  [bold]REFERENCES[/]")
        for item in rule.references:
            console.print(Padding(Text(f"· {item}", style="muted"), (0, 0, 0, 4)))

    if rule.tags:
        console.print()
        console.print(
            Text.assemble(
                ("  tags  ", "muted"),
                (" · ".join(rule.tags), "dim"),
            )
        )
    console.print()


@rules_app.command("validate")
def validate_rules(
    path: Path = typer.Argument(
        ...,
        help="Rule file or directory to validate.",
    ),
) -> None:
    """Check rule files for schema, metadata, and condition errors."""
    try:
        rules = load_rules_path(path)
    except RuleError as exc:
        print_error(str(exc), hint="Fix the rule file, then re-run validation.")
        raise typer.Exit(ExitCode.ERROR) from exc

    console.print()
    console.print(
        f"[brand]RULE VALIDATION[/]  [muted]{path} · "
        f"{len(rules)} file{'s' if len(rules) != 1 else ''} passed[/]"
    )
    console.print()

    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="muted",
        pad_edge=False,
        expand=False,
    )
    table.add_column("STATUS", no_wrap=True)
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("TYPE", no_wrap=True)
    table.add_column("FILE", style="muted", overflow="fold")

    for rule in rules:
        table.add_row(
            Text("valid", style="ok"),
            rule.id,
            rule.condition.value,
            Path(rule.source).name,
        )

    console.print(Padding(table, (0, 0, 0, 2)))
    console.print()
    console.print(
        "  [ok]✓[/] [muted]All rules match the SOCSift schema and can be "
        "loaded by the detection engine.[/]"
    )
    console.print()


@rules_app.command("test")
def run_rule_test(
    rule_id: str = typer.Argument(..., help="Rule id to exercise."),
    input_path: Path = typer.Option(
        ...,
        "-i",
        "--input",
        help="Log file used to test the rule.",
    ),
    log_type: LogType = typer.Option(
        LogType.AUTO,
        "-t",
        "--type",
        metavar="TYPE",
        help="Log source: auto, ssh, windows, web, or syslog.",
        case_sensitive=False,
    ),
    rules_path: Path | None = typer.Option(
        None,
        "-r",
        "--rules",
        help="Rule file or directory. Defaults to the built-in library.",
        show_default=False,
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Show every risk-score factor for each match.",
    ),
) -> None:
    """Run one rule against a log and show every match."""
    rules = _load_or_fail(rules_path)
    try:
        rule = find_rule(rules, rule_id)
    except LookupError as exc:
        print_error(
            f"no rule with id {rule_id}",
            hint="Run socsift rules list to see the available ids.",
        )
        raise typer.Exit(ExitCode.ERROR) from exc

    try:
        lines, source = read_lines(input_path)
    except ValueError as exc:
        print_error(str(exc), hint="Pass -i FILE for the log to test.")
        raise typer.Exit(ExitCode.ERROR) from exc
    except OSError as exc:
        print_error(f"cannot read input: {exc}", hint="Check the path and permissions.")
        raise typer.Exit(ExitCode.ERROR) from exc

    try:
        result = parse_events(lines, log_type, source=source)
    except UnsupportedLogTypeError as exc:
        print_error(str(exc), hint="Use -t ssh for OpenSSH auth.log evidence.")
        raise typer.Exit(ExitCode.ERROR) from exc

    if not result.events:
        print_error(
            "no events were parsed",
            hint="Check the log format, or pass -t ssh explicitly.",
        )
        raise typer.Exit(ExitCode.ERROR)

    alerts = detect(result.events, [rule], min_severity=Severity.INFO)
    scored = sort_alerts((score_alert(alert) for alert in alerts), SortOrder.RISK)

    format_label = result.events[0].log_source
    if log_type is LogType.AUTO:
        format_label = f"{format_label} (auto)"

    report = AnalysisReport(
        source=source,
        format_label=format_label,
        parse_result=result,
        rules_label=str(rules_path) if rules_path is not None else "built-in",
        rule_count=1,
        alerts=tuple(scored),
        min_severity=Severity.INFO,
        explain=explain,
        title="RULE TEST",
        clean_message=f"No events matched {rule.id}.",
    )
    render_analysis(console, report)
    raise typer.Exit(ExitCode.ALERTS if scored else ExitCode.CLEAN)
