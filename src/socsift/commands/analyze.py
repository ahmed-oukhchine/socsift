"""``socsift analyze`` — parse evidence, run rules, and qualify alerts."""

from __future__ import annotations

from pathlib import Path

import typer

from socsift.console import console, print_error
from socsift.detection.engine import detect
from socsift.enums import LogType, OutputFormat, Severity, SortOrder
from socsift.exit_codes import ExitCode
from socsift.parsers import UnsupportedLogTypeError, parse_events
from socsift.reporting.text import (
    AnalysisReport,
    render_analysis,
    render_written_confirmation,
    write_text_report,
)
from socsift.risk.scoring import score_alert, sort_alerts
from socsift.rules.loader import RuleError, load_builtin_rules, load_rules_path
from socsift.sources import read_lines


def analyze(
    input_path: Path | None = typer.Option(
        None,
        "-i",
        "--input",
        help="Log file to analyze. Omit to read from stdin.",
        show_default=False,
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
    enrich: bool = typer.Option(
        False,
        "--enrich",
        help="Reserved for Phase 9 offline IOC context; not available yet.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TEXT,
        "-f",
        "--format",
        metavar="FORMAT",
        help="Report format; only text is available in this build.",
        case_sensitive=False,
    ),
    output_path: Path | None = typer.Option(
        None,
        "-o",
        "--output",
        help="Write the text report to a file instead of stdout.",
        show_default=False,
    ),
    min_severity: Severity = typer.Option(
        Severity.LOW,
        "-s",
        "--min-severity",
        metavar="LEVEL",
        help="Minimum severity: info, low, medium, high, or critical.",
        case_sensitive=False,
    ),
    min_score: int = typer.Option(
        0,
        "--min-score",
        min=0,
        max=100,
        help="Only keep alerts at or above this 0-100 risk score.",
    ),
    sort_order: SortOrder = typer.Option(
        SortOrder.RISK,
        "--sort",
        metavar="ORDER",
        help="Alert order: risk, severity, or time.",
        case_sensitive=False,
    ),
    explain: bool = typer.Option(
        False,
        "--explain",
        help="Show every risk-score factor for each alert.",
    ),
    config_path: Path | None = typer.Option(
        None,
        "-c",
        "--config",
        help="Reserved for the Phase 9 configuration loader; not available yet.",
        show_default=False,
    ),
) -> None:
    """Detect and qualify alerts in SSH, Windows, web, or syslog evidence."""
    if config_path is not None:
        print_error(
            "configuration files are not available in this build yet",
            hint="Use --rules to load custom detections; config arrives in Phase 9.",
        )
        raise typer.Exit(ExitCode.ERROR)

    if enrich:
        print_error(
            "IOC enrichment is not available in this build yet",
            hint="No external lookups were made. Enrichment arrives in Phase 9.",
        )
        raise typer.Exit(ExitCode.ERROR)

    if output_format is not OutputFormat.TEXT:
        print_error(
            f"the {output_format.value} report format is not available in this build",
            hint="Use -f text; the other report formats arrive in Phase 6.",
        )
        raise typer.Exit(ExitCode.ERROR)

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

    if not result.events:
        print_error(
            "no events were parsed",
            hint="Check the log format, or pass -t ssh explicitly.",
        )
        raise typer.Exit(ExitCode.ERROR)

    try:
        rules = (
            load_rules_path(rules_path) if rules_path is not None else list(load_builtin_rules())
        )
    except RuleError as exc:
        print_error(str(exc), hint="Fix the rule file, or omit --rules to use built-ins.")
        raise typer.Exit(ExitCode.ERROR) from exc

    alerts = detect(result.events, rules, min_severity=min_severity)
    scored = [score_alert(alert) for alert in alerts]
    if min_score:
        scored = [item for item in scored if item.risk.score >= min_score]
    scored = sort_alerts(scored, sort_order)

    clean_message = "No alerts matched the loaded rules."
    if alerts and not scored:
        clean_message = "Every alert was filtered out by the severity or score floor."

    format_label = result.events[0].log_source
    if log_type is LogType.AUTO:
        format_label = f"{format_label} (auto)"

    report = AnalysisReport(
        source=source,
        format_label=format_label,
        parse_result=result,
        rules_label=str(rules_path) if rules_path is not None else "built-in",
        rule_count=len(rules),
        alerts=tuple(scored),
        min_severity=min_severity,
        sort_order=sort_order,
        min_score=min_score,
        explain=explain,
        clean_message=clean_message,
    )

    if output_path is not None:
        try:
            write_text_report(output_path, report)
        except OSError as exc:
            detail = exc.strerror or str(exc)
            print_error(
                f"cannot write report: {detail}",
                hint="Check that the destination directory exists and is writable.",
            )
            raise typer.Exit(ExitCode.ERROR) from exc
        render_written_confirmation(console, report, output_path)
    else:
        render_analysis(console, report)

    raise typer.Exit(ExitCode.ALERTS if scored else ExitCode.CLEAN)
