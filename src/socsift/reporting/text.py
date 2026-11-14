"""Plain-text analysis reports shared by ``analyze`` and ``rules test``."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from rich import box
from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from socsift.console import THEME
from socsift.detection.models import Alert
from socsift.enums import Severity
from socsift.events import Event
from socsift.parsers.base import ParseResult

_SEVERITY_BORDER = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "bright_red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    """Everything needed to render one analysis or rule-test result."""

    source: str
    format_label: str
    parse_result: ParseResult
    rules_label: str
    rule_count: int
    alerts: tuple[Alert, ...]
    min_severity: Severity
    title: str = "ANALYSIS REPORT"
    clean_message: str = "No alerts matched the loaded rules."


def _severity_counts(alerts: tuple[Alert, ...]) -> str:
    counts = Counter(alert.severity for alert in alerts)
    return " · ".join(
        f"{counts[severity]} {severity.value}"
        for severity in reversed(Severity)
        if counts[severity]
    )


def _format_time_range(alert: Alert) -> str:
    first = alert.first_seen
    last = alert.last_seen
    if first == last:
        return first.strftime("%Y-%m-%d %H:%M:%S UTC")
    if first.date() == last.date():
        return f"{first:%Y-%m-%d %H:%M:%S} → " f"{last:%H:%M:%S} UTC"
    return f"{first:%Y-%m-%d %H:%M:%S} → " f"{last:%Y-%m-%d %H:%M:%S} UTC"


def _append_meta(text: Text, label: str, value: str, *, style: str = "white") -> None:
    text.append(f"{label:<8}", style="muted")
    text.append(value, style=style)
    text.append("\n")


def _evidence_events(alert: Alert, limit: int = 4) -> tuple[tuple[Event, ...], int]:
    if len(alert.events) <= limit:
        return alert.events, 0
    head = alert.events[:2]
    tail = alert.events[-(limit - 2) :]
    return (*head, *tail), len(alert.events) - limit


def _alert_content(alert: Alert, *, message_width: int = 90) -> Text:
    text = Text()
    text.append(alert.severity.value.upper(), style=f"sev.{alert.severity.value}")
    text.append("  ")
    text.append(alert.rule.id, style="brand")
    text.append("  ")
    text.append(alert.rule.title, style="bold white")
    text.append("\n\n")

    _append_meta(text, "time", _format_time_range(alert))
    _append_meta(text, "source", ", ".join(alert.source_ips) or "-")
    _append_meta(text, "user", ", ".join(alert.usernames) or "-")
    if alert.hostnames:
        _append_meta(text, "host", ", ".join(alert.hostnames))
    _append_meta(text, "matched", alert.summary)
    _append_meta(text, "events", str(alert.count))

    text.append("\n")
    text.append("EVIDENCE", style="bold")
    text.append("\n")
    shown, omitted = _evidence_events(alert)
    for event in shown:
        message = event.message
        if len(message) > message_width:
            message = f"{message[: message_width - 3]}..."
        text.append(f"L{event.line_number:<4} ", style="dim")
        text.append(f"{event.timestamp:%H:%M:%S} ", style="cyan")
        text.append(message, style="white")
        text.append("\n")
    if omitted:
        text.append(f"… {omitted} more event(s)\n", style="muted")

    text.append("\n")
    _append_meta(
        text,
        "MITRE",
        f"{alert.rule.mitre.technique_id} · {alert.rule.mitre.technique_name}",
    )
    _append_meta(text, "NEXT", alert.rule.recommended_actions[0])
    return text


def render_alert_panels(
    console: Console, alerts: tuple[Alert, ...], *, label: str = "ALERT"
) -> None:
    """Print one evidence panel per alert."""
    total = len(alerts)
    message_width = max(40, console.width - 24)
    for index, alert in enumerate(alerts, start=1):
        panel = Panel(
            _alert_content(alert, message_width=message_width),
            title=Text(f"{label} {index}/{total}", style="muted"),
            title_align="left",
            border_style=_SEVERITY_BORDER[alert.severity],
            box=box.ROUNDED,
            padding=(0, 2),
        )
        console.print(panel)
        console.print()


def render_summary(console: Console, report: AnalysisReport) -> None:
    """Print ingestion metadata and the alert counter."""
    result = report.parse_result
    console.print()
    console.print(
        Text.assemble(
            (report.title, "brand"),
            ("  ", ""),
            (report.source, "muted"),
        )
    )
    console.print()

    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="muted", no_wrap=True)
    meta.add_column(style="white")
    meta.add_row("format", report.format_label)
    meta.add_row(
        "lines",
        f"{result.total_lines} · events {len(result.events)} · " f"coverage {result.coverage:.1f}%",
    )
    meta.add_row("skipped", f"{result.skipped_lines} non-SSH or unparsed line(s)")
    meta.add_row("rules", f"{report.rule_count} from {report.rules_label}")
    meta.add_row("filter", f"minimum severity {report.min_severity.value}")
    console.print(Padding(meta, (0, 0, 0, 2)))

    if result.issues:
        console.print(
            f"  [warn]![/] [muted]{len(result.issues)} malformed SSH line(s); "
            "run socsift parse --show-skipped for details.[/]"
        )

    console.print()
    if report.alerts:
        alert_label = "ALERT" if len(report.alerts) == 1 else "ALERTS"
        console.print(
            f"  [bold]{len(report.alerts)} {alert_label}[/]  "
            f"[muted]{_severity_counts(report.alerts)}[/]"
        )
    else:
        console.print(f"  [ok]✓[/] [muted]{report.clean_message}[/]")


def render_analysis(console: Console, report: AnalysisReport) -> None:
    """Render the complete text analysis."""
    render_summary(console, report)
    if not report.alerts:
        console.print()
        return

    console.print()
    render_alert_panels(console, report.alerts)
    console.print("  [muted]Inspect rule context with[/] " "[bold]socsift rules show <ID>[/]")
    console.print()


def write_text_report(path: Path, report: AnalysisReport) -> None:
    """Write the same report as plain UTF-8 text without ANSI escapes."""
    buffer = StringIO()
    plain = Console(
        file=buffer,
        theme=THEME,
        no_color=True,
        highlight=False,
        emoji=False,
        soft_wrap=False,
        width=100,
    )
    render_analysis(plain, report)
    cleaned = "\n".join(line.rstrip() for line in buffer.getvalue().splitlines())
    path.write_text(f"{cleaned}\n", encoding="utf-8", newline="\n")


def render_written_confirmation(console: Console, report: AnalysisReport, path: Path) -> None:
    """Show a compact confirmation after writing a report file."""
    console.print()
    console.print(
        Text.assemble(
            ("REPORT WRITTEN", "brand"),
            ("  ", ""),
            (str(path), "white"),
        )
    )
    alert_label = "alert" if len(report.alerts) == 1 else "alerts"
    console.print(
        f"  [muted]{len(report.alerts)} {alert_label}"
        + (f" · {_severity_counts(report.alerts)}" if report.alerts else "")
        + "[/]"
    )
    console.print()
