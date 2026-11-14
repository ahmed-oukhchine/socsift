"""SOCSift command-line entry point.

Global switches are extracted by :func:`socsift.options.parse_global_options`
before Typer sees the arguments, so they work before or after a subcommand.
Typer then handles command routing, help pages, and usage errors. User mistakes
surface as short Click errors and exit code 2, never as Python tracebacks.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

import typer

from socsift import __version__
from socsift.banner import show_banner, show_landing
from socsift.commands.analyze import analyze
from socsift.commands.cases import cases_app
from socsift.commands.completion import completion
from socsift.commands.correlate import correlate
from socsift.commands.export import export_case
from socsift.commands.parse import parse_logs
from socsift.commands.rules import rules_app
from socsift.commands.stats import stats
from socsift.commands.watch import watch
from socsift.console import configure_output, console, enable_utf8_output, print_error
from socsift.exit_codes import ExitCode
from socsift.options import parse_global_options

APP_HELP = (
    "SOCSift is a blue-team triage console for security logs.\n\n"
    "It turns SSH, Windows, web, and syslog evidence into qualified alerts, "
    "correlated incidents, and case-ready reports — offline by default."
)

app = typer.Typer(
    name="socsift",
    help=APP_HELP,
    epilog=(
        "Run [bold]socsift <command> --help[/] for command details. "
        "Authorized defensive use only."
    ),
    no_args_is_help=False,
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=False,
    context_settings={"help_option_names": ["-h", "--help"]},
)


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    quiet: bool = typer.Option(
        False,
        "-q",
        "--quiet",
        help="Hide the banner and non-essential output.",
    ),
    verbosity: int = typer.Option(
        0,
        "-v",
        "--verbose",
        count=True,
        help="Increase diagnostic verbosity (repeatable).",
    ),
    no_color: bool = typer.Option(
        False,
        "--no-color",
        help="Disable ANSI colour output.",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        help="Print the SOCSift version and exit.",
    ),
) -> None:
    """Route commands and handle the no-command landing screen.

    The global switches are declared here so they appear in ``--help``. Their
    values are actually consumed by :func:`main` before Typer dispatch, which
    is why the parameters are intentionally unused.
    """
    del quiet, verbosity, no_color
    if version:
        typer.echo(f"socsift {__version__}")
        raise typer.Exit(ExitCode.CLEAN)
    if ctx.invoked_subcommand is None:
        show_landing()
        raise typer.Exit(ExitCode.CLEAN)


app.command("analyze", rich_help_panel="Detection")(
    analyze,
)
app.command("watch", rich_help_panel="Detection")(
    watch,
)
app.command("correlate", rich_help_panel="Investigation")(
    correlate,
)
app.add_typer(rules_app, name="rules", rich_help_panel="Investigation")
app.command("stats", rich_help_panel="Investigation")(
    stats,
)
app.add_typer(cases_app, name="cases", rich_help_panel="Case workflow")
app.command("export", rich_help_panel="Case workflow")(
    export_case,
)
app.command("parse", rich_help_panel="Diagnostics")(parse_logs)
app.command("completion", rich_help_panel="Utility")(
    completion,
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and translate every outcome into a stable exit code.

    Args:
        argv: Optional argument list for tests; defaults to ``sys.argv[1:]``.

    Returns:
        ``0`` for a clean run, ``1`` when alerts are produced, ``2`` for an
        operational or usage error.
    """
    raw_args = list(sys.argv[1:] if argv is None else argv)
    enable_utf8_output()
    args, options = parse_global_options(raw_args)
    configure_output(no_color=options.no_color)

    if options.show_version:
        typer.echo(f"socsift {__version__}")
        return int(ExitCode.CLEAN)

    if not args:
        show_landing(show_logo=not options.quiet)
        return int(ExitCode.CLEAN)

    help_requested = any(token in ("-h", "--help") for token in args)
    if help_requested and not options.quiet:
        show_banner()

    try:
        app(args=args, prog_name="socsift")
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return int(ExitCode.CLEAN)
        if isinstance(code, int):
            if code == 130:
                print_error("interrupted")
                return int(ExitCode.ERROR)
            return code
        return int(ExitCode.ERROR)
    except KeyboardInterrupt:
        print_error("interrupted")
        return int(ExitCode.ERROR)
    except Exception as exc:  # Defensive boundary: no traceback for users.
        if options.verbosity:
            console.print_exception()
        else:
            print_error(
                f"unexpected failure: {exc}",
                hint="Re-run with -v for a traceback.",
            )
        return int(ExitCode.ERROR)

    return int(ExitCode.CLEAN)
