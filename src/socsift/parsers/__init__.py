"""Parser selection and format sniffing."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from socsift.enums import LogType
from socsift.parsers.base import ParseResult
from socsift.parsers.ssh import SSHParser


class UnsupportedLogTypeError(ValueError):
    """Raised when no parser exists for the requested source format."""


_SSH_HINT = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")


def sniff_log_type(lines: Sequence[str]) -> LogType | None:
    """Detect the log source from a small sample of lines.

    Only SSH is implemented in this build. Future parsers add their signatures
    here without changing the CLI contract.
    """
    sample = lines[:100]
    ssh_lines = sum(1 for line in sample if _SSH_HINT.search(line))
    if ssh_lines >= 2:
        return LogType.SSH
    return None


def available_log_types() -> tuple[LogType, ...]:
    """Return the formats that currently have a working parser."""
    return (LogType.SSH,)


def parse_events(
    lines: Iterable[str],
    log_type: LogType,
    *,
    source: str = "<stdin>",
    default_year: int | None = None,
) -> ParseResult:
    """Parse lines with the requested parser.

    ``auto`` sniffs the format first. Materializing the sample is acceptable
    for the current CLI sizes; the live watch phase can add streaming once its
    ingestion API is defined.
    """
    materialized = list(lines)

    if log_type is LogType.AUTO:
        detected = sniff_log_type(materialized)
        if detected is None:
            raise UnsupportedLogTypeError("could not detect the log format; pass -t ssh explicitly")
        log_type = detected

    if log_type is not LogType.SSH:
        raise UnsupportedLogTypeError(
            f"the {log_type.value} parser is not available in this build yet"
        )

    return SSHParser(default_year=default_year).parse(materialized, source=source)
