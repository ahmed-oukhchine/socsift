"""Parser contracts and ingestion diagnostics."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from socsift.events import Event


@dataclass(frozen=True, slots=True)
class ParseIssue:
    """A line that looked like SSH evidence but could not be normalized."""

    line_number: int
    reason: str
    excerpt: str


@dataclass(slots=True)
class ParseResult:
    """Events plus enough counters to explain ingestion quality."""

    events: list[Event] = field(default_factory=list)
    total_lines: int = 0
    skipped_lines: int = 0
    issues: list[ParseIssue] = field(default_factory=list)
    source: str = "<stdin>"

    @property
    def parsed_lines(self) -> int:
        """Number of lines that produced an event."""
        return self.total_lines - self.skipped_lines

    @property
    def coverage(self) -> float:
        """Share of input lines that produced events, from 0 to 100."""
        if self.total_lines == 0:
            return 0.0
        return (len(self.events) / self.total_lines) * 100


class Parser(Protocol):
    """Minimal interface every log parser implements."""

    log_source: str

    def parse(self, lines: Iterable[str], *, source: str = "<stdin>") -> ParseResult:
        """Normalize log lines into events."""
        ...
