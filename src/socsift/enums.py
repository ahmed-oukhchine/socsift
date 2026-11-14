"""Small, typed vocabularies used by the CLI and the detection engine."""

from __future__ import annotations

from enum import Enum


class _ValueEnum(str, Enum):
    """String enum whose ``str()`` is the CLI value, never ``Class.member``."""

    def __str__(self) -> str:
        return self.value


class LogType(_ValueEnum):
    """Supported log sources (``auto`` sniffs the format later)."""

    AUTO = "auto"
    SSH = "ssh"
    WINDOWS = "windows"
    WEB = "web"
    SYSLOG = "syslog"


class OutputFormat(_ValueEnum):
    """Report formats produced by ``socsift analyze`` and ``export``."""

    TEXT = "text"
    MARKDOWN = "md"
    JSON = "json"
    HTML = "html"
    CSV = "csv"


class Severity(_ValueEnum):
    """Alert severity ordered from least to most urgent."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return a sortable rank (0 = info, 4 = critical)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class EscalationLevel(_ValueEnum):
    """Analyst tier a case can be escalated to."""

    N2 = "n2"
    N3 = "n3"


class ExportTarget(_ValueEnum):
    """Ticket/report payload formats for ``socsift export``."""

    THEHIVE = "thehive"
    JSON = "json"
    MARKDOWN = "md"


class Shell(_ValueEnum):
    """Shells supported by ``socsift completion``."""

    BASH = "bash"
    ZSH = "zsh"
