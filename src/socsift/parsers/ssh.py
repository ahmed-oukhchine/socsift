"""Parser for OpenSSH ``auth.log`` evidence."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from socsift.events import Event
from socsift.parsers.base import ParseIssue, ParseResult

_SYSLOG_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r")"
    r"\s+(?P<hostname>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s?"
    r"(?P<message>.*)$"
)

_ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>[A-Za-z0-9/_-]+) for (?P<username>\S+) "
    r"from (?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) "
    r"ssh2(?P<rest>.*)$"
)

_FAILED_RE = re.compile(
    r"^Failed (?P<method>[A-Za-z0-9/_-]+) for "
    r"(?P<invalid>invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) "
    r"ssh2(?P<rest>.*)$"
)

_INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<username>\S+) from "
    r"(?P<source_ip>[0-9A-Fa-f:.]+)"
    r"(?: port (?P<port>\d+))?(?P<rest>.*)$"
)

_INPUT_INVALID_USER_RE = re.compile(
    r"^input_userauth_request: invalid user (?P<username>\S+)(?: \[preauth\])?$"
)

_MAX_AUTH_RE = re.compile(
    r"^error: maximum authentication attempts exceeded for "
    r"(?P<invalid>invalid user )?(?P<username>\S+) "
    r"from (?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+) "
    r"ssh2(?P<rest>.*)$"
)

_PAM_SESSION_RE = re.compile(
    r"^pam_unix\(sshd:session\): session (?P<action>opened|closed) "
    r"for user (?P<username>[^\s(]+)(?:\(uid=\d+\))?.*$"
)

_CONNECTION_CLOSED_RE = re.compile(
    r"^Connection closed by "
    r"(?:(?P<kind>authenticating|invalid) user (?P<username>\S+) )?"
    r"(?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)(?P<rest>.*)$"
)

_DISCONNECTED_RE = re.compile(
    r"^Disconnected from "
    r"(?:(?P<kind>invalid|authenticating) user (?P<username>\S+) )?"
    r"(?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)(?P<rest>.*)$"
)

_RECEIVED_DISCONNECT_RE = re.compile(
    r"^Received disconnect from (?P<source_ip>[0-9A-Fa-f:.]+) "
    r"port (?P<port>\d+):\d+:\s*(?P<reason>.*)$"
)

_CONNECTION_FROM_RE = re.compile(
    r"^Connection from (?P<source_ip>[0-9A-Fa-f:.]+) "
    r"port (?P<port>\d+) on (?P<local_ip>[0-9A-Fa-f:.]+) "
    r"port (?P<local_port>\d+)(?P<rest>.*)$"
)

_NO_IDENT_RE = re.compile(
    r"^Did not receive identification string from "
    r"(?P<source_ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)"
)

_TIMEOUT_RE = re.compile(
    r"^Timeout before authentication for (?P<source_ip>[0-9A-Fa-f:.]+) " r"port (?P<port>\d+)"
)


@dataclass(frozen=True, slots=True)
class _Message:
    """Fields extracted from one SSH daemon message."""

    event_type: str
    outcome: str
    username: str | None = None
    source_ip: str | None = None
    port: int | None = None
    auth_method: str | None = None
    invalid_user: bool = False
    reason: str | None = None
    local_ip: str | None = None
    local_port: int | None = None


def _port(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _normalise_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _excerpt(line: str) -> str:
    compact = " ".join(line.split())
    return compact if len(compact) <= 160 else f"{compact[:157]}..."


def _failure_type(method: str) -> str:
    if method == "password":
        return "failed_password"
    if method == "publickey":
        return "failed_publickey"
    if method == "none":
        return "failed_none"
    return "failed_auth"


def _success_type(method: str) -> str:
    if method == "password":
        return "accepted_password"
    if method == "publickey":
        return "accepted_publickey"
    return "accepted_auth"


def _parse_message(message: str) -> _Message | None:
    """Normalize one sshd message.

    PAM authentication-failure lines are ignored because OpenSSH logs the same
    failure as a human-readable ``Failed ...`` line. Counting both would double
    every brute-force event.
    """
    if message.startswith("pam_unix(sshd:auth):"):
        return None

    match = _ACCEPTED_RE.match(message)
    if match is not None:
        method = match.group("method")
        return _Message(
            event_type=_success_type(method),
            outcome="success",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            auth_method=method,
        )

    match = _FAILED_RE.match(message)
    if match is not None:
        method = match.group("method")
        return _Message(
            event_type=_failure_type(method),
            outcome="failure",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            auth_method=method,
            invalid_user=bool(match.group("invalid")),
        )

    match = _INVALID_USER_RE.match(message)
    if match is not None:
        return _Message(
            event_type="invalid_user",
            outcome="info",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            invalid_user=True,
        )

    match = _INPUT_INVALID_USER_RE.match(message)
    if match is not None:
        return _Message(
            event_type="invalid_user",
            outcome="info",
            username=match.group("username"),
            invalid_user=True,
        )

    match = _MAX_AUTH_RE.match(message)
    if match is not None:
        return _Message(
            event_type="max_auth_exceeded",
            outcome="failure",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            invalid_user=bool(match.group("invalid")),
        )

    match = _PAM_SESSION_RE.match(message)
    if match is not None:
        return _Message(
            event_type=f"session_{match.group('action')}",
            outcome="info",
            username=match.group("username"),
        )

    match = _CONNECTION_CLOSED_RE.match(message)
    if match is not None:
        return _Message(
            event_type="connection_closed",
            outcome="info",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
        )

    match = _DISCONNECTED_RE.match(message)
    if match is not None:
        return _Message(
            event_type="disconnect",
            outcome="info",
            username=match.group("username"),
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
        )

    match = _RECEIVED_DISCONNECT_RE.match(message)
    if match is not None:
        return _Message(
            event_type="disconnect",
            outcome="info",
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            reason=match.group("reason").strip(),
        )

    match = _CONNECTION_FROM_RE.match(message)
    if match is not None:
        return _Message(
            event_type="connection_open",
            outcome="info",
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
            local_ip=_normalise_ip(match.group("local_ip")),
            local_port=_port(match.group("local_port")),
        )

    match = _NO_IDENT_RE.match(message)
    if match is not None:
        return _Message(
            event_type="identification_failure",
            outcome="info",
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
        )

    match = _TIMEOUT_RE.match(message)
    if match is not None:
        return _Message(
            event_type="timeout",
            outcome="info",
            source_ip=_normalise_ip(match.group("source_ip")),
            port=_port(match.group("port")),
        )

    return _Message(event_type="other", outcome="info")


class SSHParser:
    """Turn OpenSSH syslog lines into normalized :class:`Event` objects."""

    log_source = "ssh"

    def __init__(self, default_year: int | None = None) -> None:
        """Create a parser.

        Args:
            default_year: Year applied to classic ``Nov 14 10:15:01`` syslog
                timestamps, which omit the year. Defaults to the current UTC
                year.
        """
        self.default_year = default_year or datetime.now(timezone.utc).year

    def _parse_timestamp(self, value: str) -> datetime:
        if value[0].isdigit():
            normalized = value.replace("Z", "+00:00")
            # Python 3.10's fromisoformat() only accepts the extended offset
            # (+HH:MM) and 3- or 6-digit fractions. Normalize common syslog
            # variants before parsing so the parser stays portable.
            normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)
            normalized = re.sub(
                r"\.\d+",
                lambda match: match.group(0)[:7].ljust(7, "0"),
                normalized,
                count=1,
            )
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        cleaned = " ".join(value.split())
        if "." in cleaned:
            cleaned = cleaned.split(".", 1)[0]
        parsed = datetime.strptime(f"{self.default_year} {cleaned}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc)

    def parse(self, lines: Iterable[str], *, source: str = "<stdin>") -> ParseResult:
        """Parse SSH log lines.

        Non-SSH daemon lines (cron, sudo, ...) are counted as skipped. SSH
        daemon lines that cannot be parsed become diagnostics rather than
        aborting the whole ingestion.
        """
        result = ParseResult(source=source)

        for line_number, raw_line in enumerate(lines, start=1):
            result.total_lines += 1
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                result.skipped_lines += 1
                continue

            syslog = _SYSLOG_RE.match(line)
            if syslog is None:
                result.skipped_lines += 1
                if "sshd" in line:
                    result.issues.append(
                        ParseIssue(
                            line_number=line_number,
                            reason="not a recognised syslog line",
                            excerpt=_excerpt(line),
                        )
                    )
                continue

            process = syslog.group("process")
            if not process.startswith("sshd"):
                result.skipped_lines += 1
                continue

            try:
                timestamp = self._parse_timestamp(syslog.group("timestamp"))
            except ValueError:
                result.skipped_lines += 1
                result.issues.append(
                    ParseIssue(
                        line_number=line_number,
                        reason="invalid timestamp",
                        excerpt=_excerpt(line),
                    )
                )
                continue

            message = syslog.group("message")
            parsed = _parse_message(message)
            if parsed is None:
                result.skipped_lines += 1
                continue

            pid_text = syslog.group("pid")
            fields: dict[str, object] = {
                "outcome": parsed.outcome,
                "port": parsed.port,
                "auth_method": parsed.auth_method,
                "invalid_user": parsed.invalid_user,
                "is_root": parsed.username == "root",
                "pid": int(pid_text) if pid_text else None,
                "service": "sshd",
            }
            if parsed.reason:
                fields["disconnect_reason"] = parsed.reason
            if parsed.local_ip:
                fields["local_ip"] = parsed.local_ip
                fields["local_port"] = parsed.local_port

            result.events.append(
                Event(
                    timestamp=timestamp,
                    log_source=self.log_source,
                    event_type=parsed.event_type,
                    message=message,
                    raw=line,
                    source=source,
                    line_number=line_number,
                    hostname=syslog.group("hostname"),
                    source_ip=parsed.source_ip,
                    username=parsed.username,
                    fields=fields,
                )
            )

        return result
