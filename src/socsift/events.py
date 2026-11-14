"""Normalized evidence shared by parsers, detection rules, and reports."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class Event:
    """One normalized log event.

    Parsers keep the common fields below strongly typed and put source-specific
    values (``outcome``, ``port``, ``auth_method``, ...) in ``fields``. Detection
    rules address both through :meth:`get`, so a YAML rule does not need to know
    which parser produced the event.

    Timestamps are normalized to timezone-aware UTC by every parser.
    """

    timestamp: datetime
    log_source: str
    event_type: str
    message: str
    raw: str
    source: str
    line_number: int
    hostname: str | None = None
    source_ip: str | None = None
    username: str | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Return a field by name, or ``None`` when it is unavailable.

        Source-specific fields win over the common fields so a parser can
        deliberately override a value without changing the model.
        """
        if name in self.fields:
            return self.fields[name]
        return getattr(self, name, None)

    @property
    def outcome(self) -> str | None:
        """Authentication outcome (``success``, ``failure``, ``info``)."""
        value = self.fields.get("outcome")
        return str(value) if value is not None else None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event for JSON reports and ticket payloads."""
        payload: dict[str, Any] = {
            "timestamp": self.timestamp.isoformat(),
            "log_source": self.log_source,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "username": self.username,
            "message": self.message,
            "source": self.source,
            "line_number": self.line_number,
            "fields": dict(self.fields),
        }
        return payload
