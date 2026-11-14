"""Alert objects produced by the detection engine."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from socsift.enums import Severity
from socsift.events import Event
from socsift.rules.models import DetectionRule


@dataclass(frozen=True, slots=True)
class Alert:
    """One qualified detection with the evidence that produced it.

    Alerts keep the full ``DetectionRule`` so later phases (risk scoring,
    reports, cases) can use severity, MITRE metadata, false positives, and
    recommended actions without a second lookup.
    """

    rule: DetectionRule
    events: tuple[Event, ...]
    group: Mapping[str, str]
    summary: str

    @property
    def severity(self) -> Severity:
        """Severity inherited from the rule."""
        return self.rule.severity

    @property
    def rule_id(self) -> str:
        """Shorthand used by reports and case payloads."""
        return self.rule.id

    @property
    def first_seen(self) -> datetime:
        """Timestamp of the earliest event in the alert."""
        return self.events[0].timestamp

    @property
    def last_seen(self) -> datetime:
        """Timestamp of the latest event in the alert."""
        return self.events[-1].timestamp

    @property
    def count(self) -> int:
        """Number of evidence events attached to the alert."""
        return len(self.events)

    @property
    def source_ips(self) -> tuple[str, ...]:
        """Unique source addresses, sorted for deterministic reports."""
        return tuple(sorted({event.source_ip for event in self.events if event.source_ip}))

    @property
    def usernames(self) -> tuple[str, ...]:
        """Unique usernames, sorted for deterministic reports."""
        return tuple(sorted({event.username for event in self.events if event.username}))

    @property
    def hostnames(self) -> tuple[str, ...]:
        """Unique affected hosts, sorted for deterministic reports."""
        return tuple(sorted({event.hostname for event in self.events if event.hostname}))
