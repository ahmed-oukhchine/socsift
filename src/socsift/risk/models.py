"""Explainable risk objects shared by scoring and report rendering."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from socsift.detection.models import Alert
from socsift.enums import Priority, Severity
from socsift.events import Event
from socsift.rules.models import DetectionRule

# Score bands are deliberately wide enough to stay stable when one factor
# changes. Severity remains the rule author's voice; priority is the queue
# order produced by the assembled evidence.
_P1_FLOOR = 85
_P2_FLOOR = 60
_P3_FLOOR = 35


def priority_for_score(score: int) -> Priority:
    """Map a 0-100 score to an operational triage band."""
    if score >= _P1_FLOOR:
        return Priority.P1
    if score >= _P2_FLOOR:
        return Priority.P2
    if score >= _P3_FLOOR:
        return Priority.P3
    return Priority.P4


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One named, additive contribution to an alert's score.

    ``detail`` is written for an analyst reading a ticket, not for a log
    parser, so it can mention the concrete host, address, or account that
    earned the points.
    """

    name: str
    points: int
    detail: str


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A deterministic 0-100 score with every factor that produced it."""

    factors: tuple[RiskFactor, ...]

    @property
    def raw(self) -> int:
        """Sum of all factors before the 0-100 clamp."""
        return sum(factor.points for factor in self.factors)

    @property
    def score(self) -> int:
        """Final clamped score shown in reports."""
        return min(100, max(0, self.raw))

    @property
    def capped(self) -> bool:
        """Whether the raw total exceeded the 100-point ceiling."""
        return self.raw > 100

    @property
    def priority(self) -> Priority:
        """Operational band derived from the final score."""
        return priority_for_score(self.score)


@dataclass(frozen=True, slots=True)
class ScoredAlert:
    """An alert paired with its risk assessment.

    Detection stays independent from prioritization: the engine emits
    :class:`~socsift.detection.models.Alert` objects, and this wrapper adds the
    score at the command boundary. Reports can keep reading alert fields
    directly through the delegating properties below.
    """

    alert: Alert
    risk: RiskScore

    @property
    def rule(self) -> DetectionRule:
        """Detection rule that produced the alert."""
        return self.alert.rule

    @property
    def severity(self) -> Severity:
        """Severity inherited from the rule."""
        return self.alert.severity

    @property
    def rule_id(self) -> str:
        """Shorthand used by reports and case payloads."""
        return self.alert.rule_id

    @property
    def summary(self) -> str:
        """Human-readable match summary."""
        return self.alert.summary

    @property
    def group(self) -> Mapping[str, str]:
        """Grouping values used by threshold and sequence rules."""
        return self.alert.group

    @property
    def events(self) -> tuple[Event, ...]:
        """Evidence events attached to the alert."""
        return self.alert.events

    @property
    def first_seen(self) -> datetime:
        """Timestamp of the earliest evidence event."""
        return self.alert.first_seen

    @property
    def last_seen(self) -> datetime:
        """Timestamp of the latest evidence event."""
        return self.alert.last_seen

    @property
    def count(self) -> int:
        """Number of evidence events."""
        return self.alert.count

    @property
    def source_ips(self) -> tuple[str, ...]:
        """Unique source addresses."""
        return self.alert.source_ips

    @property
    def usernames(self) -> tuple[str, ...]:
        """Unique usernames."""
        return self.alert.usernames

    @property
    def hostnames(self) -> tuple[str, ...]:
        """Unique affected hosts."""
        return self.alert.hostnames
