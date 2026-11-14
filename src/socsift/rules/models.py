"""Typed detection-rule model shared by the loader and later engines."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum

from socsift.enums import Severity

RuleScalar = str | int | float | bool
RuleValue = RuleScalar | list[RuleScalar]
Selection = Mapping[str, RuleValue]


class RuleCondition(str, Enum):
    """Supported detection shapes."""

    SELECTION = "selection"
    THRESHOLD = "threshold"
    SEQUENCE = "sequence"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class MitreMapping:
    """MITRE ATT&CK metadata attached to a detection."""

    tactic: str
    technique: str
    technique_name: str
    subtechnique: str | None = None
    url: str | None = None

    @property
    def technique_id(self) -> str:
        """Return the most specific technique identifier."""
        return self.subtechnique or self.technique


@dataclass(frozen=True, slots=True)
class RuleThreshold:
    """Count-and-window aggregation used by threshold/sequence rules."""

    count: int
    window: timedelta
    group_by: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """A validated, code-independent detection rule.

    Rules are immutable data. The detection engine receives these objects, not
    raw YAML, which keeps matching logic separate from parsing and validation.
    """

    id: str
    title: str
    description: str
    severity: Severity
    logsource: Mapping[str, str]
    condition: RuleCondition
    selection: Selection
    threshold: RuleThreshold | None
    followup: Selection | None
    followup_window: timedelta | None
    mitre: MitreMapping
    falsepositives: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    references: tuple[str, ...]
    tags: tuple[str, ...]
    status: str | None
    author: str | None
    date: str | None
    source: str


def format_duration(value: timedelta) -> str:
    """Render a timedelta in compact SOC notation (``5m``, ``2h``)."""
    total = int(value.total_seconds())
    if total and total % 86400 == 0:
        return f"{total // 86400}d"
    if total and total % 3600 == 0:
        return f"{total // 3600}h"
    if total and total % 60 == 0:
        return f"{total // 60}m"
    return f"{total}s"
