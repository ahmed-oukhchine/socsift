"""Deterministic rule matching for selection, threshold, and sequence rules."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from socsift.detection.models import Alert
from socsift.enums import Severity
from socsift.events import Event
from socsift.rules.models import (
    DetectionRule,
    RuleCondition,
    RuleThreshold,
    Selection,
    format_duration,
)

_SELECTION_GROUP_FIELDS = ("hostname", "source_ip", "username")


def matches_selection(event: Event, selection: Selection) -> bool:
    """Return ``True`` when every field in ``selection`` matches the event.

    Strings compare case-insensitively and lists are treated as OR, matching
    Sigma's practical semantics without adding a full expression language yet.
    """
    return all(_matches_value(event.get(field), expected) for field, expected in selection.items())


def _matches_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, list):
        return any(_matches_value(actual, item) for item in expected)

    if isinstance(expected, bool):
        return isinstance(actual, bool) and actual is expected

    if isinstance(expected, (int, float)):
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return actual == expected

    if isinstance(expected, str):
        if actual is None:
            return False
        return str(actual).casefold() == expected.casefold()

    return False


def _label(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _group_key(event: Event, fields: Sequence[str]) -> tuple[str, ...]:
    return tuple(_label(event.get(field)) for field in fields)


def _group_map(keys: Sequence[str], fields: Sequence[str]) -> dict[str, str]:
    return {field: value for field, value in zip(fields, keys, strict=True) if value != "-"}


def _logsource_matches(rule: DetectionRule, event: Event) -> bool:
    """Check the rule's log source against the parser that produced the event.

    The SSH daemon calls its service ``sshd`` while the parser names the format
    ``ssh``. Keeping the alias here means new parsers only need to extend this
    function, not every rule.
    """
    service = str(rule.logsource.get("service", "")).casefold()
    source = event.log_source.casefold()
    if source == "ssh":
        return service in {"ssh", "sshd"}
    return service == source


def _bursts(events: Sequence[Event], threshold: RuleThreshold) -> list[tuple[Event, ...]]:
    """Return one evidence-rich burst per dense grouping of events.

    A burst grows while consecutive events stay inside the threshold window.
    When the window closes, all events collected for that burst are emitted as
    one alert. A cooldown equal to the window prevents a single noisy source
    from producing the same alert repeatedly.
    """
    bursts: list[tuple[Event, ...]] = []
    window: deque[Event] = deque()
    cooldown_until: datetime | None = None

    for event in events:
        if cooldown_until is not None and event.timestamp <= cooldown_until:
            continue

        if window and event.timestamp - window[0].timestamp > threshold.window:
            if len(window) >= threshold.count:
                bursts.append(tuple(window))
                cooldown_until = window[-1].timestamp + threshold.window
            window.clear()

        window.append(event)

    if len(window) >= threshold.count:
        bursts.append(tuple(window))

    return bursts


def _selection_alerts(rule: DetectionRule, events: Sequence[Event]) -> list[Alert]:
    buckets: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        if matches_selection(event, rule.selection):
            buckets[_group_key(event, _SELECTION_GROUP_FIELDS)].append(event)

    alerts: list[Alert] = []
    for keys, matched in buckets.items():
        count = len(matched)
        alerts.append(
            Alert(
                rule=rule,
                events=tuple(matched),
                group=_group_map(keys, _SELECTION_GROUP_FIELDS),
                summary=f"{count} matching event{'s' if count != 1 else ''}",
            )
        )
    return alerts


def _threshold_alerts(
    rule: DetectionRule,
    events: Sequence[Event],
    threshold: RuleThreshold,
) -> list[Alert]:
    buckets: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        buckets[_group_key(event, threshold.group_by)].append(event)

    alerts: list[Alert] = []
    for keys, grouped in buckets.items():
        matched = [event for event in grouped if matches_selection(event, rule.selection)]
        for burst in _bursts(matched, threshold):
            count = len(burst)
            alerts.append(
                Alert(
                    rule=rule,
                    events=burst,
                    group=_group_map(keys, threshold.group_by),
                    summary=(
                        f"{count} matching event{'s' if count != 1 else ''} "
                        f"within {format_duration(threshold.window)}"
                    ),
                )
            )
    return alerts


def _sequence_alerts(
    rule: DetectionRule,
    events: Sequence[Event],
    threshold: RuleThreshold,
) -> list[Alert]:
    if rule.followup is None or rule.followup_window is None:
        return []

    buckets: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        buckets[_group_key(event, threshold.group_by)].append(event)

    alerts: list[Alert] = []
    for keys, grouped in buckets.items():
        matched = [event for event in grouped if matches_selection(event, rule.selection)]
        for burst in _bursts(matched, threshold):
            last = burst[-1]
            last_index = next(index for index, event in enumerate(grouped) if event is last)
            followup = None
            for candidate in grouped[last_index + 1 :]:
                if candidate.timestamp > last.timestamp + rule.followup_window:
                    break
                if matches_selection(candidate, rule.followup):
                    followup = candidate
                    break

            if followup is None:
                continue

            if followup.outcome == "success":
                followup_label = "successful authentication"
            else:
                followup_label = followup.event_type.replace("_", " ")

            alerts.append(
                Alert(
                    rule=rule,
                    events=(*burst, followup),
                    group=_group_map(keys, threshold.group_by),
                    summary=(
                        f"{len(burst)} failure events followed by "
                        f"{followup_label} within "
                        f"{format_duration(rule.followup_window)}"
                    ),
                )
            )
    return alerts


def detect(
    events: Iterable[Event],
    rules: Iterable[DetectionRule],
    *,
    min_severity: Severity = Severity.LOW,
) -> list[Alert]:
    """Run every applicable rule and return alerts ordered by severity/time."""
    ordered = sorted(events, key=lambda event: (event.timestamp, event.source, event.line_number))
    alerts: list[Alert] = []

    for rule in rules:
        if rule.severity.rank < min_severity.rank:
            continue

        applicable = [event for event in ordered if _logsource_matches(rule, event)]
        if not applicable:
            continue

        if rule.condition is RuleCondition.SELECTION:
            alerts.extend(_selection_alerts(rule, applicable))
        elif rule.condition is RuleCondition.THRESHOLD and rule.threshold is not None:
            alerts.extend(_threshold_alerts(rule, applicable, rule.threshold))
        elif rule.condition is RuleCondition.SEQUENCE and rule.threshold is not None:
            alerts.extend(_sequence_alerts(rule, applicable, rule.threshold))

    alerts.sort(key=lambda alert: (-alert.severity.rank, alert.first_seen, alert.rule_id))
    return alerts
