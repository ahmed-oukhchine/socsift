"""YAML rule loading, strict validation, and built-in rule discovery."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, NoReturn, cast

import yaml

from socsift.enums import Severity
from socsift.rules.models import (
    DetectionRule,
    MitreMapping,
    RuleCondition,
    RuleThreshold,
    RuleValue,
    Selection,
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "id",
        "title",
        "description",
        "severity",
        "logsource",
        "detection",
        "mitre",
        "falsepositives",
        "recommended_actions",
        "references",
        "tags",
        "status",
        "author",
        "date",
    }
)
_REQUIRED_KEYS = frozenset(
    {
        "id",
        "title",
        "description",
        "severity",
        "logsource",
        "detection",
        "mitre",
        "falsepositives",
        "recommended_actions",
    }
)
_DETECTION_KEYS = frozenset({"condition", "selection", "threshold", "followup", "followup_window"})
_THRESHOLD_KEYS = frozenset({"count", "window", "group_by"})
_LOGSOURCE_KEYS = frozenset({"product", "service"})
_MITRE_KEYS = frozenset({"tactic", "technique", "technique_name", "subtechnique", "url"})
_STATUS_VALUES = frozenset({"experimental", "test", "stable", "deprecated"})

_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")
_FIELD_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}$")
_SUBTECHNIQUE_RE = re.compile(r"^T\d{4}\.\d{3}$")
_DURATION_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[smhdw])$")
_URL_RE = re.compile(r"^https?://\S+$")

_DURATION_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class RuleError(Exception):
    """Base class for every user-facing rule problem."""


class RuleFileError(RuleError):
    """A rule file or directory could not be read."""


class RuleValidationError(RuleError):
    """A rule is syntactically or semantically invalid."""


def _fail(source: str, message: str) -> NoReturn:
    raise RuleValidationError(f"{source}: {message}")


def _require_mapping(value: Any, path: str, source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(source, f"{path} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        _fail(source, f"{path} contains a non-string key")
    return cast(Mapping[str, Any], value)


def _require_string(value: Any, path: str, source: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(source, f"{path} must be a string")
    text = value.strip()
    if not text and not allow_empty:
        _fail(source, f"{path} must not be empty")
    return text


def _optional_string(data: Mapping[str, Any], key: str, source: str) -> str | None:
    if key not in data:
        return None
    return _require_string(data[key], key, source)


def _require_string_list(
    value: Any, path: str, source: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(source, f"{path} must be a list of strings")
    items = tuple(
        _require_string(item, f"{path}[{index}]", source) for index, item in enumerate(value)
    )
    if not items and not allow_empty:
        _fail(source, f"{path} must contain at least one item")
    return items


def _optional_string_list(
    data: Mapping[str, Any], key: str, source: str, *, require_url: bool = False
) -> tuple[str, ...]:
    if key not in data:
        return ()
    items = _require_string_list(data[key], key, source, allow_empty=True)
    if require_url:
        for index, item in enumerate(items):
            if not _URL_RE.match(item):
                _fail(source, f"{key}[{index}] must be an http(s) URL")
    return items


def _reject_unknown(
    data: Mapping[str, Any], allowed: frozenset[str], path: str, source: str
) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        _fail(source, f"{path} contains unknown key(s): {', '.join(unknown)}")


def _require_keys(
    data: Mapping[str, Any], required: frozenset[str], path: str, source: str
) -> None:
    missing = sorted(required - set(data))
    if missing:
        _fail(source, f"{path} is missing required key(s): {', '.join(missing)}")


def _parse_duration(value: Any, path: str, source: str) -> timedelta:
    text = _require_string(value, path, source)
    match = _DURATION_RE.fullmatch(text)
    if match is None:
        _fail(source, f"{path} must use s, m, h, d, or w (for example 5m)")
    seconds = int(match.group("value")) * _DURATION_SECONDS[match.group("unit")]
    if seconds <= 0:
        _fail(source, f"{path} must be greater than zero")
    return timedelta(seconds=seconds)


def _parse_scalar(value: Any, path: str, source: str) -> str | int | float | bool:
    if isinstance(value, (str, int, float, bool)):
        if isinstance(value, str) and not value.strip():
            _fail(source, f"{path} must not be an empty string")
        return value
    _fail(source, f"{path} must be a string, number, or boolean")


def _parse_selection(value: Any, path: str, source: str) -> Selection:
    mapping = _require_mapping(value, path, source)
    if not mapping:
        _fail(source, f"{path} must contain at least one field")

    selection: dict[str, RuleValue] = {}
    for field, raw_value in mapping.items():
        if _FIELD_RE.fullmatch(field) is None:
            _fail(source, f"{path}.{field} is not a valid field name")
        if isinstance(raw_value, list):
            if not raw_value:
                _fail(source, f"{path}.{field} must not be an empty list")
            selection[field] = [
                _parse_scalar(item, f"{path}.{field}[{index}]", source)
                for index, item in enumerate(raw_value)
            ]
        else:
            selection[field] = _parse_scalar(raw_value, f"{path}.{field}", source)
    return selection


def _parse_threshold(value: Any, source: str) -> RuleThreshold:
    mapping = _require_mapping(value, "detection.threshold", source)
    _reject_unknown(mapping, _THRESHOLD_KEYS, "detection.threshold", source)
    _require_keys(mapping, _THRESHOLD_KEYS, "detection.threshold", source)

    count = mapping["count"]
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        _fail(source, "detection.threshold.count must be an integer >= 1")

    group_by = _require_string_list(mapping["group_by"], "detection.threshold.group_by", source)
    if len(set(group_by)) != len(group_by):
        _fail(source, "detection.threshold.group_by contains duplicates")
    for field in group_by:
        if _FIELD_RE.fullmatch(field) is None:
            _fail(source, f"detection.threshold.group_by field {field!r} is not valid")

    return RuleThreshold(
        count=count,
        window=_parse_duration(mapping["window"], "detection.threshold.window", source),
        group_by=group_by,
    )


def _parse_logsource(value: Any, source: str) -> Mapping[str, str]:
    mapping = _require_mapping(value, "logsource", source)
    _reject_unknown(mapping, _LOGSOURCE_KEYS, "logsource", source)
    _require_keys(mapping, _LOGSOURCE_KEYS, "logsource", source)
    return {
        "product": _require_string(mapping["product"], "logsource.product", source),
        "service": _require_string(mapping["service"], "logsource.service", source),
    }


def _parse_mitre(value: Any, source: str) -> MitreMapping:
    mapping = _require_mapping(value, "mitre", source)
    _reject_unknown(mapping, _MITRE_KEYS, "mitre", source)
    _require_keys(mapping, frozenset({"tactic", "technique", "technique_name"}), "mitre", source)

    technique = _require_string(mapping["technique"], "mitre.technique", source)
    if _TECHNIQUE_RE.fullmatch(technique) is None:
        _fail(source, "mitre.technique must look like T1110")

    subtechnique = None
    if "subtechnique" in mapping:
        subtechnique = _require_string(mapping["subtechnique"], "mitre.subtechnique", source)
        if _SUBTECHNIQUE_RE.fullmatch(subtechnique) is None:
            _fail(source, "mitre.subtechnique must look like T1110.001")
        if not subtechnique.startswith(f"{technique}."):
            _fail(source, "mitre.subtechnique must belong to mitre.technique")

    url = None
    if "url" in mapping:
        url = _require_string(mapping["url"], "mitre.url", source)
        if not _URL_RE.match(url):
            _fail(source, "mitre.url must be an http(s) URL")

    return MitreMapping(
        tactic=_require_string(mapping["tactic"], "mitre.tactic", source),
        technique=technique,
        technique_name=_require_string(mapping["technique_name"], "mitre.technique_name", source),
        subtechnique=subtechnique,
        url=url,
    )


def _parse_detection(value: Any, source: str) -> tuple[
    RuleCondition,
    Selection,
    RuleThreshold | None,
    Selection | None,
    timedelta | None,
]:
    mapping = _require_mapping(value, "detection", source)
    _reject_unknown(mapping, _DETECTION_KEYS, "detection", source)
    _require_keys(mapping, frozenset({"condition", "selection"}), "detection", source)

    condition_text = _require_string(mapping["condition"], "detection.condition", source)
    try:
        condition = RuleCondition(condition_text)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in RuleCondition)
        raise RuleValidationError(
            f"{source}: detection.condition must be one of: {allowed}"
        ) from exc

    selection = _parse_selection(mapping["selection"], "detection.selection", source)
    threshold = None
    if "threshold" in mapping:
        threshold = _parse_threshold(mapping["threshold"], source)

    followup = None
    if "followup" in mapping:
        followup = _parse_selection(mapping["followup"], "detection.followup", source)

    followup_window = None
    if "followup_window" in mapping:
        followup_window = _parse_duration(
            mapping["followup_window"], "detection.followup_window", source
        )

    if condition is RuleCondition.SELECTION:
        extras = sorted(set(mapping) & {"threshold", "followup", "followup_window"})
        if extras:
            _fail(source, f"selection rules do not use: {', '.join(extras)}")
    elif condition is RuleCondition.THRESHOLD:
        if threshold is None:
            _fail(source, "threshold rules require detection.threshold")
        extras = sorted(set(mapping) & {"followup", "followup_window"})
        if extras:
            _fail(source, f"threshold rules do not use: {', '.join(extras)}")
    else:
        if threshold is None:
            _fail(source, "sequence rules require detection.threshold")
        if followup is None:
            _fail(source, "sequence rules require detection.followup")
        if followup_window is None:
            _fail(source, "sequence rules require detection.followup_window")

    return condition, selection, threshold, followup, followup_window


def load_rule_text(text: str, *, source: str = "<string>") -> DetectionRule:
    """Parse and validate one YAML rule document."""
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        problem = getattr(exc, "problem", str(exc))
        location = f" at line {mark.line + 1}" if mark is not None else ""
        raise RuleValidationError(f"{source}: invalid YAML{location}: {problem}") from exc

    data = _require_mapping(loaded, "rule", source)
    _reject_unknown(data, _TOP_LEVEL_KEYS, "rule", source)
    _require_keys(data, _REQUIRED_KEYS, "rule", source)

    rule_id = _require_string(data["id"], "id", source)
    if _ID_RE.fullmatch(rule_id) is None:
        _fail(source, "id must be uppercase with hyphens, for example SSH-BRUTE-001")

    severity_text = _require_string(data["severity"], "severity", source).lower()
    try:
        severity = Severity(severity_text)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in Severity)
        raise RuleValidationError(f"{source}: severity must be one of: {allowed}") from exc

    status = _optional_string(data, "status", source)
    if status is not None:
        status = status.lower()
        if status not in _STATUS_VALUES:
            _fail(source, f"status must be one of: {', '.join(sorted(_STATUS_VALUES))}")

    date_text = None
    if "date" in data:
        raw_date = data["date"]
        if isinstance(raw_date, date) and not isinstance(raw_date, datetime):
            date_text = raw_date.isoformat()
        elif isinstance(raw_date, str):
            try:
                date_text = date.fromisoformat(raw_date).isoformat()
            except ValueError:
                _fail(source, "date must be an ISO date such as 2026-11-14")
        else:
            _fail(source, "date must be an ISO date such as 2026-11-14")

    condition, selection, threshold, followup, followup_window = _parse_detection(
        data["detection"], source
    )

    return DetectionRule(
        id=rule_id,
        title=_require_string(data["title"], "title", source),
        description=_require_string(data["description"], "description", source),
        severity=severity,
        logsource=_parse_logsource(data["logsource"], source),
        condition=condition,
        selection=selection,
        threshold=threshold,
        followup=followup,
        followup_window=followup_window,
        mitre=_parse_mitre(data["mitre"], source),
        falsepositives=_require_string_list(data["falsepositives"], "falsepositives", source),
        recommended_actions=_require_string_list(
            data["recommended_actions"], "recommended_actions", source
        ),
        references=_optional_string_list(data, "references", source, require_url=True),
        tags=_optional_string_list(data, "tags", source),
        status=status,
        author=_optional_string(data, "author", source),
        date=date_text,
        source=source,
    )


def load_rule_file(path: Path) -> DetectionRule:
    """Read and validate a single YAML rule file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        detail = exc.strerror or str(exc)
        raise RuleFileError(f"cannot read {path}: {detail}") from exc
    return load_rule_text(text, source=str(path))


def _check_duplicate_ids(rules: Iterable[DetectionRule]) -> None:
    seen: dict[str, str] = {}
    for rule in rules:
        key = rule.id.casefold()
        if key in seen:
            raise RuleValidationError(
                f"duplicate rule id {rule.id} in {seen[key]} and {rule.source}"
            )
        seen[key] = rule.source


def load_rules_path(path: Path) -> list[DetectionRule]:
    """Load one rule file or every YAML rule under a directory."""
    if path.is_file():
        rules = [load_rule_file(path)]
    elif path.is_dir():
        files = sorted(
            (*path.rglob("*.yaml"), *path.rglob("*.yml")),
            key=lambda item: str(item).lower(),
        )
        if not files:
            raise RuleFileError(f"no .yaml or .yml rule files found in {path}")
        rules = [load_rule_file(item) for item in files]
    else:
        raise RuleFileError(f"rule path does not exist: {path}")

    _check_duplicate_ids(rules)
    return rules


@lru_cache(maxsize=1)
def load_builtin_rules() -> tuple[DetectionRule, ...]:
    """Load the rules shipped inside the installed package."""
    package_root = resources.files("socsift.rules").joinpath("builtin")
    if not package_root.is_dir():
        raise RuleFileError("built-in rules directory is missing")

    entries = sorted(
        (entry for entry in package_root.iterdir() if entry.name.endswith((".yaml", ".yml"))),
        key=lambda entry: entry.name,
    )
    if not entries:
        raise RuleFileError("no built-in rule files found")

    rules: list[DetectionRule] = []
    for entry in entries:
        try:
            text = entry.read_text(encoding="utf-8")
        except OSError as exc:
            detail = exc.strerror or str(exc)
            raise RuleFileError(f"cannot read built-in rule {entry.name}: {detail}") from exc
        rules.append(load_rule_text(text, source=f"builtin/{entry.name}"))

    _check_duplicate_ids(rules)
    return tuple(rules)


def find_rule(rules: Iterable[DetectionRule], rule_id: str) -> DetectionRule:
    """Find a rule by id, case-insensitively."""
    wanted = rule_id.casefold()
    for rule in rules:
        if rule.id.casefold() == wanted:
            return rule
    raise LookupError(f"no rule with id {rule_id}")
