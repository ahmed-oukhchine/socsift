"""Deterministic, explainable risk scoring for qualified alerts.

Every point is attached to a named factor so an L1 analyst can defend the
priority in a ticket. No machine learning, no hidden weights, no network calls.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

from socsift.detection.models import Alert
from socsift.enums import Severity, SortOrder
from socsift.risk.models import RiskFactor, RiskScore, ScoredAlert
from socsift.rules.models import RuleCondition

# Severity is the rule author's baseline. The remaining factors adjust that
# baseline using what the evidence actually shows.
_SEVERITY_BASE: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 15,
    Severity.MEDIUM: 30,
    Severity.HIGH: 50,
    Severity.CRITICAL: 70,
}

_CONDITION_BONUS: dict[RuleCondition, tuple[int, str]] = {
    RuleCondition.THRESHOLD: (5, "repeated activity inside one window"),
    RuleCondition.SEQUENCE: (10, "failures followed by a follow-up event"),
}

_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

# Hostname tokens that usually carry business-critical services. Matching is
# token-based (split on -, ., _) so "dc01" matches but "soc-lab-web01" does not.
_CRITICAL_ASSET_TOKENS = frozenset(
    {
        "admin",
        "backup",
        "bastion",
        "ca",
        "database",
        "db",
        "dc",
        "domain",
        "jump",
        "kdc",
        "mail",
        "prod",
        "sql",
        "vpn",
    }
)
_SERVER_ASSET_TOKENS = frozenset(
    {
        "api",
        "app",
        "build",
        "ci",
        "file",
        "git",
        "log",
        "monitor",
        "nas",
        "proxy",
        "server",
        "srv",
        "web",
    }
)
_PRIVILEGED_ACCOUNTS = frozenset(
    {"admin", "administrator", "da", "domain admin", "root", "sysadmin"}
)
_HOST_SPLIT = re.compile(r"[-._]")


def base_score(severity: Severity) -> int:
    """Return the severity component used before evidence adjustments."""
    return _SEVERITY_BASE[severity]


def _token_matches(token: str, keyword: str) -> bool:
    """Match a full token or a keyword with a numeric suffix (``web01``)."""
    if token == keyword:
        return True
    return token.startswith(keyword) and token[len(keyword) :].isdigit()


def _host_kind(hostname: str) -> str | None:
    """Classify one hostname as ``critical``, ``server``, or unknown."""
    tokens = [token for token in _HOST_SPLIT.split(hostname.casefold()) if token]
    for token in tokens:
        if any(_token_matches(token, keyword) for keyword in _CRITICAL_ASSET_TOKENS):
            return "critical"
    for token in tokens:
        if any(_token_matches(token, keyword) for keyword in _SERVER_ASSET_TOKENS):
            return "server"
    return None


def _is_internal(value: str) -> bool | None:
    """Classify an address without trusting documentation ranges as private.

    RFC 5737 and documentation IPv6 prefixes are treated as external because
    the sample corpus uses them to represent internet sources. Only RFC 1918,
    loopback, link-local, and IPv6 ULA addresses count as internal.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return any(
        address in network for network in _INTERNAL_NETWORKS if network.version == address.version
    )


def _condition_factor(alert: Alert) -> RiskFactor | None:
    bonus = _CONDITION_BONUS.get(alert.rule.condition)
    if bonus is None:
        return None
    return RiskFactor("correlation", bonus[0], bonus[1])


def _volume_factor(alert: Alert) -> RiskFactor | None:
    if alert.count <= 1:
        return None
    points = min(6, alert.count - 1)
    noun = "event" if alert.count == 1 else "events"
    return RiskFactor("volume", points, f"{alert.count} evidence {noun}")


def _access_factor(alert: Alert) -> RiskFactor | None:
    if not any(event.outcome == "success" for event in alert.events):
        return None
    return RiskFactor("access", 10, "successful authentication in evidence")


def _exposure_factor(alert: Alert) -> RiskFactor | None:
    external = [source for source in alert.source_ips if _is_internal(source) is False]
    if not external:
        return None
    shown = ", ".join(external[:2])
    if len(external) > 2:
        shown = f"{shown} (+{len(external) - 2} more)"
    return RiskFactor("exposure", 8, f"external source {shown}")


def _asset_factor(alert: Alert) -> RiskFactor | None:
    server: RiskFactor | None = None
    for hostname in alert.hostnames:
        kind = _host_kind(hostname)
        if kind == "critical":
            return RiskFactor("asset", 8, f"critical hostname {hostname}")
        if kind == "server" and server is None:
            server = RiskFactor("asset", 4, f"server hostname {hostname}")
    return server


def _account_factor(alert: Alert) -> RiskFactor | None:
    # Only real authentication targets count. An invalid username from an
    # enumeration attempt is evidence of discovery, not a targeted account.
    privileged = sorted(
        {
            event.username
            for event in alert.events
            if event.username
            and event.outcome in {"success", "failure"}
            and event.username.casefold() in _PRIVILEGED_ACCOUNTS
        }
    )
    if not privileged:
        return None
    noun = "account" if len(privileged) == 1 else "accounts"
    return RiskFactor(
        "account",
        6,
        f"privileged {noun} {', '.join(privileged)}",
    )


def _breadth_factor(alert: Alert) -> RiskFactor | None:
    if len(alert.hostnames) <= 1:
        return None
    return RiskFactor(
        "breadth",
        4,
        f"activity across {len(alert.hostnames)} hosts",
    )


def score_alert(alert: Alert) -> ScoredAlert:
    """Score one qualified alert with a fully visible factor list."""
    factors: list[RiskFactor] = [
        RiskFactor(
            "severity",
            base_score(alert.severity),
            f"rule severity {alert.severity.value}",
        )
    ]
    for factor in (
        _condition_factor(alert),
        _volume_factor(alert),
        _access_factor(alert),
        _exposure_factor(alert),
        _asset_factor(alert),
        _account_factor(alert),
        _breadth_factor(alert),
    ):
        if factor is not None:
            factors.append(factor)

    return ScoredAlert(alert=alert, risk=RiskScore(tuple(factors)))


def score_alerts(alerts: Iterable[Alert]) -> list[ScoredAlert]:
    """Score a batch of alerts without changing their input order."""
    return [score_alert(alert) for alert in alerts]


def sort_alerts(
    alerts: Iterable[ScoredAlert],
    order: SortOrder = SortOrder.RISK,
) -> list[ScoredAlert]:
    """Order scored alerts for queue work or chronological review."""
    items = list(alerts)
    if order is SortOrder.TIME:
        return sorted(items, key=lambda item: (item.first_seen, -item.risk.score, item.rule_id))
    if order is SortOrder.SEVERITY:
        return sorted(
            items,
            key=lambda item: (
                -item.severity.rank,
                -item.risk.score,
                item.first_seen,
                item.rule_id,
            ),
        )
    return sorted(
        items,
        key=lambda item: (
            -item.risk.score,
            -item.severity.rank,
            item.first_seen,
            item.rule_id,
        ),
    )
