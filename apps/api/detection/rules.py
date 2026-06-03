"""Regles de detection — definitions declaratives des regles."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import timedelta


class Severity(enum.Enum):
    """Niveaux de severite des regles de detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class Rule:
    """Definition declarative d'une regle de detection."""

    id: str
    event_type: str
    group_by: list[str]
    threshold_count: int
    time_window: timedelta
    dedup_window: timedelta
    severity: Severity
    title_template: str
    description_template: str = ""
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


BRUTE_FORCE_RULE = Rule(
    id="bruteforce.v1",
    event_type="auth.fail",
    group_by=["src_ip"],
    threshold_count=10,
    time_window=timedelta(minutes=2),
    dedup_window=timedelta(minutes=2),
    severity=Severity.HIGH,
    title_template="Brute force suspected from {src_ip}",
    description_template=(
        "{count} failed authentication attempts detected within a {window}-second window. {extra}"
    ),
    tags=["authentication", "brute-force"],
)

PORT_SCAN_RULE = Rule(
    id="portscan.v1",
    event_type="conn.attempt",
    group_by=["src_ip"],
    threshold_count=50,
    time_window=timedelta(minutes=1),
    dedup_window=timedelta(minutes=1),
    severity=Severity.HIGH,
    title_template="Port scan detected from {src_ip}",
    description_template=(
        "{count} connection attempts detected from {src_ip} within a "
        "{window}-second window. Possible port scanning activity."
    ),
    tags=["network", "port-scan", "reconnaissance"],
)

BRUTE_FORCE_USERNAME_RULE = Rule(
    id="bruteforce-username.v1",
    event_type="auth.fail",
    group_by=["username"],
    threshold_count=5,
    time_window=timedelta(minutes=2),
    dedup_window=timedelta(minutes=2),
    severity=Severity.HIGH,
    title_template="Brute force on account {username}",
    description_template=(
        "{count} failed authentication attempts targeting user '{username}' "
        "within a {window}-second window. Distributed brute force suspected."
    ),
    tags=["authentication", "brute-force", "account-targeted"],
)

PRIV_ESC_RULE = Rule(
    id="privesc.v1",
    event_type="priv.escalation",
    group_by=["username"],
    threshold_count=3,
    time_window=timedelta(minutes=5),
    dedup_window=timedelta(minutes=5),
    severity=Severity.CRITICAL,
    title_template="Privilege escalation attempts by {username}",
    description_template=(
        "{count} privilege escalation attempts by user '{username}' "
        "within a {window}-second window."
    ),
    tags=["privilege-escalation", "lateral-movement"],
)

AUTH_TARGETED_RULE = Rule(
    id="auth-targeted.v1",
    event_type="auth.fail",
    group_by=["src_ip", "username"],
    threshold_count=3,
    time_window=timedelta(minutes=1),
    dedup_window=timedelta(minutes=1),
    severity=Severity.CRITICAL,
    title_template="Targeted auth attack on {username} from {src_ip}",
    description_template=(
        "{count} failed authentication attempts on user '{username}' from "
        "{src_ip} within a {window}-second window. Targeted credential attack."
    ),
    tags=["authentication", "targeted-attack", "credential-stuffing"],
)

ALL_RULES: list[Rule] = [
    BRUTE_FORCE_RULE,
    PORT_SCAN_RULE,
    BRUTE_FORCE_USERNAME_RULE,
    AUTH_TARGETED_RULE,
    PRIV_ESC_RULE,
]


def get_rules(*, enabled_only: bool = True) -> list[Rule]:
    """Retourne les regles enregistrees, avec filtrage optionnel par statut actif."""
    if enabled_only:
        return [r for r in ALL_RULES if r.enabled]
    return list(ALL_RULES)
