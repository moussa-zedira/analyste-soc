"""MITRE ATT&CK mapping registry for detection rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    id: str
    name: str
    tactic_id: str
    tactic_name: str
    url: str = ""


# --- Technique definitions ---

T1110 = MitreTechnique(
    id="T1110", name="Brute Force",
    tactic_id="TA0006", tactic_name="Credential Access",
    url="https://attack.mitre.org/techniques/T1110/",
)
T1110_001 = MitreTechnique(
    id="T1110.001", name="Brute Force: Password Guessing",
    tactic_id="TA0006", tactic_name="Credential Access",
    url="https://attack.mitre.org/techniques/T1110/001/",
)
T1110_004 = MitreTechnique(
    id="T1110.004", name="Brute Force: Credential Stuffing",
    tactic_id="TA0006", tactic_name="Credential Access",
    url="https://attack.mitre.org/techniques/T1110/004/",
)
T1046 = MitreTechnique(
    id="T1046", name="Network Service Discovery",
    tactic_id="TA0007", tactic_name="Discovery",
    url="https://attack.mitre.org/techniques/T1046/",
)
T1078 = MitreTechnique(
    id="T1078", name="Valid Accounts",
    tactic_id="TA0006", tactic_name="Credential Access",
    url="https://attack.mitre.org/techniques/T1078/",
)
T1499 = MitreTechnique(
    id="T1499", name="Endpoint Denial of Service",
    tactic_id="TA0040", tactic_name="Impact",
    url="https://attack.mitre.org/techniques/T1499/",
)
T1071 = MitreTechnique(
    id="T1071", name="Application Layer Protocol",
    tactic_id="TA0011", tactic_name="Command and Control",
    url="https://attack.mitre.org/techniques/T1071/",
)
T1548 = MitreTechnique(
    id="T1548", name="Abuse Elevation Control Mechanism",
    tactic_id="TA0004", tactic_name="Privilege Escalation",
    url="https://attack.mitre.org/techniques/T1548/",
)

ALL_TECHNIQUES: list[MitreTechnique] = [
    T1110, T1110_001, T1110_004, T1046, T1078, T1499, T1071, T1548,
]

RULE_MITRE_MAP: dict[str, list[MitreTechnique]] = {
    "bruteforce.v1": [T1110, T1110_001],
    "bruteforce-username.v1": [T1110, T1110_001],
    "auth-targeted.v1": [T1110_004, T1078],
    "portscan.v1": [T1046],
    "privesc.v1": [T1548],
    "impossible-travel.v1": [T1078],
    "anomaly.volume.v1": [T1499],
    "anomaly.ip.v1": [T1071],
    "ml.isolation_forest.v1": [T1071, T1499],
}

TACTIC_ORDER: list[dict[str, str]] = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Defense Evasion"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]


def get_techniques_for_rule(rule_id: str) -> list[MitreTechnique]:
    return RULE_MITRE_MAP.get(rule_id, [])


def get_all_mapped_techniques() -> list[MitreTechnique]:
    seen: set[str] = set()
    result: list[MitreTechnique] = []
    for techs in RULE_MITRE_MAP.values():
        for t in techs:
            if t.id not in seen:
                seen.add(t.id)
                result.append(t)
    return result
