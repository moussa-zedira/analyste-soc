"""Registre MITRE ATT&CK pour les regles de detection (~45 techniques majeures).

Cette base est volontairement large mais pas exhaustive : elle couvre les
techniques rencontrees au quotidien dans un SOC. Elle est utilisee pour :

- enrichir les incidents avec les techniques pertinentes,
- exporter une couverture compatible MITRE ATT&CK Navigator (cf
  ``routes/mitre.py``),
- generer des heatmaps de couverture (regles actives par tactique).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """Representation d'une technique MITRE ATT&CK Enterprise."""

    id: str
    name: str
    tactic_id: str
    tactic_name: str
    url: str = ""

    @property
    def navigator_payload(self) -> dict[str, object]:
        """Format compatible avec une couche MITRE ATT&CK Navigator."""
        return {
            "techniqueID": self.id,
            "tactic": self.tactic_name.lower().replace(" ", "-"),
            "color": "",
            "comment": "",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": False,
        }


def _t(tid: str, name: str, tactic_id: str, tactic: str) -> MitreTechnique:
    return MitreTechnique(
        id=tid,
        name=name,
        tactic_id=tactic_id,
        tactic_name=tactic,
        url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    )


# ─────────────────────────────────────────────────────────────────────
# Reconnaissance (TA0043)
# ─────────────────────────────────────────────────────────────────────
T1595 = _t("T1595", "Active Scanning", "TA0043", "Reconnaissance")
T1595_001 = _t("T1595.001", "Scanning IP Blocks", "TA0043", "Reconnaissance")
T1595_002 = _t("T1595.002", "Vulnerability Scanning", "TA0043", "Reconnaissance")
T1592 = _t("T1592", "Gather Victim Host Information", "TA0043", "Reconnaissance")

# ─────────────────────────────────────────────────────────────────────
# Initial Access (TA0001)
# ─────────────────────────────────────────────────────────────────────
T1190 = _t("T1190", "Exploit Public-Facing Application", "TA0001", "Initial Access")
T1133 = _t("T1133", "External Remote Services", "TA0001", "Initial Access")
T1566 = _t("T1566", "Phishing", "TA0001", "Initial Access")
T1566_001 = _t("T1566.001", "Spearphishing Attachment", "TA0001", "Initial Access")
T1566_002 = _t("T1566.002", "Spearphishing Link", "TA0001", "Initial Access")

# ─────────────────────────────────────────────────────────────────────
# Execution (TA0002)
# ─────────────────────────────────────────────────────────────────────
T1059 = _t("T1059", "Command and Scripting Interpreter", "TA0002", "Execution")
T1059_001 = _t("T1059.001", "PowerShell", "TA0002", "Execution")
T1059_003 = _t("T1059.003", "Windows Command Shell", "TA0002", "Execution")
T1059_004 = _t("T1059.004", "Unix Shell", "TA0002", "Execution")
T1203 = _t("T1203", "Exploitation for Client Execution", "TA0002", "Execution")
T1106 = _t("T1106", "Native API", "TA0002", "Execution")

# ─────────────────────────────────────────────────────────────────────
# Persistence (TA0003)
# ─────────────────────────────────────────────────────────────────────
T1098 = _t("T1098", "Account Manipulation", "TA0003", "Persistence")
T1136 = _t("T1136", "Create Account", "TA0003", "Persistence")
T1543 = _t("T1543", "Create or Modify System Process", "TA0003", "Persistence")
T1547 = _t("T1547", "Boot or Logon Autostart Execution", "TA0003", "Persistence")
T1053 = _t("T1053", "Scheduled Task/Job", "TA0003", "Persistence")

# ─────────────────────────────────────────────────────────────────────
# Privilege Escalation (TA0004)
# ─────────────────────────────────────────────────────────────────────
T1548 = _t("T1548", "Abuse Elevation Control Mechanism", "TA0004", "Privilege Escalation")
T1068 = _t("T1068", "Exploitation for Privilege Escalation", "TA0004", "Privilege Escalation")
T1055 = _t("T1055", "Process Injection", "TA0004", "Privilege Escalation")

# ─────────────────────────────────────────────────────────────────────
# Defense Evasion (TA0005)
# ─────────────────────────────────────────────────────────────────────
T1027 = _t("T1027", "Obfuscated Files or Information", "TA0005", "Defense Evasion")
T1140 = _t("T1140", "Deobfuscate/Decode Files or Information", "TA0005", "Defense Evasion")
T1562 = _t("T1562", "Impair Defenses", "TA0005", "Defense Evasion")
T1070 = _t("T1070", "Indicator Removal", "TA0005", "Defense Evasion")
T1112 = _t("T1112", "Modify Registry", "TA0005", "Defense Evasion")

# ─────────────────────────────────────────────────────────────────────
# Credential Access (TA0006)
# ─────────────────────────────────────────────────────────────────────
T1110 = _t("T1110", "Brute Force", "TA0006", "Credential Access")
T1110_001 = _t("T1110.001", "Brute Force: Password Guessing", "TA0006", "Credential Access")
T1110_003 = _t("T1110.003", "Brute Force: Password Spraying", "TA0006", "Credential Access")
T1110_004 = _t("T1110.004", "Brute Force: Credential Stuffing", "TA0006", "Credential Access")
T1003 = _t("T1003", "OS Credential Dumping", "TA0006", "Credential Access")
T1078 = _t("T1078", "Valid Accounts", "TA0006", "Credential Access")
T1552 = _t("T1552", "Unsecured Credentials", "TA0006", "Credential Access")
T1555 = _t("T1555", "Credentials from Password Stores", "TA0006", "Credential Access")

# ─────────────────────────────────────────────────────────────────────
# Discovery (TA0007)
# ─────────────────────────────────────────────────────────────────────
T1046 = _t("T1046", "Network Service Discovery", "TA0007", "Discovery")
T1083 = _t("T1083", "File and Directory Discovery", "TA0007", "Discovery")
T1018 = _t("T1018", "Remote System Discovery", "TA0007", "Discovery")
T1057 = _t("T1057", "Process Discovery", "TA0007", "Discovery")
T1518 = _t("T1518", "Software Discovery", "TA0007", "Discovery")
T1082 = _t("T1082", "System Information Discovery", "TA0007", "Discovery")

# ─────────────────────────────────────────────────────────────────────
# Lateral Movement (TA0008)
# ─────────────────────────────────────────────────────────────────────
T1021 = _t("T1021", "Remote Services", "TA0008", "Lateral Movement")
T1021_001 = _t("T1021.001", "Remote Desktop Protocol", "TA0008", "Lateral Movement")
T1021_002 = _t("T1021.002", "SMB/Windows Admin Shares", "TA0008", "Lateral Movement")
T1021_004 = _t("T1021.004", "SSH", "TA0008", "Lateral Movement")
T1570 = _t("T1570", "Lateral Tool Transfer", "TA0008", "Lateral Movement")

# ─────────────────────────────────────────────────────────────────────
# Collection (TA0009)
# ─────────────────────────────────────────────────────────────────────
T1005 = _t("T1005", "Data from Local System", "TA0009", "Collection")
T1056 = _t("T1056", "Input Capture", "TA0009", "Collection")
T1113 = _t("T1113", "Screen Capture", "TA0009", "Collection")

# ─────────────────────────────────────────────────────────────────────
# Command and Control (TA0011)
# ─────────────────────────────────────────────────────────────────────
T1071 = _t("T1071", "Application Layer Protocol", "TA0011", "Command and Control")
T1071_001 = _t("T1071.001", "Web Protocols", "TA0011", "Command and Control")
T1090 = _t("T1090", "Proxy", "TA0011", "Command and Control")
T1572 = _t("T1572", "Protocol Tunneling", "TA0011", "Command and Control")
T1219 = _t("T1219", "Remote Access Software", "TA0011", "Command and Control")

# ─────────────────────────────────────────────────────────────────────
# Exfiltration (TA0010)
# ─────────────────────────────────────────────────────────────────────
T1041 = _t("T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration")
T1048 = _t("T1048", "Exfiltration Over Alternative Protocol", "TA0010", "Exfiltration")
T1567 = _t("T1567", "Exfiltration Over Web Service", "TA0010", "Exfiltration")

# ─────────────────────────────────────────────────────────────────────
# Impact (TA0040)
# ─────────────────────────────────────────────────────────────────────
T1499 = _t("T1499", "Endpoint Denial of Service", "TA0040", "Impact")
T1486 = _t("T1486", "Data Encrypted for Impact", "TA0040", "Impact")
T1490 = _t("T1490", "Inhibit System Recovery", "TA0040", "Impact")
T1561 = _t("T1561", "Disk Wipe", "TA0040", "Impact")


ALL_TECHNIQUES: list[MitreTechnique] = [
    T1595,
    T1595_001,
    T1595_002,
    T1592,
    T1190,
    T1133,
    T1566,
    T1566_001,
    T1566_002,
    T1059,
    T1059_001,
    T1059_003,
    T1059_004,
    T1203,
    T1106,
    T1098,
    T1136,
    T1543,
    T1547,
    T1053,
    T1548,
    T1068,
    T1055,
    T1027,
    T1140,
    T1562,
    T1070,
    T1112,
    T1110,
    T1110_001,
    T1110_003,
    T1110_004,
    T1003,
    T1078,
    T1552,
    T1555,
    T1046,
    T1083,
    T1018,
    T1057,
    T1518,
    T1082,
    T1021,
    T1021_001,
    T1021_002,
    T1021_004,
    T1570,
    T1005,
    T1056,
    T1113,
    T1071,
    T1071_001,
    T1090,
    T1572,
    T1219,
    T1041,
    T1048,
    T1567,
    T1499,
    T1486,
    T1490,
    T1561,
]

TECHNIQUES_BY_ID: dict[str, MitreTechnique] = {t.id: t for t in ALL_TECHNIQUES}

RULE_MITRE_MAP: dict[str, list[MitreTechnique]] = {
    # Built-in detection rules
    "bruteforce.v1": [T1110, T1110_001],
    "bruteforce-username.v1": [T1110, T1110_001],
    "auth-targeted.v1": [T1110_004, T1078],
    "portscan.v1": [T1046, T1595_001],
    "privesc.v1": [T1548, T1068],
    "impossible-travel.v1": [T1078],
    "anomaly.volume.v1": [T1499],
    "anomaly.ip.v1": [T1071, T1071_001],
    "ml.isolation_forest.v1": [T1071, T1499],
    # Correlation built-ins (cf builtin_correlations.py — id pattern)
    "corr-001-bruteforce-success": [T1110, T1078],
    "corr-002-recon-then-exploit": [T1046, T1190],
    "corr-003-spray-then-success": [T1110_003, T1078],
    "corr-004-priv-then-lateral": [T1548, T1021],
    "corr-005-data-staging-exfil": [T1005, T1041],
    "corr-006-c2-then-exfil": [T1071, T1041],
    "corr-007-account-creation-priv": [T1136, T1098, T1078],
    "corr-008-suspicious-process-injection": [T1055],
    "corr-009-defense-evasion-chain": [T1562, T1070],
    "corr-010-rce-then-credential-dump": [T1190, T1003],
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

TACTICS_BY_ID: dict[str, str] = {t["id"]: t["name"] for t in TACTIC_ORDER}


def get_techniques_for_rule(rule_id: str) -> list[MitreTechnique]:
    """Retourne les techniques MITRE associees a une regle donnee."""
    return RULE_MITRE_MAP.get(rule_id, [])


def get_all_mapped_techniques() -> list[MitreTechnique]:
    """Retourne toutes les techniques MITRE uniques referencees par des regles."""
    seen: set[str] = set()
    result: list[MitreTechnique] = []
    for techs in RULE_MITRE_MAP.values():
        for t in techs:
            if t.id not in seen:
                seen.add(t.id)
                result.append(t)
    return result


def coverage_by_tactic() -> dict[str, dict[str, object]]:
    """Couverture des regles par tactique : {tactic_id: {name, techniques: [...]}}."""
    coverage: dict[str, dict[str, object]] = {
        t["id"]: {"name": t["name"], "techniques": []} for t in TACTIC_ORDER
    }
    seen: set[str] = set()
    for rule_id, techs in RULE_MITRE_MAP.items():
        for tech in techs:
            key = f"{tech.id}|{rule_id}"
            if key in seen:
                continue
            seen.add(key)
            entry = coverage.setdefault(
                tech.tactic_id,
                {"name": tech.tactic_name, "techniques": []},
            )
            techs_list: list[dict[str, object]] = entry["techniques"]  # type: ignore[assignment]
            techs_list.append(
                {
                    "technique_id": tech.id,
                    "name": tech.name,
                    "rule_id": rule_id,
                }
            )
    return coverage


def navigator_layer(*, name: str = "Cyber Defense — Coverage") -> dict[str, object]:
    """Genere une couche compatible MITRE ATT&CK Navigator (v4.5)."""
    techniques: list[dict[str, object]] = []
    counts: dict[str, int] = {}
    for techs in RULE_MITRE_MAP.values():
        for tech in techs:
            counts[tech.id] = counts.get(tech.id, 0) + 1

    max_count = max(counts.values(), default=1)
    for tech_id, count in counts.items():
        tech = TECHNIQUES_BY_ID.get(tech_id)
        if tech is None:
            continue
        score = round(100 * count / max_count, 1)
        payload = tech.navigator_payload
        payload["score"] = score
        payload["comment"] = f"{count} regle(s) couvrent {tech.id}"
        techniques.append(payload)

    return {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": "4.9.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": "Auto-generated coverage layer from cyberdef detection rules",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,
        "viewMode": 0,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#fff7ec", "#fdbb84", "#7f0000"],
            "minValue": 0,
            "maxValue": 100,
        },
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
