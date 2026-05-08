"""CQL Saved Queries — persist, share, and schedule CQL queries."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# In-memory store (swap for DB model in production)
# ---------------------------------------------------------------------------

_saved_queries: dict[str, dict[str, Any]] = {}

CATEGORIES = ("threat_hunting", "incident_response", "compliance", "monitoring", "custom")


def _now() -> str:
    return datetime.now(UTC).isoformat()


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

def save_query(
    *,
    name: str,
    query: str,
    description: str = "",
    category: str = "custom",
    tags: list[str] | None = None,
    author: str = "system",
    schedule: str | None = None,
) -> dict[str, Any]:
    """Save a CQL query. Returns the saved record."""
    qid = str(uuid.uuid4())
    record = {
        "id": qid,
        "name": name,
        "query": query,
        "description": description,
        "category": category if category in CATEGORIES else "custom",
        "tags": tags or [],
        "author": author,
        "schedule": schedule,
        "created_at": _now(),
        "updated_at": _now(),
        "run_count": 0,
        "is_builtin": False,
    }
    _saved_queries[qid] = record
    return record


def get_query(qid: str) -> dict[str, Any] | None:
    return _saved_queries.get(qid)


def delete_query(qid: str) -> bool:
    if qid in _saved_queries:
        q = _saved_queries[qid]
        if q.get("is_builtin"):
            return False
        del _saved_queries[qid]
        return True
    return False


def list_queries(
    category: str | None = None,
    tag: str | None = None,
    author: str | None = None,
) -> list[dict[str, Any]]:
    results = list(_saved_queries.values())
    if category:
        results = [q for q in results if q["category"] == category]
    if tag:
        results = [q for q in results if tag in q.get("tags", [])]
    if author:
        results = [q for q in results if q["author"] == author]
    return sorted(results, key=lambda q: q["name"])


def increment_run_count(qid: str) -> None:
    if qid in _saved_queries:
        _saved_queries[qid]["run_count"] = _saved_queries[qid].get("run_count", 0) + 1


# ---------------------------------------------------------------------------
# Built-in queries (30+) covering MITRE ATT&CK techniques
# ---------------------------------------------------------------------------

_BUILTIN_QUERIES: list[dict[str, Any]] = [
    # --- Credential Access ---
    {
        "name": "Failed logins last 24h",
        "query": 'event_type="auth_failure" | stats count by username, src_ip | sort count desc',
        "description": "List all authentication failures grouped by user and source IP.",
        "category": "threat_hunting",
        "tags": ["authentication", "T1110", "credential-access"],
    },
    {
        "name": "Brute force detection",
        "query": 'event_type="auth_failure" | stats count by src_ip | where count > 10',
        "description": "Detect brute-force attempts: IPs with more than 10 failed logins.",
        "category": "threat_hunting",
        "tags": ["brute-force", "T1110", "credential-access"],
    },
    {
        "name": "Password spraying",
        "query": 'event_type="auth_failure" | stats dc(username) as unique_users by src_ip | where unique_users > 5',
        "description": "Detect password spraying: one IP targeting many accounts.",
        "category": "threat_hunting",
        "tags": ["password-spray", "T1110.003", "credential-access"],
    },
    {
        "name": "Credential stuffing",
        "query": 'event_type="auth_failure" | stats count, dc(username) as users by src_ip | where count > 50 AND users > 20',
        "description": "Detect credential stuffing: high volume of failures across many accounts.",
        "category": "threat_hunting",
        "tags": ["credential-stuffing", "T1110.004", "credential-access"],
    },
    # --- Execution ---
    {
        "name": "Suspicious PowerShell",
        "query": 'event_type="process_create" AND message CONTAINS "powershell" AND (message CONTAINS "-enc" OR message CONTAINS "bypass")',
        "description": "Detect suspicious PowerShell execution with encoded commands or bypass flags.",
        "category": "threat_hunting",
        "tags": ["powershell", "T1059.001", "execution"],
    },
    {
        "name": "Script execution",
        "query": 'event_type="process_create" AND (message CONTAINS "wscript" OR message CONTAINS "cscript" OR message CONTAINS "mshta")',
        "description": "Detect Windows script host execution (wscript, cscript, mshta).",
        "category": "threat_hunting",
        "tags": ["scripting", "T1059", "execution"],
    },
    {
        "name": "Scheduled task creation",
        "query": 'event_type="scheduled_task" | stats count by username, src_ip | sort count desc',
        "description": "Monitor scheduled task creation for persistence techniques.",
        "category": "threat_hunting",
        "tags": ["scheduled-task", "T1053", "persistence"],
    },
    # --- Lateral Movement ---
    {
        "name": "Lateral movement",
        "query": 'event_type IN ("rdp_connect", "ssh_connect", "smb_connect") | stats dc(dst_ip) as unique_targets by src_ip | where unique_targets > 3',
        "description": "Detect lateral movement: one IP connecting to multiple targets via RDP/SSH/SMB.",
        "category": "threat_hunting",
        "tags": ["lateral-movement", "T1021", "lateral-movement"],
    },
    {
        "name": "RDP activity",
        "query": 'event_type="rdp_connect" | stats count by src_ip, dst_ip, username | sort count desc',
        "description": "Monitor RDP connection patterns.",
        "category": "monitoring",
        "tags": ["rdp", "T1021.001", "lateral-movement"],
    },
    {
        "name": "SMB enumeration",
        "query": 'event_type="smb_connect" | stats dc(dst_ip) as targets by src_ip | where targets > 5 | sort targets desc',
        "description": "Detect SMB enumeration: one host scanning multiple shares.",
        "category": "threat_hunting",
        "tags": ["smb", "T1021.002", "lateral-movement"],
    },
    # --- Privilege Escalation ---
    {
        "name": "Privilege escalation",
        "query": 'event_type="privilege_change" | stats count by username, src_ip | sort count desc',
        "description": "Monitor privilege escalation events.",
        "category": "threat_hunting",
        "tags": ["privesc", "T1548", "privilege-escalation"],
    },
    # --- Exfiltration ---
    {
        "name": "Data exfiltration",
        "query": 'message CONTAINS "bytes" | stats count by src_ip, dst_ip | sort count desc | head 20',
        "description": "Detect potential data exfiltration by monitoring high-volume data transfers.",
        "category": "threat_hunting",
        "tags": ["exfiltration", "T1048", "exfiltration"],
    },
    # --- Command and Control ---
    {
        "name": "C2 beaconing",
        "query": 'event_type="network_connection" | stats count by dst_ip | where count > 100 | sort count desc',
        "description": "Detect C2 beaconing: repetitive connections to same destination.",
        "category": "threat_hunting",
        "tags": ["c2", "T1071", "command-and-control"],
    },
    {
        "name": "DNS tunneling",
        "query": 'event_type="dns_query" | stats count by src_ip | where count > 500 | sort count desc',
        "description": "Detect DNS tunneling: excessive DNS queries from single source.",
        "category": "threat_hunting",
        "tags": ["dns-tunnel", "T1071.004", "command-and-control"],
    },
    {
        "name": "Unusual DNS queries",
        "query": 'event_type="dns_query" AND message CONTAINS "." | stats count by src_ip | sort count desc | head 20',
        "description": "Monitor unusual DNS query patterns.",
        "category": "monitoring",
        "tags": ["dns", "T1071.004", "command-and-control"],
    },
    # --- Defense Evasion ---
    {
        "name": "Registry modifications",
        "query": 'event_type="registry_modify" | stats count by username, src_ip | sort count desc',
        "description": "Monitor registry modifications for defense evasion.",
        "category": "threat_hunting",
        "tags": ["registry", "T1112", "defense-evasion"],
    },
    {
        "name": "Service installation",
        "query": 'event_type="service_install" | stats count by username, src_ip | sort count desc',
        "description": "Monitor new service installations (potential persistence).",
        "category": "threat_hunting",
        "tags": ["service", "T1543", "persistence"],
    },
    {
        "name": "Log clearing",
        "query": 'event_type="audit_log_clear" OR message CONTAINS "clear-eventlog" | stats count by username, src_ip',
        "description": "Detect event log clearing (anti-forensics).",
        "category": "threat_hunting",
        "tags": ["log-clearing", "T1070.001", "defense-evasion"],
    },
    # --- Persistence ---
    {
        "name": "New admin accounts",
        "query": 'event_type="user_create" AND message CONTAINS "admin" | stats count by username, src_ip',
        "description": "Detect creation of new admin accounts.",
        "category": "threat_hunting",
        "tags": ["account-creation", "T1136", "persistence"],
    },
    {
        "name": "Startup persistence",
        "query": '(event_type="registry_modify" AND message CONTAINS "Run") OR event_type="scheduled_task" | stats count by src_ip | sort count desc',
        "description": "Detect persistence via startup registry keys or scheduled tasks.",
        "category": "threat_hunting",
        "tags": ["persistence", "T1547", "persistence"],
    },
    # --- Compliance & Monitoring ---
    {
        "name": "High severity events",
        "query": 'severity="high" | stats count by event_type, src_ip | sort count desc',
        "description": "Summary of all high-severity events.",
        "category": "monitoring",
        "tags": ["high-severity", "monitoring"],
    },
    {
        "name": "Event volume by type",
        "query": '| stats count by event_type | sort count desc',
        "description": "Event volume breakdown by type.",
        "category": "monitoring",
        "tags": ["volume", "monitoring"],
    },
    {
        "name": "Event timeline",
        "query": '| timechart span=1h count by severity',
        "description": "Hourly event timeline grouped by severity.",
        "category": "monitoring",
        "tags": ["timeline", "monitoring"],
    },
    {
        "name": "Top talkers",
        "query": '| top 20 src_ip',
        "description": "Top 20 most active source IPs.",
        "category": "monitoring",
        "tags": ["network", "monitoring"],
    },
    {
        "name": "Rare event types",
        "query": '| rare 10 event_type',
        "description": "10 least common event types (may indicate anomalies).",
        "category": "threat_hunting",
        "tags": ["anomaly", "monitoring"],
    },
    {
        "name": "Failed auth by hour",
        "query": 'event_type="auth_failure" | timechart span=1h count',
        "description": "Hourly count of authentication failures.",
        "category": "monitoring",
        "tags": ["authentication", "monitoring"],
    },
    {
        "name": "Threat intel hits",
        "query": 'ti_score > 50 | stats count by src_ip, ti_tags | sort count desc',
        "description": "Events with high threat intelligence score.",
        "category": "threat_hunting",
        "tags": ["threat-intel", "ioc"],
    },
    {
        "name": "MITRE ATT&CK mapping",
        "query": '| mitre event_type | stats count by technique_id, technique, tactic | sort count desc',
        "description": "Map all events to MITRE ATT&CK techniques.",
        "category": "threat_hunting",
        "tags": ["mitre", "att&ck"],
    },
    # --- Incident Response ---
    {
        "name": "IP investigation",
        "query": 'src_ip="REPLACE_IP" OR dst_ip="REPLACE_IP" | table ts, event_type, src_ip, dst_ip, username, message | sort ts desc',
        "description": "Investigate all activity for a specific IP. Replace REPLACE_IP with target.",
        "category": "incident_response",
        "tags": ["investigation", "ip"],
    },
    {
        "name": "User investigation",
        "query": 'username="REPLACE_USER" | table ts, event_type, src_ip, severity, message | sort ts desc',
        "description": "Investigate all activity for a specific user. Replace REPLACE_USER.",
        "category": "incident_response",
        "tags": ["investigation", "user"],
    },
    {
        "name": "Source correlation",
        "query": 'src_ip="REPLACE_IP" | stats count by event_type | sort count desc',
        "description": "Correlate all event types from a suspicious source IP.",
        "category": "incident_response",
        "tags": ["correlation", "investigation"],
    },
    {
        "name": "Authentication audit",
        "query": 'event_type IN ("auth_failure", "auth_success") | stats count by event_type, username | sort count desc',
        "description": "Audit authentication success/failure ratio per user.",
        "category": "compliance",
        "tags": ["authentication", "audit", "compliance"],
    },
    {
        "name": "Privileged account usage",
        "query": '(username="admin" OR username="root" OR username="Administrator") | table ts, event_type, src_ip, message | sort ts desc',
        "description": "Monitor privileged account activity.",
        "category": "compliance",
        "tags": ["privileged-access", "compliance"],
    },
    {
        "name": "Network scanning",
        "query": 'event_type="network_connection" | stats dc(dst_ip) as targets by src_ip | where targets > 20 | sort targets desc',
        "description": "Detect network scanning: one IP connecting to many destinations.",
        "category": "threat_hunting",
        "tags": ["scanning", "T1046", "discovery"],
    },
]


def seed_builtin_queries() -> int:
    """Seed built-in saved queries. Returns count of seeded queries."""
    count = 0
    existing_names = {q["name"] for q in _saved_queries.values()}
    for bq in _BUILTIN_QUERIES:
        if bq["name"] in existing_names:
            continue
        qid = str(uuid.uuid4())
        record = {
            "id": qid,
            "name": bq["name"],
            "query": bq["query"],
            "description": bq.get("description", ""),
            "category": bq.get("category", "custom"),
            "tags": bq.get("tags", []),
            "author": "system",
            "schedule": None,
            "created_at": _now(),
            "updated_at": _now(),
            "run_count": 0,
            "is_builtin": True,
        }
        _saved_queries[qid] = record
        count += 1
    return count


# ---------------------------------------------------------------------------
# Example queries by use case
# ---------------------------------------------------------------------------

EXAMPLE_QUERIES: dict[str, list[dict[str, str]]] = {
    "basic_search": [
        {"query": 'event_type="auth_failure"', "description": "Simple field match"},
        {"query": "severity=\"high\" AND src_ip=\"10.0.0.1\"", "description": "Multiple conditions"},
        {"query": "message CONTAINS \"error\"", "description": "Substring search"},
        {"query": "src_ip LIKE \"192.168.*\"", "description": "Wildcard pattern"},
        {"query": 'event_type IN ("auth_failure", "auth_success")', "description": "Value list"},
        {"query": 'NOT severity="low"', "description": "Negation"},
    ],
    "aggregation": [
        {"query": "| stats count by event_type", "description": "Count by field"},
        {"query": '| stats count, avg(ti_score) by severity', "description": "Multiple aggregations"},
        {"query": "| stats dc(src_ip) as unique_sources by event_type", "description": "Distinct count with alias"},
        {"query": "| top 10 src_ip", "description": "Top values shortcut"},
        {"query": "| rare 5 event_type", "description": "Rare values"},
    ],
    "time_analysis": [
        {"query": "earliest=-1h | timechart span=5m count", "description": "Events per 5 minutes (last hour)"},
        {"query": "earliest=-7d | timechart span=1d count by severity", "description": "Daily events by severity"},
        {"query": "| bucket ts span=1h | stats count by ts", "description": "Bucket by hour"},
    ],
    "enrichment": [
        {"query": "| iplocation src_ip", "description": "Add geolocation"},
        {"query": "| mitre event_type", "description": "Map to MITRE ATT&CK"},
        {"query": '| eval risk = if(severity = "high", 100, 50)', "description": "Compute risk score"},
    ],
    "formatting": [
        {"query": "| table ts, src_ip, event_type, severity", "description": "Select columns"},
        {"query": "| fields - raw, id", "description": "Exclude columns"},
        {"query": "| rename src_ip as source_address", "description": "Rename column"},
        {"query": "| sort ts desc | head 50", "description": "Sort and limit"},
    ],
    "threat_hunting": [
        {"query": 'event_type="auth_failure" | stats count by src_ip | where count > 10', "description": "Brute force"},
        {"query": 'ti_score > 70 | table ts, src_ip, dst_ip, ti_tags, message', "description": "High threat intel"},
        {"query": '| stats dc(dst_ip) by src_ip | where dc_dst_ip > 10', "description": "Port scanning"},
        {"query": '| transaction src_ip maxspan=5m | where event_count > 20', "description": "Activity bursts"},
    ],
}
