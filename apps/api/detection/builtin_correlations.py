"""Regles de correlation integrees — 20+ scenarios d'attaque multi-evenements."""

from __future__ import annotations

from apps.api.detection.correlation import (
    CorrelationRule,
    CorrelationType,
    EventPattern,
)

_BUILTIN_RULES: list[CorrelationRule] | None = None


def get_builtin_rules() -> list[CorrelationRule]:
    """Retourne les regles de correlation integrees (cache en memoire)."""
    global _BUILTIN_RULES
    if _BUILTIN_RULES is None:
        _BUILTIN_RULES = _build_rules()
    return _BUILTIN_RULES


def _build_rules() -> list[CorrelationRule]:
    return [
        # ------------------------------------------------------------------
        # 1. Brute force -> successful login (account compromise)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-001-bruteforce-success",
            name="Brute Force then Successful Login",
            description=(
                "Multiple failed authentication attempts followed by a "
                "successful login from the same source — likely account compromise."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.fail",
                    label="failed_logins",
                ),
                EventPattern(
                    event_type="auth.fail",
                    label="failed_logins_2",
                ),
                EventPattern(
                    event_type="auth.fail",
                    label="failed_logins_3",
                ),
                EventPattern(
                    event_type="auth.success",
                    label="successful_login",
                ),
            ],
            time_window=300,
            group_by=["src_ip"],
            threshold=4,
            severity="critical",
            mitre_tactics=["credential-access", "initial-access"],
            actions=["create_incident", "notify_soc"],
            tags=["brute-force", "account-compromise"],
        ),
        # ------------------------------------------------------------------
        # 2. Port scan -> exploit attempt -> reverse shell
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-002-scan-exploit-shell",
            name="Full Attack Chain: Scan to Shell",
            description=(
                "Port scanning followed by exploit attempt and reverse shell "
                "connection — full attack chain detected."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="conn.attempt",
                    label="port_scan",
                ),
                EventPattern(
                    event_type="exploit.attempt",
                    label="exploit",
                ),
                EventPattern(
                    event_type="shell.reverse",
                    label="reverse_shell",
                ),
            ],
            time_window=1800,
            group_by=["src_ip"],
            threshold=3,
            severity="critical",
            mitre_tactics=["reconnaissance", "initial-access", "execution"],
            actions=["create_incident", "block_ip", "notify_soc"],
            tags=["attack-chain", "exploitation", "reverse-shell"],
        ),
        # ------------------------------------------------------------------
        # 3. Distributed brute force (many IPs, same target user)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-003-distributed-bruteforce",
            name="Distributed Brute Force Attack",
            description=(
                "Failed login attempts from multiple distinct source IPs "
                "targeting the same account — distributed credential attack."
            ),
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[
                EventPattern(event_type="auth.fail"),
            ],
            time_window=600,
            group_by=["username"],
            threshold=10,
            severity="high",
            mitre_tactics=["credential-access"],
            actions=["create_incident", "disable_account"],
            tags=["distributed-brute-force", "credential-attack"],
        ),
        # ------------------------------------------------------------------
        # 4. Impossible travel + sensitive data access
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-004-impossible-travel-data",
            name="Impossible Travel with Data Access",
            description=(
                "Authentication from geographically impossible locations "
                "combined with sensitive data access — insider threat indicator."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.impossible_travel",
                    label="travel_alert",
                ),
                EventPattern(
                    event_type="data.access",
                    field_conditions={"severity": "high"},
                    label="sensitive_access",
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="critical",
            mitre_tactics=["initial-access", "collection"],
            actions=["create_incident", "disable_account", "notify_soc"],
            tags=["insider-threat", "impossible-travel", "data-access"],
        ),
        # ------------------------------------------------------------------
        # 5. Privilege escalation -> lateral movement -> data exfiltration
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-005-apt-chain",
            name="APT Attack Chain",
            description=(
                "Privilege escalation followed by lateral movement and data "
                "exfiltration — advanced persistent threat behavior."
            ),
            correlation_type=CorrelationType.KILL_CHAIN,
            event_patterns=[
                EventPattern(
                    event_type="priv.escalation",
                    label="privesc",
                ),
                EventPattern(
                    event_type="lateral.movement",
                    label="lateral",
                ),
                EventPattern(
                    event_type="data.exfiltration",
                    label="exfil",
                ),
            ],
            time_window=7200,
            group_by=["username"],
            threshold=3,
            severity="critical",
            mitre_tactics=[
                "privilege-escalation",
                "lateral-movement",
                "exfiltration",
            ],
            actions=["create_incident", "block_ip", "notify_soc"],
            tags=["apt", "kill-chain", "advanced-threat"],
        ),
        # ------------------------------------------------------------------
        # 6. DNS tunneling detection
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-006-dns-tunneling",
            name="DNS Tunneling Detected",
            description=(
                "Abnormally high DNS query rate with unusual subdomain patterns "
                "— potential DNS tunneling for data exfiltration or C2."
            ),
            correlation_type=CorrelationType.STATISTICAL,
            event_patterns=[
                EventPattern(
                    event_type="dns.query",
                    regex_conditions={"message": r"[a-z0-9]{20,}\."},
                ),
            ],
            time_window=300,
            group_by=["src_ip"],
            threshold=50,
            severity="high",
            mitre_tactics=["command-and-control", "exfiltration"],
            actions=["create_incident", "block_ip"],
            tags=["dns-tunneling", "c2", "exfiltration"],
            baseline_window=3600,
            std_dev_threshold=3.0,
        ),
        # ------------------------------------------------------------------
        # 7. Beaconing detection (periodic callbacks)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-007-beaconing",
            name="C2 Beaconing Pattern",
            description=(
                "Regular periodic network callbacks detected — potential "
                "command-and-control beaconing activity."
            ),
            correlation_type=CorrelationType.STATISTICAL,
            event_patterns=[
                EventPattern(event_type="conn.outbound"),
            ],
            time_window=3600,
            group_by=["src_ip", "dst_ip"],
            threshold=20,
            severity="high",
            mitre_tactics=["command-and-control"],
            actions=["create_incident"],
            tags=["beaconing", "c2", "periodic-callback"],
            baseline_window=7200,
            std_dev_threshold=2.5,
        ),
        # ------------------------------------------------------------------
        # 8. Credential stuffing (many users, few passwords, same source)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-008-credential-stuffing",
            name="Credential Stuffing Attack",
            description=(
                "Authentication failures across many different user accounts "
                "from the same source — credential stuffing with leaked "
                "credential database."
            ),
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[
                EventPattern(event_type="auth.fail"),
            ],
            time_window=600,
            group_by=["src_ip"],
            threshold=20,
            severity="high",
            mitre_tactics=["credential-access", "initial-access"],
            actions=["create_incident", "block_ip"],
            tags=["credential-stuffing", "leaked-credentials"],
        ),
        # ------------------------------------------------------------------
        # 9. Ransomware indicators (mass file operations)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-009-ransomware",
            name="Ransomware Activity Indicators",
            description=(
                "Mass file rename and encryption operations detected — "
                "potential ransomware attack in progress."
            ),
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[
                EventPattern(
                    event_type="file.modify",
                    regex_conditions={
                        "message": r"\.(encrypted|locked|crypt|enc|ransom)",
                    },
                ),
            ],
            time_window=120,
            group_by=["username"],
            threshold=50,
            severity="critical",
            mitre_tactics=["impact"],
            actions=["create_incident", "quarantine_host", "notify_soc"],
            tags=["ransomware", "encryption", "impact"],
        ),
        # ------------------------------------------------------------------
        # 10. C2 communication patterns
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-010-c2-comms",
            name="C2 Communication Pattern",
            description=(
                "Regular interval outbound connections with encoded or "
                "unusual payload patterns — command-and-control communication."
            ),
            correlation_type=CorrelationType.TEMPORAL,
            event_patterns=[
                EventPattern(
                    event_type="conn.outbound",
                    regex_conditions={
                        "message": r"(base64|encoded|obfuscated|beacon)",
                    },
                ),
                EventPattern(
                    event_type="dns.query",
                    regex_conditions={
                        "message": r"[a-z0-9]{30,}\.",
                    },
                ),
            ],
            time_window=1800,
            group_by=["src_ip"],
            threshold=2,
            severity="high",
            mitre_tactics=["command-and-control"],
            actions=["create_incident", "block_ip"],
            tags=["c2", "encoded-payload", "communication"],
        ),
        # ------------------------------------------------------------------
        # 11. Data staging before exfiltration
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-011-data-staging",
            name="Data Staging Before Exfiltration",
            description=(
                "Large data collection and compression operations followed "
                "by outbound transfer — data staging for exfiltration."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="file.archive",
                    label="staging",
                ),
                EventPattern(
                    event_type="data.transfer",
                    label="exfil",
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="high",
            mitre_tactics=["collection", "exfiltration"],
            actions=["create_incident", "notify_soc"],
            tags=["data-staging", "exfiltration", "archive"],
        ),
        # ------------------------------------------------------------------
        # 12. Account enumeration -> password spray
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-012-enum-spray",
            name="Account Enumeration then Password Spray",
            description=(
                "User enumeration activity followed by password spray "
                "attempts — methodical credential attack."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.enum",
                    label="enumeration",
                ),
                EventPattern(
                    event_type="auth.fail",
                    label="spray",
                ),
            ],
            time_window=1800,
            group_by=["src_ip"],
            threshold=2,
            severity="high",
            mitre_tactics=["credential-access", "reconnaissance"],
            actions=["create_incident", "block_ip"],
            tags=["enumeration", "password-spray"],
        ),
        # ------------------------------------------------------------------
        # 13. Web shell upload -> command execution
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-013-webshell",
            name="Web Shell Upload and Execution",
            description=(
                "File upload of suspicious web shell followed by command "
                "execution from the web server — web shell compromise."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="file.upload",
                    regex_conditions={
                        "message": r"\.(php|jsp|aspx|asp|py|sh|cmd)",
                    },
                    label="upload",
                ),
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"(cmd|powershell|bash|sh|whoami|id|net\s)",
                    },
                    label="execution",
                ),
            ],
            time_window=600,
            group_by=["dst_ip"],
            threshold=2,
            severity="critical",
            mitre_tactics=["persistence", "execution"],
            actions=["create_incident", "quarantine_host", "notify_soc"],
            tags=["webshell", "rce", "persistence"],
        ),
        # ------------------------------------------------------------------
        # 14. SQL injection -> data dump -> exfiltration
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-014-sqli-chain",
            name="SQL Injection to Data Exfiltration",
            description=(
                "SQL injection attack followed by database dump and data "
                "exfiltration — complete data theft chain."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="web.attack",
                    regex_conditions={
                        "message": r"(sqli|sql.injection|union.select|or.1=1)",
                    },
                    label="sqli",
                ),
                EventPattern(
                    event_type="db.query",
                    regex_conditions={
                        "message": r"(dump|extract|select.*from.*information_schema)",
                    },
                    label="dump",
                ),
                EventPattern(
                    event_type="data.transfer",
                    label="exfil",
                ),
            ],
            time_window=3600,
            group_by=["src_ip"],
            threshold=3,
            severity="critical",
            mitre_tactics=["initial-access", "collection", "exfiltration"],
            actions=["create_incident", "block_ip", "notify_soc"],
            tags=["sqli", "data-theft", "exfiltration"],
        ),
        # ------------------------------------------------------------------
        # 15. Phishing click -> malware download -> C2 callback
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-015-phishing-chain",
            name="Phishing to C2 Attack Chain",
            description=(
                "User clicked phishing link, followed by malware download "
                "and command-and-control callback — full phishing kill chain."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="email.phishing_click",
                    label="phishing",
                ),
                EventPattern(
                    event_type="file.download",
                    regex_conditions={
                        "message": r"\.(exe|dll|scr|bat|ps1|vbs|hta|msi)",
                    },
                    label="malware_download",
                ),
                EventPattern(
                    event_type="conn.outbound",
                    label="c2_callback",
                ),
            ],
            time_window=1800,
            group_by=["username"],
            threshold=3,
            severity="critical",
            mitre_tactics=[
                "initial-access",
                "execution",
                "command-and-control",
            ],
            actions=["create_incident", "quarantine_host", "notify_soc"],
            tags=["phishing", "malware", "c2"],
        ),
        # ------------------------------------------------------------------
        # 16. Service account abuse (unusual hours/systems)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-016-service-account-abuse",
            name="Service Account Abuse",
            description=(
                "Service account authenticated from unusual source or at "
                "unusual hours — potential service account compromise."
            ),
            correlation_type=CorrelationType.TEMPORAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.success",
                    regex_conditions={
                        "username": r"^(svc_|service_|sa_|app_)",
                    },
                ),
                EventPattern(
                    event_type="auth.success",
                    regex_conditions={
                        "username": r"^(svc_|service_|sa_|app_)",
                    },
                    field_conditions={"severity": "high"},
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="high",
            mitre_tactics=["credential-access", "persistence"],
            actions=["create_incident", "notify_soc"],
            tags=["service-account", "abuse", "unusual-access"],
        ),
        # ------------------------------------------------------------------
        # 17. Golden ticket / Pass-the-Hash detection
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-017-pth-golden-ticket",
            name="Golden Ticket / Pass-the-Hash",
            description=(
                "Kerberos ticket anomalies or NTLM authentication bypass "
                "detected — golden ticket or pass-the-hash attack."
            ),
            correlation_type=CorrelationType.TEMPORAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.kerberos",
                    regex_conditions={
                        "message": r"(ticket.lifetime.exceeded|forged|"
                        r"encryption.type.mismatch)",
                    },
                ),
                EventPattern(
                    event_type="auth.ntlm",
                    regex_conditions={
                        "message": r"(pass.the.hash|relay|ntlm.downgrade)",
                    },
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=1,
            severity="critical",
            mitre_tactics=[
                "credential-access",
                "lateral-movement",
                "defense-evasion",
            ],
            actions=["create_incident", "disable_account", "notify_soc"],
            tags=["golden-ticket", "pass-the-hash", "kerberos"],
        ),
        # ------------------------------------------------------------------
        # 18. DGA domain detection
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-018-dga-domains",
            name="DGA Domain Detection",
            description=(
                "Multiple DNS queries to algorithmically generated domain "
                "names — DGA malware communication detected."
            ),
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[
                EventPattern(
                    event_type="dns.query",
                    regex_conditions={
                        "message": r"[a-z]{8,}[0-9]{2,}\.(top|xyz|tk|ml|ga|cf|gq|pw)",
                    },
                ),
            ],
            time_window=300,
            group_by=["src_ip"],
            threshold=15,
            severity="high",
            mitre_tactics=["command-and-control"],
            actions=["create_incident", "block_ip"],
            tags=["dga", "malware", "c2"],
        ),
        # ------------------------------------------------------------------
        # 19. Suspicious PowerShell execution chains
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-019-powershell-chain",
            name="Suspicious PowerShell Chain",
            description=(
                "Chain of suspicious PowerShell commands including download, "
                "decode, and execution — fileless malware or attack tool."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"powershell.*(DownloadString|DownloadFile|"
                        r"IEX|Invoke-Expression|WebClient)",
                    },
                    label="download_cradle",
                ),
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"powershell.*(FromBase64|Decompress|"
                        r"-enc|-EncodedCommand|bypass)",
                    },
                    label="decode_execute",
                ),
            ],
            time_window=300,
            group_by=["username"],
            threshold=2,
            severity="critical",
            mitre_tactics=["execution", "defense-evasion"],
            actions=["create_incident", "quarantine_host", "notify_soc"],
            tags=["powershell", "fileless", "living-off-the-land"],
        ),
        # ------------------------------------------------------------------
        # 20. Cloud resource manipulation (IAM + data access)
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-020-cloud-manipulation",
            name="Cloud Resource Manipulation",
            description=(
                "IAM policy changes followed by unusual data access or "
                "resource creation — potential cloud account compromise."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="cloud.iam_change",
                    label="iam_change",
                ),
                EventPattern(
                    event_type="cloud.data_access",
                    label="data_access",
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="high",
            mitre_tactics=[
                "persistence",
                "privilege-escalation",
                "collection",
            ],
            actions=["create_incident", "notify_soc"],
            tags=["cloud", "iam", "data-access"],
        ),
        # ------------------------------------------------------------------
        # 21. Lateral movement via RDP/SSH after initial compromise
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-021-lateral-rdp-ssh",
            name="Lateral Movement via RDP/SSH",
            description=(
                "Successful authentication followed by RDP or SSH sessions "
                "to multiple internal hosts — lateral movement detected."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.success",
                    label="initial_access",
                ),
                EventPattern(
                    event_type="conn.rdp",
                    label="rdp_lateral",
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="high",
            mitre_tactics=["lateral-movement"],
            actions=["create_incident", "notify_soc"],
            tags=["lateral-movement", "rdp", "ssh"],
        ),
        # ------------------------------------------------------------------
        # 22. Suspicious process injection chain
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-022-process-injection",
            name="Process Injection Chain",
            description=(
                "Memory allocation, code writing, and remote thread creation "
                "detected — process injection technique in use."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"(VirtualAllocEx|NtAllocateVirtualMemory)",
                    },
                    label="alloc",
                ),
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"(WriteProcessMemory|NtWriteVirtualMemory)",
                    },
                    label="write",
                ),
                EventPattern(
                    event_type="process.exec",
                    regex_conditions={
                        "message": r"(CreateRemoteThread|NtCreateThreadEx|"
                        r"RtlCreateUserThread)",
                    },
                    label="execute",
                ),
            ],
            time_window=60,
            group_by=["src_ip"],
            threshold=3,
            severity="critical",
            mitre_tactics=["defense-evasion", "privilege-escalation"],
            actions=["create_incident", "quarantine_host", "notify_soc"],
            tags=["process-injection", "evasion"],
        ),
        # ------------------------------------------------------------------
        # 23. Email compromise -> forwarding rule -> data exfil
        # ------------------------------------------------------------------
        CorrelationRule(
            id="corr-023-email-compromise",
            name="Email Account Compromise Chain",
            description=(
                "Suspicious login to email followed by inbox rule creation "
                "and data forwarding — business email compromise."
            ),
            correlation_type=CorrelationType.SEQUENTIAL,
            event_patterns=[
                EventPattern(
                    event_type="auth.success",
                    regex_conditions={
                        "message": r"(outlook|exchange|o365|gmail)",
                    },
                    label="email_login",
                ),
                EventPattern(
                    event_type="email.rule_created",
                    label="rule_created",
                ),
            ],
            time_window=3600,
            group_by=["username"],
            threshold=2,
            severity="high",
            mitre_tactics=["collection", "exfiltration"],
            actions=["create_incident", "disable_account", "notify_soc"],
            tags=["bec", "email-compromise", "forwarding"],
        ),
    ]
