"""15 built-in SOAR playbooks couvrant les principaux scenarios de reponse a incident."""

from __future__ import annotations

BUILTIN_PLAYBOOKS: list[dict] = [
    # ------------------------------------------------------------------ 1
    {
        "name": "Phishing Response",
        "description": "Analyse et confinement automatique d'un email de phishing: extraction IOCs, verification TI, blocage expediteur, notification utilisateur.",
        "category": "email",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["phishing", "suspicious_email"]},
        "tags": ["phishing", "email", "ioc"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "extract_sender_ip",
                    "action": "lookup_ip_reputation",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "check_domain",
                    "action": "lookup_domain",
                    "params": {"domain": "{{ input.sender_domain }}"},
                },
                {
                    "name": "check_url",
                    "action": "check_url_sandbox",
                    "params": {"url": "{{ input.url }}", "sandbox": "any"},
                    "condition": {"field": "input.url", "operator": "exists", "value": None},
                },
                {
                    "name": "check_attachment",
                    "action": "lookup_hash",
                    "params": {"hash": "{{ input.attachment_hash }}", "hash_type": "sha256"},
                    "condition": {"field": "input.attachment_hash", "operator": "exists", "value": None},
                },
                {
                    "name": "block_sender",
                    "action": "block_domain_dns",
                    "params": {"domain": "{{ input.sender_domain }}"},
                    "condition": {
                        "any": [
                            {"field": "steps.extract_sender_ip.malicious", "operator": "eq", "value": True},
                            {"field": "steps.check_domain.threat_intel.malicious", "operator": "eq", "value": True},
                        ]
                    },
                },
                {
                    "name": "notify_user",
                    "action": "send_email",
                    "params": {
                        "to": "{{ input.recipient }}",
                        "subject": "Phishing email detected — action required",
                        "body": "A phishing email from {{ input.sender_domain }} has been blocked. Do not interact with this message.",
                    },
                },
                {
                    "name": "create_ticket",
                    "action": "add_timeline_entry",
                    "params": {
                        "incident_id": "{{ input.incident_id }}",
                        "message": "Phishing playbook completed — sender domain {{ input.sender_domain }} analyzed",
                        "entry_type": "playbook",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 2
    {
        "name": "Malware Incident",
        "description": "Reponse malware: isolation hote, verification hash, blocage C2, scan reseau.",
        "category": "malware",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["malware", "suspicious_binary"]},
        "tags": ["malware", "containment", "c2"],
        "definition": {
            "rollback_on_failure": True,
            "steps": [
                {
                    "name": "isolate",
                    "action": "isolate_host",
                    "params": {"hostname": "{{ input.hostname }}", "isolation_level": "full"},
                    "rollback": {"action": "isolate_host", "params": {"hostname": "{{ input.hostname }}", "isolation_level": "none"}},
                },
                {
                    "name": "check_hash",
                    "action": "lookup_hash",
                    "params": {"hash": "{{ input.file_hash }}", "hash_type": "sha256"},
                },
                {
                    "name": "check_c2",
                    "action": "lookup_domain",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "block_c2",
                    "action": "block_domain_dns",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "block_c2_ip",
                    "action": "block_ip_firewall",
                    "params": {"ip": "{{ input.c2_ip }}", "direction": "both", "duration_hours": 720},
                    "condition": {"field": "input.c2_ip", "operator": "exists", "value": None},
                },
                {
                    "name": "quarantine_file",
                    "action": "quarantine_file",
                    "params": {"file_path": "{{ input.file_path }}", "hostname": "{{ input.hostname }}"},
                },
                {
                    "name": "scan_network",
                    "action": "search_events",
                    "params": {"query": "{{ input.file_hash }}", "time_range_hours": 72, "limit": 200},
                },
                {
                    "name": "notify_team",
                    "action": "send_slack",
                    "params": {
                        "channel": "#incident-response",
                        "message": "Malware incident on {{ input.hostname }} — host isolated, file quarantined.",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 3
    {
        "name": "Brute Force Response",
        "description": "Reponse attaque par force brute: blocage IP, verification comptes compromis, reset mots de passe.",
        "category": "authentication",
        "trigger_type": "on_threshold",
        "trigger_config": {"metric": "failed_logins", "threshold": 10},
        "tags": ["brute-force", "authentication", "blocking"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "check_ip",
                    "action": "lookup_ip_reputation",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "geoip",
                    "action": "geoip_lookup",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "block_ip",
                    "action": "block_ip_firewall",
                    "params": {"ip": "{{ input.src_ip }}", "direction": "inbound", "duration_hours": 24},
                },
                {
                    "name": "check_accounts",
                    "action": "search_events",
                    "params": {"query": "{{ input.src_ip }}", "time_range_hours": 1, "limit": 100},
                },
                {
                    "name": "reset_passwords",
                    "action": "rotate_credentials",
                    "params": {"username": "{{ input.target_username }}", "notify_user": True},
                    "condition": {"field": "input.successful_login", "operator": "eq", "value": True},
                },
                {
                    "name": "update_incident",
                    "action": "update_incident",
                    "params": {
                        "incident_id": "{{ input.incident_id }}",
                        "status": "ack",
                        "notes": "Brute force from {{ input.src_ip }} ({{ steps.geoip.country }}) — IP blocked for 24h",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 4
    {
        "name": "Data Exfiltration",
        "description": "Detection d'exfiltration: isolation hote, capture trafic, investigation utilisateur.",
        "category": "data-loss",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["data_exfil", "unusual_upload", "dns_tunnel"]},
        "tags": ["exfiltration", "dlp", "investigation"],
        "definition": {
            "rollback_on_failure": True,
            "steps": [
                {
                    "name": "isolate",
                    "action": "isolate_host",
                    "params": {"hostname": "{{ input.hostname }}", "isolation_level": "partial"},
                    "rollback": {"action": "isolate_host", "params": {"hostname": "{{ input.hostname }}", "isolation_level": "none"}},
                },
                {
                    "name": "capture_traffic",
                    "action": "capture_pcap",
                    "params": {"interface": "eth0", "filter": "host {{ input.src_ip }}", "duration_seconds": 300},
                },
                {
                    "name": "check_dest",
                    "action": "lookup_ip_reputation",
                    "params": {"ip": "{{ input.dst_ip }}"},
                },
                {
                    "name": "user_activity",
                    "action": "get_user_activity",
                    "params": {"username": "{{ input.username }}", "hours": 48},
                },
                {
                    "name": "notify_manager",
                    "action": "send_email",
                    "params": {
                        "to": "{{ input.manager_email }}",
                        "subject": "Data exfiltration alert — {{ input.username }}",
                        "body": "Suspicious data transfer detected from {{ input.hostname }}. Investigation underway.",
                    },
                    "condition": {"field": "input.manager_email", "operator": "exists", "value": None},
                },
                {
                    "name": "timeline",
                    "action": "add_timeline_entry",
                    "params": {
                        "incident_id": "{{ input.incident_id }}",
                        "message": "Data exfiltration playbook executed — host partially isolated, traffic captured",
                        "entry_type": "playbook",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 5
    {
        "name": "Ransomware Response",
        "description": "Reponse ransomware: isolation segment reseau, verification backups, blocage C2, notification equipe.",
        "category": "malware",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["ransomware", "crypto_activity", "mass_file_encrypt"]},
        "tags": ["ransomware", "critical", "containment"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "isolate_host",
                    "action": "isolate_host",
                    "params": {"hostname": "{{ input.hostname }}", "isolation_level": "full"},
                },
                {
                    "name": "block_c2_domains",
                    "action": "block_domain_dns",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "block_c2_ip",
                    "action": "block_ip_firewall",
                    "params": {"ip": "{{ input.c2_ip }}", "direction": "both", "duration_hours": 8760},
                    "condition": {"field": "input.c2_ip", "operator": "exists", "value": None},
                },
                {
                    "name": "check_lateral",
                    "action": "search_events",
                    "params": {"query": "{{ input.hostname }}", "time_range_hours": 24, "limit": 500},
                },
                {
                    "name": "verify_backups",
                    "action": "restore_backup",
                    "params": {"target": "{{ input.hostname }}", "backup_id": "latest"},
                },
                {
                    "name": "pagerduty",
                    "action": "send_pagerduty",
                    "params": {
                        "routing_key": "{{ input.pagerduty_key }}",
                        "summary": "RANSOMWARE on {{ input.hostname }} — immediate response required",
                        "severity": "critical",
                    },
                    "condition": {"field": "input.pagerduty_key", "operator": "exists", "value": None},
                },
                {
                    "name": "slack_alert",
                    "action": "send_slack",
                    "params": {
                        "channel": "#incident-response",
                        "message": "CRITICAL: Ransomware detected on {{ input.hostname }}. Host isolated. All hands on deck.",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 6
    {
        "name": "Insider Threat",
        "description": "Investigation menace interne: surveillance utilisateur, audit acces, alerte management.",
        "category": "insider",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["insider_threat", "privilege_abuse", "data_hoarding"]},
        "tags": ["insider", "investigation", "hr"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "user_activity",
                    "action": "get_user_activity",
                    "params": {"username": "{{ input.username }}", "hours": 168},
                },
                {
                    "name": "check_data_access",
                    "action": "search_events",
                    "params": {"query": "{{ input.username }}", "time_range_hours": 168, "limit": 500},
                },
                {
                    "name": "geoip_check",
                    "action": "geoip_lookup",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "notify_security",
                    "action": "send_email",
                    "params": {
                        "to": "security-team@company.com",
                        "subject": "Insider threat alert — {{ input.username }}",
                        "body": "Suspicious activity detected for {{ input.username }}. Activity audit attached. Review required.",
                    },
                },
                {
                    "name": "timeline",
                    "action": "add_timeline_entry",
                    "params": {
                        "incident_id": "{{ input.incident_id }}",
                        "message": "Insider threat playbook — {{ steps.user_activity.count }} events analyzed over 7 days",
                        "entry_type": "investigation",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 7
    {
        "name": "DDoS Mitigation",
        "description": "Reponse DDoS: activation rate limiting, notification ISP, activation CDN.",
        "category": "availability",
        "trigger_type": "on_threshold",
        "trigger_config": {"metric": "requests_per_second", "threshold": 10000},
        "tags": ["ddos", "availability", "network"],
        "definition": {
            "rollback_on_failure": True,
            "steps": [
                {
                    "name": "identify_sources",
                    "action": "search_events",
                    "params": {"query": "{{ input.target_ip }}", "time_range_hours": 1, "limit": 500},
                },
                {
                    "name": "block_top_ips",
                    "action": "update_waf_rules",
                    "params": {"rule_type": "rate_limit", "pattern": "{{ input.target_ip }}", "action": "block"},
                    "rollback": {"action": "update_waf_rules", "params": {"rule_type": "rate_limit", "pattern": "{{ input.target_ip }}", "action": "remove"}},
                },
                {
                    "name": "geoip_analysis",
                    "action": "geoip_lookup",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "notify_isp",
                    "action": "send_email",
                    "params": {
                        "to": "{{ input.isp_contact }}",
                        "subject": "DDoS attack in progress — requesting upstream filtering",
                        "body": "DDoS targeting {{ input.target_ip }}. Peak: {{ input.peak_rps }} rps. Source analysis attached.",
                    },
                    "condition": {"field": "input.isp_contact", "operator": "exists", "value": None},
                },
                {
                    "name": "notify_team",
                    "action": "send_slack",
                    "params": {
                        "channel": "#incident-response",
                        "message": "DDoS mitigation active for {{ input.target_ip }}. WAF rules updated. ISP notified.",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 8
    {
        "name": "Account Compromise",
        "description": "Reponse compromission de compte: desactivation, revocation sessions, verification mouvement lateral.",
        "category": "authentication",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["account_compromise", "credential_theft", "impossible_travel"]},
        "tags": ["compromise", "account", "lateral"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "disable_account",
                    "action": "disable_user",
                    "params": {"username": "{{ input.username }}", "reason": "Suspected account compromise"},
                },
                {
                    "name": "revoke_sessions",
                    "action": "revoke_sessions",
                    "params": {"username": "{{ input.username }}"},
                },
                {
                    "name": "check_lateral",
                    "action": "get_user_activity",
                    "params": {"username": "{{ input.username }}", "hours": 24},
                },
                {
                    "name": "check_source",
                    "action": "run_osint",
                    "params": {"indicator": "{{ input.src_ip }}", "indicator_type": "ip"},
                },
                {
                    "name": "reset_password",
                    "action": "rotate_credentials",
                    "params": {"username": "{{ input.username }}", "notify_user": True},
                },
                {
                    "name": "update_status",
                    "action": "update_incident",
                    "params": {
                        "incident_id": "{{ input.incident_id }}",
                        "status": "ack",
                        "notes": "Account {{ input.username }} disabled, sessions revoked, password reset initiated",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 9
    {
        "name": "Vulnerability Disclosure",
        "description": "Gestion divulgation vulnerabilite: evaluation impact, priorisation patch, notification responsables.",
        "category": "vulnerability",
        "trigger_type": "manual",
        "trigger_config": {},
        "tags": ["vulnerability", "patch", "disclosure"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "search_affected",
                    "action": "search_events",
                    "params": {"query": "{{ input.cve_id }}", "time_range_hours": 720, "limit": 500},
                },
                {
                    "name": "schedule_patch",
                    "action": "patch_vulnerability",
                    "params": {
                        "cve_id": "{{ input.cve_id }}",
                        "target_hosts": "{{ input.affected_hosts }}",
                        "priority": "{{ input.priority }}",
                    },
                },
                {
                    "name": "notify_owners",
                    "action": "send_email",
                    "params": {
                        "to": "{{ input.system_owner }}",
                        "subject": "Vulnerability {{ input.cve_id }} — patch required",
                        "body": "CVE {{ input.cve_id }} affects your systems. Priority: {{ input.priority }}. Patch deployment scheduled.",
                    },
                },
                {
                    "name": "create_ticket",
                    "action": "create_ticket_jira",
                    "params": {
                        "url": "{{ input.jira_url }}",
                        "project": "SEC",
                        "summary": "Patch {{ input.cve_id }}",
                        "description": "Vulnerability {{ input.cve_id }} — {{ input.description }}",
                        "priority": "High",
                    },
                    "condition": {"field": "input.jira_url", "operator": "exists", "value": None},
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 10
    {
        "name": "Suspicious Login",
        "description": "Verification connexion suspecte: MFA, geolocalisation, notification utilisateur.",
        "category": "authentication",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["suspicious_login", "impossible_travel", "new_device"]},
        "tags": ["login", "mfa", "authentication"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "geoip",
                    "action": "geoip_lookup",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "check_tor",
                    "action": "check_tor_exit",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "reputation",
                    "action": "lookup_ip_reputation",
                    "params": {"ip": "{{ input.src_ip }}"},
                },
                {
                    "name": "user_history",
                    "action": "get_user_activity",
                    "params": {"username": "{{ input.username }}", "hours": 72},
                },
                {
                    "name": "revoke_if_tor",
                    "action": "revoke_sessions",
                    "params": {"username": "{{ input.username }}"},
                    "condition": {"field": "steps.check_tor.is_tor_exit", "operator": "eq", "value": True},
                },
                {
                    "name": "notify_user",
                    "action": "send_email",
                    "params": {
                        "to": "{{ input.user_email }}",
                        "subject": "Suspicious login to your account",
                        "body": "A login from {{ steps.geoip.country_name }} ({{ input.src_ip }}) was detected. If this wasn't you, change your password immediately.",
                    },
                    "condition": {"field": "input.user_email", "operator": "exists", "value": None},
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 11
    {
        "name": "C2 Detection",
        "description": "Detection C2: blocage domaine/IP, scan implants, verification autres hotes.",
        "category": "malware",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["c2_beacon", "dns_c2", "http_c2"]},
        "tags": ["c2", "beacon", "containment"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "block_domain",
                    "action": "block_domain_dns",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "block_ip",
                    "action": "block_ip_firewall",
                    "params": {"ip": "{{ input.c2_ip }}", "direction": "both", "duration_hours": 8760},
                    "condition": {"field": "input.c2_ip", "operator": "exists", "value": None},
                },
                {
                    "name": "scan_implants",
                    "action": "get_host_processes",
                    "params": {"hostname": "{{ input.hostname }}"},
                },
                {
                    "name": "check_other_hosts",
                    "action": "search_events",
                    "params": {"query": "{{ input.c2_domain }}", "time_range_hours": 168, "limit": 500},
                },
                {
                    "name": "isolate_host",
                    "action": "isolate_host",
                    "params": {"hostname": "{{ input.hostname }}", "isolation_level": "full"},
                },
                {
                    "name": "export_iocs",
                    "action": "export_iocs",
                    "params": {
                        "iocs": [
                            {"type": "domain-name", "value": "{{ input.c2_domain }}"},
                            {"type": "ipv4-addr", "value": "{{ input.c2_ip }}"},
                        ],
                        "format": "stix",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 12
    {
        "name": "Web Shell Detection",
        "description": "Detection webshell: quarantaine fichier, analyse logs acces, patch vulnerabilite.",
        "category": "web",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["webshell", "suspicious_upload", "web_backdoor"]},
        "tags": ["webshell", "web", "remediation"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "quarantine",
                    "action": "quarantine_file",
                    "params": {"file_path": "{{ input.file_path }}", "hostname": "{{ input.hostname }}"},
                },
                {
                    "name": "check_hash",
                    "action": "lookup_hash",
                    "params": {"hash": "{{ input.file_hash }}", "hash_type": "sha256"},
                },
                {
                    "name": "access_logs",
                    "action": "search_events",
                    "params": {"query": "{{ input.file_path }}", "time_range_hours": 168, "limit": 500},
                },
                {
                    "name": "check_source_ip",
                    "action": "run_osint",
                    "params": {"indicator": "{{ input.src_ip }}", "indicator_type": "ip"},
                },
                {
                    "name": "waf_rule",
                    "action": "update_waf_rules",
                    "params": {"rule_type": "path", "pattern": "{{ input.file_path }}", "action": "block"},
                },
                {
                    "name": "remove_persistence",
                    "action": "remove_persistence",
                    "params": {
                        "hostname": "{{ input.hostname }}",
                        "persistence_type": "webshell",
                        "path": "{{ input.file_path }}",
                    },
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 13
    {
        "name": "Privilege Escalation",
        "description": "Detection escalade de privileges: revocation, audit modifications, investigation.",
        "category": "authentication",
        "trigger_type": "on_alert",
        "trigger_config": {"rule_ids": ["privesc", "sudo_abuse", "admin_grant"]},
        "tags": ["privesc", "audit", "investigation"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "revoke_privileges",
                    "action": "disable_user",
                    "params": {"username": "{{ input.username }}", "reason": "Privilege escalation detected"},
                },
                {
                    "name": "revoke_sessions",
                    "action": "revoke_sessions",
                    "params": {"username": "{{ input.username }}"},
                },
                {
                    "name": "audit_changes",
                    "action": "get_user_activity",
                    "params": {"username": "{{ input.username }}", "hours": 24},
                },
                {
                    "name": "check_processes",
                    "action": "get_host_processes",
                    "params": {"hostname": "{{ input.hostname }}"},
                },
                {
                    "name": "report",
                    "action": "generate_report",
                    "params": {"incident_id": "{{ input.incident_id }}", "format": "json", "include_timeline": True},
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 14
    {
        "name": "Supply Chain Attack",
        "description": "Reponse attaque supply chain: inventaire affectes, isolation, verification integrite.",
        "category": "supply-chain",
        "trigger_type": "manual",
        "trigger_config": {},
        "tags": ["supply-chain", "critical", "investigation"],
        "definition": {
            "rollback_on_failure": False,
            "steps": [
                {
                    "name": "identify_affected",
                    "action": "search_events",
                    "params": {"query": "{{ input.package_name }}", "time_range_hours": 720, "limit": 500},
                },
                {
                    "name": "check_hash",
                    "action": "lookup_hash",
                    "params": {"hash": "{{ input.package_hash }}", "hash_type": "sha256"},
                },
                {
                    "name": "check_c2",
                    "action": "lookup_domain",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "block_domains",
                    "action": "block_domain_dns",
                    "params": {"domain": "{{ input.c2_domain }}"},
                    "condition": {"field": "input.c2_domain", "operator": "exists", "value": None},
                },
                {
                    "name": "notify_critical",
                    "action": "send_pagerduty",
                    "params": {
                        "routing_key": "{{ input.pagerduty_key }}",
                        "summary": "Supply chain attack — {{ input.package_name }} compromised",
                        "severity": "critical",
                    },
                    "condition": {"field": "input.pagerduty_key", "operator": "exists", "value": None},
                },
                {
                    "name": "export_iocs",
                    "action": "export_iocs",
                    "params": {"iocs": [], "format": "stix"},
                },
            ],
        },
    },
    # ------------------------------------------------------------------ 15
    {
        "name": "Zero Day Response",
        "description": "Reponse zero-day: patch virtuel, monitoring renforce, threat hunting.",
        "category": "vulnerability",
        "trigger_type": "manual",
        "trigger_config": {},
        "tags": ["zero-day", "critical", "hunting"],
        "definition": {
            "rollback_on_failure": True,
            "steps": [
                {
                    "name": "virtual_patch",
                    "action": "update_waf_rules",
                    "params": {
                        "rule_type": "virtual_patch",
                        "pattern": "{{ input.exploit_pattern }}",
                        "action": "block",
                    },
                    "rollback": {
                        "action": "update_waf_rules",
                        "params": {"rule_type": "virtual_patch", "pattern": "{{ input.exploit_pattern }}", "action": "remove"},
                    },
                },
                {
                    "name": "search_exploitation",
                    "action": "search_events",
                    "params": {"query": "{{ input.exploit_signature }}", "time_range_hours": 720, "limit": 500},
                },
                {
                    "name": "check_indicators",
                    "action": "run_osint",
                    "params": {"indicator": "{{ input.indicator }}", "indicator_type": "auto"},
                    "condition": {"field": "input.indicator", "operator": "exists", "value": None},
                },
                {
                    "name": "block_known_ips",
                    "action": "block_ip_firewall",
                    "params": {"ip": "{{ input.attacker_ip }}", "direction": "both", "duration_hours": 8760},
                    "condition": {"field": "input.attacker_ip", "operator": "exists", "value": None},
                },
                {
                    "name": "enhanced_monitoring",
                    "action": "capture_pcap",
                    "params": {
                        "interface": "eth0",
                        "filter": "{{ input.pcap_filter }}",
                        "duration_seconds": 3600,
                    },
                    "condition": {"field": "input.pcap_filter", "operator": "exists", "value": None},
                },
                {
                    "name": "pagerduty",
                    "action": "send_pagerduty",
                    "params": {
                        "routing_key": "{{ input.pagerduty_key }}",
                        "summary": "Zero-day {{ input.cve_id }} — virtual patch applied, hunting in progress",
                        "severity": "critical",
                    },
                    "condition": {"field": "input.pagerduty_key", "operator": "exists", "value": None},
                },
                {
                    "name": "slack_notify",
                    "action": "send_slack",
                    "params": {
                        "channel": "#incident-response",
                        "message": "Zero-day response active for {{ input.cve_id }}. Virtual patch deployed. Enhanced monitoring on.",
                    },
                },
                {
                    "name": "report",
                    "action": "generate_report",
                    "params": {"incident_id": "{{ input.incident_id }}", "format": "json"},
                },
            ],
        },
    },
]
