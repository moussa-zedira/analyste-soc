"""Table de mapping Windows Event IDs vers types d'evenements SIEM."""

from __future__ import annotations

# (event_type, severity, description)
WINLOG_EVENT_MAP: dict[int, tuple[str, str, str]] = {
    # Authentication
    4624: ("auth.success", "low", "Successful logon"),
    4625: ("auth.fail", "medium", "Failed logon"),
    4634: ("session.close", "low", "Logoff"),
    4647: ("session.close", "low", "User initiated logoff"),
    4648: ("auth.explicit", "medium", "Logon using explicit credentials"),
    4768: ("auth.kerberos.tgt", "low", "Kerberos TGT requested"),
    4769: ("auth.kerberos.service", "low", "Kerberos service ticket requested"),
    4771: ("auth.kerberos.fail", "medium", "Kerberos pre-authentication failed"),
    4776: ("auth.ntlm", "low", "NTLM authentication attempt"),
    # Privilege escalation
    4672: ("priv.escalation", "high", "Special privileges assigned"),
    4673: ("priv.service", "medium", "Privileged service called"),
    4674: ("priv.object", "medium", "Operation on privileged object"),
    # Account management
    4720: ("account.created", "medium", "User account created"),
    4722: ("account.enabled", "low", "User account enabled"),
    4723: ("account.password_change", "low", "Password change attempt"),
    4724: ("account.password_reset", "medium", "Password reset attempt"),
    4725: ("account.disabled", "medium", "User account disabled"),
    4726: ("account.deleted", "high", "User account deleted"),
    4738: ("account.changed", "medium", "User account changed"),
    4740: ("account.locked", "medium", "Account locked out"),
    # Group changes
    4728: ("group.member_added", "medium", "Member added to global group"),
    4729: ("group.member_removed", "medium", "Member removed from global group"),
    4732: ("group.member_added", "medium", "Member added to local group"),
    4733: ("group.member_removed", "medium", "Member removed from local group"),
    4756: ("group.member_added", "medium", "Member added to universal group"),
    4757: ("group.member_removed", "medium", "Member removed from universal group"),
    # System events
    1102: ("audit.log_cleared", "critical", "Audit log cleared"),
    4616: ("system.time_changed", "high", "System time changed"),
    4697: ("service.installed", "medium", "Service installed"),
    7045: ("service.installed", "medium", "New service installed"),
    7040: ("service.changed", "medium", "Service start type changed"),
    # Process events
    4688: ("process.created", "low", "New process created"),
    4689: ("process.terminated", "low", "Process terminated"),
    # Policy changes
    4713: ("policy.kerberos_changed", "high", "Kerberos policy changed"),
    4719: ("policy.audit_changed", "high", "System audit policy changed"),
    4739: ("policy.domain_changed", "high", "Domain policy changed"),
    # Firewall
    5152: ("network.blocked", "low", "Windows Filtering Platform blocked packet"),
    5156: ("network.allowed", "low", "Windows Filtering Platform allowed connection"),
    5157: ("network.blocked", "low", "Windows Filtering Platform blocked connection"),
    # Scheduled tasks
    4698: ("task.created", "medium", "Scheduled task created"),
    4699: ("task.deleted", "low", "Scheduled task deleted"),
    4702: ("task.updated", "medium", "Scheduled task updated"),
}

# IDs considered high-priority for immediate alerting
HIGH_PRIORITY_IDS = {
    1102,
    4625,
    4648,
    4672,
    4720,
    4726,
    4740,
    4713,
    4719,
    4739,
    7045,
    4697,
}
