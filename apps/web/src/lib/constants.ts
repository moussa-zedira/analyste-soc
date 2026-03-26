import type { Severity, IncidentStatus } from "./types";

export const DEFAULT_LIMIT = 25;

export const SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
];

/** Subset used on the Events page (events don't have "critical"). */
export const EVENT_SEVERITY_OPTIONS = SEVERITY_OPTIONS.filter(
  (o) => o.value !== "critical",
);

export const STATUS_OPTIONS: { value: IncidentStatus; label: string }[] = [
  { value: "open", label: "Open" },
  { value: "ack", label: "Acknowledged" },
  { value: "closed", label: "Closed" },
];

export const RULE_MITRE_MAP: Record<string, { id: string; name: string; tactic: string }[]> = {
  "bruteforce.v1": [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  ],
  "bruteforce-username.v1": [
    { id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  ],
  "auth-targeted.v1": [
    { id: "T1110.004", name: "Credential Stuffing", tactic: "Credential Access" },
  ],
  "portscan.v1": [
    { id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  ],
  "anomaly.volume.v1": [
    { id: "T1499", name: "Endpoint Denial of Service", tactic: "Impact" },
  ],
  "anomaly.ip.v1": [
    { id: "T1071", name: "Application Layer Protocol", tactic: "C2" },
  ],
};
