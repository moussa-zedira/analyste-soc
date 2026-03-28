"use client";

import { Fragment, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface StepLog {
  step: string;
  status: "success" | "failed" | "skipped";
  duration: string;
  output: string;
}

interface Execution {
  id: string;
  playbookName: string;
  status: "running" | "success" | "failed" | "cancelled";
  startedAt: string;
  duration: string;
  triggerSource: string;
  affectedEntities: string[];
  steps: StepLog[];
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const EXECUTIONS: Execution[] = [
  {
    id: "exec-001", playbookName: "Isolate Compromised Host", status: "running",
    startedAt: "2026-03-29 09:45:12", duration: "1m 42s", triggerSource: "EDR Alert #8821",
    affectedEntities: ["host-web-04", "10.0.2.15"],
    steps: [
      { step: "Receive Alert", status: "success", duration: "0.2s", output: "Alert received: malware detected on host-web-04" },
      { step: "Validate IOC", status: "success", duration: "3.1s", output: "Hash a1b2c3... flagged by 42/70 engines on VT" },
      { step: "Is Malicious?", status: "success", duration: "0.1s", output: "Condition TRUE: score 42 > threshold 5" },
      { step: "Isolate Host", status: "success", duration: "8.5s", output: "Host host-web-04 isolated via CrowdStrike API" },
      { step: "Notify SOC", status: "success", duration: "1.2s", output: "Slack notification sent to #incidents" },
    ],
  },
  {
    id: "exec-002", playbookName: "Phishing Response", status: "success",
    startedAt: "2026-03-29 09:30:00", duration: "3m 12s", triggerSource: "Email Gateway Alert",
    affectedEntities: ["user@corp.com", "malicious-site.com"],
    steps: [
      { step: "Email Alert", status: "success", duration: "0.1s", output: "Phishing email detected from sender spoof@evil.com" },
      { step: "Extract IOCs", status: "success", duration: "1.5s", output: "Extracted 3 URLs, 1 domain, 2 file hashes" },
      { step: "Enrich IOCs", status: "success", duration: "12.3s", output: "All IOCs enriched: 2 malicious, 1 suspicious" },
      { step: "Block Domain", status: "success", duration: "2.1s", output: "malicious-site.com added to DNS sinkhole" },
      { step: "Check Recipients", status: "success", duration: "5.2s", output: "15 recipients found, 3 clicked the link" },
      { step: "Any Clicks?", status: "success", duration: "0.1s", output: "Condition TRUE: 3 users clicked" },
      { step: "Reset Passwords", status: "success", duration: "4.8s", output: "Password reset forced for 3 affected users" },
      { step: "Report", status: "success", duration: "8.2s", output: "Incident report generated and sent to mgmt" },
    ],
  },
  {
    id: "exec-003", playbookName: "Threat Intel Enrichment", status: "success",
    startedAt: "2026-03-29 09:25:00", duration: "0m 45s", triggerSource: "Webhook",
    affectedEntities: ["185.220.101.42"],
    steps: [
      { step: "New IOC", status: "success", duration: "0.1s", output: "Received IP 185.220.101.42 from SIEM webhook" },
      { step: "Multi-Source Lookup", status: "success", duration: "8.5s", output: "VT: malicious, OTX: Tor exit node, AbuseIPDB: 98% confidence" },
      { step: "Update Database", status: "success", duration: "0.3s", output: "IOC record updated with enrichment data" },
    ],
  },
  {
    id: "exec-004", playbookName: "Malware Containment", status: "failed",
    startedAt: "2026-03-29 08:45:00", duration: "2m 08s", triggerSource: "EDR Alert #8815",
    affectedEntities: ["host-dev-02", "10.0.5.33"],
    steps: [
      { step: "EDR Detection", status: "success", duration: "0.2s", output: "Ransomware detected on host-dev-02" },
      { step: "Quarantine File", status: "success", duration: "2.1s", output: "File quarantined: C:\\Users\\Public\\update.exe" },
      { step: "Scan Host", status: "failed", duration: "45.0s", output: "ERROR: EDR agent unresponsive on host-dev-02" },
      { step: "More Found?", status: "skipped", duration: "-", output: "Skipped due to previous step failure" },
      { step: "Isolate & Notify", status: "skipped", duration: "-", output: "Skipped due to previous step failure" },
      { step: "Create Ticket", status: "skipped", duration: "-", output: "Skipped due to previous step failure" },
    ],
  },
  {
    id: "exec-005", playbookName: "User Account Lockout", status: "success",
    startedAt: "2026-03-29 08:20:00", duration: "0m 22s", triggerSource: "Brute Force Detection",
    affectedEntities: ["admin@corp.com", "192.168.1.100"],
    steps: [
      { step: "Brute Force Alert", status: "success", duration: "0.1s", output: "50 failed login attempts from 192.168.1.100" },
      { step: "Lock Account", status: "success", duration: "1.2s", output: "Account admin@corp.com locked in AD" },
      { step: "Block Source IP", status: "success", duration: "2.5s", output: "IP 192.168.1.100 blocked at firewall" },
      { step: "Notify User", status: "success", duration: "0.8s", output: "Email sent to admin@corp.com with instructions" },
    ],
  },
  {
    id: "exec-006", playbookName: "Vulnerability Scan Nightly", status: "success",
    startedAt: "2026-03-29 02:00:00", duration: "12m 34s", triggerSource: "Cron Schedule",
    affectedEntities: ["subnet-10.0.0.0/24", "48 hosts"],
    steps: [
      { step: "Cron Trigger", status: "success", duration: "0.1s", output: "Scheduled scan triggered at 02:00 UTC" },
      { step: "Scan Assets", status: "success", duration: "10m 15s", output: "Scanned 48 hosts, found 23 vulnerabilities" },
      { step: "Parse Results", status: "success", duration: "1m 45s", output: "3 critical, 8 high, 12 medium findings" },
      { step: "Create Tickets", status: "success", duration: "0m 34s", output: "11 Jira tickets created for critical/high findings" },
    ],
  },
  {
    id: "exec-007", playbookName: "DDoS Mitigation", status: "cancelled",
    startedAt: "2026-03-28 18:30:00", duration: "0m 15s", triggerSource: "Traffic Spike Alert",
    affectedEntities: ["edge-lb-01"],
    steps: [
      { step: "Traffic Spike", status: "success", duration: "0.1s", output: "Traffic 15x above baseline detected" },
      { step: "Analyze Pattern", status: "success", duration: "5.2s", output: "Pattern: legitimate marketing campaign traffic" },
      { step: "Is DDoS?", status: "success", duration: "0.3s", output: "Condition FALSE: not a DDoS attack" },
    ],
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const STATUS_COLORS: Record<string, string> = {
  running: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  success: "bg-green-500/15 text-green-400 border-green-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  cancelled: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const STEP_STATUS_COLORS: Record<string, string> = {
  success: "text-green-400",
  failed: "text-red-400",
  skipped: "text-gray-500",
};

const STEP_DOT: Record<string, string> = {
  success: "bg-green-500",
  failed: "bg-red-500",
  skipped: "bg-gray-600",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function ExecutionsPage() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filterPlaybook, setFilterPlaybook] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterDateFrom, setFilterDateFrom] = useState<string>("");
  const [filterDateTo, setFilterDateTo] = useState<string>("");

  const playbookNames = [...new Set(EXECUTIONS.map((e) => e.playbookName))];

  const filtered = EXECUTIONS.filter((ex) => {
    if (filterPlaybook !== "all" && ex.playbookName !== filterPlaybook) return false;
    if (filterStatus !== "all" && ex.status !== filterStatus) return false;
    return true;
  });

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Execution History
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SOAR // ALL PLAYBOOK EXECUTIONS
          </p>
        </div>
        <div className="glass-panel flex items-center gap-2 px-3 py-1.5">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-glow opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-cyan-glow" />
          </span>
          <span className="text-[10px] tracking-wider text-gray-500">
            {EXECUTIONS.filter((e) => e.status === "running").length} RUNNING
          </span>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Filters */}
      <div className="glass-panel flex flex-wrap items-center gap-4 p-3">
        <span className="text-[9px] uppercase tracking-wider text-gray-500">Filters:</span>
        <select
          value={filterPlaybook}
          onChange={(e) => setFilterPlaybook(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Playbooks</option>
          {playbookNames.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Status</option>
          <option value="running">Running</option>
          <option value="success">Success</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </select>
        <div className="flex items-center gap-2">
          <span className="text-[9px] text-gray-500">From:</span>
          <input
            type="date"
            value={filterDateFrom}
            onChange={(e) => setFilterDateFrom(e.target.value)}
            className="rounded border border-cyan-glow/15 bg-black/40 px-2 py-1.5 text-[10px] text-gray-300 outline-none"
          />
          <span className="text-[9px] text-gray-500">To:</span>
          <input
            type="date"
            value={filterDateTo}
            onChange={(e) => setFilterDateTo(e.target.value)}
            className="rounded border border-cyan-glow/15 bg-black/40 px-2 py-1.5 text-[10px] text-gray-300 outline-none"
          />
        </div>
        <span className="ml-auto text-[10px] text-gray-500">{filtered.length} executions</span>
      </div>

      {/* Executions Table */}
      <div className="glass-panel overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-cyan-glow/10">
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">ID</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Playbook</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Started</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Trigger</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Entities</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ex) => (
              <Fragment key={ex.id}>
                <tr
                  className={`cursor-pointer border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5 ${expandedId === ex.id ? "bg-cyan-glow/5" : ""}`}
                  onClick={() => setExpandedId(expandedId === ex.id ? null : ex.id)}
                >
                  <td className="px-4 py-3 text-[10px] font-mono text-cyan-glow/70">{ex.id}</td>
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{ex.playbookName}</td>
                  <td className="px-4 py-3"><Badge text={ex.status} cls={STATUS_COLORS[ex.status]} /></td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{ex.startedAt}</td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{ex.duration}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-500">{ex.triggerSource}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {ex.affectedEntities.map((e, i) => (
                        <span key={i} className="rounded bg-gray-800/50 px-1.5 py-0.5 text-[9px] font-mono text-gray-400">{e}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {ex.status === "running" && (
                      <button
                        onClick={(ev) => { ev.stopPropagation(); }}
                        className="rounded border border-red-500/20 bg-red-500/5 px-2 py-1 text-[9px] font-bold uppercase tracking-wider text-red-400 hover:bg-red-500/15"
                      >
                        CANCEL
                      </button>
                    )}
                  </td>
                </tr>
                {expandedId === ex.id && (
                  <tr>
                    <td colSpan={8} className="bg-black/30 px-6 py-4">
                      <h4 className="mb-3 text-[10px] font-bold uppercase tracking-wider text-cyan-glow">Step-by-Step Execution Log</h4>
                      <div className="space-y-2">
                        {ex.steps.map((step, i) => (
                          <div key={i} className="flex items-start gap-3 rounded border border-gray-800/50 bg-gray-900/30 p-3">
                            <div className="flex items-center gap-2 pt-0.5">
                              <span className={`h-2 w-2 rounded-full ${STEP_DOT[step.status]}`} />
                              <span className="w-4 text-center text-[9px] font-mono text-gray-600">{i + 1}</span>
                            </div>
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] font-bold text-gray-300">{step.step}</span>
                                <span className={`text-[9px] font-mono ${STEP_STATUS_COLORS[step.status]}`}>[{step.status.toUpperCase()}]</span>
                                <span className="text-[9px] font-mono text-gray-600">{step.duration}</span>
                              </div>
                              <p className="mt-1 text-[10px] font-mono text-gray-500">{step.output}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

