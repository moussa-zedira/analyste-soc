"use client";

import { useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface Playbook {
  id: string;
  name: string;
  trigger: "alert" | "scheduled" | "manual" | "webhook";
  lastRun: string;
  successRate: number;
  status: "active" | "disabled";
  steps: number;
}

interface Execution {
  id: string;
  playbookName: string;
  status: "running" | "success" | "failed" | "cancelled";
  startedAt: string;
  duration: string;
  trigger: string;
}

interface ActionDef {
  id: string;
  name: string;
  category: string;
  description: string;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const MOCK_PLAYBOOKS: Playbook[] = [
  { id: "pb-001", name: "Isolate Compromised Host", trigger: "alert", lastRun: "2 min ago", successRate: 98, status: "active", steps: 5 },
  { id: "pb-002", name: "Phishing Response", trigger: "alert", lastRun: "15 min ago", successRate: 95, status: "active", steps: 8 },
  { id: "pb-003", name: "Malware Containment", trigger: "alert", lastRun: "1h ago", successRate: 92, status: "active", steps: 6 },
  { id: "pb-004", name: "Threat Intel Enrichment", trigger: "webhook", lastRun: "5 min ago", successRate: 99, status: "active", steps: 3 },
  { id: "pb-005", name: "Vulnerability Scan Nightly", trigger: "scheduled", lastRun: "8h ago", successRate: 100, status: "active", steps: 4 },
  { id: "pb-006", name: "User Account Lockout", trigger: "alert", lastRun: "30 min ago", successRate: 97, status: "active", steps: 4 },
  { id: "pb-007", name: "DDoS Mitigation", trigger: "alert", lastRun: "3h ago", successRate: 88, status: "disabled", steps: 7 },
  { id: "pb-008", name: "Compliance Check", trigger: "scheduled", lastRun: "12h ago", successRate: 100, status: "active", steps: 5 },
];

const MOCK_EXECUTIONS: Execution[] = [
  { id: "ex-001", playbookName: "Isolate Compromised Host", status: "running", startedAt: "2 min ago", duration: "1m 42s", trigger: "SIEM Alert #4521" },
  { id: "ex-002", playbookName: "Phishing Response", status: "success", startedAt: "15 min ago", duration: "3m 12s", trigger: "Email Gateway" },
  { id: "ex-003", playbookName: "Threat Intel Enrichment", status: "success", startedAt: "20 min ago", duration: "0m 45s", trigger: "Webhook" },
  { id: "ex-004", playbookName: "Malware Containment", status: "failed", startedAt: "1h ago", duration: "2m 08s", trigger: "EDR Alert" },
  { id: "ex-005", playbookName: "User Account Lockout", status: "success", startedAt: "30 min ago", duration: "0m 22s", trigger: "Brute Force Detection" },
  { id: "ex-006", playbookName: "Vulnerability Scan Nightly", status: "success", startedAt: "8h ago", duration: "12m 34s", trigger: "Cron Schedule" },
];

const MOCK_ACTIONS: ActionDef[] = [
  { id: "a1", name: "Block IP", category: "Firewall", description: "Add IP to firewall blocklist" },
  { id: "a2", name: "Isolate Host", category: "EDR", description: "Network-isolate endpoint via EDR" },
  { id: "a3", name: "Disable User", category: "IAM", description: "Disable user account in Active Directory" },
  { id: "a4", name: "Send Notification", category: "Comms", description: "Send Slack/email notification" },
  { id: "a5", name: "Enrich IOC", category: "Intel", description: "Query threat intel for IOC context" },
  { id: "a6", name: "Create Ticket", category: "ITSM", description: "Open incident ticket in ServiceNow" },
  { id: "a7", name: "Snapshot VM", category: "Cloud", description: "Take VM snapshot for forensics" },
  { id: "a8", name: "Run Script", category: "Custom", description: "Execute custom remediation script" },
  { id: "a9", name: "Quarantine File", category: "EDR", description: "Quarantine suspicious file on endpoint" },
  { id: "a10", name: "Reset Password", category: "IAM", description: "Force password reset for compromised account" },
];

const BUILDER_STEPS = [
  { id: 1, name: "Trigger", type: "trigger", desc: "Alert matches severity >= HIGH" },
  { id: 2, name: "Enrich IOC", type: "action", desc: "Query VirusTotal + AbuseIPDB" },
  { id: 3, name: "Decision", type: "condition", desc: "If malicious score > 70" },
  { id: 4, name: "Block IP", type: "action", desc: "Add to firewall blocklist" },
  { id: 5, name: "Notify SOC", type: "action", desc: "Send Slack alert to #incidents" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const TRIGGER_COLORS: Record<string, string> = {
  alert: "bg-red-500/15 text-red-400 border-red-500/30",
  scheduled: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  manual: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  webhook: "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  running: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  success: "bg-green-500/15 text-green-400 border-green-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  cancelled: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const STEP_COLORS: Record<string, string> = {
  trigger: "border-cyan-glow/40 bg-cyan-glow/10",
  action: "border-green-500/40 bg-green-500/10",
  condition: "border-yellow-500/40 bg-yellow-500/10",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

function MetricCard({ label, value, sub, accent = "cyan" }: { label: string; value: string; sub?: string; accent?: string }) {
  const colors: Record<string, string> = {
    cyan: "border-cyan-glow/20 shadow-cyan-sm",
    green: "border-green-500/20",
    yellow: "border-yellow-500/20",
    red: "border-red-500/20",
  };
  const textColors: Record<string, string> = {
    cyan: "text-cyan-glow",
    green: "text-green-400",
    yellow: "text-yellow-400",
    red: "text-red-400",
  };
  return (
    <div className={`glass-panel border ${colors[accent] || colors.cyan} p-4`}>
      <p className="text-[9px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold tracking-wide ${textColors[accent] || textColors.cyan}`} style={{ fontFamily: "Orbitron, sans-serif" }}>{value}</p>
      {sub && <p className="mt-1 text-[10px] text-gray-500">{sub}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function SoarDashboard() {
  const [activeTab, setActiveTab] = useState<"overview" | "builder" | "actions">("overview");
  const [runningPlaybook, setRunningPlaybook] = useState<string | null>(null);

  const handleRunPlaybook = useCallback((id: string) => {
    setRunningPlaybook(id);
    setTimeout(() => setRunningPlaybook(null), 2000);
  }, []);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            SOAR Dashboard
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SECURITY ORCHESTRATION // AUTOMATION & RESPONSE
          </p>
        </div>
        <div className="flex gap-2">
          {(["overview", "builder", "actions"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold uppercase tracking-wider transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow shadow-cyan-sm"
                  : "border-gray-700/50 bg-gray-900/50 text-gray-500 hover:border-cyan-glow/20 hover:text-cyan-dim"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      <div className="cyan-line" />

      {/* Metrics */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Mean Time to Detect" value="4.2m" sub="Avg across all alerts" accent="cyan" />
        <MetricCard label="Mean Time to Respond" value="8.7m" sub="-23% from last week" accent="green" />
        <MetricCard label="Playbooks Executed Today" value="147" sub="12 currently running" accent="yellow" />
        <MetricCard label="Auto-Resolved" value="73%" sub="107 of 147 executions" accent="cyan" />
      </div>

      {activeTab === "overview" && (
        <>
          {/* Playbook Library Grid */}
          <div>
            <h2 className="hud-heading mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Playbook Library
            </h2>
            <div className="grid grid-cols-4 gap-3">
              {MOCK_PLAYBOOKS.map((pb) => (
                <div
                  key={pb.id}
                  className="glass-panel group relative border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/30 hover:shadow-cyan-sm"
                >
                  <div className="mb-2 flex items-center justify-between">
                    <Badge text={pb.trigger} cls={TRIGGER_COLORS[pb.trigger]} />
                    <span className={`h-2 w-2 rounded-full ${pb.status === "active" ? "bg-green-400 animate-pulse" : "bg-gray-600"}`} />
                  </div>
                  <h3 className="text-xs font-bold text-gray-200">{pb.name}</h3>
                  <div className="mt-2 flex items-center justify-between text-[9px] text-gray-500">
                    <span>{pb.steps} steps</span>
                    <span>Last: {pb.lastRun}</span>
                  </div>
                  <div className="mt-2">
                    <div className="flex items-center justify-between text-[9px]">
                      <span className="text-gray-500">Success Rate</span>
                      <span className={pb.successRate >= 95 ? "text-green-400" : pb.successRate >= 85 ? "text-yellow-400" : "text-red-400"}>
                        {pb.successRate}%
                      </span>
                    </div>
                    <div className="mt-1 h-1 w-full rounded-full bg-gray-800">
                      <div
                        className={`h-1 rounded-full transition-all ${pb.successRate >= 95 ? "bg-green-500" : pb.successRate >= 85 ? "bg-yellow-500" : "bg-red-500"}`}
                        style={{ width: `${pb.successRate}%` }}
                      />
                    </div>
                  </div>
                  <button
                    onClick={() => handleRunPlaybook(pb.id)}
                    className="mt-3 w-full rounded border border-cyan-glow/20 bg-cyan-glow/5 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15 active:scale-95"
                  >
                    {runningPlaybook === pb.id ? "EXECUTING..." : "RUN NOW"}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Active Executions Feed */}
          <div>
            <h2 className="hud-heading mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Recent Executions
            </h2>
            <div className="glass-panel overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Playbook</th>
                    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Started</th>
                    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
                    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Trigger</th>
                  </tr>
                </thead>
                <tbody>
                  {MOCK_EXECUTIONS.map((ex) => (
                    <tr key={ex.id} className="border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5">
                      <td className="px-4 py-3 text-xs font-medium text-gray-200">{ex.playbookName}</td>
                      <td className="px-4 py-3">
                        <Badge text={ex.status} cls={STATUS_COLORS[ex.status]} />
                      </td>
                      <td className="px-4 py-3 text-[10px] text-gray-400">{ex.startedAt}</td>
                      <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{ex.duration}</td>
                      <td className="px-4 py-3 text-[10px] text-gray-500">{ex.trigger}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Execution Timeline */}
          <div>
            <h2 className="hud-heading mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Execution Timeline
            </h2>
            <div className="glass-panel p-4">
              <div className="relative">
                <div className="absolute left-4 top-0 h-full w-px bg-cyan-glow/20" />
                {MOCK_EXECUTIONS.map((ex, i) => (
                  <div key={ex.id} className="relative mb-4 ml-10 last:mb-0">
                    <div className={`absolute -left-[26px] top-1 h-3 w-3 rounded-full border-2 ${
                      ex.status === "running" ? "border-cyan-glow bg-cyan-glow/30 animate-pulse" :
                      ex.status === "success" ? "border-green-500 bg-green-500/30" :
                      ex.status === "failed" ? "border-red-500 bg-red-500/30" :
                      "border-gray-500 bg-gray-500/30"
                    }`} />
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] text-gray-500">{ex.startedAt}</span>
                      <span className="text-xs font-medium text-gray-300">{ex.playbookName}</span>
                      <Badge text={ex.status} cls={STATUS_COLORS[ex.status]} />
                      <span className="text-[10px] font-mono text-gray-600">{ex.duration}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}

      {activeTab === "builder" && (
        <div>
          <h2 className="hud-heading mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Playbook Builder
          </h2>
          <div className="glass-panel p-6">
            <div className="mb-4 flex items-center gap-4">
              <input
                type="text"
                placeholder="Playbook Name..."
                className="flex-1 rounded border border-cyan-glow/20 bg-black/40 px-4 py-2 text-xs font-mono text-gray-200 outline-none focus:border-cyan-glow/50"
              />
              <select className="rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none">
                <option value="alert">Trigger: Alert</option>
                <option value="scheduled">Trigger: Scheduled</option>
                <option value="manual">Trigger: Manual</option>
                <option value="webhook">Trigger: Webhook</option>
              </select>
              <button className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20">
                Save Playbook
              </button>
            </div>

            {/* Visual Steps */}
            <div className="space-y-3">
              {BUILDER_STEPS.map((step, i) => (
                <div key={step.id} className="relative">
                  {i > 0 && (
                    <div className="absolute -top-3 left-8 h-3 w-px bg-cyan-glow/30" />
                  )}
                  <div className={`flex items-center gap-4 rounded-lg border p-4 ${STEP_COLORS[step.type]}`}>
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-black/40 text-xs font-bold text-cyan-glow">
                      {step.id}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold text-gray-200">{step.name}</span>
                        <Badge
                          text={step.type}
                          cls={
                            step.type === "trigger" ? "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30" :
                            step.type === "condition" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                            "bg-green-500/15 text-green-400 border-green-500/30"
                          }
                        />
                      </div>
                      <p className="mt-1 text-[10px] text-gray-500">{step.desc}</p>
                    </div>
                    <button className="rounded border border-gray-700 bg-gray-900/50 px-3 py-1 text-[9px] text-gray-500 transition-colors hover:border-red-500/30 hover:text-red-400">
                      REMOVE
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <button className="mt-4 w-full rounded border border-dashed border-cyan-glow/20 bg-cyan-glow/5 py-3 text-[10px] font-bold uppercase tracking-wider text-cyan-glow/50 transition-all hover:border-cyan-glow/40 hover:text-cyan-glow">
              + ADD STEP
            </button>
          </div>
        </div>
      )}

      {activeTab === "actions" && (
        <div>
          <h2 className="hud-heading mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Action Library
          </h2>
          <div className="grid grid-cols-2 gap-3">
            {MOCK_ACTIONS.map((action) => (
              <div key={action.id} className="glass-panel flex items-center gap-4 border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/30">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-glow/20 bg-cyan-glow/5">
                  <svg className="h-5 w-5 text-cyan-glow" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
                  </svg>
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-gray-200">{action.name}</span>
                    <Badge text={action.category} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
                  </div>
                  <p className="mt-0.5 text-[10px] text-gray-500">{action.description}</p>
                </div>
                <button className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15">
                  USE
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
