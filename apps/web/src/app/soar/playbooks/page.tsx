"use client";

import { useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface PlaybookStep {
  id: number;
  name: string;
  type: "trigger" | "action" | "condition" | "notification";
  config: string;
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: "alert" | "scheduled" | "manual" | "webhook";
  category: "incident" | "enrichment" | "remediation" | "notification";
  status: "active" | "disabled" | "draft";
  steps: PlaybookStep[];
  lastRun: string;
  runCount: number;
  successRate: number;
  createdAt: string;
  updatedAt: string;
}

interface ExecutionLog {
  id: string;
  timestamp: string;
  status: "success" | "failed";
  duration: string;
  trigger: string;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const PLAYBOOKS: Playbook[] = [
  {
    id: "pb-001", name: "Isolate Compromised Host", description: "Automatically isolate hosts flagged by EDR with high-confidence malware detection",
    trigger: "alert", category: "remediation", status: "active",
    steps: [
      { id: 1, name: "Receive Alert", type: "trigger", config: "EDR alert severity >= HIGH" },
      { id: 2, name: "Validate IOC", type: "action", config: "Check hash against VT" },
      { id: 3, name: "Is Malicious?", type: "condition", config: "VT score > 5/70" },
      { id: 4, name: "Isolate Host", type: "action", config: "EDR network isolation" },
      { id: 5, name: "Notify SOC", type: "notification", config: "Slack #incidents" },
    ],
    lastRun: "2 min ago", runCount: 342, successRate: 98, createdAt: "2025-01-15", updatedAt: "2026-03-28",
  },
  {
    id: "pb-002", name: "Phishing Response", description: "Complete phishing incident response from detection to remediation",
    trigger: "alert", category: "incident", status: "active",
    steps: [
      { id: 1, name: "Email Alert", type: "trigger", config: "Phishing detection alert" },
      { id: 2, name: "Extract IOCs", type: "action", config: "URLs, domains, hashes" },
      { id: 3, name: "Enrich IOCs", type: "action", config: "TI lookup all indicators" },
      { id: 4, name: "Block Domain", type: "action", config: "DNS sinkhole" },
      { id: 5, name: "Check Recipients", type: "action", config: "Query mail logs" },
      { id: 6, name: "Any Clicks?", type: "condition", config: "Proxy log analysis" },
      { id: 7, name: "Reset Passwords", type: "action", config: "Force reset affected users" },
      { id: 8, name: "Report", type: "notification", config: "Generate incident report" },
    ],
    lastRun: "15 min ago", runCount: 128, successRate: 95, createdAt: "2025-02-10", updatedAt: "2026-03-27",
  },
  {
    id: "pb-003", name: "Malware Containment", description: "Contain and eradicate malware infections across endpoints",
    trigger: "alert", category: "remediation", status: "active",
    steps: [
      { id: 1, name: "EDR Detection", type: "trigger", config: "Malware detected" },
      { id: 2, name: "Quarantine File", type: "action", config: "EDR quarantine" },
      { id: 3, name: "Scan Host", type: "action", config: "Full AV scan" },
      { id: 4, name: "More Found?", type: "condition", config: "Additional IOCs" },
      { id: 5, name: "Isolate & Notify", type: "action", config: "Network isolation + Slack" },
      { id: 6, name: "Create Ticket", type: "notification", config: "ServiceNow P2" },
    ],
    lastRun: "1h ago", runCount: 89, successRate: 92, createdAt: "2025-03-05", updatedAt: "2026-03-25",
  },
  {
    id: "pb-004", name: "Threat Intel Enrichment", description: "Automatically enrich all new IOCs with threat intelligence data",
    trigger: "webhook", category: "enrichment", status: "active",
    steps: [
      { id: 1, name: "New IOC", type: "trigger", config: "Webhook from SIEM" },
      { id: 2, name: "Multi-Source Lookup", type: "action", config: "VT, OTX, AbuseIPDB" },
      { id: 3, name: "Update Database", type: "action", config: "Store enrichment data" },
    ],
    lastRun: "5 min ago", runCount: 2451, successRate: 99, createdAt: "2025-01-20", updatedAt: "2026-03-28",
  },
  {
    id: "pb-005", name: "Vulnerability Scan Nightly", description: "Scheduled nightly vulnerability scan of all critical assets",
    trigger: "scheduled", category: "remediation", status: "active",
    steps: [
      { id: 1, name: "Cron Trigger", type: "trigger", config: "0 2 * * * (2:00 AM)" },
      { id: 2, name: "Scan Assets", type: "action", config: "Nessus scan profile" },
      { id: 3, name: "Parse Results", type: "action", config: "Extract critical/high" },
      { id: 4, name: "Create Tickets", type: "notification", config: "Jira for each finding" },
    ],
    lastRun: "8h ago", runCount: 365, successRate: 100, createdAt: "2025-04-01", updatedAt: "2026-03-28",
  },
  {
    id: "pb-006", name: "DDoS Mitigation", description: "Automated DDoS detection and mitigation response",
    trigger: "alert", category: "remediation", status: "disabled",
    steps: [
      { id: 1, name: "Traffic Spike", type: "trigger", config: "Threshold > 10x baseline" },
      { id: 2, name: "Analyze Pattern", type: "action", config: "Traffic classification" },
      { id: 3, name: "Is DDoS?", type: "condition", config: "ML-based detection" },
      { id: 4, name: "Enable Scrubbing", type: "action", config: "CDN/WAF rules" },
      { id: 5, name: "Rate Limit", type: "action", config: "Edge rate limiting" },
      { id: 6, name: "Monitor", type: "action", config: "Real-time dashboard" },
      { id: 7, name: "All Clear", type: "notification", config: "Notify when mitigated" },
    ],
    lastRun: "3h ago", runCount: 12, successRate: 88, createdAt: "2025-06-15", updatedAt: "2026-03-20",
  },
];

const EXECUTION_HISTORY: ExecutionLog[] = [
  { id: "el-1", timestamp: "2026-03-29 09:42", status: "success", duration: "1m 42s", trigger: "EDR Alert #8821" },
  { id: "el-2", timestamp: "2026-03-29 08:15", status: "success", duration: "1m 38s", trigger: "EDR Alert #8819" },
  { id: "el-3", timestamp: "2026-03-28 22:30", status: "failed", duration: "0m 52s", trigger: "EDR Alert #8815" },
  { id: "el-4", timestamp: "2026-03-28 17:05", status: "success", duration: "2m 01s", trigger: "EDR Alert #8810" },
  { id: "el-5", timestamp: "2026-03-28 14:22", status: "success", duration: "1m 45s", trigger: "EDR Alert #8807" },
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

const CAT_COLORS: Record<string, string> = {
  incident: "bg-red-500/15 text-red-400 border-red-500/30",
  enrichment: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  remediation: "bg-green-500/15 text-green-400 border-green-500/30",
  notification: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const STATUS_BADGE: Record<string, string> = {
  active: "bg-green-500/15 text-green-400 border-green-500/30",
  disabled: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  draft: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const STEP_TYPE_COLORS: Record<string, { border: string; bg: string; dot: string }> = {
  trigger: { border: "border-cyan-glow/30", bg: "bg-cyan-glow/10", dot: "bg-cyan-glow" },
  action: { border: "border-green-500/30", bg: "bg-green-500/10", dot: "bg-green-500" },
  condition: { border: "border-yellow-500/30", bg: "bg-yellow-500/10", dot: "bg-yellow-500" },
  notification: { border: "border-purple-500/30", bg: "bg-purple-500/10", dot: "bg-purple-500" },
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function PlaybooksPage() {
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [filterTrigger, setFilterTrigger] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [showImportExport, setShowImportExport] = useState(false);

  const filtered = PLAYBOOKS.filter((pb) => {
    if (filterTrigger !== "all" && pb.trigger !== filterTrigger) return false;
    if (filterStatus !== "all" && pb.status !== filterStatus) return false;
    if (filterCategory !== "all" && pb.category !== filterCategory) return false;
    return true;
  });

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Playbook Management
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SOAR // PLAYBOOK CONFIGURATION & MONITORING
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setShowImportExport(!showImportExport)}
            className="rounded-md border border-gray-700/50 bg-gray-900/50 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 transition-all hover:border-cyan-glow/20 hover:text-cyan-dim"
          >
            IMPORT / EXPORT
          </button>
          <button
            onClick={() => { setShowCreateForm(!showCreateForm); setSelectedPlaybook(null); }}
            className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md"
          >
            + NEW PLAYBOOK
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Import/Export Panel */}
      {showImportExport && (
        <div className="glass-panel border border-cyan-glow/20 p-4">
          <h3 className="mb-3 text-xs font-bold text-cyan-glow">Import / Export YAML</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <textarea
                placeholder="Paste YAML playbook definition here..."
                className="h-32 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs font-mono text-gray-300 outline-none focus:border-cyan-glow/50"
              />
              <button className="mt-2 rounded border border-cyan-glow/20 bg-cyan-glow/10 px-4 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/20">
                IMPORT
              </button>
            </div>
            <div className="rounded border border-gray-800 bg-black/30 p-3">
              <p className="mb-2 text-[9px] uppercase tracking-wider text-gray-500">Export Preview</p>
              <pre className="text-[10px] font-mono text-gray-400">
{`name: Isolate Compromised Host
trigger: alert
category: remediation
steps:
  - name: Receive Alert
    type: trigger
    config: EDR severity >= HIGH
  - name: Validate IOC
    type: action
    config: Check hash against VT`}
              </pre>
              <button className="mt-2 rounded border border-green-500/20 bg-green-500/10 px-4 py-1.5 text-[9px] font-bold uppercase tracking-wider text-green-400 hover:bg-green-500/20">
                DOWNLOAD YAML
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Form */}
      {showCreateForm && (
        <div className="glass-panel border border-cyan-glow/20 p-4">
          <h3 className="mb-3 text-xs font-bold text-cyan-glow">Create New Playbook</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Playbook Name</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="e.g. Ransomware Response" />
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Trigger Type</label>
              <select className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none">
                <option value="alert">Alert</option>
                <option value="scheduled">Scheduled</option>
                <option value="manual">Manual</option>
                <option value="webhook">Webhook</option>
              </select>
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Category</label>
              <select className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none">
                <option value="incident">Incident</option>
                <option value="enrichment">Enrichment</option>
                <option value="remediation">Remediation</option>
                <option value="notification">Notification</option>
              </select>
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Description</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="Brief description..." />
            </div>
          </div>
          <div className="mt-4 flex gap-2">
            <button className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/20">
              CREATE
            </button>
            <button onClick={() => setShowCreateForm(false)} className="rounded border border-gray-700 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-500 hover:text-gray-300">
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="glass-panel flex items-center gap-4 p-3">
        <span className="text-[9px] uppercase tracking-wider text-gray-500">Filters:</span>
        <select
          value={filterTrigger}
          onChange={(e) => setFilterTrigger(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Triggers</option>
          <option value="alert">Alert</option>
          <option value="scheduled">Scheduled</option>
          <option value="manual">Manual</option>
          <option value="webhook">Webhook</option>
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="disabled">Disabled</option>
          <option value="draft">Draft</option>
        </select>
        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Categories</option>
          <option value="incident">Incident</option>
          <option value="enrichment">Enrichment</option>
          <option value="remediation">Remediation</option>
          <option value="notification">Notification</option>
        </select>
        <span className="ml-auto text-[10px] text-gray-500">{filtered.length} playbooks</span>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Playbook List */}
        <div className="col-span-1 space-y-2">
          {filtered.map((pb) => (
            <button
              key={pb.id}
              onClick={() => { setSelectedPlaybook(pb); setShowCreateForm(false); }}
              className={`glass-panel w-full border p-4 text-left transition-all ${
                selectedPlaybook?.id === pb.id
                  ? "border-cyan-glow/30 shadow-cyan-sm"
                  : "border-cyan-glow/10 hover:border-cyan-glow/20"
              }`}
            >
              <div className="mb-2 flex items-center justify-between">
                <Badge text={pb.trigger} cls={TRIGGER_COLORS[pb.trigger]} />
                <Badge text={pb.status} cls={STATUS_BADGE[pb.status]} />
              </div>
              <h3 className="text-xs font-bold text-gray-200">{pb.name}</h3>
              <p className="mt-1 text-[10px] text-gray-500">{pb.description}</p>
              <div className="mt-2 flex items-center justify-between text-[9px] text-gray-600">
                <span>{pb.runCount} runs</span>
                <span>{pb.successRate}% success</span>
              </div>
            </button>
          ))}
        </div>

        {/* Detail View */}
        <div className="col-span-2">
          {selectedPlaybook ? (
            <div className="space-y-4">
              {/* Playbook Info */}
              <div className="glass-panel border border-cyan-glow/20 p-5">
                <div className="mb-4 flex items-center justify-between">
                  <div>
                    <h2 className="text-sm font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>{selectedPlaybook.name}</h2>
                    <p className="mt-1 text-[10px] text-gray-400">{selectedPlaybook.description}</p>
                  </div>
                  <div className="flex gap-2">
                    <button className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15">
                      EDIT
                    </button>
                    <button className="rounded border border-blue-500/20 bg-blue-500/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-blue-400 hover:bg-blue-500/15">
                      DUPLICATE
                    </button>
                    <button className={`rounded border px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider ${
                      selectedPlaybook.status === "active"
                        ? "border-red-500/20 text-red-400 hover:bg-red-500/10"
                        : "border-green-500/20 text-green-400 hover:bg-green-500/10"
                    }`}>
                      {selectedPlaybook.status === "active" ? "DISABLE" : "ENABLE"}
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-4 gap-3">
                  <div className="rounded border border-gray-800 bg-black/30 p-3">
                    <p className="text-[9px] uppercase tracking-wider text-gray-500">Trigger</p>
                    <p className="mt-1 text-xs font-bold text-gray-200 capitalize">{selectedPlaybook.trigger}</p>
                  </div>
                  <div className="rounded border border-gray-800 bg-black/30 p-3">
                    <p className="text-[9px] uppercase tracking-wider text-gray-500">Category</p>
                    <p className="mt-1 text-xs font-bold text-gray-200 capitalize">{selectedPlaybook.category}</p>
                  </div>
                  <div className="rounded border border-gray-800 bg-black/30 p-3">
                    <p className="text-[9px] uppercase tracking-wider text-gray-500">Total Runs</p>
                    <p className="mt-1 text-xs font-bold text-cyan-glow">{selectedPlaybook.runCount}</p>
                  </div>
                  <div className="rounded border border-gray-800 bg-black/30 p-3">
                    <p className="text-[9px] uppercase tracking-wider text-gray-500">Success Rate</p>
                    <p className="mt-1 text-xs font-bold text-green-400">{selectedPlaybook.successRate}%</p>
                  </div>
                </div>
              </div>

              {/* Step Visualization (Flowchart) */}
              <div className="glass-panel border border-cyan-glow/20 p-5">
                <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Step Flowchart</h3>
                <div className="flex flex-col items-center">
                  {selectedPlaybook.steps.map((step, i) => {
                    const tc = STEP_TYPE_COLORS[step.type] || STEP_TYPE_COLORS.action;
                    return (
                      <div key={step.id} className="flex flex-col items-center">
                        {i > 0 && (
                          <div className="my-1 h-6 w-px bg-cyan-glow/20" />
                        )}
                        <div className={`flex w-80 items-center gap-3 rounded-lg border p-3 ${tc.border} ${tc.bg}`}>
                          <div className={`h-3 w-3 rounded-full ${tc.dot}`} />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-bold text-gray-200">{step.name}</span>
                              <Badge text={step.type} cls={`${tc.bg} text-gray-400 ${tc.border}`} />
                            </div>
                            <p className="text-[9px] text-gray-500">{step.config}</p>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Execution History */}
              <div className="glass-panel border border-cyan-glow/20 p-5">
                <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Execution History</h3>
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-800">
                      <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Timestamp</th>
                      <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                      <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
                      <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Trigger</th>
                    </tr>
                  </thead>
                  <tbody>
                    {EXECUTION_HISTORY.map((log) => (
                      <tr key={log.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                        <td className="px-3 py-2 text-[10px] font-mono text-gray-400">{log.timestamp}</td>
                        <td className="px-3 py-2">
                          <Badge
                            text={log.status}
                            cls={log.status === "success" ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-red-500/15 text-red-400 border-red-500/30"}
                          />
                        </td>
                        <td className="px-3 py-2 text-[10px] font-mono text-gray-400">{log.duration}</td>
                        <td className="px-3 py-2 text-[10px] text-gray-500">{log.trigger}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="glass-panel flex h-96 items-center justify-center border border-cyan-glow/10">
              <div className="text-center">
                <svg className="mx-auto h-12 w-12 text-cyan-glow/20" fill="none" viewBox="0 0 24 24" strokeWidth={1} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
                </svg>
                <p className="mt-3 text-[10px] uppercase tracking-wider text-gray-600">Select a playbook to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
