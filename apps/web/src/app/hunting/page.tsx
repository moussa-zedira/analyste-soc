"use client";

import { useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface QueryCondition {
  id: number;
  field: string;
  operator: string;
  value: string;
}

interface SavedQuery {
  id: string;
  name: string;
  description: string;
  conditions: QueryCondition[];
  createdAt: string;
  runCount: number;
}

interface HuntResult {
  id: string;
  ts: string;
  source: string;
  eventType: string;
  severity: "critical" | "high" | "medium" | "low";
  srcIp: string;
  dstIp: string;
  message: string;
  tags: string[];
}

interface Hypothesis {
  id: string;
  name: string;
  technique: string;
  description: string;
  category: string;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const FIELDS = [
  "src_ip", "dst_ip", "username", "event_type", "severity", "source",
  "message", "port", "protocol", "user_agent", "domain", "hash", "file_path",
];
const OPERATORS = ["equals", "contains", "starts_with", "ends_with", "regex", "not_equals", "greater_than", "less_than", "in"];

const SAVED_QUERIES: SavedQuery[] = [
  { id: "sq-1", name: "Lateral Movement Detection", description: "Detect potential lateral movement via SMB/RDP", conditions: [{ id: 1, field: "event_type", operator: "contains", value: "smb" }], createdAt: "2026-03-20", runCount: 45 },
  { id: "sq-2", name: "Suspicious PowerShell", description: "Hunt for encoded PowerShell execution", conditions: [{ id: 1, field: "message", operator: "contains", value: "powershell" }], createdAt: "2026-03-18", runCount: 32 },
  { id: "sq-3", name: "Data Exfiltration Indicators", description: "Large outbound transfers to rare destinations", conditions: [{ id: 1, field: "event_type", operator: "equals", value: "network.transfer" }], createdAt: "2026-03-15", runCount: 18 },
  { id: "sq-4", name: "Brute Force Patterns", description: "Multiple failed logins from same source", conditions: [{ id: 1, field: "event_type", operator: "equals", value: "auth.fail" }], createdAt: "2026-03-10", runCount: 67 },
  { id: "sq-5", name: "C2 Beaconing", description: "Periodic connections to external IPs", conditions: [{ id: 1, field: "event_type", operator: "contains", value: "beacon" }], createdAt: "2026-03-08", runCount: 12 },
];

const MOCK_RESULTS: HuntResult[] = [
  { id: "hr-1", ts: "2026-03-29 09:42:15", source: "EDR", eventType: "process.exec", severity: "high", srcIp: "10.0.2.15", dstIp: "185.220.101.42", message: "powershell.exe -enc SQBFAFgA...", tags: ["T1059.001"] },
  { id: "hr-2", ts: "2026-03-29 09:40:03", source: "Firewall", eventType: "network.connection", severity: "medium", srcIp: "10.0.2.15", dstIp: "185.220.101.42", message: "Outbound connection to known Tor exit node", tags: ["T1090"] },
  { id: "hr-3", ts: "2026-03-29 09:38:22", source: "SIEM", eventType: "auth.fail", severity: "high", srcIp: "192.168.1.100", dstIp: "10.0.1.5", message: "50 failed RDP login attempts in 2 minutes", tags: ["T1110"] },
  { id: "hr-4", ts: "2026-03-29 09:35:10", source: "EDR", eventType: "file.create", severity: "critical", srcIp: "10.0.3.22", dstIp: "-", message: "Suspicious DLL dropped in C:\\Windows\\Temp\\", tags: ["T1055"] },
  { id: "hr-5", ts: "2026-03-29 09:32:45", source: "Proxy", eventType: "http.request", severity: "medium", srcIp: "10.0.2.15", dstIp: "45.33.32.156", message: "Repeated POST to /api/upload every 60s (beaconing)", tags: ["T1071.001"] },
  { id: "hr-6", ts: "2026-03-29 09:30:00", source: "DNS", eventType: "dns.query", severity: "high", srcIp: "10.0.4.8", dstIp: "-", message: "DNS query for long subdomain (possible DNS tunneling)", tags: ["T1071.004"] },
  { id: "hr-7", ts: "2026-03-29 09:28:11", source: "EDR", eventType: "registry.modify", severity: "high", srcIp: "10.0.2.15", dstIp: "-", message: "Run key added: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", tags: ["T1547.001"] },
  { id: "hr-8", ts: "2026-03-29 09:25:33", source: "Firewall", eventType: "network.scan", severity: "medium", srcIp: "10.0.2.15", dstIp: "10.0.0.0/24", message: "Port scan detected: 445,3389,22,80 across subnet", tags: ["T1046"] },
];

const HISTOGRAM_DATA = [
  { hour: "00:00", count: 12 }, { hour: "01:00", count: 8 }, { hour: "02:00", count: 5 },
  { hour: "03:00", count: 3 }, { hour: "04:00", count: 4 }, { hour: "05:00", count: 6 },
  { hour: "06:00", count: 15 }, { hour: "07:00", count: 22 }, { hour: "08:00", count: 35 },
  { hour: "09:00", count: 48 }, { hour: "10:00", count: 42 }, { hour: "11:00", count: 38 },
  { hour: "12:00", count: 30 }, { hour: "13:00", count: 25 }, { hour: "14:00", count: 28 },
  { hour: "15:00", count: 32 }, { hour: "16:00", count: 40 }, { hour: "17:00", count: 45 },
  { hour: "18:00", count: 38 }, { hour: "19:00", count: 25 }, { hour: "20:00", count: 18 },
  { hour: "21:00", count: 14 }, { hour: "22:00", count: 10 }, { hour: "23:00", count: 8 },
];

const HYPOTHESES: Hypothesis[] = [
  { id: "h1", name: "Initial Access via Phishing", technique: "T1566", description: "Hunt for phishing email indicators and suspicious attachments", category: "Initial Access" },
  { id: "h2", name: "PowerShell Abuse", technique: "T1059.001", description: "Detect encoded/obfuscated PowerShell commands", category: "Execution" },
  { id: "h3", name: "Credential Dumping", technique: "T1003", description: "Hunt for LSASS access or mimikatz-like behavior", category: "Credential Access" },
  { id: "h4", name: "Lateral Movement via SMB", technique: "T1021.002", description: "Detect unusual SMB connections between workstations", category: "Lateral Movement" },
  { id: "h5", name: "DNS Tunneling", technique: "T1071.004", description: "Hunt for anomalous DNS query patterns", category: "Command and Control" },
  { id: "h6", name: "Data Staging", technique: "T1074", description: "Detect file collection and staging for exfiltration", category: "Collection" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function HuntingPage() {
  const [conditions, setConditions] = useState<QueryCondition[]>([
    { id: 1, field: "event_type", operator: "contains", value: "" },
  ]);
  const [activeTab, setActiveTab] = useState<"results" | "saved" | "hypotheses">("results");
  const [showResults, setShowResults] = useState(true);
  const [annotations, setAnnotations] = useState<Record<string, string>>({});
  const maxCount = Math.max(...HISTOGRAM_DATA.map((d) => d.count));

  const addCondition = useCallback(() => {
    setConditions((prev) => [...prev, { id: Date.now(), field: "src_ip", operator: "equals", value: "" }]);
  }, []);

  const removeCondition = useCallback((id: number) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  }, []);

  const updateCondition = useCallback((id: number, key: keyof QueryCondition, value: string) => {
    setConditions((prev) => prev.map((c) => c.id === id ? { ...c, [key]: value } : c));
  }, []);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Threat Hunting
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            PROACTIVE THREAT DETECTION // HYPOTHESIS-DRIVEN INVESTIGATION
          </p>
        </div>
        <div className="flex gap-2">
          {(["results", "saved", "hypotheses"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold uppercase tracking-wider transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700/50 bg-gray-900/50 text-gray-500 hover:border-cyan-glow/20 hover:text-cyan-dim"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      <div className="cyan-line" />

      {/* Query Builder */}
      <div className="glass-panel border border-cyan-glow/20 p-4">
        <h3 className="mb-3 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Query Builder</h3>
        <div className="space-y-2">
          {conditions.map((cond) => (
            <div key={cond.id} className="flex items-center gap-2">
              <select
                value={cond.field}
                onChange={(e) => updateCondition(cond.id, "field", e.target.value)}
                className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-2 text-[10px] text-gray-300 outline-none"
              >
                {FIELDS.map((f) => <option key={f} value={f}>{f}</option>)}
              </select>
              <select
                value={cond.operator}
                onChange={(e) => updateCondition(cond.id, "operator", e.target.value)}
                className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-2 text-[10px] text-gray-300 outline-none"
              >
                {OPERATORS.map((op) => <option key={op} value={op}>{op}</option>)}
              </select>
              <input
                value={cond.value}
                onChange={(e) => updateCondition(cond.id, "value", e.target.value)}
                placeholder="Value..."
                className="flex-1 rounded border border-cyan-glow/15 bg-black/40 px-3 py-2 text-[10px] font-mono text-gray-200 outline-none focus:border-cyan-glow/40"
              />
              <button
                onClick={() => removeCondition(cond.id)}
                className="rounded border border-gray-700 px-2 py-2 text-[10px] text-gray-600 hover:border-red-500/30 hover:text-red-400"
              >
                X
              </button>
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center gap-2">
          <button
            onClick={addCondition}
            className="rounded border border-dashed border-cyan-glow/20 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow/50 hover:border-cyan-glow/40 hover:text-cyan-glow"
          >
            + ADD CONDITION
          </button>
          <button className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-1.5 text-[10px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/20">
            RUN HUNT
          </button>
          <button className="rounded border border-green-500/20 bg-green-500/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-green-400 hover:bg-green-500/15">
            SAVE QUERY
          </button>
          <button className="rounded border border-yellow-500/20 bg-yellow-500/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-yellow-400 hover:bg-yellow-500/15">
            EXTRACT IOCs
          </button>
          <button className="rounded border border-red-500/20 bg-red-500/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-red-400 hover:bg-red-500/15">
            CREATE INCIDENT
          </button>
        </div>
      </div>

      {activeTab === "results" && (
        <>
          {/* Histogram Timeline */}
          <div className="glass-panel border border-cyan-glow/10 p-4">
            <h3 className="mb-3 text-xs font-bold text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>Event Timeline (24h)</h3>
            <div className="flex h-32 items-end gap-1">
              {HISTOGRAM_DATA.map((d) => (
                <div key={d.hour} className="group relative flex flex-1 flex-col items-center">
                  <div className="absolute -top-6 hidden rounded bg-black/80 px-2 py-1 text-[8px] text-cyan-glow group-hover:block">
                    {d.count} events
                  </div>
                  <div
                    className="w-full rounded-t bg-cyan-glow/30 transition-all hover:bg-cyan-glow/60"
                    style={{ height: `${(d.count / maxCount) * 100}%` }}
                  />
                  <span className="mt-1 text-[7px] text-gray-600">{d.hour.split(":")[0]}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Results Table */}
          <div className="glass-panel overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Timestamp</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Source</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Type</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Severity</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Src IP</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Dst IP</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Message</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">MITRE</th>
                  <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Tag</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_RESULTS.map((r) => (
                  <tr key={r.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{r.ts}</td>
                    <td className="px-4 py-3 text-[10px] text-gray-300">{r.source}</td>
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{r.eventType}</td>
                    <td className="px-4 py-3"><Badge text={r.severity} cls={SEV_COLORS[r.severity]} /></td>
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{r.srcIp}</td>
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{r.dstIp}</td>
                    <td className="max-w-xs truncate px-4 py-3 text-[10px] text-gray-400">{r.message}</td>
                    <td className="px-4 py-3">
                      {r.tags.map((t) => (
                        <Badge key={t} text={t} cls="bg-purple-500/15 text-purple-400 border-purple-500/30" />
                      ))}
                    </td>
                    <td className="px-4 py-3">
                      <input
                        value={annotations[r.id] || ""}
                        onChange={(e) => setAnnotations((prev) => ({ ...prev, [r.id]: e.target.value }))}
                        placeholder="Tag..."
                        className="w-20 rounded border border-gray-800 bg-black/30 px-2 py-1 text-[9px] text-gray-400 outline-none focus:border-cyan-glow/30"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === "saved" && (
        <div className="grid grid-cols-2 gap-4">
          {SAVED_QUERIES.map((sq) => (
            <div key={sq.id} className="glass-panel border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/30">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-gray-200">{sq.name}</h3>
                <span className="text-[9px] font-mono text-gray-600">{sq.runCount} runs</span>
              </div>
              <p className="mt-1 text-[10px] text-gray-500">{sq.description}</p>
              <div className="mt-3 flex items-center gap-2">
                <button className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15">
                  RUN
                </button>
                <button className="rounded border border-gray-700 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-gray-500 hover:text-gray-300">
                  EDIT
                </button>
                <button className="rounded border border-red-500/20 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-red-400/50 hover:text-red-400">
                  DELETE
                </button>
                <span className="ml-auto text-[9px] text-gray-600">Created: {sq.createdAt}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === "hypotheses" && (
        <div className="grid grid-cols-3 gap-4">
          {HYPOTHESES.map((h) => (
            <div key={h.id} className="glass-panel border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/30">
              <div className="mb-2 flex items-center gap-2">
                <Badge text={h.technique} cls="bg-purple-500/15 text-purple-400 border-purple-500/30" />
                <Badge text={h.category} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
              </div>
              <h3 className="text-xs font-bold text-gray-200">{h.name}</h3>
              <p className="mt-1 text-[10px] text-gray-500">{h.description}</p>
              <button className="mt-3 w-full rounded border border-cyan-glow/20 bg-cyan-glow/5 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15">
                START HUNT
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
