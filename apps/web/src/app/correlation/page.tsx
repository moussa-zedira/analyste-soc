"use client";

import { useState } from "react";
import { PageTransition, StaggerItem } from "@/components/PageTransition";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  eventPatterns: string[];
  timeWindow: number;
  groupBy: string;
  threshold: number;
  enabled: boolean;
  matchCount: number;
  lastTriggered: string | null;
}

interface CorrelationMatch {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  events: number;
  groupValue: string;
  timestamp: string;
  mitreTactic: string;
}

interface KillChainStage {
  id: string;
  name: string;
  mitreId: string;
  activeDetections: number;
  recentMatches: number;
  status: "active" | "idle" | "alert";
}

/* ------------------------------------------------------------------ */
/*  Mock data                                                          */
/* ------------------------------------------------------------------ */

const MOCK_RULES: CorrelationRule[] = [
  { id: "cr-1", name: "Brute Force then Login", description: "Multiple auth failures followed by success from same IP", eventPatterns: ["auth.fail >= 5", "auth.success == 1"], timeWindow: 300, groupBy: "src_ip", threshold: 5, enabled: true, matchCount: 42, lastTriggered: "2026-03-29T10:02:00Z" },
  { id: "cr-2", name: "Lateral Movement Chain", description: "Internal scan followed by remote execution attempt", eventPatterns: ["net.scan", "exec.remote"], timeWindow: 600, groupBy: "src_ip", threshold: 1, enabled: true, matchCount: 8, lastTriggered: "2026-03-29T09:30:00Z" },
  { id: "cr-3", name: "Data Exfiltration Pattern", description: "Large outbound transfer after privilege escalation", eventPatterns: ["privesc.*", "net.transfer > 100MB"], timeWindow: 1800, groupBy: "username", threshold: 1, enabled: true, matchCount: 3, lastTriggered: "2026-03-28T22:15:00Z" },
  { id: "cr-4", name: "Credential Dumping", description: "Process access to LSASS followed by network auth", eventPatterns: ["proc.access target=lsass", "auth.ntlm"], timeWindow: 120, groupBy: "hostname", threshold: 1, enabled: false, matchCount: 0, lastTriggered: null },
  { id: "cr-5", name: "Persistence Install", description: "Registry modification in Run keys or scheduled task creation", eventPatterns: ["reg.modify path=*\\Run*", "schtask.create"], timeWindow: 60, groupBy: "hostname", threshold: 1, enabled: true, matchCount: 15, lastTriggered: "2026-03-29T07:45:00Z" },
];

const MOCK_MATCHES: CorrelationMatch[] = [
  { id: "m-1", ruleId: "cr-1", ruleName: "Brute Force then Login", severity: "high", events: 12, groupValue: "192.168.1.45", timestamp: "2026-03-29T10:02:00Z", mitreTactic: "Initial Access" },
  { id: "m-2", ruleId: "cr-2", ruleName: "Lateral Movement Chain", severity: "critical", events: 4, groupValue: "10.0.0.22", timestamp: "2026-03-29T09:30:00Z", mitreTactic: "Lateral Movement" },
  { id: "m-3", ruleId: "cr-5", ruleName: "Persistence Install", severity: "high", events: 2, groupValue: "WS-DEV-042", timestamp: "2026-03-29T07:45:00Z", mitreTactic: "Persistence" },
  { id: "m-4", ruleId: "cr-3", ruleName: "Data Exfiltration Pattern", severity: "critical", events: 3, groupValue: "admin.svc", timestamp: "2026-03-28T22:15:00Z", mitreTactic: "Exfiltration" },
  { id: "m-5", ruleId: "cr-1", ruleName: "Brute Force then Login", severity: "medium", events: 7, groupValue: "172.16.0.100", timestamp: "2026-03-28T18:00:00Z", mitreTactic: "Initial Access" },
];

const KILL_CHAIN: KillChainStage[] = [
  { id: "kc-1", name: "Reconnaissance", mitreId: "TA0043", activeDetections: 3, recentMatches: 12, status: "active" },
  { id: "kc-2", name: "Resource Development", mitreId: "TA0042", activeDetections: 1, recentMatches: 0, status: "idle" },
  { id: "kc-3", name: "Initial Access", mitreId: "TA0001", activeDetections: 4, recentMatches: 47, status: "alert" },
  { id: "kc-4", name: "Execution", mitreId: "TA0002", activeDetections: 5, recentMatches: 8, status: "active" },
  { id: "kc-5", name: "Persistence", mitreId: "TA0003", activeDetections: 3, recentMatches: 15, status: "alert" },
  { id: "kc-6", name: "Privilege Escalation", mitreId: "TA0004", activeDetections: 4, recentMatches: 5, status: "active" },
  { id: "kc-7", name: "Defense Evasion", mitreId: "TA0005", activeDetections: 6, recentMatches: 3, status: "active" },
  { id: "kc-8", name: "Credential Access", mitreId: "TA0006", activeDetections: 2, recentMatches: 0, status: "idle" },
  { id: "kc-9", name: "Discovery", mitreId: "TA0007", activeDetections: 3, recentMatches: 20, status: "active" },
  { id: "kc-10", name: "Lateral Movement", mitreId: "TA0008", activeDetections: 2, recentMatches: 8, status: "alert" },
  { id: "kc-11", name: "Collection", mitreId: "TA0009", activeDetections: 1, recentMatches: 2, status: "active" },
  { id: "kc-12", name: "C2", mitreId: "TA0011", activeDetections: 3, recentMatches: 6, status: "active" },
  { id: "kc-13", name: "Exfiltration", mitreId: "TA0010", activeDetections: 2, recentMatches: 3, status: "alert" },
  { id: "kc-14", name: "Impact", mitreId: "TA0040", activeDetections: 1, recentMatches: 0, status: "idle" },
];

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function CorrelationPage() {
  const [activeTab, setActiveTab] = useState<"rules" | "matches" | "killchain" | "builder">("rules");
  const [rules, setRules] = useState<CorrelationRule[]>(MOCK_RULES);
  const [matches] = useState<CorrelationMatch[]>(MOCK_MATCHES);

  // Rule builder state
  const [builderName, setBuilderName] = useState("");
  const [builderDesc, setBuilderDesc] = useState("");
  const [builderPatterns, setBuilderPatterns] = useState<string[]>([""]);
  const [builderWindow, setBuilderWindow] = useState(300);
  const [builderGroupBy, setBuilderGroupBy] = useState("src_ip");
  const [builderThreshold, setBuilderThreshold] = useState(1);

  const handleToggle = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleAddPattern = () => setBuilderPatterns((prev) => [...prev, ""]);
  const handlePatternChange = (idx: number, val: string) => {
    setBuilderPatterns((prev) => prev.map((p, i) => (i === idx ? val : p)));
  };
  const handleRemovePattern = (idx: number) => {
    setBuilderPatterns((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleCreateRule = () => {
    if (!builderName.trim()) return;
    const newRule: CorrelationRule = {
      id: `cr-${Date.now()}`,
      name: builderName,
      description: builderDesc,
      eventPatterns: builderPatterns.filter((p) => p.trim()),
      timeWindow: builderWindow,
      groupBy: builderGroupBy,
      threshold: builderThreshold,
      enabled: true,
      matchCount: 0,
      lastTriggered: null,
    };
    setRules((prev) => [...prev, newRule]);
    setBuilderName("");
    setBuilderDesc("");
    setBuilderPatterns([""]);
    setBuilderWindow(300);
    setBuilderGroupBy("src_ip");
    setBuilderThreshold(1);
    setActiveTab("rules");
  };

  const sevColor = (s: string) => {
    if (s === "critical") return "bg-red-500/15 text-red-400";
    if (s === "high") return "bg-orange-500/15 text-orange-400";
    if (s === "medium") return "bg-yellow-500/15 text-yellow-400";
    return "bg-blue-500/15 text-blue-400";
  };

  const stageColor = (s: string) => {
    if (s === "alert") return "border-red-500/40 bg-red-500/10";
    if (s === "active") return "border-cyan-glow/30 bg-cyan-glow/5";
    return "border-gray-700 bg-gray-800/30";
  };

  // Stats
  const totalMatches = rules.reduce((a, r) => a + r.matchCount, 0);
  const activeRules = rules.filter((r) => r.enabled).length;
  const topRule = [...rules].sort((a, b) => b.matchCount - a.matchCount)[0];

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Correlation Engine
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            EVENT CORRELATION // ATTACK CHAINS // KILL CHAIN TRACKER
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Stats bar */}
      <StaggerItem>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{activeRules}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">ACTIVE RULES</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{totalMatches}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOTAL MATCHES</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{matches.length}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">RECENT MATCHES</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-lg font-bold text-cyan-glow font-mono truncate">{topRule?.name || "-"}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOP TRIGGERED</p>
          </div>
        </div>
      </StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <div className="flex gap-2">
          {(["rules", "matches", "killchain", "builder"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700 text-gray-500 hover:border-gray-600"
              }`}
            >
              {tab === "rules" ? "RULES" : tab === "matches" ? "MATCHES" : tab === "killchain" ? "KILL CHAIN" : "RULE BUILDER"}
            </button>
          ))}
        </div>
      </StaggerItem>

      {/* ---- RULES TAB ---- */}
      {activeTab === "rules" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">RULE</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">PATTERNS</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">WINDOW</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">MATCHES</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">LAST TRIGGERED</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="px-4 py-3">
                      <p className="text-sm text-gray-200">{rule.name}</p>
                      <p className="text-[10px] text-gray-500 mt-0.5">{rule.description}</p>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-0.5">
                        {rule.eventPatterns.map((p, i) => (
                          <code key={i} className="text-[10px] text-cyan-glow/70 font-mono">{p}</code>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400 font-mono">{rule.timeWindow}s</td>
                    <td className="px-4 py-3 text-sm text-cyan-glow font-mono font-bold">{rule.matchCount}</td>
                    <td className="px-4 py-3 text-[10px] text-gray-400 font-mono">
                      {rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleString() : "-"}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleToggle(rule.id)}
                        className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${
                          rule.enabled
                            ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                            : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"
                        }`}
                      >
                        {rule.enabled ? "ACTIVE" : "INACTIVE"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </StaggerItem>
      )}

      {/* ---- MATCHES TAB ---- */}
      {activeTab === "matches" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">TIME</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">RULE</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">SEVERITY</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">GROUP</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">EVENTS</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">MITRE</th>
                </tr>
              </thead>
              <tbody>
                {matches.map((m) => (
                  <tr key={m.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="px-4 py-3 text-[10px] text-gray-400 font-mono whitespace-nowrap">
                      {new Date(m.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-200">{m.ruleName}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${sevColor(m.severity)}`}>
                        {m.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-cyan-glow font-mono">{m.groupValue}</td>
                    <td className="px-4 py-3 text-sm text-gray-300 font-mono">{m.events}</td>
                    <td className="px-4 py-3">
                      <span className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-2 py-0.5 text-[10px] text-cyan-glow">
                        {m.mitreTactic}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </StaggerItem>
      )}

      {/* ---- KILL CHAIN TAB ---- */}
      {activeTab === "killchain" && (
        <StaggerItem>
          <div className="space-y-3">
            {/* Attack chain visualization */}
            <div className="glass-panel p-4">
              <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-4">ATTACK CHAIN PROGRESSION</h3>
              <div className="flex items-center overflow-x-auto pb-2">
                {KILL_CHAIN.map((stage, i) => (
                  <div key={stage.id} className="flex items-center">
                    <div className={`rounded-lg border p-3 min-w-[120px] text-center ${stageColor(stage.status)}`}>
                      <p className="text-[10px] font-bold text-gray-300">{stage.name}</p>
                      <p className="text-[9px] text-gray-500 font-mono">{stage.mitreId}</p>
                      <div className="mt-2 flex justify-center gap-2">
                        <span className="text-[10px] text-cyan-glow font-mono">{stage.activeDetections}D</span>
                        <span className={`text-[10px] font-mono ${stage.recentMatches > 0 ? "text-orange-400" : "text-gray-600"}`}>
                          {stage.recentMatches}M
                        </span>
                      </div>
                    </div>
                    {i < KILL_CHAIN.length - 1 && (
                      <div className="mx-1 text-gray-600 text-xs">&rarr;</div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Stage details grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {KILL_CHAIN.filter((s) => s.status !== "idle").map((stage) => (
                <div key={stage.id} className={`glass-panel p-4 ${stage.status === "alert" ? "border-red-500/20" : ""}`}>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-bold text-gray-200">{stage.name}</p>
                    <span className={`rounded-full px-2 py-0.5 text-[9px] font-bold ${
                      stage.status === "alert" ? "bg-red-500/15 text-red-400" : "bg-cyan-glow/10 text-cyan-glow"
                    }`}>
                      {stage.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[10px] text-gray-500 font-mono">{stage.mitreId}</p>
                  <div className="mt-2 flex gap-4">
                    <div>
                      <p className="text-lg font-bold text-cyan-glow font-mono">{stage.activeDetections}</p>
                      <p className="text-[9px] text-gray-500">Detections</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold text-orange-400 font-mono">{stage.recentMatches}</p>
                      <p className="text-[9px] text-gray-500">Matches</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </StaggerItem>
      )}

      {/* ---- RULE BUILDER TAB ---- */}
      {activeTab === "builder" && (
        <StaggerItem>
          <div className="glass-panel p-6 space-y-4">
            <h3 className="text-[10px] font-bold tracking-widest text-gray-500">CREATE CORRELATION RULE</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">RULE NAME</label>
                <input
                  type="text"
                  value={builderName}
                  onChange={(e) => setBuilderName(e.target.value)}
                  placeholder="e.g. Brute Force then Lateral Move"
                  className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">GROUP BY</label>
                <select
                  value={builderGroupBy}
                  onChange={(e) => setBuilderGroupBy(e.target.value)}
                  className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none"
                >
                  <option value="src_ip">Source IP</option>
                  <option value="dst_ip">Destination IP</option>
                  <option value="username">Username</option>
                  <option value="hostname">Hostname</option>
                </select>
              </div>
            </div>

            <div>
              <label className="text-[10px] tracking-widest text-gray-500 block mb-1">DESCRIPTION</label>
              <input
                type="text"
                value={builderDesc}
                onChange={(e) => setBuilderDesc(e.target.value)}
                placeholder="Describe what this rule detects"
                className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
              />
            </div>

            {/* Event patterns */}
            <div>
              <label className="text-[10px] tracking-widest text-gray-500 block mb-1">EVENT PATTERNS</label>
              <div className="space-y-2">
                {builderPatterns.map((p, i) => (
                  <div key={i} className="flex gap-2">
                    <input
                      type="text"
                      value={p}
                      onChange={(e) => handlePatternChange(i, e.target.value)}
                      placeholder="e.g. auth.fail >= 5"
                      className="flex-1 rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
                    />
                    {builderPatterns.length > 1 && (
                      <button
                        onClick={() => handleRemovePattern(i)}
                        className="text-red-400/50 hover:text-red-400 text-xs px-2"
                      >
                        REMOVE
                      </button>
                    )}
                  </div>
                ))}
                <button
                  onClick={handleAddPattern}
                  className="text-[10px] text-cyan-glow hover:text-cyan-glow/80 transition-colors"
                >
                  + ADD PATTERN
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">TIME WINDOW (seconds)</label>
                <input
                  type="number"
                  value={builderWindow}
                  onChange={(e) => setBuilderWindow(Number(e.target.value))}
                  className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none"
                />
              </div>
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">THRESHOLD</label>
                <input
                  type="number"
                  value={builderThreshold}
                  onChange={(e) => setBuilderThreshold(Number(e.target.value))}
                  className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none"
                />
              </div>
            </div>

            <button
              onClick={handleCreateRule}
              disabled={!builderName.trim() || builderPatterns.every((p) => !p.trim())}
              className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50"
            >
              CREATE RULE
            </button>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
