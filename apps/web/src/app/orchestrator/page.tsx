"use client";

import { useState, useCallback, useEffect } from "react";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface OrcProfile {
  id: string;
  name: string;
  description: string;
  estimatedTime: string;
  stages: string[];
  intensity: 0 | 1 | 2 | 3 | 4 | 5;
}

interface ActiveOrchestration {
  id: string;
  target: string;
  profile: string;
  currentPhase: number;
  totalPhases: number;
  currentAction: string;
  findings: { critical: number; high: number; medium: number; low: number };
  elapsed: string;
  status: "running" | "paused" | "completed" | "failed";
}

interface HistoryEntry {
  id: string;
  date: string;
  target: string;
  profile: string;
  duration: string;
  findings: { critical: number; high: number; medium: number; low: number };
  status: "completed" | "failed" | "cancelled";
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------

const PROFILES: OrcProfile[] = [
  { id: "quick_recon", name: "Quick Recon", description: "Fast surface-level reconnaissance. Port scan, service detection, basic enumeration.", estimatedTime: "5-10 min", stages: ["Port Scan", "Service ID", "Banner Grab"], intensity: 1 },
  { id: "web_full", name: "Web Full", description: "Complete web application audit. Crawling, form analysis, injection testing, auth bypass.", estimatedTime: "30-60 min", stages: ["Crawl", "Form Analysis", "SQLi", "XSS", "SSRF", "Auth Test"], intensity: 3 },
  { id: "network_full", name: "Network Full", description: "Full network penetration test. Port scan, service exploitation, lateral movement.", estimatedTime: "1-2 hours", stages: ["Port Scan", "Vuln Scan", "Exploit", "Privesc", "Lateral"], intensity: 4 },
  { id: "stealth", name: "Stealth", description: "Low-and-slow approach to avoid detection. Rate limiting, evasion techniques, minimal footprint.", estimatedTime: "2-4 hours", stages: ["Slow Scan", "Evasion", "Passive Recon", "Selective Exploit"], intensity: 2 },
  { id: "full_pentest", name: "Full Pentest", description: "Complete penetration test lifecycle. All phases from recon to reporting.", estimatedTime: "4-8 hours", stages: ["Recon", "Scanning", "Exploitation", "Post-Exploit", "Reporting"], intensity: 5 },
  { id: "red_team", name: "Red Team", description: "Adversary emulation with stealth, persistence, and C2. MITRE ATT&CK mapped.", estimatedTime: "8-24 hours", stages: ["Initial Access", "Execution", "Persistence", "C2", "Exfil"], intensity: 5 },
  { id: "api_audit", name: "API Audit", description: "API-focused testing. Endpoint discovery, auth flaws, rate limiting, injection.", estimatedTime: "20-45 min", stages: ["Discovery", "Auth Test", "Injection", "Rate Limit", "Data Exposure"], intensity: 3 },
  { id: "custom", name: "Custom", description: "Build your own profile. Select individual phases and tools.", estimatedTime: "Varies", stages: [], intensity: 0 },
];

const MOCK_ACTIVE: ActiveOrchestration[] = [
  {
    id: "orc-001",
    target: "192.168.1.0/24",
    profile: "Network Full",
    currentPhase: 3,
    totalPhases: 5,
    currentAction: "Exploiting vsftpd 2.3.4 backdoor on 192.168.1.45:21",
    findings: { critical: 2, high: 5, medium: 12, low: 8 },
    elapsed: "47m 23s",
    status: "running",
  },
  {
    id: "orc-002",
    target: "https://app.example.com",
    profile: "Web Full",
    currentPhase: 4,
    totalPhases: 6,
    currentAction: "Testing SSRF on /api/webhooks endpoint",
    findings: { critical: 1, high: 3, medium: 7, low: 4 },
    elapsed: "32m 10s",
    status: "running",
  },
  {
    id: "orc-003",
    target: "10.0.0.0/16",
    profile: "Stealth",
    currentPhase: 2,
    totalPhases: 4,
    currentAction: "Passive DNS enumeration",
    findings: { critical: 0, high: 1, medium: 3, low: 2 },
    elapsed: "1h 12m",
    status: "paused",
  },
];

const MOCK_HISTORY: HistoryEntry[] = [
  { id: "h1", date: "2026-03-28 14:30", target: "192.168.1.0/24", profile: "Full Pentest", duration: "5h 42m", findings: { critical: 4, high: 12, medium: 28, low: 15 }, status: "completed" },
  { id: "h2", date: "2026-03-27 09:15", target: "https://staging.app.com", profile: "Web Full", duration: "48m", findings: { critical: 1, high: 5, medium: 9, low: 3 }, status: "completed" },
  { id: "h3", date: "2026-03-26 22:00", target: "10.10.0.0/24", profile: "Red Team", duration: "12h 15m", findings: { critical: 7, high: 18, medium: 34, low: 21 }, status: "completed" },
  { id: "h4", date: "2026-03-25 16:45", target: "api.internal.com", profile: "API Audit", duration: "35m", findings: { critical: 0, high: 2, medium: 6, low: 8 }, status: "completed" },
  { id: "h5", date: "2026-03-24 11:00", target: "172.16.0.0/16", profile: "Network Full", duration: "2h 10m", findings: { critical: 3, high: 8, medium: 15, low: 10 }, status: "failed" },
  { id: "h6", date: "2026-03-23 08:30", target: "https://prod.example.com", profile: "Stealth", duration: "3h 55m", findings: { critical: 2, high: 6, medium: 11, low: 7 }, status: "completed" },
];

const AUTHORIZED_TARGETS = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "*.example.com", "*.internal.com", "localhost"];

const CUSTOM_PHASES = [
  "Port Scanning", "Service Detection", "OS Fingerprinting", "Web Crawling", "Form Analysis",
  "SQLi Testing", "XSS Testing", "SSRF Testing", "LFI/RFI Testing", "Auth Bypass",
  "Vulnerability Scanning", "Exploitation", "Privilege Escalation", "Lateral Movement",
  "Persistence", "C2 Setup", "Data Exfiltration", "Reporting",
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function FindingsBadges({ findings }: { findings: { critical: number; high: number; medium: number; low: number } }) {
  return (
    <div className="flex items-center gap-1.5">
      {findings.critical > 0 && <Badge text={`C:${findings.critical}`} cls="bg-red-500/15 text-red-400 border-red-500/30" />}
      {findings.high > 0 && <Badge text={`H:${findings.high}`} cls="bg-orange-500/15 text-orange-400 border-orange-500/30" />}
      {findings.medium > 0 && <Badge text={`M:${findings.medium}`} cls="bg-yellow-500/15 text-yellow-400 border-yellow-500/30" />}
      {findings.low > 0 && <Badge text={`L:${findings.low}`} cls="bg-blue-500/15 text-blue-400 border-blue-500/30" />}
    </div>
  );
}

function IntensityBar({ level }: { level: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1, 2, 3, 4, 5].map((i) => (
        <div
          key={i}
          className={`h-2 w-3 rounded-sm ${
            i <= level
              ? level >= 4
                ? "bg-red-500"
                : level >= 3
                ? "bg-yellow-500"
                : "bg-green-500"
              : "bg-gray-700"
          }`}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function OrchestratorDashboard() {
  const [activeTab, setActiveTab] = useState<"launch" | "active" | "history">("launch");
  const [target, setTarget] = useState("");
  const [selectedProfile, setSelectedProfile] = useState<string | null>(null);
  const [customPhases, setCustomPhases] = useState<string[]>([]);
  const [scopeWarning, setScopeWarning] = useState(false);
  const [orchestrations, setOrchestrations] = useState(MOCK_ACTIVE);
  const [launchPulse, setLaunchPulse] = useState(false);
  const [actionTexts, setActionTexts] = useState<Record<string, string>>({});

  // Simulate live action text updates
  useEffect(() => {
    const actions = [
      "Scanning port 443/tcp...",
      "Testing SQLi on /api/users?id=1",
      "Crawling discovered URLs (147/312)",
      "Checking CVE-2024-1234 applicability",
      "Brute-forcing SSH credentials",
      "Enumerating SMB shares",
      "Testing XSS in search parameter",
      "Attempting privilege escalation via SUID",
      "Extracting database schema",
      "Running Nmap SYN scan on subnet",
    ];
    const interval = setInterval(() => {
      setOrchestrations((prev) =>
        prev.map((o) =>
          o.status === "running"
            ? { ...o, currentAction: actions[Math.floor(Math.random() * actions.length)] }
            : o
        )
      );
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  // Scope check
  useEffect(() => {
    if (!target.trim()) {
      setScopeWarning(false);
      return;
    }
    const inScope = AUTHORIZED_TARGETS.some((t) => {
      if (t.startsWith("*")) return target.endsWith(t.slice(1));
      if (t.includes("/")) {
        const base = t.split("/")[0].split(".").slice(0, 2).join(".");
        return target.startsWith(base);
      }
      return target === t;
    });
    setScopeWarning(!inScope);
  }, [target]);

  const handleLaunch = useCallback(() => {
    if (!target.trim() || !selectedProfile) return;
    setLaunchPulse(true);
    setTimeout(() => setLaunchPulse(false), 1000);
    const profile = PROFILES.find((p) => p.id === selectedProfile);
    const newOrc: ActiveOrchestration = {
      id: `orc-${Date.now()}`,
      target,
      profile: profile?.name || "Custom",
      currentPhase: 1,
      totalPhases: selectedProfile === "custom" ? customPhases.length : (profile?.stages.length || 5),
      currentAction: "Initializing...",
      findings: { critical: 0, high: 0, medium: 0, low: 0 },
      elapsed: "0m 0s",
      status: "running",
    };
    setOrchestrations((prev) => [newOrc, ...prev]);
    setActiveTab("active");
  }, [target, selectedProfile, customPhases]);

  const togglePause = useCallback((id: string) => {
    setOrchestrations((prev) =>
      prev.map((o) =>
        o.id === id
          ? { ...o, status: o.status === "running" ? "paused" as const : "running" as const }
          : o
      )
    );
  }, []);

  const cancelOrchestration = useCallback((id: string) => {
    setOrchestrations((prev) => prev.filter((o) => o.id !== id));
  }, []);

  const totalFindings = MOCK_HISTORY.reduce(
    (acc, h) => acc + h.findings.critical + h.findings.high + h.findings.medium + h.findings.low,
    0
  );

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Pentest Orchestrator
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            MISSION CONTROL // AUTOMATED PENETRATION TESTING
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-md border border-cyan-glow/10 bg-cyan-glow/5 px-3 py-1.5">
            <div className="relative">
              <div className="h-2 w-2 rounded-full bg-green-400" />
              <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-green-400 opacity-40" />
            </div>
            <span className="text-[9px] font-mono tracking-wider text-cyan-glow/60">
              {orchestrations.filter((o) => o.status === "running").length} ACTIVE OPS
            </span>
          </div>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Metrics */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Active Orchestrations" value={String(orchestrations.filter((o) => o.status === "running").length)} sub="Currently running" accent="cyan" />
        <MetricCard label="Total Findings" value={String(totalFindings)} sub="Across all engagements" accent="yellow" />
        <MetricCard label="Critical Vulns" value={String(MOCK_HISTORY.reduce((a, h) => a + h.findings.critical, 0))} sub="Requires immediate action" accent="red" />
        <MetricCard label="Completed Tests" value={String(MOCK_HISTORY.length)} sub="This week" accent="green" />
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(["launch", "active", "history"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold uppercase tracking-wider transition-all ${
              activeTab === tab
                ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow shadow-cyan-sm"
                : "border-gray-700/50 bg-gray-900/50 text-gray-500 hover:border-cyan-glow/20 hover:text-cyan-dim"
            }`}
          >
            {tab === "launch" ? "New Mission" : tab === "active" ? `Active (${orchestrations.length})` : "History"}
          </button>
        ))}
      </div>

      {/* ================================================================== */}
      {/*  Launch Tab                                                        */}
      {/* ================================================================== */}
      {activeTab === "launch" && (
        <div className="space-y-6">
          {/* Target Input */}
          <div className="glass-panel border border-cyan-glow/10 p-6">
            <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Target
            </h2>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="IP, URL, domain, or CIDR range..."
              className="w-full rounded border border-cyan-glow/20 bg-black/40 px-4 py-3 text-sm font-mono text-gray-200 outline-none focus:border-cyan-glow/50 transition-colors"
            />
            {scopeWarning && (
              <div className="mt-2 flex items-center gap-2 rounded border border-yellow-500/30 bg-yellow-500/10 px-3 py-2">
                <svg className="h-4 w-4 text-yellow-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
                <span className="text-[10px] text-yellow-400">
                  Target not in authorized scope. Authorized: {AUTHORIZED_TARGETS.join(", ")}
                </span>
              </div>
            )}
            {target.trim() && !scopeWarning && (
              <div className="mt-2 flex items-center gap-2 text-[10px] text-green-400">
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
                Target is within authorized scope
              </div>
            )}
          </div>

          {/* Profile Selector */}
          <div>
            <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Attack Profile
            </h2>
            <div className="grid grid-cols-4 gap-3">
              {PROFILES.map((p) => (
                <button
                  key={p.id}
                  onClick={() => setSelectedProfile(p.id)}
                  className={`glass-panel group relative border p-4 text-left transition-all hover:scale-[1.02] ${
                    selectedProfile === p.id
                      ? "border-cyan-glow/40 bg-cyan-glow/10 shadow-cyan-sm"
                      : "border-cyan-glow/10 hover:border-cyan-glow/25"
                  }`}
                >
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-bold text-gray-200">{p.name}</span>
                    {p.intensity > 0 && <IntensityBar level={p.intensity} />}
                  </div>
                  <p className="mb-3 text-[9px] leading-relaxed text-gray-500">{p.description}</p>
                  <div className="flex items-center justify-between">
                    <span className="text-[8px] font-mono text-cyan-glow/40">{p.estimatedTime}</span>
                    {p.stages.length > 0 && (
                      <span className="text-[8px] font-mono text-gray-600">{p.stages.length} stages</span>
                    )}
                  </div>
                  {p.stages.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {p.stages.map((s) => (
                        <span key={s} className="rounded bg-cyan-glow/5 px-1.5 py-0.5 text-[7px] font-mono text-cyan-glow/40">
                          {s}
                        </span>
                      ))}
                    </div>
                  )}
                  {selectedProfile === p.id && (
                    <div className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-cyan-glow text-[9px] font-bold text-black">
                      &#10003;
                    </div>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Custom phases */}
          {selectedProfile === "custom" && (
            <div className="glass-panel border border-cyan-glow/10 p-6">
              <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
                Custom Phases
              </h2>
              <div className="grid grid-cols-3 gap-2">
                {CUSTOM_PHASES.map((phase) => (
                  <button
                    key={phase}
                    onClick={() =>
                      setCustomPhases((prev) =>
                        prev.includes(phase) ? prev.filter((p) => p !== phase) : [...prev, phase]
                      )
                    }
                    className={`rounded border px-3 py-2 text-[10px] text-left transition-all ${
                      customPhases.includes(phase)
                        ? "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                        : "border-gray-700/30 bg-gray-900/30 text-gray-500 hover:border-cyan-glow/15"
                    }`}
                  >
                    <div className={`inline-block mr-2 h-2 w-2 rounded-sm ${customPhases.includes(phase) ? "bg-cyan-glow" : "bg-gray-600"}`} />
                    {phase}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Launch Button */}
          <div className="flex justify-center pt-4">
            <button
              onClick={handleLaunch}
              disabled={!target.trim() || !selectedProfile}
              className={`relative rounded-xl border-2 px-12 py-4 text-sm font-bold uppercase tracking-[0.3em] transition-all ${
                !target.trim() || !selectedProfile
                  ? "border-gray-700 bg-gray-900 text-gray-600 cursor-not-allowed"
                  : "border-cyan-glow/50 bg-cyan-glow/10 text-cyan-glow hover:bg-cyan-glow/20 hover:shadow-cyan-glow active:scale-95"
              }`}
              style={{ fontFamily: "Orbitron, sans-serif" }}
            >
              {launchPulse && (
                <div className="absolute inset-0 rounded-xl bg-cyan-glow/20 animate-ping" />
              )}
              <span className="relative z-10">LAUNCH MISSION</span>
            </button>
          </div>
        </div>
      )}

      {/* ================================================================== */}
      {/*  Active Orchestrations                                             */}
      {/* ================================================================== */}
      {activeTab === "active" && (
        <div className="space-y-4">
          {orchestrations.length === 0 && (
            <div className="glass-panel flex flex-col items-center justify-center p-12">
              <p className="text-sm text-gray-500">No active orchestrations</p>
              <button
                onClick={() => setActiveTab("launch")}
                className="mt-4 rounded border border-cyan-glow/20 bg-cyan-glow/5 px-6 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15"
              >
                LAUNCH NEW
              </button>
            </div>
          )}
          {orchestrations.map((orc) => (
            <div
              key={orc.id}
              className={`glass-panel border transition-all ${
                orc.status === "running"
                  ? "border-cyan-glow/20 hover:border-cyan-glow/30"
                  : orc.status === "paused"
                  ? "border-yellow-500/20"
                  : "border-gray-700/30"
              }`}
            >
              <div className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className={`relative h-3 w-3 rounded-full ${
                      orc.status === "running" ? "bg-green-400" : orc.status === "paused" ? "bg-yellow-400" : "bg-gray-500"
                    }`}>
                      {orc.status === "running" && (
                        <div className="absolute inset-0 h-3 w-3 animate-ping rounded-full bg-green-400 opacity-40" />
                      )}
                    </div>
                    <span className="text-sm font-bold text-gray-200">{orc.target}</span>
                    <Badge
                      text={orc.profile}
                      cls="bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono text-gray-500">{orc.elapsed}</span>
                    <button
                      onClick={() => togglePause(orc.id)}
                      className={`rounded border px-3 py-1 text-[9px] font-bold uppercase tracking-wider transition-all ${
                        orc.status === "running"
                          ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20"
                          : "border-green-500/30 bg-green-500/10 text-green-400 hover:bg-green-500/20"
                      }`}
                    >
                      {orc.status === "running" ? "PAUSE" : "RESUME"}
                    </button>
                    <button
                      onClick={() => cancelOrchestration(orc.id)}
                      className="rounded border border-red-500/30 bg-red-500/10 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-red-400 transition-all hover:bg-red-500/20"
                    >
                      CANCEL
                    </button>
                    <Link
                      href={`/orchestrator/${orc.id}`}
                      className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15"
                    >
                      DETAILS
                    </Link>
                  </div>
                </div>

                {/* Phase progress */}
                <div className="mb-3">
                  <div className="flex items-center gap-1 mb-1">
                    {Array.from({ length: orc.totalPhases }).map((_, i) => (
                      <div
                        key={i}
                        className={`h-2 flex-1 rounded-full transition-all ${
                          i < orc.currentPhase
                            ? "bg-cyan-glow"
                            : i === orc.currentPhase
                            ? "bg-cyan-glow/40 animate-pulse"
                            : "bg-gray-700"
                        }`}
                      />
                    ))}
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-mono text-gray-500">
                      Phase {orc.currentPhase}/{orc.totalPhases}
                    </span>
                    <span className="text-[9px] font-mono text-gray-500">
                      {Math.round((orc.currentPhase / orc.totalPhases) * 100)}%
                    </span>
                  </div>
                </div>

                {/* Current action */}
                <div className="mb-3 flex items-center gap-2 rounded border border-cyan-glow/10 bg-black/20 px-3 py-2">
                  {orc.status === "running" && (
                    <div className="h-1.5 w-1.5 rounded-full bg-cyan-glow animate-pulse flex-shrink-0" />
                  )}
                  <span className="text-[10px] font-mono text-gray-400 truncate">{orc.currentAction}</span>
                </div>

                {/* Findings */}
                <FindingsBadges findings={orc.findings} />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ================================================================== */}
      {/*  History                                                           */}
      {/* ================================================================== */}
      {activeTab === "history" && (
        <div className="glass-panel overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyan-glow/10">
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Date</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Target</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Profile</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Findings</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_HISTORY.map((h) => (
                <tr key={h.id} className="border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5">
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{h.date}</td>
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{h.target}</td>
                  <td className="px-4 py-3">
                    <Badge text={h.profile} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
                  </td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{h.duration}</td>
                  <td className="px-4 py-3">
                    <FindingsBadges findings={h.findings} />
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      text={h.status}
                      cls={
                        h.status === "completed"
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : h.status === "failed"
                          ? "bg-red-500/15 text-red-400 border-red-500/30"
                          : "bg-gray-500/15 text-gray-400 border-gray-500/30"
                      }
                    />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <Link
                        href={`/orchestrator/${h.id}`}
                        className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-2 py-1 text-[8px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15"
                      >
                        VIEW
                      </Link>
                      <button className="rounded border border-gray-700/30 bg-gray-900/30 px-2 py-1 text-[8px] font-bold uppercase tracking-wider text-gray-500 transition-all hover:border-cyan-glow/20 hover:text-cyan-dim">
                        PDF
                      </button>
                      <button className="rounded border border-gray-700/30 bg-gray-900/30 px-2 py-1 text-[8px] font-bold uppercase tracking-wider text-gray-500 transition-all hover:border-cyan-glow/20 hover:text-cyan-dim">
                        JSON
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
