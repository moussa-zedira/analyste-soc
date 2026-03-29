"use client";

import { useState, useMemo } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Severity = "critical" | "high" | "medium" | "low";
type QualityGate = "passed" | "failed" | "warning";

interface Project {
  id: string;
  name: string;
  language: string;
  repoUrl: string;
  branch: string;
  lastScan: string;
  findings: { critical: number; high: number; medium: number; low: number };
  qualityGate: QualityGate;
  dependencies: number;
  vulnDeps: number;
}

interface ScanRun {
  id: string;
  project: string;
  type: string;
  startedAt: string;
  duration: number;
  findings: number;
  status: "completed" | "running" | "failed";
}

interface VulnDep {
  name: string;
  version: string;
  cve: string;
  severity: Severity;
  fixVersion: string;
}

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------
const SEV_COLORS: Record<Severity, string> = { critical: "#EF4444", high: "#F97316", medium: "#EAB308", low: "#3B82F6" };
const SEV_BG: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
};
const QG_COLORS: Record<QualityGate, string> = {
  passed: "bg-green-500/15 text-green-400 border-green-500/20",
  failed: "bg-red-500/15 text-red-400 border-red-500/20",
  warning: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
};

// ---------------------------------------------------------------------------
// Demo Data
// ---------------------------------------------------------------------------
function generateProjects(): Project[] {
  return [
    { id: "p1", name: "api-gateway", language: "Python", repoUrl: "https://github.com/org/api-gateway", branch: "main", lastScan: "2026-03-28T14:00:00Z", findings: { critical: 2, high: 5, medium: 12, low: 8 }, qualityGate: "failed", dependencies: 142, vulnDeps: 7 },
    { id: "p2", name: "web-frontend", language: "TypeScript", repoUrl: "https://github.com/org/web-frontend", branch: "develop", lastScan: "2026-03-28T10:00:00Z", findings: { critical: 0, high: 1, medium: 4, low: 15 }, qualityGate: "passed", dependencies: 234, vulnDeps: 3 },
    { id: "p3", name: "auth-service", language: "Go", repoUrl: "https://github.com/org/auth-service", branch: "main", lastScan: "2026-03-27T18:00:00Z", findings: { critical: 1, high: 3, medium: 6, low: 2 }, qualityGate: "warning", dependencies: 45, vulnDeps: 2 },
    { id: "p4", name: "data-pipeline", language: "Java", repoUrl: "https://github.com/org/data-pipeline", branch: "release/1.2", lastScan: "2026-03-28T08:00:00Z", findings: { critical: 0, high: 0, medium: 2, low: 5 }, qualityGate: "passed", dependencies: 89, vulnDeps: 1 },
    { id: "p5", name: "infra-terraform", language: "HCL", repoUrl: "https://github.com/org/infra-terraform", branch: "main", lastScan: "2026-03-26T12:00:00Z", findings: { critical: 3, high: 8, medium: 15, low: 4 }, qualityGate: "failed", dependencies: 12, vulnDeps: 0 },
    { id: "p6", name: "mobile-app", language: "Kotlin", repoUrl: "https://github.com/org/mobile-app", branch: "main", lastScan: "2026-03-28T16:00:00Z", findings: { critical: 0, high: 2, medium: 7, low: 11 }, qualityGate: "passed", dependencies: 67, vulnDeps: 4 },
  ];
}

function generateScanRuns(): ScanRun[] {
  return [
    { id: "s1", project: "api-gateway", type: "SAST + SCA", startedAt: "2026-03-28T14:00:00Z", duration: 245, findings: 27, status: "completed" },
    { id: "s2", project: "web-frontend", type: "SAST", startedAt: "2026-03-28T10:00:00Z", duration: 180, findings: 20, status: "completed" },
    { id: "s3", project: "auth-service", type: "Secrets + SCA", startedAt: "2026-03-27T18:00:00Z", duration: 120, findings: 12, status: "completed" },
    { id: "s4", project: "infra-terraform", type: "IaC", startedAt: "2026-03-26T12:00:00Z", duration: 60, findings: 30, status: "completed" },
    { id: "s5", project: "mobile-app", type: "Full Scan", startedAt: "2026-03-28T16:00:00Z", duration: 0, findings: 0, status: "running" },
    { id: "s6", project: "data-pipeline", type: "DAST", startedAt: "2026-03-28T08:00:00Z", duration: 340, findings: 7, status: "completed" },
  ];
}

function generateVulnDeps(): VulnDep[] {
  return [
    { name: "log4j-core", version: "2.14.1", cve: "CVE-2021-44228", severity: "critical", fixVersion: "2.17.1" },
    { name: "spring-core", version: "5.3.17", cve: "CVE-2022-22965", severity: "critical", fixVersion: "5.3.18" },
    { name: "lodash", version: "4.17.20", cve: "CVE-2021-23337", severity: "high", fixVersion: "4.17.21" },
    { name: "requests", version: "2.25.1", cve: "CVE-2023-32681", severity: "medium", fixVersion: "2.31.0" },
    { name: "golang.org/x/crypto", version: "0.0.0-20220315", cve: "CVE-2022-27191", severity: "high", fixVersion: "0.0.0-20220331" },
    { name: "jackson-databind", version: "2.13.2", cve: "CVE-2022-42003", severity: "high", fixVersion: "2.13.4.1" },
    { name: "axios", version: "0.21.1", cve: "CVE-2021-3749", severity: "medium", fixVersion: "0.21.2" },
    { name: "pillow", version: "9.0.0", cve: "CVE-2022-22817", severity: "high", fixVersion: "9.0.1" },
  ];
}

// ---------------------------------------------------------------------------
// Trend data
// ---------------------------------------------------------------------------
function generateTrendData() {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  return days.map(d => ({
    day: d,
    critical: Math.floor(Math.random() * 5),
    high: Math.floor(Math.random() * 10) + 3,
    medium: Math.floor(Math.random() * 20) + 5,
    low: Math.floor(Math.random() * 15) + 2,
  }));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function DevSecOpsDashboard() {
  const [projects] = useState(generateProjects);
  const [scanRuns] = useState(generateScanRuns);
  const [vulnDeps] = useState(generateVulnDeps);
  const [trendData] = useState(generateTrendData);
  const [showAddProject, setShowAddProject] = useState(false);
  const [addName, setAddName] = useState("");
  const [addRepo, setAddRepo] = useState("");
  const [addBranch, setAddBranch] = useState("main");
  const [addLang, setAddLang] = useState("Python");

  const totalFindings = useMemo(() => {
    const t = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
    for (const p of projects) {
      t.critical += p.findings.critical;
      t.high += p.findings.high;
      t.medium += p.findings.medium;
      t.low += p.findings.low;
    }
    t.total = t.critical + t.high + t.medium + t.low;
    return t;
  }, [projects]);

  const qgPassRate = useMemo(() => {
    const passed = projects.filter(p => p.qualityGate === "passed").length;
    return projects.length > 0 ? Math.round((passed / projects.length) * 100) : 0;
  }, [projects]);

  const trendMax = useMemo(() => Math.max(...trendData.map(d => d.critical + d.high + d.medium + d.low), 1), [trendData]);

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            DevSecOps Dashboard
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SECURITY POSTURE // SAST // SCA // SECRETS // IaC
          </p>
        </div>
        <button onClick={() => setShowAddProject(!showAddProject)} className="glass-panel px-4 py-2 text-[10px] font-bold tracking-wider text-cyan-glow hover:bg-cyan-glow/10 transition-colors">
          + ADD PROJECT
        </button>
      </div>
      <div className="cyan-line" />

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-cyan-glow font-mono">{projects.length}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">PROJECTS</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold font-mono" style={{ color: SEV_COLORS.critical }}>{totalFindings.critical}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">CRITICAL</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold font-mono" style={{ color: SEV_COLORS.high }}>{totalFindings.high}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">HIGH</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold font-mono" style={{ color: SEV_COLORS.medium }}>{totalFindings.medium}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">MEDIUM</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold font-mono" style={{ color: SEV_COLORS.low }}>{totalFindings.low}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">LOW</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className={`text-2xl font-bold font-mono ${qgPassRate >= 70 ? "text-green-400" : qgPassRate >= 40 ? "text-yellow-400" : "text-red-400"}`}>{qgPassRate}%</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">QG PASS RATE</p>
        </div>
      </div>

      {/* Add Project Form */}
      {showAddProject && (
        <div className="glass-panel p-4 space-y-3 max-w-xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">ADD PROJECT</h3>
          <div className="grid grid-cols-2 gap-3">
            <input type="text" value={addName} onChange={e => setAddName(e.target.value)} placeholder="Project name" className="rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            <input type="text" value={addRepo} onChange={e => setAddRepo(e.target.value)} placeholder="Repo URL" className="rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            <input type="text" value={addBranch} onChange={e => setAddBranch(e.target.value)} placeholder="Branch" className="rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            <select value={addLang} onChange={e => setAddLang(e.target.value)} className="rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
              {["Python", "TypeScript", "JavaScript", "Go", "Java", "Kotlin", "Rust", "C#", "HCL", "Ruby"].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <button className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors">
            CREATE PROJECT
          </button>
        </div>
      )}

      {/* Trend Chart */}
      <div className="glass-panel p-4">
        <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">FINDINGS TREND (7 DAYS)</p>
        <div className="flex items-end gap-2 h-32">
          {trendData.map((d, i) => {
            const total = d.critical + d.high + d.medium + d.low;
            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-1">
                <div className="w-full flex flex-col-reverse" style={{ height: `${(total / trendMax) * 100}%`, minHeight: 4 }}>
                  <div style={{ height: `${(d.low / total) * 100}%`, background: SEV_COLORS.low + "66" }} className="w-full rounded-b" />
                  <div style={{ height: `${(d.medium / total) * 100}%`, background: SEV_COLORS.medium + "66" }} className="w-full" />
                  <div style={{ height: `${(d.high / total) * 100}%`, background: SEV_COLORS.high + "66" }} className="w-full" />
                  <div style={{ height: `${(d.critical / total) * 100}%`, background: SEV_COLORS.critical + "66" }} className="w-full rounded-t" />
                </div>
                <span className="text-[9px] text-gray-500">{d.day}</span>
              </div>
            );
          })}
        </div>
        <div className="flex gap-4 mt-3 justify-center">
          {(["critical", "high", "medium", "low"] as Severity[]).map(s => (
            <div key={s} className="flex items-center gap-1">
              <div className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[s] }} />
              <span className="text-[9px] text-gray-500 capitalize">{s}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Projects Table */}
      <div className="glass-panel overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-cyan-glow/10">
              <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">PROJECT</th>
              <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">LANGUAGE</th>
              <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">LAST SCAN</th>
              <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">FINDINGS</th>
              <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">QUALITY GATE</th>
            </tr>
          </thead>
          <tbody>
            {projects.map(p => (
              <tr key={p.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5 transition-colors">
                <td className="px-4 py-3">
                  <p className="text-sm text-gray-200 font-medium">{p.name}</p>
                  <p className="text-[10px] font-mono text-gray-500">{p.branch}</p>
                </td>
                <td className="px-4 py-3">
                  <span className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-2 py-0.5 text-[10px] text-cyan-glow">{p.language}</span>
                </td>
                <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{new Date(p.lastScan).toLocaleString()}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-1.5">
                    {(["critical", "high", "medium", "low"] as Severity[]).map(s => (
                      p.findings[s] > 0 && <span key={s} className={`rounded border px-1.5 py-0.5 text-[10px] font-bold ${SEV_BG[s]}`}>{p.findings[s]} {s[0].toUpperCase()}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${QG_COLORS[p.qualityGate]}`}>{p.qualityGate.toUpperCase()}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Bottom row: Vuln Deps + Recent Scans */}
      <div className="grid grid-cols-2 gap-4">
        {/* Vulnerable Dependencies */}
        <div className="glass-panel p-4 space-y-3">
          <p className="text-[10px] font-bold tracking-widest text-gray-500">TOP VULNERABLE DEPENDENCIES</p>
          <div className="space-y-2">
            {vulnDeps.map((d, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded border border-gray-800/50">
                <div>
                  <span className="text-xs text-gray-200 font-mono">{d.name}@{d.version}</span>
                  <span className="ml-2 text-[10px] text-cyan-glow/50 font-mono">{d.cve}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold ${SEV_BG[d.severity]}`}>{d.severity.toUpperCase()}</span>
                  <span className="text-[9px] text-green-400 font-mono">fix: {d.fixVersion}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Scan Runs */}
        <div className="glass-panel p-4 space-y-3">
          <p className="text-[10px] font-bold tracking-widest text-gray-500">RECENT SCAN RUNS</p>
          <div className="space-y-2">
            {scanRuns.map(s => (
              <div key={s.id} className="flex items-center justify-between p-2 rounded border border-gray-800/50">
                <div>
                  <span className="text-xs text-gray-200">{s.project}</span>
                  <span className="ml-2 text-[10px] text-gray-500">{s.type}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-mono text-gray-500">{s.duration > 0 ? `${s.duration}s` : "--"}</span>
                  <span className="text-[10px] font-mono text-cyan-glow">{s.findings} findings</span>
                  <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${s.status === "completed" ? "bg-green-500/15 text-green-400" : s.status === "running" ? "bg-cyan-glow/15 text-cyan-glow animate-pulse" : "bg-red-500/15 text-red-400"}`}>{s.status.toUpperCase()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
