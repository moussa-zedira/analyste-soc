"use client";

import { useState, useEffect, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Phase {
  id: number;
  name: string;
  status: "completed" | "running" | "pending";
  tasks: Task[];
}

interface Task {
  name: string;
  status: "done" | "running" | "pending" | "failed";
  duration?: string;
}

interface Finding {
  id: string;
  title: string;
  type: string;
  location: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvss: number;
  details: string;
  mitreId?: string;
}

interface ActionLog {
  timestamp: string;
  message: string;
  type: "recon" | "vuln" | "exploit" | "info";
}

interface SurfaceNode {
  id: string;
  label: string;
  type: "host" | "port" | "service";
  x: number;
  y: number;
}

interface SurfaceEdge {
  from: string;
  to: string;
}

interface Remediation {
  priority: number;
  finding: string;
  action: string;
  effort: "low" | "medium" | "high";
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------

const MOCK_PHASES: Phase[] = [
  {
    id: 1, name: "Reconnaissance", status: "completed",
    tasks: [
      { name: "DNS Enumeration", status: "done", duration: "12s" },
      { name: "Port Scanning (TCP)", status: "done", duration: "45s" },
      { name: "Port Scanning (UDP)", status: "done", duration: "2m 15s" },
      { name: "Service Detection", status: "done", duration: "28s" },
      { name: "OS Fingerprinting", status: "done", duration: "8s" },
    ],
  },
  {
    id: 2, name: "Enumeration", status: "completed",
    tasks: [
      { name: "Web Crawling", status: "done", duration: "1m 42s" },
      { name: "Directory Bruteforce", status: "done", duration: "3m 05s" },
      { name: "Technology Detection", status: "done", duration: "5s" },
      { name: "Form Discovery", status: "done", duration: "22s" },
      { name: "API Endpoint Mapping", status: "done", duration: "38s" },
    ],
  },
  {
    id: 3, name: "Vulnerability Analysis", status: "running",
    tasks: [
      { name: "SQL Injection Testing", status: "done", duration: "2m 30s" },
      { name: "XSS Testing", status: "done", duration: "1m 45s" },
      { name: "SSRF Testing", status: "running" },
      { name: "Auth Bypass Checks", status: "pending" },
      { name: "File Upload Testing", status: "pending" },
    ],
  },
  {
    id: 4, name: "Exploitation", status: "pending",
    tasks: [
      { name: "Exploit Execution", status: "pending" },
      { name: "Post-Exploitation", status: "pending" },
      { name: "Privilege Escalation", status: "pending" },
    ],
  },
  {
    id: 5, name: "Reporting", status: "pending",
    tasks: [
      { name: "Generate Report", status: "pending" },
      { name: "MITRE Mapping", status: "pending" },
      { name: "Remediation Plan", status: "pending" },
    ],
  },
];

const MOCK_FINDINGS: Finding[] = [
  { id: "f1", title: "SQL Injection (Boolean Blind)", type: "SQLi", location: "/api/users?id=", severity: "critical", cvss: 9.8, details: "Boolean-based blind SQL injection in the 'id' parameter. Database: PostgreSQL 14.2. Extractable: users table, credentials.", mitreId: "T1190" },
  { id: "f2", title: "Reflected XSS in Search", type: "XSS", location: "/search?q=", severity: "high", cvss: 7.1, details: "Reflected cross-site scripting in the search query parameter. No sanitization applied. CSP header missing.", mitreId: "T1189" },
  { id: "f3", title: "IDOR on User Profile", type: "Auth", location: "/api/profile/{id}", severity: "high", cvss: 7.5, details: "Insecure Direct Object Reference allows accessing any user profile by changing the ID. No authorization check.", mitreId: "T1078" },
  { id: "f4", title: "Directory Listing Enabled", type: "Config", location: "/uploads/", severity: "medium", cvss: 5.3, details: "Apache directory listing is enabled on /uploads/, exposing uploaded files including potential sensitive documents." },
  { id: "f5", title: "Missing Rate Limiting", type: "Config", location: "/api/auth/login", severity: "medium", cvss: 5.0, details: "No rate limiting on authentication endpoint. Allows brute force attacks.", mitreId: "T1110" },
  { id: "f6", title: "Information Disclosure in Headers", type: "Info", location: "All endpoints", severity: "low", cvss: 3.1, details: "Server header reveals Apache 2.4.52, X-Powered-By reveals PHP 8.1.2." },
  { id: "f7", title: "Cookie without HttpOnly", type: "Config", location: "session_id cookie", severity: "medium", cvss: 4.7, details: "Session cookie lacks HttpOnly flag, making it accessible via JavaScript." },
  { id: "f8", title: "Outdated jQuery Version", type: "Library", location: "/js/jquery.min.js", severity: "low", cvss: 3.5, details: "jQuery 3.4.1 is used. Known XSS vulnerability in jQuery.htmlPrefilter." },
  { id: "f9", title: "SSRF via Webhook URL", type: "SSRF", location: "/api/webhooks", severity: "critical", cvss: 9.1, details: "Server-side request forgery through webhook URL parameter. Internal network accessible. AWS metadata endpoint reachable.", mitreId: "T1190" },
  { id: "f10", title: "Weak Password Policy", type: "Auth", location: "/api/auth/register", severity: "medium", cvss: 5.0, details: "No password complexity requirements. Minimum length only 4 characters." },
];

const MOCK_LOG: ActionLog[] = [
  { timestamp: "12:34:56", message: "Port scan: found 22/tcp (SSH), 80/tcp (HTTP), 443/tcp (HTTPS), 3306/tcp (MySQL), 8080/tcp (HTTP-Proxy)", type: "recon" },
  { timestamp: "12:35:10", message: "OS detection: Linux 5.x (Ubuntu 22.04 LTS) - 98% confidence", type: "recon" },
  { timestamp: "12:35:22", message: "Crawler: discovered 147 URLs, 12 forms, 3 login pages, 2 file upload endpoints", type: "recon" },
  { timestamp: "12:35:45", message: "Technology stack: Apache 2.4.52, PHP 8.1.2, Laravel 9.x, PostgreSQL 14.2", type: "info" },
  { timestamp: "12:36:01", message: "Directory brute: found /admin/, /uploads/, /api/docs/, /phpinfo.php", type: "recon" },
  { timestamp: "12:36:30", message: "API endpoints mapped: 34 REST endpoints, 2 GraphQL queries", type: "recon" },
  { timestamp: "12:37:15", message: "SQLi: VULNERABLE - parameter 'id' on /api/users (boolean blind)", type: "vuln" },
  { timestamp: "12:37:42", message: "SQLi: extracted DB version = PostgreSQL 14.2, database = app_production", type: "exploit" },
  { timestamp: "12:38:05", message: "SQLi: extracted 3,240 user records including password hashes (bcrypt)", type: "exploit" },
  { timestamp: "12:38:30", message: "XSS: VULNERABLE - reflected XSS in /search?q= (no encoding)", type: "vuln" },
  { timestamp: "12:38:55", message: "IDOR: VULNERABLE - /api/profile/1 accessible without auth, returns PII", type: "vuln" },
  { timestamp: "12:39:10", message: "SSRF: Testing webhook URL parameter for internal network access...", type: "info" },
  { timestamp: "12:39:25", message: "SSRF: VULNERABLE - internal network accessible via /api/webhooks", type: "vuln" },
  { timestamp: "12:39:40", message: "SSRF: AWS metadata endpoint (169.254.169.254) reachable - IAM role extracted", type: "exploit" },
  { timestamp: "12:40:02", message: "Auth bypass: testing default credentials on /admin/login", type: "info" },
];

const MOCK_SURFACE_NODES: SurfaceNode[] = [
  { id: "h1", label: "192.168.1.10", type: "host", x: 300, y: 150 },
  { id: "h2", label: "192.168.1.45", type: "host", x: 550, y: 100 },
  { id: "h3", label: "192.168.1.100", type: "host", x: 550, y: 250 },
  { id: "p1", label: ":22 SSH", type: "port", x: 150, y: 80 },
  { id: "p2", label: ":80 HTTP", type: "port", x: 150, y: 150 },
  { id: "p3", label: ":443 HTTPS", type: "port", x: 150, y: 220 },
  { id: "p4", label: ":3306 MySQL", type: "port", x: 450, y: 40 },
  { id: "p5", label: ":21 FTP", type: "port", x: 700, y: 100 },
  { id: "p6", label: ":8080 Proxy", type: "port", x: 700, y: 250 },
  { id: "s1", label: "Web App", type: "service", x: 300, y: 300 },
];

const MOCK_SURFACE_EDGES: SurfaceEdge[] = [
  { from: "h1", to: "p1" }, { from: "h1", to: "p2" }, { from: "h1", to: "p3" },
  { from: "h2", to: "p4" }, { from: "h2", to: "p5" },
  { from: "h3", to: "p6" },
  { from: "h1", to: "h2" }, { from: "h1", to: "h3" },
  { from: "h1", to: "s1" },
];

const MOCK_REMEDIATIONS: Remediation[] = [
  { priority: 1, finding: "SQL Injection (Boolean Blind)", action: "Use parameterized queries / prepared statements for all SQL operations", effort: "medium" },
  { priority: 2, finding: "SSRF via Webhook URL", action: "Implement allowlist for webhook destinations, block internal IP ranges", effort: "medium" },
  { priority: 3, finding: "Reflected XSS in Search", action: "Implement output encoding and Content-Security-Policy header", effort: "low" },
  { priority: 4, finding: "IDOR on User Profile", action: "Add authorization checks verifying user owns requested resource", effort: "low" },
  { priority: 5, finding: "Cookie without HttpOnly", action: "Set HttpOnly and Secure flags on all session cookies", effort: "low" },
  { priority: 6, finding: "Missing Rate Limiting", action: "Implement rate limiting (10 req/min) on authentication endpoints", effort: "medium" },
  { priority: 7, finding: "Directory Listing Enabled", action: "Disable Options -Indexes in Apache configuration", effort: "low" },
  { priority: 8, finding: "Weak Password Policy", action: "Enforce minimum 12 characters, complexity requirements", effort: "low" },
];

const MITRE_MAPPING = [
  { tactic: "Initial Access", techniques: [{ id: "T1190", name: "Exploit Public-Facing App", findings: 2 }] },
  { tactic: "Execution", techniques: [{ id: "T1059", name: "Command Scripting", findings: 1 }] },
  { tactic: "Credential Access", techniques: [{ id: "T1110", name: "Brute Force", findings: 1 }, { id: "T1003", name: "OS Credential Dumping", findings: 1 }] },
  { tactic: "Defense Evasion", techniques: [{ id: "T1078", name: "Valid Accounts", findings: 1 }] },
  { tactic: "Discovery", techniques: [{ id: "T1046", name: "Network Service Scan", findings: 0 }] },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

const LOG_COLORS: Record<string, string> = {
  recon: "text-blue-400",
  vuln: "text-yellow-400",
  exploit: "text-red-400",
  info: "text-gray-400",
};

const SEVERITY_CLS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

function RiskGauge({ level }: { level: "Critical" | "High" | "Medium" | "Low" | "Info" }) {
  const angles: Record<string, number> = { Critical: 160, High: 125, Medium: 90, Low: 50, Info: 20 };
  const colors: Record<string, string> = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#3b82f6", Info: "#6b7280" };
  const angle = angles[level];
  const color = colors[level];
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 120 70" className="w-32 h-20">
        {/* Background arc */}
        <path d="M 10 65 A 50 50 0 0 1 110 65" fill="none" stroke="#1f2937" strokeWidth="8" strokeLinecap="round" />
        {/* Colored arc */}
        <path
          d="M 10 65 A 50 50 0 0 1 110 65"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${(angle / 180) * 157} 157`}
          opacity="0.8"
        />
        {/* Needle */}
        <line
          x1="60" y1="65"
          x2={60 + 40 * Math.cos(((180 - angle) * Math.PI) / 180)}
          y2={65 - 40 * Math.sin(((180 - angle) * Math.PI) / 180)}
          stroke={color} strokeWidth="2" strokeLinecap="round"
        />
        <circle cx="60" cy="65" r="3" fill={color} />
      </svg>
      <span className="text-xs font-bold tracking-wider" style={{ color, fontFamily: "Orbitron, sans-serif" }}>
        {level.toUpperCase()} RISK
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function OrchestrationDetail() {
  const params = useParams();
  const id = params.id as string;
  const [activeView, setActiveView] = useState<"timeline" | "findings" | "surface" | "report">("timeline");
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [logEntries, setLogEntries] = useState(MOCK_LOG);
  const [phases, setPhases] = useState(MOCK_PHASES);
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  // Simulate polling for live updates
  useEffect(() => {
    const running = phases.some((p) => p.status === "running");
    if (!running) return;

    const interval = setInterval(() => {
      const newEntries: ActionLog[] = [
        { timestamp: new Date().toLocaleTimeString("fr-FR", { hour12: false }), message: "Scanning additional parameters...", type: "info" },
      ];
      setLogEntries((prev) => [...newEntries, ...prev].slice(0, 50));
    }, 5000);
    return () => clearInterval(interval);
  }, [phases]);

  const findingsGrouped = MOCK_FINDINGS.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const filteredFindings = severityFilter
    ? MOCK_FINDINGS.filter((f) => f.severity === severityFilter)
    : MOCK_FINDINGS;

  const sortedFindings = [...filteredFindings].sort((a, b) => b.cvss - a.cvss);

  const metrics = {
    hosts: 3,
    ports: 6,
    urls: 147,
    forms: 12,
    vulns: MOCK_FINDINGS.length,
    exploits: MOCK_FINDINGS.filter((f) => f.severity === "critical").length,
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Link href="/orchestrator" className="text-cyan-glow/40 hover:text-cyan-glow transition-colors">
              <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
              </svg>
            </Link>
            <h1 className="text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Orchestration {id}
            </h1>
            <Badge text="running" cls="bg-green-500/15 text-green-400 border-green-500/30 animate-pulse" />
          </div>
          <p className="ml-8 text-[10px] tracking-widest text-cyan-glow/30">
            TARGET: 192.168.1.0/24 // PROFILE: NETWORK FULL // STARTED: 12:30:00
          </p>
        </div>
        <div className="flex gap-2">
          <button className="rounded border border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-yellow-400 hover:bg-yellow-500/20">
            PAUSE
          </button>
          <button className="rounded border border-red-500/30 bg-red-500/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-red-400 hover:bg-red-500/20">
            ABORT
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Discovery Metrics */}
      <div className="grid grid-cols-6 gap-3">
        {Object.entries(metrics).map(([key, val]) => (
          <div key={key} className="glass-panel border border-cyan-glow/10 p-3 text-center">
            <p className="text-[8px] uppercase tracking-wider text-gray-500">{key}</p>
            <p className="text-lg font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>{val}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(["timeline", "findings", "surface", "report"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveView(tab)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold uppercase tracking-wider transition-all ${
              activeView === tab
                ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow shadow-cyan-sm"
                : "border-gray-700/50 bg-gray-900/50 text-gray-500 hover:border-cyan-glow/20 hover:text-cyan-dim"
            }`}
          >
            {tab === "timeline" ? "Phase Timeline" : tab === "findings" ? `Findings (${MOCK_FINDINGS.length})` : tab === "surface" ? "Attack Surface" : "Report"}
          </button>
        ))}
      </div>

      {/* ================================================================== */}
      {/*  Phase Timeline                                                    */}
      {/* ================================================================== */}
      {activeView === "timeline" && (
        <div className="grid grid-cols-3 gap-6">
          {/* Phases */}
          <div className="col-span-1 space-y-3">
            <h3 className="text-[10px] font-bold uppercase tracking-wider text-gray-500">Phases</h3>
            {phases.map((phase) => (
              <div
                key={phase.id}
                className={`glass-panel border p-4 transition-all ${
                  phase.status === "running"
                    ? "border-cyan-glow/30 bg-cyan-glow/5"
                    : phase.status === "completed"
                    ? "border-green-500/15 bg-green-500/5"
                    : "border-gray-700/20"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div
                      className={`flex h-6 w-6 items-center justify-center rounded-full text-[9px] font-bold ${
                        phase.status === "completed"
                          ? "bg-green-500/20 text-green-400 border border-green-500/30"
                          : phase.status === "running"
                          ? "bg-cyan-glow/20 text-cyan-glow border border-cyan-glow/30 animate-pulse"
                          : "bg-gray-800 text-gray-500 border border-gray-700"
                      }`}
                    >
                      {phase.status === "completed" ? "\u2713" : phase.id}
                    </div>
                    <span className="text-xs font-bold text-gray-200">{phase.name}</span>
                  </div>
                  <Badge
                    text={phase.status}
                    cls={
                      phase.status === "completed"
                        ? "bg-green-500/15 text-green-400 border-green-500/30"
                        : phase.status === "running"
                        ? "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30"
                        : "bg-gray-500/15 text-gray-400 border-gray-500/30"
                    }
                  />
                </div>
                <div className="space-y-1 ml-8">
                  {phase.tasks.map((task, ti) => (
                    <div key={ti} className="flex items-center gap-2 text-[9px]">
                      <div
                        className={`h-1.5 w-1.5 rounded-full ${
                          task.status === "done"
                            ? "bg-green-400"
                            : task.status === "running"
                            ? "bg-cyan-glow animate-pulse"
                            : task.status === "failed"
                            ? "bg-red-500"
                            : "bg-gray-600"
                        }`}
                      />
                      <span className={task.status === "pending" ? "text-gray-600" : "text-gray-400"}>
                        {task.name}
                      </span>
                      {task.duration && (
                        <span className="text-gray-600 font-mono">{task.duration}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Action Log */}
          <div className="col-span-2">
            <h3 className="mb-3 text-[10px] font-bold uppercase tracking-wider text-gray-500">Live Action Log</h3>
            <div className="glass-panel max-h-[600px] overflow-y-auto p-4">
              <div className="space-y-1.5">
                {logEntries.map((entry, i) => (
                  <div key={i} className="flex gap-3 text-[10px] font-mono">
                    <span className="text-gray-600 flex-shrink-0">[{entry.timestamp}]</span>
                    <span className={LOG_COLORS[entry.type] || "text-gray-400"}>
                      {entry.message}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ================================================================== */}
      {/*  Findings                                                          */}
      {/* ================================================================== */}
      {activeView === "findings" && (
        <div>
          {/* Severity filter */}
          <div className="mb-4 flex items-center gap-2">
            <span className="text-[9px] uppercase tracking-wider text-gray-500 mr-2">Filter:</span>
            <button
              onClick={() => setSeverityFilter(null)}
              className={`rounded border px-3 py-1 text-[9px] font-bold uppercase transition-all ${
                !severityFilter ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500 hover:border-cyan-glow/20"
              }`}
            >
              All ({MOCK_FINDINGS.length})
            </button>
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
                className={`rounded border px-3 py-1 text-[9px] font-bold uppercase transition-all ${
                  severityFilter === sev ? SEVERITY_CLS[sev] : "border-gray-700 text-gray-500 hover:border-cyan-glow/20"
                }`}
              >
                {sev} ({findingsGrouped[sev] || 0})
              </button>
            ))}
          </div>

          {/* Findings list */}
          <div className="space-y-2">
            {sortedFindings.map((f) => (
              <div key={f.id} className="glass-panel border border-cyan-glow/10 transition-all hover:border-cyan-glow/20">
                <button
                  onClick={() => setExpandedFinding(expandedFinding === f.id ? null : f.id)}
                  className="flex w-full items-center gap-4 px-4 py-3 text-left"
                >
                  <Badge text={f.severity} cls={SEVERITY_CLS[f.severity]} />
                  <span className="flex-1 text-xs font-medium text-gray-200">{f.title}</span>
                  <Badge text={f.type} cls="bg-cyan-glow/10 text-cyan-glow/60 border-cyan-glow/20" />
                  <span className="text-[10px] font-mono text-gray-500">{f.location}</span>
                  <span className={`text-sm font-bold ${f.cvss >= 9 ? "text-red-400" : f.cvss >= 7 ? "text-orange-400" : f.cvss >= 4 ? "text-yellow-400" : "text-blue-400"}`}>
                    {f.cvss}
                  </span>
                  {f.mitreId && (
                    <Badge text={f.mitreId} cls="bg-purple-500/15 text-purple-400 border-purple-500/30" />
                  )}
                  <svg
                    className={`h-4 w-4 text-gray-500 transition-transform flex-shrink-0 ${expandedFinding === f.id ? "rotate-180" : ""}`}
                    fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                  </svg>
                </button>
                {expandedFinding === f.id && (
                  <div className="border-t border-cyan-glow/10 px-4 py-3">
                    <p className="text-[10px] leading-relaxed text-gray-400">{f.details}</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ================================================================== */}
      {/*  Attack Surface Map                                                */}
      {/* ================================================================== */}
      {activeView === "surface" && (
        <div className="glass-panel border border-cyan-glow/10 p-6">
          <h3 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Attack Surface Map
          </h3>
          <svg viewBox="0 0 850 350" className="w-full h-auto" style={{ minHeight: 300 }}>
            {/* Grid */}
            <defs>
              <pattern id="grid" width="50" height="50" patternUnits="userSpaceOnUse">
                <path d="M 50 0 L 0 0 0 50" fill="none" stroke="rgba(0,229,255,0.05)" strokeWidth="0.5" />
              </pattern>
            </defs>
            <rect width="850" height="350" fill="url(#grid)" />

            {/* Edges */}
            {MOCK_SURFACE_EDGES.map((edge, i) => {
              const from = MOCK_SURFACE_NODES.find((n) => n.id === edge.from);
              const to = MOCK_SURFACE_NODES.find((n) => n.id === edge.to);
              if (!from || !to) return null;
              const isHostToHost = from.type === "host" && to.type === "host";
              return (
                <line
                  key={i}
                  x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                  stroke={isHostToHost ? "rgba(239,68,68,0.3)" : "rgba(0,229,255,0.15)"}
                  strokeWidth={isHostToHost ? 2 : 1}
                  strokeDasharray={isHostToHost ? "5,5" : "none"}
                />
              );
            })}

            {/* Nodes */}
            {MOCK_SURFACE_NODES.map((node) => {
              const size = node.type === "host" ? 24 : node.type === "service" ? 20 : 16;
              const fill = node.type === "host" ? "rgba(0,229,255,0.15)" : node.type === "service" ? "rgba(16,185,129,0.15)" : "rgba(156,163,175,0.1)";
              const stroke = node.type === "host" ? "rgba(0,229,255,0.5)" : node.type === "service" ? "rgba(16,185,129,0.5)" : "rgba(156,163,175,0.3)";
              const textColor = node.type === "host" ? "#00E5FF" : node.type === "service" ? "#10B981" : "#9CA3AF";
              return (
                <g key={node.id}>
                  <circle cx={node.x} cy={node.y} r={size} fill={fill} stroke={stroke} strokeWidth="1.5" />
                  {node.type === "host" && (
                    <circle cx={node.x} cy={node.y} r={size + 4} fill="none" stroke={stroke} strokeWidth="0.5" opacity="0.3">
                      <animate attributeName="r" values={`${size + 2};${size + 8};${size + 2}`} dur="2s" repeatCount="indefinite" />
                      <animate attributeName="opacity" values="0.3;0;0.3" dur="2s" repeatCount="indefinite" />
                    </circle>
                  )}
                  <text
                    x={node.x} y={node.y + size + 14}
                    textAnchor="middle" fill={textColor}
                    fontSize="9" fontFamily="JetBrains Mono, monospace"
                  >
                    {node.label}
                  </text>
                </g>
              );
            })}

            {/* Legend */}
            <g transform="translate(20, 310)">
              <circle cx="8" cy="0" r="6" fill="rgba(0,229,255,0.15)" stroke="rgba(0,229,255,0.5)" strokeWidth="1" />
              <text x="20" y="4" fill="#9CA3AF" fontSize="8" fontFamily="JetBrains Mono, monospace">Host</text>
              <circle cx="68" cy="0" r="5" fill="rgba(156,163,175,0.1)" stroke="rgba(156,163,175,0.3)" strokeWidth="1" />
              <text x="78" y="4" fill="#9CA3AF" fontSize="8" fontFamily="JetBrains Mono, monospace">Port</text>
              <circle cx="128" cy="0" r="5" fill="rgba(16,185,129,0.15)" stroke="rgba(16,185,129,0.5)" strokeWidth="1" />
              <text x="138" y="4" fill="#9CA3AF" fontSize="8" fontFamily="JetBrains Mono, monospace">Service</text>
              <line x1="188" y1="-2" x2="208" y2="-2" stroke="rgba(239,68,68,0.3)" strokeWidth="2" strokeDasharray="5,5" />
              <text x="213" y="2" fill="#9CA3AF" fontSize="8" fontFamily="JetBrains Mono, monospace">Lateral</text>
            </g>
          </svg>
        </div>
      )}

      {/* ================================================================== */}
      {/*  Report View                                                       */}
      {/* ================================================================== */}
      {activeView === "report" && (
        <div className="space-y-6">
          {/* Executive Summary */}
          <div className="glass-panel border border-cyan-glow/10 p-6">
            <h3 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Executive Summary
            </h3>
            <div className="grid grid-cols-3 gap-6">
              <div className="col-span-2">
                <p className="text-xs leading-relaxed text-gray-400">
                  The penetration test of <span className="text-cyan-glow">192.168.1.0/24</span> identified{" "}
                  <span className="text-red-400 font-bold">{MOCK_FINDINGS.filter((f) => f.severity === "critical").length} critical</span> and{" "}
                  <span className="text-orange-400 font-bold">{MOCK_FINDINGS.filter((f) => f.severity === "high").length} high</span> severity
                  vulnerabilities across {metrics.hosts} hosts. Critical findings include SQL Injection allowing full database access and
                  SSRF enabling internal network pivoting with AWS metadata extraction. Immediate remediation is recommended for all
                  critical and high severity findings.
                </p>
                <div className="mt-4 grid grid-cols-4 gap-2">
                  <div className="rounded border border-red-500/20 bg-red-500/5 p-2 text-center">
                    <p className="text-lg font-bold text-red-400" style={{ fontFamily: "Orbitron, sans-serif" }}>
                      {findingsGrouped.critical || 0}
                    </p>
                    <p className="text-[8px] uppercase text-red-400/60">Critical</p>
                  </div>
                  <div className="rounded border border-orange-500/20 bg-orange-500/5 p-2 text-center">
                    <p className="text-lg font-bold text-orange-400" style={{ fontFamily: "Orbitron, sans-serif" }}>
                      {findingsGrouped.high || 0}
                    </p>
                    <p className="text-[8px] uppercase text-orange-400/60">High</p>
                  </div>
                  <div className="rounded border border-yellow-500/20 bg-yellow-500/5 p-2 text-center">
                    <p className="text-lg font-bold text-yellow-400" style={{ fontFamily: "Orbitron, sans-serif" }}>
                      {findingsGrouped.medium || 0}
                    </p>
                    <p className="text-[8px] uppercase text-yellow-400/60">Medium</p>
                  </div>
                  <div className="rounded border border-blue-500/20 bg-blue-500/5 p-2 text-center">
                    <p className="text-lg font-bold text-blue-400" style={{ fontFamily: "Orbitron, sans-serif" }}>
                      {findingsGrouped.low || 0}
                    </p>
                    <p className="text-[8px] uppercase text-blue-400/60">Low</p>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-center">
                <RiskGauge level="Critical" />
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping */}
          <div className="glass-panel border border-cyan-glow/10 p-6">
            <h3 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              MITRE ATT&CK Mapping
            </h3>
            <div className="grid grid-cols-5 gap-3">
              {MITRE_MAPPING.map((tactic) => (
                <div key={tactic.tactic} className="rounded border border-cyan-glow/10 bg-cyan-glow/5 p-3">
                  <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-cyan-glow/60">{tactic.tactic}</p>
                  <div className="space-y-1.5">
                    {tactic.techniques.map((tech) => (
                      <div
                        key={tech.id}
                        className={`rounded border px-2 py-1.5 text-[8px] font-mono ${
                          tech.findings > 0
                            ? "border-red-500/30 bg-red-500/10 text-red-400"
                            : "border-gray-700 bg-gray-900/50 text-gray-500"
                        }`}
                      >
                        <div className="font-bold">{tech.id}</div>
                        <div className="text-[7px] opacity-70">{tech.name}</div>
                        {tech.findings > 0 && (
                          <div className="mt-0.5 text-[7px]">{tech.findings} finding{tech.findings > 1 ? "s" : ""}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Remediation Roadmap */}
          <div className="glass-panel border border-cyan-glow/10 p-6">
            <h3 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Remediation Roadmap
            </h3>
            <div className="space-y-2">
              {MOCK_REMEDIATIONS.map((r) => (
                <div key={r.priority} className="flex items-center gap-4 rounded border border-gray-700/30 bg-gray-900/30 px-4 py-3">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full border border-cyan-glow/20 bg-cyan-glow/5 text-[10px] font-bold text-cyan-glow">
                    {r.priority}
                  </div>
                  <div className="flex-1">
                    <span className="text-xs font-medium text-gray-200">{r.finding}</span>
                    <p className="text-[10px] text-gray-500">{r.action}</p>
                  </div>
                  <Badge
                    text={r.effort}
                    cls={
                      r.effort === "low"
                        ? "bg-green-500/15 text-green-400 border-green-500/30"
                        : r.effort === "medium"
                        ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
                        : "bg-red-500/15 text-red-400 border-red-500/30"
                    }
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Export buttons */}
          <div className="flex justify-end gap-3">
            {["PDF", "JSON", "CSV", "SARIF"].map((fmt) => (
              <button
                key={fmt}
                className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-6 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15 hover:shadow-cyan-sm"
              >
                EXPORT {fmt}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
