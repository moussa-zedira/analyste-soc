"use client";

import { useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type ScanType = "sast" | "sca" | "secrets" | "dast" | "container" | "iac" | "full";
type Severity = "critical" | "high" | "medium" | "low";

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  file: string;
  line: number;
  snippet: string;
  remediation: string;
  expanded?: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const SCAN_TABS: { key: ScanType; label: string; desc: string }[] = [
  { key: "sast", label: "SAST", desc: "Static Application Security Testing" },
  { key: "sca", label: "SCA", desc: "Software Composition Analysis" },
  { key: "secrets", label: "SECRETS", desc: "Secret Detection in Source Code" },
  { key: "dast", label: "DAST", desc: "Dynamic Application Security Testing" },
  { key: "container", label: "CONTAINER", desc: "Container Image Scanning" },
  { key: "iac", label: "IaC", desc: "Infrastructure as Code Analysis" },
  { key: "full", label: "FULL SCAN", desc: "Run All Scan Types" },
];

const SEV_BG: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
};

// ---------------------------------------------------------------------------
// Demo Findings
// ---------------------------------------------------------------------------
function generateFindings(): Finding[] {
  return [
    { id: "sf1", title: "SQL Injection via string concatenation", severity: "critical", cwe: "CWE-89", file: "src/api/users.py", line: 45, snippet: 'query = f"SELECT * FROM users WHERE id = {user_id}"', remediation: "Use parameterized queries instead of string concatenation. Replace with: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))" },
    { id: "sf2", title: "Hardcoded AWS Secret Key", severity: "critical", cwe: "CWE-798", file: "config/settings.py", line: 12, snippet: 'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', remediation: "Remove hardcoded secrets. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault)." },
    { id: "sf3", title: "Cross-Site Scripting (Reflected)", severity: "high", cwe: "CWE-79", file: "src/views/search.tsx", line: 23, snippet: '<div dangerouslySetInnerHTML={{__html: userInput}} />', remediation: "Sanitize user input before rendering. Use DOMPurify or React's built-in XSS protection by removing dangerouslySetInnerHTML." },
    { id: "sf4", title: "Insecure Deserialization", severity: "high", cwe: "CWE-502", file: "src/utils/cache.py", line: 67, snippet: 'data = pickle.loads(raw_data)', remediation: "Never deserialize untrusted data with pickle. Use JSON or a safe serialization format." },
    { id: "sf5", title: "Vulnerable dependency: lodash@4.17.20", severity: "high", cwe: "CWE-1321", file: "package.json", line: 15, snippet: '"lodash": "^4.17.20"', remediation: "Upgrade lodash to 4.17.21 or later. Run: npm install lodash@latest" },
    { id: "sf6", title: "Missing CSRF Protection", severity: "medium", cwe: "CWE-352", file: "src/middleware/auth.py", line: 34, snippet: '# TODO: add CSRF token validation', remediation: "Implement CSRF token validation for all state-changing requests. Use framework-provided CSRF middleware." },
    { id: "sf7", title: "Open S3 Bucket Policy", severity: "high", cwe: "CWE-284", file: "terraform/s3.tf", line: 8, snippet: 'acl = "public-read"', remediation: "Remove public-read ACL. Use bucket policies with explicit access controls and enable S3 Block Public Access." },
    { id: "sf8", title: "Container running as root", severity: "medium", cwe: "CWE-250", file: "Dockerfile", line: 1, snippet: 'FROM python:3.11\n# No USER directive', remediation: "Add a non-root USER directive: RUN adduser --disabled-password appuser && USER appuser" },
    { id: "sf9", title: "Weak TLS Configuration", severity: "medium", cwe: "CWE-326", file: "terraform/alb.tf", line: 22, snippet: 'ssl_policy = "ELBSecurityPolicy-2016-08"', remediation: "Use a modern TLS policy: ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"" },
    { id: "sf10", title: "Debug mode enabled in production", severity: "low", cwe: "CWE-489", file: "src/app.py", line: 5, snippet: 'app.run(debug=True)', remediation: "Disable debug mode in production. Use environment-based configuration." },
  ];
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function SecurityScannerPage() {
  const [activeScan, setActiveScan] = useState<ScanType>("sast");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [qualityGate, setQualityGate] = useState<"pass" | "fail" | null>(null);
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  // Config states
  const [repoPath, setRepoPath] = useState("");
  const [language, setLanguage] = useState("python");
  const [targetUrl, setTargetUrl] = useState("");
  const [imageName, setImageName] = useState("");
  const [iacType, setIacType] = useState("terraform");
  const [includeGitHistory, setIncludeGitHistory] = useState(false);

  const handleScan = useCallback(async () => {
    setScanning(true);
    setProgress(0);
    setFindings([]);
    setQualityGate(null);
    for (let i = 0; i <= 100; i += 5) {
      await new Promise(r => setTimeout(r, 150));
      setProgress(i);
    }
    const results = generateFindings();
    setFindings(results);
    const critCount = results.filter(f => f.severity === "critical").length;
    setQualityGate(critCount > 0 ? "fail" : "pass");
    setScanning(false);
  }, []);

  const toggleExpand = useCallback((id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const handleExport = useCallback((format: "sarif" | "junit" | "csv" | "pdf") => {
    let content = "";
    let filename = "";
    let mime = "";
    if (format === "csv") {
      content = "title,severity,cwe,file,line,remediation\n" + findings.map(f => `"${f.title}","${f.severity}","${f.cwe}","${f.file}",${f.line},"${f.remediation}"`).join("\n");
      filename = "scan-results.csv"; mime = "text/csv";
    } else if (format === "sarif") {
      const sarif = { "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", version: "2.1.0", runs: [{ tool: { driver: { name: "CyberDef Scanner" } }, results: findings.map(f => ({ ruleId: f.cwe, message: { text: f.title }, level: f.severity === "critical" || f.severity === "high" ? "error" : "warning", locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }] })) }] };
      content = JSON.stringify(sarif, null, 2); filename = "scan-results.sarif"; mime = "application/json";
    } else if (format === "junit") {
      content = `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites tests="${findings.length}">\n<testsuite name="Security Scan">\n${findings.map(f => `  <testcase name="${f.cwe}: ${f.title}" classname="${f.file}"><failure message="${f.title}" type="${f.severity}">${f.remediation}</failure></testcase>`).join("\n")}\n</testsuite>\n</testsuites>`;
      filename = "scan-results.xml"; mime = "application/xml";
    } else {
      window.print(); return;
    }
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
  }, [findings]);

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
          Security Scanner
        </h1>
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
          SAST // SCA // SECRETS // DAST // CONTAINER // IaC
        </p>
      </div>
      <div className="cyan-line" />

      {/* Scan Type Tabs */}
      <div className="flex flex-wrap gap-2">
        {SCAN_TABS.map(tab => (
          <button key={tab.key} onClick={() => setActiveScan(tab.key)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${activeScan === tab.key ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500 hover:border-gray-600"}`}>
            {tab.label}
          </button>
        ))}
      </div>

      {/* Scan Config */}
      <div className="glass-panel p-4 space-y-3">
        <h3 className="text-[10px] font-bold tracking-widest text-gray-500">
          {SCAN_TABS.find(t => t.key === activeScan)?.desc}
        </h3>

        {(activeScan === "sast" || activeScan === "full") && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">REPO PATH / URL</label>
              <input type="text" value={repoPath} onChange={e => setRepoPath(e.target.value)} placeholder="https://github.com/org/repo or /path/to/repo" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">LANGUAGE</label>
              <select value={language} onChange={e => setLanguage(e.target.value)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                {["python", "javascript", "typescript", "go", "java", "kotlin", "rust", "c#", "ruby", "php"].map(l => <option key={l} value={l}>{l}</option>)}
              </select>
            </div>
          </div>
        )}

        {activeScan === "sca" && (
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">DEPENDENCY FILE PATH</label>
            <input type="text" value={repoPath} onChange={e => setRepoPath(e.target.value)} placeholder="package.json, requirements.txt, go.mod, pom.xml..." className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
        )}

        {activeScan === "secrets" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">REPO PATH</label>
              <input type="text" value={repoPath} onChange={e => setRepoPath(e.target.value)} placeholder="/path/to/repo" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={includeGitHistory} onChange={e => setIncludeGitHistory(e.target.checked)} className="rounded border-gray-600 bg-gray-900 text-cyan-glow focus:ring-cyan-glow/30" />
                <span className="text-[10px] font-bold tracking-widest text-gray-400">INCLUDE GIT HISTORY</span>
              </label>
            </div>
          </div>
        )}

        {activeScan === "dast" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TARGET URL</label>
              <input type="text" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} placeholder="https://target.example.com" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">AUTH CONFIG</label>
              <input type="text" placeholder="Bearer token or basic auth" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
          </div>
        )}

        {activeScan === "container" && (
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">DOCKERFILE PATH OR IMAGE NAME</label>
            <input type="text" value={imageName} onChange={e => setImageName(e.target.value)} placeholder="./Dockerfile or myregistry/myimage:latest" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
        )}

        {activeScan === "iac" && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">FILE PATH</label>
              <input type="text" value={repoPath} onChange={e => setRepoPath(e.target.value)} placeholder="./terraform/" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TYPE</label>
              <select value={iacType} onChange={e => setIacType(e.target.value)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                <option value="terraform">Terraform</option>
                <option value="kubernetes">Kubernetes</option>
                <option value="cloudformation">CloudFormation</option>
                <option value="ansible">Ansible</option>
              </select>
            </div>
          </div>
        )}

        <button onClick={handleScan} disabled={scanning} className={`rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50 ${scanning ? "animate-pulse" : ""}`}>
          {scanning ? `SCANNING... ${progress}%` : "RUN SCAN"}
        </button>

        {/* Progress */}
        {scanning && (
          <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
            <div className="h-full bg-cyan-glow rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
        )}
      </div>

      {/* Quality Gate Banner */}
      {qualityGate && (
        <div className={`glass-panel p-4 flex items-center gap-3 ${qualityGate === "pass" ? "border-green-500/30" : "border-red-500/30"}`}>
          <div className={`h-10 w-10 rounded-full flex items-center justify-center ${qualityGate === "pass" ? "bg-green-500/15" : "bg-red-500/15"}`}>
            {qualityGate === "pass" ? (
              <svg className="h-6 w-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
            ) : (
              <svg className="h-6 w-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            )}
          </div>
          <div>
            <p className={`text-sm font-bold ${qualityGate === "pass" ? "text-green-400" : "text-red-400"}`}>
              Quality Gate: {qualityGate.toUpperCase()}
            </p>
            <p className="text-[10px] text-gray-500">
              {qualityGate === "pass" ? "No critical findings detected. Pipeline can proceed." : "Critical findings detected. Fix before merging."}
            </p>
          </div>
        </div>
      )}

      {/* Results */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-[10px] font-bold tracking-widest text-gray-500">SCAN RESULTS ({findings.length} FINDINGS)</p>
            <div className="flex gap-2">
              {(["sarif", "junit", "csv", "pdf"] as const).map(f => (
                <button key={f} onClick={() => handleExport(f)} className="glass-panel px-3 py-1.5 text-[10px] font-bold text-gray-400 hover:text-cyan-glow transition-colors">{f.toUpperCase()}</button>
              ))}
            </div>
          </div>

          <div className="glass-panel overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">SEVERITY</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">TITLE</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">CWE</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">LOCATION</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.id} className="border-b border-gray-800/50">
                    <td colSpan={4} className="px-0 py-0">
                      <div className="cursor-pointer hover:bg-cyan-glow/5 px-4 py-3 flex items-center gap-0 transition-colors" onClick={() => toggleExpand(f.id)}>
                        <div className="w-[80px] shrink-0">
                          <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${SEV_BG[f.severity]}`}>{f.severity.toUpperCase()}</span>
                        </div>
                        <div className="flex-1 min-w-0">
                          <span className="text-gray-200">{f.title}</span>
                        </div>
                        <div className="w-[80px] shrink-0 text-center">
                          <a href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-", "")}.html`} target="_blank" rel="noopener noreferrer" className="text-cyan-glow/60 hover:text-cyan-glow font-mono text-[10px]" onClick={e => e.stopPropagation()}>{f.cwe}</a>
                        </div>
                        <div className="w-[160px] shrink-0 text-right">
                          <span className="text-gray-400 font-mono text-[10px]">{f.file}:{f.line}</span>
                        </div>
                      </div>
                      {expandedIds.has(f.id) && (
                        <div className="mx-4 mb-3 rounded border border-cyan-glow/10 bg-space-deep/50 p-4 space-y-3">
                          <div>
                            <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-1">CODE SNIPPET</p>
                            <pre className="rounded bg-space-deep p-3 text-[11px] text-cyan-glow/80 font-mono overflow-x-auto border border-cyan-glow/10">{f.snippet}</pre>
                          </div>
                          <div>
                            <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-1">REMEDIATION</p>
                            <p className="text-xs text-gray-400 leading-relaxed">{f.remediation}</p>
                          </div>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
