"use client";

import { useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
  sections: string[];
}

interface ReportHistory {
  id: string;
  name: string;
  template: string;
  dateRange: string;
  generatedAt: string;
  format: string;
  size: string;
  status: "ready" | "generating" | "failed";
}

interface ScheduledReport {
  id: string;
  name: string;
  template: string;
  schedule: string;
  lastRun: string;
  nextRun: string;
  recipients: string[];
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const TEMPLATES: ReportTemplate[] = [
  {
    id: "t1", name: "Executive Summary", description: "High-level security posture overview for leadership",
    icon: "M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5m.75-9l3-3 2.148 2.148A12.061 12.061 0 0116.5 7.605",
    sections: ["KPI Overview", "Incident Summary", "Threat Landscape", "Compliance Status", "Risk Score Trend"],
  },
  {
    id: "t2", name: "Incident Report", description: "Detailed incident analysis and response documentation",
    icon: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z",
    sections: ["Timeline", "Affected Assets", "IOC List", "Root Cause Analysis", "Remediation Actions", "Lessons Learned"],
  },
  {
    id: "t3", name: "Compliance Report", description: "Framework compliance status and gap analysis",
    icon: "M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z",
    sections: ["Framework Selection", "Control Status", "Gap Analysis", "Evidence Summary", "Remediation Plan"],
  },
  {
    id: "t4", name: "Pentest Report", description: "Penetration testing findings and risk assessment",
    icon: "M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z",
    sections: ["Scope", "Methodology", "Findings by Severity", "Attack Paths", "Technical Details", "Remediation Priority"],
  },
  {
    id: "t5", name: "Threat Landscape", description: "Current threat intelligence and trend analysis",
    icon: "M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3",
    sections: ["Top Threats", "IOC Statistics", "Attack Trends", "Adversary Profiles", "Recommended Actions"],
  },
];

const REPORT_HISTORY: ReportHistory[] = [
  { id: "rh-1", name: "Weekly Executive Summary", template: "Executive Summary", dateRange: "Mar 22-29, 2026", generatedAt: "2026-03-29 08:00", format: "PDF", size: "2.4 MB", status: "ready" },
  { id: "rh-2", name: "Incident #IR-2026-042", template: "Incident Report", dateRange: "Mar 28, 2026", generatedAt: "2026-03-28 16:30", format: "PDF", size: "1.8 MB", status: "ready" },
  { id: "rh-3", name: "PCI-DSS Q1 Compliance", template: "Compliance Report", dateRange: "Jan-Mar 2026", generatedAt: "2026-03-28 12:00", format: "PDF", size: "5.2 MB", status: "ready" },
  { id: "rh-4", name: "External Pentest Results", template: "Pentest Report", dateRange: "Mar 15-20, 2026", generatedAt: "2026-03-22 10:00", format: "PDF", size: "8.7 MB", status: "ready" },
  { id: "rh-5", name: "March Threat Landscape", template: "Threat Landscape", dateRange: "Mar 1-29, 2026", generatedAt: "2026-03-29 09:00", format: "HTML", size: "3.1 MB", status: "generating" },
  { id: "rh-6", name: "Failed: Custom Report", template: "Executive Summary", dateRange: "Mar 1-15, 2026", generatedAt: "2026-03-15 08:00", format: "PDF", size: "-", status: "failed" },
];

const SCHEDULED_REPORTS: ScheduledReport[] = [
  { id: "sr-1", name: "Weekly Executive Summary", template: "Executive Summary", schedule: "Every Monday 08:00", lastRun: "2026-03-29 08:00", nextRun: "2026-04-05 08:00", recipients: ["ciso@corp.com", "vp-security@corp.com"], enabled: true },
  { id: "sr-2", name: "Daily Incident Digest", template: "Incident Report", schedule: "Daily 06:00", lastRun: "2026-03-29 06:00", nextRun: "2026-03-30 06:00", recipients: ["soc-team@corp.com"], enabled: true },
  { id: "sr-3", name: "Monthly Compliance Check", template: "Compliance Report", schedule: "1st of month 09:00", lastRun: "2026-03-01 09:00", nextRun: "2026-04-01 09:00", recipients: ["compliance@corp.com", "audit@corp.com"], enabled: true },
  { id: "sr-4", name: "Quarterly Threat Report", template: "Threat Landscape", schedule: "1st Jan/Apr/Jul/Oct", lastRun: "2026-01-01 09:00", nextRun: "2026-04-01 09:00", recipients: ["security-all@corp.com"], enabled: false },
];

const EXPORT_FORMATS = ["PDF", "HTML", "CSV", "JSON"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const STATUS_COLORS: Record<string, string> = {
  ready: "bg-green-500/15 text-green-400 border-green-500/30",
  generating: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function ReportsPage() {
  const [activeTab, setActiveTab] = useState<"templates" | "history" | "scheduled" | "custom">("templates");
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [dateFrom, setDateFrom] = useState("2026-03-01");
  const [dateTo, setDateTo] = useState("2026-03-29");
  const [exportFormat, setExportFormat] = useState("PDF");
  const [customSections, setCustomSections] = useState<string[]>([]);

  const allSections = [...new Set(TEMPLATES.flatMap((t) => t.sections))];

  const toggleSection = (section: string) => {
    setCustomSections((prev) =>
      prev.includes(section) ? prev.filter((s) => s !== section) : [...prev, section]
    );
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Report Center
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            SECURITY REPORTS // GENERATION & SCHEDULING
          </p>
        </div>
        <div className="flex gap-2">
          {(["templates", "history", "scheduled", "custom"] as const).map((tab) => (
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

      {activeTab === "templates" && (
        <>
          {/* Template Grid */}
          <div className="grid grid-cols-3 gap-4">
            {TEMPLATES.map((t) => (
              <div
                key={t.id}
                className={`glass-panel cursor-pointer border p-5 transition-all ${
                  selectedTemplate === t.id
                    ? "border-cyan-glow/30 shadow-cyan-sm"
                    : "border-cyan-glow/10 hover:border-cyan-glow/20"
                }`}
                onClick={() => setSelectedTemplate(t.id)}
              >
                <div className="mb-3 flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-cyan-glow/20 bg-cyan-glow/5">
                    <svg className="h-5 w-5 text-cyan-glow" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" d={t.icon} />
                    </svg>
                  </div>
                  <h3 className="text-sm font-bold text-gray-200">{t.name}</h3>
                </div>
                <p className="text-[10px] text-gray-500">{t.description}</p>
                <div className="mt-3 flex flex-wrap gap-1">
                  {t.sections.map((s) => (
                    <span key={s} className="rounded bg-cyan-glow/5 px-2 py-0.5 text-[8px] text-cyan-glow/50">{s}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Generate Report */}
          {selectedTemplate && (
            <div className="glass-panel border border-cyan-glow/20 p-5">
              <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Generate Report</h3>
              <div className="grid grid-cols-4 gap-4">
                <div>
                  <label className="text-[9px] uppercase tracking-wider text-gray-500">Template</label>
                  <p className="mt-1 text-xs font-bold text-gray-200">{TEMPLATES.find((t) => t.id === selectedTemplate)?.name}</p>
                </div>
                <div>
                  <label className="text-[9px] uppercase tracking-wider text-gray-500">From Date</label>
                  <input
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none"
                  />
                </div>
                <div>
                  <label className="text-[9px] uppercase tracking-wider text-gray-500">To Date</label>
                  <input
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none"
                  />
                </div>
                <div>
                  <label className="text-[9px] uppercase tracking-wider text-gray-500">Format</label>
                  <div className="mt-1 flex gap-2">
                    {EXPORT_FORMATS.map((fmt) => (
                      <button
                        key={fmt}
                        onClick={() => setExportFormat(fmt)}
                        className={`rounded border px-3 py-2 text-[10px] font-bold transition-all ${
                          exportFormat === fmt
                            ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                            : "border-gray-700/50 text-gray-500 hover:text-gray-300"
                        }`}
                      >
                        {fmt}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
              <button className="mt-4 rounded border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md">
                GENERATE REPORT
              </button>
            </div>
          )}
        </>
      )}

      {activeTab === "history" && (
        <div className="glass-panel overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyan-glow/10">
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Report Name</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Template</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Date Range</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Generated</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Format</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Size</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Actions</th>
              </tr>
            </thead>
            <tbody>
              {REPORT_HISTORY.map((rh) => (
                <tr key={rh.id} className="border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5">
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{rh.name}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-400">{rh.template}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-400">{rh.dateRange}</td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{rh.generatedAt}</td>
                  <td className="px-4 py-3"><Badge text={rh.format} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" /></td>
                  <td className="px-4 py-3 text-[10px] text-gray-500">{rh.size}</td>
                  <td className="px-4 py-3"><Badge text={rh.status} cls={STATUS_COLORS[rh.status]} /></td>
                  <td className="px-4 py-3">
                    {rh.status === "ready" && (
                      <button className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15">
                        DOWNLOAD
                      </button>
                    )}
                    {rh.status === "generating" && (
                      <span className="text-[9px] text-cyan-glow/50 animate-pulse">Processing...</span>
                    )}
                    {rh.status === "failed" && (
                      <button className="rounded border border-red-500/20 bg-red-500/5 px-3 py-1 text-[9px] font-bold uppercase tracking-wider text-red-400 hover:bg-red-500/15">
                        RETRY
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "scheduled" && (
        <div className="space-y-3">
          {SCHEDULED_REPORTS.map((sr) => (
            <div key={sr.id} className="glass-panel border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/20">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <h3 className="text-xs font-bold text-gray-200">{sr.name}</h3>
                    <Badge text={sr.template} cls="bg-cyan-glow/10 text-cyan-glow/60 border-cyan-glow/20" />
                    <Badge
                      text={sr.enabled ? "ACTIVE" : "PAUSED"}
                      cls={sr.enabled ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-gray-500/15 text-gray-400 border-gray-500/30"}
                    />
                  </div>
                  <div className="mt-2 flex items-center gap-6 text-[10px] text-gray-500">
                    <span>Schedule: <span className="text-gray-400">{sr.schedule}</span></span>
                    <span>Last: <span className="font-mono text-gray-400">{sr.lastRun}</span></span>
                    <span>Next: <span className="font-mono text-gray-400">{sr.nextRun}</span></span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-[9px] text-gray-600">
                    <span>Recipients:</span>
                    {sr.recipients.map((r) => (
                      <span key={r} className="rounded bg-cyan-glow/5 px-1.5 py-0.5 text-cyan-glow/50">{r}</span>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button className="rounded border border-cyan-glow/20 bg-cyan-glow/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/15">
                    EDIT
                  </button>
                  <button className="rounded border border-green-500/20 bg-green-500/5 px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider text-green-400 hover:bg-green-500/15">
                    RUN NOW
                  </button>
                  <button className={`rounded border px-3 py-1.5 text-[9px] font-bold uppercase tracking-wider ${
                    sr.enabled ? "border-red-500/20 text-red-400 hover:bg-red-500/10" : "border-green-500/20 text-green-400 hover:bg-green-500/10"
                  }`}>
                    {sr.enabled ? "PAUSE" : "ENABLE"}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === "custom" && (
        <div className="glass-panel border border-cyan-glow/20 p-6">
          <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Custom Report Builder</h3>
          <div className="grid grid-cols-2 gap-6">
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Report Name</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="Custom Security Report" />

              <label className="mt-4 block text-[9px] uppercase tracking-wider text-gray-500">Date Range</label>
              <div className="mt-1 flex gap-2">
                <input type="date" defaultValue="2026-03-01" className="flex-1 rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none" />
                <input type="date" defaultValue="2026-03-29" className="flex-1 rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none" />
              </div>

              <label className="mt-4 block text-[9px] uppercase tracking-wider text-gray-500">Export Format</label>
              <div className="mt-1 flex gap-2">
                {EXPORT_FORMATS.map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setExportFormat(fmt)}
                    className={`rounded border px-3 py-1.5 text-[10px] font-bold transition-all ${
                      exportFormat === fmt
                        ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                        : "border-gray-700/50 text-gray-500 hover:text-gray-300"
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Select Sections</label>
              <div className="mt-2 grid grid-cols-2 gap-2">
                {allSections.map((section) => (
                  <button
                    key={section}
                    onClick={() => toggleSection(section)}
                    className={`rounded border p-2 text-left text-[10px] transition-all ${
                      customSections.includes(section)
                        ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                        : "border-gray-700/50 text-gray-500 hover:border-cyan-glow/20 hover:text-gray-300"
                    }`}
                  >
                    <span className="mr-2">{customSections.includes(section) ? "[x]" : "[ ]"}</span>
                    {section}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-6 flex items-center gap-4">
            <button className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md">
              GENERATE CUSTOM REPORT
            </button>
            <span className="text-[10px] text-gray-500">
              {customSections.length} sections selected
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
