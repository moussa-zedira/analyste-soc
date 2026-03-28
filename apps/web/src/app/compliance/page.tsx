"use client";

import { useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Framework = "PCI-DSS" | "HIPAA" | "SOC2" | "ISO27001" | "NIST" | "GDPR";
type ControlStatus = "compliant" | "non-compliant" | "in-progress";

interface Control {
  id: string;
  name: string;
  description: string;
  status: ControlStatus;
  evidence: string[];
  remediation?: string;
  lastChecked: string;
}

interface FrameworkData {
  name: Framework;
  score: number;
  totalControls: number;
  compliant: number;
  inProgress: number;
  nonCompliant: number;
  controls: Control[];
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const FRAMEWORKS: FrameworkData[] = [
  {
    name: "PCI-DSS", score: 87, totalControls: 12, compliant: 9, inProgress: 2, nonCompliant: 1,
    controls: [
      { id: "1.1", name: "Install and maintain a firewall", description: "Network security controls to protect cardholder data", status: "compliant", evidence: ["Firewall rule review Q1", "Penetration test report"], lastChecked: "2026-03-25" },
      { id: "1.2", name: "Secure system defaults", description: "Change vendor-supplied defaults", status: "compliant", evidence: ["Hardening checklist"], lastChecked: "2026-03-20" },
      { id: "1.3", name: "Protect stored cardholder data", description: "Render stored PAN unreadable", status: "compliant", evidence: ["Encryption audit report"], lastChecked: "2026-03-22" },
      { id: "1.4", name: "Encrypt transmission", description: "Encrypt cardholder data across open networks", status: "compliant", evidence: ["TLS configuration scan"], lastChecked: "2026-03-24" },
      { id: "1.5", name: "Protect against malware", description: "Anti-malware software on all systems", status: "in-progress", evidence: ["EDR deployment 95%"], remediation: "Deploy EDR to 3 remaining hosts", lastChecked: "2026-03-28" },
      { id: "1.6", name: "Secure systems and applications", description: "Develop and maintain secure systems", status: "compliant", evidence: ["SAST/DAST results"], lastChecked: "2026-03-18" },
      { id: "1.7", name: "Restrict access", description: "Restrict access by business need-to-know", status: "compliant", evidence: ["RBAC review"], lastChecked: "2026-03-15" },
      { id: "1.8", name: "Identify and authenticate access", description: "Assign unique ID to each person", status: "compliant", evidence: ["MFA audit log"], lastChecked: "2026-03-20" },
      { id: "1.9", name: "Restrict physical access", description: "Restrict physical access to cardholder data", status: "non-compliant", evidence: [], remediation: "Install badge readers on server room B", lastChecked: "2026-03-10" },
      { id: "1.10", name: "Log and monitor access", description: "Track and monitor all access to network resources", status: "compliant", evidence: ["SIEM configuration review"], lastChecked: "2026-03-27" },
      { id: "1.11", name: "Test security systems", description: "Regularly test security systems and processes", status: "in-progress", evidence: ["Pentest scheduled for April"], remediation: "Complete external pentest", lastChecked: "2026-03-28" },
      { id: "1.12", name: "Maintain InfoSec policy", description: "Maintain a policy that addresses information security", status: "compliant", evidence: ["Policy v3.2 approved"], lastChecked: "2026-03-01" },
    ],
  },
  {
    name: "HIPAA", score: 72, totalControls: 8, compliant: 5, inProgress: 2, nonCompliant: 1,
    controls: [
      { id: "h1", name: "Access Control", description: "Unique user identification and emergency access", status: "compliant", evidence: ["IAM review"], lastChecked: "2026-03-25" },
      { id: "h2", name: "Audit Controls", description: "Implement hardware, software, and procedural audit mechanisms", status: "compliant", evidence: ["Audit log review"], lastChecked: "2026-03-20" },
      { id: "h3", name: "Integrity Controls", description: "Protect ePHI from improper alteration or destruction", status: "in-progress", evidence: ["Integrity monitoring 80%"], remediation: "Deploy FIM on remaining systems", lastChecked: "2026-03-22" },
      { id: "h4", name: "Transmission Security", description: "Protect ePHI during electronic transmission", status: "compliant", evidence: ["TLS audit"], lastChecked: "2026-03-18" },
      { id: "h5", name: "Risk Analysis", description: "Conduct accurate and thorough assessment of risks", status: "compliant", evidence: ["Annual risk assessment"], lastChecked: "2026-03-15" },
      { id: "h6", name: "Encryption", description: "Implement mechanism to encrypt ePHI", status: "non-compliant", evidence: [], remediation: "Encrypt database at rest", lastChecked: "2026-03-10" },
      { id: "h7", name: "Contingency Plan", description: "Establish policies for responding to emergencies", status: "in-progress", evidence: ["DR plan draft"], remediation: "Test DR runbook", lastChecked: "2026-03-12" },
      { id: "h8", name: "Workforce Training", description: "Security awareness training for workforce", status: "compliant", evidence: ["Training completion 98%"], lastChecked: "2026-03-28" },
    ],
  },
  {
    name: "SOC2", score: 91, totalControls: 5, compliant: 4, inProgress: 1, nonCompliant: 0,
    controls: [
      { id: "s1", name: "Security", description: "Protection of system resources against unauthorized access", status: "compliant", evidence: ["Access review Q1"], lastChecked: "2026-03-25" },
      { id: "s2", name: "Availability", description: "Accessibility of systems as committed", status: "compliant", evidence: ["99.99% uptime report"], lastChecked: "2026-03-28" },
      { id: "s3", name: "Processing Integrity", description: "System processing is complete and accurate", status: "compliant", evidence: ["Data validation audit"], lastChecked: "2026-03-20" },
      { id: "s4", name: "Confidentiality", description: "Information designated as confidential is protected", status: "in-progress", evidence: ["DLP deployment 90%"], remediation: "Configure DLP for email", lastChecked: "2026-03-22" },
      { id: "s5", name: "Privacy", description: "Personal information is collected and used appropriately", status: "compliant", evidence: ["Privacy impact assessment"], lastChecked: "2026-03-15" },
    ],
  },
  {
    name: "ISO27001", score: 78, totalControls: 6, compliant: 4, inProgress: 1, nonCompliant: 1,
    controls: [
      { id: "i1", name: "Information Security Policies", description: "Management direction for information security", status: "compliant", evidence: ["Policy v2.1 approved"], lastChecked: "2026-03-20" },
      { id: "i2", name: "Asset Management", description: "Inventory and acceptable use of assets", status: "compliant", evidence: ["Asset inventory complete"], lastChecked: "2026-03-22" },
      { id: "i3", name: "Access Control", description: "Limit access to information and processing facilities", status: "compliant", evidence: ["Access review Q1"], lastChecked: "2026-03-25" },
      { id: "i4", name: "Cryptography", description: "Proper and effective use of cryptography", status: "compliant", evidence: ["Crypto audit report"], lastChecked: "2026-03-18" },
      { id: "i5", name: "Operations Security", description: "Correct and secure operations of processing facilities", status: "non-compliant", evidence: [], remediation: "Implement change management process", lastChecked: "2026-03-10" },
      { id: "i6", name: "Supplier Relationships", description: "Protection of organization's assets accessible by suppliers", status: "in-progress", evidence: ["Vendor review 60%"], remediation: "Complete vendor security assessments", lastChecked: "2026-03-15" },
    ],
  },
  {
    name: "NIST", score: 82, totalControls: 5, compliant: 3, inProgress: 2, nonCompliant: 0,
    controls: [
      { id: "n1", name: "Identify", description: "Develop organizational understanding of cybersecurity risk", status: "compliant", evidence: ["Risk assessment"], lastChecked: "2026-03-25" },
      { id: "n2", name: "Protect", description: "Develop and implement safeguards", status: "compliant", evidence: ["Security controls review"], lastChecked: "2026-03-22" },
      { id: "n3", name: "Detect", description: "Develop and implement activities to identify cybersecurity events", status: "compliant", evidence: ["SIEM + EDR deployment"], lastChecked: "2026-03-28" },
      { id: "n4", name: "Respond", description: "Develop and implement activities for incident response", status: "in-progress", evidence: ["IR plan v2 draft"], remediation: "Run tabletop exercise", lastChecked: "2026-03-20" },
      { id: "n5", name: "Recover", description: "Develop and implement activities for resilience and restoration", status: "in-progress", evidence: ["BCP draft"], remediation: "Test recovery procedures", lastChecked: "2026-03-15" },
    ],
  },
  {
    name: "GDPR", score: 68, totalControls: 6, compliant: 3, inProgress: 1, nonCompliant: 2,
    controls: [
      { id: "g1", name: "Lawful Basis for Processing", description: "Ensure lawful basis for all data processing activities", status: "compliant", evidence: ["Data processing inventory"], lastChecked: "2026-03-20" },
      { id: "g2", name: "Data Subject Rights", description: "Implement mechanisms for data subject requests", status: "in-progress", evidence: ["Portal 70% complete"], remediation: "Complete self-service data portal", lastChecked: "2026-03-22" },
      { id: "g3", name: "Data Protection Officer", description: "Appoint and support a DPO", status: "compliant", evidence: ["DPO appointed"], lastChecked: "2026-03-01" },
      { id: "g4", name: "Data Breach Notification", description: "72-hour breach notification process", status: "compliant", evidence: ["Notification process tested"], lastChecked: "2026-03-15" },
      { id: "g5", name: "Privacy by Design", description: "Integrate data protection into processing activities", status: "non-compliant", evidence: [], remediation: "Implement PIA process for new projects", lastChecked: "2026-03-10" },
      { id: "g6", name: "International Transfers", description: "Safeguards for cross-border data transfers", status: "non-compliant", evidence: [], remediation: "Implement Standard Contractual Clauses", lastChecked: "2026-03-08" },
    ],
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const STATUS_COLORS: Record<ControlStatus, string> = {
  "compliant": "bg-green-500/15 text-green-400 border-green-500/30",
  "non-compliant": "bg-red-500/15 text-red-400 border-red-500/30",
  "in-progress": "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

function CircularProgress({ score, size = 100 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 85 ? "#22c55e" : score >= 70 ? "#eab308" : "#ef4444";

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6"
          strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.5s ease" }}
        />
      </svg>
      <span className="absolute text-lg font-bold" style={{ color, fontFamily: "Orbitron, sans-serif" }}>{score}%</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<Framework>("PCI-DSS");
  const [filterStatus, setFilterStatus] = useState<ControlStatus | "all">("all");

  const fw = FRAMEWORKS.find((f) => f.name === selectedFramework)!;
  const controls = fw.controls.filter((c) => filterStatus === "all" || c.status === filterStatus);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Compliance Dashboard
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            REGULATORY COMPLIANCE // CONTINUOUS MONITORING
          </p>
        </div>
        <button className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-md">
          EXPORT REPORT
        </button>
      </div>

      <div className="cyan-line" />

      {/* Framework Selector */}
      <div className="grid grid-cols-6 gap-3">
        {FRAMEWORKS.map((f) => (
          <button
            key={f.name}
            onClick={() => setSelectedFramework(f.name)}
            className={`glass-panel flex flex-col items-center border p-4 transition-all ${
              selectedFramework === f.name
                ? "border-cyan-glow/30 shadow-cyan-sm"
                : "border-cyan-glow/10 hover:border-cyan-glow/20"
            }`}
          >
            <CircularProgress score={f.score} size={70} />
            <span className="mt-2 text-[10px] font-bold tracking-wider text-gray-300">{f.name}</span>
            <span className="text-[8px] text-gray-600">{f.compliant}/{f.totalControls} controls</span>
          </button>
        ))}
      </div>

      {/* Gap Analysis */}
      <div className="grid grid-cols-4 gap-4">
        <div className="glass-panel border border-cyan-glow/20 p-4">
          <p className="text-[9px] uppercase tracking-wider text-gray-500">Overall Score</p>
          <p className="mt-1 text-2xl font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>{fw.score}%</p>
        </div>
        <div className="glass-panel border border-green-500/20 p-4">
          <p className="text-[9px] uppercase tracking-wider text-gray-500">Compliant</p>
          <p className="mt-1 text-2xl font-bold text-green-400" style={{ fontFamily: "Orbitron, sans-serif" }}>{fw.compliant}</p>
          <div className="mt-1 h-1 rounded-full bg-gray-800">
            <div className="h-1 rounded-full bg-green-500" style={{ width: `${(fw.compliant / fw.totalControls) * 100}%` }} />
          </div>
        </div>
        <div className="glass-panel border border-yellow-500/20 p-4">
          <p className="text-[9px] uppercase tracking-wider text-gray-500">In Progress</p>
          <p className="mt-1 text-2xl font-bold text-yellow-400" style={{ fontFamily: "Orbitron, sans-serif" }}>{fw.inProgress}</p>
          <div className="mt-1 h-1 rounded-full bg-gray-800">
            <div className="h-1 rounded-full bg-yellow-500" style={{ width: `${(fw.inProgress / fw.totalControls) * 100}%` }} />
          </div>
        </div>
        <div className="glass-panel border border-red-500/20 p-4">
          <p className="text-[9px] uppercase tracking-wider text-gray-500">Non-Compliant</p>
          <p className="mt-1 text-2xl font-bold text-red-400" style={{ fontFamily: "Orbitron, sans-serif" }}>{fw.nonCompliant}</p>
          <div className="mt-1 h-1 rounded-full bg-gray-800">
            <div className="h-1 rounded-full bg-red-500" style={{ width: `${(fw.nonCompliant / fw.totalControls) * 100}%` }} />
          </div>
        </div>
      </div>

      {/* Control Filters */}
      <div className="glass-panel flex items-center gap-4 p-3">
        <span className="text-[9px] uppercase tracking-wider text-gray-500">Filter by Status:</span>
        {(["all", "compliant", "non-compliant", "in-progress"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={`rounded border px-3 py-1 text-[9px] font-bold uppercase tracking-wider transition-all ${
              filterStatus === s
                ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                : "border-gray-700/50 text-gray-500 hover:text-gray-300"
            }`}
          >
            {s}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-gray-500">{controls.length} controls</span>
      </div>

      {/* Control Checklist */}
      <div className="space-y-3">
        {controls.map((ctrl) => (
          <div key={ctrl.id} className="glass-panel border border-cyan-glow/10 p-4 transition-all hover:border-cyan-glow/20">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] font-mono text-cyan-glow/50">{ctrl.id}</span>
                  <h3 className="text-xs font-bold text-gray-200">{ctrl.name}</h3>
                  <Badge text={ctrl.status} cls={STATUS_COLORS[ctrl.status]} />
                </div>
                <p className="mt-1 text-[10px] text-gray-500">{ctrl.description}</p>
                {ctrl.evidence.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    <span className="text-[8px] uppercase tracking-wider text-gray-600">Evidence:</span>
                    {ctrl.evidence.map((ev, i) => (
                      <span key={i} className="rounded bg-cyan-glow/5 px-2 py-0.5 text-[9px] text-cyan-glow/60">{ev}</span>
                    ))}
                  </div>
                )}
                {ctrl.remediation && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="text-[8px] uppercase tracking-wider text-yellow-500">Remediation:</span>
                    <span className="text-[10px] text-yellow-400/70">{ctrl.remediation}</span>
                  </div>
                )}
              </div>
              <span className="text-[9px] text-gray-600">Checked: {ctrl.lastChecked}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
