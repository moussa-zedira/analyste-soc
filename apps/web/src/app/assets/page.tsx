"use client";

import { useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Criticality = "critical" | "high" | "medium" | "low";

interface Asset {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  owner: string;
  criticality: Criticality;
  lastSeen: string;
  vulnCount: number;
  group: string;
  tags: string[];
  autoDiscovered: boolean;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------
const ASSETS: Asset[] = [
  { id: "a1", hostname: "dc-01.corp.local", ip: "10.0.1.1", os: "Windows Server 2022", owner: "IT Infra", criticality: "critical", lastSeen: "2 min ago", vulnCount: 3, group: "Domain Controllers", tags: ["AD", "DNS"], autoDiscovered: false },
  { id: "a2", hostname: "web-prod-01", ip: "10.0.2.10", os: "Ubuntu 22.04", owner: "DevOps", criticality: "critical", lastSeen: "1 min ago", vulnCount: 7, group: "Web Servers", tags: ["nginx", "production"], autoDiscovered: true },
  { id: "a3", hostname: "db-master", ip: "10.0.3.5", os: "CentOS 8", owner: "DBA Team", criticality: "critical", lastSeen: "5 min ago", vulnCount: 2, group: "Databases", tags: ["postgresql", "production"], autoDiscovered: false },
  { id: "a4", hostname: "mail-01.corp.local", ip: "10.0.1.15", os: "Windows Server 2019", owner: "IT Infra", criticality: "high", lastSeen: "3 min ago", vulnCount: 5, group: "Email", tags: ["exchange", "SMTP"], autoDiscovered: false },
  { id: "a5", hostname: "vpn-gw-01", ip: "10.0.0.1", os: "PAN-OS 11", owner: "Network", criticality: "high", lastSeen: "1 min ago", vulnCount: 1, group: "Network Devices", tags: ["VPN", "firewall"], autoDiscovered: true },
  { id: "a6", hostname: "ci-runner-01", ip: "10.0.5.20", os: "Ubuntu 24.04", owner: "DevOps", criticality: "medium", lastSeen: "10 min ago", vulnCount: 4, group: "CI/CD", tags: ["gitlab-runner"], autoDiscovered: true },
  { id: "a7", hostname: "ws-jdoe-01", ip: "192.168.1.50", os: "Windows 11", owner: "John Doe", criticality: "low", lastSeen: "1h ago", vulnCount: 2, group: "Workstations", tags: ["finance"], autoDiscovered: true },
  { id: "a8", hostname: "ws-asmith-02", ip: "192.168.1.55", os: "macOS Sonoma", owner: "Alice Smith", criticality: "low", lastSeen: "30 min ago", vulnCount: 0, group: "Workstations", tags: ["engineering"], autoDiscovered: true },
  { id: "a9", hostname: "k8s-node-01", ip: "10.0.6.10", os: "Ubuntu 22.04", owner: "DevOps", criticality: "high", lastSeen: "2 min ago", vulnCount: 6, group: "Kubernetes", tags: ["k8s", "production"], autoDiscovered: true },
  { id: "a10", hostname: "nas-backup-01", ip: "10.0.4.50", os: "Synology DSM 7", owner: "IT Infra", criticality: "high", lastSeen: "5 min ago", vulnCount: 1, group: "Storage", tags: ["backup", "NFS"], autoDiscovered: false },
  { id: "a11", hostname: "api-gw-01", ip: "10.0.2.20", os: "Alpine Linux", owner: "DevOps", criticality: "critical", lastSeen: "1 min ago", vulnCount: 3, group: "Web Servers", tags: ["kong", "API"], autoDiscovered: true },
  { id: "a12", hostname: "siem-01", ip: "10.0.7.5", os: "Ubuntu 22.04", owner: "SOC", criticality: "critical", lastSeen: "1 min ago", vulnCount: 0, group: "Security", tags: ["SIEM", "elk"], autoDiscovered: false },
];

const GROUPS = [...new Set(ASSETS.map((a) => a.group))].sort();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const CRIT_COLORS: Record<Criticality, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const CRIT_DOT: Record<Criticality, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

// Simplified topology data
const TOPOLOGY_NODES = [
  { id: "internet", x: 300, y: 30, label: "INTERNET", color: "#ef4444" },
  { id: "fw", x: 300, y: 100, label: "FIREWALL", color: "#f59e0b" },
  { id: "dmz", x: 150, y: 180, label: "DMZ", color: "#22d3ee" },
  { id: "core", x: 300, y: 180, label: "CORE", color: "#22c55e" },
  { id: "mgmt", x: 450, y: 180, label: "MGMT", color: "#a855f7" },
  { id: "web", x: 80, y: 260, label: "WEB (3)", color: "#22d3ee" },
  { id: "db", x: 220, y: 260, label: "DB (2)", color: "#22c55e" },
  { id: "k8s", x: 340, y: 260, label: "K8S (4)", color: "#22c55e" },
  { id: "ws", x: 460, y: 260, label: "WS (12)", color: "#a855f7" },
];

const TOPOLOGY_EDGES = [
  ["internet", "fw"], ["fw", "dmz"], ["fw", "core"], ["fw", "mgmt"],
  ["dmz", "web"], ["core", "db"], ["core", "k8s"], ["mgmt", "ws"],
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function AssetsPage() {
  const [activeTab, setActiveTab] = useState<"list" | "matrix" | "topology">("list");
  const [filterGroup, setFilterGroup] = useState<string>("all");
  const [filterCriticality, setFilterCriticality] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);

  const filtered = ASSETS.filter((a) => {
    if (filterGroup !== "all" && a.group !== filterGroup) return false;
    if (filterCriticality !== "all" && a.criticality !== filterCriticality) return false;
    if (searchTerm && !a.hostname.toLowerCase().includes(searchTerm.toLowerCase()) && !a.ip.includes(searchTerm)) return false;
    return true;
  });

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Asset Inventory
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            INFRASTRUCTURE ASSETS // VULNERABILITY TRACKING
          </p>
        </div>
        <div className="flex gap-2">
          {(["list", "matrix", "topology"] as const).map((tab) => (
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
          <button
            onClick={() => setShowAddForm(!showAddForm)}
            className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20"
          >
            + ADD ASSET
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Add Asset Form */}
      {showAddForm && (
        <div className="glass-panel border border-cyan-glow/20 p-4">
          <h3 className="mb-3 text-xs font-bold text-cyan-glow">Add / Import Asset</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Hostname</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="server-01.corp.local" />
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">IP Address</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="10.0.0.1" />
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">OS</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="Ubuntu 22.04" />
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Owner</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="Team name" />
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Criticality</label>
              <select className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-300 outline-none">
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div>
              <label className="text-[9px] uppercase tracking-wider text-gray-500">Group</label>
              <input className="mt-1 w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-glow/50" placeholder="Web Servers" />
            </div>
          </div>
          <div className="mt-4 flex gap-2">
            <button className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow hover:bg-cyan-glow/20">
              ADD
            </button>
            <button className="rounded border border-blue-500/20 bg-blue-500/5 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-blue-400 hover:bg-blue-500/15">
              IMPORT CSV
            </button>
            <button onClick={() => setShowAddForm(false)} className="rounded border border-gray-700 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-500 hover:text-gray-300">
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="glass-panel flex items-center gap-4 p-3">
        <input
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Search hostname or IP..."
          className="w-64 rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] font-mono text-gray-200 outline-none focus:border-cyan-glow/40"
        />
        <select
          value={filterGroup}
          onChange={(e) => setFilterGroup(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Groups</option>
          {GROUPS.map((g) => <option key={g} value={g}>{g}</option>)}
        </select>
        <select
          value={filterCriticality}
          onChange={(e) => setFilterCriticality(e.target.value)}
          className="rounded border border-cyan-glow/15 bg-black/40 px-3 py-1.5 text-[10px] text-gray-300 outline-none"
        >
          <option value="all">All Criticality</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="ml-auto text-[10px] text-gray-500">{filtered.length} assets</span>
      </div>

      {activeTab === "list" && (
        <div className="glass-panel overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyan-glow/10">
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Hostname</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">IP</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">OS</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Owner</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Criticality</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Last Seen</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Vulns</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Group</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Tags</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Source</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset) => (
                <tr key={asset.id} className="border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5">
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{asset.hostname}</td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{asset.ip}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-400">{asset.os}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-400">{asset.owner}</td>
                  <td className="px-4 py-3"><Badge text={asset.criticality} cls={CRIT_COLORS[asset.criticality]} /></td>
                  <td className="px-4 py-3 text-[10px] text-gray-500">{asset.lastSeen}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-bold ${asset.vulnCount > 5 ? "text-red-400" : asset.vulnCount > 0 ? "text-yellow-400" : "text-green-400"}`}>
                      {asset.vulnCount}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[10px] text-gray-500">{asset.group}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {asset.tags.map((t) => (
                        <span key={t} className="rounded bg-cyan-glow/5 px-1.5 py-0.5 text-[8px] text-cyan-glow/60">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      text={asset.autoDiscovered ? "AUTO" : "MANUAL"}
                      cls={asset.autoDiscovered ? "bg-blue-500/15 text-blue-400 border-blue-500/30" : "bg-gray-500/15 text-gray-400 border-gray-500/30"}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === "matrix" && (
        <div className="glass-panel border border-cyan-glow/10 p-6">
          <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Criticality Matrix (Business Impact vs Exposure)
          </h3>
          <div className="relative">
            {/* Y-axis label */}
            <div className="absolute -left-2 top-1/2 -translate-y-1/2 -rotate-90 text-[9px] uppercase tracking-wider text-gray-500">
              Business Impact
            </div>
            {/* X-axis label */}
            <div className="text-center text-[9px] uppercase tracking-wider text-gray-500">Exposure Level</div>

            <div className="ml-8 mt-2 grid grid-cols-4 gap-2">
              {/* Row labels */}
              {(["Critical", "High", "Medium", "Low"] as const).map((impact, row) => (
                (["High", "Medium-High", "Medium", "Low"] as const).map((exposure, col) => {
                  const matchingAssets = ASSETS.filter((a) => {
                    const impactMatch = a.criticality === impact.toLowerCase();
                    const exposureMatch = col === 0 ? a.vulnCount > 5 : col === 1 ? a.vulnCount > 2 && a.vulnCount <= 5 : col === 2 ? a.vulnCount > 0 && a.vulnCount <= 2 : a.vulnCount === 0;
                    return impactMatch && exposureMatch;
                  });
                  const bgColor = row + col <= 1 ? "bg-red-500/20 border-red-500/30" : row + col <= 3 ? "bg-orange-500/15 border-orange-500/20" : row + col <= 5 ? "bg-yellow-500/10 border-yellow-500/20" : "bg-green-500/10 border-green-500/20";
                  return (
                    <div key={`${row}-${col}`} className={`rounded border p-3 ${bgColor} min-h-[60px]`}>
                      {col === 0 && <span className="text-[8px] uppercase tracking-wider text-gray-500">{impact}</span>}
                      <div className="mt-1 flex flex-wrap gap-1">
                        {matchingAssets.map((a) => (
                          <span key={a.id} className="rounded bg-black/30 px-1.5 py-0.5 text-[8px] font-mono text-gray-300" title={a.hostname}>
                            {a.hostname.split(".")[0]}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === "topology" && (
        <div className="glass-panel border border-cyan-glow/10 p-6">
          <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Network Topology
          </h3>
          <svg viewBox="0 0 600 310" className="w-full" style={{ maxHeight: 400 }}>
            {/* Edges */}
            {TOPOLOGY_EDGES.map(([from, to], i) => {
              const fromNode = TOPOLOGY_NODES.find((n) => n.id === from)!;
              const toNode = TOPOLOGY_NODES.find((n) => n.id === to)!;
              return (
                <line
                  key={i}
                  x1={fromNode.x} y1={fromNode.y} x2={toNode.x} y2={toNode.y}
                  stroke="rgba(0, 229, 255, 0.2)" strokeWidth="1.5" strokeDasharray="4,4"
                />
              );
            })}
            {/* Nodes */}
            {TOPOLOGY_NODES.map((node) => (
              <g key={node.id}>
                <circle cx={node.x} cy={node.y} r="18" fill="rgba(0,0,0,0.6)" stroke={node.color} strokeWidth="1.5" />
                <circle cx={node.x} cy={node.y} r="4" fill={node.color} opacity="0.6" />
                <text x={node.x} y={node.y + 32} textAnchor="middle" fill={node.color} fontSize="8" fontFamily="monospace" opacity="0.8">
                  {node.label}
                </text>
              </g>
            ))}
          </svg>
        </div>
      )}
    </div>
  );
}
