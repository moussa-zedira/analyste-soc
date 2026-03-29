"use client";

import { useState, useMemo, useCallback, useRef, useEffect } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type IocType = "ip" | "domain" | "url" | "hash-md5" | "hash-sha1" | "hash-sha256" | "email" | "cidr";
type IocState = "active" | "revoked" | "false-positive" | "expired";
type TLP = "white" | "green" | "amber" | "red";

interface IOC {
  id: string;
  type: IocType;
  value: string;
  state: IocState;
  confidence: number;
  tlp: TLP;
  source: string;
  firstSeen: string;
  lastSeen: string;
  sightings: number;
  tags: string[];
  mitreTechnique?: string;
  killChainPhase?: string;
  expiry?: string;
  relatedIds: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const IOC_TYPE_ICONS: Record<IocType, string> = {
  ip: "M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3",
  domain: "M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3",
  url: "M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244",
  "hash-md5": "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z",
  "hash-sha1": "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z",
  "hash-sha256": "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z",
  email: "M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75",
  cidr: "M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z",
};

const TLP_COLORS: Record<TLP, string> = {
  white: "bg-gray-500/15 text-gray-300 border-gray-500/20",
  green: "bg-green-500/15 text-green-400 border-green-500/20",
  amber: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  red: "bg-red-500/15 text-red-400 border-red-500/20",
};

const STATE_COLORS: Record<IocState, string> = {
  active: "bg-green-500/15 text-green-400 border-green-500/20",
  revoked: "bg-gray-500/15 text-gray-400 border-gray-500/20",
  "false-positive": "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  expired: "bg-red-500/15 text-red-400 border-red-500/20",
};

// ---------------------------------------------------------------------------
// Demo Data
// ---------------------------------------------------------------------------
function generateIOCs(): IOC[] {
  return [
    { id: "ioc-1", type: "ip", value: "185.220.101.34", state: "active", confidence: 95, tlp: "amber", source: "AbuseIPDB", firstSeen: "2026-03-10T08:00:00Z", lastSeen: "2026-03-28T14:22:00Z", sightings: 42, tags: ["tor-exit", "brute-force", "scanner"], mitreTechnique: "T1190", killChainPhase: "Delivery", relatedIds: ["ioc-2", "ioc-5"] },
    { id: "ioc-2", type: "domain", value: "evil-c2.darknet.io", state: "active", confidence: 88, tlp: "red", source: "ThreatFox", firstSeen: "2026-03-15T12:00:00Z", lastSeen: "2026-03-28T10:00:00Z", sightings: 18, tags: ["c2", "cobalt-strike"], mitreTechnique: "T1071.001", killChainPhase: "C2", relatedIds: ["ioc-1", "ioc-3"] },
    { id: "ioc-3", type: "hash-sha256", value: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456", state: "active", confidence: 99, tlp: "red", source: "MalwareBazaar", firstSeen: "2026-03-20T06:00:00Z", lastSeen: "2026-03-27T18:00:00Z", sightings: 7, tags: ["ransomware", "lockbit"], mitreTechnique: "T1486", killChainPhase: "Actions", relatedIds: ["ioc-2"] },
    { id: "ioc-4", type: "url", value: "https://phishing.example.com/login/fake-bank", state: "active", confidence: 75, tlp: "green", source: "PhishTank", firstSeen: "2026-03-22T09:00:00Z", lastSeen: "2026-03-28T11:00:00Z", sightings: 156, tags: ["phishing", "credential-theft"], mitreTechnique: "T1566.002", killChainPhase: "Delivery", relatedIds: [] },
    { id: "ioc-5", type: "ip", value: "45.33.32.156", state: "revoked", confidence: 30, tlp: "white", source: "Manual", firstSeen: "2026-03-01T00:00:00Z", lastSeen: "2026-03-10T00:00:00Z", sightings: 2, tags: ["scanner"], relatedIds: ["ioc-1"] },
    { id: "ioc-6", type: "email", value: "attacker@malware-delivery.com", state: "active", confidence: 82, tlp: "amber", source: "OTX", firstSeen: "2026-03-18T14:00:00Z", lastSeen: "2026-03-28T09:00:00Z", sightings: 11, tags: ["spam", "malware-delivery"], mitreTechnique: "T1566.001", killChainPhase: "Delivery", relatedIds: ["ioc-4"] },
    { id: "ioc-7", type: "hash-md5", value: "d41d8cd98f00b204e9800998ecf8427e", state: "false-positive", confidence: 10, tlp: "white", source: "VirusTotal", firstSeen: "2026-03-25T00:00:00Z", lastSeen: "2026-03-25T00:00:00Z", sightings: 1, tags: ["empty-file"], relatedIds: [] },
    { id: "ioc-8", type: "cidr", value: "192.168.100.0/24", state: "active", confidence: 60, tlp: "green", source: "Internal", firstSeen: "2026-03-26T08:00:00Z", lastSeen: "2026-03-28T15:00:00Z", sightings: 5, tags: ["lateral-movement", "internal"], mitreTechnique: "T1021", killChainPhase: "Lateral", relatedIds: [] },
    { id: "ioc-9", type: "domain", value: "crypto-miner-pool.xyz", state: "expired", confidence: 70, tlp: "green", source: "Emerging Threats", firstSeen: "2026-02-01T00:00:00Z", lastSeen: "2026-02-28T00:00:00Z", sightings: 33, tags: ["cryptominer"], mitreTechnique: "T1496", killChainPhase: "Actions", expiry: "2026-03-15T00:00:00Z", relatedIds: [] },
    { id: "ioc-10", type: "ip", value: "103.224.182.245", state: "active", confidence: 91, tlp: "amber", source: "Feodo Tracker", firstSeen: "2026-03-24T10:00:00Z", lastSeen: "2026-03-28T16:00:00Z", sightings: 28, tags: ["botnet", "emotet"], mitreTechnique: "T1071", killChainPhase: "C2", relatedIds: ["ioc-2"] },
  ];
}

// ---------------------------------------------------------------------------
// Relationship Graph (D3-style SVG)
// ---------------------------------------------------------------------------
function RelationshipGraph({ iocs, selectedId }: { iocs: IOC[]; selectedId: string | null }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [nodes, setNodes] = useState<{ id: string; x: number; y: number; type: IocType; label: string }[]>([]);
  const [edges, setEdges] = useState<{ from: string; to: string }[]>([]);

  useEffect(() => {
    const relevant = selectedId ? iocs.filter(i => i.id === selectedId || iocs.find(o => o.id === selectedId)?.relatedIds.includes(i.id)) : iocs.slice(0, 8);
    const cx = 300, cy = 180;
    const r = 140;
    const n = relevant.map((ioc, i) => {
      const angle = (2 * Math.PI * i) / relevant.length - Math.PI / 2;
      return { id: ioc.id, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), type: ioc.type, label: ioc.value.length > 20 ? ioc.value.slice(0, 18) + "..." : ioc.value };
    });
    setNodes(n);
    const e: { from: string; to: string }[] = [];
    const nodeIds = new Set(n.map(nd => nd.id));
    for (const ioc of relevant) {
      for (const rid of ioc.relatedIds) {
        if (nodeIds.has(rid) && !e.find(ed => (ed.from === rid && ed.to === ioc.id))) {
          e.push({ from: ioc.id, to: rid });
        }
      }
    }
    setEdges(e);
  }, [iocs, selectedId]);

  const typeColor: Record<IocType, string> = {
    ip: "#00E5FF", domain: "#A855F7", url: "#F97316", "hash-md5": "#EF4444",
    "hash-sha1": "#EF4444", "hash-sha256": "#EF4444", email: "#EAB308", cidr: "#3B82F6",
  };

  return (
    <svg ref={svgRef} viewBox="0 0 600 360" className="w-full h-[360px]">
      <defs>
        <filter id="glow-ioc">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      {edges.map((e, i) => {
        const from = nodes.find(n => n.id === e.from);
        const to = nodes.find(n => n.id === e.to);
        if (!from || !to) return null;
        return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(0,229,255,0.2)" strokeWidth={1.5} strokeDasharray="4 4" />;
      })}
      {nodes.map(n => (
        <g key={n.id} filter="url(#glow-ioc)">
          <circle cx={n.x} cy={n.y} r={selectedId === n.id ? 28 : 22} fill={typeColor[n.type] + "18"} stroke={typeColor[n.type]} strokeWidth={selectedId === n.id ? 2 : 1} opacity={0.9} />
          <text x={n.x} y={n.y - 30} textAnchor="middle" fill={typeColor[n.type]} fontSize={9} fontFamily="JetBrains Mono, monospace">{n.label}</text>
          <text x={n.x} y={n.y + 4} textAnchor="middle" fill={typeColor[n.type]} fontSize={8} fontFamily="JetBrains Mono, monospace" fontWeight="bold">{n.type.toUpperCase()}</text>
        </g>
      ))}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function IOCManagementPage() {
  const [iocs, setIocs] = useState<IOC[]>(generateIOCs);
  const [activeTab, setActiveTab] = useState<"dashboard" | "add" | "import" | "graph">("dashboard");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState<IocType | "all">("all");
  const [filterState, setFilterState] = useState<IocState | "all">("all");
  const [filterTlp, setFilterTlp] = useState<TLP | "all">("all");
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  // Add IOC form
  const [addType, setAddType] = useState<IocType>("ip");
  const [addValue, setAddValue] = useState("");
  const [addConfidence, setAddConfidence] = useState(80);
  const [addTlp, setAddTlp] = useState<TLP>("amber");
  const [addTags, setAddTags] = useState("");
  const [addMitre, setAddMitre] = useState("");
  const [addKillChain, setAddKillChain] = useState("");
  const [addExpiry, setAddExpiry] = useState("");

  // Bulk import
  const [importFormat, setImportFormat] = useState<"stix" | "csv" | "text">("text");
  const [importData, setImportData] = useState("");

  // Filter
  const filtered = useMemo(() => {
    return iocs.filter(ioc => {
      if (filterType !== "all" && ioc.type !== filterType) return false;
      if (filterState !== "all" && ioc.state !== filterState) return false;
      if (filterTlp !== "all" && ioc.tlp !== filterTlp) return false;
      if (ioc.confidence < confidenceMin) return false;
      if (search) {
        const q = search.toLowerCase();
        return ioc.value.toLowerCase().includes(q) || ioc.tags.some(t => t.includes(q)) || ioc.source.toLowerCase().includes(q);
      }
      return true;
    });
  }, [iocs, search, filterType, filterState, filterTlp, confidenceMin]);

  // Stats
  const stats = useMemo(() => {
    const s = { total: iocs.length, active: 0, byType: {} as Record<string, number>, byTlp: {} as Record<string, number>, highConf: 0, medConf: 0, lowConf: 0 };
    for (const ioc of iocs) {
      if (ioc.state === "active") s.active++;
      s.byType[ioc.type] = (s.byType[ioc.type] || 0) + 1;
      s.byTlp[ioc.tlp] = (s.byTlp[ioc.tlp] || 0) + 1;
      if (ioc.confidence >= 80) s.highConf++;
      else if (ioc.confidence >= 50) s.medConf++;
      else s.lowConf++;
    }
    return s;
  }, [iocs]);

  const handleAddIOC = useCallback(() => {
    if (!addValue.trim()) return;
    const newIoc: IOC = {
      id: `ioc-${Date.now()}`,
      type: addType,
      value: addValue.trim(),
      state: "active",
      confidence: addConfidence,
      tlp: addTlp,
      source: "Manual",
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      sightings: 0,
      tags: addTags.split(",").map(t => t.trim()).filter(Boolean),
      mitreTechnique: addMitre || undefined,
      killChainPhase: addKillChain || undefined,
      expiry: addExpiry || undefined,
      relatedIds: [],
    };
    setIocs(prev => [newIoc, ...prev]);
    setAddValue("");
    setAddTags("");
    setAddMitre("");
    setAddKillChain("");
    setAddExpiry("");
    setActiveTab("dashboard");
  }, [addType, addValue, addConfidence, addTlp, addTags, addMitre, addKillChain, addExpiry]);

  const handleBulkImport = useCallback(() => {
    if (!importData.trim()) return;
    let values: string[] = [];
    if (importFormat === "text") {
      values = importData.split("\n").map(l => l.trim()).filter(Boolean);
    } else if (importFormat === "csv") {
      values = importData.split("\n").slice(1).map(l => l.split(",")[0]?.trim()).filter(Boolean);
    } else {
      try {
        const parsed = JSON.parse(importData);
        const objects = parsed.objects || [parsed];
        values = objects.filter((o: Record<string, string>) => o.type === "indicator").map((o: Record<string, string>) => o.pattern || o.name || "unknown");
      } catch { /* ignore */ }
    }
    const newIocs: IOC[] = values.map((v, i) => ({
      id: `ioc-import-${Date.now()}-${i}`,
      type: "ip" as IocType,
      value: v,
      state: "active" as IocState,
      confidence: 70,
      tlp: "amber" as TLP,
      source: "Bulk Import",
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      sightings: 0,
      tags: ["imported"],
      relatedIds: [],
    }));
    setIocs(prev => [...newIocs, ...prev]);
    setImportData("");
    setActiveTab("dashboard");
  }, [importData, importFormat]);

  const handleExport = useCallback((format: "stix" | "csv" | "openioc") => {
    let content = "";
    let filename = "";
    let mime = "";
    if (format === "csv") {
      content = "type,value,state,confidence,tlp,source,first_seen,last_seen,sightings,tags\n" +
        filtered.map(i => `"${i.type}","${i.value}","${i.state}",${i.confidence},"${i.tlp}","${i.source}","${i.firstSeen}","${i.lastSeen}",${i.sightings},"${i.tags.join(";")}"`).join("\n");
      filename = "iocs.csv"; mime = "text/csv";
    } else if (format === "stix") {
      const bundle = { type: "bundle", id: `bundle--${crypto.randomUUID()}`, objects: filtered.map(i => ({ type: "indicator", id: `indicator--${crypto.randomUUID()}`, name: i.value, pattern: `[${i.type}:value = '${i.value}']`, valid_from: i.firstSeen, confidence: i.confidence, labels: i.tags })) };
      content = JSON.stringify(bundle, null, 2);
      filename = "iocs-stix-bundle.json"; mime = "application/json";
    } else {
      content = `<?xml version="1.0" encoding="UTF-8"?>\n<ioc xmlns="http://schemas.mandiant.com/2010/ioc">\n` +
        filtered.map(i => `  <IndicatorItem><Context document="ioc" search="${i.type}" /><Content type="string">${i.value}</Content></IndicatorItem>`).join("\n") +
        `\n</ioc>`;
      filename = "iocs-openioc.xml"; mime = "application/xml";
    }
    const blob = new Blob([content], { type: mime });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
  }, [filtered]);

  const handleRevokeIOC = useCallback((id: string) => {
    setIocs(prev => prev.map(i => i.id === id ? { ...i, state: "revoked" as IocState } : i));
    setShowDetail(false);
  }, []);

  const handleMarkFP = useCallback((id: string) => {
    setIocs(prev => prev.map(i => i.id === id ? { ...i, state: "false-positive" as IocState } : i));
    setShowDetail(false);
  }, []);

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            IOC Management
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            INDICATORS OF COMPROMISE // STIX/TAXII // ENRICHMENT
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => handleExport("stix")} className="glass-panel px-3 py-2 text-[10px] font-bold tracking-wider text-cyan-glow hover:bg-cyan-glow/10">STIX</button>
          <button onClick={() => handleExport("csv")} className="glass-panel px-3 py-2 text-[10px] font-bold tracking-wider text-gray-400 hover:text-cyan-glow">CSV</button>
          <button onClick={() => handleExport("openioc")} className="glass-panel px-3 py-2 text-[10px] font-bold tracking-wider text-gray-400 hover:text-cyan-glow">OpenIOC</button>
        </div>
      </div>

      <div className="cyan-line" />

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-cyan-glow font-mono">{stats.total}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOTAL IOCs</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-green-400 font-mono">{stats.active}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">ACTIVE</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-cyan-glow font-mono">{stats.highConf}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">HIGH CONF</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-yellow-400 font-mono">{stats.medConf}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">MEDIUM CONF</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-red-400 font-mono">{stats.lowConf}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">LOW CONF</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-purple-400 font-mono">{Object.keys(stats.byType).length}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">IOC TYPES</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(["dashboard", "add", "import", "graph"] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${activeTab === tab ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500 hover:border-gray-600"}`}>
            {tab === "dashboard" ? "IOC TABLE" : tab === "add" ? "ADD IOC" : tab === "import" ? "BULK IMPORT" : "GRAPH"}
          </button>
        ))}
      </div>

      {/* Dashboard Tab */}
      {activeTab === "dashboard" && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="glass-panel flex flex-wrap items-center gap-3 px-4 py-3">
            <span className="text-[10px] font-bold tracking-widest text-gray-500">FILTERS</span>
            <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IOCs..." className="rounded border border-cyan-glow/15 bg-space-deep px-3 py-1.5 text-xs text-gray-300 placeholder-gray-600 w-48 focus:border-cyan-glow/30 focus:outline-none font-mono" />
            <select value={filterType} onChange={e => setFilterType(e.target.value as IocType | "all")} className="rounded border border-cyan-glow/15 bg-space-deep px-2 py-1.5 text-xs text-gray-300">
              <option value="all">All Types</option>
              {(Object.keys(IOC_TYPE_ICONS) as IocType[]).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </select>
            <select value={filterState} onChange={e => setFilterState(e.target.value as IocState | "all")} className="rounded border border-cyan-glow/15 bg-space-deep px-2 py-1.5 text-xs text-gray-300">
              <option value="all">All States</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
              <option value="false-positive">False Positive</option>
              <option value="expired">Expired</option>
            </select>
            <select value={filterTlp} onChange={e => setFilterTlp(e.target.value as TLP | "all")} className="rounded border border-cyan-glow/15 bg-space-deep px-2 py-1.5 text-xs text-gray-300">
              <option value="all">All TLP</option>
              <option value="white">TLP:WHITE</option>
              <option value="green">TLP:GREEN</option>
              <option value="amber">TLP:AMBER</option>
              <option value="red">TLP:RED</option>
            </select>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-gray-500">Conf &ge;</span>
              <input type="range" min={0} max={100} value={confidenceMin} onChange={e => setConfidenceMin(Number(e.target.value))} className="w-20 accent-cyan-400" />
              <span className="text-[10px] text-cyan-glow font-mono">{confidenceMin}%</span>
            </div>
            <span className="ml-auto text-xs text-gray-500 font-mono">{filtered.length} results</span>
          </div>

          {/* IOC Table */}
          <div className="glass-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">TYPE</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">VALUE</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">STATE</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">CONF</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">TLP</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">SOURCE</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">FIRST SEEN</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">LAST SEEN</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">SIGHTINGS</th>
                    <th className="px-3 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">TAGS</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(ioc => (
                    <tr key={ioc.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5 cursor-pointer transition-colors" onClick={() => { setSelectedIoc(ioc); setShowDetail(true); }}>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1.5">
                          <svg className="h-3.5 w-3.5 text-cyan-glow/60" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d={IOC_TYPE_ICONS[ioc.type]} />
                          </svg>
                          <span className="text-[10px] font-bold text-gray-400 uppercase">{ioc.type}</span>
                        </div>
                      </td>
                      <td className="px-3 py-3 font-mono text-[10px] text-gray-200 max-w-[200px] truncate">{ioc.value}</td>
                      <td className="px-3 py-3">
                        <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${STATE_COLORS[ioc.state]}`}>{ioc.state.toUpperCase()}</span>
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-1.5">
                          <div className="h-1.5 w-16 rounded-full bg-gray-800 overflow-hidden">
                            <div className={`h-full rounded-full ${ioc.confidence >= 80 ? "bg-green-400" : ioc.confidence >= 50 ? "bg-yellow-400" : "bg-red-400"}`} style={{ width: `${ioc.confidence}%` }} />
                          </div>
                          <span className="text-[10px] font-mono text-gray-400">{ioc.confidence}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${TLP_COLORS[ioc.tlp]}`}>TLP:{ioc.tlp.toUpperCase()}</span>
                      </td>
                      <td className="px-3 py-3 text-[10px] text-gray-400">{ioc.source}</td>
                      <td className="px-3 py-3 text-[10px] font-mono text-gray-500">{new Date(ioc.firstSeen).toLocaleDateString()}</td>
                      <td className="px-3 py-3 text-[10px] font-mono text-gray-500">{new Date(ioc.lastSeen).toLocaleDateString()}</td>
                      <td className="px-3 py-3 text-[10px] font-mono text-cyan-glow">{ioc.sightings}</td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-1">
                          {ioc.tags.slice(0, 3).map(tag => (
                            <span key={tag} className="rounded-full border border-cyan-glow/20 bg-cyan-glow/5 px-1.5 py-0.5 text-[9px] text-cyan-glow">{tag}</span>
                          ))}
                          {ioc.tags.length > 3 && <span className="text-[9px] text-gray-500">+{ioc.tags.length - 3}</span>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {filtered.length === 0 && (
              <div className="py-12 text-center">
                <p className="text-sm text-gray-500">No IOCs match your filters</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Add IOC Tab */}
      {activeTab === "add" && (
        <div className="glass-panel p-6 space-y-4 max-w-2xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">ADD NEW IOC</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TYPE</label>
              <select value={addType} onChange={e => setAddType(e.target.value as IocType)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                {(Object.keys(IOC_TYPE_ICONS) as IocType[]).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TLP</label>
              <select value={addTlp} onChange={e => setAddTlp(e.target.value as TLP)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                <option value="white">TLP:WHITE</option>
                <option value="green">TLP:GREEN</option>
                <option value="amber">TLP:AMBER</option>
                <option value="red">TLP:RED</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">VALUE</label>
            <input type="text" value={addValue} onChange={e => setAddValue(e.target.value)} placeholder="e.g. 185.220.101.34" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">CONFIDENCE: {addConfidence}%</label>
            <input type="range" min={0} max={100} value={addConfidence} onChange={e => setAddConfidence(Number(e.target.value))} className="w-full accent-cyan-400" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TAGS (comma-separated)</label>
              <input type="text" value={addTags} onChange={e => setAddTags(e.target.value)} placeholder="e.g. botnet, c2" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">MITRE TECHNIQUE</label>
              <input type="text" value={addMitre} onChange={e => setAddMitre(e.target.value)} placeholder="e.g. T1071.001" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">KILL CHAIN PHASE</label>
              <select value={addKillChain} onChange={e => setAddKillChain(e.target.value)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                <option value="">None</option>
                <option value="Reconnaissance">Reconnaissance</option>
                <option value="Weaponization">Weaponization</option>
                <option value="Delivery">Delivery</option>
                <option value="Exploitation">Exploitation</option>
                <option value="Installation">Installation</option>
                <option value="C2">C2</option>
                <option value="Actions">Actions on Objectives</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">EXPIRY DATE</label>
              <input type="date" value={addExpiry} onChange={e => setAddExpiry(e.target.value)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
          </div>
          <button onClick={handleAddIOC} disabled={!addValue.trim()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50">
            ADD IOC
          </button>
        </div>
      )}

      {/* Bulk Import Tab */}
      {activeTab === "import" && (
        <div className="glass-panel p-6 space-y-4 max-w-2xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">BULK IMPORT IOCs</h3>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">FORMAT</label>
            <div className="flex gap-2">
              {(["text", "csv", "stix"] as const).map(f => (
                <button key={f} onClick={() => setImportFormat(f)} className={`rounded border px-4 py-1.5 text-[10px] font-bold tracking-widest transition-all ${importFormat === f ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500"}`}>
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">DATA</label>
            <textarea value={importData} onChange={e => setImportData(e.target.value)} rows={12} placeholder={importFormat === "text" ? "One IOC per line:\n185.220.101.34\nevil.com\n..." : importFormat === "csv" ? "value,type,confidence\n185.220.101.34,ip,90\n..." : '{"type": "bundle", "objects": [...]}'} className="w-full rounded border border-gray-700 bg-gray-900/80 p-3 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <button onClick={handleBulkImport} disabled={!importData.trim()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50">
            IMPORT
          </button>
        </div>
      )}

      {/* Graph Tab */}
      {activeTab === "graph" && (
        <div className="glass-panel p-4">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">IOC RELATIONSHIP GRAPH</h3>
          <RelationshipGraph iocs={iocs} selectedId={selectedIoc?.id || null} />
          <p className="text-[10px] text-gray-500 mt-2 text-center">Click an IOC in the table to focus the graph on its relationships</p>
        </div>
      )}

      {/* Detail Modal */}
      {showDetail && selectedIoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-space-deep/60 backdrop-blur-sm" onClick={() => setShowDetail(false)}>
          <div className="glass-panel w-full max-w-2xl max-h-[80vh] overflow-y-auto p-6 space-y-4 m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h2 className="hud-heading text-lg text-cyan-glow">IOC Detail</h2>
              <button onClick={() => setShowDetail(false)} className="text-gray-500 hover:text-gray-300">&times;</button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">TYPE</p>
                <p className="text-sm text-gray-200 font-mono">{selectedIoc.type.toUpperCase()}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">STATE</p>
                <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${STATE_COLORS[selectedIoc.state]}`}>{selectedIoc.state.toUpperCase()}</span>
              </div>
            </div>
            <div>
              <p className="text-[10px] font-bold tracking-widest text-gray-500">VALUE</p>
              <p className="text-sm text-cyan-glow font-mono break-all">{selectedIoc.value}</p>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">CONFIDENCE</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
                    <div className={`h-full rounded-full ${selectedIoc.confidence >= 80 ? "bg-green-400" : selectedIoc.confidence >= 50 ? "bg-yellow-400" : "bg-red-400"}`} style={{ width: `${selectedIoc.confidence}%` }} />
                  </div>
                  <span className="text-xs font-mono text-gray-300">{selectedIoc.confidence}%</span>
                </div>
              </div>
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">TLP</p>
                <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${TLP_COLORS[selectedIoc.tlp]}`}>TLP:{selectedIoc.tlp.toUpperCase()}</span>
              </div>
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">SIGHTINGS</p>
                <p className="text-lg font-bold text-cyan-glow font-mono">{selectedIoc.sightings}</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">FIRST SEEN</p>
                <p className="text-xs font-mono text-gray-300">{new Date(selectedIoc.firstSeen).toLocaleString()}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">LAST SEEN</p>
                <p className="text-xs font-mono text-gray-300">{new Date(selectedIoc.lastSeen).toLocaleString()}</p>
              </div>
            </div>
            {selectedIoc.mitreTechnique && (
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">MITRE ATT&CK</p>
                <span className="rounded bg-cyan-glow/10 px-2 py-0.5 text-xs text-cyan-glow font-mono">{selectedIoc.mitreTechnique}</span>
              </div>
            )}
            {selectedIoc.killChainPhase && (
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">KILL CHAIN PHASE</p>
                <p className="text-xs text-gray-300">{selectedIoc.killChainPhase}</p>
              </div>
            )}
            <div>
              <p className="text-[10px] font-bold tracking-widest text-gray-500">TAGS</p>
              <div className="flex flex-wrap gap-1.5 mt-1">
                {selectedIoc.tags.map(tag => (
                  <span key={tag} className="rounded-full border border-cyan-glow/20 bg-cyan-glow/5 px-2.5 py-0.5 text-[10px] text-cyan-glow">{tag}</span>
                ))}
              </div>
            </div>
            {selectedIoc.relatedIds.length > 0 && (
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">RELATED IOCs</p>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {selectedIoc.relatedIds.map(rid => {
                    const r = iocs.find(i => i.id === rid);
                    return r ? <span key={rid} className="rounded border border-gray-700 bg-gray-900/50 px-2 py-0.5 text-[10px] font-mono text-gray-300">{r.value.length > 30 ? r.value.slice(0, 28) + "..." : r.value}</span> : null;
                  })}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-2 border-t border-gray-800">
              <button onClick={() => handleRevokeIOC(selectedIoc.id)} className="rounded border border-red-500/20 bg-red-500/10 px-4 py-2 text-[10px] font-bold tracking-widest text-red-400 hover:bg-red-500/20 transition-colors">REVOKE</button>
              <button onClick={() => handleMarkFP(selectedIoc.id)} className="rounded border border-yellow-500/20 bg-yellow-500/10 px-4 py-2 text-[10px] font-bold tracking-widest text-yellow-400 hover:bg-yellow-500/20 transition-colors">MARK FALSE POSITIVE</button>
              <button className="rounded border border-cyan-glow/20 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors">ENRICH</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
