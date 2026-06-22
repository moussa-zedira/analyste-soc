"use client";

import { useState, useMemo, useCallback, useRef, useEffect } from "react";
import {
  listIocs,
  createIoc,
  revokeIoc,
  markIocFalsePositive,
  bulkImportIocs,
  getIocGraph,
  type IocApi,
} from "@/lib/apiClient";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudStat,
  HudTabs,
  HudField,
  HudInput,
  HudSelect,
  HudTextarea,
  type HudTabItem,
} from "@/components/hud";

// ---------------------------------------------------------------------------
// Types (UI-side — with hyphens to match existing design tokens)
// ---------------------------------------------------------------------------
type IocType = "ip" | "domain" | "url" | "hash-md5" | "hash-sha1" | "hash-sha256" | "email" | "cidr";
type IocState = "active" | "revoked" | "false-positive" | "expired";
type TLP = "white" | "green" | "amber" | "red";
type Tab = "dashboard" | "add" | "import" | "graph";

interface IOC {
  id: number;
  type: IocType;
  rawType: string;
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
}

// ---------------------------------------------------------------------------
// Backend <-> UI shape adapters
// ---------------------------------------------------------------------------
const TYPE_API_TO_UI: Record<string, IocType> = {
  ip: "ip",
  domain: "domain",
  url: "url",
  email: "email",
  cidr: "cidr",
  hash_md5: "hash-md5",
  hash_sha1: "hash-sha1",
  hash_sha256: "hash-sha256",
};
const TYPE_UI_TO_API: Record<IocType, string> = {
  ip: "ip",
  domain: "domain",
  url: "url",
  email: "email",
  cidr: "cidr",
  "hash-md5": "hash_md5",
  "hash-sha1": "hash_sha1",
  "hash-sha256": "hash_sha256",
};
const STATE_API_TO_UI: Record<string, IocState> = {
  active: "active",
  revoked: "revoked",
  false_positive: "false-positive",
  expired: "expired",
};

function adaptIoc(api: IocApi): IOC {
  return {
    id: api.id,
    type: TYPE_API_TO_UI[api.type] ?? "ip",
    rawType: api.type,
    value: api.value,
    state: STATE_API_TO_UI[api.state] ?? "active",
    confidence: api.confidence,
    tlp: (api.tlp?.toLowerCase().split("+")[0] ?? "amber") as TLP,
    source: api.source,
    firstSeen: api.first_seen ?? "",
    lastSeen: api.last_seen ?? "",
    sightings: api.sightings_count ?? 0,
    tags: api.tags ?? [],
    mitreTechnique: api.mitre_techniques?.[0],
    killChainPhase: api.kill_chain_phase ?? undefined,
    expiry: api.expiry ?? undefined,
  };
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
// Relationship Graph (fetched from /ioc/graph)
// ---------------------------------------------------------------------------
type GraphData = {
  nodes: { id: number; type: string; value: string; confidence: number }[];
  edges: { source: number; target: number; type: string }[];
};

function RelationshipGraph({ data, selectedId }: { data: GraphData | null; selectedId: number | null }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const layout = useMemo(() => {
    if (!data || data.nodes.length === 0) return { nodes: [], edges: [] as { from: number; to: number }[] };
    const relevantIds = selectedId
      ? new Set<number>([selectedId, ...data.edges.filter(e => e.source === selectedId || e.target === selectedId).flatMap(e => [e.source, e.target])])
      : new Set(data.nodes.slice(0, 12).map(n => n.id));
    const relevant = data.nodes.filter(n => relevantIds.has(n.id));
    const cx = 300, cy = 180, r = 140;
    const positioned = relevant.map((node, i) => {
      const angle = (2 * Math.PI * i) / Math.max(relevant.length, 1) - Math.PI / 2;
      const label = node.value.length > 20 ? node.value.slice(0, 18) + "..." : node.value;
      return { id: node.id, x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle), type: node.type, label };
    });
    const ids = new Set(positioned.map(n => n.id));
    const edges = data.edges
      .filter(e => ids.has(e.source) && ids.has(e.target))
      .map(e => ({ from: e.source, to: e.target }));
    return { nodes: positioned, edges };
  }, [data, selectedId]);

  const typeColor: Record<string, string> = {
    ip: "#00E5FF", domain: "#A855F7", url: "#F97316",
    hash_md5: "#EF4444", hash_sha1: "#EF4444", hash_sha256: "#EF4444",
    email: "#EAB308", cidr: "#3B82F6",
  };

  return (
    <svg ref={svgRef} viewBox="0 0 600 360" className="w-full h-[360px]">
      <defs>
        <filter id="glow-ioc">
          <feGaussianBlur stdDeviation="3" result="blur" />
          <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>
      {layout.edges.map((e, i) => {
        const from = layout.nodes.find(n => n.id === e.from);
        const to = layout.nodes.find(n => n.id === e.to);
        if (!from || !to) return null;
        return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(0,229,255,0.2)" strokeWidth={1.5} strokeDasharray="4 4" />;
      })}
      {layout.nodes.map(n => {
        const color = typeColor[n.type] ?? "#00E5FF";
        return (
          <g key={n.id} filter="url(#glow-ioc)">
            <circle cx={n.x} cy={n.y} r={selectedId === n.id ? 28 : 22} fill={color + "18"} stroke={color} strokeWidth={selectedId === n.id ? 2 : 1} opacity={0.9} />
            <text x={n.x} y={n.y - 30} textAnchor="middle" fill={color} fontSize={9} fontFamily="JetBrains Mono, monospace">{n.label}</text>
            <text x={n.x} y={n.y + 4} textAnchor="middle" fill={color} fontSize={8} fontFamily="JetBrains Mono, monospace" fontWeight="bold">{n.type.toUpperCase()}</text>
          </g>
        );
      })}
      {layout.nodes.length === 0 && (
        <text x={300} y={180} textAnchor="middle" fill="#6B7280" fontSize={11}>No IOCs in graph yet</text>
      )}
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------
export default function IOCManagementPage() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("dashboard");
  const [search, setSearch] = useState("");
  const [filterType, setFilterType] = useState<IocType | "all">("all");
  const [filterState, setFilterState] = useState<IocState | "all">("all");
  const [filterTlp, setFilterTlp] = useState<TLP | "all">("all");
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [selectedIoc, setSelectedIoc] = useState<IOC | null>(null);
  const [showDetail, setShowDetail] = useState(false);
  const [graphData, setGraphData] = useState<GraphData | null>(null);

  // Add IOC form
  const [addType, setAddType] = useState<IocType>("ip");
  const [addValue, setAddValue] = useState("");
  const [addConfidence, setAddConfidence] = useState(80);
  const [addTlp, setAddTlp] = useState<TLP>("amber");
  const [addTags, setAddTags] = useState("");
  const [addMitre, setAddMitre] = useState("");
  const [addKillChain, setAddKillChain] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  // Bulk import
  const [importFormat, setImportFormat] = useState<"stix" | "csv" | "text">("text");
  const [importData, setImportData] = useState("");
  const [importResult, setImportResult] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { iocs: apiIocs } = await listIocs({ limit: 500 });
      setIocs(apiIocs.map(adaptIoc));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { reload(); }, [reload]);

  useEffect(() => {
    if (activeTab !== "graph") return;
    getIocGraph(200).then(setGraphData).catch(() => setGraphData({ nodes: [], edges: [] }));
  }, [activeTab, iocs.length]);

  // Filter (client-side for responsiveness on the already-loaded list)
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

  const handleAddIOC = useCallback(async () => {
    if (!addValue.trim()) return;
    setFormError(null);
    try {
      await createIoc({
        type: TYPE_UI_TO_API[addType],
        value: addValue.trim(),
        confidence: addConfidence,
        tlp: addTlp.toUpperCase(),
        source: "manual",
        tags: addTags.split(",").map(t => t.trim()).filter(Boolean),
        mitre_techniques: addMitre ? [addMitre] : undefined,
        kill_chain_phase: addKillChain || undefined,
      });
      setAddValue(""); setAddTags(""); setAddMitre(""); setAddKillChain("");
      setActiveTab("dashboard");
      await reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : "Create failed");
    }
  }, [addType, addValue, addConfidence, addTlp, addTags, addMitre, addKillChain, reload]);

  const handleBulkImport = useCallback(async () => {
    if (!importData.trim()) return;
    setImportResult(null);
    try {
      const { count } = await bulkImportIocs({ format: importFormat, data: importData, source: "bulk_import" });
      setImportResult(`${count} IOCs imported`);
      setImportData("");
      await reload();
    } catch (e) {
      setImportResult(`Import failed: ${e instanceof Error ? e.message : "unknown"}`);
    }
  }, [importData, importFormat, reload]);

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

  const handleRevokeIOC = useCallback(async (id: number) => {
    try { await revokeIoc(id); await reload(); } catch (e) { setError(e instanceof Error ? e.message : "Revoke failed"); }
    setShowDetail(false);
  }, [reload]);

  const handleMarkFP = useCallback(async (id: number) => {
    try { await markIocFalsePositive(id); await reload(); } catch (e) { setError(e instanceof Error ? e.message : "Mark FP failed"); }
    setShowDetail(false);
  }, [reload]);

  const tabs: HudTabItem<Tab>[] = [
    { id: "dashboard", label: "IOC Table" },
    { id: "add", label: "Add IOC" },
    { id: "import", label: "Bulk Import" },
    { id: "graph", label: "Graph" },
  ];

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="INDICATORS OF COMPROMISE // STIX/TAXII // ENRICHMENT">
          IOC Management
        </HudHeading>
        <div className="flex gap-2">
          <HudButton variant="secondary" size="sm" onClick={reload}>REFRESH</HudButton>
          <HudButton variant="primary" size="sm" onClick={() => handleExport("stix")}>STIX</HudButton>
          <HudButton variant="secondary" size="sm" onClick={() => handleExport("csv")}>CSV</HudButton>
          <HudButton variant="secondary" size="sm" onClick={() => handleExport("openioc")}>OpenIOC</HudButton>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <HudCard tone="alert" className="px-4 py-2 text-[11px] text-neon-pink">{error}</HudCard>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <HudStat label="TOTAL IOCs" value={stats.total} />
        <HudStat label="ACTIVE" value={stats.active} tone="matrix" />
        <HudStat label="HIGH CONF" value={stats.highConf} />
        <HudStat label="MEDIUM CONF" value={stats.medConf} tone="warn" />
        <HudStat label="LOW CONF" value={stats.lowConf} tone="alert" />
        <HudStat label="IOC TYPES" value={Object.keys(stats.byType).length} tone="purple" />
      </div>

      {/* Tabs */}
      <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />

      {/* Dashboard Tab */}
      {activeTab === "dashboard" && (
        <div className="space-y-4">
          {/* Filters */}
          <HudCard className="flex flex-wrap items-center gap-3 px-4 py-3">
            <span className="text-[10px] font-bold tracking-widest text-gray-500">FILTERS</span>
            <HudInput type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IOCs..." className="w-48 text-xs" mono />
            <HudSelect value={filterType} onChange={e => setFilterType(e.target.value as IocType | "all")} className="w-auto text-xs">
              <option value="all">All Types</option>
              {(Object.keys(IOC_TYPE_ICONS) as IocType[]).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
            </HudSelect>
            <HudSelect value={filterState} onChange={e => setFilterState(e.target.value as IocState | "all")} className="w-auto text-xs">
              <option value="all">All States</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
              <option value="false-positive">False Positive</option>
              <option value="expired">Expired</option>
            </HudSelect>
            <HudSelect value={filterTlp} onChange={e => setFilterTlp(e.target.value as TLP | "all")} className="w-auto text-xs">
              <option value="all">All TLP</option>
              <option value="white">TLP:WHITE</option>
              <option value="green">TLP:GREEN</option>
              <option value="amber">TLP:AMBER</option>
              <option value="red">TLP:RED</option>
            </HudSelect>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-gray-500">Conf &ge;</span>
              <input type="range" min={0} max={100} value={confidenceMin} onChange={e => setConfidenceMin(Number(e.target.value))} className="w-20 accent-cyan-400" />
              <span className="text-[10px] text-cyan-glow font-mono">{confidenceMin}%</span>
            </div>
            <span className="ml-auto text-xs text-gray-500 font-mono">{filtered.length} / {iocs.length} results</span>
          </HudCard>

          {/* IOC Table */}
          <HudCard className="overflow-hidden p-0">
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
                      <td className="px-3 py-3 text-[10px] font-mono text-gray-500">{ioc.firstSeen ? new Date(ioc.firstSeen).toLocaleDateString() : "-"}</td>
                      <td className="px-3 py-3 text-[10px] font-mono text-gray-500">{ioc.lastSeen ? new Date(ioc.lastSeen).toLocaleDateString() : "-"}</td>
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
            {loading && iocs.length === 0 && (
              <div className="py-12 text-center">
                <p className="text-sm text-gray-500">Loading IOCs...</p>
              </div>
            )}
            {!loading && filtered.length === 0 && (
              <div className="py-12 text-center">
                <p className="text-sm text-gray-500">{iocs.length === 0 ? "No IOCs yet — add one or bulk import" : "No IOCs match your filters"}</p>
              </div>
            )}
          </HudCard>
        </div>
      )}

      {/* Add IOC Tab */}
      {activeTab === "add" && (
        <HudCard className="p-6 space-y-4 max-w-2xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">ADD NEW IOC</h3>
          {formError && <p className="text-xs text-red-400">{formError}</p>}
          <div className="grid grid-cols-2 gap-4">
            <HudField label="Type">
              <HudSelect value={addType} onChange={e => setAddType(e.target.value as IocType)}>
                {(Object.keys(IOC_TYPE_ICONS) as IocType[]).map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </HudSelect>
            </HudField>
            <HudField label="TLP">
              <HudSelect value={addTlp} onChange={e => setAddTlp(e.target.value as TLP)}>
                <option value="white">TLP:WHITE</option>
                <option value="green">TLP:GREEN</option>
                <option value="amber">TLP:AMBER</option>
                <option value="red">TLP:RED</option>
              </HudSelect>
            </HudField>
          </div>
          <HudField label="Value">
            <HudInput type="text" value={addValue} onChange={e => setAddValue(e.target.value)} placeholder="e.g. 185.220.101.34" mono />
          </HudField>
          <HudField label={`Confidence: ${addConfidence}%`}>
            <input type="range" min={0} max={100} value={addConfidence} onChange={e => setAddConfidence(Number(e.target.value))} className="w-full accent-cyan-400" />
          </HudField>
          <div className="grid grid-cols-2 gap-4">
            <HudField label="Tags (comma-separated)">
              <HudInput type="text" value={addTags} onChange={e => setAddTags(e.target.value)} placeholder="e.g. botnet, c2" mono />
            </HudField>
            <HudField label="MITRE Technique">
              <HudInput type="text" value={addMitre} onChange={e => setAddMitre(e.target.value)} placeholder="e.g. T1071.001" mono />
            </HudField>
          </div>
          <HudField label="Kill Chain Phase">
            <HudSelect value={addKillChain} onChange={e => setAddKillChain(e.target.value)}>
              <option value="">None</option>
              <option value="Reconnaissance">Reconnaissance</option>
              <option value="Weaponization">Weaponization</option>
              <option value="Delivery">Delivery</option>
              <option value="Exploitation">Exploitation</option>
              <option value="Installation">Installation</option>
              <option value="C2">C2</option>
              <option value="Actions">Actions on Objectives</option>
            </HudSelect>
          </HudField>
          <HudButton variant="primary" disabled={!addValue.trim()} onClick={handleAddIOC}>
            ADD IOC
          </HudButton>
        </HudCard>
      )}

      {/* Bulk Import Tab */}
      {activeTab === "import" && (
        <HudCard className="p-6 space-y-4 max-w-2xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">BULK IMPORT IOCs</h3>
          {importResult && <p className="text-xs text-cyan-glow">{importResult}</p>}
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">FORMAT</label>
            <div className="flex gap-2">
              {(["text", "csv", "stix"] as const).map(f => (
                <HudButton key={f} size="sm" variant={importFormat === f ? "primary" : "secondary"} onClick={() => setImportFormat(f)}>
                  {f.toUpperCase()}
                </HudButton>
              ))}
            </div>
          </div>
          <HudField label="Data">
            <HudTextarea value={importData} onChange={e => setImportData(e.target.value)} rows={12} placeholder={importFormat === "text" ? "One IOC per line:\n185.220.101.34\nevil.com\n..." : importFormat === "csv" ? "value,type,confidence\n185.220.101.34,ip,90\n..." : '{"type": "bundle", "objects": [...]}'} />
          </HudField>
          <HudButton variant="primary" disabled={!importData.trim()} onClick={handleBulkImport}>
            IMPORT
          </HudButton>
        </HudCard>
      )}

      {/* Graph Tab */}
      {activeTab === "graph" && (
        <HudCard className="p-4">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">IOC RELATIONSHIP GRAPH</h3>
          <RelationshipGraph data={graphData} selectedId={selectedIoc?.id || null} />
          <p className="text-[10px] text-gray-500 mt-2 text-center">Click an IOC in the table to focus the graph on its relationships</p>
        </HudCard>
      )}

      {/* Detail Modal */}
      {showDetail && selectedIoc && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-space-deep/60 backdrop-blur-sm" onClick={() => setShowDetail(false)}>
          <HudCard className="w-full max-w-2xl max-h-[80vh] overflow-y-auto p-6 space-y-4 m-4" onClick={e => e.stopPropagation()}>
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
                <p className="text-xs font-mono text-gray-300">{selectedIoc.firstSeen ? new Date(selectedIoc.firstSeen).toLocaleString() : "-"}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">LAST SEEN</p>
                <p className="text-xs font-mono text-gray-300">{selectedIoc.lastSeen ? new Date(selectedIoc.lastSeen).toLocaleString() : "-"}</p>
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
            {selectedIoc.tags.length > 0 && (
              <div>
                <p className="text-[10px] font-bold tracking-widest text-gray-500">TAGS</p>
                <div className="flex flex-wrap gap-1.5 mt-1">
                  {selectedIoc.tags.map(tag => (
                    <span key={tag} className="rounded-full border border-cyan-glow/20 bg-cyan-glow/5 px-2.5 py-0.5 text-[10px] text-cyan-glow">{tag}</span>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-2 border-t border-gray-800">
              <HudButton variant="danger" disabled={selectedIoc.state === "revoked"} onClick={() => handleRevokeIOC(selectedIoc.id)}>REVOKE</HudButton>
              <HudButton variant="secondary" disabled={selectedIoc.state === "false-positive"} onClick={() => handleMarkFP(selectedIoc.id)}>MARK FALSE POSITIVE</HudButton>
            </div>
          </HudCard>
        </div>
      )}
    </div>
  );
}
