"use client";

import { useState, useMemo, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type FeedType = "taxii" | "stix" | "csv" | "misp" | "text";

interface ThreatFeed {
  id: string;
  name: string;
  type: FeedType;
  url: string;
  interval: number; // minutes
  lastPoll: string | null;
  status: "active" | "error" | "disabled";
  iocCount: number;
  enabled: boolean;
  confidenceMapping: number;
  errorLog: string[];
  pollHistory: { date: string; iocCount: number; duration: number }[];
}

// ---------------------------------------------------------------------------
// Demo Data
// ---------------------------------------------------------------------------
function generateFeeds(): ThreatFeed[] {
  return [
    { id: "f1", name: "URLhaus", type: "csv", url: "https://urlhaus.abuse.ch/downloads/csv_recent/", interval: 60, lastPoll: "2026-03-28T15:30:00Z", status: "active", iocCount: 1245, enabled: true, confidenceMapping: 80, errorLog: [], pollHistory: [
      { date: "2026-03-28T15:30:00Z", iocCount: 45, duration: 3.2 },
      { date: "2026-03-28T14:30:00Z", iocCount: 38, duration: 2.8 },
      { date: "2026-03-28T13:30:00Z", iocCount: 52, duration: 4.1 },
      { date: "2026-03-28T12:30:00Z", iocCount: 41, duration: 3.0 },
    ]},
    { id: "f2", name: "MalwareBazaar", type: "csv", url: "https://bazaar.abuse.ch/export/csv/recent/", interval: 120, lastPoll: "2026-03-28T14:00:00Z", status: "active", iocCount: 892, enabled: true, confidenceMapping: 90, errorLog: [], pollHistory: [
      { date: "2026-03-28T14:00:00Z", iocCount: 28, duration: 5.5 },
      { date: "2026-03-28T12:00:00Z", iocCount: 33, duration: 6.1 },
    ]},
    { id: "f3", name: "ThreatFox IOCs", type: "csv", url: "https://threatfox.abuse.ch/export/csv/recent/", interval: 60, lastPoll: "2026-03-28T15:00:00Z", status: "active", iocCount: 567, enabled: true, confidenceMapping: 85, errorLog: [], pollHistory: [
      { date: "2026-03-28T15:00:00Z", iocCount: 22, duration: 2.1 },
      { date: "2026-03-28T14:00:00Z", iocCount: 19, duration: 1.8 },
    ]},
    { id: "f4", name: "Emerging Threats", type: "text", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", interval: 360, lastPoll: "2026-03-28T12:00:00Z", status: "active", iocCount: 2340, enabled: true, confidenceMapping: 70, errorLog: [], pollHistory: [
      { date: "2026-03-28T12:00:00Z", iocCount: 2340, duration: 8.3 },
    ]},
    { id: "f5", name: "Tor Exit Nodes", type: "text", url: "https://check.torproject.org/torbulkexitlist", interval: 720, lastPoll: "2026-03-28T08:00:00Z", status: "active", iocCount: 1089, enabled: true, confidenceMapping: 95, errorLog: [], pollHistory: [
      { date: "2026-03-28T08:00:00Z", iocCount: 1089, duration: 1.5 },
    ]},
    { id: "f6", name: "Feodo Tracker", type: "csv", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", interval: 60, lastPoll: "2026-03-28T15:15:00Z", status: "active", iocCount: 456, enabled: true, confidenceMapping: 92, errorLog: [], pollHistory: [
      { date: "2026-03-28T15:15:00Z", iocCount: 15, duration: 1.2 },
    ]},
    { id: "f7", name: "PhishTank", type: "csv", url: "https://data.phishtank.com/data/online-valid.csv", interval: 180, lastPoll: "2026-03-28T13:00:00Z", status: "error", iocCount: 3421, enabled: true, confidenceMapping: 75, errorLog: ["2026-03-28T16:00:00Z: HTTP 429 Too Many Requests", "2026-03-28T15:00:00Z: Timeout after 30s"], pollHistory: [
      { date: "2026-03-28T13:00:00Z", iocCount: 120, duration: 12.4 },
    ]},
    { id: "f8", name: "AlienVault OTX", type: "stix", url: "https://otx.alienvault.com/api/v1/pulses/subscribed", interval: 240, lastPoll: null, status: "disabled", iocCount: 0, enabled: false, confidenceMapping: 80, errorLog: [], pollHistory: [] },
    { id: "f9", name: "Custom TAXII Server", type: "taxii", url: "https://taxii.company.local/taxii2/", interval: 30, lastPoll: "2026-03-28T15:45:00Z", status: "active", iocCount: 178, enabled: true, confidenceMapping: 85, errorLog: [], pollHistory: [
      { date: "2026-03-28T15:45:00Z", iocCount: 12, duration: 0.8 },
      { date: "2026-03-28T15:15:00Z", iocCount: 8, duration: 0.6 },
    ]},
  ];
}

const FEED_TYPE_COLORS: Record<FeedType, string> = {
  taxii: "bg-purple-500/15 text-purple-400 border-purple-500/20",
  stix: "bg-blue-500/15 text-blue-400 border-blue-500/20",
  csv: "bg-green-500/15 text-green-400 border-green-500/20",
  misp: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  text: "bg-gray-500/15 text-gray-300 border-gray-500/20",
};

const BUILTIN_FEEDS = [
  { name: "URLhaus", desc: "Malicious URLs by abuse.ch", url: "https://urlhaus.abuse.ch/downloads/csv_recent/", type: "csv" as FeedType },
  { name: "MalwareBazaar", desc: "Malware samples hashes", url: "https://bazaar.abuse.ch/export/csv/recent/", type: "csv" as FeedType },
  { name: "ThreatFox", desc: "IOCs from ThreatFox", url: "https://threatfox.abuse.ch/export/csv/recent/", type: "csv" as FeedType },
  { name: "Emerging Threats", desc: "Compromised IPs blocklist", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", type: "text" as FeedType },
  { name: "Tor Exit Nodes", desc: "Active Tor exit relays", url: "https://check.torproject.org/torbulkexitlist", type: "text" as FeedType },
  { name: "Feodo Tracker", desc: "Botnet C2 servers", url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", type: "csv" as FeedType },
  { name: "PhishTank", desc: "Verified phishing URLs", url: "https://data.phishtank.com/data/online-valid.csv", type: "csv" as FeedType },
  { name: "AlienVault OTX", desc: "Open Threat Exchange pulses", url: "https://otx.alienvault.com/api/v1/pulses/subscribed", type: "stix" as FeedType },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function FeedsPage() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>(generateFeeds);
  const [activeTab, setActiveTab] = useState<"feeds" | "add" | "builtin" | "health">("feeds");
  const [selectedFeed, setSelectedFeed] = useState<ThreatFeed | null>(null);
  const [polling, setPolling] = useState<string | null>(null);

  // Add feed form
  const [addName, setAddName] = useState("");
  const [addUrl, setAddUrl] = useState("");
  const [addType, setAddType] = useState<FeedType>("csv");
  const [addInterval, setAddInterval] = useState(60);
  const [addConfidence, setAddConfidence] = useState(80);

  const totalIocs = useMemo(() => feeds.reduce((sum, f) => sum + f.iocCount, 0), [feeds]);
  const activeFeeds = useMemo(() => feeds.filter(f => f.status === "active").length, [feeds]);
  const errorFeeds = useMemo(() => feeds.filter(f => f.status === "error").length, [feeds]);

  const handleToggleFeed = useCallback((id: string) => {
    setFeeds(prev => prev.map(f => {
      if (f.id !== id) return f;
      const enabled = !f.enabled;
      return { ...f, enabled, status: enabled ? "active" : "disabled" };
    }));
  }, []);

  const handlePoll = useCallback(async (id: string) => {
    setPolling(id);
    await new Promise(r => setTimeout(r, 2000));
    setFeeds(prev => prev.map(f => {
      if (f.id !== id) return f;
      const newIocs = Math.floor(Math.random() * 50) + 5;
      return {
        ...f,
        lastPoll: new Date().toISOString(),
        iocCount: f.iocCount + newIocs,
        status: "active",
        pollHistory: [{ date: new Date().toISOString(), iocCount: newIocs, duration: Math.random() * 5 + 0.5 }, ...f.pollHistory],
      };
    }));
    setPolling(null);
  }, []);

  const handleAddFeed = useCallback(() => {
    if (!addName.trim() || !addUrl.trim()) return;
    const newFeed: ThreatFeed = {
      id: `f-${Date.now()}`,
      name: addName.trim(),
      type: addType,
      url: addUrl.trim(),
      interval: addInterval,
      lastPoll: null,
      status: "active",
      iocCount: 0,
      enabled: true,
      confidenceMapping: addConfidence,
      errorLog: [],
      pollHistory: [],
    };
    setFeeds(prev => [newFeed, ...prev]);
    setAddName(""); setAddUrl("");
    setActiveTab("feeds");
  }, [addName, addUrl, addType, addInterval, addConfidence]);

  const handleEnableBuiltin = useCallback((name: string, url: string, type: FeedType) => {
    if (feeds.find(f => f.url === url)) return;
    const newFeed: ThreatFeed = {
      id: `f-${Date.now()}`,
      name,
      type,
      url,
      interval: 60,
      lastPoll: null,
      status: "active",
      iocCount: 0,
      enabled: true,
      confidenceMapping: 80,
      errorLog: [],
      pollHistory: [],
    };
    setFeeds(prev => [newFeed, ...prev]);
  }, [feeds]);

  return (
    <div className="flex h-full flex-col gap-4 p-6 overflow-y-auto">
      {/* Header */}
      <div>
        <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
          Threat Feed Management
        </h1>
        <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
          STIX/TAXII // CSV // MISP // AUTOMATED INGESTION
        </p>
      </div>
      <div className="cyan-line" />

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-cyan-glow font-mono">{feeds.length}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOTAL FEEDS</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-green-400 font-mono">{activeFeeds}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">ACTIVE</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-red-400 font-mono">{errorFeeds}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">ERRORS</p>
        </div>
        <div className="glass-panel p-3 text-center">
          <p className="text-2xl font-bold text-cyan-glow font-mono">{totalIocs.toLocaleString()}</p>
          <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOTAL IOCs</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(["feeds", "add", "builtin", "health"] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${activeTab === tab ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow" : "border-gray-700 text-gray-500 hover:border-gray-600"}`}>
            {tab === "feeds" ? "ACTIVE FEEDS" : tab === "add" ? "ADD FEED" : tab === "builtin" ? "BUILT-IN FEEDS" : "HEALTH"}
          </button>
        ))}
      </div>

      {/* Active Feeds Tab */}
      {activeTab === "feeds" && (
        <div className="space-y-4">
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">NAME</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">TYPE</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">URL</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">INTERVAL</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">LAST POLL</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">STATUS</th>
                  <th className="px-4 py-3 text-left text-[10px] font-bold tracking-widest text-gray-500">IOCs</th>
                  <th className="px-4 py-3 text-right text-[10px] font-bold tracking-widest text-gray-500">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {feeds.map(feed => (
                  <tr key={feed.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5 cursor-pointer transition-colors" onClick={() => setSelectedFeed(feed)}>
                    <td className="px-4 py-3 text-sm text-gray-200 font-medium">{feed.name}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded border px-2 py-0.5 text-[10px] font-bold ${FEED_TYPE_COLORS[feed.type]}`}>{feed.type.toUpperCase()}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-[10px] text-gray-400 max-w-[200px] truncate">{feed.url}</td>
                    <td className="px-4 py-3 text-[10px] text-gray-400">{feed.interval}m</td>
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-500">{feed.lastPoll ? new Date(feed.lastPoll).toLocaleTimeString() : "Never"}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className={`h-2 w-2 rounded-full ${feed.status === "active" ? "bg-green-400" : feed.status === "error" ? "bg-red-400" : "bg-gray-500"}`} />
                        <span className={`text-[10px] font-bold ${feed.status === "active" ? "text-green-400" : feed.status === "error" ? "text-red-400" : "text-gray-500"}`}>{feed.status.toUpperCase()}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[10px] font-mono text-cyan-glow">{feed.iocCount.toLocaleString()}</td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2" onClick={e => e.stopPropagation()}>
                        <button onClick={() => handlePoll(feed.id)} disabled={polling === feed.id || !feed.enabled} className={`rounded border border-cyan-glow/20 px-2 py-0.5 text-[10px] font-bold text-cyan-glow hover:bg-cyan-glow/10 transition-colors disabled:opacity-30 ${polling === feed.id ? "animate-pulse" : ""}`}>
                          {polling === feed.id ? "POLLING..." : "POLL"}
                        </button>
                        <button onClick={() => handleToggleFeed(feed.id)} className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${feed.enabled ? "bg-green-500/15 text-green-400 hover:bg-green-500/25" : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"}`}>
                          {feed.enabled ? "ON" : "OFF"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Feed Detail */}
          {selectedFeed && (
            <div className="glass-panel p-4 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-cyan-glow">{selectedFeed.name}</h3>
                <button onClick={() => setSelectedFeed(null)} className="text-gray-500 hover:text-gray-300 text-xs">&times; Close</button>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-[10px] font-bold tracking-widest text-gray-500">POLL HISTORY</p>
                  {selectedFeed.pollHistory.length === 0 ? (
                    <p className="text-xs text-gray-500 mt-1">No polls yet</p>
                  ) : (
                    <div className="mt-1 space-y-1">
                      {selectedFeed.pollHistory.slice(0, 5).map((p, i) => (
                        <div key={i} className="flex items-center justify-between text-[10px]">
                          <span className="text-gray-400 font-mono">{new Date(p.date).toLocaleTimeString()}</span>
                          <span className="text-cyan-glow font-mono">+{p.iocCount} IOCs</span>
                          <span className="text-gray-500">{p.duration.toFixed(1)}s</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div>
                  <p className="text-[10px] font-bold tracking-widest text-gray-500">IOC STATS</p>
                  <div className="mt-2">
                    <div className="flex justify-between text-[10px] mb-1">
                      <span className="text-gray-400">Total Imported</span>
                      <span className="text-cyan-glow font-mono">{selectedFeed.iocCount.toLocaleString()}</span>
                    </div>
                    <div className="flex justify-between text-[10px] mb-1">
                      <span className="text-gray-400">Confidence</span>
                      <span className="text-cyan-glow font-mono">{selectedFeed.confidenceMapping}%</span>
                    </div>
                    <div className="flex justify-between text-[10px]">
                      <span className="text-gray-400">Avg per poll</span>
                      <span className="text-cyan-glow font-mono">
                        {selectedFeed.pollHistory.length > 0 ? Math.round(selectedFeed.pollHistory.reduce((s, p) => s + p.iocCount, 0) / selectedFeed.pollHistory.length) : 0}
                      </span>
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-bold tracking-widest text-gray-500">ERROR LOG</p>
                  {selectedFeed.errorLog.length === 0 ? (
                    <p className="text-xs text-green-400 mt-1">No errors</p>
                  ) : (
                    <div className="mt-1 space-y-1">
                      {selectedFeed.errorLog.map((e, i) => (
                        <p key={i} className="text-[10px] text-red-400 font-mono">{e}</p>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Add Feed Tab */}
      {activeTab === "add" && (
        <div className="glass-panel p-6 space-y-4 max-w-2xl">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">ADD THREAT FEED</h3>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">NAME</label>
            <input type="text" value={addName} onChange={e => setAddName(e.target.value)} placeholder="e.g. My Custom Feed" className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <div>
            <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">URL</label>
            <input type="text" value={addUrl} onChange={e => setAddUrl(e.target.value)} placeholder="https://..." className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">TYPE</label>
              <select value={addType} onChange={e => setAddType(e.target.value as FeedType)} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                <option value="taxii">TAXII</option>
                <option value="stix">STIX</option>
                <option value="csv">CSV</option>
                <option value="misp">MISP</option>
                <option value="text">Text</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">POLL INTERVAL (min)</label>
              <input type="number" value={addInterval} onChange={e => setAddInterval(Number(e.target.value))} min={5} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-widest text-gray-500 block mb-1">CONFIDENCE MAPPING</label>
              <input type="number" value={addConfidence} onChange={e => setAddConfidence(Number(e.target.value))} min={0} max={100} className="w-full rounded border border-gray-700 bg-gray-900/80 px-3 py-2 text-xs text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none" />
            </div>
          </div>
          <button onClick={handleAddFeed} disabled={!addName.trim() || !addUrl.trim()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50">
            ADD FEED
          </button>
        </div>
      )}

      {/* Built-in Feeds Tab */}
      {activeTab === "builtin" && (
        <div className="space-y-3">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">FREE THREAT FEEDS - ONE CLICK ENABLE</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {BUILTIN_FEEDS.map(bf => {
              const alreadyEnabled = feeds.some(f => f.url === bf.url);
              return (
                <div key={bf.name} className="glass-panel p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-bold text-gray-200">{bf.name}</h4>
                    <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold ${FEED_TYPE_COLORS[bf.type]}`}>{bf.type.toUpperCase()}</span>
                  </div>
                  <p className="text-[10px] text-gray-500">{bf.desc}</p>
                  <button
                    onClick={() => handleEnableBuiltin(bf.name, bf.url, bf.type)}
                    disabled={alreadyEnabled}
                    className={`w-full rounded border px-3 py-1.5 text-[10px] font-bold tracking-widest transition-colors ${alreadyEnabled ? "border-green-500/30 bg-green-500/10 text-green-400" : "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow hover:bg-cyan-glow/20"}`}
                  >
                    {alreadyEnabled ? "ENABLED" : "ENABLE"}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Health Tab */}
      {activeTab === "health" && (
        <div className="space-y-4">
          <h3 className="text-[10px] font-bold tracking-widest text-gray-500">FEED HEALTH DASHBOARD</h3>
          <div className="glass-panel p-4">
            <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">IOCs IMPORTED OVER TIME (per feed)</p>
            <div className="space-y-3">
              {feeds.filter(f => f.pollHistory.length > 0).map(feed => {
                const maxIoc = Math.max(...feed.pollHistory.map(p => p.iocCount), 1);
                return (
                  <div key={feed.id} className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-gray-300">{feed.name}</span>
                      <span className="text-[10px] font-mono text-cyan-glow">{feed.iocCount.toLocaleString()} total</span>
                    </div>
                    <div className="flex gap-1 h-8 items-end">
                      {feed.pollHistory.slice().reverse().map((p, i) => (
                        <div key={i} className="flex-1 bg-cyan-glow/20 rounded-t hover:bg-cyan-glow/40 transition-colors relative group" style={{ height: `${(p.iocCount / maxIoc) * 100}%`, minHeight: 4 }}>
                          <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block glass-panel px-2 py-1 text-[9px] text-gray-300 whitespace-nowrap z-10">
                            +{p.iocCount} IOCs @ {new Date(p.date).toLocaleTimeString()}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div className="glass-panel p-4">
            <p className="text-[10px] font-bold tracking-widest text-gray-500 mb-3">FEED STATUS OVERVIEW</p>
            <div className="grid grid-cols-3 gap-3">
              {feeds.map(feed => (
                <div key={feed.id} className="flex items-center gap-2 p-2 rounded border border-gray-800">
                  <div className={`h-3 w-3 rounded-full ${feed.status === "active" ? "bg-green-400" : feed.status === "error" ? "bg-red-400 animate-pulse" : "bg-gray-600"}`} />
                  <span className="text-xs text-gray-300 flex-1">{feed.name}</span>
                  <span className="text-[10px] font-mono text-gray-500">{feed.lastPoll ? new Date(feed.lastPoll).toLocaleTimeString() : "--:--"}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
