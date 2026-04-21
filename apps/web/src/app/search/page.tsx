"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AnimatePresence, motion } from "framer-motion";
import { CQLEditor } from "@/components/CQLEditor";
import { SearchResults, type SearchResultData, type ViewMode } from "@/components/SearchResults";
import { FieldExplorer, type FieldInfo } from "@/components/FieldExplorer";
import { cqlSearch, getCqlFields, type CqlSearchResponse } from "@/lib/apiClient";

/* ------------------------------------------------------------------ */
/*  Time range presets                                                 */
/* ------------------------------------------------------------------ */

const TIME_PRESETS = [
  { label: "15m", value: "15m" },
  { label: "1h", value: "1h" },
  { label: "4h", value: "4h" },
  { label: "24h", value: "24h" },
  { label: "7d", value: "7d" },
  { label: "30d", value: "30d" },
  { label: "Custom", value: "custom" },
] as const;

const AUTO_REFRESH_OPTIONS = [
  { label: "Off", value: 0 },
  { label: "5s", value: 5000 },
  { label: "15s", value: 15000 },
  { label: "30s", value: 30000 },
  { label: "1m", value: 60000 },
  { label: "5m", value: 300000 },
];

/* ------------------------------------------------------------------ */
/*  Saved query types                                                  */
/* ------------------------------------------------------------------ */

interface SavedQuery {
  id: string;
  name: string;
  description: string;
  category: "threat-hunting" | "incident-response" | "compliance" | "monitoring" | "custom";
  tags: string[];
  query: string;
  builtIn: boolean;
  lastRun?: string;
  author: string;
}

/* ------------------------------------------------------------------ */
/*  Built-in queries library                                           */
/* ------------------------------------------------------------------ */

const BUILTIN_QUERIES: SavedQuery[] = [
  { id: "b1", name: "Brute Force Detection", description: "Detect multiple failed login attempts from same IP", category: "threat-hunting", tags: ["auth", "brute-force", "T1110"], query: 'event_type="auth.fail" | stats count by src_ip | where count > 10 | sort -count', builtIn: true, author: "System" },
  { id: "b2", name: "Lateral Movement", description: "Track internal-to-internal connections on uncommon ports", category: "threat-hunting", tags: ["lateral", "T1021"], query: 'src_ip="10.0.0.0/8" AND dst_ip="10.0.0.0/8" AND port!=443 AND port!=80 | stats count by src_ip, dst_ip, port | where count > 5', builtIn: true, author: "System" },
  { id: "b3", name: "Data Exfiltration", description: "Large outbound data transfers to external IPs", category: "threat-hunting", tags: ["exfil", "T1048"], query: 'direction="outbound" AND bytes > 10000000 | stats sum(bytes) as total_bytes by dst_ip | sort -total_bytes | head 20', builtIn: true, author: "System" },
  { id: "b4", name: "DNS Tunneling", description: "Detect suspiciously long DNS queries", category: "threat-hunting", tags: ["dns", "tunneling", "T1071"], query: 'event_type="dns" | eval query_len=len(dns_query) | where query_len > 50 | stats count by src_ip | sort -count', builtIn: true, author: "System" },
  { id: "b5", name: "Privilege Escalation", description: "Track privilege escalation events", category: "threat-hunting", tags: ["privesc", "T1068"], query: 'event_type="privesc" OR event_type="sudo" OR event_type="runas" | stats count by username, src_ip | sort -count', builtIn: true, author: "System" },
  { id: "b6", name: "Suspicious Processes", description: "Detect known malicious process names", category: "threat-hunting", tags: ["process", "T1059"], query: 'process_name IN ("mimikatz", "psexec", "procdump", "nc.exe", "ncat") | table timestamp, src_ip, username, process_name, cmdline', builtIn: true, author: "System" },
  { id: "b7", name: "Critical Events Overview", description: "All critical severity events in time buckets", category: "monitoring", tags: ["critical", "overview"], query: 'severity="critical" | timechart count by event_type', builtIn: true, author: "System" },
  { id: "b8", name: "Top Talkers", description: "Most active source IPs by event count", category: "monitoring", tags: ["traffic", "top"], query: '* | stats count by src_ip | sort -count | head 25', builtIn: true, author: "System" },
  { id: "b9", name: "Failed Auth Timeline", description: "Authentication failures over time", category: "incident-response", tags: ["auth", "timeline"], query: 'event_type="auth.fail" | timechart count by username', builtIn: true, author: "System" },
  { id: "b10", name: "Port Scan Detection", description: "Detect hosts scanning multiple ports", category: "threat-hunting", tags: ["scan", "T1046"], query: '* | stats dc(port) as unique_ports by src_ip | where unique_ports > 20 | sort -unique_ports', builtIn: true, author: "System" },
  { id: "b11", name: "Malware Detection Events", description: "All malware-related detections", category: "incident-response", tags: ["malware", "detection"], query: 'event_type="malware.detect" OR event_type="malware.quarantine" | table timestamp, src_ip, file_path, hash, action', builtIn: true, author: "System" },
  { id: "b12", name: "Firewall Blocks", description: "Top blocked connections by firewall", category: "monitoring", tags: ["firewall", "block"], query: 'source="firewall" AND action="block" | stats count by src_ip, dst_ip, port | sort -count | head 50', builtIn: true, author: "System" },
  { id: "b13", name: "User Activity Audit", description: "Complete activity for a specific user", category: "compliance", tags: ["audit", "user"], query: 'username="admin" | sort timestamp | table timestamp, event_type, src_ip, action, message', builtIn: true, author: "System" },
  { id: "b14", name: "Severity Distribution", description: "Event count breakdown by severity", category: "monitoring", tags: ["stats", "severity"], query: '* | stats count by severity', builtIn: true, author: "System" },
  { id: "b15", name: "Geographic Anomalies", description: "Logins from unusual countries", category: "threat-hunting", tags: ["geo", "anomaly"], query: 'event_type="auth.success" | iplocation src_ip | stats count by country | sort -count', builtIn: true, author: "System" },
  { id: "b16", name: "Command & Control Beaconing", description: "Detect periodic connections to same destination", category: "threat-hunting", tags: ["c2", "beaconing", "T1071"], query: '* | stats count, dc(timestamp) as unique_times by src_ip, dst_ip | where count > 100 AND unique_times > 50 | sort -count', builtIn: true, author: "System" },
  { id: "b17", name: "HTTP Error Surge", description: "Spike in HTTP 4xx/5xx errors", category: "monitoring", tags: ["http", "errors"], query: 'status >= 400 | timechart count by status', builtIn: true, author: "System" },
  { id: "b18", name: "Registry Modifications", description: "Track Windows registry changes", category: "threat-hunting", tags: ["registry", "T1112"], query: 'event_type="registry.modify" | table timestamp, username, registry_key, process_name', builtIn: true, author: "System" },
  { id: "b19", name: "SSH Anomalies", description: "SSH connections from unexpected sources", category: "threat-hunting", tags: ["ssh", "T1021.004"], query: 'protocol="SSH" AND action="allow" | stats count by src_ip, dst_ip, username | where count < 3 | sort -count', builtIn: true, author: "System" },
  { id: "b20", name: "Event Source Health", description: "Check all log source activity", category: "monitoring", tags: ["health", "sources"], query: '* | stats count, max(timestamp) as last_event by source | sort -last_event', builtIn: true, author: "System" },
  { id: "b21", name: "MITRE Coverage", description: "Events mapped to MITRE techniques", category: "compliance", tags: ["mitre", "coverage"], query: 'mitre_technique!="" | stats count by mitre_tactic, mitre_technique | sort -count', builtIn: true, author: "System" },
  { id: "b22", name: "Encoded PowerShell", description: "Detect encoded PowerShell commands", category: "threat-hunting", tags: ["powershell", "T1059.001"], query: 'process_name="powershell.exe" AND cmdline CONTAINS "-enc" | table timestamp, username, cmdline', builtIn: true, author: "System" },
  { id: "b23", name: "DDoS Indicators", description: "High volume traffic from single sources", category: "incident-response", tags: ["ddos", "flood"], query: '* | stats count, sum(bytes) as total_bytes by src_ip | where count > 1000 | sort -count | head 10', builtIn: true, author: "System" },
  { id: "b24", name: "New User Accounts", description: "Recently created user accounts", category: "compliance", tags: ["user", "creation"], query: 'event_type="user.create" | sort -timestamp | table timestamp, username, src_ip, message', builtIn: true, author: "System" },
  { id: "b25", name: "SSL/TLS Anomalies", description: "Expired or self-signed certificate connections", category: "monitoring", tags: ["ssl", "certificates"], query: 'event_type="ssl.error" OR event_type="ssl.expired" | stats count by dst_ip, domain | sort -count', builtIn: true, author: "System" },
  { id: "b26", name: "File Integrity Changes", description: "Critical file modifications", category: "compliance", tags: ["fim", "integrity"], query: 'event_type="file.modify" AND file_path CONTAINS "/etc/" | table timestamp, src_ip, username, file_path, action', builtIn: true, author: "System" },
  { id: "b27", name: "VPN Anomalies", description: "Multiple VPN sessions per user", category: "threat-hunting", tags: ["vpn", "anomaly"], query: 'event_type="vpn.connect" | stats count, dc(src_ip) as unique_ips by username | where unique_ips > 2', builtIn: true, author: "System" },
  { id: "b28", name: "Rare Processes", description: "Processes seen on very few hosts", category: "threat-hunting", tags: ["process", "rare"], query: '* | stats dc(src_ip) as host_count by process_name | where host_count < 3 | sort host_count', builtIn: true, author: "System" },
  { id: "b29", name: "Event Volume Trend", description: "Overall event ingestion rate over time", category: "monitoring", tags: ["volume", "trend"], query: '* | timechart count', builtIn: true, author: "System" },
  { id: "b30", name: "Outbound to Rare Ports", description: "External connections on uncommon ports", category: "threat-hunting", tags: ["port", "outbound"], query: 'direction="outbound" AND port!=80 AND port!=443 AND port!=53 | stats count by dst_ip, port | where count < 5 | sort -count', builtIn: true, author: "System" },
];

/* ------------------------------------------------------------------ */
/*  Time range → earliest/latest                                       */
/* ------------------------------------------------------------------ */

function timeRangeToEarliest(tr: string, customFrom?: string): string {
  if (tr === "custom" && customFrom) return new Date(customFrom).toISOString();
  const map: Record<string, string> = {
    "15m": "-15m", "1h": "-1h", "4h": "-4h",
    "24h": "-24h", "7d": "-7d", "30d": "-30d",
  };
  return map[tr] ?? "-24h";
}
function timeRangeToLatest(tr: string, customTo?: string): string {
  if (tr === "custom" && customTo) return new Date(customTo).toISOString();
  return "now";
}

/* ------------------------------------------------------------------ */
/*  CQL response → SearchResultData                                    */
/* ------------------------------------------------------------------ */

function mapCqlResponse(resp: CqlSearchResponse): SearchResultData {
  const cmds = resp.metadata.commands ?? [];
  const hasTimechart = cmds.some((c) => c.toLowerCase().includes("timechart"));
  const hasStats = cmds.some((c) => {
    const lc = c.toLowerCase();
    return lc.includes("stats") || lc.includes("top") || lc.includes("rare") || lc.includes("chart");
  });
  const queryType: SearchResultData["queryType"] = hasTimechart ? "timechart" : hasStats ? "stats" : "events";

  const results = resp.results ?? [];
  const fieldSet = new Set<string>();
  for (const row of results) {
    for (const k of Object.keys(row)) fieldSet.add(k);
  }
  const fields = Array.from(fieldSet);

  return {
    events: results,
    totalCount: resp.metadata.total ?? results.length,
    queryTimeMs: resp.metadata.execution_time_ms ?? 0,
    queryType,
    fields,
  };
}

/* ------------------------------------------------------------------ */
/*  Derive field stats from results                                    */
/* ------------------------------------------------------------------ */

function deriveFields(events: Record<string, unknown>[]): FieldInfo[] {
  if (events.length === 0) return [];
  const stats = new Map<string, { values: Map<string, number>; nulls: number; total: number; sample: unknown }>();
  for (const ev of events) {
    for (const [k, v] of Object.entries(ev)) {
      if (!stats.has(k)) stats.set(k, { values: new Map(), nulls: 0, total: 0, sample: v });
      const s = stats.get(k)!;
      s.total += 1;
      if (v === null || v === undefined || v === "") {
        s.nulls += 1;
      } else {
        const vs = String(v);
        s.values.set(vs, (s.values.get(vs) ?? 0) + 1);
      }
    }
  }
  const out: FieldInfo[] = [];
  for (const [name, s] of stats) {
    let type: FieldInfo["type"] = "string";
    const sample = s.sample;
    if (typeof sample === "number") type = "number";
    else if (typeof sample === "string") {
      if (/^\d{4}-\d{2}-\d{2}T/.test(sample)) type = "time";
      else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(sample)) type = "ip";
    }
    const topValues = Array.from(s.values.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([value, count]) => ({ value, count }));
    out.push({
      name,
      type,
      count: s.total - s.nulls,
      unique: s.values.size,
      nullPct: s.total > 0 ? (s.nulls / s.total) * 100 : 0,
      topValues,
    });
  }
  return out.sort((a, b) => b.count - a.count);
}


/* ------------------------------------------------------------------ */
/*  Save query modal                                                   */
/* ------------------------------------------------------------------ */

function SaveQueryModal({
  query,
  onSave,
  onClose,
}: {
  query: string;
  onSave: (q: SavedQuery) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState<SavedQuery["category"]>("custom");
  const [tags, setTags] = useState("");

  return (
    <motion.div
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-space-deep/60 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      onClick={onClose}
    >
      <motion.div
        className="glass-panel w-full max-w-lg mx-4 p-6 shadow-cyan-glow"
        initial={{ opacity: 0, y: -20, scale: 0.96 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -12, scale: 0.97 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="hud-heading text-sm tracking-widest text-cyan-glow mb-4">
          SAVE QUERY
        </h3>

        <div className="space-y-3">
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-1">
              Name
            </label>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded border border-cyan-glow/15 bg-space-deep/50 px-3 py-2 text-sm text-gray-200 outline-none focus:border-cyan-glow/40 font-mono"
              placeholder="My detection query"
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-1">
              Description
            </label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded border border-cyan-glow/15 bg-space-deep/50 px-3 py-2 text-sm text-gray-200 outline-none focus:border-cyan-glow/40 font-mono"
              placeholder="Detect brute force attempts..."
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-1">
              Category
            </label>
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value as SavedQuery["category"])}
              className="w-full rounded border border-cyan-glow/15 bg-space-deep/50 px-3 py-2 text-sm text-gray-200 outline-none focus:border-cyan-glow/40"
            >
              <option value="threat-hunting">Threat Hunting</option>
              <option value="incident-response">Incident Response</option>
              <option value="compliance">Compliance</option>
              <option value="monitoring">Monitoring</option>
              <option value="custom">Custom</option>
            </select>
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-1">
              Tags (comma separated)
            </label>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              className="w-full rounded border border-cyan-glow/15 bg-space-deep/50 px-3 py-2 text-sm text-gray-200 outline-none focus:border-cyan-glow/40 font-mono"
              placeholder="auth, brute-force, T1110"
            />
          </div>

          <div className="rounded border border-cyan-glow/10 bg-space-deep/50 p-3">
            <span className="text-[9px] font-bold uppercase tracking-wider text-gray-600 mb-1 block">
              Query
            </span>
            <pre
              className="font-mono text-[11px] text-cyan-glow/60 whitespace-pre-wrap"
              style={{ fontFamily: "'JetBrains Mono', monospace" }}
            >
              {query}
            </pre>
          </div>
        </div>

        <div className="flex justify-end gap-2 mt-5">
          <button
            onClick={onClose}
            className="rounded border border-gray-700 px-4 py-2 text-[11px] font-bold tracking-wider text-gray-400 hover:bg-gray-800"
          >
            CANCEL
          </button>
          <button
            onClick={() => {
              onSave({
                id: `user-${Date.now()}`,
                name,
                description,
                category,
                tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
                query,
                builtIn: false,
                lastRun: new Date().toISOString(),
                author: "You",
              });
              onClose();
            }}
            disabled={!name.trim()}
            className="rounded border border-cyan-glow/40 bg-cyan-glow/15 px-4 py-2 text-[11px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/25 hover:shadow-cyan-md disabled:opacity-30"
          >
            SAVE
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main search page content                                           */
/* ------------------------------------------------------------------ */

function SearchContent() {
  const searchParams = useSearchParams();

  // State
  const [query, setQuery] = useState(searchParams.get("q") || "");
  const [timeRange, setTimeRange] = useState("24h");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("table");
  const [results, setResults] = useState<SearchResultData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize] = useState(50);
  const [fieldsPanelCollapsed, setFieldsPanelCollapsed] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(0);
  const [showSaveModal, setShowSaveModal] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showSavedQueries, setShowSavedQueries] = useState(false);
  const [savedQueriesTab, setSavedQueriesTab] = useState<"all" | SavedQuery["category"]>("all");
  const [userQueries, setUserQueries] = useState<SavedQuery[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      return JSON.parse(localStorage.getItem("cql_saved_queries") || "[]");
    } catch {
      return [];
    }
  });
  const [queryHistory, setQueryHistory] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    try {
      return JSON.parse(localStorage.getItem("cql_history") || "[]");
    } catch {
      return [];
    }
  });

  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [schemaFields, setSchemaFields] = useState<Record<string, { type: string; description: string }>>({});

  useEffect(() => {
    getCqlFields()
      .then((r) => setSchemaFields(r.fields ?? {}))
      .catch(() => setSchemaFields({}));
  }, []);

  // Execute search
  const executeSearch = useCallback(() => {
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setPage(0);

    setQueryHistory((prev) => {
      const next = [query, ...prev.filter((q) => q !== query)].slice(0, 20);
      localStorage.setItem("cql_history", JSON.stringify(next));
      return next;
    });

    const url = new URL(window.location.href);
    url.searchParams.set("q", query);
    url.searchParams.set("t", timeRange);
    window.history.replaceState({}, "", url.toString());

    const earliest = timeRangeToEarliest(timeRange, customFrom);
    const latest = timeRangeToLatest(timeRange, customTo);

    cqlSearch({ query, earliest, latest, limit: 500 })
      .then((resp) => {
        setResults(mapCqlResponse(resp));
        setLoading(false);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Query execution failed");
        setLoading(false);
      });
  }, [query, timeRange, customFrom, customTo]);

  // Auto-refresh
  useEffect(() => {
    if (autoRefreshRef.current) {
      clearInterval(autoRefreshRef.current);
      autoRefreshRef.current = null;
    }
    if (autoRefresh > 0 && query.trim()) {
      autoRefreshRef.current = setInterval(executeSearch, autoRefresh);
    }
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current);
    };
  }, [autoRefresh, executeSearch, query]);

  // Load query from URL on mount
  useEffect(() => {
    const q = searchParams.get("q");
    const t = searchParams.get("t");
    if (q) {
      setQuery(q);
      if (t) setTimeRange(t);
      setLoading(true);
      cqlSearch({ query: q, earliest: timeRangeToEarliest(t ?? "24h"), latest: "now", limit: 500 })
        .then((resp) => {
          setResults(mapCqlResponse(resp));
          setLoading(false);
        })
        .catch((err) => {
          setError(err instanceof Error ? err.message : "Query execution failed");
          setLoading(false);
        });
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Save user query
  const saveUserQuery = useCallback((q: SavedQuery) => {
    setUserQueries((prev) => {
      const next = [q, ...prev];
      localStorage.setItem("cql_saved_queries", JSON.stringify(next));
      return next;
    });
  }, []);

  // Delete user query
  const deleteUserQuery = useCallback((id: string) => {
    setUserQueries((prev) => {
      const next = prev.filter((q) => q.id !== id);
      localStorage.setItem("cql_saved_queries", JSON.stringify(next));
      return next;
    });
  }, []);

  // Load a query into editor
  const loadQuery = useCallback((q: string) => {
    setQuery(q);
    setShowSavedQueries(false);
    setShowHistory(false);
  }, []);

  // Add expression to query
  const addToQuery = useCallback(
    (expr: string) => {
      setQuery((prev) => {
        if (!prev.trim()) return expr;
        return `${prev} AND ${expr}`;
      });
    },
    []
  );

  // Copy share URL
  const shareQuery = useCallback(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("q", query);
    url.searchParams.set("t", timeRange);
    navigator.clipboard.writeText(url.toString());
  }, [query, timeRange]);

  // Export results
  const exportResults = useCallback(
    (format: "csv" | "json") => {
      if (!results) return;
      let content: string;
      let mime: string;
      let ext: string;

      if (format === "json") {
        content = JSON.stringify(results.events, null, 2);
        mime = "application/json";
        ext = "json";
      } else {
        const fields = results.fields;
        const header = fields.join(",");
        const rows = results.events.map((e) =>
          fields.map((f) => {
            const v = String(e[f] ?? "");
            return v.includes(",") ? `"${v}"` : v;
          }).join(",")
        );
        content = [header, ...rows].join("\n");
        mime = "text/csv";
        ext = "csv";
      }

      const blob = new Blob([content], { type: mime });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `cql-results-${Date.now()}.${ext}`;
      a.click();
    },
    [results]
  );

  // Field stats: prefer derived from current results; fall back to schema names
  const fieldInfos = useMemo<FieldInfo[]>(() => {
    const derived = results ? deriveFields(results.events) : [];
    if (derived.length > 0) return derived;
    return Object.entries(schemaFields).map(([name, spec]) => {
      const t = spec.type?.toLowerCase() ?? "";
      let type: FieldInfo["type"] = "string";
      if (t.includes("int") || t.includes("float") || t.includes("num")) type = "number";
      else if (t.includes("date") || t.includes("time")) type = "time";
      else if (t.includes("ip")) type = "ip";
      return { name, type, count: 0, unique: 0, nullPct: 0, topValues: [] };
    });
  }, [results, schemaFields]);

  // All queries combined for the library
  const allQueries = useMemo(() => [...BUILTIN_QUERIES, ...userQueries], [userQueries]);
  const filteredQueries = useMemo(() => {
    if (savedQueriesTab === "all") return allQueries;
    return allQueries.filter((q) => q.category === savedQueriesTab);
  }, [allQueries, savedQueriesTab]);

  const CATEGORY_LABELS: Record<string, string> = {
    "all": "All",
    "threat-hunting": "Threat Hunting",
    "incident-response": "Incident Response",
    "compliance": "Compliance",
    "monitoring": "Monitoring",
    "custom": "Custom",
  };

  const CATEGORY_COLORS: Record<string, string> = {
    "threat-hunting": "bg-red-500/15 text-red-400 border-red-500/30",
    "incident-response": "bg-orange-500/15 text-orange-400 border-orange-500/30",
    "compliance": "bg-blue-500/15 text-blue-400 border-blue-500/30",
    "monitoring": "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    "custom": "bg-purple-500/15 text-purple-400 border-purple-500/30",
  };

  return (
    <div className="flex h-full flex-col">
      {/* ============================================================ */}
      {/*  A. QUERY BAR (sticky top)                                    */}
      {/* ============================================================ */}
      <div className="sticky top-0 z-40 border-b border-cyan-glow/15 bg-space-deep/95 backdrop-blur-xl">
        {/* Header */}
        <div className="flex items-center justify-between px-4 pt-3 pb-2">
          <div>
            <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">
              CQL SEARCH
            </h1>
            <p className="mt-0.5 text-[10px] tracking-widest text-cyan-glow/30">
              CYBER QUERY LANGUAGE // ADVANCED SEARCH ENGINE
            </p>
          </div>
          <div className="flex items-center gap-2">
            {results && (
              <div className="glass-panel flex items-center gap-2 px-3 py-1.5">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                </span>
                <span className="font-mono text-[11px] text-gray-300">
                  <span className="text-emerald-400 font-bold">{results.totalCount.toLocaleString()}</span>
                  {" "}results in{" "}
                  <span className="text-cyan-glow">{results.queryTimeMs.toFixed(0)}ms</span>
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Query editor + time range + execute button */}
        <div className="flex items-stretch gap-2 px-4 pb-2">
          <div className="flex-1 rounded-lg border border-cyan-glow/20 bg-space-mid/30 transition-colors focus-within:border-cyan-glow/40 focus-within:shadow-[0_0_15px_rgba(34,211,238,0.08)]">
            <CQLEditor
              value={query}
              onChange={setQuery}
              onExecute={executeSearch}
              error={error && !loading ? error : null}
            />
          </div>

          {/* Time range selector */}
          <div className="flex flex-col gap-1">
            <div className="glass-panel flex items-center gap-0.5 p-1">
              {TIME_PRESETS.map((preset) => (
                <button
                  key={preset.value}
                  onClick={() => setTimeRange(preset.value)}
                  className={`rounded px-2 py-1.5 text-[10px] font-bold tracking-wider transition-colors ${
                    timeRange === preset.value
                      ? "bg-cyan-glow/20 text-cyan-glow shadow-[0_0_8px_rgba(34,211,238,0.15)]"
                      : "text-gray-500 hover:text-gray-300 hover:bg-cyan-glow/5"
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
            {timeRange === "custom" && (
              <div className="flex gap-1">
                <input
                  type="datetime-local"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                  className="rounded border border-cyan-glow/15 bg-space-deep/50 px-2 py-1 text-[10px] text-gray-300 outline-none"
                />
                <input
                  type="datetime-local"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                  className="rounded border border-cyan-glow/15 bg-space-deep/50 px-2 py-1 text-[10px] text-gray-300 outline-none"
                />
              </div>
            )}
          </div>

          {/* Execute button */}
          <button
            onClick={executeSearch}
            disabled={!query.trim() || loading}
            className="group relative flex items-center gap-2 rounded-lg border border-cyan-glow/40 bg-cyan-glow/15 px-5 py-2 text-[11px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/25 hover:shadow-[0_0_20px_rgba(34,211,238,0.2)] active:scale-95 disabled:opacity-30"
          >
            {loading ? (
              <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            ) : (
              <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
              </svg>
            )}
            SEARCH
            <kbd className="ml-1 rounded border border-cyan-glow/20 bg-cyan-glow/10 px-1 py-0.5 text-[8px] opacity-60">
              Ctrl+Enter
            </kbd>
          </button>
        </div>

        {/* ============================================================ */}
        {/*  B. QUERY TOOLBAR                                             */}
        {/* ============================================================ */}
        <div className="flex items-center gap-1 border-t border-cyan-glow/10 px-4 py-1.5">
          {/* Save */}
          <button
            onClick={() => setShowSaveModal(true)}
            disabled={!query.trim()}
            className="flex items-center gap-1 rounded border border-cyan-glow/10 px-2.5 py-1 text-[10px] font-bold tracking-wider text-gray-500 transition-colors hover:bg-cyan-glow/5 hover:text-cyan-glow disabled:opacity-30"
          >
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M17.593 3.322c1.1.128 1.907 1.077 1.907 2.185V21L12 17.25 4.5 21V5.507c0-1.108.806-2.057 1.907-2.185a48.507 48.507 0 0111.186 0z" />
            </svg>
            SAVE
          </button>

          {/* Saved queries library */}
          <button
            onClick={() => setShowSavedQueries(!showSavedQueries)}
            className={`flex items-center gap-1 rounded border px-2.5 py-1 text-[10px] font-bold tracking-wider transition-colors ${
              showSavedQueries
                ? "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                : "border-cyan-glow/10 text-gray-500 hover:bg-cyan-glow/5 hover:text-cyan-glow"
            }`}
          >
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z" />
            </svg>
            LIBRARY
          </button>

          {/* History */}
          <div className="relative">
            <button
              onClick={() => setShowHistory(!showHistory)}
              className={`flex items-center gap-1 rounded border px-2.5 py-1 text-[10px] font-bold tracking-wider transition-colors ${
                showHistory
                  ? "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                  : "border-cyan-glow/10 text-gray-500 hover:bg-cyan-glow/5 hover:text-cyan-glow"
              }`}
            >
              <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              HISTORY
            </button>
            {showHistory && (
              <div className="absolute left-0 top-full z-50 mt-1 w-96 overflow-hidden rounded-lg border border-cyan-glow/20 bg-space-deep/95 shadow-lg shadow-cyan-glow/5 backdrop-blur-xl">
                <div className="max-h-[300px] overflow-y-auto">
                  {queryHistory.length === 0 ? (
                    <div className="px-4 py-6 text-center text-[11px] text-gray-600 font-mono">
                      No query history yet
                    </div>
                  ) : (
                    queryHistory.map((q, i) => (
                      <button
                        key={i}
                        onClick={() => loadQuery(q)}
                        className="flex w-full items-center gap-2 border-b border-cyan-glow/5 px-3 py-2 text-left transition-colors hover:bg-cyan-glow/5"
                      >
                        <svg className="h-3 w-3 shrink-0 text-gray-600" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span
                          className="flex-1 truncate font-mono text-[11px] text-gray-400"
                          style={{ fontFamily: "'JetBrains Mono', monospace" }}
                        >
                          {q}
                        </span>
                      </button>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="mx-1 h-4 w-px bg-cyan-glow/10" />

          {/* Share */}
          <button
            onClick={shareQuery}
            disabled={!query.trim()}
            className="flex items-center gap-1 rounded border border-cyan-glow/10 px-2.5 py-1 text-[10px] font-bold tracking-wider text-gray-500 transition-colors hover:bg-cyan-glow/5 hover:text-cyan-glow disabled:opacity-30"
          >
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M7.217 10.907a2.25 2.25 0 100 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186l9.566-5.314m-9.566 7.5l9.566 5.314m0 0a2.25 2.25 0 103.935 2.186 2.25 2.25 0 00-3.935-2.186zm0-12.814a2.25 2.25 0 103.933-2.185 2.25 2.25 0 00-3.933 2.185z" />
            </svg>
            SHARE
          </button>

          {/* Export */}
          <div className="relative group">
            <button
              disabled={!results}
              className="flex items-center gap-1 rounded border border-cyan-glow/10 px-2.5 py-1 text-[10px] font-bold tracking-wider text-gray-500 transition-colors hover:bg-cyan-glow/5 hover:text-cyan-glow disabled:opacity-30"
            >
              <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
              </svg>
              EXPORT
            </button>
            <div className="absolute left-0 top-full z-50 hidden pt-1 group-hover:block">
              <div className="overflow-hidden rounded border border-cyan-glow/20 bg-space-deep/95 shadow-lg backdrop-blur-xl">
                <button
                  onClick={() => exportResults("csv")}
                  className="flex w-full items-center gap-2 px-4 py-2 text-[10px] font-mono text-gray-400 hover:bg-cyan-glow/5 hover:text-cyan-glow"
                >
                  CSV
                </button>
                <button
                  onClick={() => exportResults("json")}
                  className="flex w-full items-center gap-2 px-4 py-2 text-[10px] font-mono text-gray-400 hover:bg-cyan-glow/5 hover:text-cyan-glow"
                >
                  JSON
                </button>
              </div>
            </div>
          </div>

          <div className="mx-1 h-4 w-px bg-cyan-glow/10" />

          {/* Auto-refresh */}
          <div className="flex items-center gap-1">
            <span className="text-[9px] font-bold tracking-wider text-gray-600">REFRESH:</span>
            <select
              value={autoRefresh}
              onChange={(e) => setAutoRefresh(Number(e.target.value))}
              className="rounded border border-cyan-glow/10 bg-transparent px-1.5 py-0.5 text-[10px] font-mono text-gray-400 outline-none"
            >
              {AUTO_REFRESH_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          <div className="flex-1" />

          {/* View mode switcher */}
          <div className="flex items-center gap-0.5 rounded border border-cyan-glow/10 p-0.5">
            {(["table", "raw", "json", "chart"] as ViewMode[]).map((mode) => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`rounded px-2 py-1 text-[9px] font-bold uppercase tracking-wider transition-colors ${
                  viewMode === mode
                    ? "bg-cyan-glow/20 text-cyan-glow"
                    : "text-gray-600 hover:text-gray-400"
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ============================================================ */}
      {/*  SAVED QUERIES LIBRARY                                        */}
      {/* ============================================================ */}
      <AnimatePresence>
        {showSavedQueries && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden border-b border-cyan-glow/15 bg-space-mid/20"
          >
            <div className="p-4">
              {/* Category tabs */}
              <div className="flex items-center gap-1 mb-3">
                {Object.entries(CATEGORY_LABELS).map(([key, label]) => (
                  <button
                    key={key}
                    onClick={() => setSavedQueriesTab(key as typeof savedQueriesTab)}
                    className={`rounded-full px-3 py-1 text-[10px] font-bold tracking-wider transition-colors ${
                      savedQueriesTab === key
                        ? "bg-cyan-glow/15 text-cyan-glow border border-cyan-glow/30"
                        : "text-gray-500 hover:text-gray-300 border border-transparent hover:border-cyan-glow/10"
                    }`}
                  >
                    {label}
                  </button>
                ))}
                <span className="ml-auto text-[10px] font-mono text-gray-600">
                  {filteredQueries.length} queries
                </span>
              </div>

              {/* Query cards grid */}
              <div className="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 max-h-[280px] overflow-y-auto">
                {filteredQueries.map((sq) => (
                  <button
                    key={sq.id}
                    onClick={() => loadQuery(sq.query)}
                    className="group rounded-lg border border-cyan-glow/10 bg-space-deep/40 p-3 text-left transition-all hover:border-cyan-glow/25 hover:bg-cyan-glow/5"
                  >
                    <div className="flex items-start justify-between mb-1">
                      <span className="text-[11px] font-bold text-gray-200 group-hover:text-cyan-glow transition-colors">
                        {sq.name}
                      </span>
                      {sq.builtIn ? (
                        <span className="shrink-0 rounded border border-cyan-glow/20 bg-cyan-glow/10 px-1.5 py-0 text-[8px] font-bold text-cyan-glow/60">
                          BUILT-IN
                        </span>
                      ) : (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            deleteUserQuery(sq.id);
                          }}
                          className="shrink-0 rounded p-0.5 text-gray-600 opacity-0 transition-opacity group-hover:opacity-100 hover:text-red-400"
                        >
                          <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                          </svg>
                        </button>
                      )}
                    </div>
                    <p className="text-[10px] text-gray-500 mb-2 line-clamp-1">
                      {sq.description}
                    </p>
                    <div className="flex items-center gap-1 flex-wrap mb-1.5">
                      <span className={`rounded-full border px-1.5 py-0 text-[8px] font-semibold ${CATEGORY_COLORS[sq.category] || ""}`}>
                        {CATEGORY_LABELS[sq.category] || sq.category}
                      </span>
                      {sq.tags.slice(0, 3).map((tag) => (
                        <span
                          key={tag}
                          className="rounded-full border border-gray-700 bg-gray-800/50 px-1.5 py-0 text-[8px] text-gray-500"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                    <div
                      className="truncate font-mono text-[9px] text-cyan-glow/30"
                      style={{ fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      {sq.query}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ============================================================ */}
      {/*  C + D. RESULTS + FIELD PANEL                                 */}
      {/* ============================================================ */}
      <div className="flex flex-1 overflow-hidden">
        {/* Results area */}
        <div className="flex-1 overflow-auto">
          <div className="glass-panel mx-4 my-3 overflow-hidden">
            <SearchResults
              data={results}
              loading={loading}
              error={error}
              viewMode={viewMode}
              query={query}
              page={page}
              pageSize={pageSize}
              onPageChange={setPage}
              onFieldClick={(field, value) => addToQuery(`${field}="${value}"`)}
            />
          </div>
        </div>

        {/* Field explorer side panel */}
        <FieldExplorer
          fields={fieldInfos}
          collapsed={fieldsPanelCollapsed}
          onToggle={() => setFieldsPanelCollapsed(!fieldsPanelCollapsed)}
          onAddToQuery={addToQuery}
        />
      </div>

      {/* ============================================================ */}
      {/*  SAVE QUERY MODAL                                             */}
      {/* ============================================================ */}
      <AnimatePresence>
        {showSaveModal && (
          <SaveQueryModal
            query={query}
            onSave={saveUserQuery}
            onClose={() => setShowSaveModal(false)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Page wrapper                                                       */
/* ------------------------------------------------------------------ */

export default function SearchPage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-full items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <svg className="h-8 w-8 animate-spin text-cyan-glow/50" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <p className="hud-label animate-pulse">INITIALIZING CQL ENGINE...</p>
          </div>
        </div>
      }
    >
      <SearchContent />
    </Suspense>
  );
}
