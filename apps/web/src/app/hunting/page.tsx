"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  cqlSearch,
  getCqlFields,
  listIocs,
  getIocStats,
  bulkImportIocs,
  type CqlSearchResponse,
  type IocApi,
  type IocStatsResponse,
} from "@/lib/apiClient";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudStat,
  HudTabs,
  HudInput,
  HudSelect,
  type HudTabItem,
} from "@/components/hud";

interface ExtractedIoc { type: string; value: string }

interface QueryCondition {
  id: number;
  field: string;
  operator: "=" | "!=" | "~" | "^=" | "$=" | ">" | "<" | "in";
  value: string;
}

interface Hypothesis {
  id: string;
  name: string;
  technique: string;
  description: string;
  category: string;
  query: string;
}

const DEFAULT_FIELDS = [
  "src_ip", "dst_ip", "username", "event_type", "severity", "source",
  "message", "raw", "ti_score",
];

const OPERATORS: QueryCondition["operator"][] = ["=", "!=", "~", "^=", "$=", ">", "<", "in"];

const HYPOTHESES: Hypothesis[] = [
  { id: "h1", name: "Encoded PowerShell", technique: "T1059.001", description: "PowerShell exécuté avec -enc", category: "Execution", query: 'message~"powershell" AND message~"-enc"' },
  { id: "h2", name: "Credential Dumping", technique: "T1003", description: "Accès LSASS / comportement type mimikatz", category: "Credential Access", query: 'event_type~"process" AND (message~"lsass" OR message~"mimikatz")' },
  { id: "h3", name: "Lateral SMB", technique: "T1021.002", description: "Connexions SMB inhabituelles entre postes", category: "Lateral Movement", query: 'event_type~"smb" | stats count by src_ip, dst_ip | where count>5' },
  { id: "h4", name: "DNS Tunneling", technique: "T1071.004", description: "Requêtes DNS anormalement longues", category: "Command & Control", query: 'event_type="dns" | stats count by src_ip | where count>100' },
  { id: "h5", name: "Brute Force", technique: "T1110", description: "Multiples échecs d'authent depuis même source", category: "Credential Access", query: 'event_type="auth.fail" | stats count by src_ip | where count>10' },
  { id: "h6", name: "Suspicious Process Creation", technique: "T1059", description: "Processus rares signés de scripts offensifs", category: "Execution", query: 'message~"psexec" OR message~"certutil" OR message~"bitsadmin"' },
];

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const TLP_COLORS: Record<string, string> = {
  RED: "bg-red-500/15 text-red-400 border-red-500/30",
  AMBER: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  "AMBER+STRICT": "bg-orange-500/15 text-orange-400 border-orange-500/30",
  GREEN: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  WHITE: "bg-gray-500/15 text-gray-300 border-gray-500/30",
};

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

function conditionToCql(c: QueryCondition): string | null {
  const v = c.value.trim();
  if (!v) return null;
  const quote = (s: string) => `"${s.replace(/"/g, '\\"')}"`;
  switch (c.operator) {
    case "=": return `${c.field}=${quote(v)}`;
    case "!=": return `${c.field}!=${quote(v)}`;
    case "~": return `${c.field}~${quote(v)}`;
    case "^=": return `${c.field}~${quote("^" + v)}`;
    case "$=": return `${c.field}~${quote(v + "$")}`;
    case ">": return `${c.field}>${v}`;
    case "<": return `${c.field}<${v}`;
    case "in": return `${c.field} IN (${v.split(",").map((x) => quote(x.trim())).join(", ")})`;
    default: return null;
  }
}

function buildCqlFromConditions(conds: QueryCondition[]): string {
  const parts = conds.map(conditionToCql).filter(Boolean) as string[];
  if (parts.length === 0) return "*";
  return parts.join(" AND ");
}

// Extract IOCs from CQL event rows (src_ip, dst_ip, hashes in message)
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;
const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;

function isPrivateIp(ip: string): boolean {
  if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip === "-") return true;
  if (ip.startsWith("172.")) {
    const o = Number(ip.split(".")[1]);
    return o >= 16 && o <= 31;
  }
  return false;
}

function extractIocsFromEvents(events: Record<string, unknown>[]): ExtractedIoc[] {
  const out = new Map<string, ExtractedIoc>();
  const push = (type: string, value: string) => {
    const k = `${type}:${value}`;
    if (!out.has(k)) out.set(k, { type, value });
  };
  for (const ev of events) {
    for (const field of ["src_ip", "dst_ip"]) {
      const v = ev[field];
      if (typeof v === "string" && IP_RE.test(v) && !isPrivateIp(v)) push("ip", v);
      IP_RE.lastIndex = 0;
    }
    const msg = String(ev.message ?? ev.raw ?? "");
    for (const m of msg.matchAll(SHA256_RE)) push("hash_sha256", m[0].toLowerCase());
    for (const m of msg.matchAll(MD5_RE)) push("hash_md5", m[0].toLowerCase());
    for (const m of msg.matchAll(DOMAIN_RE)) {
      const d = m[0].toLowerCase();
      if (!d.endsWith(".corp.local") && !d.endsWith(".local") && d.includes(".")) push("domain", d);
    }
  }
  return Array.from(out.values()).slice(0, 100);
}

function buildHistogram(events: Record<string, unknown>[]): { hour: string; count: number }[] {
  const buckets = new Map<string, number>();
  const now = new Date();
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600 * 1000);
    const key = `${String(d.getUTCHours()).padStart(2, "0")}:00`;
    buckets.set(key, 0);
  }
  for (const ev of events) {
    const ts = ev.ts ?? ev.timestamp ?? ev._time;
    if (typeof ts !== "string") continue;
    const d = new Date(ts);
    if (isNaN(d.getTime())) continue;
    const key = `${String(d.getUTCHours()).padStart(2, "0")}:00`;
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) ?? 0) + 1);
  }
  return Array.from(buckets.entries()).map(([hour, count]) => ({ hour, count }));
}

export default function HuntingPage() {
  const [conditions, setConditions] = useState<QueryCondition[]>([
    { id: 1, field: "event_type", operator: "~", value: "" },
  ]);
  const [timeRange, setTimeRange] = useState("24h");
  type HuntTab = "results" | "iocs" | "hypotheses";
  const [activeTab, setActiveTab] = useState<HuntTab>("results");
  const [annotations, setAnnotations] = useState<Record<string, string>>({});
  const [fields, setFields] = useState<string[]>(DEFAULT_FIELDS);

  // CQL results
  const [cqlResponse, setCqlResponse] = useState<CqlSearchResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // IOC feed
  const [iocs, setIocs] = useState<IocApi[]>([]);
  const [iocStats, setIocStats] = useState<IocStatsResponse | null>(null);
  const [iocBusy, setIocBusy] = useState(false);

  useEffect(() => {
    getCqlFields()
      .then((r) => {
        const names = Object.keys(r.fields ?? {});
        if (names.length > 0) setFields(names);
      })
      .catch(() => {});
    reloadIocs();
  }, []);

  async function reloadIocs() {
    try {
      const [lst, st] = await Promise.all([
        listIocs({ limit: 50 }),
        getIocStats(),
      ]);
      setIocs(lst.iocs ?? []);
      setIocStats(st);
    } catch (e) {
      console.error("IOC load failed", e);
    }
  }

  const addCondition = useCallback(() => {
    setConditions((prev) => [...prev, { id: Date.now(), field: "src_ip", operator: "=", value: "" }]);
  }, []);
  const removeCondition = useCallback((id: number) => {
    setConditions((prev) => prev.filter((c) => c.id !== id));
  }, []);
  const updateCondition = useCallback(<K extends keyof QueryCondition>(id: number, key: K, value: QueryCondition[K]) => {
    setConditions((prev) => prev.map((c) => (c.id === id ? { ...c, [key]: value } : c)));
  }, []);

  const cqlQuery = useMemo(() => buildCqlFromConditions(conditions), [conditions]);

  const runHunt = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      const earliest = timeRange === "1h" ? "-1h" : timeRange === "7d" ? "-7d" : timeRange === "4h" ? "-4h" : "-24h";
      const resp = await cqlSearch({ query: cqlQuery, earliest, latest: "now", limit: 500 });
      setCqlResponse(resp);
      setActiveTab("results");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur CQL");
    } finally {
      setRunning(false);
    }
  }, [cqlQuery, timeRange]);

  const runHypothesis = useCallback(async (h: Hypothesis) => {
    setRunning(true);
    setError(null);
    try {
      const resp = await cqlSearch({ query: h.query, earliest: "-24h", latest: "now", limit: 500 });
      setCqlResponse(resp);
      setActiveTab("results");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur CQL");
    } finally {
      setRunning(false);
    }
  }, []);

  const results = cqlResponse?.results ?? [];
  const histogram = useMemo(() => buildHistogram(results), [results]);
  const maxCount = Math.max(1, ...histogram.map((d) => d.count));

  async function extractIocs() {
    if (results.length === 0) return;
    const extracted = extractIocsFromEvents(results);
    if (extracted.length === 0) {
      setError("Aucun IOC extrait (pas d'IP publique, hash ou domaine détecté)");
      return;
    }
    setIocBusy(true);
    setError(null);
    try {
      const csv = "type,value\n" + extracted.map((i) => `${i.type},${i.value}`).join("\n");
      await bulkImportIocs({ format: "csv", data: csv, source: "hunt_extraction", default_confidence: 60, default_tlp: "AMBER" });
      await reloadIocs();
      setActiveTab("iocs");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur création IOCs");
    } finally {
      setIocBusy(false);
    }
  }

  const tabs: HudTabItem<HuntTab>[] = [
    { id: "results", label: "Results" },
    { id: "iocs", label: "IOCs" },
    { id: "hypotheses", label: "Hypotheses" },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="CQL-DRIVEN HUNT // LIVE IOC ENRICHMENT">
          Threat Hunting
        </HudHeading>
        <div className="flex items-center gap-2">
          <HudSelect
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="w-auto text-[10px]"
          >
            <option value="1h">Last 1h</option>
            <option value="4h">Last 4h</option>
            <option value="24h">Last 24h</option>
            <option value="7d">Last 7d</option>
          </HudSelect>
          <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <HudCard tone="alert" className="p-3 text-xs text-neon-pink">{error}</HudCard>
      )}

      {/* Query Builder */}
      <HudCard className="p-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Query Builder</h3>
          <code className="truncate rounded border border-cyan-glow/10 bg-black/40 px-2 py-1 text-[10px] text-cyan-glow/70" title={cqlQuery}>
            {cqlQuery}
          </code>
        </div>
        <div className="space-y-2">
          {conditions.map((cond) => (
            <div key={cond.id} className="flex items-center gap-2">
              <HudSelect
                value={cond.field}
                onChange={(e) => updateCondition(cond.id, "field", e.target.value)}
                className="w-auto text-[10px]"
              >
                {fields.map((f) => <option key={f} value={f}>{f}</option>)}
              </HudSelect>
              <HudSelect
                value={cond.operator}
                onChange={(e) => updateCondition(cond.id, "operator", e.target.value as QueryCondition["operator"])}
                className="w-auto text-[10px]"
              >
                {OPERATORS.map((op) => <option key={op} value={op}>{op}</option>)}
              </HudSelect>
              <HudInput
                value={cond.value}
                onChange={(e) => updateCondition(cond.id, "value", e.target.value)}
                placeholder="Valeur..."
                className="flex-1 text-[10px]"
                mono
              />
              <HudButton
                size="sm"
                variant="ghost"
                onClick={() => removeCondition(cond.id)}
              >
                X
              </HudButton>
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center gap-2">
          <HudButton size="sm" variant="ghost" onClick={addCondition}>
            + ADD CONDITION
          </HudButton>
          <HudButton size="sm" variant="primary" loading={running} onClick={runHunt}>
            {running ? "RUNNING..." : "RUN HUNT"}
          </HudButton>
          <HudButton
            size="sm"
            variant="secondary"
            disabled={results.length === 0 || iocBusy}
            onClick={extractIocs}
          >
            {iocBusy ? "..." : "EXTRACT IOCs"}
          </HudButton>
          <span className="ml-auto text-[10px] text-gray-500">
            {cqlResponse
              ? `${results.length}/${cqlResponse.metadata.total} events · ${cqlResponse.metadata.execution_time_ms.toFixed(0)}ms`
              : "Pas encore exécuté"}
          </span>
        </div>
      </HudCard>

      {activeTab === "results" && (
        <>
          <HudCard className="p-4">
            <h3 className="mb-3 text-xs font-bold text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>Event Timeline (24h UTC)</h3>
            <div className="flex h-32 items-end gap-1">
              {histogram.map((d) => (
                <div key={d.hour} className="group relative flex flex-1 flex-col items-center">
                  <div className="absolute -top-6 hidden rounded bg-black/80 px-2 py-1 text-[8px] text-cyan-glow group-hover:block">
                    {d.count} events
                  </div>
                  <div
                    className="w-full rounded-t bg-cyan-glow/30 transition-all hover:bg-cyan-glow/60"
                    style={{ height: `${(d.count / maxCount) * 100}%` }}
                  />
                  <span className="mt-1 text-[7px] text-gray-600">{d.hour.split(":")[0]}</span>
                </div>
              ))}
            </div>
          </HudCard>

          <HudCard className="overflow-hidden p-0">
            {results.length === 0 && !running ? (
              <div className="p-8 text-center text-xs text-gray-500">
                Aucun événement pour cette requête. Lance un <span className="text-cyan-glow">RUN HUNT</span> ou essaie une hypothèse.
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <Th>Timestamp</Th><Th>Source</Th><Th>Type</Th><Th>Severity</Th>
                    <Th>Src IP</Th><Th>Dst IP</Th><Th>Message</Th><Th>TI</Th><Th>Tag</Th>
                  </tr>
                </thead>
                <tbody>
                  {results.slice(0, 200).map((ev, i) => {
                    const id = String(ev.id ?? `row-${i}`);
                    const sev = String(ev.severity ?? "info").toLowerCase();
                    return (
                      <tr key={id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                        <td className="px-4 py-2 font-mono text-[10px] text-gray-400">{String(ev.ts ?? ev.timestamp ?? "-").slice(0, 19)}</td>
                        <td className="px-4 py-2 text-[10px] text-gray-300">{String(ev.source ?? "-")}</td>
                        <td className="px-4 py-2 font-mono text-[10px] text-gray-400">{String(ev.event_type ?? "-")}</td>
                        <td className="px-4 py-2">
                          <Badge text={sev} cls={SEV_COLORS[sev] ?? SEV_COLORS.info} />
                        </td>
                        <td className="px-4 py-2 font-mono text-[10px] text-gray-400">{String(ev.src_ip ?? "-")}</td>
                        <td className="px-4 py-2 font-mono text-[10px] text-gray-400">{String(ev.dst_ip ?? "-")}</td>
                        <td className="max-w-xs truncate px-4 py-2 text-[10px] text-gray-400" title={String(ev.message ?? "")}>
                          {String(ev.message ?? ev.raw ?? "-")}
                        </td>
                        <td className="px-4 py-2 text-[10px] text-purple-400">{ev.ti_score != null ? String(ev.ti_score) : "-"}</td>
                        <td className="px-4 py-2">
                          <input
                            value={annotations[id] || ""}
                            onChange={(e) => setAnnotations((prev) => ({ ...prev, [id]: e.target.value }))}
                            placeholder="Tag..."
                            className="w-20 rounded border border-gray-800 bg-black/30 px-2 py-1 text-[9px] text-gray-400 outline-none focus:border-cyan-glow/30"
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </HudCard>
        </>
      )}

      {activeTab === "iocs" && (
        <div className="space-y-4">
          {iocStats && (
            <div className="grid grid-cols-4 gap-3">
              <HudStat label="TOTAL" value={iocStats.total} />
              <HudStat label="ACTIVE" value={iocStats.by_state.active ?? 0} tone="matrix" />
              <HudStat label="AVG CONFIDENCE" value={`${iocStats.avg_confidence.toFixed(1)}%`} />
              <HudStat label="SIGHTINGS" value={iocStats.total_sightings} tone="purple" />
            </div>
          )}
          <HudCard className="overflow-hidden p-0">
            {iocs.length === 0 ? (
              <div className="p-8 text-center text-xs text-gray-500">
                Pas d'IOCs. Utilise <span className="text-yellow-400">EXTRACT IOCs</span> après un hunt.
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <Th>Type</Th><Th>Value</Th><Th>Source</Th><Th>TLP</Th>
                    <Th>Confidence</Th><Th>Tags</Th><Th>First seen</Th><Th>Sightings</Th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc) => (
                    <tr key={ioc.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                      <td className="px-4 py-2 text-[10px] text-gray-300">{ioc.type}</td>
                      <td className="px-4 py-2 font-mono text-[10px] text-cyan-glow truncate max-w-[260px]" title={ioc.value}>{ioc.value}</td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{ioc.source ?? "-"}</td>
                      <td className="px-4 py-2">
                        <Badge text={ioc.tlp} cls={TLP_COLORS[ioc.tlp] ?? TLP_COLORS.WHITE} />
                      </td>
                      <td className="px-4 py-2 text-[10px] text-gray-300">{ioc.confidence}%</td>
                      <td className="px-4 py-2">
                        <div className="flex flex-wrap gap-1">
                          {(ioc.tags ?? []).slice(0, 3).map((t) => (
                            <span key={t} className="rounded bg-cyan-glow/5 px-1.5 py-0.5 text-[8px] text-cyan-glow/60">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2 font-mono text-[9px] text-gray-500">{String(ioc.first_seen ?? "").slice(0, 19)}</td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{ioc.sightings_count ?? 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </HudCard>
        </div>
      )}

      {activeTab === "hypotheses" && (
        <div className="grid grid-cols-3 gap-4">
          {HYPOTHESES.map((h) => (
            <HudCard key={h.id} className="p-4 transition-all hover:border-cyan-glow/30">
              <div className="mb-2 flex items-center gap-2">
                <Badge text={h.technique} cls="bg-purple-500/15 text-purple-400 border-purple-500/30" />
                <Badge text={h.category} cls="bg-cyan-glow/10 text-cyan-glow/70 border-cyan-glow/20" />
              </div>
              <h3 className="text-xs font-bold text-gray-200">{h.name}</h3>
              <p className="mt-1 text-[10px] text-gray-500">{h.description}</p>
              <code className="mt-2 block truncate rounded border border-cyan-glow/10 bg-black/40 px-2 py-1 text-[9px] text-cyan-glow/60" title={h.query}>
                {h.query}
              </code>
              <HudButton
                block
                size="sm"
                variant="secondary"
                className="mt-3"
                disabled={running}
                onClick={() => runHypothesis(h)}
              >
                {running ? "..." : "START HUNT"}
              </HudButton>
            </HudCard>
          ))}
        </div>
      )}
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">
      {children}
    </th>
  );
}
