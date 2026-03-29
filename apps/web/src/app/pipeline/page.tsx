"use client";

import { useState, useEffect, useCallback, useRef } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface PipelineStage {
  id: string;
  name: string;
  status: "active" | "degraded" | "error" | "disabled";
  eventsProcessed: number;
  avgDurationMs: number;
  errorCount: number;
  p95LatencyMs: number;
  enabled: boolean;
}

interface PipelineEvent {
  id: string;
  timestamp: string;
  source: string;
  type: string;
  enrichments: string[];
  threatScore: number;
  detections: string[];
  stages: { name: string; added: string; durationMs: number }[];
}

interface PipelineConfig {
  batchSize: number;
  timeoutMs: number;
  tiProviders: string[];
  alertChannel: string;
}

interface TestResult {
  stage: string;
  status: "pending" | "running" | "done";
  added: string;
  durationMs: number;
}

// ---------------------------------------------------------------------------
// Mock Data
// ---------------------------------------------------------------------------

const PIPELINE_STAGES: PipelineStage[] = [
  { id: "s1", name: "Ingestion", status: "active", eventsProcessed: 124832, avgDurationMs: 2, errorCount: 0, p95LatencyMs: 5, enabled: true },
  { id: "s2", name: "Parsing", status: "active", eventsProcessed: 124830, avgDurationMs: 8, errorCount: 2, p95LatencyMs: 15, enabled: true },
  { id: "s3", name: "Normalization", status: "active", eventsProcessed: 124828, avgDurationMs: 4, errorCount: 0, p95LatencyMs: 8, enabled: true },
  { id: "s4", name: "Enrichment", status: "active", eventsProcessed: 124828, avgDurationMs: 45, errorCount: 0, p95LatencyMs: 120, enabled: true },
  { id: "s5", name: "GeoIP Lookup", status: "active", eventsProcessed: 124828, avgDurationMs: 12, errorCount: 0, p95LatencyMs: 25, enabled: true },
  { id: "s6", name: "TI Correlation", status: "degraded", eventsProcessed: 124100, avgDurationMs: 85, errorCount: 728, p95LatencyMs: 350, enabled: true },
  { id: "s7", name: "Threat Score", status: "active", eventsProcessed: 124100, avgDurationMs: 6, errorCount: 0, p95LatencyMs: 12, enabled: true },
  { id: "s8", name: "Sigma Rules", status: "active", eventsProcessed: 124100, avgDurationMs: 22, errorCount: 0, p95LatencyMs: 45, enabled: true },
  { id: "s9", name: "ML Anomaly", status: "active", eventsProcessed: 124100, avgDurationMs: 35, errorCount: 0, p95LatencyMs: 80, enabled: true },
  { id: "s10", name: "Correlation", status: "active", eventsProcessed: 124100, avgDurationMs: 18, errorCount: 3, p95LatencyMs: 40, enabled: true },
  { id: "s11", name: "Alert Routing", status: "active", eventsProcessed: 4230, avgDurationMs: 3, errorCount: 0, p95LatencyMs: 6, enabled: true },
  { id: "s12", name: "Storage", status: "active", eventsProcessed: 124100, avgDurationMs: 5, errorCount: 0, p95LatencyMs: 10, enabled: true },
  { id: "s13", name: "Indexing", status: "active", eventsProcessed: 124100, avgDurationMs: 14, errorCount: 0, p95LatencyMs: 30, enabled: true },
];

const MOCK_EVENTS: PipelineEvent[] = [
  { id: "e1", timestamp: "12:45:03.221", source: "firewall-01", type: "network.connection", enrichments: ["TI", "Geo"], threatScore: 82, detections: ["Port Scan Detection"], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 2 }, { name: "Parsing", added: "fields extracted", durationMs: 6 }, { name: "TI Correlation", added: "src_ip flagged malicious", durationMs: 78 }] },
  { id: "e2", timestamp: "12:45:02.889", source: "web-proxy", type: "http.request", enrichments: ["Geo"], threatScore: 15, detections: [], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 1 }, { name: "Parsing", added: "URL + headers", durationMs: 8 }] },
  { id: "e3", timestamp: "12:45:02.445", source: "edr-agent-12", type: "process.exec", enrichments: ["TI"], threatScore: 94, detections: ["Mimikatz Execution", "Credential Dumping"], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 2 }, { name: "TI Correlation", added: "hash known malware", durationMs: 45 }, { name: "Sigma Rules", added: "2 rules matched", durationMs: 12 }] },
  { id: "e4", timestamp: "12:45:01.992", source: "dns-resolver", type: "dns.query", enrichments: ["TI", "Geo"], threatScore: 67, detections: ["DNS Tunneling Suspect"], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 1 }, { name: "ML Anomaly", added: "anomaly score 0.89", durationMs: 32 }] },
  { id: "e5", timestamp: "12:45:01.553", source: "auth-server", type: "auth.fail", enrichments: ["Geo"], threatScore: 45, detections: [], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 2 }, { name: "GeoIP Lookup", added: "country: RU", durationMs: 8 }] },
  { id: "e6", timestamp: "12:45:01.103", source: "firewall-02", type: "network.drop", enrichments: ["TI"], threatScore: 72, detections: ["C2 Beaconing"], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 1 }, { name: "Correlation", added: "matched beacon pattern", durationMs: 15 }] },
  { id: "e7", timestamp: "12:45:00.876", source: "syslog-srv", type: "system.error", enrichments: [], threatScore: 5, detections: [], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 2 }] },
  { id: "e8", timestamp: "12:45:00.442", source: "vpn-gateway", type: "auth.success", enrichments: ["Geo"], threatScore: 12, detections: [], stages: [{ name: "Ingestion", added: "raw_log", durationMs: 1 }, { name: "GeoIP Lookup", added: "country: FR", durationMs: 6 }] },
];

const TI_PROVIDERS = ["VirusTotal", "AbuseIPDB", "OTX AlienVault", "Shodan", "GreyNoise", "URLhaus"];
const ALERT_CHANNELS = ["Slack #incidents", "Email SOC Team", "PagerDuty", "Webhook", "Telegram"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: "bg-green-400",
    degraded: "bg-yellow-400 animate-pulse",
    error: "bg-red-500 animate-pulse",
    disabled: "bg-gray-600",
  };
  return <div className={`h-2.5 w-2.5 rounded-full ${colors[status] || "bg-gray-600"}`} />;
}

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

function MetricCard({ label, value, sub, accent = "cyan" }: { label: string; value: string; sub?: string; accent?: string }) {
  const colors: Record<string, string> = {
    cyan: "border-cyan-glow/20 shadow-cyan-sm",
    green: "border-green-500/20",
    yellow: "border-yellow-500/20",
    red: "border-red-500/20",
  };
  const textColors: Record<string, string> = {
    cyan: "text-cyan-glow",
    green: "text-green-400",
    yellow: "text-yellow-400",
    red: "text-red-400",
  };
  return (
    <div className={`glass-panel border ${colors[accent] || colors.cyan} p-4`}>
      <p className="text-[9px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold tracking-wide ${textColors[accent] || textColors.cyan}`} style={{ fontFamily: "Orbitron, sans-serif" }}>{value}</p>
      {sub && <p className="mt-1 text-[10px] text-gray-500">{sub}</p>}
    </div>
  );
}

function ThreatBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 50 ? "bg-yellow-500" : score >= 25 ? "bg-cyan-glow" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-gray-800">
        <div className={`h-1.5 rounded-full transition-all ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-[9px] font-mono text-gray-400">{score}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PipelineDashboard() {
  const [stages, setStages] = useState(PIPELINE_STAGES);
  const [activeTab, setActiveTab] = useState<"metrics" | "feed" | "test">("metrics");
  const [configOpen, setConfigOpen] = useState(false);
  const [config, setConfig] = useState<PipelineConfig>({ batchSize: 100, timeoutMs: 5000, tiProviders: ["VirusTotal", "AbuseIPDB"], alertChannel: "Slack #incidents" });
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const [testInput, setTestInput] = useState("");
  const [testResults, setTestResults] = useState<TestResult[]>([]);
  const [testRunning, setTestRunning] = useState(false);
  const [eventsPerSec, setEventsPerSec] = useState(2847);
  const [tick, setTick] = useState(0);
  const animFrameRef = useRef<number>(0);

  // Simulate EPS fluctuation
  useEffect(() => {
    const interval = setInterval(() => {
      setEventsPerSec((prev) => Math.max(1200, Math.min(4500, prev + Math.floor((Math.random() - 0.48) * 200))));
      setTick((t) => t + 1);
    }, 1500);
    return () => clearInterval(interval);
  }, []);

  const toggleStage = useCallback((id: string) => {
    setStages((prev) =>
      prev.map((s) =>
        s.id === id ? { ...s, enabled: !s.enabled, status: s.enabled ? "disabled" : "active" } : s
      )
    );
  }, []);

  const bottleneckIdx = stages.reduce((maxI, s, i, arr) => (s.enabled && s.avgDurationMs > arr[maxI].avgDurationMs ? i : maxI), 0);

  const runTestPipeline = useCallback(() => {
    if (!testInput.trim()) return;
    setTestRunning(true);
    const stageNames = stages.filter((s) => s.enabled).map((s) => s.name);
    const results: TestResult[] = stageNames.map((name) => ({ stage: name, status: "pending" as const, added: "", durationMs: 0 }));
    setTestResults([...results]);

    let idx = 0;
    const runNext = () => {
      if (idx >= results.length) {
        setTestRunning(false);
        return;
      }
      results[idx].status = "running";
      setTestResults([...results]);
      const duration = Math.floor(Math.random() * 80) + 5;
      setTimeout(() => {
        const additions = [
          "parsed 12 fields",
          "normalized schema",
          "enriched with GeoIP",
          "TI match: malicious",
          "threat_score = 78",
          "sigma rule matched",
          "anomaly score = 0.42",
          "correlated with 3 events",
          "routed to alert channel",
          "stored in index",
          "indexed for search",
          "no findings",
          "classification applied",
        ];
        results[idx].status = "done";
        results[idx].durationMs = duration;
        results[idx].added = additions[idx % additions.length];
        setTestResults([...results]);
        idx++;
        runNext();
      }, 300 + Math.random() * 400);
    };
    runNext();
  }, [testInput, stages]);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Event Pipeline
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            REAL-TIME EVENT PROCESSING // {stages.filter((s) => s.enabled).length} STAGES ACTIVE
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setConfigOpen(!configOpen)}
            className="rounded-md border border-cyan-glow/20 bg-cyan-glow/5 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15"
          >
            CONFIG
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {/* ================================================================== */}
      {/*  Pipeline Flow Visualization                                       */}
      {/* ================================================================== */}
      <div className="glass-panel overflow-x-auto border border-cyan-glow/10 p-6">
        <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
          Pipeline Flow
        </h2>
        <div className="flex items-center gap-0 min-w-[1100px]">
          {stages.map((stage, i) => (
            <div key={stage.id} className="flex items-center">
              {/* Stage node */}
              <button
                onClick={() => toggleStage(stage.id)}
                className={`group relative flex flex-col items-center justify-center rounded-lg border p-3 transition-all hover:scale-105 ${
                  stage.status === "active"
                    ? "border-green-500/30 bg-green-500/5 hover:border-green-500/50"
                    : stage.status === "degraded"
                    ? "border-yellow-500/30 bg-yellow-500/5 hover:border-yellow-500/50"
                    : stage.status === "error"
                    ? "border-red-500/30 bg-red-500/5 hover:border-red-500/50"
                    : "border-gray-700/30 bg-gray-900/30 hover:border-gray-600/50"
                }`}
                style={{ minWidth: 80 }}
              >
                <StatusDot status={stage.status} />
                <span className="mt-1.5 text-[8px] font-bold uppercase tracking-wider text-gray-300 text-center leading-tight">
                  {stage.name}
                </span>
                <span className="mt-1 text-[8px] font-mono text-gray-500">
                  {stage.avgDurationMs}ms
                </span>
              </button>

              {/* Flow line */}
              {i < stages.length - 1 && (
                <div className="relative mx-1 h-px w-8 flex-shrink-0">
                  <div className="absolute inset-0 bg-cyan-glow/20" />
                  {stage.enabled && stages[i + 1].enabled && (
                    <div
                      className="absolute inset-y-0 left-0 bg-cyan-glow/60"
                      style={{
                        width: "100%",
                        animation: "pipeline-flow 1.5s ease-in-out infinite",
                        animationDelay: `${i * 0.1}s`,
                      }}
                    />
                  )}
                  {/* Arrow */}
                  <div className="absolute -right-1 top-1/2 -translate-y-1/2 text-cyan-glow/40 text-[8px]">&#9654;</div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Inline animation style */}
      <style jsx>{`
        @keyframes pipeline-flow {
          0% { opacity: 0.2; transform: scaleX(0); transform-origin: left; }
          50% { opacity: 1; transform: scaleX(1); transform-origin: left; }
          100% { opacity: 0.2; transform: scaleX(0); transform-origin: right; }
        }
      `}</style>

      {/* ================================================================== */}
      {/*  Real-time Metrics                                                 */}
      {/* ================================================================== */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Events / Second" value={eventsPerSec.toLocaleString()} sub="Real-time throughput" accent="cyan" />
        <MetricCard label="Processed Today" value="1.24M" sub="+12% from yesterday" accent="green" />
        <MetricCard label="Avg Processing Time" value={`${stages.filter((s) => s.enabled).reduce((a, s) => a + s.avgDurationMs, 0)}ms`} sub="End-to-end pipeline" accent="cyan" />
        <MetricCard label="Error Rate" value={`${((stages.reduce((a, s) => a + s.errorCount, 0) / 124832) * 100).toFixed(2)}%`} sub={`${stages.reduce((a, s) => a + s.errorCount, 0)} total errors`} accent={stages.some((s) => s.status === "error") ? "red" : "yellow"} />
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        {(["metrics", "feed", "test"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`rounded-md border px-4 py-2 text-[10px] font-bold uppercase tracking-wider transition-all ${
              activeTab === tab
                ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow shadow-cyan-sm"
                : "border-gray-700/50 bg-gray-900/50 text-gray-500 hover:border-cyan-glow/20 hover:text-cyan-dim"
            }`}
          >
            {tab === "metrics" ? "Stage Metrics" : tab === "feed" ? "Live Feed" : "Test Pipeline"}
          </button>
        ))}
      </div>

      {/* ================================================================== */}
      {/*  Per-Stage Metrics Table                                           */}
      {/* ================================================================== */}
      {activeTab === "metrics" && (
        <div className="glass-panel overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyan-glow/10">
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Stage</th>
                <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                <th className="px-4 py-3 text-right text-[9px] font-bold uppercase tracking-wider text-gray-500">Events</th>
                <th className="px-4 py-3 text-right text-[9px] font-bold uppercase tracking-wider text-gray-500">Avg Duration</th>
                <th className="px-4 py-3 text-right text-[9px] font-bold uppercase tracking-wider text-gray-500">Errors</th>
                <th className="px-4 py-3 text-right text-[9px] font-bold uppercase tracking-wider text-gray-500">P95 Latency</th>
                <th className="px-4 py-3 text-center text-[9px] font-bold uppercase tracking-wider text-gray-500">Bottleneck</th>
              </tr>
            </thead>
            <tbody>
              {stages.map((stage, i) => (
                <tr
                  key={stage.id}
                  className={`border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5 ${
                    i === bottleneckIdx && stage.enabled ? "bg-red-500/5" : ""
                  }`}
                >
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{stage.name}</td>
                  <td className="px-4 py-3">
                    <Badge
                      text={stage.status}
                      cls={
                        stage.status === "active"
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : stage.status === "degraded"
                          ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30"
                          : stage.status === "error"
                          ? "bg-red-500/15 text-red-400 border-red-500/30"
                          : "bg-gray-500/15 text-gray-400 border-gray-500/30"
                      }
                    />
                  </td>
                  <td className="px-4 py-3 text-right text-[10px] font-mono text-gray-400">{stage.eventsProcessed.toLocaleString()}</td>
                  <td className="px-4 py-3 text-right text-[10px] font-mono text-gray-400">{stage.avgDurationMs}ms</td>
                  <td className={`px-4 py-3 text-right text-[10px] font-mono ${stage.errorCount > 0 ? "text-red-400" : "text-gray-500"}`}>
                    {stage.errorCount}
                  </td>
                  <td className="px-4 py-3 text-right text-[10px] font-mono text-gray-400">{stage.p95LatencyMs}ms</td>
                  <td className="px-4 py-3 text-center">
                    {i === bottleneckIdx && stage.enabled && (
                      <span className="inline-block rounded bg-red-500/15 px-2 py-0.5 text-[8px] font-bold uppercase text-red-400 animate-pulse">
                        SLOWEST
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ================================================================== */}
      {/*  Live Event Feed                                                   */}
      {/* ================================================================== */}
      {activeTab === "feed" && (
        <div className="space-y-2">
          {MOCK_EVENTS.map((ev) => (
            <div key={ev.id} className="glass-panel border border-cyan-glow/10 transition-all hover:border-cyan-glow/20">
              <button
                onClick={() => setExpandedEvent(expandedEvent === ev.id ? null : ev.id)}
                className="flex w-full items-center gap-4 px-4 py-3 text-left"
              >
                <span className="text-[10px] font-mono text-gray-500 w-24 flex-shrink-0">{ev.timestamp}</span>
                <span className="text-[10px] font-mono text-cyan-glow/60 w-24 flex-shrink-0">{ev.source}</span>
                <span className="text-xs text-gray-300 w-40 flex-shrink-0">{ev.type}</span>
                <div className="flex items-center gap-1 w-20 flex-shrink-0">
                  {ev.enrichments.map((e) => (
                    <Badge
                      key={e}
                      text={e}
                      cls={
                        e === "TI"
                          ? "bg-red-500/15 text-red-400 border-red-500/30"
                          : "bg-blue-500/15 text-blue-400 border-blue-500/30"
                      }
                    />
                  ))}
                </div>
                <div className="flex-shrink-0 w-28">
                  <ThreatBar score={ev.threatScore} />
                </div>
                <div className="flex flex-1 gap-1 flex-wrap">
                  {ev.detections.map((d) => (
                    <Badge key={d} text={d} cls="bg-yellow-500/15 text-yellow-400 border-yellow-500/30" />
                  ))}
                </div>
                <svg
                  className={`h-4 w-4 text-gray-500 transition-transform ${expandedEvent === ev.id ? "rotate-180" : ""}`}
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={1.5}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
                </svg>
              </button>

              {/* Expanded pipeline journey */}
              {expandedEvent === ev.id && (
                <div className="border-t border-cyan-glow/10 px-4 py-3">
                  <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-cyan-glow/50">Pipeline Journey</p>
                  <div className="space-y-2">
                    {ev.stages.map((s, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <div className="flex h-5 w-5 items-center justify-center rounded-full border border-green-500/30 bg-green-500/10 text-[8px] font-bold text-green-400">
                          {i + 1}
                        </div>
                        <span className="w-28 text-[10px] font-medium text-gray-300">{s.name}</span>
                        <span className="flex-1 text-[10px] font-mono text-gray-400">{s.added}</span>
                        <span className="text-[9px] font-mono text-gray-500">{s.durationMs}ms</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ================================================================== */}
      {/*  Test Pipeline                                                     */}
      {/* ================================================================== */}
      {activeTab === "test" && (
        <div className="glass-panel border border-cyan-glow/10 p-6">
          <h2 className="mb-4 text-sm font-bold tracking-widest text-cyan-glow/80" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Test Pipeline
          </h2>
          <div className="mb-4 flex gap-3">
            <textarea
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              placeholder="Paste a raw log line here..."
              className="flex-1 rounded border border-cyan-glow/20 bg-black/40 px-4 py-3 text-xs font-mono text-gray-200 outline-none focus:border-cyan-glow/50 resize-none"
              rows={3}
            />
            <button
              onClick={runTestPipeline}
              disabled={testRunning || !testInput.trim()}
              className={`self-end rounded-lg border px-6 py-3 text-[10px] font-bold uppercase tracking-wider transition-all ${
                testRunning || !testInput.trim()
                  ? "border-gray-700 bg-gray-900 text-gray-600 cursor-not-allowed"
                  : "border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow hover:bg-cyan-glow/20 hover:shadow-cyan-sm"
              }`}
            >
              {testRunning ? "PROCESSING..." : "RUN TEST"}
            </button>
          </div>

          {testResults.length > 0 && (
            <div className="space-y-2">
              {testResults.map((r, i) => (
                <div
                  key={i}
                  className={`flex items-center gap-3 rounded-lg border p-3 transition-all ${
                    r.status === "running"
                      ? "border-cyan-glow/30 bg-cyan-glow/5"
                      : r.status === "done"
                      ? "border-green-500/20 bg-green-500/5"
                      : "border-gray-700/30 bg-gray-900/20"
                  }`}
                >
                  <div
                    className={`flex h-6 w-6 items-center justify-center rounded-full text-[9px] font-bold ${
                      r.status === "running"
                        ? "border border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow animate-pulse"
                        : r.status === "done"
                        ? "border border-green-500/40 bg-green-500/10 text-green-400"
                        : "border border-gray-600/40 bg-gray-800/40 text-gray-500"
                    }`}
                  >
                    {r.status === "done" ? "\u2713" : i + 1}
                  </div>
                  <span className="w-28 text-[10px] font-bold text-gray-300">{r.stage}</span>
                  <span className="flex-1 text-[10px] font-mono text-gray-400">
                    {r.status === "running" ? "Processing..." : r.added || "Waiting..."}
                  </span>
                  {r.status === "done" && (
                    <span className="text-[9px] font-mono text-gray-500">{r.durationMs}ms</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ================================================================== */}
      {/*  Config Side Drawer                                                */}
      {/* ================================================================== */}
      {configOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={() => setConfigOpen(false)} />
          <div className="fixed right-0 top-0 z-50 h-full w-96 border-l border-cyan-glow/10 bg-space-dark/95 backdrop-blur-xl p-6 overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-sm font-bold tracking-widest text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
                Pipeline Config
              </h2>
              <button onClick={() => setConfigOpen(false)} className="text-gray-500 hover:text-cyan-glow">
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Toggle stages */}
            <div className="mb-6">
              <p className="mb-3 text-[9px] font-bold uppercase tracking-wider text-gray-500">Stage Toggles</p>
              <div className="space-y-2">
                {stages.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => toggleStage(s.id)}
                    className={`flex w-full items-center justify-between rounded border px-3 py-2 text-[10px] transition-all ${
                      s.enabled
                        ? "border-green-500/20 bg-green-500/5 text-green-400"
                        : "border-gray-700/30 bg-gray-900/30 text-gray-500"
                    }`}
                  >
                    <span>{s.name}</span>
                    <span className="font-bold uppercase">{s.enabled ? "ON" : "OFF"}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Batch size */}
            <div className="mb-6">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-gray-500">Batch Size</p>
              <input
                type="number"
                value={config.batchSize}
                onChange={(e) => setConfig((c) => ({ ...c, batchSize: Number(e.target.value) }))}
                className="w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs font-mono text-gray-200 outline-none focus:border-cyan-glow/50"
              />
            </div>

            {/* Timeout */}
            <div className="mb-6">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-gray-500">Timeout (ms)</p>
              <input
                type="number"
                value={config.timeoutMs}
                onChange={(e) => setConfig((c) => ({ ...c, timeoutMs: Number(e.target.value) }))}
                className="w-full rounded border border-cyan-glow/20 bg-black/40 px-3 py-2 text-xs font-mono text-gray-200 outline-none focus:border-cyan-glow/50"
              />
            </div>

            {/* TI Providers */}
            <div className="mb-6">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-gray-500">Threat Intel Providers</p>
              <div className="space-y-1">
                {TI_PROVIDERS.map((p) => (
                  <button
                    key={p}
                    onClick={() =>
                      setConfig((c) => ({
                        ...c,
                        tiProviders: c.tiProviders.includes(p)
                          ? c.tiProviders.filter((x) => x !== p)
                          : [...c.tiProviders, p],
                      }))
                    }
                    className={`flex w-full items-center gap-2 rounded border px-3 py-1.5 text-[10px] transition-all ${
                      config.tiProviders.includes(p)
                        ? "border-cyan-glow/20 bg-cyan-glow/5 text-cyan-glow"
                        : "border-gray-700/30 bg-gray-900/30 text-gray-500"
                    }`}
                  >
                    <div className={`h-2 w-2 rounded-sm ${config.tiProviders.includes(p) ? "bg-cyan-glow" : "bg-gray-600"}`} />
                    {p}
                  </button>
                ))}
              </div>
            </div>

            {/* Alert channel */}
            <div className="mb-6">
              <p className="mb-2 text-[9px] font-bold uppercase tracking-wider text-gray-500">Alert Channel</p>
              <div className="space-y-1">
                {ALERT_CHANNELS.map((ch) => (
                  <button
                    key={ch}
                    onClick={() => setConfig((c) => ({ ...c, alertChannel: ch }))}
                    className={`flex w-full items-center gap-2 rounded border px-3 py-1.5 text-[10px] transition-all ${
                      config.alertChannel === ch
                        ? "border-cyan-glow/20 bg-cyan-glow/5 text-cyan-glow"
                        : "border-gray-700/30 bg-gray-900/30 text-gray-500"
                    }`}
                  >
                    <div className={`h-2 w-2 rounded-full ${config.alertChannel === ch ? "bg-cyan-glow" : "bg-gray-600"}`} />
                    {ch}
                  </button>
                ))}
              </div>
            </div>

            <button className="w-full rounded border border-cyan-glow/30 bg-cyan-glow/10 py-3 text-[10px] font-bold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-sm">
              SAVE CONFIGURATION
            </button>
          </div>
        </>
      )}
    </div>
  );
}
