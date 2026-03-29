"use client";

import { Fragment, useCallback, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export type ViewMode = "table" | "raw" | "json" | "chart";

export interface SearchResultData {
  events: Record<string, unknown>[];
  totalCount: number;
  queryTimeMs: number;
  queryType: "events" | "stats" | "timechart";
  fields: string[];
}

interface SearchResultsProps {
  data: SearchResultData | null;
  loading: boolean;
  error: string | null;
  viewMode: ViewMode;
  query: string;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onFieldClick?: (field: string, value: string) => void;
}

/* ------------------------------------------------------------------ */
/*  Severity badge                                                     */
/* ------------------------------------------------------------------ */

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-green-500/20 text-green-400 border-green-500/30",
    info: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  };
  const c = colors[severity?.toLowerCase()] || colors.info;
  return (
    <span
      className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${c}`}
    >
      {severity || "unknown"}
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Relative time                                                      */
/* ------------------------------------------------------------------ */

function relativeTime(ts: string): string {
  try {
    const diff = Date.now() - new Date(ts).getTime();
    if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch {
    return ts;
  }
}

/* ------------------------------------------------------------------ */
/*  Loading skeleton                                                   */
/* ------------------------------------------------------------------ */

function LoadingSkeleton() {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="flex gap-3">
          <div
            className="h-5 rounded bg-cyan-glow/5 animate-pulse"
            style={{ width: `${60 + (i % 3) * 40}px`, animationDelay: `${i * 80}ms` }}
          />
          <div
            className="h-5 flex-1 rounded bg-cyan-glow/5 animate-pulse"
            style={{ animationDelay: `${i * 80 + 40}ms` }}
          />
          <div
            className="h-5 rounded bg-cyan-glow/5 animate-pulse"
            style={{ width: `${80 + (i % 4) * 20}px`, animationDelay: `${i * 80 + 80}ms` }}
          />
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Empty state                                                        */
/* ------------------------------------------------------------------ */

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-16">
      <svg
        className="mb-4 h-16 w-16 text-cyan-glow/15"
        fill="none"
        viewBox="0 0 24 24"
        strokeWidth={0.5}
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
        />
      </svg>
      <p className="hud-heading text-sm tracking-wider text-cyan-glow/30">
        NO RESULTS
      </p>
      <p className="mt-2 max-w-md text-center text-[11px] text-gray-600">
        Try adjusting your query or time range. Example queries:
      </p>
      <div className="mt-3 space-y-1.5">
        {[
          'severity="critical" | stats count by src_ip',
          'event_type="auth.fail" AND username!="admin"',
          "* | timechart count by severity",
          'src_ip="10.0.0.0/8" | top dst_ip',
        ].map((q) => (
          <div
            key={q}
            className="rounded border border-cyan-glow/10 bg-cyan-glow/5 px-3 py-1.5 font-mono text-[11px] text-cyan-glow/50"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          >
            {q}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Error state                                                        */
/* ------------------------------------------------------------------ */

function ErrorState({ error }: { error: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-6 py-4">
        <div className="flex items-center gap-2 mb-2">
          <svg
            className="h-5 w-5 text-red-400"
            fill="none"
            viewBox="0 0 24 24"
            strokeWidth={1.5}
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
            />
          </svg>
          <span className="font-mono text-sm font-bold text-red-400">QUERY ERROR</span>
        </div>
        <p className="font-mono text-[12px] text-red-300/80">{error}</p>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Expanded row (JSON detail)                                         */
/* ------------------------------------------------------------------ */

function ExpandedRow({ event }: { event: Record<string, unknown> }) {
  return (
    <tr>
      <td colSpan={999} className="border-t border-cyan-glow/10 bg-space-deep/50 p-0">
        <div className="p-4">
          <pre
            className="max-h-[300px] overflow-auto rounded-lg border border-cyan-glow/10 bg-space-deep p-4 font-mono text-[11px] leading-relaxed text-gray-300"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          >
            {JSON.stringify(event, null, 2)}
          </pre>
        </div>
      </td>
    </tr>
  );
}

/* ------------------------------------------------------------------ */
/*  Table view                                                         */
/* ------------------------------------------------------------------ */

function TableView({
  data,
  page,
  pageSize,
  onPageChange,
  onFieldClick,
}: {
  data: SearchResultData;
  page: number;
  pageSize: number;
  onPageChange: (p: number) => void;
  onFieldClick?: (field: string, value: string) => void;
}) {
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const toggleRow = useCallback((idx: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const handleSort = useCallback(
    (field: string) => {
      if (sortField === field) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortField(field);
        setSortDir("desc");
      }
    },
    [sortField]
  );

  const displayFields = data.fields.length > 0 ? data.fields : Object.keys(data.events[0] || {});
  const priorityFields = ["timestamp", "ts", "severity", "event_type", "src_ip", "dst_ip", "username", "message", "source"];
  const orderedFields = [
    ...priorityFields.filter((f) => displayFields.includes(f)),
    ...displayFields.filter((f) => !priorityFields.includes(f)),
  ].slice(0, 12);

  const sortedEvents = useMemo(() => {
    if (!sortField) return data.events;
    return [...data.events].sort((a, b) => {
      const va = String(a[sortField] ?? "");
      const vb = String(b[sortField] ?? "");
      const cmp = va.localeCompare(vb, undefined, { numeric: true });
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [data.events, sortField, sortDir]);

  const start = page * pageSize;
  const end = Math.min(start + pageSize, sortedEvents.length);
  const pageEvents = sortedEvents.slice(start, end);
  const totalPages = Math.ceil(data.totalCount / pageSize);

  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b border-cyan-glow/15">
              <th className="w-8 px-2 py-2.5" />
              {orderedFields.map((field) => (
                <th
                  key={field}
                  onClick={() => handleSort(field)}
                  className="cursor-pointer whitespace-nowrap px-3 py-2.5 text-[10px] font-bold uppercase tracking-widest text-cyan-glow/50 transition-colors hover:text-cyan-glow"
                >
                  <div className="flex items-center gap-1">
                    {field}
                    {sortField === field && (
                      <span className="text-cyan-glow">
                        {sortDir === "asc" ? "▲" : "▼"}
                      </span>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageEvents.map((event, idx) => {
              const globalIdx = start + idx;
              const isExpanded = expandedRows.has(globalIdx);
              return (
                <Fragment key={globalIdx}>
                  <tr
                    onClick={() => toggleRow(globalIdx)}
                    className={`cursor-pointer border-b border-cyan-glow/5 transition-colors hover:bg-cyan-glow/5 ${
                      idx % 2 === 0 ? "bg-transparent" : "bg-white/[0.01]"
                    } ${isExpanded ? "bg-cyan-glow/5" : ""}`}
                  >
                    <td className="px-2 py-2 text-gray-600">
                      <svg
                        className={`h-3.5 w-3.5 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                        fill="none"
                        viewBox="0 0 24 24"
                        strokeWidth={2}
                        stroke="currentColor"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                      </svg>
                    </td>
                    {orderedFields.map((field) => {
                      const val = event[field];
                      const str = val == null ? "" : String(val);

                      // Special rendering for known fields
                      if (field === "severity") {
                        return (
                          <td key={field} className="px-3 py-2">
                            <SeverityBadge severity={str} />
                          </td>
                        );
                      }
                      if ((field === "timestamp" || field === "ts") && str) {
                        return (
                          <td
                            key={field}
                            className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-gray-400"
                            title={str}
                          >
                            {relativeTime(str)}
                          </td>
                        );
                      }
                      if ((field === "src_ip" || field === "dst_ip") && str) {
                        return (
                          <td key={field} className="px-3 py-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onFieldClick?.(field, str);
                              }}
                              className="font-mono text-[11px] text-blue-400 underline decoration-blue-400/30 hover:text-blue-300 hover:decoration-blue-300/50"
                              style={{ fontFamily: "'JetBrains Mono', monospace" }}
                            >
                              {str}
                            </button>
                          </td>
                        );
                      }
                      return (
                        <td
                          key={field}
                          className="max-w-[200px] truncate px-3 py-2 font-mono text-[11px] text-gray-300"
                          style={{ fontFamily: "'JetBrains Mono', monospace" }}
                          title={str}
                        >
                          {str}
                        </td>
                      );
                    })}
                  </tr>
                  {isExpanded && <ExpandedRow event={event} />}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between border-t border-cyan-glow/10 px-4 py-3">
        <span className="font-mono text-[11px] text-gray-500">
          Showing {start + 1}-{end} of {data.totalCount.toLocaleString()} results
        </span>
        <div className="flex items-center gap-1">
          <button
            onClick={() => onPageChange(Math.max(0, page - 1))}
            disabled={page === 0}
            className="rounded border border-cyan-glow/15 bg-cyan-glow/5 px-2.5 py-1 text-[10px] font-mono text-cyan-glow/60 transition-colors hover:bg-cyan-glow/10 disabled:opacity-30"
          >
            PREV
          </button>
          <span className="px-2 font-mono text-[11px] text-gray-500">
            {page + 1} / {totalPages || 1}
          </span>
          <button
            onClick={() => onPageChange(Math.min(totalPages - 1, page + 1))}
            disabled={page >= totalPages - 1}
            className="rounded border border-cyan-glow/15 bg-cyan-glow/5 px-2.5 py-1 text-[10px] font-mono text-cyan-glow/60 transition-colors hover:bg-cyan-glow/10 disabled:opacity-30"
          >
            NEXT
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Stats view                                                         */
/* ------------------------------------------------------------------ */

function StatsView({ data }: { data: SearchResultData }) {
  const [showChart, setShowChart] = useState(false);
  const fields = data.fields.length > 0 ? data.fields : Object.keys(data.events[0] || {});

  // Detect numeric columns for chart
  const numericFields = fields.filter((f) => {
    return data.events.some((e) => typeof e[f] === "number" || !isNaN(Number(e[f])));
  });
  const labelField = fields.find((f) => !numericFields.includes(f)) || fields[0];
  const chartable = numericFields.length > 0 && data.events.length <= 50;

  return (
    <div>
      {chartable && (
        <div className="flex justify-end border-b border-cyan-glow/10 px-4 py-2">
          <button
            onClick={() => setShowChart(!showChart)}
            className={`flex items-center gap-1.5 rounded border px-3 py-1 text-[10px] font-bold tracking-wider transition-colors ${
              showChart
                ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                : "border-cyan-glow/15 bg-transparent text-gray-500 hover:text-cyan-glow/60"
            }`}
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
            </svg>
            {showChart ? "TABLE" : "CHART"}
          </button>
        </div>
      )}

      {showChart && chartable ? (
        <div className="p-4">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={data.events}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(34,211,238,0.08)" />
              <XAxis
                dataKey={labelField}
                tick={{ fill: "#6b7280", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}
                stroke="rgba(34,211,238,0.15)"
              />
              <YAxis
                tick={{ fill: "#6b7280", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}
                stroke="rgba(34,211,238,0.15)"
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(3,7,18,0.95)",
                  border: "1px solid rgba(34,211,238,0.2)",
                  borderRadius: 8,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                }}
              />
              <Legend wrapperStyle={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }} />
              {numericFields.slice(0, 4).map((f, i) => {
                const colors = ["#22d3ee", "#34d399", "#f59e0b", "#f472b6"];
                return (
                  <Bar
                    key={f}
                    dataKey={f}
                    fill={colors[i % colors.length]}
                    fillOpacity={0.7}
                    radius={[3, 3, 0, 0]}
                  />
                );
              })}
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-cyan-glow/15">
                {fields.map((f) => (
                  <th
                    key={f}
                    className="px-4 py-2.5 text-[10px] font-bold uppercase tracking-widest text-cyan-glow/50"
                  >
                    {f}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.events.map((row, i) => (
                <tr
                  key={i}
                  className={`border-b border-cyan-glow/5 ${
                    i % 2 === 0 ? "bg-transparent" : "bg-white/[0.01]"
                  }`}
                >
                  {fields.map((f) => (
                    <td
                      key={f}
                      className="px-4 py-2 font-mono text-[11px] text-gray-300"
                      style={{ fontFamily: "'JetBrains Mono', monospace" }}
                    >
                      {String(row[f] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Timechart view                                                     */
/* ------------------------------------------------------------------ */

function TimechartView({ data }: { data: SearchResultData }) {
  const fields = data.fields.length > 0 ? data.fields : Object.keys(data.events[0] || {});
  const timeField = fields.find((f) =>
    ["_time", "time", "timestamp", "ts", "bucket"].includes(f)
  ) || fields[0];
  const valueFields = fields.filter((f) => f !== timeField);
  const COLORS = ["#22d3ee", "#34d399", "#f59e0b", "#f472b6", "#a78bfa", "#fb7185"];

  return (
    <div className="p-4">
      <ResponsiveContainer width="100%" height={360}>
        <AreaChart data={data.events}>
          <defs>
            {valueFields.map((f, i) => (
              <linearGradient key={f} id={`grad-${i}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS[i % COLORS.length]} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS[i % COLORS.length]} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(34,211,238,0.08)" />
          <XAxis
            dataKey={timeField}
            tick={{ fill: "#6b7280", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}
            stroke="rgba(34,211,238,0.15)"
          />
          <YAxis
            tick={{ fill: "#6b7280", fontSize: 10, fontFamily: "'JetBrains Mono', monospace" }}
            stroke="rgba(34,211,238,0.15)"
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "rgba(3,7,18,0.95)",
              border: "1px solid rgba(34,211,238,0.2)",
              borderRadius: 8,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
            }}
          />
          <Legend wrapperStyle={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11 }} />
          {valueFields.map((f, i) => (
            <Area
              key={f}
              type="monotone"
              dataKey={f}
              stroke={COLORS[i % COLORS.length]}
              fill={`url(#grad-${i})`}
              strokeWidth={2}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Raw view                                                           */
/* ------------------------------------------------------------------ */

function RawView({ data, query }: { data: SearchResultData; query: string }) {
  // Extract search terms for highlighting
  const terms = useMemo(() => {
    const words: string[] = [];
    const re = /"([^"]+)"|'([^']+)'|(\S+)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(query))) {
      const w = m[1] || m[2] || m[3];
      if (
        w &&
        !["AND", "OR", "NOT", "|", "stats", "where", "sort", "head", "table", "by"].includes(
          w.toUpperCase()
        )
      ) {
        words.push(w);
      }
    }
    return words;
  }, [query]);

  function highlightLine(text: string): React.ReactNode {
    if (terms.length === 0) return text;
    const pattern = terms.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");
    const re = new RegExp(`(${pattern})`, "gi");
    const parts = text.split(re);
    return parts.map((part, i) =>
      re.test(part) ? (
        <span key={i} className="bg-yellow-400/20 text-yellow-300 rounded px-0.5">
          {part}
        </span>
      ) : (
        <span key={i}>{part}</span>
      )
    );
  }

  return (
    <div className="p-4">
      <div
        className="max-h-[600px] overflow-auto rounded-lg border border-cyan-glow/10 bg-space-deep"
        style={{ fontFamily: "'JetBrains Mono', monospace" }}
      >
        {data.events.map((event, idx) => {
          const raw =
            typeof event.raw === "string"
              ? event.raw
              : typeof event._raw === "string"
                ? event._raw
                : JSON.stringify(event);
          return (
            <div
              key={idx}
              className={`flex border-b border-cyan-glow/5 ${
                idx % 2 === 0 ? "bg-transparent" : "bg-white/[0.01]"
              }`}
            >
              <span className="w-12 shrink-0 border-r border-cyan-glow/10 px-2 py-1.5 text-right text-[10px] text-gray-600 select-none">
                {idx + 1}
              </span>
              <span className="px-3 py-1.5 text-[11px] text-gray-300 break-all whitespace-pre-wrap">
                {highlightLine(raw)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main SearchResults component                                       */
/* ------------------------------------------------------------------ */

export function SearchResults({
  data,
  loading,
  error,
  viewMode,
  query,
  page,
  pageSize,
  onPageChange,
  onFieldClick,
}: SearchResultsProps) {
  if (loading) return <LoadingSkeleton />;
  if (error) return <ErrorState error={error} />;
  if (!data || data.events.length === 0) return <EmptyState />;

  // Auto-detect best view for query type
  if (data.queryType === "timechart") {
    return <TimechartView data={data} />;
  }
  if (data.queryType === "stats" && viewMode !== "raw") {
    return <StatsView data={data} />;
  }

  switch (viewMode) {
    case "raw":
      return <RawView data={data} query={query} />;
    case "json":
      return (
        <div className="p-4">
          <pre
            className="max-h-[600px] overflow-auto rounded-lg border border-cyan-glow/10 bg-space-deep p-4 font-mono text-[11px] leading-relaxed text-gray-300"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          >
            {JSON.stringify(data.events, null, 2)}
          </pre>
        </div>
      );
    case "chart":
      return <StatsView data={{ ...data, queryType: "stats" }} />;
    default:
      return (
        <TableView
          data={data}
          page={page}
          pageSize={pageSize}
          onPageChange={onPageChange}
          onFieldClick={onFieldClick}
        />
      );
  }
}
