"use client";

import { useCallback, useMemo, useState } from "react";
import { CQL_FIELDS } from "./CQLEditor";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface FieldInfo {
  name: string;
  type: "string" | "number" | "time" | "ip";
  count: number;
  unique: number;
  nullPct: number;
  topValues: { value: string; count: number }[];
}

interface FieldExplorerProps {
  fields: FieldInfo[];
  collapsed: boolean;
  onToggle: () => void;
  onAddToQuery: (expr: string) => void;
}

/* ------------------------------------------------------------------ */
/*  Field type icon                                                    */
/* ------------------------------------------------------------------ */

function FieldTypeIcon({ type }: { type: string }) {
  if (type === "ip") {
    return (
      <span className="flex h-5 w-5 items-center justify-center rounded bg-blue-500/15 text-[10px] font-bold text-blue-400">
        IP
      </span>
    );
  }
  if (type === "number") {
    return (
      <span className="flex h-5 w-5 items-center justify-center rounded bg-purple-500/15 text-[10px] font-bold text-purple-400">
        #
      </span>
    );
  }
  if (type === "time") {
    return (
      <svg className="h-5 w-5 rounded bg-amber-500/15 p-0.5 text-amber-400" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    );
  }
  return (
    <span className="flex h-5 w-5 items-center justify-center rounded bg-gray-500/15 text-[10px] font-bold text-gray-400">
      T
    </span>
  );
}

/* ------------------------------------------------------------------ */
/*  Generate mock field data from known fields                         */
/* ------------------------------------------------------------------ */

function generateFieldData(): FieldInfo[] {
  return CQL_FIELDS.map((name) => {
    let type: FieldInfo["type"] = "string";
    if (name.includes("ip")) type = "ip";
    else if (
      ["port", "bytes", "duration", "threat_score", "pid", "ppid"].includes(name)
    )
      type = "number";
    else if (["timestamp", "ts"].includes(name)) type = "time";

    const count = Math.floor(Math.random() * 10000) + 500;
    const unique = Math.min(count, Math.floor(Math.random() * 500) + 5);
    const nullPct = Math.random() * 30;

    const sampleValues: Record<string, string[]> = {
      severity: ["critical", "high", "medium", "low", "info"],
      event_type: ["auth.fail", "auth.success", "scan.port", "malware.detect", "ddos.attempt"],
      protocol: ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH"],
      action: ["allow", "block", "drop", "alert", "quarantine"],
      status: ["200", "403", "404", "500", "301"],
      source: ["firewall", "ids", "edr", "proxy", "dns"],
      method: ["GET", "POST", "PUT", "DELETE", "PATCH"],
      country: ["US", "CN", "RU", "DE", "FR", "GB", "JP"],
    };

    const vals = sampleValues[name] || [
      "value_1",
      "value_2",
      "value_3",
      "value_4",
      "value_5",
    ];

    const topValues = vals.map((v) => ({
      value: v,
      count: Math.floor(Math.random() * count * 0.4) + 1,
    }));
    topValues.sort((a, b) => b.count - a.count);

    return { name, type, count, unique, nullPct, topValues: topValues.slice(0, 10) };
  });
}

/* ------------------------------------------------------------------ */
/*  FieldExplorer component                                            */
/* ------------------------------------------------------------------ */

export function FieldExplorer({
  fields: propFields,
  collapsed,
  onToggle,
  onAddToQuery,
}: FieldExplorerProps) {
  const [search, setSearch] = useState("");
  const [expandedField, setExpandedField] = useState<string | null>(null);

  const fields = useMemo(() => {
    return propFields.length > 0 ? propFields : generateFieldData();
  }, [propFields]);

  const filtered = useMemo(() => {
    if (!search) return fields;
    const lower = search.toLowerCase();
    return fields.filter((f) => f.name.toLowerCase().includes(lower));
  }, [fields, search]);

  const toggleField = useCallback(
    (name: string) => {
      setExpandedField((prev) => (prev === name ? null : name));
    },
    []
  );

  if (collapsed) {
    return (
      <button
        onClick={onToggle}
        className="flex h-full w-10 flex-col items-center justify-center border-l border-cyan-glow/10 bg-space-mid/30 transition-colors hover:bg-cyan-glow/5"
        title="Show field explorer"
      >
        <svg
          className="h-4 w-4 text-cyan-glow/40"
          fill="none"
          viewBox="0 0 24 24"
          strokeWidth={1.5}
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
        </svg>
        <span
          className="mt-2 text-[9px] font-bold uppercase tracking-widest text-cyan-glow/30"
          style={{ writingMode: "vertical-lr" }}
        >
          FIELDS
        </span>
      </button>
    );
  }

  return (
    <div className="flex h-full w-72 flex-col border-l border-cyan-glow/10 bg-space-mid/20">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cyan-glow/10 px-3 py-2.5">
        <span className="text-[10px] font-bold uppercase tracking-widest text-cyan-glow/50">
          Fields
        </span>
        <button
          onClick={onToggle}
          className="rounded p-1 text-gray-500 transition-colors hover:bg-cyan-glow/10 hover:text-cyan-glow"
        >
          <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
          </svg>
        </button>
      </div>

      {/* Search */}
      <div className="border-b border-cyan-glow/10 px-3 py-2">
        <div className="flex items-center gap-2 rounded border border-cyan-glow/15 bg-space-deep/50 px-2 py-1.5">
          <svg className="h-3 w-3 text-gray-600" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter fields..."
            className="flex-1 bg-transparent text-[11px] text-gray-300 placeholder-gray-600 outline-none font-mono"
            style={{ fontFamily: "'JetBrains Mono', monospace" }}
          />
        </div>
      </div>

      {/* Field count */}
      <div className="border-b border-cyan-glow/5 px-3 py-1.5">
        <span className="text-[9px] font-mono text-gray-600">
          {filtered.length} field{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Field list */}
      <div className="flex-1 overflow-y-auto">
        {filtered.map((field) => {
          const isExpanded = expandedField === field.name;
          const maxCount = field.topValues[0]?.count || 1;
          return (
            <div key={field.name} className="border-b border-cyan-glow/5">
              <button
                onClick={() => toggleField(field.name)}
                className={`flex w-full items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-cyan-glow/5 ${
                  isExpanded ? "bg-cyan-glow/5" : ""
                }`}
              >
                <FieldTypeIcon type={field.type} />
                <span
                  className="flex-1 truncate font-mono text-[11px] text-gray-300"
                  style={{ fontFamily: "'JetBrains Mono', monospace" }}
                >
                  {field.name}
                </span>
                <svg
                  className={`h-3 w-3 text-gray-600 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                  fill="none"
                  viewBox="0 0 24 24"
                  strokeWidth={2}
                  stroke="currentColor"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                </svg>
              </button>

              {isExpanded && (
                <div className="border-t border-cyan-glow/5 bg-space-deep/30 px-3 py-2">
                  {/* Quick stats */}
                  <div className="mb-2 flex gap-3 text-[9px] font-mono text-gray-500">
                    <span>
                      Count: <span className="text-gray-400">{field.count.toLocaleString()}</span>
                    </span>
                    <span>
                      Unique: <span className="text-gray-400">{field.unique}</span>
                    </span>
                    <span>
                      Null: <span className="text-gray-400">{field.nullPct.toFixed(1)}%</span>
                    </span>
                  </div>

                  {/* Top values */}
                  <div className="space-y-1">
                    {field.topValues.map((tv) => (
                      <button
                        key={tv.value}
                        onClick={() => onAddToQuery(`${field.name}="${tv.value}"`)}
                        className="group flex w-full items-center gap-2 rounded px-1.5 py-1 text-left transition-colors hover:bg-cyan-glow/10"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between">
                            <span className="truncate font-mono text-[10px] text-gray-300 group-hover:text-cyan-glow">
                              {tv.value}
                            </span>
                            <span className="ml-2 shrink-0 font-mono text-[9px] text-gray-600">
                              {tv.count}
                            </span>
                          </div>
                          <div className="mt-0.5 h-1 w-full rounded-full bg-cyan-glow/5">
                            <div
                              className="h-full rounded-full bg-cyan-glow/25 transition-all"
                              style={{ width: `${(tv.count / maxCount) * 100}%` }}
                            />
                          </div>
                        </div>
                      </button>
                    ))}
                  </div>

                  {/* Quick actions */}
                  <div className="mt-2 flex gap-1">
                    <button
                      onClick={() => onAddToQuery(`${field.name}=`)}
                      className="rounded border border-cyan-glow/15 bg-cyan-glow/5 px-2 py-0.5 text-[9px] font-mono text-cyan-glow/60 transition-colors hover:bg-cyan-glow/15 hover:text-cyan-glow"
                    >
                      + search
                    </button>
                    <button
                      onClick={() => onAddToQuery(`${field.name}!=`)}
                      className="rounded border border-red-500/15 bg-red-500/5 px-2 py-0.5 text-[9px] font-mono text-red-400/60 transition-colors hover:bg-red-500/15 hover:text-red-400"
                    >
                      - exclude
                    </button>
                    <button
                      onClick={() => onAddToQuery(`| stats count by ${field.name}`)}
                      className="rounded border border-emerald-500/15 bg-emerald-500/5 px-2 py-0.5 text-[9px] font-mono text-emerald-400/60 transition-colors hover:bg-emerald-500/15 hover:text-emerald-400"
                    >
                      stats
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export type { FieldInfo };
