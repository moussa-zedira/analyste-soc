"use client";

import { useCallback, useEffect, useState } from "react";

import {
  ubaListEntities,
  ubaRefresh,
  ubaSummary,
} from "@/lib/apiClient";
import type { UbaEntity, UbaSummary } from "@/lib/types";

const ENTITY_TYPE_COLOR: Record<string, string> = {
  user: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  ip: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  host: "bg-amber-500/15 text-amber-300 border-amber-500/30",
};

function scoreColor(score: number) {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
}

function scoreBar(score: number) {
  if (score >= 70) return "bg-red-500";
  if (score >= 40) return "bg-amber-500";
  return "bg-emerald-500";
}

export default function UbaPage() {
  const [summary, setSummary] = useState<UbaSummary | null>(null);
  const [entities, setEntities] = useState<UbaEntity[]>([]);
  const [minScore, setMinScore] = useState(0);
  const [selected, setSelected] = useState<UbaEntity | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lookback, setLookback] = useState(60);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, list] = await Promise.all([
        ubaSummary(),
        ubaListEntities(minScore, 200),
      ]);
      setSummary(s);
      setEntities(list?.entities ?? []);
    } catch (e: any) {
      setError(e?.message ?? "load error");
    } finally {
      setLoading(false);
    }
  }, [minScore]);

  useEffect(() => {
    reload();
  }, [reload]);

  const refresh = async () => {
    setRefreshing(true);
    setError(null);
    try {
      await ubaRefresh(lookback);
      await reload();
    } catch (e: any) {
      setError(e?.message ?? "refresh error");
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
              style={{ fontFamily: "Orbitron, sans-serif" }}>
            UEBA — User &amp; Entity Behavior Analytics
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            BEHAVIORAL BASELINES // ANOMALY SCORING
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            type="number"
            value={lookback}
            min={1}
            max={1440}
            onChange={(e) => setLookback(Number(e.target.value) || 60)}
            className="w-20 rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-[11px] text-cyan-glow"
            title="lookback minutes"
          />
          <button
            onClick={refresh}
            disabled={refreshing}
            className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow disabled:opacity-50"
          >
            {refreshing ? "Refreshing…" : "Refresh baselines"}
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-[11px] text-red-300">
          {error}
        </div>
      )}

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-4 gap-4">
          <div className="glass-panel border border-cyan-glow/20 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">Total entities</p>
            <p className="mt-1 text-2xl font-bold text-cyan-glow">{summary.total_entities}</p>
          </div>
          <div className="glass-panel border border-red-500/20 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">High risk</p>
            <p className="mt-1 text-2xl font-bold text-red-400">{summary.high_risk_count}</p>
            <p className="mt-1 text-[9px] text-gray-500">≥ {summary.high_risk_threshold}</p>
          </div>
          {Object.entries(summary.by_type ?? {}).slice(0, 2).map(([t, n]) => (
            <div key={t} className="glass-panel border border-cyan-glow/10 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">{t}</p>
              <p className="mt-1 text-2xl font-bold text-gray-200">{n}</p>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-3">
        <span className="text-[10px] uppercase tracking-wider text-gray-500">Min score</span>
        <input
          type="range" min={0} max={100} value={minScore}
          onChange={(e) => setMinScore(Number(e.target.value))}
          className="w-64"
        />
        <span className="text-[11px] text-cyan-glow">{minScore}</span>
        <span className="ml-auto text-[10px] text-gray-500">{entities.length} entities</span>
      </div>

      <div className="grid grid-cols-12 gap-4">
        {/* Table */}
        <div className="col-span-7 glass-panel border border-cyan-glow/10 p-3">
          <div className="max-h-[60vh] overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="text-[9px] uppercase tracking-wider text-gray-500">
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-2 py-2 text-left">Type</th>
                  <th className="px-2 py-2 text-left">Entity</th>
                  <th className="px-2 py-2 text-right">Events</th>
                  <th className="px-2 py-2 text-right">Score</th>
                  <th className="px-2 py-2 text-left">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan={5} className="py-4 text-center text-gray-500">Loading…</td></tr>
                )}
                {!loading && entities.length === 0 && (
                  <tr><td colSpan={5} className="py-4 text-center text-gray-500">
                    No entities. Run "Refresh baselines" to ingest events.
                  </td></tr>
                )}
                {entities.map((e) => (
                  <tr
                    key={e.id}
                    onClick={() => setSelected(e)}
                    className={`cursor-pointer border-b border-cyan-glow/5 hover:bg-cyan-glow/5 ${
                      selected?.id === e.id ? "bg-cyan-glow/10" : ""
                    }`}
                  >
                    <td className="px-2 py-2">
                      <span className={`rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${
                        ENTITY_TYPE_COLOR[e.entity_type] ?? "bg-gray-500/15 text-gray-400 border-gray-500/30"
                      }`}>{e.entity_type}</span>
                    </td>
                    <td className="px-2 py-2 font-mono text-gray-200">{e.entity_key}</td>
                    <td className="px-2 py-2 text-right text-gray-400">{e.total_events}</td>
                    <td className="px-2 py-2 text-right">
                      <span className={`font-bold ${scoreColor(e.current_score ?? 0)}`}>
                        {(e.current_score ?? 0).toFixed(1)}
                      </span>
                      <div className="mt-1 h-1 w-16 ml-auto rounded-full bg-gray-800">
                        <div className={`h-1 rounded-full ${scoreBar(e.current_score ?? 0)}`}
                             style={{ width: `${Math.min(e.current_score ?? 0, 100)}%` }} />
                      </div>
                    </td>
                    <td className="px-2 py-2 text-gray-500">
                      {e.last_seen ? new Date(e.last_seen).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detail panel */}
        <div className="col-span-5 glass-panel border border-cyan-glow/10 p-4">
          {!selected && (
            <p className="text-[11px] text-gray-500">
              Select an entity to view its behavioral profile.
            </p>
          )}
          {selected && (
            <div className="space-y-3">
              <div>
                <h3 className="text-sm font-bold text-cyan-glow">{selected.entity_type}: {selected.entity_key}</h3>
                <p className={`text-2xl font-bold ${scoreColor(selected.current_score ?? 0)}`}>
                  {(selected.current_score ?? 0).toFixed(1)}
                  {selected.high_risk && (
                    <span className="ml-2 text-[10px] uppercase tracking-wider text-red-400">HIGH RISK</span>
                  )}
                </p>
              </div>
              <div className="grid grid-cols-2 gap-3 text-[10px]">
                <div><span className="text-gray-500">Events:</span> <span className="text-gray-200">{selected.total_events}</span></div>
                <div><span className="text-gray-500">First seen:</span> <span className="text-gray-200">{selected.first_seen ? new Date(selected.first_seen).toLocaleDateString() : "—"}</span></div>
              </div>

              {selected.score_reasons && Object.keys(selected.score_reasons).length > 0 && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Score breakdown</p>
                  <div className="mt-1 space-y-1">
                    {Object.entries(selected.score_reasons).map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between text-[10px]">
                        <span className="text-gray-400">{k}</span>
                        <span className="font-mono text-cyan-glow/80">{Number(v).toFixed(2)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selected.event_types_top && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Top event types</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {Object.entries(selected.event_types_top).slice(0, 8).map(([k, v]) => (
                      <span key={k} className="rounded bg-cyan-glow/5 px-2 py-0.5 text-[9px] text-cyan-glow/70">
                        {k} ({v})
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selected.geos_top && Object.keys(selected.geos_top).length > 0 && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Geos</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {Object.entries(selected.geos_top).slice(0, 8).map(([k, v]) => (
                      <span key={k} className="rounded bg-purple-500/5 px-2 py-0.5 text-[9px] text-purple-300/70">
                        {k} ({v})
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selected.src_ips_top && Object.keys(selected.src_ips_top).length > 0 && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Source IPs</p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {Object.entries(selected.src_ips_top).slice(0, 8).map(([k, v]) => (
                      <span key={k} className="rounded bg-amber-500/5 px-2 py-0.5 text-[9px] text-amber-300/70 font-mono">
                        {k} ({v})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
