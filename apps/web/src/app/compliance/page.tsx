"use client";

import { useCallback, useEffect, useState } from "react";

import {
  complianceFrameworkReport,
  complianceGlobalReport,
} from "@/lib/apiClient";
import type {
  ComplianceFrameworkReport,
  ComplianceGlobalReport,
} from "@/lib/types";

const STATUS_COLORS: Record<string, string> = {
  covered: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  partial: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  uncovered: "bg-red-500/15 text-red-300 border-red-500/30",
  manual: "bg-gray-500/15 text-gray-300 border-gray-500/30",
};

function CircularProgress({ score, size = 70 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 85 ? "#22c55e" : score >= 60 ? "#eab308" : "#ef4444";
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="6" />
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke={color} strokeWidth="6"
                strokeLinecap="round" strokeDasharray={circumference} strokeDashoffset={offset}
                style={{ transition: "stroke-dashoffset 0.5s ease" }} />
      </svg>
      <span className="absolute text-sm font-bold" style={{ color, fontFamily: "Orbitron, sans-serif" }}>
        {score.toFixed(0)}%
      </span>
    </div>
  );
}

export default function CompliancePage() {
  const [global, setGlobal] = useState<ComplianceGlobalReport | null>(null);
  const [selectedFid, setSelectedFid] = useState<string | null>(null);
  const [report, setReport] = useState<ComplianceFrameworkReport | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadGlobal = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const g = await complianceGlobalReport();
      setGlobal(g);
      const first = g.summary[0]?.id;
      if (first && !selectedFid) {
        setSelectedFid(first);
        setReport(g.reports[first]);
      }
    } catch (e: any) {
      setError(e?.message ?? "load error");
    } finally {
      setLoading(false);
    }
  }, [selectedFid]);

  useEffect(() => { loadGlobal(); }, [loadGlobal]);

  const selectFramework = async (fid: string) => {
    setSelectedFid(fid);
    if (global?.reports[fid]) {
      setReport(global.reports[fid]);
      return;
    }
    try {
      const r = await complianceFrameworkReport(fid);
      setReport(r);
    } catch (e: any) {
      setError(e?.message ?? "load framework error");
    }
  };

  const controls = report?.controls.filter((c) => filter === "all" || c.status === filter) ?? [];

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
              style={{ fontFamily: "Orbitron, sans-serif" }}>
            Compliance Dashboard
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            FRAMEWORK COVERAGE // EVIDENCE-BASED SCORING
          </p>
        </div>
        <button onClick={loadGlobal}
                className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow">
          Refresh
        </button>
      </div>

      <div className="cyan-line" />

      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-[11px] text-red-300">
          {error}
        </div>
      )}

      {loading && <p className="text-[11px] text-gray-500">Loading…</p>}

      {/* Framework selector */}
      {global && (
        <div className="grid grid-cols-5 gap-3">
          {global.summary.map((f) => (
            <button key={f.id} onClick={() => selectFramework(f.id)}
                    className={`glass-panel flex flex-col items-center border p-3 transition-all ${
                      selectedFid === f.id
                        ? "border-cyan-glow/30 shadow-cyan-sm"
                        : "border-cyan-glow/10 hover:border-cyan-glow/20"
                    }`}>
              <CircularProgress score={f.coverage_score} size={70} />
              <span className="mt-2 text-[10px] font-bold tracking-wider text-gray-300 truncate w-full text-center">
                {f.name}
              </span>
              <span className="text-[8px] text-gray-600">
                {f.by_status.covered ?? 0}/{f.controls_total} covered
              </span>
            </button>
          ))}
        </div>
      )}

      {report && (
        <>
          {/* Counts */}
          <div className="grid grid-cols-5 gap-4">
            <div className="glass-panel border border-cyan-glow/20 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">Coverage</p>
              <p className="mt-1 text-2xl font-bold text-cyan-glow">{report.summary.coverage_score.toFixed(1)}%</p>
            </div>
            <div className="glass-panel border border-emerald-500/20 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">Covered</p>
              <p className="mt-1 text-2xl font-bold text-emerald-300">{report.summary.by_status.covered ?? 0}</p>
            </div>
            <div className="glass-panel border border-amber-500/20 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">Partial</p>
              <p className="mt-1 text-2xl font-bold text-amber-300">{report.summary.by_status.partial ?? 0}</p>
            </div>
            <div className="glass-panel border border-red-500/20 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">Uncovered</p>
              <p className="mt-1 text-2xl font-bold text-red-400">{report.summary.by_status.uncovered ?? 0}</p>
            </div>
            <div className="glass-panel border border-gray-500/20 p-4">
              <p className="text-[9px] uppercase tracking-wider text-gray-500">Manual</p>
              <p className="mt-1 text-2xl font-bold text-gray-400">{report.summary.by_status.manual ?? 0}</p>
            </div>
          </div>

          {/* Filters */}
          <div className="glass-panel flex items-center gap-3 p-3">
            <span className="text-[9px] uppercase tracking-wider text-gray-500">Filter:</span>
            {["all", "covered", "partial", "uncovered", "manual"].map((s) => (
              <button key={s} onClick={() => setFilter(s)}
                      className={`rounded border px-3 py-1 text-[9px] font-bold uppercase tracking-wider ${
                        filter === s
                          ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                          : "border-gray-700/50 text-gray-500 hover:text-gray-300"
                      }`}>
                {s}
              </button>
            ))}
            <span className="ml-auto text-[10px] text-gray-500">{controls.length} controls</span>
            <a href={report.framework.url} target="_blank" rel="noreferrer"
               className="text-[10px] text-cyan-glow hover:underline">
              {report.framework.name} ↗
            </a>
          </div>

          {/* Controls */}
          <div className="space-y-3">
            {controls.map((ctrl) => (
              <div key={ctrl.id} className="glass-panel border border-cyan-glow/10 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <span className="text-[10px] font-mono text-cyan-glow/50">{ctrl.id}</span>
                      <h3 className="text-xs font-bold text-gray-200">{ctrl.title}</h3>
                      <span className={`rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${STATUS_COLORS[ctrl.status]}`}>
                        {ctrl.status}
                      </span>
                      {!ctrl.mandatory && (
                        <span className="rounded border border-gray-700/50 px-2 py-0.5 text-[8px] uppercase text-gray-500">
                          optional
                        </span>
                      )}
                    </div>
                    <p className="mt-1 text-[10px] text-gray-500">{ctrl.description}</p>

                    {ctrl.covered_capabilities.length > 0 && (
                      <div className="mt-2">
                        <span className="text-[8px] uppercase tracking-wider text-emerald-400/70">Covered capabilities:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {ctrl.covered_capabilities.map((cap) => (
                            <span key={cap} className="rounded bg-emerald-500/5 px-2 py-0.5 text-[9px] text-emerald-300/80">
                              {cap}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {ctrl.missing_capabilities.length > 0 && (
                      <div className="mt-2">
                        <span className="text-[8px] uppercase tracking-wider text-red-400/70">Missing capabilities:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {ctrl.missing_capabilities.map((cap) => (
                            <span key={cap} className="rounded bg-red-500/5 px-2 py-0.5 text-[9px] text-red-300/80">
                              {cap}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence */}
                    <details className="mt-2">
                      <summary className="cursor-pointer text-[9px] uppercase tracking-wider text-gray-500 hover:text-gray-300">
                        View evidence
                      </summary>
                      <div className="mt-2 space-y-1">
                        {Object.entries(ctrl.evidence).flatMap(([cap, evList]) =>
                          evList.map((ev, i) => (
                            <div key={`${cap}-${i}`} className="text-[9px] text-gray-500">
                              <span className="text-cyan-glow/50">[{ev.type}]</span> {ev.ref}
                            </div>
                          ))
                        )}
                        {Object.values(ctrl.evidence).every((v) => v.length === 0) && (
                          <p className="text-[9px] text-gray-600">no evidence collected</p>
                        )}
                      </div>
                    </details>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
