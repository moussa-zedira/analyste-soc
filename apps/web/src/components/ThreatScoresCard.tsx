"use client";

import { getThreatScores, computeThreatScores } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { ThreatScoreEntry } from "@/lib/types";
import { useCallback, useState } from "react";

function scoreColor(score: number): string {
  if (score >= 75) return "bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.4)]";
  if (score >= 50) return "bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.3)]";
  if (score >= 25) return "bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.3)]";
  return "bg-cyan-glow shadow-[0_0_8px_rgba(0,229,255,0.3)]";
}

function scoreBadgeClass(score: number): string {
  if (score >= 75) return "text-red-400 border-red-500/30 bg-red-500/10";
  if (score >= 50) return "text-orange-400 border-orange-500/30 bg-orange-500/10";
  if (score >= 25) return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
  return "text-cyan-glow border-cyan-glow/30 bg-cyan-glow/10";
}

function scoreTrackColor(score: number): string {
  if (score >= 75) return "bg-red-500/10";
  if (score >= 50) return "bg-orange-500/10";
  if (score >= 25) return "bg-yellow-500/10";
  return "bg-cyan-glow/10";
}

export function ThreatScoresCard({ refreshKey }: { refreshKey: number }) {
  const [computing, setComputing] = useState(false);
  const [localRefresh, setLocalRefresh] = useState(0);

  const { data: scores, loading } = useFetchData<ThreatScoreEntry[]>(
    (signal) => getThreatScores({ limit: 10 }, { signal }),
    [],
    [refreshKey, localRefresh],
  );

  const handleCompute = useCallback(async () => {
    setComputing(true);
    try {
      await computeThreatScores();
      setLocalRefresh((k) => k + 1);
    } catch {
      /* ignore */
    } finally {
      setComputing(false);
    }
  }, []);

  return (
    <div className="glass-panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="hud-label">Top Threat IPs</h2>
        <button
          onClick={handleCompute}
          disabled={computing}
          className="rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-3 py-1 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-sm disabled:opacity-50"
        >
          {computing ? "COMPUTING..." : "REFRESH SCORES"}
        </button>
      </div>

      {loading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="skeleton h-8 w-full" />
          ))}
        </div>
      ) : scores.length === 0 ? (
        <p className="text-xs tracking-wide text-gray-600">
          No threat scores yet. Click &quot;REFRESH SCORES&quot; to compute.
        </p>
      ) : (
        <div className="space-y-2">
          {scores.map((entry) => (
            <div
              key={entry.ip}
              className="flex items-center gap-3 rounded-md px-2 py-1.5 transition-colors hover:bg-cyan-glow/5"
            >
              <span className="w-32 shrink-0 font-mono text-[11px] text-cyan-dim/70">
                {entry.ip}
              </span>
              <div
                className={`h-1.5 flex-1 overflow-hidden rounded-full ${scoreTrackColor(entry.score)}`}
              >
                <div
                  className={`h-full rounded-full transition-all duration-500 ${scoreColor(entry.score)}`}
                  style={{ width: `${entry.score}%` }}
                />
              </div>
              <span
                className={`rounded-md border px-2 py-0.5 text-[10px] font-bold tabular-nums tracking-wider ${scoreBadgeClass(entry.score)}`}
              >
                {entry.score}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
