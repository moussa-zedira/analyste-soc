"use client";

import { useCallback, useState } from "react";
import { getThreatScores, computeThreatScores } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { ThreatScoreEntry } from "@/lib/types";

function scoreColor(score: number): string {
  if (score >= 75) return "bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.4)]";
  if (score >= 50) return "bg-orange-500 shadow-[0_0_6px_rgba(249,115,22,0.3)]";
  if (score >= 25) return "bg-yellow-500 shadow-[0_0_6px_rgba(234,179,8,0.3)]";
  return "bg-cyan-glow shadow-[0_0_6px_rgba(0,229,255,0.3)]";
}

function scoreBadge(score: number): string {
  if (score >= 75) return "text-red-400 border-red-500/30 bg-red-500/10";
  if (score >= 50) return "text-orange-400 border-orange-500/30 bg-orange-500/10";
  if (score >= 25) return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
  return "text-cyan-glow border-cyan-glow/30 bg-cyan-glow/10";
}

export default function ThreatScoreWidget({ refreshKey }: { refreshKey: number }) {
  const [computing, setComputing] = useState(false);
  const [localKey, setLocalKey] = useState(0);

  const { data: scores, loading } = useFetchData<ThreatScoreEntry[]>(
    (signal) => getThreatScores({ limit: 8 }, { signal }),
    [],
    [refreshKey, localKey],
  );

  const handleCompute = useCallback(async () => {
    setComputing(true);
    try {
      await computeThreatScores();
      setLocalKey((k) => k + 1);
    } catch { /* ignore */ }
    finally { setComputing(false); }
  }, []);

  if (loading) {
    return (
      <div className="space-y-2">
        {[1, 2, 3].map((i) => <div key={i} className="skeleton h-7 w-full" />)}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex justify-end">
        <button
          onClick={handleCompute}
          disabled={computing}
          className="rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-2.5 py-1 text-[8px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 disabled:opacity-50"
        >
          {computing ? "COMPUTING..." : "REFRESH"}
        </button>
      </div>

      {scores.length === 0 ? (
        <p className="text-[10px] tracking-wider text-gray-600">
          No threat scores. Click REFRESH to compute.
        </p>
      ) : (
        <div className="max-h-[250px] space-y-1.5 overflow-y-auto">
          {scores.map((entry) => (
            <div key={entry.ip} className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-cyan-glow/5 transition-colors">
              <span className="w-[100px] shrink-0 truncate font-mono text-[10px] text-cyan-dim/70">
                {entry.ip}
              </span>
              <div className="h-1 flex-1 overflow-hidden rounded-full bg-space-mid">
                <div
                  className={`h-full rounded-full transition-all duration-500 ${scoreColor(entry.score)}`}
                  style={{ width: `${entry.score}%` }}
                />
              </div>
              <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold tabular-nums tracking-wider ${scoreBadge(entry.score)}`}>
                {entry.score}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
