"use client";

import { getMitreStats } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type { MitreStatsResponse, MitreTechniqueInfo } from "@/lib/types";
import { useState } from "react";
import Link from "next/link";

function heatColor(count: number): string {
  if (count === 0) return "border-gray-700 bg-gray-800/50 text-gray-500";
  if (count <= 3) return "border-yellow-700 bg-yellow-900/40 text-yellow-300";
  if (count <= 10) return "border-orange-700 bg-orange-900/40 text-orange-300";
  return "border-red-700 bg-red-900/40 text-red-300";
}

export default function MitrePage() {
  const { data, loading, error } = useFetchData<MitreStatsResponse | null>(
    (signal) => getMitreStats({ signal }),
    null,
    [],
  );
  const [selected, setSelected] = useState<MitreTechniqueInfo | null>(null);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center text-gray-500">
        Loading MITRE ATT&CK data...
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded border border-red-800 bg-red-950/30 px-4 py-3 text-sm text-red-400">
        {error}
      </div>
    );
  }

  if (!data) return null;

  // Group techniques by tactic_id
  const byTactic: Record<string, MitreTechniqueInfo[]> = {};
  for (const tech of data.techniques) {
    (byTactic[tech.tactic_id] ??= []).push(tech);
  }

  // Only show tactics that have mapped techniques
  const activeTactics = data.tactics.filter((t) => byTactic[t.id]?.length);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          MITRE ATT&CK Coverage
        </h1>
        <div className="text-sm text-gray-400">
          {data.total_mapped_incidents} incidents mapped
        </div>
      </div>

      {/* Matrix grid */}
      <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${activeTactics.length}, minmax(160px, 1fr))` }}>
        {activeTactics.map((tactic) => (
          <div key={tactic.id} className="space-y-2">
            <div className="rounded bg-gray-800 px-3 py-2 text-center">
              <p className="text-xs font-semibold text-gray-300">{tactic.name}</p>
              <p className="text-[10px] text-gray-500">{tactic.id}</p>
            </div>
            {(byTactic[tactic.id] ?? []).map((tech) => (
              <button
                key={tech.technique_id}
                onClick={() => setSelected(tech)}
                className={`w-full rounded border px-3 py-2.5 text-left transition hover:brightness-125 ${heatColor(tech.incident_count)}`}
              >
                <p className="text-xs font-medium">{tech.technique_id}</p>
                <p className="text-[10px] leading-tight opacity-80">{tech.technique_name}</p>
                {tech.incident_count > 0 && (
                  <p className="mt-1 text-[10px] font-bold">{tech.incident_count} incidents</p>
                )}
              </button>
            ))}
          </div>
        ))}
      </div>

      {/* All tactics overview (including empty ones) */}
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
        <h2 className="mb-3 text-sm font-medium text-gray-400">Full Tactic Coverage</h2>
        <div className="flex flex-wrap gap-2">
          {data.tactics.map((tactic) => {
            const hasTech = byTactic[tactic.id]?.length > 0;
            return (
              <div
                key={tactic.id}
                className={`rounded px-3 py-1.5 text-xs ${
                  hasTech
                    ? "border border-purple-700 bg-purple-900/40 text-purple-300"
                    : "border border-gray-700 bg-gray-800/50 text-gray-500"
                }`}
              >
                {tactic.name}
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-5">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">
                {selected.technique_id} — {selected.technique_name}
              </h2>
              <p className="mt-1 text-sm text-gray-400">
                Tactic: {selected.tactic_name} ({selected.tactic_id})
              </p>
            </div>
            <button
              onClick={() => setSelected(null)}
              className="text-sm text-gray-500 hover:text-white"
            >
              Close
            </button>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <div className="rounded border border-gray-700 bg-gray-800 px-3 py-2">
              <p className="text-xs text-gray-500">Incidents</p>
              <p className="text-lg font-bold text-white">{selected.incident_count}</p>
            </div>
            <div className="rounded border border-gray-700 bg-gray-800 px-3 py-2">
              <p className="text-xs text-gray-500">Rules</p>
              <p className="text-sm font-mono text-gray-300">{selected.rule_ids.join(", ")}</p>
            </div>
          </div>
          <div className="mt-4 flex gap-3">
            {selected.url && (
              <a
                href={selected.url}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded bg-purple-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-purple-600"
              >
                View on MITRE ATT&CK
              </a>
            )}
            {selected.incident_count > 0 && (
              <Link
                href={`/incidents?rule_id=${selected.rule_ids[0]}`}
                className="rounded bg-blue-700 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-600"
              >
                View Incidents
              </Link>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
