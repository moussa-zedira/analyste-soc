"use client";

import { getMitreStats } from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { MitreStatsResponse, MitreTechniqueInfo } from "@/lib/types";
import { useState } from "react";
import Link from "next/link";

function heatColor(count: number): string {
  if (count === 0) return "border-cyan-glow/10 bg-space-mid/30 text-gray-500";
  if (count <= 3) return "border-yellow-500/30 bg-yellow-500/10 text-yellow-300";
  if (count <= 10) return "border-orange-500/30 bg-orange-500/10 text-orange-300";
  return "border-red-500/30 bg-red-500/10 text-red-300";
}

/** Page de la matrice MITRE ATT&CK avec couverture des techniques detectees. */
export default function MitrePage() {
  const { data, loading, error } = useFetchData<MitreStatsResponse | null>(
    (signal) => getMitreStats({ signal }),
    null,
    [],
  );
  const [selected, setSelected] = useState<MitreTechniqueInfo | null>(null);

  if (loading) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3">
        <svg
          className="h-8 w-8 animate-spin text-cyan-glow/50"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        <p className="hud-label animate-pulse">LOADING MITRE DATA...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="animate-slide-up glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
        <span className="mr-2 text-red-500">&#x25B2;</span>
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
    <PageTransition className="space-y-6">
      <StaggerItem>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
              MITRE ATT&CK
            </h1>
            <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
              THREAT FRAMEWORK // TECHNIQUE COVERAGE
            </p>
          </div>
          <div className="glass-panel px-3 py-1.5 text-center">
            <p className="text-[9px] tracking-wider text-cyan-glow/40">MAPPED</p>
            <p className="font-mono text-sm font-bold text-cyan-glow">
              {data.total_mapped_incidents}
            </p>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Matrix grid */}
      <StaggerItem>
        <div className="overflow-x-auto">
          <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${activeTactics.length}, minmax(160px, 1fr))` }}>
            {activeTactics.map((tactic) => (
              <div key={tactic.id} className="space-y-2">
                <div className="glass-panel px-3 py-2 text-center">
                  <p className="text-xs font-semibold text-cyan-glow/80">{tactic.name}</p>
                  <p className="text-[10px] text-gray-500">{tactic.id}</p>
                </div>
                {(byTactic[tactic.id] ?? []).map((tech) => (
                  <button
                    key={tech.technique_id}
                    onClick={() => setSelected(tech)}
                    className={`w-full rounded-md border px-3 py-2.5 text-left transition hover:brightness-125 ${heatColor(tech.incident_count)}`}
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
        </div>
      </StaggerItem>

      {/* All tactics overview */}
      <StaggerItem>
        <div className="glass-panel p-5">
          <h2 className="hud-label mb-3">Full Tactic Coverage</h2>
          <div className="flex flex-wrap gap-2">
            {data.tactics.map((tactic) => {
              const hasTech = byTactic[tactic.id]?.length > 0;
              return (
                <div
                  key={tactic.id}
                  className={`rounded-md px-3 py-1.5 text-xs ${
                    hasTech
                      ? "border border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                      : "border border-cyan-glow/10 bg-space-mid/30 text-gray-500"
                  }`}
                >
                  {tactic.name}
                </div>
              );
            })}
          </div>
        </div>
      </StaggerItem>

      {/* Detail panel */}
      {selected && (
        <StaggerItem>
          <div className="glass-panel glass-panel-animated p-5 animate-slide-up">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="hud-heading text-base font-bold tracking-wider text-cyan-glow">
                  {selected.technique_id} &mdash; {selected.technique_name}
                </h2>
                <p className="mt-1 text-xs text-gray-400">
                  Tactic: {selected.tactic_name} ({selected.tactic_id})
                </p>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-gray-500 transition-colors hover:text-cyan-glow"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="mt-4 flex flex-wrap gap-3">
              <div className="glass-panel px-3 py-2">
                <p className="text-[9px] tracking-wider text-cyan-glow/40">INCIDENTS</p>
                <p className="font-mono text-lg font-bold text-cyan-glow">{selected.incident_count}</p>
              </div>
              <div className="glass-panel px-3 py-2">
                <p className="text-[9px] tracking-wider text-cyan-glow/40">RULES</p>
                <p className="font-mono text-sm text-gray-300">{selected.rule_ids.join(", ")}</p>
              </div>
            </div>
            <div className="mt-4 flex gap-3">
              {selected.url && (
                <a
                  href={selected.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1.5 text-[10px] font-bold tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20"
                >
                  VIEW ON MITRE
                </a>
              )}
              {selected.incident_count > 0 && (
                <Link
                  href={`/incidents?rule_id=${selected.rule_ids[0]}`}
                  className="rounded-md border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-[10px] font-bold tracking-wider text-gray-300 transition-all hover:border-cyan-glow/40 hover:text-cyan-glow"
                >
                  VIEW INCIDENTS
                </Link>
              )}
            </div>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
