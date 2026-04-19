"use client";

import { useMemo, useState } from "react";
import Link from "next/link";

import { PageTransition, StaggerItem } from "@/components/PageTransition";
import {
  getMitreCoverage,
  getMitreNavigator,
  listIncidents,
} from "@/lib/apiClient";
import { useFetchData } from "@/lib/hooks";
import type {
  Incident,
  MitreCoverageResponse,
  MitreCoverageTechnique,
  MitreNavigatorLayer,
} from "@/lib/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function lerpColor(hex1: string, hex2: string, t: number): string {
  const a = parseInt(hex1.slice(1), 16);
  const b = parseInt(hex2.slice(1), 16);
  const r1 = (a >> 16) & 0xff, g1 = (a >> 8) & 0xff, b1 = a & 0xff;
  const r2 = (b >> 16) & 0xff, g2 = (b >> 8) & 0xff, b2 = b & 0xff;
  const r = Math.round(r1 + (r2 - r1) * t);
  const g = Math.round(g1 + (g2 - g1) * t);
  const bl = Math.round(b1 + (b2 - b1) * t);
  return `rgb(${r}, ${g}, ${bl})`;
}

function gradientFor(score: number, colors: string[]): string {
  if (score <= 0) return "transparent";
  const t = Math.max(0, Math.min(1, score / 100));
  if (colors.length >= 3 && t > 0.5) {
    return lerpColor(colors[1], colors[2], (t - 0.5) * 2);
  }
  if (colors.length >= 2) {
    return lerpColor(colors[0], colors[1], t * 2);
  }
  return colors[0] ?? "#fdbb84";
}

function downloadJson(name: string, data: object) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ThreatHuntPage() {
  const cov = useFetchData<MitreCoverageResponse | null>(
    (signal) => getMitreCoverage({ signal }),
    null,
    [],
  );
  const nav = useFetchData<MitreNavigatorLayer | null>(
    (signal) => getMitreNavigator({ signal }),
    null,
    [],
  );

  const [selected, setSelected] = useState<{
    technique: MitreCoverageTechnique;
    tacticName: string;
  } | null>(null);

  const incidents = useFetchData<Incident[] | null>(
    (signal) =>
      selected
        ? listIncidents({ rule_id: selected.technique.rule_id, limit: 25 }, { signal })
        : Promise.resolve(null),
    null,
    [selected?.technique.rule_id ?? ""],
  );

  const scoreByTechnique = useMemo(() => {
    const m = new Map<string, number>();
    for (const t of nav.data?.techniques ?? []) {
      const prev = m.get(t.techniqueID) ?? 0;
      m.set(t.techniqueID, Math.max(prev, t.score ?? 0));
    }
    return m;
  }, [nav.data]);

  if (cov.loading || nav.loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="hud-label animate-pulse text-cyan-glow/50">LOADING NAVIGATOR LAYER...</p>
      </div>
    );
  }

  if (cov.error || nav.error) {
    return (
      <div className="glass-panel border-red-500/30 px-4 py-3 text-xs text-red-400">
        {cov.error ?? nav.error}
      </div>
    );
  }

  if (!cov.data || !nav.data) return null;

  const tactics = (cov.data.tactics ?? []).filter((t) => (t.techniques?.length ?? 0) > 0);
  const gradient = nav.data.gradient?.colors ?? ["#fdbb84", "#e34a33", "#b30000"];

  return (
    <PageTransition className="space-y-6">
      <StaggerItem>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
              Threat Hunt — MITRE Navigator
            </h1>
            <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
              LIVE COVERAGE LAYER // CLICK A TECHNIQUE TO PIVOT
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-cyan-glow/40">TECHNIQUES</p>
              <p className="font-mono text-sm font-bold text-cyan-glow">
                {cov.data.totals?.techniques_covered ?? 0} / {cov.data.totals?.techniques_known ?? 0}
              </p>
            </div>
            <div className="glass-panel px-3 py-1.5 text-center">
              <p className="text-[9px] tracking-wider text-cyan-glow/40">RULES</p>
              <p className="font-mono text-sm font-bold text-cyan-glow">
                {cov.data.totals?.rules_mapped ?? 0}
              </p>
            </div>
            <button
              onClick={() => downloadJson("cyberdef-mitre-layer.json", nav.data!)}
              className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1.5 text-[10px] font-bold tracking-wider text-cyan-glow hover:bg-cyan-glow/20"
            >
              EXPORT NAVIGATOR JSON
            </button>
          </div>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Gradient legend */}
      <StaggerItem>
        <div className="glass-panel flex items-center gap-3 px-4 py-2 text-[10px] text-cyan-glow/60">
          <span>Coverage score</span>
          <div
            className="h-2 w-48 rounded"
            style={{
              background: `linear-gradient(to right, ${gradient.join(", ")})`,
            }}
          />
          <span>0</span>
          <span className="ml-auto">100</span>
        </div>
      </StaggerItem>

      {/* Heatmap matrix */}
      <StaggerItem>
        <div className="overflow-x-auto pb-2">
          <div
            className="grid gap-3"
            style={{
              gridTemplateColumns: `repeat(${tactics.length}, minmax(170px, 1fr))`,
            }}
          >
            {tactics.map((tactic) => (
              <div key={tactic.id} className="space-y-1.5">
                <div className="glass-panel px-3 py-2 text-center">
                  <p className="text-xs font-semibold text-cyan-glow/80">{tactic.name}</p>
                  <p className="text-[10px] text-gray-500">
                    {tactic.id} · {tactic.techniques.length} hits
                  </p>
                </div>
                {/* Group techniques by technique_id for compactness */}
                {Object.entries(
                  tactic.techniques.reduce<Record<string, MitreCoverageTechnique[]>>(
                    (acc, t) => ((acc[t.technique_id] ??= []).push(t), acc),
                    {},
                  ),
                ).map(([techId, items]) => {
                  const score = scoreByTechnique.get(techId) ?? 0;
                  const bg = gradientFor(score, gradient);
                  return (
                    <button
                      key={techId}
                      onClick={() =>
                        setSelected({ technique: items[0], tacticName: tactic.name })
                      }
                      className="w-full rounded border border-cyan-glow/20 px-2 py-2 text-left text-[10px] transition hover:border-cyan-glow/60"
                      style={{ background: bg, color: score > 50 ? "#fff" : "#cbd5e1" }}
                    >
                      <p className="font-mono font-semibold">{techId}</p>
                      <p className="leading-tight opacity-90">{items[0].name}</p>
                      <p className="mt-1 text-[9px] opacity-70">
                        {items.length} regle{items.length > 1 ? "s" : ""} · score {score}
                      </p>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </StaggerItem>

      {/* Drill-down panel */}
      {selected && (
        <StaggerItem>
          <div className="glass-panel glass-panel-animated animate-slide-up p-5">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="hud-heading text-base font-bold tracking-wider text-cyan-glow">
                  {selected.technique.technique_id} — {selected.technique.name}
                </h2>
                <p className="mt-1 text-xs text-gray-400">
                  Tactic: {selected.tacticName} · Rule: {selected.technique.rule_id}
                </p>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-gray-500 hover:text-cyan-glow"
                aria-label="close"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
              <div>
                <p className="hud-label mb-2">Recent incidents (rule {selected.technique.rule_id})</p>
                {incidents.loading && (
                  <p className="text-[11px] text-cyan-glow/40">Loading...</p>
                )}
                {!incidents.loading && (incidents.data?.length ?? 0) === 0 && (
                  <p className="text-[11px] text-gray-500">
                    Aucun incident pour cette regle dans la fenetre actuelle.
                  </p>
                )}
                <ul className="space-y-1.5">
                  {(incidents.data ?? []).slice(0, 10).map((inc) => (
                    <li
                      key={inc.id}
                      className="flex items-center justify-between rounded border border-cyan-glow/10 bg-space-mid/30 px-3 py-2 text-[11px] hover:border-cyan-glow/30"
                    >
                      <Link
                        href={`/incidents/${inc.id}`}
                        className="truncate text-gray-300 hover:text-cyan-glow"
                      >
                        {inc.title}
                      </Link>
                      <span
                        className={`ml-2 rounded px-1.5 py-0.5 text-[9px] font-bold ${
                          inc.severity === "high"
                            ? "bg-red-500/20 text-red-300"
                            : inc.severity === "medium"
                            ? "bg-orange-500/20 text-orange-300"
                            : "bg-blue-500/20 text-blue-300"
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <p className="hud-label mb-2">Actions</p>
                <div className="flex flex-wrap gap-2">
                  <a
                    href={`https://attack.mitre.org/techniques/${selected.technique.technique_id.replace(".", "/")}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1.5 text-[10px] font-bold tracking-wider text-cyan-glow hover:bg-cyan-glow/20"
                  >
                    VIEW ON MITRE
                  </a>
                  <Link
                    href={`/incidents?rule_id=${selected.technique.rule_id}`}
                    className="rounded border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-[10px] font-bold tracking-wider text-gray-300 hover:border-cyan-glow/40 hover:text-cyan-glow"
                  >
                    OPEN INCIDENTS LIST
                  </Link>
                  <Link
                    href={`/search?q=${encodeURIComponent(`rule_id:${selected.technique.rule_id}`)}`}
                    className="rounded border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-[10px] font-bold tracking-wider text-gray-300 hover:border-cyan-glow/40 hover:text-cyan-glow"
                  >
                    PIVOT TO CQL
                  </Link>
                </div>
                <p className="hud-label mb-2 mt-4">Coverage score</p>
                <div className="text-2xl font-bold text-cyan-glow">
                  {scoreByTechnique.get(selected.technique.technique_id) ?? 0}
                  <span className="ml-1 text-xs text-cyan-glow/40">/ 100</span>
                </div>
              </div>
            </div>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
