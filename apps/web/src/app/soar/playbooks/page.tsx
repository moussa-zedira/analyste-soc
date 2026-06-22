"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  cancelExecution,
  executePlaybook,
  getPlaybook,
  getPlaybookHistory,
  getSoarMetrics,
  listPlaybooks,
  simulatePlaybook,
  type ExecutionReadApi,
  type PlaybookReadApi,
  type PlaybookSummaryApi,
  type SoarMetricsApi,
} from "@/lib/apiClient";
import { HudHeading, HudCard, HudButton, HudSelect, HudTextarea } from "@/components/hud";

// ---------------------------------------------------------------------------
// Helpers / colour maps
// ---------------------------------------------------------------------------
const TRIGGER_COLORS: Record<string, string> = {
  on_alert: "bg-red-500/15 text-red-400 border-red-500/30",
  on_threshold: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  on_schedule: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  on_event: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  manual: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  webhook: "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

const STATUS_BADGE: Record<string, string> = {
  enabled: "bg-green-500/15 text-green-400 border-green-500/30",
  disabled: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const EXEC_STATUS_BADGE: Record<string, string> = {
  pending: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  running: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  completed: "bg-green-500/15 text-green-400 border-green-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  cancelled: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const STEP_COLORS = { border: "border-cyan-glow/30", bg: "bg-cyan-glow/10", dot: "bg-cyan-glow" };

function Badge({ text, cls }: { text: string; cls: string }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${cls}`}>{text}</span>;
}

function fmtDate(s: string | null | undefined): string {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<PlaybookSummaryApi[]>([]);
  const [metrics, setMetrics] = useState<SoarMetricsApi | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selected, setSelected] = useState<PlaybookReadApi | null>(null);
  const [history, setHistory] = useState<ExecutionReadApi[]>([]);
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const [filterTrigger, setFilterTrigger] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterCategory, setFilterCategory] = useState("all");
  const [executeInput, setExecuteInput] = useState("{}");

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [pbList, met] = await Promise.all([listPlaybooks(), getSoarMetrics()]);
      setPlaybooks(pbList);
      setMetrics(met);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const loadDetail = useCallback(async (id: string) => {
    setDetailLoading(true);
    try {
      const [pb, hist] = await Promise.all([getPlaybook(id), getPlaybookHistory(id, 20)]);
      setSelected(pb);
      setHistory(hist);
    } catch (e) {
      setActionMsg(`Erreur chargement playbook: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selectedId) void loadDetail(selectedId);
    else { setSelected(null); setHistory([]); }
  }, [selectedId, loadDetail]);

  const categories = useMemo(() => Array.from(new Set(playbooks.map((p) => p.category))).sort(), [playbooks]);
  const triggers = useMemo(() => Array.from(new Set(playbooks.map((p) => p.trigger_type))).sort(), [playbooks]);

  const filtered = playbooks.filter((pb) => {
    if (filterTrigger !== "all" && pb.trigger_type !== filterTrigger) return false;
    if (filterStatus !== "all" && (filterStatus === "enabled") !== pb.enabled) return false;
    if (filterCategory !== "all" && pb.category !== filterCategory) return false;
    return true;
  });

  async function handleExecute(simulate: boolean) {
    if (!selected) return;
    let parsed: Record<string, unknown> = {};
    try { parsed = executeInput.trim() ? JSON.parse(executeInput) : {}; }
    catch { setActionMsg("input_data: JSON invalide"); return; }
    setActionMsg(simulate ? "Simulation lancée…" : "Exécution lancée…");
    try {
      const exec = simulate
        ? await simulatePlaybook(selected.id, { input_data: parsed })
        : await executePlaybook(selected.id, { input_data: parsed });
      setActionMsg(`${simulate ? "Simulation" : "Exécution"} ${exec.status} (${exec.id.slice(0, 8)})`);
      // refresh history after a short delay
      setTimeout(() => { if (selected) void loadDetail(selected.id); }, 1500);
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async function handleCancel(execId: string) {
    try {
      await cancelExecution(execId);
      setActionMsg(`Exécution ${execId.slice(0, 8)} annulée`);
      if (selected) void loadDetail(selected.id);
    } catch (e) {
      setActionMsg(`Erreur annulation: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="SOAR // PLAYBOOK CONFIGURATION & MONITORING">
          Playbook Management
        </HudHeading>
        <HudButton variant="secondary" size="sm" onClick={() => void reload()}>
          {loading ? "…" : "REFRESH"}
        </HudButton>
      </div>

      <div className="cyan-line" />

      {error && <HudCard tone="alert" className="p-3 text-[11px] text-neon-pink">{error}</HudCard>}
      {actionMsg && <HudCard className="p-3 text-[11px] text-cyan-200">{actionMsg}</HudCard>}

      {/* Metrics row */}
      {metrics && (
        <div className="grid grid-cols-5 gap-3">
          <Stat label="Total Playbooks" value={metrics.total_playbooks} />
          <Stat label="Enabled" value={metrics.enabled_playbooks} color="text-green-400" />
          <Stat label="Executions" value={metrics.total_executions} />
          <Stat label="Success Rate" value={`${(metrics.success_rate * 100).toFixed(0)}%`} color="text-green-400" />
          <Stat label="Avg Duration" value={fmtDuration(metrics.avg_duration_ms)} />
        </div>
      )}

      {/* Filters */}
      <HudCard className="flex items-center gap-4 p-3">
        <span className="text-[9px] uppercase tracking-wider text-gray-500">Filters:</span>
        <HudSelect value={filterTrigger} onChange={(e) => setFilterTrigger(e.target.value)} className="w-auto text-[10px]">
          <option value="all">All Triggers</option>
          {triggers.map((t) => <option key={t} value={t}>{t}</option>)}
        </HudSelect>
        <HudSelect value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="w-auto text-[10px]">
          <option value="all">All Status</option>
          <option value="enabled">Enabled</option>
          <option value="disabled">Disabled</option>
        </HudSelect>
        <HudSelect value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} className="w-auto text-[10px]">
          <option value="all">All Categories</option>
          {categories.map((c) => <option key={c} value={c}>{c}</option>)}
        </HudSelect>
        <span className="ml-auto text-[10px] text-gray-500">{filtered.length} playbooks</span>
      </HudCard>

      <div className="grid grid-cols-3 gap-6">
        {/* List */}
        <div className="col-span-1 space-y-2">
          {loading && playbooks.length === 0 && <HudCard className="p-4 text-[11px] text-gray-500">Chargement…</HudCard>}
          {!loading && filtered.length === 0 && <HudCard className="p-4 text-[11px] text-gray-500">Aucun playbook.</HudCard>}
          {filtered.map((pb) => (
            <HudCard
              as="button"
              key={pb.id}
              onClick={() => setSelectedId(pb.id)}
              className={`w-full p-4 text-left transition-all ${
                selectedId === pb.id
                  ? "border-cyan-glow/30 shadow-cyan-sm"
                  : "hover:border-cyan-glow/20"
              }`}
            >
              <div className="mb-2 flex items-center justify-between">
                <Badge text={pb.trigger_type} cls={TRIGGER_COLORS[pb.trigger_type] || TRIGGER_COLORS.manual} />
                <Badge text={pb.enabled ? "enabled" : "disabled"} cls={STATUS_BADGE[pb.enabled ? "enabled" : "disabled"]} />
              </div>
              <h3 className="text-xs font-bold text-gray-200">{pb.name}</h3>
              <p className="mt-1 line-clamp-2 text-[10px] text-gray-500">{pb.description}</p>
              <div className="mt-2 flex items-center justify-between text-[9px] text-gray-600">
                <span>{pb.category}</span>
                <span>v{pb.version}{pb.builtin ? " · builtin" : ""}</span>
              </div>
            </HudCard>
          ))}
        </div>

        {/* Detail */}
        <div className="col-span-2">
          {detailLoading && <HudCard className="p-5 text-[11px] text-gray-500">Chargement détail…</HudCard>}
          {!detailLoading && selected && (
            <div className="space-y-4">
              {/* Info */}
              <HudCard className="p-5">
                <div className="mb-4 flex items-start justify-between gap-4">
                  <div>
                    <h2 className="text-sm font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>{selected.name}</h2>
                    <p className="mt-1 text-[10px] text-gray-400">{selected.description}</p>
                    {selected.tags && selected.tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {selected.tags.map((t) => (
                          <span key={t} className="rounded border border-gray-700 bg-black/30 px-1.5 py-0.5 text-[9px] text-gray-400">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-shrink-0 gap-2">
                    <Badge text={selected.enabled ? "enabled" : "disabled"} cls={STATUS_BADGE[selected.enabled ? "enabled" : "disabled"]} />
                    {selected.builtin && <Badge text="builtin" cls="bg-purple-500/15 text-purple-400 border-purple-500/30" />}
                  </div>
                </div>
                <div className="grid grid-cols-4 gap-3">
                  <Stat label="Trigger" value={selected.trigger_type} />
                  <Stat label="Category" value={selected.category} />
                  <Stat label="Version" value={selected.version} />
                  <Stat label="Steps" value={selected.definition.steps?.length ?? 0} color="text-cyan-glow" />
                </div>
              </HudCard>

              {/* Run panel */}
              <HudCard className="p-5">
                <h3 className="mb-3 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Run</h3>
                <label className="text-[9px] uppercase tracking-wider text-gray-500">input_data (JSON)</label>
                <HudTextarea
                  value={executeInput}
                  onChange={(e) => setExecuteInput(e.target.value)}
                  rows={3}
                  className="mt-1 text-[11px]"
                  placeholder='{"username": "alice", "src_ip": "1.2.3.4"}'
                />
                <div className="mt-3 flex gap-2">
                  <HudButton variant="matrix" size="sm" disabled={!selected.enabled} onClick={() => void handleExecute(false)}>
                    EXECUTE
                  </HudButton>
                  <HudButton variant="primary" size="sm" onClick={() => void handleExecute(true)}>
                    SIMULATE (DRY-RUN)
                  </HudButton>
                </div>
              </HudCard>

              {/* Steps */}
              <HudCard className="p-5">
                <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
                  Step Flowchart ({selected.definition.steps?.length ?? 0})
                </h3>
                <div className="flex flex-col items-center">
                  {(selected.definition.steps || []).map((step, i) => (
                    <div key={`${step.name}-${i}`} className="flex flex-col items-center">
                      {i > 0 && <div className="my-1 h-6 w-px bg-cyan-glow/20" />}
                      <div className={`flex w-96 items-center gap-3 rounded-lg border p-3 ${STEP_COLORS.border} ${STEP_COLORS.bg}`}>
                        <div className={`h-3 w-3 rounded-full ${STEP_COLORS.dot}`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold text-gray-200">{step.name}</span>
                            <Badge text={step.action} cls="bg-black/30 text-cyan-dim border-cyan-glow/20" />
                          </div>
                          {step.params && Object.keys(step.params).length > 0 && (
                            <p className="mt-0.5 truncate text-[9px] text-gray-500">
                              {Object.keys(step.params).join(", ")}
                            </p>
                          )}
                          {step.condition && (
                            <p className="mt-0.5 text-[9px] text-yellow-400/70">if: {step.condition}</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </HudCard>

              {/* History */}
              <HudCard className="p-5">
                <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>Execution History</h3>
                {history.length === 0 ? (
                  <p className="text-[11px] text-gray-500">Aucune exécution pour ce playbook.</p>
                ) : (
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-800">
                        <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Started</th>
                        <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
                        <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Trigger</th>
                        <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
                        <th className="px-3 py-2 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((ex) => (
                        <tr key={ex.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                          <td className="px-3 py-2 text-[10px] font-mono text-gray-400">{fmtDate(ex.started_at || ex.created_at)}</td>
                          <td className="px-3 py-2">
                            <Badge text={ex.status} cls={EXEC_STATUS_BADGE[ex.status] || EXEC_STATUS_BADGE.pending} />
                            {ex.dry_run && <Badge text="dry-run" cls="ml-1 bg-purple-500/15 text-purple-400 border-purple-500/30" />}
                          </td>
                          <td className="px-3 py-2 text-[10px] text-gray-500">{ex.trigger}</td>
                          <td className="px-3 py-2 text-[10px] font-mono text-gray-400">{fmtDuration(ex.duration_ms)}</td>
                          <td className="px-3 py-2">
                            {(ex.status === "running" || ex.status === "pending") && (
                              <HudButton size="sm" variant="danger" onClick={() => void handleCancel(ex.id)}>
                                CANCEL
                              </HudButton>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </HudCard>
            </div>
          )}
          {!detailLoading && !selected && (
            <HudCard className="flex h-96 items-center justify-center">
              <div className="text-center">
                <svg className="mx-auto h-12 w-12 text-cyan-glow/20" fill="none" viewBox="0 0 24 24" strokeWidth={1} stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z" />
                </svg>
                <p className="mt-3 text-[10px] uppercase tracking-wider text-gray-600">Sélectionne un playbook pour voir le détail</p>
              </div>
            </HudCard>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <HudCard className="p-3">
      <p className="text-[9px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`mt-1 text-xs font-bold ${color || "text-gray-200"}`}>{value}</p>
    </HudCard>
  );
}
