"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";

import {
  cancelExecution,
  getExecution,
  listExecutions,
  type ExecutionReadApi,
} from "@/lib/apiClient";
import { HudHeading, HudCard, HudButton, HudSelect } from "@/components/hud";

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-gray-500/15 text-gray-400 border-gray-500/30",
  running: "bg-cyan-glow/15 text-cyan-glow border-cyan-glow/30",
  completed: "bg-green-500/15 text-green-400 border-green-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  cancelled: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const STEP_STATUS_COLORS: Record<string, string> = {
  completed: "text-green-400",
  success: "text-green-400",
  failed: "text-red-400",
  skipped: "text-gray-500",
  running: "text-cyan-glow",
  pending: "text-gray-500",
};

const STEP_DOT: Record<string, string> = {
  completed: "bg-green-500",
  success: "bg-green-500",
  failed: "bg-red-500",
  skipped: "bg-gray-600",
  running: "bg-cyan-glow",
  pending: "bg-gray-600",
};

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

interface StepItem {
  name: string;
  action?: string;
  status: string;
  output?: unknown;
  error?: string | null;
  duration_ms?: number | null;
}

export default function ExecutionsPage() {
  const [executions, setExecutions] = useState<ExecutionReadApi[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expandedDetail, setExpandedDetail] = useState<{ steps?: StepItem[] } | null>(null);
  const [filterPlaybook, setFilterPlaybook] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await listExecutions({ limit: 100 });
      setExecutions(list);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    const t = setInterval(() => { void reload(); }, 10_000);
    return () => clearInterval(t);
  }, [reload]);

  const playbookNames = useMemo(
    () => Array.from(new Set(executions.map((e) => e.playbook_name))).sort(),
    [executions],
  );

  const filtered = executions.filter((ex) => {
    if (filterPlaybook !== "all" && ex.playbook_name !== filterPlaybook) return false;
    if (filterStatus !== "all" && ex.status !== filterStatus) return false;
    return true;
  });

  const runningCount = executions.filter((e) => e.status === "running" || e.status === "pending").length;

  async function handleExpand(id: string) {
    if (expandedId === id) {
      setExpandedId(null);
      setExpandedDetail(null);
      return;
    }
    setExpandedId(id);
    setExpandedDetail(null);
    try {
      const detail = await getExecution(id);
      setExpandedDetail(detail);
    } catch (e) {
      setActionMsg(`Erreur détail: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  async function handleCancel(id: string) {
    try {
      await cancelExecution(id);
      setActionMsg(`Exécution ${id.slice(0, 8)} annulée`);
      void reload();
    } catch (e) {
      setActionMsg(`Erreur annulation: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="SOAR // ALL PLAYBOOK EXECUTIONS">
          Execution History
        </HudHeading>
        <div className="flex items-center gap-2">
          <HudButton variant="secondary" size="sm" onClick={() => void reload()}>
            {loading ? "…" : "REFRESH"}
          </HudButton>
          <HudCard className="flex items-center gap-2 px-3 py-1.5">
            <span className="relative flex h-2 w-2">
              {runningCount > 0 && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-glow opacity-75" />}
              <span className={`relative inline-flex h-2 w-2 rounded-full ${runningCount > 0 ? "bg-cyan-glow" : "bg-gray-600"}`} />
            </span>
            <span className="text-[10px] tracking-wider text-gray-500">{runningCount} RUNNING</span>
          </HudCard>
        </div>
      </div>

      <div className="cyan-line" />

      {error && <HudCard tone="alert" className="p-3 text-[11px] text-neon-pink">{error}</HudCard>}
      {actionMsg && <HudCard className="p-3 text-[11px] text-cyan-200">{actionMsg}</HudCard>}

      <HudCard className="flex flex-wrap items-center gap-4 p-3">
        <span className="text-[9px] uppercase tracking-wider text-gray-500">Filters:</span>
        <HudSelect value={filterPlaybook} onChange={(e) => setFilterPlaybook(e.target.value)} className="w-auto text-[10px]">
          <option value="all">All Playbooks</option>
          {playbookNames.map((name) => <option key={name} value={name}>{name}</option>)}
        </HudSelect>
        <HudSelect value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="w-auto text-[10px]">
          <option value="all">All Status</option>
          <option value="pending">Pending</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </HudSelect>
        <span className="ml-auto text-[10px] text-gray-500">{filtered.length} executions</span>
      </HudCard>

      <HudCard className="overflow-hidden p-0">
        <table className="w-full">
          <thead>
            <tr className="border-b border-cyan-glow/10">
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">ID</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Playbook</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Status</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Started</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Duration</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Trigger</th>
              <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">Actions</th>
            </tr>
          </thead>
          <tbody>
            {!loading && filtered.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-[11px] text-gray-500">Aucune exécution.</td></tr>
            )}
            {filtered.map((ex) => (
              <Fragment key={ex.id}>
                <tr
                  className={`cursor-pointer border-b border-gray-800/50 transition-colors hover:bg-cyan-glow/5 ${expandedId === ex.id ? "bg-cyan-glow/5" : ""}`}
                  onClick={() => void handleExpand(ex.id)}
                >
                  <td className="px-4 py-3 text-[10px] font-mono text-cyan-glow/70">{ex.id.slice(0, 8)}</td>
                  <td className="px-4 py-3 text-xs font-medium text-gray-200">{ex.playbook_name}</td>
                  <td className="px-4 py-3">
                    <Badge text={ex.status} cls={STATUS_COLORS[ex.status] || STATUS_COLORS.pending} />
                    {ex.dry_run && <Badge text="dry-run" cls="ml-1 bg-purple-500/15 text-purple-400 border-purple-500/30" />}
                  </td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{fmtDate(ex.started_at || ex.created_at)}</td>
                  <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{fmtDuration(ex.duration_ms)}</td>
                  <td className="px-4 py-3 text-[10px] text-gray-500">{ex.trigger}</td>
                  <td className="px-4 py-3">
                    {(ex.status === "running" || ex.status === "pending") && (
                      <HudButton
                        size="sm"
                        variant="danger"
                        onClick={(e) => { e.stopPropagation(); void handleCancel(ex.id); }}
                      >
                        CANCEL
                      </HudButton>
                    )}
                  </td>
                </tr>
                {expandedId === ex.id && (
                  <tr>
                    <td colSpan={7} className="bg-black/30 px-6 py-4">
                      {!expandedDetail && <p className="text-[10px] text-gray-500">Chargement…</p>}
                      {expandedDetail && (
                        <>
                          {ex.error && (
                            <div className="mb-3 rounded border border-red-500/30 bg-red-500/5 p-2 text-[10px] font-mono text-red-300">
                              ERROR: {ex.error}
                            </div>
                          )}
                          <h4 className="mb-3 text-[10px] font-bold uppercase tracking-wider text-cyan-glow">Step-by-Step Execution Log</h4>
                          {(!expandedDetail.steps || expandedDetail.steps.length === 0) ? (
                            <p className="text-[10px] text-gray-500">Pas de détail step-by-step disponible.</p>
                          ) : (
                            <div className="space-y-2">
                              {expandedDetail.steps.map((step, i) => (
                                <div key={i} className="flex items-start gap-3 rounded border border-gray-800/50 bg-gray-900/30 p-3">
                                  <div className="flex items-center gap-2 pt-0.5">
                                    <span className={`h-2 w-2 rounded-full ${STEP_DOT[step.status] || "bg-gray-600"}`} />
                                    <span className="w-4 text-center text-[9px] font-mono text-gray-600">{i + 1}</span>
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span className="text-[10px] font-bold text-gray-300">{step.name}</span>
                                      {step.action && <span className="text-[9px] font-mono text-cyan-dim">[{step.action}]</span>}
                                      <span className={`text-[9px] font-mono ${STEP_STATUS_COLORS[step.status] || "text-gray-500"}`}>[{step.status.toUpperCase()}]</span>
                                      {step.duration_ms != null && <span className="text-[9px] font-mono text-gray-600">{fmtDuration(step.duration_ms)}</span>}
                                    </div>
                                    {step.error && <p className="mt-1 text-[10px] font-mono text-red-400">{step.error}</p>}
                                    {step.output != null && (
                                      <pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-all text-[10px] font-mono text-gray-500">
                                        {typeof step.output === "string" ? step.output : JSON.stringify(step.output, null, 2)}
                                      </pre>
                                    )}
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </HudCard>
    </div>
  );
}
