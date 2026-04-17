"use client";

import { useCallback, useEffect, useState } from "react";

import {
  casesAssign,
  casesClose,
  casesCreate,
  casesGet,
  casesGetTimeline,
  casesList,
  casesListEvidence,
  casesScanSla,
  casesStats,
  casesTransition,
  casesAddEvidence,
} from "@/lib/apiClient";
import type {
  CaseEvidenceItem,
  CaseStats,
  CaseSummary,
  CaseTimelineItem,
} from "@/lib/types";

const STATUS_COLORS: Record<string, string> = {
  open: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  triaging: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  investigating: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  containment: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  recovery: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  closed: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const PRIORITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/40",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-gray-500/15 text-gray-400 border-gray-500/30",
};

const TRANSITIONS: Record<string, string[]> = {
  open: ["triaging", "closed"],
  triaging: ["investigating", "closed"],
  investigating: ["containment", "closed"],
  containment: ["recovery", "closed"],
  recovery: ["closed"],
  closed: [],
};

export default function CasesPage() {
  const [stats, setStats] = useState<CaseStats | null>(null);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [filter, setFilter] = useState<{ status?: string; priority?: string; sla_breached?: boolean }>({});
  const [selected, setSelected] = useState<CaseSummary | null>(null);
  const [timeline, setTimeline] = useState<CaseTimelineItem[]>([]);
  const [evidence, setEvidence] = useState<CaseEvidenceItem[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Create form
  const [newCase, setNewCase] = useState({
    title: "", description: "", priority: "medium", severity: "medium",
  });

  const reload = useCallback(async () => {
    setError(null);
    try {
      const [s, list] = await Promise.all([
        casesStats(),
        casesList({ ...filter, limit: 100 }),
      ]);
      setStats(s);
      setCases(list.cases);
    } catch (e: any) {
      setError(e?.message ?? "load error");
    }
  }, [filter]);

  useEffect(() => { reload(); }, [reload]);

  const openCase = async (c: CaseSummary) => {
    setSelected(c);
    try {
      const [tl, ev] = await Promise.all([
        casesGetTimeline(c.id),
        casesListEvidence(c.id),
      ]);
      setTimeline(tl.timeline);
      setEvidence(ev.evidence);
    } catch (e: any) {
      setError(e?.message ?? "load detail error");
    }
  };

  const refreshSelected = async () => {
    if (!selected) return;
    try {
      const fresh = await casesGet(selected.id);
      setSelected(fresh);
      const [tl, ev] = await Promise.all([
        casesGetTimeline(fresh.id),
        casesListEvidence(fresh.id),
      ]);
      setTimeline(tl.timeline);
      setEvidence(ev.evidence);
      reload();
    } catch (e: any) {
      setError(e?.message ?? "refresh error");
    }
  };

  const transition = async (status: string) => {
    if (!selected) return;
    try {
      await casesTransition(selected.id, status);
      await refreshSelected();
    } catch (e: any) { setError(e?.message ?? "transition error"); }
  };

  const close = async () => {
    if (!selected) return;
    const resolution = window.prompt("Resolution (true_positive | false_positive | benign | duplicate | mitigated)");
    if (!resolution) return;
    try {
      await casesClose(selected.id, resolution);
      await refreshSelected();
    } catch (e: any) { setError(e?.message ?? "close error"); }
  };

  const assignTo = async () => {
    if (!selected) return;
    const username = window.prompt("Assignee username (empty to unassign)");
    if (username === null) return;
    try {
      await casesAssign(selected.id, { assignee_username: username || undefined });
      await refreshSelected();
    } catch (e: any) { setError(e?.message ?? "assign error"); }
  };

  const addEvidence = async () => {
    if (!selected) return;
    const kind = window.prompt("Evidence kind (file | url | hash | log_excerpt | note | ioc | image | command)") ?? "";
    if (!kind) return;
    const title = window.prompt("Title") ?? "";
    if (!title) return;
    const content = window.prompt("Content") ?? "";
    try {
      await casesAddEvidence(selected.id, { kind, title, content });
      await refreshSelected();
    } catch (e: any) { setError(e?.message ?? "evidence error"); }
  };

  const create = async () => {
    if (!newCase.title) return;
    try {
      await casesCreate(newCase);
      setShowCreate(false);
      setNewCase({ title: "", description: "", priority: "medium", severity: "medium" });
      reload();
    } catch (e: any) { setError(e?.message ?? "create error"); }
  };

  const scanSla = async () => {
    try {
      const r = await casesScanSla();
      alert(`${r.count} case(s) newly breached`);
      reload();
    } catch (e: any) { setError(e?.message ?? "sla scan error"); }
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow"
              style={{ fontFamily: "Orbitron, sans-serif" }}>
            Case Management
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            INVESTIGATIONS // SLA TRACKING // CHAIN OF CUSTODY
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={scanSla}
                  className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-amber-300">
            SLA Scan
          </button>
          <button onClick={() => setShowCreate((v) => !v)}
                  className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-cyan-glow">
            + New Case
          </button>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-[11px] text-red-300">
          {error}
        </div>
      )}

      {showCreate && (
        <div className="glass-panel space-y-3 border border-cyan-glow/20 p-4">
          <h3 className="text-sm font-bold text-cyan-glow">Create case</h3>
          <input
            placeholder="Title"
            value={newCase.title}
            onChange={(e) => setNewCase({ ...newCase, title: e.target.value })}
            className="w-full rounded border border-cyan-glow/30 bg-black/40 px-3 py-2 text-[11px] text-gray-200"
          />
          <textarea
            placeholder="Description"
            value={newCase.description}
            onChange={(e) => setNewCase({ ...newCase, description: e.target.value })}
            className="w-full rounded border border-cyan-glow/30 bg-black/40 px-3 py-2 text-[11px] text-gray-200"
            rows={3}
          />
          <div className="flex gap-3">
            <select value={newCase.priority}
                    onChange={(e) => setNewCase({ ...newCase, priority: e.target.value })}
                    className="rounded border border-cyan-glow/30 bg-black/40 px-3 py-2 text-[11px] text-gray-200">
              {["critical", "high", "medium", "low"].map((p) =>
                <option key={p} value={p}>{p}</option>
              )}
            </select>
            <select value={newCase.severity}
                    onChange={(e) => setNewCase({ ...newCase, severity: e.target.value })}
                    className="rounded border border-cyan-glow/30 bg-black/40 px-3 py-2 text-[11px] text-gray-200">
              {["critical", "high", "medium", "low"].map((p) =>
                <option key={p} value={p}>{p}</option>
              )}
            </select>
            <button onClick={create}
                    className="rounded border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-[10px] font-bold uppercase text-emerald-300">
              Create
            </button>
          </div>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-4 gap-4">
          <div className="glass-panel border border-cyan-glow/20 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">Total</p>
            <p className="mt-1 text-2xl font-bold text-cyan-glow">{stats.total}</p>
          </div>
          <div className="glass-panel border border-amber-500/20 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">Open</p>
            <p className="mt-1 text-2xl font-bold text-amber-300">{stats.open}</p>
          </div>
          <div className="glass-panel border border-red-500/20 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">SLA breached</p>
            <p className="mt-1 text-2xl font-bold text-red-400">{stats.sla_breached}</p>
          </div>
          <div className="glass-panel border border-cyan-glow/10 p-4">
            <p className="text-[9px] uppercase tracking-wider text-gray-500">By priority</p>
            <div className="mt-1 flex flex-wrap gap-1 text-[9px]">
              {Object.entries(stats.by_priority).map(([k, v]) => (
                <span key={k} className={`rounded border px-2 py-0.5 ${PRIORITY_COLORS[k] ?? PRIORITY_COLORS.low}`}>
                  {k}: {v}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-3">
        <span className="text-[10px] uppercase tracking-wider text-gray-500">Filter:</span>
        <select value={filter.status ?? ""}
                onChange={(e) => setFilter({ ...filter, status: e.target.value || undefined })}
                className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-[11px] text-gray-200">
          <option value="">All statuses</option>
          {["open", "triaging", "investigating", "containment", "recovery", "closed"].map((s) =>
            <option key={s} value={s}>{s}</option>
          )}
        </select>
        <select value={filter.priority ?? ""}
                onChange={(e) => setFilter({ ...filter, priority: e.target.value || undefined })}
                className="rounded border border-cyan-glow/30 bg-black/40 px-2 py-1 text-[11px] text-gray-200">
          <option value="">All priorities</option>
          {["critical", "high", "medium", "low"].map((s) =>
            <option key={s} value={s}>{s}</option>
          )}
        </select>
        <label className="flex items-center gap-2 text-[10px] text-gray-400">
          <input type="checkbox"
                 checked={filter.sla_breached ?? false}
                 onChange={(e) => setFilter({ ...filter, sla_breached: e.target.checked || undefined })} />
          SLA breached only
        </label>
      </div>

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-7 glass-panel border border-cyan-glow/10 p-3">
          <div className="max-h-[60vh] overflow-y-auto">
            <table className="w-full text-[11px]">
              <thead className="text-[9px] uppercase tracking-wider text-gray-500">
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-2 py-2 text-left">Title</th>
                  <th className="px-2 py-2 text-left">Status</th>
                  <th className="px-2 py-2 text-left">Priority</th>
                  <th className="px-2 py-2 text-left">Assignee</th>
                  <th className="px-2 py-2 text-left">SLA</th>
                </tr>
              </thead>
              <tbody>
                {cases.length === 0 && (
                  <tr><td colSpan={5} className="py-4 text-center text-gray-500">No cases.</td></tr>
                )}
                {cases.map((c) => (
                  <tr key={c.id} onClick={() => openCase(c)}
                      className={`cursor-pointer border-b border-cyan-glow/5 hover:bg-cyan-glow/5 ${
                        selected?.id === c.id ? "bg-cyan-glow/10" : ""
                      }`}>
                    <td className="px-2 py-2 text-gray-200">{c.title}</td>
                    <td className="px-2 py-2">
                      <span className={`rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${STATUS_COLORS[c.status] ?? STATUS_COLORS.open}`}>
                        {c.status}
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      <span className={`rounded border px-2 py-0.5 text-[9px] font-mono uppercase ${PRIORITY_COLORS[c.priority] ?? PRIORITY_COLORS.low}`}>
                        {c.priority}
                      </span>
                    </td>
                    <td className="px-2 py-2 text-gray-400">{c.assignee_username ?? "—"}</td>
                    <td className="px-2 py-2">
                      {c.sla_breached ? (
                        <span className="text-red-400 text-[10px] font-bold">BREACHED</span>
                      ) : (
                        <span className="text-emerald-400 text-[10px]">OK</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col-span-5 glass-panel border border-cyan-glow/10 p-4">
          {!selected && (
            <p className="text-[11px] text-gray-500">Select a case to view details.</p>
          )}
          {selected && (
            <div className="space-y-3">
              <div>
                <h3 className="text-sm font-bold text-cyan-glow">{selected.title}</h3>
                <p className="mt-1 text-[10px] text-gray-400">{selected.description || "(no description)"}</p>
              </div>
              <div className="flex flex-wrap gap-2 text-[10px]">
                <span className={`rounded border px-2 py-0.5 ${STATUS_COLORS[selected.status]}`}>{selected.status}</span>
                <span className={`rounded border px-2 py-0.5 ${PRIORITY_COLORS[selected.priority]}`}>{selected.priority}</span>
                {selected.sla?.any_breach && (
                  <span className="rounded border border-red-500/40 bg-red-500/15 px-2 py-0.5 text-red-400">SLA BREACHED</span>
                )}
              </div>

              <div className="text-[10px] text-gray-400 space-y-1">
                <div>Assignee: <span className="text-gray-200">{selected.assignee_username ?? "—"}</span></div>
                <div>Created: <span className="text-gray-200">{selected.created_at ? new Date(selected.created_at).toLocaleString() : "—"}</span></div>
                {selected.sla && (
                  <div>Resolution due: <span className="text-gray-200">
                    {new Date(selected.sla.resolution_deadline).toLocaleString()}
                    ({selected.sla.minutes_to_resolution.toFixed(0)} min)
                  </span></div>
                )}
              </div>

              {/* Actions */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-cyan-glow/10">
                {(TRANSITIONS[selected.status] ?? []).map((s) => (
                  <button key={s} onClick={() => transition(s)}
                          className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-2 py-1 text-[9px] font-bold uppercase text-cyan-glow">
                    → {s}
                  </button>
                ))}
                {selected.status !== "closed" && (
                  <>
                    <button onClick={assignTo}
                            className="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-[9px] font-bold uppercase text-blue-300">
                      Assign
                    </button>
                    <button onClick={addEvidence}
                            className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-1 text-[9px] font-bold uppercase text-purple-300">
                      + Evidence
                    </button>
                    <button onClick={close}
                            className="rounded border border-red-500/30 bg-red-500/10 px-2 py-1 text-[9px] font-bold uppercase text-red-300">
                      Close
                    </button>
                  </>
                )}
              </div>

              {/* Evidence */}
              {evidence.length > 0 && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Evidence ({evidence.length})</p>
                  <div className="mt-1 space-y-1">
                    {evidence.map((e) => (
                      <div key={e.id} className="rounded border border-cyan-glow/10 bg-black/20 p-2 text-[10px]">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-cyan-glow/80">[{e.kind}] {e.title}</span>
                          <span className="font-mono text-[8px] text-gray-500">{e.sha256?.slice(0, 12)}…</span>
                        </div>
                        <div className="text-[9px] text-gray-500">
                          custody: {e.custody_chain.length} link(s) · {e.content_size}B
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Timeline */}
              {timeline.length > 0 && (
                <div>
                  <p className="text-[9px] uppercase tracking-wider text-gray-500">Timeline</p>
                  <div className="mt-1 max-h-40 overflow-y-auto space-y-1 text-[10px]">
                    {timeline.map((t) => (
                      <div key={t.id} className="border-l-2 border-cyan-glow/30 pl-2">
                        <div className="text-gray-300">{t.message}</div>
                        <div className="text-[9px] text-gray-500">
                          {t.kind} · {t.actor_username ?? "system"} · {t.ts ? new Date(t.ts).toLocaleString() : ""}
                        </div>
                      </div>
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
