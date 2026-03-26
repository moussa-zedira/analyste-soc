"use client";

import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { fetchUsers, updateUser, deleteUser, fetchAuditLog } from "@/lib/apiClient";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import type { AdminUser, AuditLogEntry } from "@/lib/types";

/* ---------- Tab selector ---------- */

type Tab = "users" | "audit";

/* ---------- Main component ---------- */

export default function AdminPage() {
  const [tab, setTab] = useState<Tab>("users");
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [auditLog, setAuditLog] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchUsers({ limit: 100 });
      setUsers(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur lors du chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAuditLog = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAuditLog({ limit: 100 });
      setAuditLog(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur lors du chargement");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (tab === "users") loadUsers();
    else loadAuditLog();
  }, [tab, loadUsers, loadAuditLog]);

  const handleRoleChange = async (userId: string, newRole: string) => {
    try {
      const updated = await updateUser(userId, { role: newRole });
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur");
    }
  };

  const handleToggleActive = async (userId: string, currentActive: boolean) => {
    try {
      const updated = await updateUser(userId, { is_active: !currentActive });
      setUsers((prev) => prev.map((u) => (u.id === userId ? updated : u)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur");
    }
  };

  const handleDelete = async (userId: string, username: string) => {
    if (!confirm(`Supprimer l'utilisateur ${username} ?`)) return;
    try {
      await deleteUser(userId);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erreur");
    }
  };

  const roleColor = (role: string) => {
    if (role === "admin") return "text-red-400 bg-red-400/10 border-red-400/30";
    if (role === "lead") return "text-amber-400 bg-amber-400/10 border-amber-400/30";
    return "text-cyan-glow bg-cyan-glow/10 border-cyan-glow/30";
  };

  const actionColor = (action: string) => {
    if (action.includes("delete")) return "text-red-400";
    if (action.includes("update")) return "text-amber-400";
    if (action.includes("scan")) return "text-cyan-glow";
    return "text-gray-400";
  };

  return (
    <PageTransition className="space-y-6">
      {/* Header */}
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Administration
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            USER MANAGEMENT // AUDIT LOG
          </p>
        </div>
      </StaggerItem>

      <StaggerItem>
        <div className="cyan-line" />
      </StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <div className="flex gap-2">
          {(["users", "audit"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`rounded-md border px-4 py-2 text-[11px] font-bold tracking-widest transition-all ${
                tab === t
                  ? "border-cyan-glow/50 bg-cyan-glow/10 text-cyan-glow"
                  : "border-gray-700 bg-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              {t === "users" ? "UTILISATEURS" : "JOURNAL D'AUDIT"}
            </button>
          ))}
        </div>
      </StaggerItem>

      {/* Error */}
      {error && (
        <div className="glass-panel border-red-500/30 px-4 py-3 text-xs tracking-wide text-red-400">
          <span className="mr-2 text-red-500">&#x25B2;</span>
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex justify-center py-8">
          <div className="h-8 w-8 rounded-full border-2 border-t-cyan-glow border-transparent animate-spin" />
        </div>
      )}

      {/* Users tab */}
      {!loading && tab === "users" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Username</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Email</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Role</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Status</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Created</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <motion.tr
                      key={user.id}
                      className="border-b border-cyan-glow/5 hover:bg-cyan-glow/5 transition-colors"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                    >
                      <td className="px-4 py-3 text-[11px] font-mono text-gray-200">{user.username}</td>
                      <td className="px-4 py-3 text-[11px] font-mono text-gray-400">{user.email}</td>
                      <td className="px-4 py-3">
                        <select
                          value={user.role}
                          onChange={(e) => handleRoleChange(user.id, e.target.value)}
                          className={`rounded border px-2 py-1 text-[10px] font-bold tracking-wider bg-transparent ${roleColor(user.role)}`}
                        >
                          <option value="analyst" className="bg-gray-900">analyst</option>
                          <option value="lead" className="bg-gray-900">lead</option>
                          <option value="admin" className="bg-gray-900">admin</option>
                        </select>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleToggleActive(user.id, user.is_active)}
                          className={`rounded-full px-3 py-1 text-[9px] font-bold tracking-widest border ${
                            user.is_active
                              ? "text-emerald-400 bg-emerald-400/10 border-emerald-400/30"
                              : "text-red-400 bg-red-400/10 border-red-400/30"
                          }`}
                        >
                          {user.is_active ? "ACTIF" : "INACTIF"}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-[10px] text-gray-500 font-mono">
                        {user.created_at ? new Date(user.created_at).toLocaleDateString() : "N/A"}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => handleDelete(user.id, user.username)}
                          className="rounded border border-red-500/30 bg-red-500/10 px-3 py-1 text-[9px] font-bold tracking-wider text-red-400 hover:bg-red-500/20 transition-colors"
                        >
                          SUPPRIMER
                        </button>
                      </td>
                    </motion.tr>
                  ))}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-[11px] text-gray-600">
                        Aucun utilisateur trouve
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </StaggerItem>
      )}

      {/* Audit log tab */}
      {!loading && tab === "audit" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Date</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">User</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Action</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Target</th>
                    <th className="px-4 py-3 text-[9px] font-bold tracking-widest text-cyan-glow/50 uppercase">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLog.map((entry) => (
                    <motion.tr
                      key={entry.id}
                      className="border-b border-cyan-glow/5 hover:bg-cyan-glow/5 transition-colors"
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                    >
                      <td className="px-4 py-3 text-[10px] font-mono text-gray-500">
                        {entry.created_at ? new Date(entry.created_at).toLocaleString() : "N/A"}
                      </td>
                      <td className="px-4 py-3 text-[11px] font-mono text-gray-300">
                        {entry.username || "system"}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold tracking-wider ${actionColor(entry.action)}`}>
                          {entry.action.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[11px] font-mono text-gray-400">
                        {entry.target || "—"}
                      </td>
                      <td className="px-4 py-3 text-[10px] font-mono text-gray-600 max-w-[200px] truncate">
                        {entry.details !== "{}" ? entry.details : "—"}
                      </td>
                    </motion.tr>
                  ))}
                  {auditLog.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-[11px] text-gray-600">
                        Aucune entree dans le journal
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
