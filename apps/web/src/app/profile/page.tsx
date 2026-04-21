"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import { useAuthStore } from "@/stores/authStore";

type UserStats = {
  total_logins: number;
  events_reviewed: number;
  incidents_handled: number;
  scans_performed: number;
  last_login: string | null;
};

type ActivityEntry = {
  id: string;
  action: string;
  target: string | null;
  ip_address: string | null;
  created_at: string;
};

type Preferences = {
  notif_email: boolean;
  notif_browser: boolean;
  notif_critical_only: boolean;
  default_layout: "grid" | "list";
  timezone: string;
};

type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  last_used_at: string | null;
  created_at: string;
  expires_at: string | null;
  revoked: boolean;
};

type ApiKeyCreated = ApiKey & { key: string };

type TotpSetup = { secret: string; otpauth_url: string; qr_png_base64: string };

const PROXY = "/api/proxy";

async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${PROXY}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

function AnimatedCounter({ target, duration = 1200 }: { target: number; duration?: number }) {
  const [value, setValue] = useState(0);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    let start = 0;
    const step = Math.max(1, Math.ceil(target / (duration / 16)));
    const id = setInterval(() => {
      start += step;
      if (start >= target) {
        start = target;
        clearInterval(id);
      }
      setValue(start);
    }, 16);
    return () => clearInterval(id);
  }, [target, duration]);
  return <span ref={ref}>{value.toLocaleString()}</span>;
}

function HudCard({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`glass-panel hud-corners p-5 ${className}`}>
      <h3 className="hud-heading text-xs font-semibold tracking-widest text-cyan-glow/70 mb-4">{title}</h3>
      {children}
    </div>
  );
}

function InitialsAvatar({ name }: { name: string }) {
  const initials = name
    .split(/[\s._-]+/)
    .map((s) => s[0]?.toUpperCase() ?? "")
    .slice(0, 2)
    .join("");
  return (
    <div className="relative mx-auto h-24 w-24 flex-shrink-0">
      <div className="flex h-full w-full items-center justify-center rounded-full bg-gradient-to-br from-cyan-glow/30 to-space-light border border-cyan-glow/30 shadow-cyan-lg">
        <span className="hud-heading text-2xl font-bold text-cyan-glow">{initials || "??"}</span>
      </div>
      <div className="absolute -inset-1 rounded-full opacity-30 blur-lg" style={{ background: "radial-gradient(circle, #00E5FF 0%, transparent 70%)" }} />
      <div className="absolute bottom-0 right-0 h-4 w-4 rounded-full border-2 border-space-dark bg-emerald-400 shadow-lg" title="Online" />
    </div>
  );
}

function formatAction(action: string): string {
  return action
    .split("_")
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(" ");
}

export default function ProfilePage() {
  const router = useRouter();
  const { user, status, refreshMe, logout } = useAuthStore();
  const [loggingOut, setLoggingOut] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const [stats, setStats] = useState<UserStats | null>(null);
  const [activities, setActivities] = useState<ActivityEntry[]>([]);
  const [prefs, setPrefs] = useState<Preferences | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [totpEnabled, setTotpEnabled] = useState(false);

  const [dataError, setDataError] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    if (!user) return;
    setDataError(null);
    try {
      const [s, a, p, k, t] = await Promise.all([
        apiJson<UserStats>("/auth/me/stats"),
        apiJson<{ total: number; items: ActivityEntry[] }>("/auth/me/activity?limit=25"),
        apiJson<Preferences>("/auth/me/preferences"),
        apiJson<ApiKey[]>("/auth/me/api-keys"),
        apiJson<{ enabled: boolean }>("/auth/me/2fa/status"),
      ]);
      setStats(s);
      setActivities(a.items);
      setPrefs(p);
      setApiKeys(k);
      setTotpEnabled(t.enabled);
    } catch (e) {
      setDataError(e instanceof Error ? e.message : "Failed to load profile data");
    }
  }, [user]);

  useEffect(() => {
    if (status === "idle") void refreshMe();
  }, [status, refreshMe]);

  useEffect(() => {
    if (status === "authenticated") void loadAll();
  }, [status, loadAll]);

  const username = user?.username ?? "—";
  const role = user?.role ?? "—";
  const email = user?.email ?? "—";
  const userId = user?.id ?? "—";
  const memberSince = useMemo(() => {
    if (!user?.created_at) return "—";
    const d = new Date(user.created_at);
    if (Number.isNaN(d.getTime())) return user.created_at;
    return d.toLocaleDateString("fr-FR", { year: "numeric", month: "short" });
  }, [user?.created_at]);

  async function onLogout() {
    setLoggingOut(true);
    try {
      await logout();
      router.replace("/login");
    } finally {
      setLoggingOut(false);
    }
  }

  async function onRefresh() {
    setRefreshing(true);
    try {
      await refreshMe();
      await loadAll();
    } finally {
      setRefreshing(false);
    }
  }

  // --- Preferences ---
  const [savingPrefs, setSavingPrefs] = useState(false);
  const [prefsMsg, setPrefsMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  async function savePrefs(next: Preferences) {
    setSavingPrefs(true);
    setPrefsMsg(null);
    try {
      const updated = await apiJson<Preferences>("/auth/me/preferences", {
        method: "PUT",
        body: JSON.stringify(next),
      });
      setPrefs(updated);
      setPrefsMsg({ type: "ok", text: "Preferences saved" });
      setTimeout(() => setPrefsMsg(null), 2500);
    } catch (e) {
      setPrefsMsg({ type: "err", text: e instanceof Error ? e.message : "Save failed" });
    } finally {
      setSavingPrefs(false);
    }
  }

  function updatePref<K extends keyof Preferences>(key: K, value: Preferences[K]) {
    if (!prefs) return;
    const next = { ...prefs, [key]: value };
    setPrefs(next);
    void savePrefs(next);
  }

  // --- Password change ---
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwMsg, setPwMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [pwSaving, setPwSaving] = useState(false);

  async function handlePasswordChange(e: React.FormEvent) {
    e.preventDefault();
    if (!currentPw || !newPw) {
      setPwMsg({ type: "err", text: "All fields are required." });
      return;
    }
    if (newPw.length < 8) {
      setPwMsg({ type: "err", text: "Password must be at least 8 characters." });
      return;
    }
    if (newPw !== confirmPw) {
      setPwMsg({ type: "err", text: "Passwords do not match." });
      return;
    }
    setPwSaving(true);
    try {
      await apiJson<void>("/auth/me/password", {
        method: "POST",
        body: JSON.stringify({ current_password: currentPw, new_password: newPw }),
      });
      setPwMsg({ type: "ok", text: "Password updated successfully." });
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
      setTimeout(() => setPwMsg(null), 4000);
    } catch (err) {
      setPwMsg({ type: "err", text: err instanceof Error ? err.message : "Update failed" });
    } finally {
      setPwSaving(false);
    }
  }

  // --- API Key create/revoke ---
  const [newKeyName, setNewKeyName] = useState("");
  const [newKeyScopes, setNewKeyScopes] = useState("read");
  const [newKeyExpiry, setNewKeyExpiry] = useState<string>("");
  const [createdKey, setCreatedKey] = useState<ApiKeyCreated | null>(null);
  const [keyMsg, setKeyMsg] = useState<string | null>(null);
  const [keyBusy, setKeyBusy] = useState(false);

  async function onCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    setKeyBusy(true);
    setKeyMsg(null);
    try {
      const exp = newKeyExpiry ? parseInt(newKeyExpiry, 10) : null;
      const k = await apiJson<ApiKeyCreated>("/auth/me/api-keys", {
        method: "POST",
        body: JSON.stringify({
          name: newKeyName.trim(),
          scopes: newKeyScopes,
          expires_in_days: Number.isFinite(exp) ? exp : null,
        }),
      });
      setCreatedKey(k);
      setNewKeyName("");
      setNewKeyExpiry("");
      await loadAll();
    } catch (err) {
      setKeyMsg(err instanceof Error ? err.message : "Create failed");
    } finally {
      setKeyBusy(false);
    }
  }

  async function onRevokeKey(id: string) {
    if (!confirm("Revoke this API key? This cannot be undone.")) return;
    try {
      await apiJson<void>(`/auth/me/api-keys/${id}`, { method: "DELETE" });
      await loadAll();
    } catch (err) {
      setKeyMsg(err instanceof Error ? err.message : "Revoke failed");
    }
  }

  // --- 2FA flow ---
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpMsg, setTotpMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);
  const [totpBusy, setTotpBusy] = useState(false);
  const [disablePw, setDisablePw] = useState("");

  async function onSetup2FA() {
    setTotpBusy(true);
    setTotpMsg(null);
    try {
      const s = await apiJson<TotpSetup>("/auth/me/2fa/setup", { method: "POST" });
      setTotpSetup(s);
    } catch (err) {
      setTotpMsg({ type: "err", text: err instanceof Error ? err.message : "Setup failed" });
    } finally {
      setTotpBusy(false);
    }
  }

  async function onEnable2FA(e: React.FormEvent) {
    e.preventDefault();
    if (!totpCode.trim()) return;
    setTotpBusy(true);
    try {
      await apiJson<{ enabled: boolean }>("/auth/me/2fa/enable", {
        method: "POST",
        body: JSON.stringify({ code: totpCode.trim() }),
      });
      setTotpEnabled(true);
      setTotpSetup(null);
      setTotpCode("");
      setTotpMsg({ type: "ok", text: "2FA enabled successfully." });
      setTimeout(() => setTotpMsg(null), 4000);
    } catch (err) {
      setTotpMsg({ type: "err", text: err instanceof Error ? err.message : "Invalid code" });
    } finally {
      setTotpBusy(false);
    }
  }

  async function onDisable2FA(e: React.FormEvent) {
    e.preventDefault();
    if (!disablePw) return;
    setTotpBusy(true);
    try {
      await apiJson<{ enabled: boolean }>("/auth/me/2fa/disable", {
        method: "POST",
        body: JSON.stringify({ password: disablePw }),
      });
      setTotpEnabled(false);
      setDisablePw("");
      setTotpMsg({ type: "ok", text: "2FA disabled." });
      setTimeout(() => setTotpMsg(null), 4000);
    } catch (err) {
      setTotpMsg({ type: "err", text: err instanceof Error ? err.message : "Disable failed" });
    } finally {
      setTotpBusy(false);
    }
  }

  const statItems = [
    { label: "Total Logins", value: stats?.total_logins ?? 0, color: "text-cyan-glow" },
    { label: "Events Reviewed", value: stats?.events_reviewed ?? 0, color: "text-blue-400" },
    { label: "Incidents Handled", value: stats?.incidents_handled ?? 0, color: "text-amber-400" },
    { label: "Scans Performed", value: stats?.scans_performed ?? 0, color: "text-emerald-400" },
  ];

  const lastLoginFmt = stats?.last_login
    ? new Date(stats.last_login).toLocaleString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";

  return (
    <PageTransition className="min-h-screen p-6 lg:p-8 space-y-6">
      {/* Header */}
      <StaggerItem>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-3">
            <svg className="h-5 w-5 text-cyan-glow" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z" />
            </svg>
            <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">User Profile</h1>
            {status === "loading" && (
              <span className="text-[10px] uppercase tracking-widest text-cyan-glow/40">loading...</span>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={onRefresh}
              disabled={refreshing}
              className="rounded-md border border-gray-700/50 bg-gray-900/50 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 hover:text-cyan-glow disabled:opacity-50"
            >
              {refreshing ? "..." : "REFRESH"}
            </button>
            <button
              onClick={onLogout}
              disabled={loggingOut}
              className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2 text-[10px] font-bold uppercase tracking-wider text-red-400 hover:bg-red-500/20 disabled:opacity-50"
            >
              {loggingOut ? "..." : "LOGOUT"}
            </button>
          </div>
        </div>
        <div className="cyan-line w-full" />
        {dataError && (
          <p className="mt-2 text-[11px] text-red-400">{dataError}</p>
        )}
      </StaggerItem>

      {/* Avatar + Info + Stats */}
      <StaggerItem>
        <div className="grid gap-6 lg:grid-cols-3">
          <HudCard title="Identity" className="flex flex-col items-center text-center lg:col-span-1">
            <InitialsAvatar name={username} />
            <div className="mt-4 space-y-1">
              <p className="hud-heading text-base font-bold text-cyan-glow tracking-wider">{username}</p>
              <span className="inline-block rounded-full border border-cyan-glow/20 bg-cyan-glow/10 px-3 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-cyan-glow">
                {role}
              </span>
              <p className="text-xs text-gray-500 mt-2">{email}</p>
              <p className="text-[10px] text-gray-600">Member since {memberSince}</p>
              <p className="mt-1 font-mono text-[9px] text-gray-700 break-all">{userId}</p>
              {user && !user.is_active && (
                <span className="mt-2 inline-block rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[9px] font-mono uppercase tracking-wider text-amber-400">
                  account disabled
                </span>
              )}
            </div>
          </HudCard>

          <HudCard title="Statistics" className="lg:col-span-2">
            <div className="grid grid-cols-2 gap-4">
              {statItems.map((s) => (
                <div key={s.label} className="glass-panel p-4 text-center">
                  <p className={`text-2xl font-bold ${s.color}`}>
                    <AnimatedCounter target={s.value} />
                  </p>
                  <p className="hud-label mt-1 text-[10px]">{s.label}</p>
                </div>
              ))}
            </div>
            <p className="mt-4 text-[10px] text-gray-600 uppercase tracking-wider">
              Last login: <span className="text-gray-400">{lastLoginFmt}</span>
            </p>
          </HudCard>
        </div>
      </StaggerItem>

      {/* Security section */}
      <StaggerItem>
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Change Password */}
          <HudCard title="Change Password">
            <form onSubmit={handlePasswordChange} className="space-y-3">
              {[
                { label: "Current Password", val: currentPw, set: setCurrentPw },
                { label: "New Password", val: newPw, set: setNewPw },
                { label: "Confirm New Password", val: confirmPw, set: setConfirmPw },
              ].map((f) => (
                <div key={f.label}>
                  <label className="block text-[10px] text-gray-500 uppercase tracking-wider mb-1">{f.label}</label>
                  <input
                    type="password"
                    value={f.val}
                    onChange={(e) => f.set(e.target.value)}
                    className="w-full rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 placeholder-gray-600 outline-none focus:border-cyan-glow/40 focus:shadow-cyan-sm transition-all"
                    placeholder="••••••••"
                  />
                </div>
              ))}
              {pwMsg && (
                <p className={`text-[11px] ${pwMsg.type === "ok" ? "text-emerald-400" : "text-red-400"}`}>{pwMsg.text}</p>
              )}
              <button
                type="submit"
                disabled={pwSaving}
                className="mt-1 w-full rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-4 py-2 text-xs font-semibold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-sm disabled:opacity-50"
              >
                {pwSaving ? "..." : "Update Password"}
              </button>
            </form>
          </HudCard>

          {/* 2FA */}
          <HudCard title="Two-Factor Authentication">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-300 font-medium">TOTP Authenticator</p>
                  <p className="text-[10px] text-gray-600 mt-0.5">Google Authenticator, Authy, 1Password...</p>
                </div>
                <span
                  className={`rounded-full border px-3 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                    totpEnabled
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-400"
                  }`}
                >
                  {totpEnabled ? "Enabled" : "Disabled"}
                </span>
              </div>

              {totpMsg && (
                <p className={`text-[11px] ${totpMsg.type === "ok" ? "text-emerald-400" : "text-red-400"}`}>{totpMsg.text}</p>
              )}

              {!totpEnabled && !totpSetup && (
                <button
                  onClick={onSetup2FA}
                  disabled={totpBusy}
                  className="w-full rounded-md border border-cyan-glow/15 bg-space-mid/50 px-4 py-2 text-xs text-cyan-dim hover:bg-cyan-glow/10 transition-all uppercase tracking-wider font-medium disabled:opacity-50"
                >
                  {totpBusy ? "..." : "Enable 2FA"}
                </button>
              )}

              {!totpEnabled && totpSetup && (
                <form onSubmit={onEnable2FA} className="space-y-3">
                  <div className="flex justify-center">
                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                      src={`data:image/png;base64,${totpSetup.qr_png_base64}`}
                      alt="TOTP QR code"
                      className="rounded-md border border-cyan-glow/20 bg-white p-2"
                      width={180}
                      height={180}
                    />
                  </div>
                  <p className="text-[10px] text-gray-500 text-center">
                    Or enter secret manually:
                  </p>
                  <code className="block rounded-md border border-cyan-glow/10 bg-space-deep/80 px-3 py-2 text-[11px] text-cyan-dim font-mono break-all text-center">
                    {totpSetup.secret}
                  </code>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="\d{6}"
                    maxLength={6}
                    placeholder="6-digit code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value)}
                    className="w-full rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40 text-center tracking-widest font-mono"
                  />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => { setTotpSetup(null); setTotpCode(""); }}
                      className="flex-1 rounded-md border border-gray-700 bg-gray-900/50 px-3 py-2 text-[10px] uppercase tracking-wider text-gray-400"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={totpBusy || totpCode.length !== 6}
                      className="flex-1 rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-3 py-2 text-[10px] uppercase tracking-wider text-cyan-glow disabled:opacity-50"
                    >
                      {totpBusy ? "..." : "Verify & Enable"}
                    </button>
                  </div>
                </form>
              )}

              {totpEnabled && (
                <form onSubmit={onDisable2FA} className="space-y-2">
                  <label className="block text-[10px] text-gray-500 uppercase tracking-wider">
                    Password (to disable 2FA)
                  </label>
                  <input
                    type="password"
                    value={disablePw}
                    onChange={(e) => setDisablePw(e.target.value)}
                    className="w-full rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40"
                  />
                  <button
                    type="submit"
                    disabled={totpBusy || !disablePw}
                    className="w-full rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-[10px] uppercase tracking-wider text-red-400 hover:bg-red-500/20 disabled:opacity-50"
                  >
                    {totpBusy ? "..." : "Disable 2FA"}
                  </button>
                </form>
              )}
            </div>
          </HudCard>
        </div>
      </StaggerItem>

      {/* API Keys */}
      <StaggerItem>
        <HudCard title="API Keys">
          <form onSubmit={onCreateKey} className="grid gap-3 sm:grid-cols-4 mb-4">
            <input
              type="text"
              placeholder="Key name"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              className="rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40 sm:col-span-2"
            />
            <select
              value={newKeyScopes}
              onChange={(e) => setNewKeyScopes(e.target.value)}
              className="rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none"
            >
              <option value="read" className="bg-space-deep">read</option>
              <option value="read,write" className="bg-space-deep">read+write</option>
              <option value="admin" className="bg-space-deep">admin</option>
            </select>
            <div className="flex gap-2">
              <input
                type="number"
                min={1}
                placeholder="Expires (days)"
                value={newKeyExpiry}
                onChange={(e) => setNewKeyExpiry(e.target.value)}
                className="flex-1 rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40"
              />
              <button
                type="submit"
                disabled={keyBusy || !newKeyName.trim()}
                className="rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-3 py-2 text-[10px] uppercase tracking-wider text-cyan-glow disabled:opacity-50"
              >
                {keyBusy ? "..." : "Create"}
              </button>
            </div>
          </form>

          {createdKey && (
            <div className="mb-4 rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3">
              <p className="text-[11px] text-emerald-400 font-semibold uppercase tracking-wider mb-2">
                Copy this key now — it will not be shown again
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded-md border border-cyan-glow/10 bg-space-deep/80 px-3 py-2 text-[11px] text-cyan-dim font-mono break-all">
                  {createdKey.key}
                </code>
                <button
                  onClick={() => navigator.clipboard.writeText(createdKey.key)}
                  className="rounded-md border border-cyan-glow/15 bg-space-mid/50 px-3 py-2 text-[10px] uppercase tracking-wider text-cyan-dim hover:bg-cyan-glow/10"
                >
                  Copy
                </button>
                <button
                  onClick={() => setCreatedKey(null)}
                  className="rounded-md border border-gray-700 bg-gray-900/50 px-3 py-2 text-[10px] uppercase tracking-wider text-gray-400"
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {keyMsg && <p className="text-[11px] text-red-400 mb-2">{keyMsg}</p>}

          {apiKeys.length === 0 ? (
            <p className="text-[11px] text-gray-600">No API keys yet.</p>
          ) : (
            <div className="space-y-2">
              {apiKeys.map((k) => (
                <div
                  key={k.id}
                  className="flex items-center justify-between rounded-md border border-cyan-glow/10 bg-space-deep/40 px-3 py-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-3">
                      <p className="text-xs text-gray-300 font-medium truncate">{k.name}</p>
                      <code className="text-[10px] text-cyan-dim font-mono">{k.prefix}…</code>
                      <span className="text-[9px] text-gray-600 uppercase tracking-wider">{k.scopes}</span>
                      {k.revoked && (
                        <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[9px] uppercase tracking-wider text-red-400">
                          revoked
                        </span>
                      )}
                      {k.expires_at && !k.revoked && new Date(k.expires_at) < new Date() && (
                        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[9px] uppercase tracking-wider text-amber-400">
                          expired
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] text-gray-600 mt-0.5">
                      Created {new Date(k.created_at).toLocaleDateString()}
                      {k.last_used_at && ` · last used ${new Date(k.last_used_at).toLocaleDateString()}`}
                      {k.expires_at && ` · expires ${new Date(k.expires_at).toLocaleDateString()}`}
                    </p>
                  </div>
                  {!k.revoked && (
                    <button
                      onClick={() => onRevokeKey(k.id)}
                      className="ml-3 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-1 text-[10px] uppercase tracking-wider text-red-400 hover:bg-red-500/20"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </HudCard>
      </StaggerItem>

      {/* Preferences */}
      <StaggerItem>
        <HudCard title="Preferences">
          {!prefs ? (
            <p className="text-[11px] text-gray-600">Loading preferences…</p>
          ) : (
            <>
              <div className="grid gap-6 sm:grid-cols-3">
                <div className="space-y-3">
                  <p className="text-xs text-gray-300 font-medium mb-2">Notifications</p>
                  {[
                    { label: "Email alerts", key: "notif_email" as const },
                    { label: "Browser notifications", key: "notif_browser" as const },
                    { label: "Critical only", key: "notif_critical_only" as const },
                  ].map((n) => {
                    const checked = prefs[n.key];
                    return (
                      <label key={n.label} className="flex items-center gap-3 cursor-pointer group">
                        <div
                          onClick={() => updatePref(n.key, !checked)}
                          className={`relative h-5 w-9 rounded-full transition-all ${checked ? "bg-cyan-glow/30 border-cyan-glow/40" : "bg-space-mid border-gray-700"} border`}
                        >
                          <div className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${checked ? "left-[18px] bg-cyan-glow shadow-cyan-sm" : "left-0.5 bg-gray-500"}`} />
                        </div>
                        <span className="text-[11px] text-gray-400 group-hover:text-gray-300 transition-colors">{n.label}</span>
                      </label>
                    );
                  })}
                </div>

                <div>
                  <p className="text-xs text-gray-300 font-medium mb-2">Default Layout</p>
                  <div className="flex gap-2">
                    {(["grid", "list"] as const).map((l) => (
                      <button
                        key={l}
                        onClick={() => updatePref("default_layout", l)}
                        className={`flex-1 rounded-md border px-3 py-2 text-[11px] uppercase tracking-wider font-medium transition-all ${
                          prefs.default_layout === l
                            ? "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                            : "border-gray-700 bg-space-mid/40 text-gray-500 hover:border-cyan-glow/15 hover:text-gray-400"
                        }`}
                      >
                        {l}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="text-xs text-gray-300 font-medium mb-2">Timezone</p>
                  <select
                    value={prefs.timezone}
                    onChange={(e) => updatePref("timezone", e.target.value)}
                    className="w-full rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40 focus:shadow-cyan-sm transition-all"
                  >
                    {["UTC", "Europe/Paris", "Europe/London", "America/New_York", "America/Los_Angeles", "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney"].map((tz) => (
                      <option key={tz} value={tz} className="bg-space-deep text-gray-300">{tz}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="mt-3 flex items-center justify-end gap-3">
                {savingPrefs && <span className="text-[10px] text-gray-500">saving…</span>}
                {prefsMsg && (
                  <span className={`text-[10px] ${prefsMsg.type === "ok" ? "text-emerald-400" : "text-red-400"}`}>
                    {prefsMsg.text}
                  </span>
                )}
              </div>
            </>
          )}
        </HudCard>
      </StaggerItem>

      {/* Activity Log */}
      <StaggerItem>
        <HudCard title="Recent Activity">
          {activities.length === 0 ? (
            <p className="text-[11px] text-gray-600">No activity yet.</p>
          ) : (
            <div className="relative space-y-0">
              <div className="absolute left-[7px] top-2 bottom-2 w-px bg-gradient-to-b from-cyan-glow/30 via-cyan-glow/10 to-transparent" />
              {activities.map((a, i) => (
                <motion.div
                  key={a.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.03, duration: 0.3 }}
                  className="relative flex items-start gap-3 py-2 pl-6"
                >
                  <div className="absolute left-0 top-3 h-[14px] w-[14px] rounded-full border border-cyan-glow/30 bg-space-deep flex items-center justify-center">
                    <div className="h-1.5 w-1.5 rounded-full bg-cyan-glow/60" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-300">
                      {formatAction(a.action)}
                      {a.target && <span className="text-gray-500"> · {a.target}</span>}
                      {a.ip_address && <span className="text-gray-600 ml-2 font-mono text-[10px]">{a.ip_address}</span>}
                    </p>
                    <p className="text-[10px] text-gray-600 mt-0.5">
                      {new Date(a.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                      {" "}
                      {new Date(a.created_at).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </HudCard>
      </StaggerItem>
    </PageTransition>
  );
}
