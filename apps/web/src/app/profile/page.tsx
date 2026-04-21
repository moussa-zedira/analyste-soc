"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "framer-motion";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import { useAuthStore } from "@/stores/authStore";

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

/* ---------- mock data generators ---------- */

function mockStats() {
  return { totalLogins: 342, eventsReviewed: 1287, incidentsHandled: 56, scansPerformed: 89 };
}

function mockActivityLog() {
  const actions = [
    "Logged in from 192.168.1.42",
    "Reviewed event #EVT-4821",
    "Acknowledged incident INC-0032",
    "Ran Sigma rule scan",
    "Exported events CSV",
    "Updated notification preferences",
    "Changed dashboard layout",
    "Created new Sigma rule",
    "Closed incident INC-0028",
    "Ran OSINT recon on target",
    "Updated threat intel feed",
    "Performed vulnerability scan",
    "Reviewed scan results",
    "Generated pentest report",
    "Added new log source",
    "Modified detection rule DR-15",
    "Triggered manual scan",
    "Reviewed threat map alerts",
    "Updated MITRE mappings",
    "Logged out",
  ];
  const now = Date.now();
  return actions.map((action, i) => ({
    id: `act-${i}`,
    action,
    ts: new Date(now - i * 3600000 * (1 + Math.random() * 2)).toISOString(),
  }));
}

/* ---------- page ---------- */

export default function ProfilePage() {
  const router = useRouter();
  const { user, status, refreshMe, logout } = useAuthStore();
  const [loggingOut, setLoggingOut] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    if (status === "idle") void refreshMe();
  }, [status, refreshMe]);

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

  const stats = useMemo(mockStats, []);
  const activities = useMemo(mockActivityLog, []);

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
    } finally {
      setRefreshing(false);
    }
  }

  const [showApiKey, setShowApiKey] = useState(false);
  const maskedKey = "cd-xxxx-xxxx-xxxx-" + "a1b2c3d4".slice(0, 4);
  const fullKey = "cd-9f3e-71a2-b8c4-a1b2c3d4";

  // Preferences state (UI only)
  const [notifEmail, setNotifEmail] = useState(true);
  const [notifBrowser, setNotifBrowser] = useState(true);
  const [notifCritical, setNotifCritical] = useState(true);
  const [defaultLayout, setDefaultLayout] = useState<"grid" | "list">("grid");
  const [timezone, setTimezone] = useState("UTC");

  // Password form (UI only)
  const [currentPw, setCurrentPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [pwMsg, setPwMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  function handlePasswordChange(e: React.FormEvent) {
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
    setPwMsg({ type: "ok", text: "Password updated successfully." });
    setCurrentPw("");
    setNewPw("");
    setConfirmPw("");
    setTimeout(() => setPwMsg(null), 4000);
  }

  const statItems = [
    { label: "Total Logins", value: stats.totalLogins, color: "text-cyan-glow" },
    { label: "Events Reviewed", value: stats.eventsReviewed, color: "text-blue-400" },
    { label: "Incidents Handled", value: stats.incidentsHandled, color: "text-amber-400" },
    { label: "Scans Performed", value: stats.scansPerformed, color: "text-emerald-400" },
  ];

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
      </StaggerItem>

      {/* Avatar + Info + Stats */}
      <StaggerItem>
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Avatar & identity */}
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

          {/* Stats grid */}
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
          </HudCard>
        </div>
      </StaggerItem>

      {/* Session info */}
      <StaggerItem>
        <HudCard title="Session Info">
          <div className="grid gap-4 sm:grid-cols-3">
            {[
              { label: "Current Session", value: "Active — 2h 14m", icon: "M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" },
              { label: "Last Login", value: new Date(Date.now() - 86400000).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }), icon: "M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 012.25-2.25h13.5A2.25 2.25 0 0121 7.5v11.25m-18 0A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75m-18 0v-7.5A2.25 2.25 0 015.25 9h13.5A2.25 2.25 0 0121 11.25v7.5" },
              { label: "IP Address", value: "192.168.1.42", icon: "M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" },
            ].map((item) => (
              <div key={item.label} className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-glow/15 bg-cyan-glow/5">
                  <svg className="h-4 w-4 text-cyan-glow/70" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={item.icon} />
                  </svg>
                </div>
                <div>
                  <p className="text-[10px] text-gray-600 uppercase tracking-wider">{item.label}</p>
                  <p className="text-xs text-gray-300 font-medium">{item.value}</p>
                </div>
              </div>
            ))}
          </div>
        </HudCard>
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
                className="mt-1 w-full rounded-md border border-cyan-glow/20 bg-cyan-glow/10 px-4 py-2 text-xs font-semibold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/20 hover:shadow-cyan-sm"
              >
                Update Password
              </button>
            </form>
          </HudCard>

          {/* 2FA & API Key */}
          <HudCard title="Security">
            <div className="space-y-5">
              {/* 2FA */}
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-300 font-medium">Two-Factor Authentication</p>
                  <p className="text-[10px] text-gray-600 mt-0.5">Protect your account with TOTP</p>
                </div>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-0.5 text-[10px] font-semibold text-amber-400 uppercase tracking-wider">
                  Disabled
                </span>
              </div>
              <button className="w-full rounded-md border border-cyan-glow/15 bg-space-mid/50 px-4 py-2 text-xs text-cyan-dim hover:bg-cyan-glow/10 transition-all uppercase tracking-wider font-medium">
                Enable 2FA
              </button>

              <div className="cyan-line" />

              {/* API Key */}
              <div>
                <p className="text-xs text-gray-300 font-medium mb-2">API Key</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 rounded-md border border-cyan-glow/10 bg-space-deep/80 px-3 py-2 text-[11px] text-cyan-dim font-mono">
                    {showApiKey ? fullKey : maskedKey}
                  </code>
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="rounded-md border border-cyan-glow/15 bg-space-mid/50 p-2 text-cyan-dim hover:bg-cyan-glow/10 transition-all"
                    title={showApiKey ? "Hide" : "Reveal"}
                  >
                    <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                      {showApiKey ? (
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.894 7.894L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                      ) : (
                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178zM15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      )}
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          </HudCard>
        </div>
      </StaggerItem>

      {/* Preferences */}
      <StaggerItem>
        <HudCard title="Preferences">
          <div className="grid gap-6 sm:grid-cols-3">
            {/* Notifications */}
            <div className="space-y-3">
              <p className="text-xs text-gray-300 font-medium mb-2">Notifications</p>
              {[
                { label: "Email alerts", checked: notifEmail, set: setNotifEmail },
                { label: "Browser notifications", checked: notifBrowser, set: setNotifBrowser },
                { label: "Critical only", checked: notifCritical, set: setNotifCritical },
              ].map((n) => (
                <label key={n.label} className="flex items-center gap-3 cursor-pointer group">
                  <div
                    onClick={() => n.set(!n.checked)}
                    className={`relative h-5 w-9 rounded-full transition-all ${n.checked ? "bg-cyan-glow/30 border-cyan-glow/40" : "bg-space-mid border-gray-700"} border`}
                  >
                    <div className={`absolute top-0.5 h-3.5 w-3.5 rounded-full transition-all ${n.checked ? "left-[18px] bg-cyan-glow shadow-cyan-sm" : "left-0.5 bg-gray-500"}`} />
                  </div>
                  <span className="text-[11px] text-gray-400 group-hover:text-gray-300 transition-colors">{n.label}</span>
                </label>
              ))}
            </div>

            {/* Layout */}
            <div>
              <p className="text-xs text-gray-300 font-medium mb-2">Default Layout</p>
              <div className="flex gap-2">
                {(["grid", "list"] as const).map((l) => (
                  <button
                    key={l}
                    onClick={() => setDefaultLayout(l)}
                    className={`flex-1 rounded-md border px-3 py-2 text-[11px] uppercase tracking-wider font-medium transition-all ${
                      defaultLayout === l
                        ? "border-cyan-glow/30 bg-cyan-glow/10 text-cyan-glow"
                        : "border-gray-700 bg-space-mid/40 text-gray-500 hover:border-cyan-glow/15 hover:text-gray-400"
                    }`}
                  >
                    {l}
                  </button>
                ))}
              </div>
            </div>

            {/* Timezone */}
            <div>
              <p className="text-xs text-gray-300 font-medium mb-2">Timezone</p>
              <select
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                className="w-full rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 outline-none focus:border-cyan-glow/40 focus:shadow-cyan-sm transition-all"
              >
                {["UTC", "Europe/Paris", "Europe/London", "America/New_York", "America/Los_Angeles", "Asia/Tokyo", "Asia/Shanghai", "Australia/Sydney"].map((tz) => (
                  <option key={tz} value={tz} className="bg-space-deep text-gray-300">{tz}</option>
                ))}
              </select>
            </div>
          </div>
        </HudCard>
      </StaggerItem>

      {/* Activity Log */}
      <StaggerItem>
        <HudCard title="Recent Activity">
          <div className="relative space-y-0">
            {/* Vertical timeline line */}
            <div className="absolute left-[7px] top-2 bottom-2 w-px bg-gradient-to-b from-cyan-glow/30 via-cyan-glow/10 to-transparent" />

            {activities.map((a, i) => (
              <motion.div
                key={a.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.03, duration: 0.3 }}
                className="relative flex items-start gap-3 py-2 pl-6"
              >
                {/* Dot */}
                <div className="absolute left-0 top-3 h-[14px] w-[14px] rounded-full border border-cyan-glow/30 bg-space-deep flex items-center justify-center">
                  <div className="h-1.5 w-1.5 rounded-full bg-cyan-glow/60" />
                </div>
                {/* Content */}
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-gray-300">{a.action}</p>
                  <p className="text-[10px] text-gray-600 mt-0.5">
                    {new Date(a.ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })}
                    {" "}
                    {new Date(a.ts).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </HudCard>
      </StaggerItem>
    </PageTransition>
  );
}
