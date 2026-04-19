"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useSoundAlert, SoundToggleButton } from "./SoundAlert";

type NotifType = "incident" | "warning" | "info" | "success";

interface Notification {
  id: string;
  type: NotifType;
  title: string;
  message: string;
  timestamp: number;
  read: boolean;
}

const TYPE_CONFIG: Record<NotifType, { color: string; bg: string; icon: React.ReactNode }> = {
  incident: {
    color: "text-severity-critical",
    bg: "bg-severity-critical/10 border-severity-critical/30",
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  warning: {
    color: "text-severity-high",
    bg: "bg-severity-high/10 border-severity-high/30",
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M10.29 3.86l-8.6 14.86A1 1 0 002.54 20h16.93a1 1 0 00.85-1.47l-8.6-14.86a1 1 0 00-1.72 0z" />
      </svg>
    ),
  },
  info: {
    color: "text-cyan-glow",
    bg: "bg-cyan-glow/10 border-cyan-glow/30",
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
  success: {
    color: "text-green-400",
    bg: "bg-green-400/10 border-green-400/30",
    icon: (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
  },
};

const STORAGE_KEY = "cyberdef_notifications";
const MAX_NOTIFS = 100;

function loadNotifs(): Notification[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveNotifs(n: Notification[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(n.slice(0, MAX_NOTIFS)));
}

function timeAgo(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const [notifs, setNotifs] = useState<Notification[]>([]);
  const [filter, setFilter] = useState<NotifType | "all">("all");
  const [shake] = useState(false);
  const { muted, setMuted } = useSoundAlert();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setNotifs(loadNotifs());
  }, []);

  useEffect(() => {
    saveNotifs(notifs);
  }, [notifs]);

  // Listen for keyboard shortcut 'N'
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "n" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const tag = (e.target as HTMLElement).tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
        setOpen((p) => !p);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // WebSocket listener for real-time notifications.
  // NOTE: le backend n'expose pas d'endpoint /ws/events (les WS sont sur
  // /ws/live, /pentest/campaign/{id}/ws, /ws/redteam/c2/events, etc.).
  // On desactive l'auto-connect pour eviter une boucle de reconnection
  // bruyante et des erreurs console permanentes. Quand un endpoint SOC
  // generique sera disponible, reactiver ici en passant par
  // /api/auth/ws-token pour l'auth (voir useRedteamEvents).
  useEffect(() => {
    // no-op volontaire — pas d'endpoint /ws/events cote API.
    return;
  }, []);

  // Listen to the "toggle-notifications" event dispatched by KeyboardShortcuts (N key).
  useEffect(() => {
    const handler = () => setOpen((p) => !p);
    window.addEventListener("toggle-notifications", handler);
    return () => window.removeEventListener("toggle-notifications", handler);
  }, []);

  const unreadCount = notifs.filter((n) => !n.read).length;
  const filtered = filter === "all" ? notifs : notifs.filter((n) => n.type === filter);

  const markRead = useCallback((id: string) => {
    setNotifs((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const markAllRead = useCallback(() => {
    setNotifs((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const deleteNotif = useCallback((id: string) => {
    setNotifs((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifs([]);
  }, []);

  // Close on click outside
  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const filters: { label: string; value: NotifType | "all" }[] = [
    { label: "All", value: "all" },
    { label: "Incidents", value: "incident" },
    { label: "Warnings", value: "warning" },
    { label: "Info", value: "info" },
    { label: "Success", value: "success" },
  ];

  return (
    <div className="relative z-50" ref={panelRef}>
      {/* Bell Button */}
      <button
        onClick={() => setOpen((p) => !p)}
        className={`relative p-2 rounded-lg transition-all hover:bg-cyan-glow/10 ${shake ? "animate-[shake_0.5s_ease-in-out]" : ""}`}
        title="Notifications (N)"
      >
        <svg className="w-5 h-5 text-cyan-dim" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-bold text-white bg-severity-critical rounded-full border border-space-dark">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {/* Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, x: 20, scale: 0.95 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 20, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute right-0 top-12 w-96 max-h-[80vh] glass-panel flex flex-col shadow-cyan-lg"
          >
            {/* Header */}
            <div className="p-4 border-b border-cyan-glow/10">
              <div className="flex items-center justify-between mb-3">
                <h3 className="hud-heading text-sm text-cyan-glow">Notifications</h3>
                <div className="flex items-center gap-1">
                  <SoundToggleButton muted={muted} onToggle={() => setMuted(!muted)} />
                  <button
                    onClick={markAllRead}
                    className="text-[10px] hud-label text-cyan-muted hover:text-cyan-glow transition-colors px-2 py-1"
                  >
                    Mark all read
                  </button>
                  <button
                    onClick={clearAll}
                    className="text-[10px] hud-label text-severity-critical/60 hover:text-severity-critical transition-colors px-2 py-1"
                  >
                    Clear
                  </button>
                </div>
              </div>

              {/* Filters */}
              <div className="flex gap-1">
                {filters.map((f) => (
                  <button
                    key={f.value}
                    onClick={() => setFilter(f.value)}
                    className={`px-2 py-0.5 text-[10px] rounded font-mono transition-all ${
                      filter === f.value
                        ? "bg-cyan-glow/20 text-cyan-glow border border-cyan-glow/30"
                        : "text-cyan-muted hover:text-cyan-dim border border-transparent"
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto min-h-0">
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-cyan-muted">
                  <svg className="w-10 h-10 mb-3 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
                  </svg>
                  <span className="hud-label">No notifications</span>
                </div>
              ) : (
                filtered.map((notif, i) => {
                  const cfg = TYPE_CONFIG[notif.type];
                  return (
                    <motion.div
                      key={notif.id}
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.03 }}
                      onClick={() => markRead(notif.id)}
                      className={`relative px-4 py-3 border-b border-cyan-glow/5 cursor-pointer transition-colors hover:bg-cyan-glow/5 ${
                        !notif.read ? "bg-cyan-glow/[0.03]" : ""
                      }`}
                    >
                      {!notif.read && (
                        <div className="absolute left-1.5 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full bg-cyan-glow shadow-cyan-sm" />
                      )}
                      <div className="flex items-start gap-3 ml-2">
                        <div className={`mt-0.5 p-1 rounded ${cfg.bg} ${cfg.color}`}>{cfg.icon}</div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between">
                            <span className={`text-xs font-semibold ${cfg.color}`}>{notif.title}</span>
                            <button
                              onClick={(e) => { e.stopPropagation(); deleteNotif(notif.id); }}
                              className="text-cyan-muted/40 hover:text-severity-critical transition-colors ml-2"
                            >
                              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            </button>
                          </div>
                          <p className="text-[11px] text-cyan-muted mt-0.5 truncate">{notif.message}</p>
                          <span className="text-[9px] text-cyan-muted/50 mt-1 block">{timeAgo(notif.timestamp)}</span>
                        </div>
                      </div>
                    </motion.div>
                  );
                })
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Shake keyframe (injected once) */}
      <style jsx global>{`
        @keyframes shake {
          0%, 100% { transform: translateX(0); }
          20% { transform: translateX(-3px) rotate(-5deg); }
          40% { transform: translateX(3px) rotate(5deg); }
          60% { transform: translateX(-2px) rotate(-3deg); }
          80% { transform: translateX(2px) rotate(3deg); }
        }
      `}</style>
    </div>
  );
}
