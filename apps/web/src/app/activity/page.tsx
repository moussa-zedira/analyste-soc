"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { PageTransition, StaggerItem } from "@/components/PageTransition";

/* ---------- types ---------- */

type ActivityType = "login" | "incident" | "scan" | "rule" | "config" | "export";

interface ActivityEntry {
  id: string;
  type: ActivityType;
  user: string;
  action: string;
  resource: string;
  ts: string;
}

/* ---------- constants ---------- */

const TYPE_META: Record<ActivityType, { label: string; color: string; bgColor: string; icon: string }> = {
  login:    { label: "Login",     color: "text-emerald-400", bgColor: "bg-emerald-400/10 border-emerald-400/25", icon: "M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" },
  incident: { label: "Incident",  color: "text-red-400",     bgColor: "bg-red-400/10 border-red-400/25",     icon: "M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" },
  scan:     { label: "Scan",      color: "text-blue-400",    bgColor: "bg-blue-400/10 border-blue-400/25",    icon: "M12 2a10 10 0 1010 10A10 10 0 0012 2zm0 4a1.5 1.5 0 11-1.5 1.5A1.5 1.5 0 0112 6zm-1 4h2v7h-2z M12 2l0 4m0 12l0 4m10-10l-4 0m-12 0l-4 0" },
  rule:     { label: "Rule",      color: "text-amber-400",   bgColor: "bg-amber-400/10 border-amber-400/25",  icon: "M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" },
  config:   { label: "Config",    color: "text-purple-400",  bgColor: "bg-purple-400/10 border-purple-400/25", icon: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z" },
  export:   { label: "Export",    color: "text-cyan-400",    bgColor: "bg-cyan-400/10 border-cyan-400/25",    icon: "M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" },
};

const ALL_TYPES: ActivityType[] = ["login", "incident", "scan", "rule", "config", "export"];
const USERS = ["admin", "operator", "analyst", "scanner-svc", "siem-agent"];

/* ---------- mock data ---------- */

function generateActivities(count: number, existingCount: number): ActivityEntry[] {
  const templates: Record<ActivityType, { actions: string[]; resources: string[] }> = {
    login:    { actions: ["Logged in successfully", "Logged out", "Failed login attempt", "Session refreshed"], resources: ["Web UI", "API /auth/login", "SSH Gateway", "VPN Portal"] },
    incident: { actions: ["Created incident", "Acknowledged incident", "Closed incident", "Escalated incident"], resources: ["INC-0032", "INC-0045", "INC-0051", "INC-0067", "INC-0078"] },
    scan:     { actions: ["Completed vulnerability scan", "Started network scan", "Finished port scan", "Ran deep scan"], resources: ["192.168.1.0/24", "10.0.0.0/16", "target.local", "dmz-segment"] },
    rule:     { actions: ["Sigma rule triggered", "Detection rule matched", "Correlation rule fired", "Threshold alert triggered"], resources: ["DR-15 Brute Force", "DR-22 Lateral Movement", "DR-08 Data Exfil", "DR-31 Privilege Escalation"] },
    config:   { actions: ["Updated system config", "Modified log source", "Changed retention policy", "Updated API key"], resources: ["syslog-collector", "waf-module", "retention-30d", "api-key-rotation"] },
    export:   { actions: ["Exported events CSV", "Generated PDF report", "Exported incident data", "Downloaded scan results"], resources: ["events_2026-03.csv", "pentest_report_v2.pdf", "incidents_q1.json", "scan_results_latest.xlsx"] },
  };

  const now = Date.now();
  const entries: ActivityEntry[] = [];

  for (let i = 0; i < count; i++) {
    const idx = existingCount + i;
    const type = ALL_TYPES[Math.floor(Math.random() * ALL_TYPES.length)];
    const t = templates[type];
    entries.push({
      id: `activity-${idx}`,
      type,
      user: USERS[Math.floor(Math.random() * USERS.length)],
      action: t.actions[Math.floor(Math.random() * t.actions.length)],
      resource: t.resources[Math.floor(Math.random() * t.resources.length)],
      ts: new Date(now - idx * 900000 * (0.5 + Math.random())).toISOString(),
    });
  }
  return entries.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
}

/* ---------- helpers ---------- */

function groupByDate(entries: ActivityEntry[]): { label: string; items: ActivityEntry[] }[] {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  const weekAgo = new Date(today.getTime() - 7 * 86400000);

  const groups: Record<string, ActivityEntry[]> = { Today: [], Yesterday: [], "This Week": [], Older: [] };

  for (const e of entries) {
    const d = new Date(e.ts);
    if (d >= today) groups["Today"].push(e);
    else if (d >= yesterday) groups["Yesterday"].push(e);
    else if (d >= weekAgo) groups["This Week"].push(e);
    else groups["Older"].push(e);
  }

  return Object.entries(groups)
    .filter(([, items]) => items.length > 0)
    .map(([label, items]) => ({ label, items }));
}

/* ---------- skeleton ---------- */

function Skeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      {[1, 2, 3].map((g) => (
        <div key={g}>
          <div className="h-4 w-24 skeleton mb-4 rounded" />
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-start gap-4 py-3 pl-8">
              <div className="h-8 w-8 skeleton rounded-full" />
              <div className="flex-1 space-y-2">
                <div className="h-3 w-3/4 skeleton rounded" />
                <div className="h-2 w-1/2 skeleton rounded" />
              </div>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

/* ---------- page ---------- */

export default function ActivityPage() {
  const [activities, setActivities] = useState<ActivityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const PAGE_SIZE = 30;

  // Filters
  const [typeFilter, setTypeFilter] = useState<ActivityType | "all">("all");
  const [userFilter, setUserFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  // Initial load
  useEffect(() => {
    const timer = setTimeout(() => {
      setActivities(generateActivities(PAGE_SIZE, 0));
      setLoading(false);
    }, 600);
    return () => clearTimeout(timer);
  }, []);

  // Polling for new entries every 15s
  useEffect(() => {
    const interval = setInterval(() => {
      setActivities((prev) => {
        const newEntry = generateActivities(1, prev.length + 1000);
        // Only prepend if we aren't filtered
        return [...newEntry, ...prev];
      });
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  // Load more
  const handleLoadMore = useCallback(() => {
    setLoadingMore(true);
    setTimeout(() => {
      setActivities((prev) => [...prev, ...generateActivities(PAGE_SIZE, prev.length)]);
      setLoadingMore(false);
    }, 500);
  }, []);

  // Filter activities
  const filtered = useMemo(() => {
    let result = activities;
    if (typeFilter !== "all") result = result.filter((a) => a.type === typeFilter);
    if (userFilter !== "all") result = result.filter((a) => a.user === userFilter);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(
        (a) =>
          a.action.toLowerCase().includes(q) ||
          a.resource.toLowerCase().includes(q) ||
          a.user.toLowerCase().includes(q)
      );
    }
    if (dateFrom) {
      const from = new Date(dateFrom).getTime();
      result = result.filter((a) => new Date(a.ts).getTime() >= from);
    }
    if (dateTo) {
      const to = new Date(dateTo).getTime() + 86400000;
      result = result.filter((a) => new Date(a.ts).getTime() <= to);
    }
    return result;
  }, [activities, typeFilter, userFilter, search, dateFrom, dateTo]);

  const groups = useMemo(() => groupByDate(filtered), [filtered]);

  // Counts by type
  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of activities) counts[a.type] = (counts[a.type] || 0) + 1;
    return counts;
  }, [activities]);

  const inputClass =
    "rounded-md border border-cyan-glow/15 bg-space-deep/60 px-3 py-2 text-xs text-gray-300 placeholder-gray-600 outline-none focus:border-cyan-glow/40 focus:shadow-cyan-sm transition-all";

  return (
    <PageTransition className="min-h-screen p-6 lg:p-8 space-y-6">
      {/* Header */}
      <StaggerItem>
        <div className="flex items-center gap-3 mb-2">
          <svg className="h-5 w-5 text-cyan-glow" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h1 className="hud-heading text-lg font-bold tracking-widest text-cyan-glow">Activity Timeline</h1>
          <div className="ml-auto flex items-center gap-2">
            <div className="relative h-2 w-2">
              <div className="h-2 w-2 rounded-full bg-emerald-400" />
              <div className="absolute inset-0 h-2 w-2 animate-ping rounded-full bg-emerald-400 opacity-40" />
            </div>
            <span className="text-[10px] tracking-wider text-emerald-400/70">LIVE</span>
          </div>
        </div>
        <div className="cyan-line w-full" />
      </StaggerItem>

      {/* Type filter pills */}
      <StaggerItem>
        <div className="glass-panel hud-corners p-4">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setTypeFilter("all")}
              className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-wider transition-all ${
                typeFilter === "all"
                  ? "border-cyan-glow/30 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700 text-gray-500 hover:border-cyan-glow/15 hover:text-gray-400"
              }`}
            >
              All ({activities.length})
            </button>
            {ALL_TYPES.map((t) => {
              const meta = TYPE_META[t];
              return (
                <button
                  key={t}
                  onClick={() => setTypeFilter(typeFilter === t ? "all" : t)}
                  className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                    typeFilter === t
                      ? `${meta.bgColor} ${meta.color}`
                      : "border-gray-700 text-gray-500 hover:border-cyan-glow/15 hover:text-gray-400"
                  }`}
                >
                  <svg className="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d={meta.icon} />
                  </svg>
                  {meta.label} ({typeCounts[t] || 0})
                </button>
              );
            })}
          </div>
        </div>
      </StaggerItem>

      {/* Filters bar */}
      <StaggerItem>
        <div className="glass-panel hud-corners p-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {/* Search */}
            <div className="relative">
              <svg className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
              </svg>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search activities..."
                className={`${inputClass} w-full pl-9`}
              />
            </div>

            {/* User filter */}
            <select
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              className={`${inputClass} w-full`}
            >
              <option value="all" className="bg-space-deep">All Users</option>
              {USERS.map((u) => (
                <option key={u} value={u} className="bg-space-deep">{u}</option>
              ))}
            </select>

            {/* Date from */}
            <input
              type="date"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              className={`${inputClass} w-full`}
              placeholder="From"
            />

            {/* Date to */}
            <input
              type="date"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              className={`${inputClass} w-full`}
              placeholder="To"
            />
          </div>
        </div>
      </StaggerItem>

      {/* Timeline */}
      <StaggerItem>
        {loading ? (
          <div className="glass-panel hud-corners p-6">
            <Skeleton />
          </div>
        ) : filtered.length === 0 ? (
          /* Empty state */
          <div className="glass-panel hud-corners p-12 text-center">
            <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full border border-cyan-glow/15 bg-cyan-glow/5">
              <svg className="h-8 w-8 text-cyan-glow/30" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <p className="hud-heading text-sm text-cyan-glow/50 tracking-wider">No activities found</p>
            <p className="mt-1 text-xs text-gray-600">Adjust your filters or wait for new events</p>
          </div>
        ) : (
          <div className="space-y-6">
            {groups.map((group) => (
              <div key={group.label} className="glass-panel hud-corners p-5">
                {/* Group header */}
                <div className="flex items-center gap-3 mb-4">
                  <h2 className="hud-heading text-xs font-semibold tracking-widest text-cyan-glow/60">{group.label}</h2>
                  <div className="flex-1 cyan-line" />
                  <span className="text-[10px] text-gray-600">{group.items.length} events</span>
                </div>

                {/* Timeline */}
                <div className="relative">
                  {/* Vertical line */}
                  <div className="absolute left-[19px] top-0 bottom-0 w-px bg-gradient-to-b from-cyan-glow/20 via-cyan-glow/10 to-transparent" />

                  <AnimatePresence>
                    {group.items.map((entry, i) => {
                      const meta = TYPE_META[entry.type];
                      return (
                        <motion.div
                          key={entry.id}
                          initial={{ opacity: 0, x: -15 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: 15 }}
                          transition={{ delay: i * 0.02, duration: 0.3 }}
                          className="relative flex items-start gap-4 py-3 pl-10 group"
                        >
                          {/* Timeline node */}
                          <div className={`absolute left-[11px] top-4 flex h-[18px] w-[18px] items-center justify-center rounded-full border ${meta.bgColor}`}>
                            <svg className={`h-2.5 w-2.5 ${meta.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d={meta.icon} />
                            </svg>
                          </div>

                          {/* Content */}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={`text-[10px] font-semibold uppercase tracking-wider ${meta.color}`}>{meta.label}</span>
                              <span className="text-[10px] text-gray-600">by</span>
                              <span className="text-[11px] text-cyan-dim font-medium">{entry.user}</span>
                              <span className="ml-auto text-[10px] text-gray-600 tabular-nums whitespace-nowrap">
                                {new Date(entry.ts).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                              </span>
                            </div>
                            <p className="text-xs text-gray-300 mt-0.5">{entry.action}</p>
                            <p className="text-[10px] text-gray-500 mt-0.5 flex items-center gap-1">
                              <svg className="h-3 w-3 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
                              </svg>
                              {entry.resource}
                            </p>
                          </div>
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </div>
              </div>
            ))}

            {/* Load more */}
            <div className="flex justify-center">
              <button
                onClick={handleLoadMore}
                disabled={loadingMore}
                className="rounded-md border border-cyan-glow/20 bg-cyan-glow/5 px-6 py-2.5 text-xs font-semibold uppercase tracking-wider text-cyan-glow transition-all hover:bg-cyan-glow/15 hover:shadow-cyan-sm disabled:opacity-50"
              >
                {loadingMore ? (
                  <span className="flex items-center gap-2">
                    <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                    </svg>
                    Loading...
                  </span>
                ) : (
                  "Load More"
                )}
              </button>
            </div>
          </div>
        )}
      </StaggerItem>
    </PageTransition>
  );
}
