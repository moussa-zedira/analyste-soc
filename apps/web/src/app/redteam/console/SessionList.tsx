"use client";

import { useEffect, useMemo, useState } from "react";
import type { SliverSessionDTO } from "./OperatorConsole";
import type { RedteamEvent } from "@/hooks/useRedteamEvents";

interface Props {
  events: RedteamEvent[];
  selectedId: string | null;
  onSelect: (s: SliverSessionDTO) => void;
}

function relativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  if (!Number.isFinite(d)) return iso;
  const sec = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function osBadge(os?: string): string {
  const o = (os || "").toLowerCase();
  if (o.includes("win")) return "WIN";
  if (o.includes("linux")) return "LIN";
  if (o.includes("darwin") || o.includes("mac")) return "MAC";
  return o ? o.slice(0, 3).toUpperCase() : "???";
}

export default function SessionList({ events, selectedId, onSelect }: Props) {
  const [sessions, setSessions] = useState<SliverSessionDTO[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const res = await fetch("/api/proxy/redteam/c2/sessions", {
          credentials: "include",
          cache: "no-store",
        });
        if (res.status === 503) {
          setError("Sliver C2 not configured. Set SLIVER_OPERATOR_CFG.");
          setSessions([]);
          return;
        }
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const data = (await res.json()) as SliverSessionDTO[];
        if (!cancelled) setSessions(Array.isArray(data) ? data : []);
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // Apply live events to local list
  useEffect(() => {
    if (!events.length) return;
    setSessions((prev) => {
      let next = prev;
      // les events sont en ordre LIFO (les plus recents en tete) — on
      // les applique du plus ancien au plus recent pour preserver
      // l'ordre causal.
      for (const ev of [...events].reverse()) {
        if (ev.type === "session.new") {
          const data = (ev.data as Record<string, unknown>) ?? {};
          const id = data.id as string | undefined;
          if (!id) continue;
          if (!next.some((s) => s.id === id)) {
            next = [data as unknown as SliverSessionDTO, ...next];
          }
        } else if (ev.type === "session.dead") {
          const id = (ev.data as Record<string, unknown>)?.id as
            | string
            | undefined;
          if (!id) continue;
          next = next.map((s) => (s.id === id ? { ...s, active: false } : s));
        }
      }
      return next;
    });
  }, [events]);

  const sorted = useMemo(() => {
    return [...sessions].sort((a, b) => {
      // active d'abord, puis last_checkin desc
      if (a.active !== b.active) return a.active ? -1 : 1;
      const ta = a.last_checkin ? new Date(a.last_checkin).getTime() : 0;
      const tb = b.last_checkin ? new Date(b.last_checkin).getTime() : 0;
      return tb - ta;
    });
  }, [sessions]);

  if (loading) {
    return (
      <div className="p-3 text-[11px] tracking-wider text-cyan-glow/40">
        Loading sessions...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-3 text-[11px] leading-relaxed text-amber-300/80">
        <div className="mb-1 font-bold tracking-widest">EMPTY</div>
        <div className="text-amber-300/60">{error}</div>
      </div>
    );
  }

  if (sorted.length === 0) {
    return (
      <div className="p-3 text-[11px] tracking-wider text-cyan-glow/40">
        No active sessions. Waiting for implants...
      </div>
    );
  }

  return (
    <ul className="space-y-1 p-2">
      {sorted.map((s) => {
        const active = !!s.active;
        const isSelected = selectedId === s.id;
        return (
          <li key={s.id}>
            <button
              onClick={() => onSelect(s)}
              className={`w-full rounded border px-2 py-2 text-left text-[11px] transition ${
                isSelected
                  ? "border-cyan-glow/60 bg-cyan-glow/10 text-cyan-glow"
                  : "border-cyan-glow/10 text-gray-400 hover:border-cyan-glow/30 hover:bg-cyan-glow/5"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 truncate">
                  <span
                    className={`inline-block h-1.5 w-1.5 rounded-full ${
                      active ? "bg-emerald-400" : "bg-gray-600"
                    }`}
                  />
                  <span className="truncate font-mono">
                    {s.hostname || (s.id ?? "").slice(0, 8)}
                  </span>
                </div>
                <span className="rounded bg-space-dark/80 px-1.5 py-0.5 text-[9px] tracking-widest text-cyan-glow/60">
                  {osBadge(s.os)}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[9px] text-gray-500">
                <span className="truncate">
                  {s.username || "?"}@{s.remote_address || "?"}
                </span>
                <span>{relativeTime(s.last_checkin)}</span>
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
