"use client";

import { useState } from "react";
import { useRedteamEvents } from "@/hooks/useRedteamEvents";
import EngagementSelector from "./EngagementSelector";
import SessionList from "./SessionList";
import Terminal from "./Terminal";
import QuickCommands from "./QuickCommands";
import BeaconGraph from "./BeaconGraph";

export interface SliverSessionDTO {
  id: string;
  hostname?: string;
  username?: string;
  os?: string;
  arch?: string;
  transport?: string;
  remote_address?: string;
  active?: boolean;
  last_checkin?: string | null;
  first_contact?: string | null;
}

export default function OperatorConsole() {
  const [selectedEngagementId, setSelectedEngagementId] = useState<string | null>(
    null,
  );
  const [selectedSession, setSelectedSession] =
    useState<SliverSessionDTO | null>(null);
  const [terminalSendCmd, setTerminalSendCmd] = useState<
    ((cmd: string) => void) | null
  >(null);

  const { events, status, lastError, clear } = useRedteamEvents();

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col gap-3">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 rounded-md border border-cyan-glow/15 bg-space-dark/60 p-3 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="relative h-2 w-2">
            <div
              className={`absolute inset-0 rounded-full ${
                status === "open"
                  ? "bg-emerald-400"
                  : status === "connecting"
                    ? "bg-amber-400"
                    : "bg-red-500"
              }`}
            />
            {status === "open" && (
              <div className="absolute inset-0 animate-ping rounded-full bg-emerald-400 opacity-40" />
            )}
          </div>
          <div>
            <h1 className="hud-heading text-sm font-bold tracking-widest text-cyan-glow">
              OPERATOR CONSOLE
            </h1>
            <p className="text-[10px] tracking-wider text-cyan-glow/40">
              SLIVER C2 // {status.toUpperCase()}{" "}
              {lastError ? `// ${lastError}` : ""}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <EngagementSelector
            selectedId={selectedEngagementId}
            onChange={setSelectedEngagementId}
          />
          <button
            onClick={clear}
            className="rounded border border-cyan-glow/20 px-2 py-1 text-[10px] tracking-widest text-cyan-glow/70 hover:bg-cyan-glow/10"
            title="Clear event buffer"
          >
            CLEAR EVENTS ({events.length})
          </button>
        </div>
      </div>

      {/* 3-col grid */}
      <div className="grid flex-1 gap-3 overflow-hidden lg:grid-cols-[280px_1fr_360px]">
        {/* LEFT: sessions */}
        <div className="flex flex-col overflow-hidden rounded-md border border-cyan-glow/15 bg-space-dark/60">
          <div className="border-b border-cyan-glow/10 px-3 py-2">
            <p className="hud-label text-[10px] tracking-widest text-cyan-glow/60">
              SESSIONS
            </p>
          </div>
          <div className="flex-1 overflow-y-auto">
            <SessionList
              events={events}
              selectedId={selectedSession?.id ?? null}
              onSelect={setSelectedSession}
            />
          </div>
        </div>

        {/* MIDDLE: terminal + quick commands */}
        <div className="flex flex-col gap-3 overflow-hidden">
          <div className="flex-1 overflow-hidden rounded-md border border-cyan-glow/15 bg-black/80">
            <Terminal
              session={selectedSession}
              engagementId={selectedEngagementId}
              registerSend={setTerminalSendCmd}
            />
          </div>
          <div className="rounded-md border border-cyan-glow/15 bg-space-dark/60 p-3">
            <QuickCommands
              session={selectedSession}
              onRun={(cmd) => terminalSendCmd?.(cmd)}
              disabled={!selectedSession || !selectedEngagementId}
            />
          </div>
        </div>

        {/* RIGHT: graph */}
        <div className="flex flex-col overflow-hidden rounded-md border border-cyan-glow/15 bg-space-dark/60">
          <div className="border-b border-cyan-glow/10 px-3 py-2">
            <p className="hud-label text-[10px] tracking-widest text-cyan-glow/60">
              BEACON GRAPH
            </p>
          </div>
          <div className="flex-1 overflow-hidden">
            <BeaconGraph
              events={events}
              selectedId={selectedSession?.id ?? null}
              onSelect={setSelectedSession}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
