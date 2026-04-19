"use client";

import { useEffect, useRef, useState } from "react";
import type { SliverSessionDTO } from "./OperatorConsole";

interface Props {
  session: SliverSessionDTO | null;
  engagementId: string | null;
  registerSend: (fn: ((cmd: string) => void) | null) => void;
}

interface Line {
  id: number;
  kind: "cmd" | "out" | "err" | "info";
  text: string;
}

let lineIdCounter = 0;

function wsBase(): string {
  const env =
    (process.env.NEXT_PUBLIC_API_BASE_URL as string | undefined) ?? "";
  if (env) return env.replace(/^http/, "ws");
  if (typeof window !== "undefined") {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${window.location.hostname}:8000`;
  }
  return "ws://localhost:8000";
}

export default function Terminal({ session, engagementId, registerSend }: Props) {
  const [lines, setLines] = useState<Line[]>([]);
  const [input, setInput] = useState("");
  const [wsStatus, setWsStatus] = useState<
    "idle" | "connecting" | "open" | "closed" | "error"
  >("idle");
  const [errMsg, setErrMsg] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  function addLine(kind: Line["kind"], text: string) {
    lineIdCounter += 1;
    setLines((prev) => [...prev.slice(-499), { id: lineIdCounter, kind, text }]);
  }

  // Connexion WS quand session + engagement OK
  useEffect(() => {
    setLines([]);
    setErrMsg(null);
    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch {
        /* noop */
      }
      wsRef.current = null;
    }
    registerSend(null);
    if (!session || !engagementId) return;

    let stopped = false;
    setWsStatus("connecting");

    (async () => {
      // Recupere token via la route Next
      let token: string | null = null;
      try {
        const res = await fetch("/api/auth/ws-token", {
          credentials: "include",
          cache: "no-store",
        });
        if (res.ok) {
          const j = await res.json();
          if (typeof j?.token === "string") token = j.token;
        }
      } catch {
        /* fall through */
      }
      if (!token) {
        setWsStatus("error");
        setErrMsg("Auth token unavailable");
        return;
      }

      const url =
        wsBase() +
        "/ws/redteam/c2/sessions/" +
        encodeURIComponent(session.id) +
        "/terminal?token=" +
        encodeURIComponent(token) +
        "&engagement_id=" +
        encodeURIComponent(engagementId);

      let ws: WebSocket;
      try {
        ws = new WebSocket(url);
      } catch (e) {
        setWsStatus("error");
        setErrMsg(String(e));
        return;
      }
      if (stopped) {
        ws.close();
        return;
      }
      wsRef.current = ws;

      ws.onopen = () => {
        setWsStatus("open");
        addLine("info", `--- connected to ${session.hostname || session.id} ---`);
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === "ping") return;
          if (msg.type === "ready") {
            // ack — on a deja log open
            return;
          }
          if (msg.type === "exec_start") {
            addLine("cmd", `$ ${msg.command}`);
            return;
          }
          if (msg.type === "exec_result") {
            const out = (msg.output ?? "") as string;
            if (out.trim()) addLine("out", out);
            return;
          }
          if (msg.type === "exec_error") {
            addLine("err", `! ${msg.detail || "exec error"}`);
            return;
          }
          if (msg.type === "error") {
            const detail = msg.detail || "error";
            addLine("err", `! ${detail}`);
            setErrMsg(String(detail));
            return;
          }
        } catch {
          // ignore malformed
        }
      };
      ws.onerror = () => {
        setWsStatus("error");
        setErrMsg("websocket error");
      };
      ws.onclose = () => {
        setWsStatus("closed");
        wsRef.current = null;
      };

      registerSend((cmd: string) => {
        const sock = wsRef.current;
        if (!sock || sock.readyState !== WebSocket.OPEN) return;
        sock.send(JSON.stringify({ command: cmd }));
      });
    })();

    return () => {
      stopped = true;
      registerSend(null);
      const sock = wsRef.current;
      if (sock) {
        try {
          sock.close();
        } catch {
          /* noop */
        }
      }
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.id, engagementId]);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  function submit() {
    const cmd = input.trim();
    if (!cmd) return;
    const sock = wsRef.current;
    if (!sock || sock.readyState !== WebSocket.OPEN) {
      addLine("err", "! not connected");
      return;
    }
    sock.send(JSON.stringify({ command: cmd }));
    setInput("");
  }

  if (!session) {
    return (
      <div className="flex h-full items-center justify-center text-[11px] tracking-widest text-cyan-glow/30">
        SELECT A SESSION TO OPEN TERMINAL
      </div>
    );
  }

  if (!engagementId) {
    return (
      <div className="flex h-full items-center justify-center text-[11px] tracking-widest text-amber-300/60">
        SELECT AN ENGAGEMENT FIRST
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-cyan-glow/10 px-3 py-1.5 text-[10px] tracking-widest">
        <span className="text-cyan-glow/70">
          TERMINAL // {session.hostname || (session.id ?? "").slice(0, 8)}
        </span>
        <span
          className={`${
            wsStatus === "open"
              ? "text-emerald-400"
              : wsStatus === "connecting"
                ? "text-amber-400"
                : "text-red-400"
          }`}
        >
          {(wsStatus ?? "").toUpperCase()}
          {errMsg ? ` // ${errMsg}` : ""}
        </span>
      </div>
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-3 py-2 font-mono text-[12px] leading-snug"
        style={{ background: "rgba(0,0,0,0.85)" }}
      >
        {lines.length === 0 ? (
          <p className="text-cyan-glow/30">
            // type a command and press Enter to execute
          </p>
        ) : (
          lines.map((l) => (
            <pre
              key={l.id}
              className={`whitespace-pre-wrap break-words ${
                l.kind === "cmd"
                  ? "text-cyan-glow"
                  : l.kind === "err"
                    ? "text-red-400"
                    : l.kind === "info"
                      ? "text-cyan-glow/40"
                      : "text-gray-200"
              }`}
            >
              {l.text}
            </pre>
          ))
        )}
      </div>
      <div className="flex items-center gap-2 border-t border-cyan-glow/10 bg-space-dark/80 px-2 py-1.5">
        <span className="font-mono text-cyan-glow/60">$</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              submit();
            }
          }}
          placeholder={
            wsStatus === "open" ? "command..." : "waiting connection..."
          }
          className="flex-1 bg-transparent font-mono text-xs text-gray-100 outline-none placeholder:text-gray-600"
          disabled={wsStatus !== "open"}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          onClick={submit}
          disabled={wsStatus !== "open" || !input.trim()}
          className="rounded border border-cyan-glow/30 px-2 py-0.5 text-[10px] tracking-widest text-cyan-glow hover:bg-cyan-glow/10 disabled:cursor-not-allowed disabled:opacity-30"
        >
          RUN
        </button>
      </div>
    </div>
  );
}
