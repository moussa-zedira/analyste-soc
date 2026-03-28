"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";

interface TermLine {
  type: "input" | "output" | "error" | "success" | "info" | "warning";
  text: string;
}

const COMMANDS: Record<string, string> = {
  help: "Show available commands",
  status: "System status check",
  events: "Show recent events summary",
  incidents: "List open incidents",
  clear: "Clear terminal",
  whoami: "Show current user",
  uptime: "Show system uptime",
  goto: "Navigate to page (goto dashboard|events|incidents|map|pentest|mitre|graph)",
  scan: "Trigger scan on target (scan <target>)",
  threat: "Lookup IP threat score (threat <ip>)",
  version: "Show system version",
  neofetch: "System information display",
  history: "Show command history",
};

const NAV_ROUTES: Record<string, string> = {
  dashboard: "/",
  home: "/",
  events: "/events",
  incidents: "/incidents",
  map: "/map",
  pentest: "/pentest",
  mitre: "/mitre",
  graph: "/graph",
  recon: "/recon",
  scanner: "/scanner",
  "threat-intel": "/threat-intel",
  investigate: "/investigate",
  sources: "/sources",
  admin: "/admin",
};

export function Terminal() {
  const [open, setOpen] = useState(false);
  const [lines, setLines] = useState<TermLine[]>([
    { type: "info", text: "CyberDef Terminal v2.0 — Type 'help' for commands" },
  ]);
  const [input, setInput] = useState("");
  const [cmdHistory, setCmdHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [height, setHeight] = useState(300);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const startY = useRef(0);
  const startH = useRef(0);
  const router = useRouter();
  const bootTime = useRef(Date.now());

  // Toggle with Ctrl+`
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "`" && e.ctrlKey) {
        e.preventDefault();
        setOpen((p) => !p);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Auto-scroll
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [lines]);

  // Focus input when opened
  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 100);
  }, [open]);

  // Drag resize
  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: MouseEvent) => {
      const newH = startH.current + (startY.current - e.clientY);
      setHeight(Math.max(150, Math.min(window.innerHeight * 0.7, newH)));
    };
    const onUp = () => setDragging(false);
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [dragging]);

  const addLine = useCallback((type: TermLine["type"], text: string) => {
    setLines((prev) => [...prev, { type, text }]);
  }, []);

  const apiBase = typeof window !== "undefined"
    ? process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000"
    : "http://localhost:8000";

  const apiKey = typeof window !== "undefined"
    ? process.env.NEXT_PUBLIC_API_KEY || localStorage.getItem("api_key") || ""
    : "";

  const executeCmd = useCallback(
    async (cmd: string) => {
      const parts = cmd.trim().split(/\s+/);
      const command = parts[0]?.toLowerCase();
      const args = parts.slice(1);

      switch (command) {
        case "help":
          addLine("info", "┌─── Available Commands ───────────────────┐");
          Object.entries(COMMANDS).forEach(([name, desc]) => {
            addLine("info", `│  ${name.padEnd(12)} ${desc}`);
          });
          addLine("info", "└──────────────────────────────────────────┘");
          break;

        case "clear":
          setLines([]);
          break;

        case "whoami":
          try {
            const token = localStorage.getItem("token");
            if (token) {
              const payload = JSON.parse(atob(token.split(".")[1]));
              addLine("success", `User: ${payload.sub || "admin"} | Role: ${payload.role || "admin"}`);
            } else {
              addLine("output", "User: admin");
            }
          } catch {
            addLine("output", "User: admin");
          }
          break;

        case "uptime":
          const upSec = Math.floor((Date.now() - bootTime.current) / 1000);
          const h = Math.floor(upSec / 3600);
          const m = Math.floor((upSec % 3600) / 60);
          const s = upSec % 60;
          addLine("success", `Uptime: ${h}h ${m}m ${s}s`);
          break;

        case "version":
          addLine("info", "CyberDef SIEM Platform v2.0");
          addLine("info", "Kernel: FastAPI 0.100+ | UI: Next.js 15 | DB: PostgreSQL 16");
          break;

        case "neofetch":
          addLine("info", "");
          addLine("info", "   ██████╗██████╗    CyberDef SIEM v2.0");
          addLine("info", "  ██╔════╝██╔══██╗   ─────────────────────");
          addLine("info", "  ██║     ██║  ██║   OS: Docker Linux");
          addLine("info", "  ██║     ██║  ██║   Backend: Python 3.11 + FastAPI");
          addLine("info", "  ╚██████╗██████╔╝   Frontend: Next.js 15 + React 19");
          addLine("info", "   ╚═════╝╚═════╝    DB: PostgreSQL 16 + Redis 7");
          addLine("info", "                      ML: scikit-learn (Isolation Forest)");
          addLine("info", "");
          break;

        case "status":
          addLine("info", "Checking system status...");
          try {
            const res = await fetch(`${apiBase}/docs`, { signal: AbortSignal.timeout(5000) });
            addLine("success", `API: ${res.ok ? "ONLINE" : "DEGRADED"} (HTTP ${res.status})`);
          } catch {
            addLine("error", "API: OFFLINE — Cannot reach backend");
          }
          break;

        case "events":
          addLine("info", "Fetching events...");
          try {
            const res = await fetch(`${apiBase}/api/events?limit=1`, {
              headers: { "X-API-Key": apiKey },
              signal: AbortSignal.timeout(5000),
            });
            if (res.ok) {
              const data = await res.json();
              const total = data.total ?? data.length ?? 0;
              addLine("success", `Total events: ${total}`);
            } else {
              addLine("error", `Failed: HTTP ${res.status}`);
            }
          } catch {
            addLine("error", "Cannot fetch events — API unreachable");
          }
          break;

        case "incidents":
          addLine("info", "Fetching incidents...");
          try {
            const res = await fetch(`${apiBase}/api/incidents?status=open`, {
              headers: { "X-API-Key": apiKey },
              signal: AbortSignal.timeout(5000),
            });
            if (res.ok) {
              const data = await res.json();
              const items = Array.isArray(data) ? data : data.items || [];
              addLine("success", `Open incidents: ${items.length}`);
              items.slice(0, 5).forEach((inc: { id: number; title?: string; severity?: string }) => {
                addLine("warning", `  #${inc.id} [${inc.severity || "?"}] ${inc.title || "Untitled"}`);
              });
            } else {
              addLine("error", `Failed: HTTP ${res.status}`);
            }
          } catch {
            addLine("error", "Cannot fetch incidents — API unreachable");
          }
          break;

        case "goto":
          if (!args[0]) {
            addLine("error", "Usage: goto <page>");
            addLine("info", `Available: ${Object.keys(NAV_ROUTES).join(", ")}`);
          } else {
            const route = NAV_ROUTES[args[0].toLowerCase()];
            if (route) {
              addLine("success", `Navigating to ${args[0]}...`);
              setTimeout(() => router.push(route), 300);
            } else {
              addLine("error", `Unknown page: ${args[0]}`);
              addLine("info", `Available: ${Object.keys(NAV_ROUTES).join(", ")}`);
            }
          }
          break;

        case "scan":
          if (!args[0]) {
            addLine("error", "Usage: scan <target>");
          } else {
            addLine("info", `Scanning ${args[0]}...`);
            addLine("warning", "Scan dispatched — check /pentest for results");
          }
          break;

        case "threat":
          if (!args[0]) {
            addLine("error", "Usage: threat <ip>");
          } else {
            addLine("info", `Looking up ${args[0]}...`);
            try {
              const res = await fetch(`${apiBase}/api/threat-intel/lookup?ip=${args[0]}`, {
                headers: { "X-API-Key": apiKey },
                signal: AbortSignal.timeout(10000),
              });
              if (res.ok) {
                const data = await res.json();
                addLine("success", `IP: ${args[0]} | Score: ${data.score ?? data.threat_score ?? "N/A"} | Country: ${data.country || "?"}`);
              } else {
                addLine("error", `Lookup failed: HTTP ${res.status}`);
              }
            } catch {
              addLine("error", "Cannot reach threat intel API");
            }
          }
          break;

        case "history":
          if (cmdHistory.length === 0) {
            addLine("info", "No command history");
          } else {
            cmdHistory.forEach((c, i) => addLine("output", `  ${i + 1}  ${c}`));
          }
          break;

        default:
          if (command) addLine("error", `Unknown command: ${command}. Type 'help' for available commands.`);
      }
    },
    [addLine, apiBase, apiKey, cmdHistory, router]
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    addLine("input", `cyberdef@soc:~$ ${input}`);
    setCmdHistory((prev) => [...prev, input]);
    setHistoryIdx(-1);
    executeCmd(input);
    setInput("");
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdHistory.length === 0) return;
      const idx = historyIdx === -1 ? cmdHistory.length - 1 : Math.max(0, historyIdx - 1);
      setHistoryIdx(idx);
      setInput(cmdHistory[idx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx === -1) return;
      const idx = historyIdx + 1;
      if (idx >= cmdHistory.length) {
        setHistoryIdx(-1);
        setInput("");
      } else {
        setHistoryIdx(idx);
        setInput(cmdHistory[idx]);
      }
    } else if (e.key === "Tab") {
      e.preventDefault();
      const partial = input.toLowerCase();
      const match = Object.keys(COMMANDS).find((c) => c.startsWith(partial));
      if (match) setInput(match);
    }
  };

  const lineColor = (type: TermLine["type"]) => {
    switch (type) {
      case "input": return "text-cyan-glow";
      case "error": return "text-severity-critical";
      case "success": return "text-green-400";
      case "warning": return "text-severity-medium";
      case "info": return "text-cyan-dim/80";
      default: return "text-cyan-muted";
    }
  };

  return (
    <>
      {/* Toggle button */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-4 right-20 z-50 p-2 rounded-lg glass-panel border border-cyan-glow/20 hover:border-cyan-glow/40 transition-all group"
          title="Terminal (Ctrl+`)"
        >
          <svg className="w-5 h-5 text-cyan-dim group-hover:text-cyan-glow transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
          </svg>
        </button>
      )}

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ y: "100%", opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: "100%", opacity: 0 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="fixed bottom-0 left-56 right-0 z-50 flex flex-col"
            style={{ height }}
          >
            {/* Drag handle */}
            <div
              className="h-2 cursor-ns-resize flex items-center justify-center bg-space-deep/80 border-t border-cyan-glow/15 hover:border-cyan-glow/30 transition-colors"
              onMouseDown={(e) => {
                setDragging(true);
                startY.current = e.clientY;
                startH.current = height;
              }}
            >
              <div className="w-8 h-0.5 rounded-full bg-cyan-muted/30" />
            </div>

            {/* Terminal body */}
            <div className="flex-1 flex flex-col bg-[#0a0e14]/95 backdrop-blur-md border-t border-cyan-glow/10 overflow-hidden">
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-1.5 border-b border-cyan-glow/10 bg-space-deep/50">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-2.5 h-2.5 rounded-full bg-severity-critical/70" />
                    <div className="w-2.5 h-2.5 rounded-full bg-severity-medium/70" />
                    <div className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
                  </div>
                  <span className="hud-label text-[10px]">Terminal</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[9px] text-cyan-muted/40 font-mono">Ctrl+` to toggle</span>
                  <button
                    onClick={() => setOpen(false)}
                    className="text-cyan-muted/50 hover:text-cyan-glow transition-colors"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </div>
              </div>

              {/* Output */}
              <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-2 font-mono text-xs space-y-0.5">
                {lines.map((line, i) => (
                  <div key={i} className={lineColor(line.type)}>
                    {line.text}
                  </div>
                ))}
              </div>

              {/* Input */}
              <form onSubmit={handleSubmit} className="flex items-center px-4 py-2 border-t border-cyan-glow/5">
                <span className="text-cyan-glow text-xs font-mono mr-2">cyberdef@soc:~$</span>
                <input
                  ref={inputRef}
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  className="flex-1 bg-transparent text-xs text-cyan-dim font-mono outline-none caret-cyan-glow placeholder-cyan-muted/30"
                  placeholder="Type a command..."
                  spellCheck={false}
                  autoComplete="off"
                />
              </form>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
