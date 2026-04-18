"use client";

import { useMemo } from "react";
import type { SliverSessionDTO } from "./OperatorConsole";

interface Props {
  session: SliverSessionDTO | null;
  onRun: (cmd: string) => void;
  disabled?: boolean;
}

interface PresetGroup {
  label: string;
  items: { label: string; cmd: string }[];
}

const COMMON_LINUX: PresetGroup[] = [
  {
    label: "Common",
    items: [
      { label: "whoami", cmd: "whoami" },
      { label: "id", cmd: "id" },
      { label: "hostname", cmd: "hostname" },
      { label: "pwd", cmd: "pwd" },
      { label: "uname -a", cmd: "uname -a" },
    ],
  },
  {
    label: "Discovery",
    items: [
      { label: "ifconfig", cmd: "ifconfig" },
      { label: "ip a", cmd: "ip a" },
      { label: "netstat -an", cmd: "netstat -an" },
      { label: "ps aux", cmd: "ps aux" },
      { label: "env", cmd: "env" },
    ],
  },
  {
    label: "Files",
    items: [
      { label: "ls -la", cmd: "ls -la" },
      { label: "cat /etc/passwd", cmd: "cat /etc/passwd" },
    ],
  },
];

const COMMON_WINDOWS: PresetGroup[] = [
  {
    label: "Common",
    items: [
      { label: "whoami", cmd: "whoami" },
      { label: "whoami /priv", cmd: "whoami /priv" },
      { label: "hostname", cmd: "hostname" },
      { label: "cd", cmd: "cd" },
      { label: "systeminfo", cmd: "systeminfo" },
    ],
  },
  {
    label: "Discovery",
    items: [
      { label: "ipconfig /all", cmd: "ipconfig /all" },
      { label: "netstat -an", cmd: "netstat -an" },
      { label: "tasklist", cmd: "tasklist" },
      { label: "net user", cmd: "net user" },
      { label: "net localgroup administrators", cmd: "net localgroup administrators" },
    ],
  },
  {
    label: "Files",
    items: [
      { label: "dir", cmd: "dir" },
      { label: "type C:\\Windows\\System32\\drivers\\etc\\hosts", cmd: "type C:\\Windows\\System32\\drivers\\etc\\hosts" },
    ],
  },
];

export default function QuickCommands({ session, onRun, disabled }: Props) {
  const groups = useMemo(() => {
    const os = (session?.os || "").toLowerCase();
    if (os.includes("win")) return COMMON_WINDOWS;
    return COMMON_LINUX;
  }, [session?.os]);

  return (
    <div>
      <div className="mb-2 flex items-center justify-between">
        <p className="hud-label text-[10px] tracking-widest text-cyan-glow/60">
          QUICK COMMANDS
        </p>
        <span className="text-[9px] tracking-wider text-cyan-glow/30">
          {(session?.os || "?").toUpperCase()}
        </span>
      </div>
      <div className="flex flex-wrap gap-3">
        {groups.map((g) => (
          <div key={g.label} className="flex flex-col gap-1">
            <span className="text-[9px] tracking-widest text-cyan-glow/40">
              {g.label}
            </span>
            <div className="flex flex-wrap gap-1">
              {g.items.map((it) => (
                <button
                  key={it.cmd}
                  disabled={disabled}
                  onClick={() => onRun(it.cmd)}
                  className="rounded border border-cyan-glow/15 bg-space-dark/50 px-2 py-0.5 font-mono text-[10px] text-cyan-glow/80 hover:border-cyan-glow/40 hover:bg-cyan-glow/10 disabled:cursor-not-allowed disabled:opacity-30"
                  title={it.cmd}
                >
                  {it.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
