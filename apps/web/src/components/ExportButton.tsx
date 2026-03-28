"use client";

import React, { useState, useRef, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";

/* -------------------------------------------------------------------------- */
/*  ExportButton – universal export dropdown (PDF / CSV / JSON / Markdown)    */
/* -------------------------------------------------------------------------- */

export interface ExportButtonProps {
  /** Array of objects to export */
  data: Record<string, unknown>[];
  /** Base filename (no extension) */
  filename?: string;
  /** Report title (used in markdown / PDF header) */
  title?: string;
}

/* ---- Helpers ------------------------------------------------------------- */

function triggerDownload(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function toCsv(data: Record<string, unknown>[]): string {
  if (!data.length) return "";
  const keys = Object.keys(data[0]);
  const escape = (v: unknown) => {
    const s = String(v ?? "");
    return s.includes(",") || s.includes('"') || s.includes("\n")
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };
  const header = keys.map(escape).join(",");
  const rows = data.map((r) => keys.map((k) => escape(r[k])).join(","));
  return [header, ...rows].join("\n");
}

function toMarkdown(data: Record<string, unknown>[], title: string): string {
  if (!data.length) return `# ${title}\n\nNo data.\n`;
  const keys = Object.keys(data[0]);
  const header = `| ${keys.join(" | ")} |`;
  const sep = `| ${keys.map(() => "---").join(" | ")} |`;
  const rows = data.map((r) => `| ${keys.map((k) => String(r[k] ?? "")).join(" | ")} |`).join("\n");
  return `# ${title}\n\n${header}\n${sep}\n${rows}\n`;
}

function formatDate(): string {
  return new Date().toISOString().slice(0, 10);
}

/* ---- Icons --------------------------------------------------------------- */

const Icons = {
  pdf: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
    </svg>
  ),
  csv: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  ),
  json: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
    </svg>
  ),
  markdown: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h7" />
    </svg>
  ),
  export: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
    </svg>
  ),
  check: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  ),
};

/* ---- Component ----------------------------------------------------------- */

type ExportFormat = "pdf" | "csv" | "json" | "markdown";

interface ExportOption {
  id: ExportFormat;
  label: string;
  icon: React.ReactNode;
  ext: string;
}

const OPTIONS: ExportOption[] = [
  { id: "pdf", label: "PDF (Print)", icon: Icons.pdf, ext: "pdf" },
  { id: "csv", label: "CSV", icon: Icons.csv, ext: "csv" },
  { id: "json", label: "JSON", icon: Icons.json, ext: "json" },
  { id: "markdown", label: "Markdown", icon: Icons.markdown, ext: "md" },
];

export default function ExportButton({ data, filename = "report", title = "CyberDef Report" }: ExportButtonProps) {
  const [open, setOpen] = useState(false);
  const [downloading, setDownloading] = useState<ExportFormat | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  const handleExport = useCallback(
    (format: ExportFormat) => {
      setDownloading(format);
      const base = `${filename}_${formatDate()}`;

      setTimeout(() => {
        switch (format) {
          case "csv": {
            const csv = toCsv(data);
            triggerDownload(new Blob([csv], { type: "text/csv;charset=utf-8" }), `${base}.csv`);
            break;
          }
          case "json": {
            const json = JSON.stringify(data, null, 2);
            triggerDownload(new Blob([json], { type: "application/json" }), `${base}.json`);
            break;
          }
          case "markdown": {
            const md = toMarkdown(data, title);
            triggerDownload(new Blob([md], { type: "text/markdown" }), `${base}.md`);
            break;
          }
          case "pdf": {
            // Build and print a report page
            const keys = data.length ? Object.keys(data[0]) : [];
            const th = keys.map((k) => `<th style="padding:6px 10px;border:1px solid #cbd5e1;background:#f1f5f9;font-size:11px;text-transform:uppercase;">${k}</th>`).join("");
            const rows = data.map((r) =>
              `<tr>${keys.map((k) => `<td style="padding:5px 10px;border:1px solid #e2e8f0;font-size:11px;">${String(r[k] ?? "")}</td>`).join("")}</tr>`
            ).join("");
            const w = window.open("", "_blank", "width=900,height=700");
            if (w) {
              w.document.write(`<!DOCTYPE html><html><head><title>${title}</title>
<style>
@page { size:A4; margin:20mm 15mm 25mm 15mm; }
body { font-family:'Segoe UI',Arial,sans-serif; color:#1e293b; font-size:12px; }
table { width:100%; border-collapse:collapse; }
.hdr { border-bottom:3px solid #0ea5e9; padding-bottom:10px; margin-bottom:14px; }
.logo { font-size:24px; font-weight:800; color:#0ea5e9; }
h1 { font-size:20px; margin:2px 0; }
.meta { font-size:10px; color:#64748b; }
</style></head><body>
<div class="hdr"><div class="logo">CYBERDEF</div><h1>${title}</h1><div class="meta">Generated: ${new Date().toLocaleString()} | Rows: ${data.length}</div></div>
<table><thead><tr>${th}</tr></thead><tbody>${rows}</tbody></table>
</body></html>`);
              w.document.close();
              setTimeout(() => { w.focus(); w.print(); w.close(); }, 400);
            }
            break;
          }
        }
        // Show checkmark briefly then reset
        setTimeout(() => {
          setDownloading(null);
          setOpen(false);
        }, 600);
      }, 300);
    },
    [data, filename, title],
  );

  return (
    <div ref={menuRef} className="relative inline-block">
      <button
        onClick={() => setOpen((p) => !p)}
        className="flex items-center gap-2 px-4 py-2 text-xs font-semibold tracking-wider uppercase rounded glass-panel border border-cyan-glow/20 text-cyan-glow hover:border-cyan-glow/50 hover:shadow-cyan-md transition-all duration-200"
      >
        {Icons.export}
        Export
        <svg className={`w-3 h-3 transition-transform duration-200 ${open ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.95 }}
            transition={{ duration: 0.18, ease: "easeOut" }}
            className="absolute right-0 z-50 mt-2 w-52 glass-panel border border-cyan-glow/20 rounded-lg overflow-hidden shadow-cyan-lg"
          >
            {OPTIONS.map((opt) => {
              const isActive = downloading === opt.id;
              return (
                <button
                  key={opt.id}
                  onClick={() => handleExport(opt.id)}
                  disabled={!!downloading}
                  className="flex items-center gap-3 w-full px-4 py-2.5 text-left text-xs tracking-wide text-slate-300 hover:text-cyan-glow hover:bg-cyan-glow/5 transition-colors disabled:opacity-50"
                >
                  {isActive ? (
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      className="text-emerald-400"
                    >
                      {Icons.check}
                    </motion.div>
                  ) : (
                    <span className="text-cyan-dim">{opt.icon}</span>
                  )}
                  <span className="flex-1 font-medium">{opt.label}</span>
                  {isActive && (
                    <motion.div
                      className="w-4 h-4 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full"
                      animate={{ rotate: 360 }}
                      transition={{ duration: 0.8, repeat: Infinity, ease: "linear" }}
                    />
                  )}
                </button>
              );
            })}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
