"use client";

import React, { useRef, useCallback } from "react";

/* -------------------------------------------------------------------------- */
/*  ExportPDF – print-optimized report generator using window.print()         */
/* -------------------------------------------------------------------------- */

export interface ExportPDFProps {
  title: string;
  subtitle?: string;
  data?: Record<string, unknown>[] | null;
  children?: React.ReactNode;
  generatedBy?: string;
}

/** Formats the current date as "28 Mar 2026 – 14:35 UTC" */
function formatDate(): string {
  const d = new Date();
  return d.toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }) + " – " + d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZoneName: "short" });
}

/** Severity colour for print (plain, high-contrast) */
function severityPrintColor(val: string): string {
  const v = String(val).toLowerCase();
  if (v === "critical") return "#dc2626";
  if (v === "high") return "#ea580c";
  if (v === "medium") return "#ca8a04";
  if (v === "low") return "#2563eb";
  return "#1e293b";
}

/** Render data as an HTML table string */
function dataToTable(data: Record<string, unknown>[]): string {
  if (!data.length) return "<p>No data.</p>";
  const keys = Object.keys(data[0]);
  const th = keys.map((k) => `<th style="padding:6px 10px;border:1px solid #cbd5e1;background:#f1f5f9;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;">${k}</th>`).join("");
  const rows = data
    .map((row) => {
      const tds = keys
        .map((k) => {
          const val = String(row[k] ?? "");
          const isSeverity = k.toLowerCase().includes("severity") || k.toLowerCase().includes("level");
          const style = isSeverity
            ? `color:${severityPrintColor(val)};font-weight:600;`
            : "";
          return `<td style="padding:5px 10px;border:1px solid #e2e8f0;font-size:11px;${style}">${val}</td>`;
        })
        .join("");
      return `<tr>${tds}</tr>`;
    })
    .join("");
  return `<table style="width:100%;border-collapse:collapse;margin:16px 0;">\n<thead><tr>${th}</tr></thead>\n<tbody>${rows}</tbody>\n</table>`;
}

/** Copies report content as markdown */
function dataToMarkdown(title: string, data: Record<string, unknown>[]): string {
  if (!data.length) return `# ${title}\n\nNo data.\n`;
  const keys = Object.keys(data[0]);
  const header = `| ${keys.join(" | ")} |`;
  const sep = `| ${keys.map(() => "---").join(" | ")} |`;
  const rows = data.map((r) => `| ${keys.map((k) => String(r[k] ?? "")).join(" | ")} |`).join("\n");
  return `# ${title}\n\nGenerated: ${formatDate()}\n\n${header}\n${sep}\n${rows}\n`;
}

export default function ExportPDF({ title, subtitle, data, children, generatedBy = "CyberDef Platform" }: ExportPDFProps) {
  const printRef = useRef<HTMLDivElement>(null);

  const handlePrint = useCallback(() => {
    if (!printRef.current) return;
    const content = printRef.current.innerHTML;

    const printWindow = window.open("", "_blank", "width=900,height=700");
    if (!printWindow) return;

    printWindow.document.write(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>${title} – CyberDef Report</title>
<style>
  @page {
    size: A4 portrait;
    margin: 20mm 15mm 25mm 15mm;
    @bottom-center { content: counter(page) " / " counter(pages); font-size: 9px; color: #94a3b8; }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, Helvetica, sans-serif; color: #1e293b; font-size: 12px; line-height: 1.5; }
  h1 { font-size: 22px; font-weight: 700; margin-bottom: 2px; }
  h2 { font-size: 16px; font-weight: 600; color: #0369a1; margin: 18px 0 8px; border-bottom: 2px solid #0ea5e9; padding-bottom: 4px; }
  h3 { font-size: 13px; font-weight: 600; margin: 12px 0 4px; }
  table { width: 100%; border-collapse: collapse; page-break-inside: auto; }
  tr { page-break-inside: avoid; page-break-after: auto; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #0ea5e9; padding-bottom: 12px; margin-bottom: 16px; }
  .header-left h1 { color: #0c4a6e; }
  .header-left .subtitle { color: #64748b; font-size: 13px; margin-top: 2px; }
  .header-right { text-align: right; font-size: 10px; color: #64748b; }
  .logo { font-size: 28px; font-weight: 800; color: #0ea5e9; letter-spacing: 0.05em; margin-bottom: 4px; }
  .footer { position: fixed; bottom: 0; left: 0; right: 0; text-align: center; font-size: 9px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding: 6px 0; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; }
  .badge-critical { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
  .badge-high { background: #fff7ed; color: #ea580c; border: 1px solid #fdba74; }
  .badge-medium { background: #fefce8; color: #ca8a04; border: 1px solid #fde047; }
  .badge-low { background: #eff6ff; color: #2563eb; border: 1px solid #93c5fd; }
  .section { margin: 12px 0; }
  @media print {
    body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style>
</head>
<body>
  <div class="header">
    <div class="header-left">
      <div class="logo">CYBERDEF</div>
      <h1>${title}</h1>
      ${subtitle ? `<div class="subtitle">${subtitle}</div>` : ""}
    </div>
    <div class="header-right">
      <div><strong>Date:</strong> ${formatDate()}</div>
      <div><strong>Generated by:</strong> ${generatedBy}</div>
      <div><strong>Classification:</strong> INTERNAL</div>
    </div>
  </div>
  <div class="section">${content}</div>
  <div class="footer">CyberDef Security Report – Confidential – ${formatDate()}</div>
</body>
</html>`);

    printWindow.document.close();
    // Small delay to let styles render
    setTimeout(() => {
      printWindow.focus();
      printWindow.print();
      printWindow.close();
    }, 400);
  }, [title, subtitle, generatedBy]);

  const handleCopyMarkdown = useCallback(() => {
    if (!data?.length) return;
    const md = dataToMarkdown(title, data);
    navigator.clipboard.writeText(md).catch(() => { /* noop */ });
  }, [title, data]);

  return (
    <>
      {/* Hidden print-ready content */}
      <div ref={printRef} className="hidden">
        {data?.length ? (
          <div dangerouslySetInnerHTML={{ __html: dataToTable(data) }} />
        ) : null}
        {children}
      </div>

      {/* Visible action buttons */}
      <div className="flex items-center gap-2">
        <button
          onClick={handlePrint}
          className="flex items-center gap-2 px-4 py-2 text-xs font-semibold tracking-wider uppercase rounded glass-panel border border-cyan-glow/20 text-cyan-glow hover:border-cyan-glow/50 hover:shadow-cyan-md transition-all duration-200"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
          </svg>
          Export PDF
        </button>

        {data?.length ? (
          <button
            onClick={handleCopyMarkdown}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold tracking-wider uppercase rounded glass-panel border border-cyan-glow/20 text-cyan-dim hover:border-cyan-glow/50 hover:shadow-cyan-md transition-all duration-200"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
            Copy Markdown
          </button>
        ) : null}
      </div>
    </>
  );
}
