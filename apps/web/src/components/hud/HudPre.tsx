"use client";

import * as React from "react";
import { HudButton } from "./HudButton";

function copy(text: string) {
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    navigator.clipboard.writeText(text);
  }
}

function downloadText(filename: string, content: string, mime = "text/plain") {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export interface HudPreProps {
  text: string;
  title?: React.ReactNode;
  filename?: string;
  mime?: string;
  maxHeight?: number;
  className?: string;
}

export function HudPre({
  text,
  title,
  filename,
  mime = "text/plain",
  maxHeight = 280,
  className = "",
}: HudPreProps) {
  return (
    <div className={`space-y-1 ${className}`}>
      {(title || filename) && (
        <div className="flex items-center justify-between gap-2">
          {title && (
            <div className="text-[10px] uppercase tracking-widest text-cyan-glow/60">
              {title}
            </div>
          )}
          <div className="flex gap-2">
            <HudButton size="sm" variant="secondary" onClick={() => copy(text)}>
              Copy
            </HudButton>
            {filename && (
              <HudButton
                size="sm"
                variant="secondary"
                onClick={() => downloadText(filename, text, mime)}
              >
                Download
              </HudButton>
            )}
          </div>
        </div>
      )}
      <pre
        className="overflow-auto rounded border border-cyan-glow/15 bg-oled-near/80 p-3 font-mono text-[10px] text-cyan-glow whitespace-pre-wrap"
        style={{ maxHeight }}
      >
        {text}
      </pre>
    </div>
  );
}
