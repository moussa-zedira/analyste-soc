"use client";

import { useState } from "react";
import { PageTransition, StaggerItem } from "@/components/PageTransition";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface ParserFormat {
  id: string;
  name: string;
  description: string;
  eventsParsed: number;
  example: string;
  regex: string;
  active: boolean;
}

interface ParsedField {
  key: string;
  value: string;
}

/* ------------------------------------------------------------------ */
/*  Mock data                                                          */
/* ------------------------------------------------------------------ */

const MOCK_FORMATS: ParserFormat[] = [
  { id: "p-1", name: "Syslog (RFC 5424)", description: "Standard syslog format with structured data", eventsParsed: 245890, active: true, example: "<34>1 2026-03-29T10:00:00.000Z server01 sshd 12345 - - Failed password for admin from 192.168.1.100 port 22 ssh2", regex: "^<(\\d+)>(\\d+) (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (\\S+) (.*)$" },
  { id: "p-2", name: "Apache Access Log", description: "Combined log format from Apache/Nginx", eventsParsed: 1523400, active: true, example: "192.168.1.100 - admin [29/Mar/2026:10:00:00 +0000] \"GET /admin HTTP/1.1\" 200 4523 \"-\" \"Mozilla/5.0\"", regex: "^(\\S+) \\S+ (\\S+) \\[(.+?)\\] \"(.+?)\" (\\d+) (\\d+)" },
  { id: "p-3", name: "Windows Event Log (XML)", description: "Windows Event Viewer XML export format", eventsParsed: 89340, active: true, example: "<Event><System><EventID>4625</EventID><TimeCreated SystemTime=\"2026-03-29T10:00:00Z\"/><Computer>DC01</Computer></System><EventData><Data Name=\"TargetUserName\">admin</Data><Data Name=\"IpAddress\">10.0.0.5</Data></EventData></Event>", regex: "N/A (XML parser)" },
  { id: "p-4", name: "JSON (Generic)", description: "Arbitrary JSON log entries", eventsParsed: 567200, active: true, example: "{\"timestamp\":\"2026-03-29T10:00:00Z\",\"level\":\"ERROR\",\"src_ip\":\"10.0.0.5\",\"event\":\"auth.fail\",\"user\":\"admin\"}", regex: "N/A (JSON parser)" },
  { id: "p-5", name: "CEF (Common Event Format)", description: "ArcSight Common Event Format", eventsParsed: 34500, active: true, example: "CEF:0|Security|IDS|1.0|100|Intrusion Detected|8|src=192.168.1.100 dst=10.0.0.1 act=blocked", regex: "^CEF:(\\d+)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|(.*)" },
  { id: "p-6", name: "CSV Log", description: "Comma-separated log entries with header", eventsParsed: 12000, active: false, example: "timestamp,src_ip,dst_ip,event_type,severity\n2026-03-29T10:00:00Z,10.0.0.5,192.168.1.1,auth.fail,high", regex: "N/A (CSV parser)" },
  { id: "p-7", name: "LEEF (Log Event Extended Format)", description: "IBM QRadar LEEF format", eventsParsed: 8900, active: true, example: "LEEF:2.0|IBM|QRadar|1.0|Authentication|src=10.0.0.5\tidentSrc=admin\tcat=auth\tsev=7", regex: "^LEEF:(\\S+)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|([^|]*)\\|(.*)" },
];

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function ParsersPage() {
  const [activeTab, setActiveTab] = useState<"formats" | "test" | "custom" | "import">("formats");
  const [formats, setFormats] = useState<ParserFormat[]>(MOCK_FORMATS);
  const [testInput, setTestInput] = useState("");
  const [detectedFormat, setDetectedFormat] = useState<string | null>(null);
  const [parsedFields, setParsedFields] = useState<ParsedField[]>([]);
  const [parseError, setParseError] = useState<string | null>(null);

  // Custom parser state
  const [customName, setCustomName] = useState("");
  const [customDesc, setCustomDesc] = useState("");
  const [customRegex, setCustomRegex] = useState("");
  const [customExample, setCustomExample] = useState("");

  // Import state
  const [importFile, setImportFile] = useState<string | null>(null);
  const [importFormat, setImportFormat] = useState("auto");
  const [importPreview, setImportPreview] = useState<string[]>([]);

  const handleTestParse = () => {
    if (!testInput.trim()) return;
    setParseError(null);
    setParsedFields([]);
    setDetectedFormat(null);

    const input = testInput.trim();

    try {
      // Auto-detect format
      if (input.startsWith("{")) {
        setDetectedFormat("JSON (Generic)");
        const obj = JSON.parse(input);
        setParsedFields(Object.entries(obj).map(([k, v]) => ({ key: k, value: String(v) })));
      } else if (input.startsWith("<Event>") || input.startsWith("<?xml")) {
        setDetectedFormat("Windows Event Log (XML)");
        const fields: ParsedField[] = [];
        const eventIdMatch = input.match(/<EventID>(\d+)<\/EventID>/);
        if (eventIdMatch) fields.push({ key: "EventID", value: eventIdMatch[1] });
        const computerMatch = input.match(/<Computer>([^<]+)<\/Computer>/);
        if (computerMatch) fields.push({ key: "Computer", value: computerMatch[1] });
        const dataMatches = input.matchAll(/<Data Name="([^"]+)">([^<]+)<\/Data>/g);
        for (const m of dataMatches) fields.push({ key: m[1], value: m[2] });
        setParsedFields(fields);
      } else if (input.startsWith("CEF:")) {
        setDetectedFormat("CEF (Common Event Format)");
        const parts = input.split("|");
        if (parts.length >= 8) {
          setParsedFields([
            { key: "version", value: parts[0].replace("CEF:", "") },
            { key: "vendor", value: parts[1] },
            { key: "product", value: parts[2] },
            { key: "version", value: parts[3] },
            { key: "signatureId", value: parts[4] },
            { key: "name", value: parts[5] },
            { key: "severity", value: parts[6] },
            ...parts[7].split(" ").filter(Boolean).map((kv) => {
              const [k, ...v] = kv.split("=");
              return { key: k, value: v.join("=") };
            }),
          ]);
        }
      } else if (input.startsWith("LEEF:")) {
        setDetectedFormat("LEEF (Log Event Extended Format)");
        const parts = input.split("|");
        if (parts.length >= 6) {
          const extFields = parts[5].split("\t").filter(Boolean).map((kv) => {
            const [k, ...v] = kv.split("=");
            return { key: k, value: v.join("=") };
          });
          setParsedFields([
            { key: "version", value: parts[0].replace("LEEF:", "") },
            { key: "vendor", value: parts[1] },
            { key: "product", value: parts[2] },
            { key: "productVersion", value: parts[3] },
            { key: "eventType", value: parts[4] },
            ...extFields,
          ]);
        }
      } else if (input.startsWith("<")) {
        setDetectedFormat("Syslog (RFC 5424)");
        const m = input.match(/^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)/);
        if (m) {
          setParsedFields([
            { key: "priority", value: m[1] },
            { key: "version", value: m[2] },
            { key: "timestamp", value: m[3] },
            { key: "hostname", value: m[4] },
            { key: "appname", value: m[5] },
            { key: "procid", value: m[6] },
            { key: "msgid", value: m[7] },
            { key: "structuredData", value: m[8] },
            { key: "message", value: m[9] },
          ]);
        }
      } else {
        // Try Apache combined log format
        const apacheMatch = input.match(/^(\S+)\s+\S+\s+(\S+)\s+\[(.+?)\]\s+"(.+?)"\s+(\d+)\s+(\d+)/);
        if (apacheMatch) {
          setDetectedFormat("Apache Access Log");
          setParsedFields([
            { key: "remote_host", value: apacheMatch[1] },
            { key: "remote_user", value: apacheMatch[2] },
            { key: "timestamp", value: apacheMatch[3] },
            { key: "request", value: apacheMatch[4] },
            { key: "status", value: apacheMatch[5] },
            { key: "bytes", value: apacheMatch[6] },
          ]);
        } else {
          setParseError("Could not auto-detect format. Try pasting a log in a supported format.");
        }
      }
    } catch (err) {
      setParseError(err instanceof Error ? err.message : "Parse error");
    }
  };

  const handleCreateCustom = () => {
    if (!customName.trim() || !customRegex.trim()) return;
    const newFormat: ParserFormat = {
      id: `p-${Date.now()}`,
      name: customName,
      description: customDesc,
      eventsParsed: 0,
      example: customExample,
      regex: customRegex,
      active: true,
    };
    setFormats((prev) => [...prev, newFormat]);
    setCustomName("");
    setCustomDesc("");
    setCustomRegex("");
    setCustomExample("");
    setActiveTab("formats");
  };

  const handleToggleFormat = (id: string) => {
    setFormats((prev) => prev.map((f) => (f.id === id ? { ...f, active: !f.active } : f)));
  };

  const handleFileDrop = () => {
    setImportFile("sample_logs.txt");
    setImportPreview([
      "192.168.1.100 - admin [29/Mar/2026:10:00:00 +0000] \"GET /api/users HTTP/1.1\" 200 1234",
      "192.168.1.100 - admin [29/Mar/2026:10:00:01 +0000] \"POST /api/login HTTP/1.1\" 401 89",
      "192.168.1.101 - - [29/Mar/2026:10:00:02 +0000] \"GET /admin HTTP/1.1\" 403 0",
    ]);
  };

  const totalParsed = formats.reduce((a, f) => a + f.eventsParsed, 0);

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Log Parsers
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            FORMAT DETECTION // PARSER CONFIG // BULK IMPORT
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Stats */}
      <StaggerItem>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{formats.length}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">FORMATS</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{formats.filter((f) => f.active).length}</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">ACTIVE</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">{(totalParsed / 1000).toFixed(0)}K</p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">EVENTS PARSED</p>
          </div>
          <div className="glass-panel p-4 text-center">
            <p className="text-2xl font-bold text-cyan-glow font-mono">
              {formats.reduce((best, f) => (f.eventsParsed > (best?.eventsParsed || 0) ? f : best), formats[0])?.name.split(" ")[0] || "-"}
            </p>
            <p className="text-[10px] tracking-widest text-gray-500 mt-1">TOP FORMAT</p>
          </div>
        </div>
      </StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <div className="flex gap-2">
          {(["formats", "test", "custom", "import"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700 text-gray-500 hover:border-gray-600"
              }`}
            >
              {tab === "formats" ? "FORMATS" : tab === "test" ? "TEST PARSER" : tab === "custom" ? "CUSTOM PARSER" : "BULK IMPORT"}
            </button>
          ))}
        </div>
      </StaggerItem>

      {/* ---- FORMATS TAB ---- */}
      {activeTab === "formats" && (
        <StaggerItem>
          <div className="space-y-3">
            {formats.map((f) => (
              <div key={f.id} className="glass-panel p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-gray-200">{f.name}</p>
                    <p className="text-[10px] text-gray-500">{f.description}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-cyan-glow font-mono">{f.eventsParsed.toLocaleString()} events</span>
                    <button
                      onClick={() => handleToggleFormat(f.id)}
                      className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${
                        f.active
                          ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                          : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"
                      }`}
                    >
                      {f.active ? "ACTIVE" : "INACTIVE"}
                    </button>
                  </div>
                </div>
                <div className="rounded border border-gray-800 bg-gray-900/50 p-2">
                  <p className="text-[10px] tracking-widest text-gray-500 mb-1">EXAMPLE</p>
                  <code className="text-[10px] text-cyan-glow/70 font-mono break-all">{f.example}</code>
                </div>
                {f.regex !== "N/A (XML parser)" && f.regex !== "N/A (JSON parser)" && f.regex !== "N/A (CSV parser)" && (
                  <div className="rounded border border-gray-800 bg-gray-900/50 p-2">
                    <p className="text-[10px] tracking-widest text-gray-500 mb-1">REGEX</p>
                    <code className="text-[10px] text-yellow-400/70 font-mono break-all">{f.regex}</code>
                  </div>
                )}
              </div>
            ))}
          </div>
        </StaggerItem>
      )}

      {/* ---- TEST PARSER TAB ---- */}
      {activeTab === "test" && (
        <StaggerItem>
          <div className="glass-panel p-6 space-y-4">
            <h3 className="text-[10px] font-bold tracking-widest text-gray-500">PASTE RAW LOG</h3>
            <textarea
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              placeholder={'Paste a raw log line here...\n\nExamples:\n{"timestamp":"2026-03-29T10:00:00Z","level":"ERROR","event":"auth.fail"}\n<34>1 2026-03-29T10:00:00.000Z server01 sshd 12345 - - Failed password\nCEF:0|Security|IDS|1.0|100|Intrusion|8|src=10.0.0.5'}
              className="w-full rounded-md border border-gray-700 bg-gray-900/80 p-3 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
              rows={6}
            />
            <button
              onClick={handleTestParse}
              disabled={!testInput.trim()}
              className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50"
            >
              PARSE
            </button>

            {parseError && (
              <div className="rounded border border-red-500/30 bg-red-500/5 px-4 py-2 text-xs text-red-400">
                {parseError}
              </div>
            )}

            {detectedFormat && (
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <span className="text-[10px] tracking-widest text-gray-500">DETECTED FORMAT:</span>
                  <span className="rounded border border-cyan-glow/30 bg-cyan-glow/10 px-3 py-1 text-xs font-bold text-cyan-glow">
                    {detectedFormat}
                  </span>
                </div>

                <div className="glass-panel overflow-hidden">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="border-b border-cyan-glow/10">
                        <th className="px-4 py-2 text-[10px] font-bold tracking-widest text-gray-500">FIELD</th>
                        <th className="px-4 py-2 text-[10px] font-bold tracking-widest text-gray-500">VALUE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {parsedFields.map((f, i) => (
                        <tr key={i} className="border-b border-gray-800/50">
                          <td className="px-4 py-2 text-xs text-cyan-glow font-mono">{f.key}</td>
                          <td className="px-4 py-2 text-xs text-gray-300 font-mono">{f.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </StaggerItem>
      )}

      {/* ---- CUSTOM PARSER TAB ---- */}
      {activeTab === "custom" && (
        <StaggerItem>
          <div className="glass-panel p-6 space-y-4">
            <h3 className="text-[10px] font-bold tracking-widest text-gray-500">CREATE CUSTOM PARSER</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">NAME</label>
                <input type="text" value={customName} onChange={(e) => setCustomName(e.target.value)} placeholder="Custom Firewall Log" className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
              </div>
              <div>
                <label className="text-[10px] tracking-widest text-gray-500 block mb-1">DESCRIPTION</label>
                <input type="text" value={customDesc} onChange={(e) => setCustomDesc(e.target.value)} placeholder="Parser for custom firewall logs" className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
              </div>
            </div>
            <div>
              <label className="text-[10px] tracking-widest text-gray-500 block mb-1">REGEX PATTERN</label>
              <input type="text" value={customRegex} onChange={(e) => setCustomRegex(e.target.value)} placeholder="^(\S+)\s+(\S+)\s+(.*)$" className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] tracking-widest text-gray-500 block mb-1">EXAMPLE LOG LINE</label>
              <textarea value={customExample} onChange={(e) => setCustomExample(e.target.value)} placeholder="Paste an example log line" className="w-full rounded-md border border-gray-700 bg-gray-900/80 p-3 text-xs text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" rows={3} />
            </div>
            <button onClick={handleCreateCustom} disabled={!customName.trim() || !customRegex.trim()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors disabled:opacity-50">
              CREATE PARSER
            </button>
          </div>
        </StaggerItem>
      )}

      {/* ---- BULK IMPORT TAB ---- */}
      {activeTab === "import" && (
        <StaggerItem>
          <div className="space-y-4">
            <div className="glass-panel p-6 space-y-4">
              <h3 className="text-[10px] font-bold tracking-widest text-gray-500">BULK LOG IMPORT</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] tracking-widest text-gray-500 block mb-1">FORMAT</label>
                  <select value={importFormat} onChange={(e) => setImportFormat(e.target.value)} className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none">
                    <option value="auto">Auto-detect</option>
                    {formats.map((f) => (
                      <option key={f.id} value={f.id}>{f.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Drop zone */}
              <div
                onClick={handleFileDrop}
                className="cursor-pointer rounded-lg border-2 border-dashed border-gray-700 bg-gray-900/30 p-12 text-center hover:border-cyan-glow/30 hover:bg-cyan-glow/5 transition-all"
              >
                <svg className="mx-auto h-12 w-12 text-gray-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
                <p className="text-sm text-gray-400">Click to upload or drag and drop log files</p>
                <p className="text-[10px] text-gray-600 mt-1">Supports .log, .txt, .json, .csv, .xml (max 100MB)</p>
              </div>

              {importFile && (
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-gray-500">FILE:</span>
                    <span className="text-xs text-cyan-glow font-mono">{importFile}</span>
                  </div>
                  <div className="rounded border border-gray-800 bg-gray-900/50 p-3">
                    <p className="text-[10px] tracking-widest text-gray-500 mb-2">PREVIEW (first 3 lines)</p>
                    {importPreview.map((line, i) => (
                      <code key={i} className="block text-[10px] text-gray-400 font-mono mb-1">{line}</code>
                    ))}
                  </div>
                  <button className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2.5 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors">
                    IMPORT {importPreview.length}+ ENTRIES
                  </button>
                </div>
              )}
            </div>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
