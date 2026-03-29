"use client";

import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { CQLAutocomplete, type Suggestion } from "./CQLAutocomplete";

/* ------------------------------------------------------------------ */
/*  Token types & regex                                                */
/* ------------------------------------------------------------------ */

type TokenType =
  | "keyword"
  | "pipe"
  | "command"
  | "field"
  | "operator"
  | "string"
  | "number"
  | "function"
  | "comment"
  | "error"
  | "text";

interface Token {
  type: TokenType;
  value: string;
}

const CQL_KEYWORDS = new Set([
  "AND",
  "OR",
  "NOT",
  "IN",
  "LIKE",
  "CONTAINS",
  "BETWEEN",
  "IS",
  "NULL",
  "TRUE",
  "FALSE",
  "EXISTS",
  "MATCHES",
  "STARTSWITH",
  "ENDSWITH",
]);

const CQL_COMMANDS = new Set([
  "stats",
  "where",
  "sort",
  "head",
  "tail",
  "table",
  "dedup",
  "rename",
  "eval",
  "fields",
  "rex",
  "timechart",
  "top",
  "rare",
  "bucket",
  "chart",
  "lookup",
  "join",
  "append",
  "uniq",
  "count",
  "sum",
  "avg",
  "min",
  "max",
  "values",
  "dc",
  "list",
  "first",
  "last",
  "fillnull",
  "iplocation",
  "transaction",
  "streamstats",
  "eventstats",
  "format",
  "outputlookup",
  "collect",
  "regex",
]);

const CQL_FUNCTIONS = new Set([
  "count",
  "sum",
  "avg",
  "min",
  "max",
  "values",
  "dc",
  "list",
  "first",
  "last",
  "len",
  "lower",
  "upper",
  "trim",
  "substr",
  "replace",
  "split",
  "coalesce",
  "if",
  "case",
  "cidrmatch",
  "tonumber",
  "tostring",
  "now",
  "relative_time",
  "strftime",
  "strptime",
  "round",
  "ceil",
  "floor",
  "abs",
  "log",
  "pow",
  "sqrt",
  "urldecode",
  "md5",
  "sha256",
]);

const CQL_FIELDS = [
  "src_ip",
  "dst_ip",
  "username",
  "event_type",
  "severity",
  "source",
  "message",
  "port",
  "protocol",
  "user_agent",
  "domain",
  "hash",
  "file_path",
  "action",
  "status",
  "method",
  "url",
  "referer",
  "bytes",
  "duration",
  "country",
  "city",
  "asn",
  "process_name",
  "pid",
  "ppid",
  "cmdline",
  "registry_key",
  "dns_query",
  "dns_response",
  "threat_score",
  "mitre_tactic",
  "mitre_technique",
  "rule_name",
  "alert_id",
  "session_id",
  "device_id",
  "mac_address",
  "vlan",
  "interface",
  "direction",
  "timestamp",
  "raw",
];

const OPERATORS = ["!=", ">=", "<=", "=", ">", "<"];

/* ------------------------------------------------------------------ */
/*  Tokenizer                                                          */
/* ------------------------------------------------------------------ */

export function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < input.length) {
    // Whitespace
    if (/\s/.test(input[i])) {
      let ws = "";
      while (i < input.length && /\s/.test(input[i])) {
        ws += input[i++];
      }
      tokens.push({ type: "text", value: ws });
      continue;
    }

    // Comment
    if (input[i] === "/" && input[i + 1] === "/") {
      let comment = "";
      while (i < input.length && input[i] !== "\n") {
        comment += input[i++];
      }
      tokens.push({ type: "comment", value: comment });
      continue;
    }

    // String (double or single quoted)
    if (input[i] === '"' || input[i] === "'") {
      const q = input[i];
      let str = q;
      i++;
      while (i < input.length && input[i] !== q) {
        if (input[i] === "\\" && i + 1 < input.length) {
          str += input[i++];
        }
        str += input[i++];
      }
      if (i < input.length) str += input[i++];
      tokens.push({ type: "string", value: str });
      continue;
    }

    // Pipe
    if (input[i] === "|") {
      tokens.push({ type: "pipe", value: "|" });
      i++;
      continue;
    }

    // Parentheses, comma
    if ("(),".includes(input[i])) {
      tokens.push({ type: "text", value: input[i] });
      i++;
      continue;
    }

    // Operators
    let foundOp = false;
    for (const op of OPERATORS) {
      if (input.substring(i, i + op.length) === op) {
        tokens.push({ type: "operator", value: op });
        i += op.length;
        foundOp = true;
        break;
      }
    }
    if (foundOp) continue;

    // Wildcard
    if (input[i] === "*") {
      tokens.push({ type: "operator", value: "*" });
      i++;
      continue;
    }

    // Number
    if (/\d/.test(input[i])) {
      let num = "";
      while (i < input.length && /[\d.]/.test(input[i])) {
        num += input[i++];
      }
      tokens.push({ type: "number", value: num });
      continue;
    }

    // Word (identifier)
    if (/[a-zA-Z_]/.test(input[i])) {
      let word = "";
      while (i < input.length && /[a-zA-Z0-9_.]/.test(input[i])) {
        word += input[i++];
      }
      // Check if followed by ( => function
      if (i < input.length && input[i] === "(" && CQL_FUNCTIONS.has(word.toLowerCase())) {
        tokens.push({ type: "function", value: word });
      } else if (CQL_KEYWORDS.has(word.toUpperCase())) {
        tokens.push({ type: "keyword", value: word });
      } else if (CQL_COMMANDS.has(word.toLowerCase())) {
        tokens.push({ type: "command", value: word });
      } else if (CQL_FIELDS.includes(word)) {
        tokens.push({ type: "field", value: word });
      } else {
        tokens.push({ type: "text", value: word });
      }
      continue;
    }

    // Anything else
    tokens.push({ type: "text", value: input[i] });
    i++;
  }

  return tokens;
}

/* ------------------------------------------------------------------ */
/*  Token CSS classes                                                   */
/* ------------------------------------------------------------------ */

const TOKEN_CLASSES: Record<TokenType, string> = {
  keyword: "text-cyan-400 font-bold",
  pipe: "text-yellow-400 font-bold",
  command: "text-emerald-400",
  field: "text-blue-300",
  operator: "text-orange-400",
  string: "text-green-300",
  number: "text-purple-300",
  function: "text-pink-400",
  comment: "text-gray-600 italic",
  error: "text-red-400 underline",
  text: "text-gray-200",
};

/* ------------------------------------------------------------------ */
/*  Autocomplete context detection                                     */
/* ------------------------------------------------------------------ */

type ACContext = "field" | "operator" | "value" | "command" | "general";

function detectContext(text: string): ACContext {
  const trimmed = text.trimEnd();

  // After pipe => command
  if (/\|\s*\w*$/.test(trimmed) && !/\|\s*\w+\s/.test(trimmed.replace(/\|\s*\w*$/, ""))) {
    const afterPipe = trimmed.slice(trimmed.lastIndexOf("|") + 1).trim();
    if (!afterPipe.includes(" ")) return "command";
  }
  // Check if after pipe command is complete and we need field/args
  const pipeSegments = trimmed.split("|");
  if (pipeSegments.length > 1) {
    const lastSeg = pipeSegments[pipeSegments.length - 1].trim();
    const parts = lastSeg.split(/\s+/);
    if (parts.length >= 2) return "field";
  }

  // After operator => value
  if (/[=!<>]+\s*\S*$/.test(trimmed)) {
    const match = trimmed.match(/[=!<>]+\s*(\S*)$/);
    if (match) return "value";
  }

  // After field name => operator
  const fieldRegex = new RegExp(
    `(${CQL_FIELDS.join("|")})\\s*$`
  );
  if (fieldRegex.test(trimmed)) return "operator";

  return "field";
}

function getSuggestions(context: ACContext, partial: string): Suggestion[] {
  const lower = partial.toLowerCase();

  if (context === "command") {
    return Array.from(CQL_COMMANDS)
      .filter((c) => c.startsWith(lower))
      .slice(0, 10)
      .map((c) => ({
        text: c,
        type: "command" as const,
        description: getCommandDesc(c),
        icon: "cmd",
      }));
  }

  if (context === "operator") {
    return OPERATORS.map((op) => ({
      text: op,
      type: "operator" as const,
      description: getOperatorDesc(op),
      icon: "op",
    }));
  }

  if (context === "field") {
    return CQL_FIELDS.filter((f) => f.includes(lower))
      .slice(0, 10)
      .map((f) => ({
        text: f,
        type: "field" as const,
        description: getFieldDesc(f),
        icon: getFieldIcon(f),
      }));
  }

  // General / value context - combine
  const fields = CQL_FIELDS.filter((f) => f.includes(lower))
    .slice(0, 5)
    .map((f) => ({
      text: f,
      type: "field" as const,
      description: getFieldDesc(f),
      icon: getFieldIcon(f),
    }));
  const keywords = Array.from(CQL_KEYWORDS)
    .filter((k) => k.toLowerCase().startsWith(lower))
    .slice(0, 3)
    .map((k) => ({
      text: k,
      type: "keyword" as const,
      description: "Logical operator",
      icon: "key",
    }));
  return [...fields, ...keywords];
}

function getCommandDesc(cmd: string): string {
  const descs: Record<string, string> = {
    stats: "Calculate aggregate statistics",
    where: "Filter results by condition",
    sort: "Sort results by field",
    head: "Return first N results",
    tail: "Return last N results",
    table: "Display only specified fields",
    dedup: "Remove duplicate values",
    rename: "Rename a field",
    eval: "Create/calculate fields",
    fields: "Include or exclude fields",
    timechart: "Create time-based chart",
    top: "Most common values",
    rare: "Least common values",
    bucket: "Group into buckets",
    chart: "Create a chart",
    join: "Join with another dataset",
    rex: "Extract fields with regex",
    uniq: "Remove duplicate events",
    fillnull: "Replace null with value",
    iplocation: "Add geolocation from IP",
    transaction: "Group related events",
    regex: "Filter with regex",
  };
  return descs[cmd] || "CQL command";
}

function getOperatorDesc(op: string): string {
  const descs: Record<string, string> = {
    "=": "Equals",
    "!=": "Not equals",
    ">": "Greater than",
    "<": "Less than",
    ">=": "Greater or equal",
    "<=": "Less or equal",
  };
  return descs[op] || "Operator";
}

function getFieldDesc(field: string): string {
  const descs: Record<string, string> = {
    src_ip: "Source IP address",
    dst_ip: "Destination IP address",
    username: "User account name",
    event_type: "Type of security event",
    severity: "Event severity level",
    source: "Log source identifier",
    message: "Event message content",
    port: "Network port number",
    protocol: "Network protocol (TCP/UDP)",
    user_agent: "HTTP user-agent string",
    domain: "Domain name",
    hash: "File or artifact hash",
    file_path: "File system path",
    action: "Action taken (allow/block)",
    status: "HTTP or event status",
    timestamp: "Event timestamp",
    threat_score: "Calculated threat score",
    mitre_tactic: "MITRE ATT&CK tactic",
    mitre_technique: "MITRE ATT&CK technique",
    process_name: "Process executable name",
    cmdline: "Command line arguments",
    dns_query: "DNS query hostname",
    country: "Geographic country",
    bytes: "Data size in bytes",
    duration: "Event duration (ms)",
  };
  return descs[field] || "Event field";
}

function getFieldIcon(field: string): string {
  if (field.includes("ip") || field === "domain") return "globe";
  if (field.includes("time") || field === "timestamp" || field === "duration")
    return "clock";
  if (
    field === "port" ||
    field === "bytes" ||
    field === "threat_score" ||
    field === "pid" ||
    field === "ppid"
  )
    return "hash";
  return "text";
}

/* ------------------------------------------------------------------ */
/*  CQL Editor Component                                               */
/* ------------------------------------------------------------------ */

interface CQLEditorProps {
  value: string;
  onChange: (val: string) => void;
  onExecute: () => void;
  placeholder?: string;
  className?: string;
  error?: string | null;
}

export function CQLEditor({
  value,
  onChange,
  onExecute,
  placeholder = 'src_ip="10.0.0.1" AND severity="critical" | stats count by event_type',
  className = "",
  error,
}: CQLEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [showAC, setShowAC] = useState(false);
  const [acSuggestions, setAcSuggestions] = useState<Suggestion[]>([]);
  const [cursorPos, setCursorPos] = useState({ x: 0, y: 0 });
  const [historyIdx, setHistoryIdx] = useState(-1);

  // Query history from localStorage
  const history = useMemo(() => {
    if (typeof window === "undefined") return [];
    try {
      return JSON.parse(
        localStorage.getItem("cql_history") || "[]"
      ) as string[];
    } catch {
      return [];
    }
  }, []);

  // Tokenize and render highlighted HTML
  const highlighted = useMemo(() => {
    if (!value) return "";
    const tokens = tokenize(value);
    return tokens
      .map((t) => {
        const escaped = t.value
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/\n/g, "<br/>");
        if (t.type === "pipe") {
          return `<span class="${TOKEN_CLASSES[t.type]}">&nbsp;${escaped}&nbsp;</span>`;
        }
        return `<span class="${TOKEN_CLASSES[t.type]}">${escaped}</span>`;
      })
      .join("");
  }, [value]);

  // Sync scroll between textarea and highlight overlay
  const syncScroll = useCallback(() => {
    if (textareaRef.current && highlightRef.current) {
      highlightRef.current.scrollTop = textareaRef.current.scrollTop;
      highlightRef.current.scrollLeft = textareaRef.current.scrollLeft;
    }
  }, []);

  // Auto-resize textarea
  useLayoutEffect(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    const newH = Math.max(44, Math.min(ta.scrollHeight, 200));
    ta.style.height = `${newH}px`;
    if (highlightRef.current) {
      highlightRef.current.style.height = `${newH}px`;
    }
  }, [value]);

  // Autocomplete logic
  const updateAutocomplete = useCallback(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    const pos = ta.selectionStart;
    const textBefore = value.substring(0, pos);

    // Get partial word
    const match = textBefore.match(/[\w.]*$/);
    const partial = match ? match[0] : "";

    const ctx = detectContext(textBefore);
    const suggestions = getSuggestions(ctx, partial);

    if (suggestions.length > 0 && (partial.length > 0 || ctx === "operator" || ctx === "command")) {
      setAcSuggestions(suggestions);
      setShowAC(true);

      // Approximate cursor position
      const rect = ta.getBoundingClientRect();
      const linesBefore = textBefore.split("\n");
      const currentLine = linesBefore[linesBefore.length - 1];
      const charWidth = 8.4; // approx for JetBrains Mono 13px
      const lineHeight = 22;
      setCursorPos({
        x: Math.min(currentLine.length * charWidth + 16, rect.width - 280),
        y: (linesBefore.length) * lineHeight + 4,
      });
    } else {
      setShowAC(false);
    }
  }, [value]);

  // Accept autocomplete suggestion
  const acceptSuggestion = useCallback(
    (suggestion: Suggestion) => {
      const ta = textareaRef.current;
      if (!ta) return;
      const pos = ta.selectionStart;
      const textBefore = value.substring(0, pos);
      const textAfter = value.substring(pos);

      // Replace partial word
      const match = textBefore.match(/[\w.]*$/);
      const partial = match ? match[0] : "";
      const newBefore = textBefore.slice(0, textBefore.length - partial.length);

      let insert = suggestion.text;
      // Add helpful suffixes
      if (suggestion.type === "field") insert += "=";
      if (suggestion.type === "operator") insert += "";
      if (suggestion.type === "command") insert += " ";

      const newValue = newBefore + insert + textAfter;
      onChange(newValue);
      setShowAC(false);

      // Restore cursor
      requestAnimationFrame(() => {
        const newPos = newBefore.length + insert.length;
        ta.selectionStart = ta.selectionEnd = newPos;
        ta.focus();
      });
    },
    [value, onChange]
  );

  // Keyboard handler
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      // Execute: Ctrl+Enter
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        onExecute();
        return;
      }

      // New line: Shift+Enter
      if (e.key === "Enter" && e.shiftKey) {
        // Let default behavior add new line
        return;
      }

      // If autocomplete is open, let it handle keys
      if (showAC) {
        if (
          e.key === "ArrowDown" ||
          e.key === "ArrowUp" ||
          e.key === "Tab" ||
          e.key === "Enter"
        ) {
          // These are handled by CQLAutocomplete
          return;
        }
        if (e.key === "Escape") {
          e.preventDefault();
          setShowAC(false);
          return;
        }
      }

      // History navigation (up/down when empty line)
      if (e.key === "ArrowUp" && !value.trim()) {
        e.preventDefault();
        const newIdx = Math.min(historyIdx + 1, history.length - 1);
        if (history[newIdx]) {
          setHistoryIdx(newIdx);
          onChange(history[newIdx]);
        }
        return;
      }
      if (e.key === "ArrowDown" && !value.trim()) {
        e.preventDefault();
        const newIdx = Math.max(historyIdx - 1, -1);
        setHistoryIdx(newIdx);
        onChange(newIdx >= 0 ? history[newIdx] : "");
        return;
      }

      // Plain Enter without shift/ctrl => execute
      if (e.key === "Enter" && !e.shiftKey && !e.ctrlKey && !e.metaKey && !showAC) {
        e.preventDefault();
        onExecute();
        return;
      }
    },
    [onExecute, showAC, value, historyIdx, history, onChange]
  );

  // Update autocomplete on text change
  useEffect(() => {
    const timer = setTimeout(updateAutocomplete, 100);
    return () => clearTimeout(timer);
  }, [value, updateAutocomplete]);

  return (
    <div ref={containerRef} className={`relative ${className}`}>
      {/* Highlight overlay */}
      <div
        ref={highlightRef}
        className="pointer-events-none absolute inset-0 overflow-hidden whitespace-pre-wrap break-words px-4 py-3 font-mono text-[13px] leading-[22px]"
        style={{ fontFamily: "'JetBrains Mono', monospace" }}
        aria-hidden="true"
        dangerouslySetInnerHTML={{ __html: highlighted || `<span class="text-gray-600">${placeholder}</span>` }}
      />

      {/* Textarea (transparent text, visible caret) */}
      <textarea
        ref={textareaRef}
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
          setHistoryIdx(-1);
        }}
        onKeyDown={handleKeyDown}
        onScroll={syncScroll}
        className={`relative z-10 w-full resize-none bg-transparent px-4 py-3 font-mono text-[13px] leading-[22px] text-transparent caret-cyan-400 outline-none selection:bg-cyan-500/20 selection:text-transparent ${
          error ? "ring-1 ring-red-500/50" : ""
        }`}
        style={{
          fontFamily: "'JetBrains Mono', monospace",
          minHeight: 44,
          caretColor: "#22d3ee",
        }}
        spellCheck={false}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
      />

      {/* Error indicator */}
      {error && (
        <div className="absolute bottom-0 left-0 right-0 border-t border-red-500/30 bg-red-500/10 px-4 py-1">
          <span className="font-mono text-[11px] text-red-400">{error}</span>
        </div>
      )}

      {/* Autocomplete dropdown */}
      {showAC && (
        <CQLAutocomplete
          suggestions={acSuggestions}
          position={cursorPos}
          onSelect={acceptSuggestion}
          onDismiss={() => setShowAC(false)}
          visible={showAC}
        />
      )}
    </div>
  );
}

export { CQL_FIELDS, CQL_COMMANDS, CQL_KEYWORDS, CQL_FUNCTIONS };
