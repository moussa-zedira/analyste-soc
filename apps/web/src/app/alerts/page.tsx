"use client";

import { useState } from "react";
import { PageTransition, StaggerItem } from "@/components/PageTransition";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

type ChannelType = "slack" | "discord" | "email" | "pagerduty" | "teams" | "telegram";

interface AlertChannel {
  id: string;
  name: string;
  type: ChannelType;
  config: Record<string, string>;
  enabled: boolean;
  health: "healthy" | "degraded" | "down";
  lastPing: string | null;
}

interface AlertRule {
  id: string;
  severity: string;
  channelIds: string[];
  enabled: boolean;
}

interface AlertHistoryEntry {
  id: string;
  channelName: string;
  channelType: ChannelType;
  severity: string;
  message: string;
  status: "delivered" | "failed" | "pending";
  timestamp: string;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const CHANNEL_TYPES: { value: ChannelType; label: string; icon: string }[] = [
  { value: "slack", label: "Slack", icon: "#" },
  { value: "discord", label: "Discord", icon: "D" },
  { value: "email", label: "Email", icon: "@" },
  { value: "pagerduty", label: "PagerDuty", icon: "P" },
  { value: "teams", label: "Teams", icon: "T" },
  { value: "telegram", label: "Telegram", icon: "TG" },
];

const CHANNEL_FIELDS: Record<ChannelType, { key: string; label: string; placeholder: string }[]> = {
  slack: [
    { key: "webhook_url", label: "Webhook URL", placeholder: "https://hooks.slack.com/services/..." },
    { key: "channel", label: "Channel", placeholder: "#security-alerts" },
  ],
  discord: [
    { key: "webhook_url", label: "Webhook URL", placeholder: "https://discord.com/api/webhooks/..." },
  ],
  email: [
    { key: "smtp_host", label: "SMTP Host", placeholder: "smtp.example.com" },
    { key: "smtp_port", label: "SMTP Port", placeholder: "587" },
    { key: "from_address", label: "From", placeholder: "alerts@example.com" },
    { key: "to_addresses", label: "To (comma-separated)", placeholder: "soc@example.com, admin@example.com" },
  ],
  pagerduty: [
    { key: "routing_key", label: "Routing Key", placeholder: "your-pagerduty-routing-key" },
    { key: "severity_map", label: "Severity Mapping", placeholder: "critical=critical,high=error" },
  ],
  teams: [
    { key: "webhook_url", label: "Webhook URL", placeholder: "https://outlook.office.com/webhook/..." },
  ],
  telegram: [
    { key: "bot_token", label: "Bot Token", placeholder: "123456:ABC-DEF..." },
    { key: "chat_id", label: "Chat ID", placeholder: "-1001234567890" },
  ],
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

/* ------------------------------------------------------------------ */
/*  Mock data                                                          */
/* ------------------------------------------------------------------ */

const MOCK_CHANNELS: AlertChannel[] = [
  { id: "ch-1", name: "SOC Slack", type: "slack", config: { webhook_url: "https://hooks.slack.com/...", channel: "#soc-alerts" }, enabled: true, health: "healthy", lastPing: "2026-03-29T10:00:00Z" },
  { id: "ch-2", name: "Incident Email", type: "email", config: { smtp_host: "smtp.corp.com", smtp_port: "587", from_address: "alerts@corp.com", to_addresses: "soc@corp.com" }, enabled: true, health: "healthy", lastPing: "2026-03-29T09:55:00Z" },
  { id: "ch-3", name: "PagerDuty Critical", type: "pagerduty", config: { routing_key: "R0xxxxx", severity_map: "critical=critical" }, enabled: true, health: "degraded", lastPing: "2026-03-29T08:30:00Z" },
  { id: "ch-4", name: "Discord SOC", type: "discord", config: { webhook_url: "https://discord.com/api/webhooks/..." }, enabled: false, health: "down", lastPing: null },
];

const MOCK_RULES: AlertRule[] = [
  { id: "r-1", severity: "critical", channelIds: ["ch-1", "ch-2", "ch-3"], enabled: true },
  { id: "r-2", severity: "high", channelIds: ["ch-1", "ch-2"], enabled: true },
  { id: "r-3", severity: "medium", channelIds: ["ch-1"], enabled: true },
  { id: "r-4", severity: "low", channelIds: [], enabled: false },
  { id: "r-5", severity: "info", channelIds: [], enabled: false },
];

const MOCK_HISTORY: AlertHistoryEntry[] = [
  { id: "h-1", channelName: "SOC Slack", channelType: "slack", severity: "critical", message: "Brute force detected on SSH (10.0.0.5)", status: "delivered", timestamp: "2026-03-29T10:05:00Z" },
  { id: "h-2", channelName: "Incident Email", channelType: "email", severity: "critical", message: "Brute force detected on SSH (10.0.0.5)", status: "delivered", timestamp: "2026-03-29T10:05:01Z" },
  { id: "h-3", channelName: "PagerDuty Critical", channelType: "pagerduty", severity: "critical", message: "Brute force detected on SSH (10.0.0.5)", status: "failed", timestamp: "2026-03-29T10:05:02Z" },
  { id: "h-4", channelName: "SOC Slack", channelType: "slack", severity: "high", message: "Suspicious outbound connection to C2 IP", status: "delivered", timestamp: "2026-03-29T09:45:00Z" },
  { id: "h-5", channelName: "SOC Slack", channelType: "slack", severity: "medium", message: "New admin user created", status: "delivered", timestamp: "2026-03-29T09:30:00Z" },
  { id: "h-6", channelName: "Incident Email", channelType: "email", severity: "high", message: "Suspicious outbound connection to C2 IP", status: "pending", timestamp: "2026-03-29T09:45:01Z" },
];

/* ------------------------------------------------------------------ */
/*  Component                                                          */
/* ------------------------------------------------------------------ */

export default function AlertChannelsPage() {
  const [activeTab, setActiveTab] = useState<"channels" | "rules" | "history">("channels");
  const [channels, setChannels] = useState<AlertChannel[]>(MOCK_CHANNELS);
  const [rules, setRules] = useState<AlertRule[]>(MOCK_RULES);
  const [history] = useState<AlertHistoryEntry[]>(MOCK_HISTORY);

  // Add/edit modal state
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState<ChannelType>("slack");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);

  const resetForm = () => {
    setFormName("");
    setFormType("slack");
    setFormConfig({});
    setEditingId(null);
    setShowForm(false);
  };

  const openEdit = (ch: AlertChannel) => {
    setEditingId(ch.id);
    setFormName(ch.name);
    setFormType(ch.type);
    setFormConfig({ ...ch.config });
    setShowForm(true);
  };

  const handleSave = () => {
    if (!formName.trim()) return;
    if (editingId) {
      setChannels((prev) =>
        prev.map((ch) =>
          ch.id === editingId ? { ...ch, name: formName, type: formType, config: formConfig } : ch
        )
      );
    } else {
      const newCh: AlertChannel = {
        id: `ch-${Date.now()}`,
        name: formName,
        type: formType,
        config: formConfig,
        enabled: true,
        health: "healthy",
        lastPing: null,
      };
      setChannels((prev) => [...prev, newCh]);
    }
    resetForm();
  };

  const handleDelete = (id: string) => {
    setChannels((prev) => prev.filter((ch) => ch.id !== id));
    setRules((prev) =>
      prev.map((r) => ({ ...r, channelIds: r.channelIds.filter((cid) => cid !== id) }))
    );
  };

  const handleToggleChannel = (id: string) => {
    setChannels((prev) =>
      prev.map((ch) => (ch.id === id ? { ...ch, enabled: !ch.enabled } : ch))
    );
  };

  const handleTest = (ch: AlertChannel) => {
    setTestResult({ id: ch.id, ok: true, msg: "Test alert sent successfully" });
    setTimeout(() => setTestResult(null), 3000);
  };

  const handleToggleRule = (id: string) => {
    setRules((prev) =>
      prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleRuleChannel = (ruleId: string, channelId: string, add: boolean) => {
    setRules((prev) =>
      prev.map((r) => {
        if (r.id !== ruleId) return r;
        const ids = add
          ? [...r.channelIds, channelId]
          : r.channelIds.filter((c) => c !== channelId);
        return { ...r, channelIds: ids };
      })
    );
  };

  const healthColor = (h: string) => {
    if (h === "healthy") return "text-green-400 bg-green-500/15 border-green-500/30";
    if (h === "degraded") return "text-yellow-400 bg-yellow-500/15 border-yellow-500/30";
    return "text-red-400 bg-red-500/15 border-red-500/30";
  };

  const statusColor = (s: string) => {
    if (s === "delivered") return "text-green-400";
    if (s === "pending") return "text-yellow-400";
    return "text-red-400";
  };

  const sevColor = (s: string) => {
    if (s === "critical") return "bg-red-500/15 text-red-400";
    if (s === "high") return "bg-orange-500/15 text-orange-400";
    if (s === "medium") return "bg-yellow-500/15 text-yellow-400";
    if (s === "low") return "bg-blue-500/15 text-blue-400";
    return "bg-gray-500/15 text-gray-400";
  };

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">
            Alert Channels
          </h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            NOTIFICATION CHANNELS // ROUTING RULES // DELIVERY STATUS
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {/* Tabs */}
      <StaggerItem>
        <div className="flex gap-2">
          {(["channels", "rules", "history"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`rounded-md border px-4 py-2 text-[10px] font-bold tracking-widest transition-all ${
                activeTab === tab
                  ? "border-cyan-glow/40 bg-cyan-glow/15 text-cyan-glow"
                  : "border-gray-700 text-gray-500 hover:border-gray-600"
              }`}
            >
              {tab === "channels" ? "CHANNELS" : tab === "rules" ? "ROUTING RULES" : "ALERT HISTORY"}
            </button>
          ))}
        </div>
      </StaggerItem>

      {/* ---- CHANNELS TAB ---- */}
      {activeTab === "channels" && (
        <StaggerItem>
          <div className="space-y-4">
            {/* Add button */}
            <div className="flex justify-end">
              <button
                onClick={() => { resetForm(); setShowForm(true); }}
                className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors"
              >
                + ADD CHANNEL
              </button>
            </div>

            {/* Form modal */}
            {showForm && (
              <div className="glass-panel p-6 space-y-4">
                <h3 className="text-[10px] font-bold tracking-widest text-gray-500">
                  {editingId ? "EDIT CHANNEL" : "NEW CHANNEL"}
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-[10px] tracking-widest text-gray-500 block mb-1">NAME</label>
                    <input
                      type="text"
                      value={formName}
                      onChange={(e) => setFormName(e.target.value)}
                      placeholder="Channel name"
                      className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] tracking-widest text-gray-500 block mb-1">TYPE</label>
                    <select
                      value={formType}
                      onChange={(e) => { setFormType(e.target.value as ChannelType); setFormConfig({}); }}
                      className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono focus:border-cyan-glow/40 focus:outline-none"
                    >
                      {CHANNEL_TYPES.map((ct) => (
                        <option key={ct.value} value={ct.value}>{ct.label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                {/* Dynamic config fields */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {CHANNEL_FIELDS[formType].map((field) => (
                    <div key={field.key}>
                      <label className="text-[10px] tracking-widest text-gray-500 block mb-1">{field.label.toUpperCase()}</label>
                      <input
                        type="text"
                        value={formConfig[field.key] || ""}
                        onChange={(e) => setFormConfig((prev) => ({ ...prev, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 text-sm text-gray-200 font-mono placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none"
                      />
                    </div>
                  ))}
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleSave}
                    className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20 transition-colors"
                  >
                    {editingId ? "UPDATE" : "CREATE"}
                  </button>
                  <button
                    onClick={resetForm}
                    className="rounded-md border border-gray-700 px-6 py-2 text-[10px] font-bold tracking-widest text-gray-500 hover:border-gray-600 transition-colors"
                  >
                    CANCEL
                  </button>
                </div>
              </div>
            )}

            {/* Channel cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {channels.map((ch) => (
                <div key={ch.id} className="glass-panel p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="flex h-8 w-8 items-center justify-center rounded-md border border-cyan-glow/20 bg-cyan-glow/5 text-xs font-bold text-cyan-glow">
                        {CHANNEL_TYPES.find((ct) => ct.value === ch.type)?.icon}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-200">{ch.name}</p>
                        <p className="text-[10px] text-gray-500 uppercase">{ch.type}</p>
                      </div>
                    </div>
                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold ${healthColor(ch.health)}`}>
                      {ch.health.toUpperCase()}
                    </span>
                  </div>
                  {ch.lastPing && (
                    <p className="text-[10px] text-gray-600 font-mono">
                      Last ping: {new Date(ch.lastPing).toLocaleString()}
                    </p>
                  )}
                  <div className="flex gap-2">
                    <button
                      onClick={() => handleToggleChannel(ch.id)}
                      className={`rounded px-2 py-1 text-[10px] font-bold transition-colors ${
                        ch.enabled
                          ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                          : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"
                      }`}
                    >
                      {ch.enabled ? "ENABLED" : "DISABLED"}
                    </button>
                    <button
                      onClick={() => handleTest(ch)}
                      className="rounded border border-cyan-glow/20 px-2 py-1 text-[10px] font-bold text-cyan-glow hover:bg-cyan-glow/10 transition-colors"
                    >
                      TEST
                    </button>
                    <button
                      onClick={() => openEdit(ch)}
                      className="rounded border border-gray-700 px-2 py-1 text-[10px] font-bold text-gray-400 hover:border-gray-600 transition-colors"
                    >
                      EDIT
                    </button>
                    <button
                      onClick={() => handleDelete(ch.id)}
                      className="rounded px-2 py-1 text-[10px] font-bold text-red-400/50 hover:text-red-400 transition-colors"
                    >
                      DELETE
                    </button>
                  </div>
                  {testResult?.id === ch.id && (
                    <div className={`rounded border px-3 py-1.5 text-[10px] ${
                      testResult.ok
                        ? "border-green-500/30 bg-green-500/5 text-green-400"
                        : "border-red-500/30 bg-red-500/5 text-red-400"
                    }`}>
                      {testResult.msg}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </StaggerItem>
      )}

      {/* ---- RULES TAB ---- */}
      {activeTab === "rules" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">SEVERITY</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">CHANNELS</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="px-4 py-3">
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${sevColor(rule.severity)}`}>
                        {rule.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {channels.map((ch) => (
                          <button
                            key={ch.id}
                            onClick={() => handleRuleChannel(rule.id, ch.id, !rule.channelIds.includes(ch.id))}
                            className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${
                              rule.channelIds.includes(ch.id)
                                ? "bg-cyan-glow/15 text-cyan-glow border border-cyan-glow/30"
                                : "bg-gray-800/50 text-gray-600 border border-gray-700 hover:border-gray-600"
                            }`}
                          >
                            {ch.name}
                          </button>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleToggleRule(rule.id)}
                        className={`rounded px-2 py-0.5 text-[10px] font-bold transition-colors ${
                          rule.enabled
                            ? "bg-green-500/15 text-green-400 hover:bg-green-500/25"
                            : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"
                        }`}
                      >
                        {rule.enabled ? "ACTIVE" : "INACTIVE"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </StaggerItem>
      )}

      {/* ---- HISTORY TAB ---- */}
      {activeTab === "history" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">TIME</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">CHANNEL</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">SEVERITY</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">MESSAGE</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="px-4 py-3 text-[10px] text-gray-400 font-mono whitespace-nowrap">
                      {new Date(h.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-gray-500 uppercase">{h.channelType}</span>
                        <span className="text-xs text-gray-300">{h.channelName}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${sevColor(h.severity)}`}>
                        {h.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-300 max-w-xs truncate">{h.message}</td>
                    <td className="px-4 py-3">
                      <span className={`text-[10px] font-bold ${statusColor(h.status)}`}>
                        {h.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
