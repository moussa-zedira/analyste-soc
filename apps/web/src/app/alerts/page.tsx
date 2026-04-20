"use client";

import { useCallback, useEffect, useState } from "react";
import { PageTransition, StaggerItem } from "@/components/PageTransition";

import {
  createAlertChannel,
  createAlertRule,
  deleteAlertChannel,
  deleteAlertRule,
  listAlertChannels,
  listAlertDedupFingerprints,
  listAlertRules,
  testAlertChannel,
  updateAlertChannel,
  updateAlertRule,
  type AlertChannelApi,
  type AlertRuleApi,
} from "@/lib/apiClient";

type ChannelType = "slack" | "discord" | "email" | "pagerduty" | "teams" | "telegram" | "webhook";

const CHANNEL_TYPES: { value: ChannelType; label: string; icon: string }[] = [
  { value: "slack", label: "Slack", icon: "#" },
  { value: "discord", label: "Discord", icon: "D" },
  { value: "email", label: "Email", icon: "@" },
  { value: "pagerduty", label: "PagerDuty", icon: "P" },
  { value: "teams", label: "Teams", icon: "T" },
  { value: "telegram", label: "Telegram", icon: "TG" },
  { value: "webhook", label: "Webhook", icon: "W" },
];

const CHANNEL_FIELDS: Record<ChannelType, { key: string; label: string; placeholder: string }[]> = {
  slack: [
    { key: "webhook_url", label: "Webhook URL", placeholder: "https://hooks.slack.com/services/..." },
    { key: "channel", label: "Channel", placeholder: "#security-alerts" },
  ],
  discord: [{ key: "webhook_url", label: "Webhook URL", placeholder: "https://discord.com/api/webhooks/..." }],
  email: [
    { key: "smtp_host", label: "SMTP Host", placeholder: "smtp.example.com" },
    { key: "smtp_port", label: "SMTP Port", placeholder: "587" },
    { key: "from_address", label: "From", placeholder: "alerts@example.com" },
    { key: "to_addresses", label: "To (comma)", placeholder: "soc@example.com" },
  ],
  pagerduty: [
    { key: "routing_key", label: "Routing Key", placeholder: "your-pagerduty-routing-key" },
  ],
  teams: [{ key: "webhook_url", label: "Webhook URL", placeholder: "https://outlook.office.com/webhook/..." }],
  telegram: [
    { key: "bot_token", label: "Bot Token", placeholder: "123456:ABC-DEF..." },
    { key: "chat_id", label: "Chat ID", placeholder: "-1001234567890" },
  ],
  webhook: [
    { key: "url", label: "URL", placeholder: "https://example.com/hook" },
  ],
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

function parseConfig(s: string): Record<string, string> {
  try { const o = JSON.parse(s || "{}"); return typeof o === "object" && o ? o as Record<string, string> : {}; }
  catch { return {}; }
}

function sevColor(s: string) {
  if (s === "critical") return "bg-red-500/15 text-red-400";
  if (s === "high") return "bg-orange-500/15 text-orange-400";
  if (s === "medium") return "bg-yellow-500/15 text-yellow-400";
  if (s === "low") return "bg-blue-500/15 text-blue-400";
  return "bg-gray-500/15 text-gray-400";
}

export default function AlertChannelsPage() {
  const [activeTab, setActiveTab] = useState<"channels" | "rules" | "history">("channels");
  const [channels, setChannels] = useState<AlertChannelApi[]>([]);
  const [rules, setRules] = useState<AlertRuleApi[]>([]);
  const [dedup, setDedup] = useState<{ fingerprint: string; count: number; first_seen: string; last_seen: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);

  // channel form
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState<ChannelType>("slack");
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [formMinSev, setFormMinSev] = useState("high");

  // rule form
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [ruleDesc, setRuleDesc] = useState("");
  const [ruleChannel, setRuleChannel] = useState("");
  const [ruleConditions, setRuleConditions] = useState('{"severity": "high"}');
  const [rulePriority, setRulePriority] = useState(0);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [ch, rl, dd] = await Promise.all([
        listAlertChannels(),
        listAlertRules(),
        listAlertDedupFingerprints().catch(() => ({ fingerprints: [] })),
      ]);
      setChannels(ch);
      setRules(rl);
      setDedup(dd.fingerprints || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void reload(); }, [reload]);

  const resetForm = () => {
    setFormName(""); setFormType("slack"); setFormConfig({}); setFormMinSev("high");
    setEditingId(null); setShowForm(false);
  };

  const openEdit = (ch: AlertChannelApi) => {
    setEditingId(ch.id);
    setFormName(ch.name);
    setFormType((ch.channel_type as ChannelType) || "slack");
    setFormConfig(parseConfig(ch.config_json));
    setFormMinSev(ch.min_severity);
    setShowForm(true);
  };

  const handleSave = async () => {
    if (!formName.trim()) return;
    try {
      if (editingId) {
        await updateAlertChannel(editingId, {
          name: formName, channel_type: formType,
          config_json: JSON.stringify(formConfig), min_severity: formMinSev,
        });
        setActionMsg(`Channel ${formName} mis à jour`);
      } else {
        await createAlertChannel({
          channel_type: formType, name: formName,
          config_json: JSON.stringify(formConfig), min_severity: formMinSev,
        });
        setActionMsg(`Channel ${formName} créé`);
      }
      resetForm();
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Supprimer le channel "${name}" ?`)) return;
    try {
      await deleteAlertChannel(id);
      setActionMsg(`Channel supprimé`);
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleToggleChannel = async (ch: AlertChannelApi) => {
    try {
      await updateAlertChannel(ch.id, { enabled: !ch.enabled });
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleTest = async (ch: AlertChannelApi) => {
    try {
      const r = await testAlertChannel(ch.id);
      setActionMsg(`Test ${ch.name}: ${r.status}${r.message ? ` — ${r.message}` : ""}`);
    } catch (e) {
      setActionMsg(`Test ${ch.name}: KO — ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleCreateRule = async () => {
    if (!ruleName.trim() || !ruleChannel) { setActionMsg("Nom et channel obligatoires"); return; }
    try {
      JSON.parse(ruleConditions || "{}"); // validate
    } catch { setActionMsg("conditions_json: JSON invalide"); return; }
    try {
      await createAlertRule({
        name: ruleName, description: ruleDesc,
        conditions_json: ruleConditions || "{}",
        channel_id: ruleChannel, priority: rulePriority,
      });
      setActionMsg(`Règle ${ruleName} créée`);
      setRuleName(""); setRuleDesc(""); setRuleConditions('{"severity": "high"}'); setRulePriority(0);
      setShowRuleForm(false);
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleToggleRule = async (r: AlertRuleApi) => {
    try {
      await updateAlertRule(r.id, { enabled: !r.enabled });
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleDeleteRule = async (id: string, name: string) => {
    if (!confirm(`Supprimer la règle "${name}" ?`)) return;
    try {
      await deleteAlertRule(id);
      setActionMsg("Règle supprimée");
      void reload();
    } catch (e) {
      setActionMsg(`Erreur: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <div>
          <h1 className="hud-heading text-xl font-bold tracking-widest text-cyan-glow">Alert Channels</h1>
          <p className="mt-1 text-[10px] tracking-widest text-cyan-glow/30">
            NOTIFICATION CHANNELS // ROUTING RULES // DEDUP STATUS
          </p>
        </div>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {error && <StaggerItem><div className="glass-panel border border-red-500/30 p-3 text-[11px] text-red-300">{error}</div></StaggerItem>}
      {actionMsg && <StaggerItem><div className="glass-panel border border-cyan-glow/30 p-3 text-[11px] text-cyan-200">{actionMsg}</div></StaggerItem>}

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
              {tab === "channels" ? `CHANNELS (${channels.length})` : tab === "rules" ? `ROUTING RULES (${rules.length})` : `DEDUP (${dedup.length})`}
            </button>
          ))}
          <button onClick={() => void reload()} className="ml-auto rounded-md border border-gray-700/50 bg-gray-900/50 px-3 py-2 text-[10px] font-bold uppercase tracking-wider text-gray-400 hover:border-cyan-glow/20 hover:text-cyan-dim">
            {loading ? "…" : "REFRESH"}
          </button>
        </div>
      </StaggerItem>

      {activeTab === "channels" && (
        <StaggerItem>
          <div className="space-y-4">
            <div className="flex justify-end">
              <button
                onClick={() => { resetForm(); setShowForm(true); }}
                className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20"
              >
                + ADD CHANNEL
              </button>
            </div>

            {showForm && (
              <div className="glass-panel space-y-4 p-6">
                <h3 className="text-[10px] font-bold tracking-widest text-gray-500">{editingId ? "EDIT CHANNEL" : "NEW CHANNEL"}</h3>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-[10px] tracking-widest text-gray-500">NAME</label>
                    <input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Channel name"
                      className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1 block text-[10px] tracking-widest text-gray-500">TYPE</label>
                    <select value={formType} onChange={(e) => { setFormType(e.target.value as ChannelType); setFormConfig({}); }}
                      className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                      {CHANNEL_TYPES.map((ct) => <option key={ct.value} value={ct.value}>{ct.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-[10px] tracking-widest text-gray-500">MIN SEVERITY</label>
                    <select value={formMinSev} onChange={(e) => setFormMinSev(e.target.value)}
                      className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  {(CHANNEL_FIELDS[formType] || []).map((field) => (
                    <div key={field.key}>
                      <label className="mb-1 block text-[10px] tracking-widest text-gray-500">{field.label.toUpperCase()}</label>
                      <input value={formConfig[field.key] || ""} onChange={(e) => setFormConfig((p) => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
                    </div>
                  ))}
                </div>
                <div className="flex gap-3">
                  <button onClick={() => void handleSave()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20">
                    {editingId ? "UPDATE" : "CREATE"}
                  </button>
                  <button onClick={resetForm} className="rounded-md border border-gray-700 px-6 py-2 text-[10px] font-bold tracking-widest text-gray-500 hover:border-gray-600">
                    CANCEL
                  </button>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {!loading && channels.length === 0 && <div className="glass-panel p-4 text-[11px] text-gray-500">Aucun channel.</div>}
              {channels.map((ch) => {
                const cfg = parseConfig(ch.config_json);
                const cfgPreview = Object.entries(cfg).slice(0, 2).map(([k, v]) => `${k}=${String(v).slice(0, 30)}`).join(", ");
                return (
                  <div key={ch.id} className="glass-panel space-y-3 p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 items-center justify-center rounded-md border border-cyan-glow/20 bg-cyan-glow/5 text-xs font-bold text-cyan-glow">
                          {CHANNEL_TYPES.find((c) => c.value === ch.channel_type)?.icon || "?"}
                        </div>
                        <div>
                          <p className="text-sm font-medium text-gray-200">{ch.name}</p>
                          <p className="text-[10px] uppercase text-gray-500">{ch.channel_type} · min: {ch.min_severity}</p>
                        </div>
                      </div>
                    </div>
                    {cfgPreview && <p className="truncate font-mono text-[10px] text-gray-600">{cfgPreview}</p>}
                    <div className="flex flex-wrap gap-2">
                      <button onClick={() => void handleToggleChannel(ch)}
                        className={`rounded px-2 py-1 text-[10px] font-bold ${ch.enabled ? "bg-green-500/15 text-green-400 hover:bg-green-500/25" : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"}`}>
                        {ch.enabled ? "ENABLED" : "DISABLED"}
                      </button>
                      <button onClick={() => void handleTest(ch)} className="rounded border border-cyan-glow/20 px-2 py-1 text-[10px] font-bold text-cyan-glow hover:bg-cyan-glow/10">TEST</button>
                      <button onClick={() => openEdit(ch)} className="rounded border border-gray-700 px-2 py-1 text-[10px] font-bold text-gray-400 hover:border-gray-600">EDIT</button>
                      <button onClick={() => void handleDelete(ch.id, ch.name)} className="rounded px-2 py-1 text-[10px] font-bold text-red-400/50 hover:text-red-400">DELETE</button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </StaggerItem>
      )}

      {activeTab === "rules" && (
        <StaggerItem>
          <div className="space-y-4">
            <div className="flex justify-end">
              <button onClick={() => setShowRuleForm((v) => !v)} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-4 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20">
                + ADD RULE
              </button>
            </div>
            {showRuleForm && (
              <div className="glass-panel space-y-3 p-6">
                <h3 className="text-[10px] font-bold tracking-widest text-gray-500">NEW ROUTING RULE</h3>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <input value={ruleName} onChange={(e) => setRuleName(e.target.value)} placeholder="Rule name"
                    className="rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
                  <select value={ruleChannel} onChange={(e) => setRuleChannel(e.target.value)}
                    className="rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 focus:border-cyan-glow/40 focus:outline-none">
                    <option value="">Select channel…</option>
                    {channels.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.channel_type})</option>)}
                  </select>
                  <input value={ruleDesc} onChange={(e) => setRuleDesc(e.target.value)} placeholder="Description"
                    className="rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
                  <input type="number" value={rulePriority} onChange={(e) => setRulePriority(parseInt(e.target.value) || 0)} placeholder="Priority"
                    className="rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-sm text-gray-200 focus:border-cyan-glow/40 focus:outline-none" />
                </div>
                <textarea value={ruleConditions} onChange={(e) => setRuleConditions(e.target.value)} rows={3}
                  placeholder='{"severity": "high"}'
                  className="w-full rounded-md border border-gray-700 bg-gray-900/80 px-3 py-2 font-mono text-xs text-gray-200 placeholder-gray-600 focus:border-cyan-glow/40 focus:outline-none" />
                <div className="flex gap-3">
                  <button onClick={() => void handleCreateRule()} className="rounded-md border border-cyan-glow/30 bg-cyan-glow/10 px-6 py-2 text-[10px] font-bold tracking-widest text-cyan-glow hover:bg-cyan-glow/20">CREATE</button>
                  <button onClick={() => setShowRuleForm(false)} className="rounded-md border border-gray-700 px-6 py-2 text-[10px] font-bold tracking-widest text-gray-500 hover:border-gray-600">CANCEL</button>
                </div>
              </div>
            )}

            <div className="glass-panel overflow-hidden">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">NAME</th>
                    <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">CONDITIONS</th>
                    <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">CHANNEL</th>
                    <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">PRIO</th>
                    <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">STATUS</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody>
                  {!loading && rules.length === 0 && (
                    <tr><td colSpan={6} className="px-4 py-6 text-center text-[11px] text-gray-500">Aucune règle.</td></tr>
                  )}
                  {rules.map((rule) => {
                    const ch = channels.find((c) => c.id === rule.channel_id);
                    return (
                      <tr key={rule.id} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                        <td className="px-4 py-3">
                          <p className="text-xs text-gray-200">{rule.name}</p>
                          {rule.description && <p className="text-[10px] text-gray-500">{rule.description}</p>}
                        </td>
                        <td className="max-w-xs px-4 py-3">
                          <code className="block truncate text-[10px] text-cyan-dim">{rule.conditions_json}</code>
                        </td>
                        <td className="px-4 py-3 text-[11px] text-gray-300">{ch ? `${ch.name} (${ch.channel_type})` : <span className="text-red-400">orphan</span>}</td>
                        <td className="px-4 py-3 text-[10px] font-mono text-gray-400">{rule.priority}</td>
                        <td className="px-4 py-3">
                          <button onClick={() => void handleToggleRule(rule)}
                            className={`rounded px-2 py-0.5 text-[10px] font-bold ${rule.enabled ? "bg-green-500/15 text-green-400 hover:bg-green-500/25" : "bg-gray-700/50 text-gray-500 hover:bg-gray-700"}`}>
                            {rule.enabled ? "ACTIVE" : "INACTIVE"}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <button onClick={() => void handleDeleteRule(rule.id, rule.name)} className="rounded px-2 py-1 text-[10px] font-bold text-red-400/50 hover:text-red-400">DELETE</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </StaggerItem>
      )}

      {activeTab === "history" && (
        <StaggerItem>
          <div className="glass-panel overflow-hidden">
            <p className="border-b border-gray-800 px-4 py-2 text-[10px] text-gray-500">
              Empreintes de dédoublonnage : alerts identiques regroupées par fingerprint pour limiter le bruit.
            </p>
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">FINGERPRINT</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">COUNT</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">FIRST SEEN</th>
                  <th className="px-4 py-3 text-[10px] font-bold tracking-widest text-gray-500">LAST SEEN</th>
                </tr>
              </thead>
              <tbody>
                {!loading && dedup.length === 0 && (
                  <tr><td colSpan={4} className="px-4 py-6 text-center text-[11px] text-gray-500">Aucun fingerprint actif.</td></tr>
                )}
                {dedup.map((d) => (
                  <tr key={d.fingerprint} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                    <td className="max-w-xs truncate px-4 py-3 font-mono text-[10px] text-cyan-dim">{d.fingerprint}</td>
                    <td className="px-4 py-3 text-[10px] font-mono text-gray-300">{d.count}</td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-[10px] text-gray-400">{new Date(d.first_seen).toLocaleString()}</td>
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-[10px] text-gray-400">{new Date(d.last_seen).toLocaleString()}</td>
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
