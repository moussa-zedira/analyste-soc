"use client";

import { useCallback, useEffect, useState } from "react";
import { PageTransition, StaggerItem } from "@/components/PageTransition";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudTabs,
  HudField,
  HudInput,
  HudSelect,
  HudTextarea,
  type HudTabItem,
} from "@/components/hud";

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
type Tab = "channels" | "rules" | "history";

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

export default function AlertChannelsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("channels");
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

  const tabs: HudTabItem<Tab>[] = [
    { id: "channels", label: "Channels", count: channels.length },
    { id: "rules", label: "Routing Rules", count: rules.length },
    { id: "history", label: "Dedup", count: dedup.length },
  ];

  return (
    <PageTransition className="space-y-4">
      <StaggerItem>
        <HudHeading level={1} subtitle="NOTIFICATION CHANNELS // ROUTING RULES // DEDUP STATUS">
          Alert Channels
        </HudHeading>
      </StaggerItem>

      <StaggerItem><div className="cyan-line" /></StaggerItem>

      {error && (
        <StaggerItem>
          <HudCard tone="alert" className="p-3 text-[11px] text-neon-pink">{error}</HudCard>
        </StaggerItem>
      )}
      {actionMsg && (
        <StaggerItem>
          <HudCard className="p-3 text-[11px] text-cyan-200">{actionMsg}</HudCard>
        </StaggerItem>
      )}

      <StaggerItem>
        <div className="flex items-center gap-2">
          <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />
          <HudButton variant="secondary" size="sm" className="ml-auto" onClick={() => void reload()}>
            {loading ? "…" : "REFRESH"}
          </HudButton>
        </div>
      </StaggerItem>

      {activeTab === "channels" && (
        <StaggerItem>
          <div className="space-y-4">
            <div className="flex justify-end">
              <HudButton variant="primary" size="sm" onClick={() => { resetForm(); setShowForm(true); }}>
                + ADD CHANNEL
              </HudButton>
            </div>

            {showForm && (
              <HudCard className="space-y-4 p-6">
                <h3 className="text-[10px] font-bold tracking-widest text-gray-500">{editingId ? "EDIT CHANNEL" : "NEW CHANNEL"}</h3>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <HudField label="Name">
                    <HudInput value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Channel name" />
                  </HudField>
                  <HudField label="Type">
                    <HudSelect value={formType} onChange={(e) => { setFormType(e.target.value as ChannelType); setFormConfig({}); }}>
                      {CHANNEL_TYPES.map((ct) => <option key={ct.value} value={ct.value}>{ct.label}</option>)}
                    </HudSelect>
                  </HudField>
                  <HudField label="Min Severity">
                    <HudSelect value={formMinSev} onChange={(e) => setFormMinSev(e.target.value)}>
                      {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </HudSelect>
                  </HudField>
                </div>
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  {(CHANNEL_FIELDS[formType] || []).map((field) => (
                    <HudField key={field.key} label={field.label}>
                      <HudInput
                        value={formConfig[field.key] || ""}
                        onChange={(e) => setFormConfig((p) => ({ ...p, [field.key]: e.target.value }))}
                        placeholder={field.placeholder}
                        mono
                      />
                    </HudField>
                  ))}
                </div>
                <div className="flex gap-3">
                  <HudButton variant="primary" onClick={() => void handleSave()}>
                    {editingId ? "UPDATE" : "CREATE"}
                  </HudButton>
                  <HudButton variant="ghost" onClick={resetForm}>CANCEL</HudButton>
                </div>
              </HudCard>
            )}

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              {!loading && channels.length === 0 && <HudCard className="p-4 text-[11px] text-gray-500">Aucun channel.</HudCard>}
              {channels.map((ch) => {
                const cfg = parseConfig(ch.config_json);
                const cfgPreview = Object.entries(cfg).slice(0, 2).map(([k, v]) => `${k}=${String(v).slice(0, 30)}`).join(", ");
                return (
                  <HudCard key={ch.id} className="space-y-3 p-4">
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
                      <HudButton
                        size="sm"
                        variant={ch.enabled ? "matrix" : "ghost"}
                        onClick={() => void handleToggleChannel(ch)}
                      >
                        {ch.enabled ? "ENABLED" : "DISABLED"}
                      </HudButton>
                      <HudButton size="sm" variant="secondary" onClick={() => void handleTest(ch)}>TEST</HudButton>
                      <HudButton size="sm" variant="ghost" onClick={() => openEdit(ch)}>EDIT</HudButton>
                      <HudButton size="sm" variant="danger" onClick={() => void handleDelete(ch.id, ch.name)}>DELETE</HudButton>
                    </div>
                  </HudCard>
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
              <HudButton variant="primary" size="sm" onClick={() => setShowRuleForm((v) => !v)}>
                + ADD RULE
              </HudButton>
            </div>
            {showRuleForm && (
              <HudCard className="space-y-3 p-6">
                <h3 className="text-[10px] font-bold tracking-widest text-gray-500">NEW ROUTING RULE</h3>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <HudInput value={ruleName} onChange={(e) => setRuleName(e.target.value)} placeholder="Rule name" mono />
                  <HudSelect value={ruleChannel} onChange={(e) => setRuleChannel(e.target.value)}>
                    <option value="">Select channel…</option>
                    {channels.map((c) => <option key={c.id} value={c.id}>{c.name} ({c.channel_type})</option>)}
                  </HudSelect>
                  <HudInput value={ruleDesc} onChange={(e) => setRuleDesc(e.target.value)} placeholder="Description" mono />
                  <HudInput type="number" value={rulePriority} onChange={(e) => setRulePriority(parseInt(e.target.value) || 0)} placeholder="Priority" mono />
                </div>
                <HudTextarea value={ruleConditions} onChange={(e) => setRuleConditions(e.target.value)} rows={3} placeholder='{"severity": "high"}' />
                <div className="flex gap-3">
                  <HudButton variant="primary" onClick={() => void handleCreateRule()}>CREATE</HudButton>
                  <HudButton variant="ghost" onClick={() => setShowRuleForm(false)}>CANCEL</HudButton>
                </div>
              </HudCard>
            )}

            <HudCard className="overflow-hidden p-0">
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
                          <HudButton
                            size="sm"
                            variant={rule.enabled ? "matrix" : "ghost"}
                            onClick={() => void handleToggleRule(rule)}
                          >
                            {rule.enabled ? "ACTIVE" : "INACTIVE"}
                          </HudButton>
                        </td>
                        <td className="px-4 py-3">
                          <HudButton size="sm" variant="danger" onClick={() => void handleDeleteRule(rule.id, rule.name)}>DELETE</HudButton>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </HudCard>
          </div>
        </StaggerItem>
      )}

      {activeTab === "history" && (
        <StaggerItem>
          <HudCard className="overflow-hidden p-0">
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
          </HudCard>
        </StaggerItem>
      )}
    </PageTransition>
  );
}
