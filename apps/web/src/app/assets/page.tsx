"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  getNetmapInventory,
  getNetmapTopology,
  netmapDiscover,
  type NetmapInventoryApi,
  type NetmapServiceApi,
  type NetmapTopologyApi,
  type NetmapDiscoverRequest,
} from "@/lib/apiClient";
import {
  HudHeading,
  HudCard,
  HudButton,
  HudBadge,
  HudStat,
  HudTabs,
  HudField,
  HudInput,
  HudSelect,
  type HudTabItem,
} from "@/components/hud";

type Tab = "list" | "matrix" | "topology";
type Risk = "critical" | "high" | "medium" | "low";

function serviceKey(s: NetmapServiceApi): string {
  return `${s.host}:${s.port}/${s.protocol ?? "tcp"}`;
}

function riskForService(s: NetmapServiceApi): Risk {
  const svc = (s.service ?? "").toLowerCase();
  const port = s.port;
  if (["telnet", "ftp", "rlogin", "rsh", "vnc"].includes(svc)) return "critical";
  if (port === 22 || port === 3389 || port === 445 || svc === "smb" || svc === "rdp") return "high";
  if (port === 80 || port === 8080 || svc === "http") return "medium";
  if (port === 443 || port === 8443 || svc === "https") return "low";
  return "medium";
}

export default function AssetsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("list");
  const [inventory, setInventory] = useState<NetmapInventoryApi | null>(null);
  const [topology, setTopology] = useState<NetmapTopologyApi | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [showDiscoverForm, setShowDiscoverForm] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [discoverError, setDiscoverError] = useState<string | null>(null);
  const [form, setForm] = useState<NetmapDiscoverRequest>({
    target: "",
    scan_types: ["icmp", "tcp_syn"],
    ports: "top100",
    timeout_ms: 2000,
    max_hosts: 256,
    os_detection: true,
    service_detection: true,
    aggressive: false,
  });

  // Filters
  const [filterHost, setFilterHost] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [filterRisk, setFilterRisk] = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [inv, topo] = await Promise.all([getNetmapInventory(), getNetmapTopology()]);
      setInventory(inv);
      setTopology(topo);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Erreur chargement inventaire");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const services = useMemo(() => inventory?.services ?? [], [inventory]);
  const filteredServices = useMemo(() => {
    return services.filter((s) => {
      if (filterHost && !s.host.includes(filterHost)) return false;
      if (filterPort && String(s.port) !== filterPort.trim()) return false;
      if (filterRisk !== "all" && riskForService(s) !== filterRisk) return false;
      return true;
    });
  }, [services, filterHost, filterPort, filterRisk]);

  const uniqueHosts = useMemo(() => {
    const set = new Set(services.map((s) => s.host));
    return Array.from(set).sort();
  }, [services]);

  async function onDiscover() {
    if (!form.target.trim()) {
      setDiscoverError("Target requis (CIDR ou IP)");
      return;
    }
    setDiscovering(true);
    setDiscoverError(null);
    try {
      await netmapDiscover(form);
      setShowDiscoverForm(false);
      await load();
    } catch (e) {
      setDiscoverError(e instanceof Error ? e.message : "Erreur discover");
    } finally {
      setDiscovering(false);
    }
  }

  const tabs: HudTabItem<Tab>[] = [
    { id: "list", label: "List" },
    { id: "matrix", label: "Matrix" },
    { id: "topology", label: "Topology" },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <HudHeading level={1} subtitle="NETWORK MAPPER // LIVE INFRASTRUCTURE DISCOVERY">
          Asset Inventory
        </HudHeading>
        <div className="flex items-center gap-2">
          <HudTabs items={tabs} value={activeTab} onChange={setActiveTab} />
          <HudButton variant="secondary" size="sm" onClick={() => load()}>
            {loading ? "..." : "REFRESH"}
          </HudButton>
          <HudButton variant="primary" size="sm" onClick={() => setShowDiscoverForm(!showDiscoverForm)}>
            + DISCOVER
          </HudButton>
        </div>
      </div>

      <div className="cyan-line" />

      {error && (
        <HudCard tone="alert" className="p-3 text-xs text-neon-pink">{error}</HudCard>
      )}

      {/* Discover Form */}
      {showDiscoverForm && (
        <HudCard className="p-4">
          <h3 className="mb-3 text-xs font-bold text-cyan-glow">Lancer une découverte réseau</h3>
          <div className="grid grid-cols-3 gap-4">
            <HudField className="col-span-2" label="Target (CIDR ou IP)">
              <HudInput
                value={form.target}
                onChange={(e) => setForm({ ...form, target: e.target.value })}
                placeholder="10.0.0.0/24"
                mono
              />
            </HudField>
            <HudField label="Ports">
              <HudSelect value={form.ports} onChange={(e) => setForm({ ...form, ports: e.target.value })}>
                <option value="top100">Top 100</option>
                <option value="top1000">Top 1000</option>
                <option value="all">All (1-65535)</option>
                <option value="1-1024">1-1024</option>
              </HudSelect>
            </HudField>
            <HudField label="Max hosts">
              <HudInput
                type="number"
                value={form.max_hosts ?? 256}
                onChange={(e) => setForm({ ...form, max_hosts: Number(e.target.value) })}
              />
            </HudField>
            <HudField label="Timeout (ms)">
              <HudInput
                type="number"
                value={form.timeout_ms ?? 2000}
                onChange={(e) => setForm({ ...form, timeout_ms: Number(e.target.value) })}
              />
            </HudField>
            <div className="flex items-end gap-3 text-[10px] text-gray-400">
              <label className="inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={!!form.os_detection}
                  onChange={(e) => setForm({ ...form, os_detection: e.target.checked })}
                />
                OS
              </label>
              <label className="inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={!!form.service_detection}
                  onChange={(e) => setForm({ ...form, service_detection: e.target.checked })}
                />
                SERVICE
              </label>
              <label className="inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={!!form.traceroute}
                  onChange={(e) => setForm({ ...form, traceroute: e.target.checked })}
                />
                TRACERT
              </label>
              <label className="inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={!!form.aggressive}
                  onChange={(e) => setForm({ ...form, aggressive: e.target.checked })}
                />
                AGGR
              </label>
            </div>
          </div>
          {discoverError && (
            <HudCard tone="alert" className="mt-3 p-2 text-[10px] text-neon-pink">
              {discoverError}
            </HudCard>
          )}
          <div className="mt-4 flex gap-2">
            <HudButton variant="primary" size="sm" loading={discovering} onClick={onDiscover}>
              {discovering ? "SCANNING..." : "LANCER SCAN"}
            </HudButton>
            <HudButton variant="ghost" size="sm" onClick={() => setShowDiscoverForm(false)}>
              CANCEL
            </HudButton>
          </div>
        </HudCard>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-5 gap-3">
        <HudStat label="HOSTS" value={inventory?.total_hosts ?? 0} />
        <HudStat label="SERVICES" value={inventory?.total_services ?? 0} />
        <HudStat label="SUBNETS" value={inventory?.subnets?.length ?? 0} />
        <HudStat label="OS TYPES" value={Object.keys(inventory?.os_summary ?? {}).length} />
        <HudStat
          label="LAST SCAN"
          value={
            <span className="text-[11px] text-gray-300">
              {topology?.last_scan ? new Date(topology.last_scan).toLocaleString() : "—"}
            </span>
          }
        />
      </div>

      {/* Filters */}
      <HudCard className="flex items-center gap-4 p-3">
        <HudInput
          value={filterHost}
          onChange={(e) => setFilterHost(e.target.value)}
          placeholder="Filter host/IP..."
          className="w-64 text-[10px]"
          mono
          list="asset-hosts"
        />
        <datalist id="asset-hosts">
          {uniqueHosts.map((h) => <option key={h} value={h} />)}
        </datalist>
        <HudInput
          value={filterPort}
          onChange={(e) => setFilterPort(e.target.value)}
          placeholder="Port"
          className="w-24 text-[10px]"
          mono
        />
        <HudSelect
          value={filterRisk}
          onChange={(e) => setFilterRisk(e.target.value)}
          className="w-auto text-[10px]"
        >
          <option value="all">All risk</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </HudSelect>
        <span className="ml-auto text-[10px] text-gray-500">
          {filteredServices.length} / {services.length} services
        </span>
      </HudCard>

      {/* List tab */}
      {activeTab === "list" && (
        <HudCard className="overflow-hidden p-0">
          {services.length === 0 && !loading ? (
            <div className="p-8 text-center text-xs text-gray-500">
              Aucun service découvert. Lance un <span className="text-cyan-glow">+ DISCOVER</span> pour scanner un réseau.
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-cyan-glow/10">
                  <Th>Host</Th>
                  <Th>Port</Th>
                  <Th>Proto</Th>
                  <Th>Service</Th>
                  <Th>Version</Th>
                  <Th>Banner</Th>
                  <Th>State</Th>
                  <Th>Risk</Th>
                </tr>
              </thead>
              <tbody>
                {filteredServices.map((s) => {
                  const risk = riskForService(s);
                  return (
                    <tr key={serviceKey(s)} className="border-b border-gray-800/50 hover:bg-cyan-glow/5">
                      <td className="px-4 py-2 font-mono text-[11px] text-gray-200">{s.host}</td>
                      <td className="px-4 py-2 font-mono text-[11px] text-cyan-glow">{s.port}</td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{s.protocol ?? "tcp"}</td>
                      <td className="px-4 py-2 text-[11px] text-gray-200">{s.service ?? "-"}</td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{s.version ?? "-"}</td>
                      <td className="px-4 py-2 truncate max-w-[240px] text-[10px] text-gray-500" title={s.banner ?? ""}>
                        {s.banner ?? "-"}
                      </td>
                      <td className="px-4 py-2 text-[10px] text-gray-400">{s.state ?? "open"}</td>
                      <td className="px-4 py-2">
                        <HudBadge tone={risk} mono>{risk}</HudBadge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </HudCard>
      )}

      {/* Matrix tab (OS × device_summary) */}
      {activeTab === "matrix" && (
        <div className="grid grid-cols-2 gap-4">
          <HudCard className="p-4">
            <h3 className="mb-3 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
              OS Distribution
            </h3>
            {Object.keys(inventory?.os_summary ?? {}).length === 0 ? (
              <div className="text-[11px] text-gray-500">Pas de fingerprint OS disponible.</div>
            ) : (
              <div className="space-y-2">
                {Object.entries(inventory!.os_summary).map(([os, count]) => {
                  const max = Math.max(...Object.values(inventory!.os_summary));
                  const pct = max > 0 ? (count / max) * 100 : 0;
                  return (
                    <div key={os} className="space-y-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-gray-300">{os}</span>
                        <span className="text-cyan-glow">{count}</span>
                      </div>
                      <div className="h-2 rounded bg-black/40">
                        <div className="h-full rounded bg-cyan-glow/60" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </HudCard>
          <HudCard className="p-4">
            <h3 className="mb-3 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Device Types
            </h3>
            {Object.keys(inventory?.device_summary ?? {}).length === 0 ? (
              <div className="text-[11px] text-gray-500">Pas de device type détecté.</div>
            ) : (
              <div className="space-y-2">
                {Object.entries(inventory!.device_summary).map(([dt, count]) => {
                  const max = Math.max(...Object.values(inventory!.device_summary));
                  const pct = max > 0 ? (count / max) * 100 : 0;
                  return (
                    <div key={dt} className="space-y-1">
                      <div className="flex justify-between text-[10px]">
                        <span className="text-gray-300">{dt}</span>
                        <span className="text-purple-400">{count}</span>
                      </div>
                      <div className="h-2 rounded bg-black/40">
                        <div className="h-full rounded bg-purple-500/60" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </HudCard>
          <HudCard className="col-span-2 p-4">
            <h3 className="mb-3 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
              Subnets
            </h3>
            {(inventory?.subnets ?? []).length === 0 ? (
              <div className="text-[11px] text-gray-500">Pas encore de sous-réseau découvert.</div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-cyan-glow/10">
                    <Th>CIDR</Th>
                    <Th>Hosts</Th>
                    <Th>Services</Th>
                  </tr>
                </thead>
                <tbody>
                  {inventory!.subnets.map((sb) => (
                    <tr key={sb.cidr} className="border-b border-gray-800/50">
                      <td className="px-4 py-2 font-mono text-[11px] text-cyan-glow">{sb.cidr}</td>
                      <td className="px-4 py-2 text-[11px] text-gray-200">{sb.hosts}</td>
                      <td className="px-4 py-2 text-[11px] text-gray-400">{sb.services ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </HudCard>
        </div>
      )}

      {/* Topology tab */}
      {activeTab === "topology" && (
        <HudCard className="p-6">
          <h3 className="mb-4 text-xs font-bold text-cyan-glow" style={{ fontFamily: "Orbitron, sans-serif" }}>
            Network Topology ({topology?.total_hosts ?? 0} hosts · {topology?.total_edges ?? 0} edges · {topology?.total_segments ?? 0} segments)
          </h3>
          {(!topology || topology.nodes.length === 0) ? (
            <div className="py-8 text-center text-xs text-gray-500">
              Aucune topologie. Active <span className="text-cyan-glow">traceroute</span> dans le scan pour tracer les liens.
            </div>
          ) : (
            <TopologySvg topology={topology} />
          )}
        </HudCard>
      )}
    </div>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-3 text-left text-[9px] font-bold uppercase tracking-wider text-gray-500">
      {children}
    </th>
  );
}

function TopologySvg({ topology }: { topology: NetmapTopologyApi }) {
  const { nodes, edges } = topology;
  const radius = 240;
  const cx = 300;
  const cy = 200;
  const positioned = nodes.map((n, i) => {
    const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
    return { ...n, x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius };
  });
  const byId = new Map(positioned.map((n) => [n.id, n]));
  return (
    <svg viewBox="0 0 600 420" className="w-full" style={{ maxHeight: 500 }}>
      {edges.map((e, i) => {
        const from = byId.get(e.from);
        const to = byId.get(e.to);
        if (!from || !to) return null;
        return (
          <line
            key={i}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            stroke="rgba(0, 229, 255, 0.25)"
            strokeWidth="1.5"
            strokeDasharray="4,4"
          />
        );
      })}
      {positioned.map((n) => (
        <g key={n.id}>
          <circle cx={n.x} cy={n.y} r="16" fill="rgba(0,0,0,0.6)" stroke="#22d3ee" strokeWidth="1.2" />
          <circle cx={n.x} cy={n.y} r="4" fill="#22d3ee" opacity="0.7" />
          <text x={n.x} y={n.y + 30} textAnchor="middle" fill="#22d3ee" fontSize="8" fontFamily="monospace" opacity="0.85">
            {n.label ?? n.hostname ?? n.ip ?? n.id}
          </text>
        </g>
      ))}
    </svg>
  );
}
