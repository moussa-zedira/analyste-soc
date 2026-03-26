export type Severity = "low" | "medium" | "high" | "critical";
export type IncidentStatus = "open" | "ack" | "closed";

export interface Event {
  id: string;
  ts: string;
  source: string;
  event_type: string;
  severity: Severity;
  src_ip: string | null;
  dst_ip: string | null;
  username: string | null;
  message: string | null;
  raw: string | null;
}

export interface Incident {
  id: string;
  created_at: string;
  updated_at: string;
  status: IncidentStatus;
  severity: Severity;
  title: string;
  description: string;
  rule_id: string;
  entity_key: string;
  start_ts: string;
  end_ts: string;
  dedup_hash: string;
  suggested_severity: string | null;
}

export interface IncidentDetail extends Incident {
  events: Event[];
}

export interface EventListParams {
  limit?: number;
  offset?: number;
  severity?: string;
  event_type?: string;
  src_ip?: string;
}

export interface IncidentListParams {
  limit?: number;
  offset?: number;
  severity?: string;
  status_filter?: string;
  rule_id?: string;
}

export interface RulesRunResponse {
  rules_evaluated: number;
  incidents_created: number;
}

export interface KpiResponse {
  total_events_24h: number;
  open_incidents: number;
  high_incidents_24h: number;
}

// --- Stats / Visualization types ---

export interface EventsPerMinuteBucket {
  minute: string;
  count: number;
}

export interface HeatmapCell {
  day_of_week: number;
  hour: number;
  count: number;
}

export interface GeoEvent {
  src_ip: string;
  lat: number;
  lon: number;
  country: string;
  city: string;
  event_count: number;
  max_severity: string;
}

export interface GraphNode {
  id: string;
  type: "ip" | "user" | "incident";
  label: string;
  severity: string | null;
  event_count: number | null;
}

export interface GraphEdge {
  source: string;
  target: string;
  weight: number;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// --- MITRE ATT&CK types ---

export interface MitreTechniqueInfo {
  technique_id: string;
  technique_name: string;
  tactic_id: string;
  tactic_name: string;
  url: string;
  rule_ids: string[];
  incident_count: number;
}

export interface MitreTactic {
  id: string;
  name: string;
}

export interface MitreStatsResponse {
  tactics: MitreTactic[];
  techniques: MitreTechniqueInfo[];
  total_mapped_incidents: number;
}

// --- Threat Score types ---

export interface ThreatScoreEntry {
  ip: string;
  score: number;
  factors: Record<string, number | Record<string, number>>;
  updated_at: string;
}

export interface ThreatScoreComputeResponse {
  ips_scored: number;
}

// --- ML types ---

export interface MLDetectResponse {
  anomalies_detected: number;
  incidents_created: number;
  samples_analyzed: number;
  error?: string;
}

export interface MLModelInfo {
  n_samples: number | null;
  n_features: number | null;
  last_trained: string | null;
  contamination: number | null;
  status: string;
}

export interface ClassifyResponse {
  status: string;
  incidents_classified: number;
}

export interface ClassifierInfo {
  status: string;
  n_samples: number | null;
  last_trained: string | null;
}

// --- Chat types ---

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

export interface ChatResponse {
  conversation_id: string;
  response: string;
  context_used: string[];
}

// --- Anomaly types ---

export interface AnomalyRunResponse {
  volume_metrics_evaluated: number;
  ip_metrics_evaluated: number;
  incidents_created: number;
}

export interface AnomalyBaselineStat {
  metric_type: string;
  metric_key: string;
  count: number;
  mean: number;
  stddev: number;
  last_value: number;
}

// --- Scanner types ---

export interface PortResult {
  port: number;
  service: string;
  state: "open" | "closed" | "filtered";
  banner: string | null;
}

export interface CveResult {
  id: string;
  severity: string;
  score: number | null;
  description: string;
  service: string;
}

export interface ReputationResult {
  abuse_score: number;
  is_tor: boolean;
  is_proxy: boolean;
  is_vpn: boolean;
  is_bot: boolean;
  total_reports: number;
  last_reported: string | null;
  source: string;
}

export interface ScanHistoryEntry {
  id: string;
  target: string;
  target_type: string;
  resolved_ip: string | null;
  security_score: number;
  open_ports_count: number;
  scan_duration_ms: number;
  created_at: string;
}

export interface ScannerResult {
  id: string | null;
  target: string;
  target_type: "domain" | "ip";
  resolved_ip: string | null;
  geo: Record<string, unknown> | null;
  dns: Record<string, unknown> | null;
  ssl_cert: Record<string, unknown> | null;
  http_headers: Record<string, unknown> | null;
  security_headers: Record<string, unknown> | null;
  whois_info: Record<string, unknown> | null;
  open_ports: PortResult[];
  ports_scanned: number;
  cves: CveResult[];
  reputation: ReputationResult | null;
  security_score: number;
  score_details: Array<{ check: string; passed: boolean; points: number; max?: number }>;
  scan_duration_ms: number;
  errors: string[];
}

// --- Admin types ---

export interface AdminUser {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  user_id: string | null;
  username: string | null;
  action: string;
  target: string | null;
  details: string;
  ip_address: string | null;
  created_at: string;
}
