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
  ti_score: number | null;
  ti_tags: string | null;
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

// --- MITRE coverage (Vague 8 endpoints) ---

export interface MitreCoverageTechnique {
  technique_id: string;
  name: string;
  rule_id: string;
}

export interface MitreCoverageTactic {
  id: string;
  name: string;
  techniques: MitreCoverageTechnique[];
}

export interface MitreCoverageResponse {
  tactics: MitreCoverageTactic[];
  totals: {
    techniques_known: number;
    techniques_covered: number;
    rules_mapped: number;
  };
}

export interface MitreNavigatorTechnique {
  techniqueID: string;
  tactic: string;
  score: number;
  comment: string;
  enabled: boolean;
}

export interface MitreNavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: string;
  description: string;
  techniques: MitreNavigatorTechnique[];
  gradient: { colors: string[]; minValue: number; maxValue: number };
}

// --- Red Team Campaign types (Vague 11) ---

export interface CampaignScenarioInfo {
  file?: string;
  name?: string;
  description?: string;
  target?: string;
  stages?: number;
  tags?: string[];
  mitre_tactics?: string[];
  error?: string;
}

export type CampaignStageStatus =
  | "pending"
  | "running"
  | "success"
  | "failed"
  | "skipped";

export type CampaignStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface CampaignStageResult {
  stage_id: string;
  name: string;
  action: string;
  status: CampaignStageStatus;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number;
  output: Record<string, unknown>;
  error: string | null;
  iocs: Record<string, unknown>[];
}

export interface CampaignEvent {
  ts: string;
  stage_id: string;
  kind: string;
  message: string;
  data: Record<string, unknown>;
}

export interface CampaignState {
  id: string;
  scenario_name: string;
  target: string;
  status: CampaignStatus;
  started_at: string | null;
  ended_at: string | null;
  duration_ms: number;
  progress: number;
  current_stage: string | null;
  stages: CampaignStageResult[];
  timeline: CampaignEvent[];
  iocs: Record<string, unknown>[];
  summary: Record<string, unknown>;
}

export interface CampaignSummary {
  id: string;
  scenario_name: string;
  target: string;
  status: CampaignStatus;
  progress: number;
  current_stage: string | null;
  started_at: string | null;
  ended_at: string | null;
  stages_total: number;
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

// --- Log Sources types ---

export interface LogSourceStatus {
  source: string;
  event_count: number;
  last_seen: string | null;
  events_per_minute: number;
}

// --- Threat Intelligence types ---

export interface TILookupResult {
  ip: string;
  risk_score: number;
  is_malicious: boolean;
  tags: string[];
  providers: TIProviderResult[];
}

export interface TIProviderResult {
  source: string;
  risk_score: number;
  is_malicious: boolean;
  categories: string[];
  tags: string[];
  total_reports: number;
  cached: boolean;
}

export interface TIStatsResponse {
  cache_entries: number;
  providers_configured: string[];
  abuseipdb_daily_used: number;
  abuseipdb_daily_limit: number;
  otx_hourly_used: number;
  otx_hourly_limit: number;
}

// --- SIGMA Rules types ---

export interface SigmaRuleInfo {
  id: number;
  name: string;
  description: string | null;
  level: string;
  enabled: boolean;
  author: string | null;
  created_at: string;
}

// --- Investigation / OSINT types ---

export interface InvestigateResult {
  target: string;
  target_type: "ip" | "domain";
  resolved_ip: string | null;
  geo: Record<string, unknown> | null;
  dns: Record<string, string[]> | null;
  whois: {
    registrar: string | null;
    creation_date: string | null;
    expiration_date: string | null;
    name_servers: string[];
    org: string | null;
    country: string | null;
  } | null;
  threat_intel: TILookupResult | null;
  event_count: number;
  recent_events: {
    id: string;
    ts: string;
    event_type: string;
    severity: string;
    message: string | null;
    username: string | null;
  }[];
  event_types: { type: string; count: number }[];
  incident_count: number;
  recent_incidents: {
    id: string;
    title: string;
    severity: string;
    status: string;
    created_at: string;
    rule_id: string;
  }[];
  threat_score: {
    score: number;
    factors: Record<string, unknown>;
    updated_at: string;
  } | null;
  reverse_dns: string | null;
  related_users: { username: string; event_count: number }[];
  timeline: { hour: string; count: number }[];
}

// --- Recon / OSINT types ---

export interface ReconResult {
  target: string;
  target_type: "ip" | "domain";
  resolved_ip: string | null;
  whois: Record<string, unknown> | null;
  dns_records: Record<string, string[]> | null;
  subdomains: { subdomain: string; ip: string | null }[] | null;
  reverse_ip: string[] | null;
  geo: Record<string, unknown> | null;
  tech_stack: {
    server: string | null;
    powered_by: string | null;
    framework: string | null;
    cms: string | null;
    cdn: string | null;
    language: string | null;
    cookies: string[];
    detected: string[];
  } | null;
  ssl_cert: {
    subject: string | null;
    issuer: string | null;
    not_before: string | null;
    not_after: string | null;
    days_remaining: number | null;
    serial: string | null;
    san: string[];
    protocol: string | null;
    cipher: string | null;
    key_size: number | null;
    is_expired: boolean;
  } | null;
  headers: {
    raw: Record<string, string>;
    security_missing: string[];
    security_score: number;
    max_score: number;
    details: { header: string; present: boolean; points: number; description: string }[];
  } | null;
  wayback: {
    snapshots_count: number;
    first_seen: string | null;
    last_seen: string | null;
    urls: { timestamp: string; url: string; status: string; mimetype: string }[];
  } | null;
  google_dorks: { label: string; query: string; category: string }[];
  robots_sitemap: {
    robots_txt: string | null;
    disallowed: string[];
    sitemaps: string[];
  } | null;
  open_ports: { port: number; service: string; state: string }[];
  emails_found: string[];
  errors: string[];
  scan_duration_ms: number;
}

// --- Pentest Lab types ---

export interface BruteForceResult {
  target: string;
  service: string;
  port: number;
  attempts: number;
  found_credentials: { username: string; password: string }[];
  duration_ms: number;
  errors: string[];
}

export interface WebVulnerability {
  type: string;
  severity: string;
  url: string;
  payload: string;
  evidence: string;
  description: string;
}

export interface WebScanResult {
  target: string;
  vulnerabilities: WebVulnerability[];
  total_found: number;
  by_severity: Record<string, number>;
  tests_run: string[];
  duration_ms: number;
}

export interface StressTestResult {
  target: string;
  total_requests: number;
  successful: number;
  failed: number;
  avg_response_ms: number;
  min_response_ms: number;
  max_response_ms: number;
  p95_response_ms: number;
  requests_per_second: number;
  status_codes: Record<string, number>;
  duration_ms: number;
  timeline: { index: number; ms: number; status: number }[];
}

export interface BannerResult {
  target: string;
  services: { port: number; service: string; state: string; banner: string; version: string | null }[];
  total_scanned: number;
  open_count: number;
  duration_ms: number;
}

export interface DirBustResult {
  target: string;
  paths_found: { path: string; status: number; size: number; redirect: string | null; content_type: string }[];
  total_found: number;
  total_checked: number;
  duration_ms: number;
}

export interface PayloadTestResult {
  target: string;
  parameter: string;
  payload_type: string;
  results: {
    payload: string; status_code: number; reflected: boolean;
    blocked: boolean; error_triggered: boolean; response_size: number; verdict: string;
  }[];
  total_payloads: number;
  vulnerable: number;
  blocked: number;
  filtered: number;
  waf_detected: boolean;
  duration_ms: number;
}

export interface NetworkDiscoveryResult {
  subnet: string;
  hosts_scanned: number;
  hosts_alive: number;
  hosts: { ip: string; port: number; hostname: string | null }[];
  duration_ms: number;
}

export interface ExploitSuggestion {
  port: number;
  service: string;
  banner: string;
  cve: string;
  severity: string;
  description: string;
}

export interface ExploitResult {
  services_analyzed: number;
  exploits_found: number;
  suggestions: ExploitSuggestion[];
}

// --- Pentest Lab extended modules ---

export interface WafDetectResult {
  target: string;
  waf_detected: boolean;
  waf_type: string | null;
  fingerprints: string[];
  bypass_results: { technique: string; payload: string; status: number; bypassed: boolean }[];
  duration_ms: number;
}

export interface SslAuditResult {
  target: string;
  protocols: { version: string; supported: boolean }[];
  certificate: Record<string, unknown> | null;
  weak_ciphers: string[];
  vulnerabilities: { name: string; severity: string; description: string }[];
  hsts: boolean;
  score: number;
  max_score: number;
  duration_ms: number;
}

export interface SubdomainTakeoverResult {
  domain: string;
  subdomains_checked: number;
  vulnerable: { subdomain: string; cname: string; service: string; status: string }[];
  duration_ms: number;
}

export interface CorsTestResult {
  target: string;
  tests: { origin: string; acao: string | null; acac: boolean; vulnerable: boolean; description: string }[];
  vulnerable_count: number;
  duration_ms: number;
}

export interface HttpMethodsResult {
  target: string;
  methods: { method: string; status: number; size: number; dangerous: boolean; reason: string }[];
  duration_ms: number;
}

export interface FuzzerResult {
  target: string;
  parameter: string;
  total_sent: number;
  anomalies: { input_desc: string; payload_preview: string; status: number; response_ms: number; response_size: number; anomaly_type: string }[];
  baseline: { status: number; avg_ms: number; avg_size: number };
  duration_ms: number;
}

export interface CmsScanResult {
  target: string;
  cms_type: string | null;
  cms_version: string | null;
  findings: { type: string; severity: string; url: string; description: string }[];
  users_found: string[];
  duration_ms: number;
}

export interface CrawlResult {
  target: string;
  pages_crawled: number;
  urls: string[];
  forms: { url: string; action: string; method: string; fields: string[] }[];
  js_files: string[];
  emails: string[];
  comments: { url: string; comment: string }[];
  external_links: string[];
  duration_ms: number;
}

export interface AuthBypassResult {
  target: string;
  tests: { technique: string; payload: string; status: number; success: boolean; description: string }[];
  bypasses_found: number;
  duration_ms: number;
}

export interface DnsReconResult {
  domain: string;
  zone_transfer: { success: boolean; records: string[] };
  subdomains_found: { name: string; ip: string | null; method: string }[];
  wildcard_detected: boolean;
  dns_security: { spf: boolean; dmarc: boolean; dkim: boolean };
  duration_ms: number;
}

export interface SsrfTestResult {
  target: string;
  parameter: string;
  tests: { payload: string; status: number; response_size: number; baseline_diff: number; potentially_vulnerable: boolean; description: string }[];
  ssrf_indicators: number;
  duration_ms: number;
}

export interface JwtAnalyzeResult {
  token_preview: string;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature_valid: boolean | null;
  vulnerabilities: { type: string; severity: string; description: string }[];
  expiration: { exp: number | null; is_expired: boolean; remaining_seconds: number | null };
  weak_secret_found: string | null;
  duration_ms: number;
}

// --- Advanced Attack modules ---

export interface SqliAdvancedResult {
  target: string;
  parameter: string;
  dbms_detected: string | null;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_payloads: number;
  vulnerable_count: number;
  waf_detected: boolean;
  duration_ms: number;
}

export interface XssHunterResult {
  target: string;
  parameter: string;
  contexts_found: string[];
  payloads_found: { payload: string; context: string; type: string; severity: string; bypasses_waf: boolean }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface LfiExploitResult {
  target: string;
  parameter: string;
  os_detected: string | null;
  files_found: { payload: string; technique: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface SstiResult {
  target: string;
  parameter: string;
  engine_detected: string | null;
  payloads_found: { engine: string; payload: string; evidence: string; severity: string; rce_possible: boolean }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface XxeResult {
  target: string;
  endpoint: string;
  payloads_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  oob_possible: boolean;
  duration_ms: number;
}

export interface RaceConditionResult {
  target: string;
  total_sent: number;
  concurrency: number;
  anomalies: { type: string; description: string; evidence: string; severity: string }[];
  responses: { status: number; size: number; time_ms: number }[];
  unique_statuses: number;
  size_variance: number;
  duration_ms: number;
}

export interface GraphqlResult {
  target: string;
  introspection_enabled: boolean;
  types_found: string[];
  queries_found: string[];
  mutations_found: string[];
  injections: { field: string; payload: string; evidence: string; severity: string }[];
  batch_allowed: boolean;
  suggestions_enabled: boolean;
  duration_ms: number;
}

export interface UploadBypassResult {
  target: string;
  endpoint: string;
  bypasses: { technique: string; filename: string; content_type: string; status: number; success: boolean; description: string }[];
  total_tested: number;
  bypassed_count: number;
  duration_ms: number;
}

// --- Advanced modules: SQLi Extract, RevShell, Post-Exploit ---

export interface SqliExtractResult {
  target: string;
  parameter: string;
  technique: string;
  dbms: string;
  steps: { step: string; status: string; data: string | null }[];
  extracted: {
    dbms?: string;
    version?: string;
    user?: string | null;
    current_db?: string | null;
    databases?: string[];
    tables?: string[];
    columns?: string[];
    rows?: Record<string, string>[];
  };
  total_rows: number;
  duration_ms: number;
}

export interface RevShellResult {
  lhost: string;
  lport: number;
  shells: { language: string; name: string; payload: string; encoded: string | null; encoding: string | null; os: string }[];
  total_generated: number;
  listeners: { tool: string; command: string }[];
  upgrades: { name: string; command: string }[];
  duration_ms: number;
}

export interface PostExploitResult {
  target: string;
  os_target: string;
  modules_run: string[];
  results: Record<string, { label: string; command: string; output: string; success: boolean }[]>;
  findings: { severity: string; finding: string }[];
  total_executed: number;
  total_success: number;
  duration_ms: number;
}

// --- Modules 32-43 ---

export interface NosqlResult {
  target: string;
  parameter: string;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface LdapResult {
  target: string;
  parameter: string;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface ProtoPollutionResult {
  target: string;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface SmugglingResult {
  target: string;
  techniques_found: { technique: string; description: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface WsInjectResult {
  target: string;
  ws_url: string;
  connected: boolean;
  tests: { test: string; description: string; response: string; vulnerable: boolean; severity: string }[];
  vulnerable_count: number;
  duration_ms: number;
}

export interface CrlfResult {
  target: string;
  parameter: string;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface OpenRedirectResult {
  target: string;
  parameter: string;
  techniques_found: { technique: string; payload: string; evidence: string; severity: string }[];
  total_tested: number;
  vulnerable_count: number;
  duration_ms: number;
}

export interface PrivescResult {
  target: string;
  os_target: string;
  suggestions: { vector: string; binary: string; exploit: string; severity: string }[];
  total_found: number;
  duration_ms: number;
}

export interface CredDumpResult {
  credentials: { type: string; username: string; value: string; source: string }[];
  total_found: number;
  by_type: Record<string, number>;
  duration_ms: number;
}

export interface PivotScanResult {
  target: string;
  subnet: string;
  hosts_found: { ip: string; ports: { port: number; state: string }[]; hostname: string | null }[];
  network_info: { interfaces: string; arp_table: string; routes: string; connections: string; hosts_file: string };
  total_alive: number;
  duration_ms: number;
}

export interface PayloadEncodeResult {
  original: string;
  encodings_applied: string[];
  steps: { encoding: string; input: string; output: string }[];
  final_payload: string;
  wrappers: { name: string; payload: string }[];
  duration_ms: number;
}

export interface PhishingResult {
  target_url: string;
  capture_url: string;
  forms_found: { action: string; inputs: { name: string; type: string }[] }[];
  original_size: number;
  modified_size: number;
  phishing_html: string;
  duration_ms: number;
}

// --- Scan Persistence & Pipeline ---

export interface ScanResultEntry {
  id: string;
  created_at: string;
  module_id: string;
  target: string;
  mode: string;
  status: string;
  result_json: string;
  duration_ms: number;
  findings_count: number;
  severity_max: string | null;
  notes: string | null;
}

export interface ScanStats {
  total_scans: number;
  by_module: Record<string, number>;
  by_severity: Record<string, number>;
  total_findings: number;
}

export interface PipelinePreset {
  name: string;
  steps: { module_id: string; config: Record<string, unknown>; condition: string }[];
  step_count: number;
}

export interface PipelineStatus {
  pipeline_id: string;
  name: string;
  status: string;
  current_step: number;
  total_steps: number;
  step_results: { module_id: string; status: string; findings?: number; duration_ms?: number; error?: string }[];
  started_at: string | null;
  finished_at: string | null;
}

export interface WordlistInfo {
  name: string;
  type: string;
  count: number;
}

// === Scan Sessions ===
export interface ScanSession {
  id: string;
  name: string;
  created_at: string;
  target: string;
  status: "active" | "paused" | "completed";
  auth: { cookies?: Record<string, string>; headers?: Record<string, string>; bearer_token?: string };
  findings_count: number;
  discovered_endpoints: string[];
  discovered_params: string[];
  chain_queue: ChainSuggestion[];
}

export interface ChainSuggestion {
  module: string;
  priority: number;
  reason: string;
  auto_params: Record<string, any>;
}

export interface HttpHistoryEntry {
  id: number;
  timestamp: string;
  method: string;
  url: string;
  status_code: number;
  response_time_ms: number;
  request_headers: Record<string, string>;
  response_size: number;
}

export interface SessionFinding {
  id: string;
  module_id: string;
  severity: string;
  type: string;
  detail: string;
  timestamp: string;
  evidence?: string;
}

// === NVD CVE ===
export interface NvdCve {
  cve_id: string;
  description: string;
  cvss_score: number | null;
  severity: string;
  vector_string: string;
  references: string[];
  published: string;
  cwes: string[];
}

// === Templates ===
export interface PentestTemplate {
  id: string;
  name: string;
  severity: string;
  description: string;
  tags: string[];
  author?: string;
}

export interface TemplateScanResult {
  template_id: string;
  template_name: string;
  matched: boolean;
  severity: string;
  details: Record<string, any>;
  url: string;
}

// --- Network Evasion types ---

export interface NetworkInfo {
  local_ip: string;
  public_ip: string;
  dns_servers: string[];
  gateway: string;
  hostname: string;
}

export interface ProxyChainResult {
  proxies: { proxy: string; status: string; latency_ms: number; error?: string }[];
  exit_ip: string | null;
  chain_working: boolean;
  total_latency_ms: number;
}

export interface TorStatus {
  connected: boolean;
  exit_ip: string | null;
  circuit: { position: number; fingerprint: string; nickname: string; country: string }[];
  country: string | null;
  new_identity?: boolean;
  error?: string;
}

export interface DnsTunnelResult {
  action: string;
  data?: string;
  encoded_queries?: string[];
  decoded_data?: string;
  domain?: string;
  record_type?: string;
  feasible?: boolean;
  max_throughput_bps?: number;
  latency_ms?: number;
  error?: string;
}

export interface DomainFrontResult {
  front_domain: string;
  real_host: string;
  path: string;
  success: boolean;
  status_code: number | null;
  response_size: number | null;
  fronting_detected: boolean;
  error?: string;
}

export interface CdnFrontingEntry {
  cdn: string;
  domains: string[];
  fronting_support: "confirmed" | "partial" | "blocked";
}

export interface EgressResult {
  target: string;
  ports: { port: number; status: "open" | "closed" | "filtered"; latency_ms: number | null; protocol: string }[];
  open_count: number;
  closed_count: number;
  filtered_count: number;
  duration_ms: number;
}

export interface HttpTunnelResult {
  proxy_url: string;
  target: string;
  method: string;
  success: boolean;
  status_code: number | null;
  allowed_ports: number[];
  blocked_ports: number[];
  error?: string;
}

export interface EvasionAdvice {
  rank: number;
  technique: string;
  description: string;
  feasibility: "high" | "medium" | "low";
  requirements: string[];
  setup_steps: string[];
}

// --- Hash Cracker types ---

export interface HashIdentifyResult {
  possible_types: { type: string; confidence: number; description: string }[];
}

export interface HashCrackResult {
  hash: string;
  plaintext: string | null;
  hash_type: string;
  time_ms: number;
  method: string;
}

export interface HashBatchResult {
  total: number;
  cracked: number;
  results: HashCrackResult[];
  success_rate: number;
  total_time_ms: number;
}

// --- Pentest Report types ---

export interface PentestReportInfo {
  id: string;
  title: string;
  client: string;
  date: string;
  scan_count: number;
  vuln_count: number;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  sections: string[];
}

// --- Wordlist Generator types ---

export interface CrawlWordResult { words: { word: string; frequency: number; sources: string[] }[]; total_unique: number; pages_crawled: number }
export interface MutateResult { words: { word: string; rule: string; source: string }[]; total: number }
export interface UsernameResult { usernames: string[]; total: number }
export interface PatternResult { words: string[]; total: number }
export interface CompanyProfileResult { categories: Record<string, string[]>; total: number }
export interface MergeResult { words: string[]; stats: { before: number; after: number; removed: number } }

export interface ReportSummary {
  risk_level: string;
  total_vulns: number;
  by_severity: Record<string, number>;
  top_findings: { name: string; severity: string; module: string }[];
}

// --- Deep Scan types ---

export interface DeepScanResult {
  target: string; scan_id: string; started_at: string; completed_at: string; duration_seconds: number;
  crawl_summary: { pages_crawled: number; forms_found: number; forms_skipped: number; api_endpoints_found: number; parameters_discovered: number; attack_points_total: number; skipped_forms_details: { action: string; method: string; page_url: string; reason: string; input_names: string[] }[] };
  attack_summary: { total_tests_run: number; total_findings: number; by_severity: Record<string, number>; by_type: Record<string, number>; most_vulnerable_pages: { url: string; findings: number }[] };
  findings: DeepFinding[];
  attack_surface: { url: string; method: string; params: string[]; source: string; tests_run: number; findings_count: number }[];
  risk_score: number; risk_level: string; verdict_fr: string;
}

export interface DeepFinding {
  id: string; type: string; severity: string; url: string; method: string; parameter: string; payload: string; evidence: string;
  description_fr: string; remediation_fr: string; request: string; response_code: number; response_time_ms: number; confirmed: boolean; false_positive_risk: string;
}

export interface DeepScanStatus {
  scan_id: string; phase: string; progress: number; pages_crawled: number; attack_points: number; tests_run: number; findings: number; status: string;
}

export interface DeepScanEntry {
  scan_id: string; target: string; date: string; findings_count: number; risk_score: number; risk_level: string; status: string;
}

// --- Blind Extraction types ---
export interface BlindJob { job_id: string; type: string; target: string; status: string; phase: string; percentage: number; chars_extracted: number; data_length?: number; result?: any; error?: string; }

// --- OOB Callback types ---
export interface OOBListener { listener_id: string; token: string; test_type: string; target: string; is_active: boolean; remaining_seconds: number; callbacks_count: number; callbacks: any[]; verdict_fr: string; }
export interface OOBPayload { name: string; payload: string; description: string; }

// --- SSRF Advanced types ---
export interface SSRFResult { target: string; param: string; findings: any[]; summary: { total_tests: number; findings: number; cloud_metadata_exposed: number; internal_ports_open: number; protocols_accessible: number; ip_bypasses_working: number }; all_results: any[]; }
export interface IPBypass { url: string; technique: string; }
export interface GopherPayload { name: string; url: string; raw_command: string; }

// --- Subdomain Discovery types ---
export interface SubdomainResult { domain: string; total_found: number; total_resolved: number; duration_seconds: number; sources_summary: Record<string, number>; wildcard_detected: boolean; subdomains: { subdomain: string; ips: string[]; sources: string[]; takeover_vulnerable?: boolean; takeover_service?: string }[]; takeover_candidates: any[]; ip_distribution: { ip: string; count: number; subdomains: string[] }[]; }
export interface SubdomainJob { job_id: string; domain: string; status: string; phase: string; percentage: number; found_so_far: number; result?: SubdomainResult; }

// --- WAF Bypass types ---
export interface WAFBypassResult { target: string; param: string; vuln_type: string; detected_waf: string; total_payloads_tested: number; bypassed_count: number; effective_count: number; blocked_count: number; bypass_rate: number; effective_payloads: any[]; bypassed_payloads: any[]; verdict_fr: string; }
export interface WAFFingerprint { url: string; detected_wafs: { waf: string; confidence: number; evidence: string[] }[]; primary_waf: string; confidence: number; }

// --- Exfiltration types ---
export interface ExfilPlan { data_size: string; environment: string; stealth_level: string; recommended_channels: { channel: string; stealth_score: number; speed_score: number; capacity_score: number; reliability_score: number; total_score: number; description_fr: string }[]; execution_plan: string[]; }
export interface ExfilDNSResult { domain: string; data_size: number; chunks_count: number; subdomains: string[]; commands: string[]; description_fr: string; }
export interface ExfilHTTPResult { target: string; method: string; data_size: number; requests: { url: string; method: string; headers?: Record<string, string>; body?: string }[]; description_fr: string; }
export interface ExfilTechnique { name: string; stealth: string; speed: string; capacity: string; description_fr: string; }

// --- Persistence types ---
export interface WebshellResult { language: string; obfuscation_level: string; code: string; filename: string; deploy_instructions: string[]; access_url: string; description_fr: string; }
export interface BackdoorResult { type: string; target_os: string; code: string; persistence_commands: string[]; description_fr: string; }
export interface DropperResult { method: string; target_os: string; payload_url: string; commands: string[]; description_fr: string; }
export interface PersistTechnique { name: string; target_os: string; stealth: string; description_fr: string; }

// --- Anti-Forensics types ---
export interface CleanLogsResult { target_os: string; log_type: string; commands: { name: string; command: string }[]; verification: string[]; description_fr: string; }
export interface TimestompResult { file_path: string; target_os: string; commands: { name: string; command: string }[]; description_fr: string; }
export interface EvidenceCheck { category: string; items: { name: string; check_command: string; clean_command: string; status: string }[]; }
export interface CleanupPlan { phases: { phase: number; name: string; description_fr: string; commands: { name: string; command: string }[] }[]; verification_commands: string[]; }
export interface AntiForensicsTechnique { name: string; category: string; description_fr: string; }

// --- Kill Chain types ---
export interface KillChainPlan { target: string; objective: string; stealth_level: string; phases: KillChainPhase[]; estimated_duration: string; risk_assessment: string; description_fr: string; }
export interface KillChainPhase { phase: number; name: string; description_fr: string; steps: { action: string; tool: string; api_command?: string; description_fr: string }[]; success_criteria: string; }
export interface KillChainTemplate { id: string; name: string; description_fr: string; objective: string; phases_count: number; stealth_level: string; }

// --- Shell Handler types ---
export interface ListenerInfo { listener_id: string; host: string; port: number; started_at: string; sessions_count: number; status: string; }
export interface ShellSession { session_id: string; listener_id: string; remote_ip: string; remote_port: number; connected_at: string; last_activity: string; os_hint: string; status: string; commands_count: number; }
export interface ShellSessionDetail extends ShellSession { history: { timestamp: string; direction: string; data: string }[]; }
export interface ExecResponse { session_id: string; command: string; output: string; exit_hint: string; duration_ms: number; }
export interface ShellPayload { name: string; payload: string; description: string; language: string; }

// --- Attack Chain types ---
export interface ChainInfo { chain_id: string; target: string; mode: string; phase: string; findings_count: number; credentials_count: number; created_at: string; }
export interface ChainDetail extends ChainInfo { findings: ChainFinding[]; credentials: ChainCredential[]; sessions: string[]; exfil_data: any[]; }
export interface ChainFinding { id: string; type: string; url: string; method: string; param: string; payload: string; evidence: string; severity: string; confirmed: boolean; exploitable: boolean; module_source: string; discovered_at: string; metadata: Record<string, any>; }
export interface ChainCredential { username: string; password?: string; hash?: string; source: string; service: string; }
export interface ChainSuggestion { rule_id: string; action: string; description_fr: string; priority: number; mode: string; params: Record<string, any>; api_endpoint: string; api_method: string; }
export interface ChainLogEntry { timestamp: string; action_type: string; module: string; input_params: Record<string, any>; result_summary: string; duration_ms: number; }

// --- SQLi Engine types ---
export interface SQLiDetectResult { url: string; param: string; dbms: string; dbms_confidence: number; technique: string; injectable: boolean; details: Record<string, any>; }
export interface SQLiJob { job_id: string; target_url: string; status: string; phase: string; progress: number; technique: string; dbms: string; results: any; log: string[]; }
export interface SQLiSchema { databases: { name: string; tables: { name: string; columns: { name: string; type: string }[]; row_count: number }[] }[]; }
export interface SQLiTamper { name: string; description: string; example_before: string; example_after: string; }

// --- Session Manager types ---
export interface ManagedSession { session_id: string; target_base_url: string; auth_type: string; is_authenticated: boolean; is_admin: boolean; username: string; cookies_count: number; created_at: string; last_used: string; }

// --- Privilege Escalation types ---
export interface PrivescFinding { check: string; category: string; risk: string; commands: { name: string; command: string }[]; exploitation: string; description_fr: string; }
export interface GTFOBinEntry { binary: string; suid?: string; sudo?: string; capabilities?: string; }

// --- Credential Auditor types ---
export interface CredScanResult { section: string; source: string; credential_type: string; description: string; commands: { name: string; command: string }[]; risk_level: string; next_steps: string[]; }
export interface ParsedCredential { key?: string; value?: string; username?: string; password?: string; hash?: string; hash_type?: string; }

// --- Lateral Movement types ---
export interface LateralTechnique { name: string; mitre_id: string; tools: string[]; stealth: string; description_fr: string; }
export interface PivotPlan { hops: { from: string; to: string; technique: string; commands: string[] }[]; total_hops: number; }
export interface SprayResult { target: string; service: string; success: boolean; command: string; }

// --- XSS Engine types ---
export interface XSSConfirmResult { url: string; param: string; context: string; confirmed: boolean; payload_used: string; }
export interface XSSPayloadSet { context: string; payloads: { name: string; payload: string; description: string }[]; }

// --- LFI to RCE types ---
export interface LFIConfirmResult { url: string; param: string; vulnerable: boolean; technique: string; file_read?: string; }
export interface LFIChainResult { phases: { name: string; status: string; technique: string; result?: string }[]; rce_achieved: boolean; shell_command?: string; }

// --- Protocol Exploiter types ---
export interface ProtocolResult { protocol: string; target: string; findings: { name: string; severity: string; detail: string; commands: string[] }[]; }
export interface SMBEnumResult { shares: { name: string; type: string; remark: string }[]; users: string[]; null_session: boolean; }

// --- Execution Bridge types ---
export interface BridgeExecResult { id: string; session_id: string; command: string; output: string; exit_code: number | null; duration_ms: number; timestamp: number; parsed?: any; parser_used?: string; }
export interface BridgeBatchResult { session_id: string; results: { command: string; output: string; exit_code: number | null; success: boolean }[]; total_duration_ms: number; succeeded: number; failed: number; }
export interface BridgeSession { session_id: string; remote_ip: string; remote_port: number; os_hint: string; status: string; }
export interface BridgeTunnel { tunnel_id: string; session_id: string; type: string; local_port: number; remote_host: string; remote_port: number; status: string; }
export interface BridgeModuleResult { session_id: string; module: string; action: string; results: { command: string; output: string; parsed?: any }[]; }

// --- C2 Server types ---
export interface C2Listener { id: string; protocol: string; host: string; port: number; started_at: string; active: boolean; agents_connected: number; profile?: string; }
export interface C2Agent { id: string; listener_id: string; hostname: string; username: string; os: string; arch: string; pid: number; integrity: string; first_seen: string; last_seen: string; sleep_seconds: number; jitter_percent: number; status: string; pending_tasks: number; tags: string[]; }
export interface C2AgentDetail extends C2Agent { tasks: C2Task[]; metadata: Record<string, any>; }
export interface C2Task { id: string; agent_id: string; task_type: string; args: Record<string, any>; status: string; created_at: string; completed_at?: string; result?: any; error?: string; }
export interface C2Dashboard { listeners_count: number; agents_active: number; agents_dormant: number; agents_dead: number; pending_tasks: number; completed_tasks: number; }
export interface C2Implant { format: string; source: string; filename: string; size_bytes: number; encryption_key: string; config: Record<string, any>; }
export interface C2Profile { name: string; user_agent: string; url_paths: string[]; headers: Record<string, string>; content_type: string; }

// --- HTTP Proxy types ---
export interface ProxyStatus { running: boolean; port: number; intercept_enabled: boolean; total_requests: number; scope_rules_count: number; intercepted_queue_size: number; }
export interface ProxyEntry { id: string; timestamp: number; method: string; url: string; host: string; path: string; status_code: number | null; content_type: string; request_size: number; response_size: number | null; duration_ms: number | null; intercepted: boolean; modified: boolean; notes: string; tags: string[]; highlight_color: string; }
export interface ProxyEntryDetail extends ProxyEntry { request_headers: Record<string, string>; request_body: string; response_headers: Record<string, string>; response_body: string; }
export interface ProxyScopeRule { host_pattern: string; include: boolean; }
export interface ProxyInterceptRule { id: string; enabled: boolean; match_type: string; match_field: string; match_value: string; action: string; replace_value: string; }
export interface ProxyMatchReplace { id: string; enabled: boolean; scope: string; match_type: string; match_in: string; match_pattern: string; replace_with: string; }
export interface ProxySitemap { hosts: Record<string, { paths: string[]; params: Record<string, string[]> }>; }
export interface ProxyStats { total_requests: number; by_method: Record<string, number>; by_status: Record<string, number>; by_host: Record<string, number>; avg_response_time_ms: number; unique_hosts: number; unique_paths: number; }
export interface ProxyCompare { differences: { field: string; value_a: string; value_b: string }[]; similarity_percent: number; }

// --- AV/EDR Evasion types ---
export interface EvasionEncodeResult { original_size: number; encoded_size: number; encodings_applied: string[]; encoded_payload: string; decoder_stub: string; }
export interface EvasionShellcodeResult { technique: string; output_format: string; encoded_shellcode: string; decoder_code: string; key: string; size_before: number; size_after: number; }
export interface EvasionAmsiResult { technique: string; language: string; payload: string; description: string; detection_risk: string; notes: string; }
export interface EvasionLoaderResult { loader_type: string; technique: string; source_code: string; description: string; detection_notes: string; }
export interface EvasionInjectResult { technique: string; target_process: string; code_template: string; mitre_id: string; description: string; detection_indicators: string[]; }
export interface EvasionUnhookResult { technique: string; target_dll: string; code_template: string; language: string; description: string; }
export interface EvasionSignature { name: string; category: string; pattern: string; av_vendors: string[]; bypass_suggestion: string; }
export interface EvasionObfuscateResult { original_size: number; obfuscated_size: number; techniques_applied: string[]; obfuscated_script: string; }
export interface EvasionSandboxResult { checks: string[]; language: string; detection_code: string; descriptions: Record<string, string>; }
export interface EvasionTechnique { name: string; category: string; mitre_id: string; description: string; }

// --- Fuzzer types ---
export interface FuzzAnomaly { payload: string; status: number; size: number; time_ms: number; anomaly_type: string; evidence: string; }
export interface FuzzParamResult { job_id: string; target: string; param: string; total_sent: number; anomalies: FuzzAnomaly[]; baseline: { status: number; size: number; time_ms: number }; duration_ms: number; }
export interface FuzzDirResult { target: string; total_tested: number; found: { path: string; status: number; size: number; redirect_to?: string; content_type: string }[]; duration_ms: number; }
export interface FuzzVhostResult { ip: string; domain: string; found: { hostname: string; status: number; size: number; different_from_default: boolean }[]; duration_ms: number; }
export interface FuzzAuthResult { target: string; total_attempts: number; valid_creds: { username: string; password: string; status: number; evidence: string }[]; duration_ms: number; }
export interface FuzzMutateResult { seed: string; total_mutations: number; payloads: string[]; }
export interface FuzzRaceResult { url: string; concurrent: number; rounds: number; responses_by_round: { statuses: number[]; sizes: number[]; unique_responses: number }[]; race_detected: boolean; evidence: string; }
export interface FuzzJob { id: string; target: string; status: string; total_requests: number; anomalies: number; }

// --- Network Scanner types ---
export interface NetScanPortResult { port: number; state: string; service: string; version: string; banner: string; ssl: boolean; }
export interface NetScanResult { target: string; scan_type: string; total_scanned: number; open_ports: number; results: NetScanPortResult[]; duration_ms: number; }
export interface NetScanSweepHost { ip: string; hostname: string; latency_ms: number; method: string; }
export interface NetScanSweepResult { subnet: string; alive_hosts: NetScanSweepHost[]; total_scanned: number; duration_ms: number; }
export interface NetScanOSResult { target: string; os_guesses: { os: string; confidence: number; evidence: string }[]; ttl: number; }
export interface NetScanSSLResult { target: string; port: number; certificate: { cn: string; san: string[]; issuer: string; not_before: string; not_after: string; expired: boolean; self_signed: boolean; key_size: number }; tls_versions: string[]; ciphers: string[]; vulnerabilities: { name: string; severity: string; description: string }[]; }
export interface NetScanDNSResult { target: string; records: { type: string; name: string; value: string; ttl: number }[]; }
export interface NetScanJob { id: string; target: string; status: string; progress: number; open_ports: number; }

// --- Exploit Dev types ---
export interface ExploitPattern { pattern: string; length: number; }
export interface ExploitOffset { value: string; offset: number; exact_match: boolean; }
export interface ExploitPack { address: string; packed_hex: string; packed_python: string; arch: string; endian: string; }
export interface ExploitGadget { offset: number; bytes: string; disassembly: string; category: string; }
export interface ExploitROPChain { chain_template: string; description: string; placeholders: { name: string; description: string; typical_value: string }[]; code: string; }
export interface ExploitFormatString { payload_hex: string; payload_python: string; writes: { address: string; value: string; format_spec: string }[]; description: string; }
export interface ExploitShellcode { shellcode_hex: string; shellcode_c: string; shellcode_python: string; size: number; type: string; arch: string; null_free: boolean; }
export interface ExploitEgghunter { egghunter_hex: string; egg_tag: string; size: number; technique: string; description: string; }
export interface ExploitHeap { technique: string; description: string; template_code: string; steps: string[]; references: string[]; }
export interface ExploitBadChars { bad_chars: string[]; good_chars: string[]; total_bad: number; first_bad_offset: number; }

// --- AI Assistant types ---
export interface AIAnalysis { analysis: string; suggested_actions: string[]; risk_assessment: string; attack_paths: string[]; model_used: string; }
export interface AISuggestion { technique: string; description: string; commands: string[]; mitre_id: string; priority: number; risk: string; }
export interface AIVulnExplain { explanation: string; impact: string; exploitation_steps: string[]; example_payloads: string[]; remediation: string; cwe_id: string; cvss_estimate: string; }
export interface AIPayload { payload: string; language: string; explanation: string; usage_instructions: string; detection_risk: string; }
export interface AIReviewResult { findings: { type: string; detail: string; severity: string; actionable: boolean }[]; summary: string; next_commands: string[]; }
export interface AIReport { report_section: string; risk_summary: string; recommendations: string[]; }
export interface AIBypass { bypass_techniques: { technique: string; payload: string; explanation: string; success_likelihood: string }[]; }
export interface AIPersona { id: string; name: string; description: string; }

// --- Workflow types ---
export interface WorkflowTemplate {
  id: string; name: string; description_fr: string; difficulty: number;
  estimated_time_minutes: number; category: string; steps: WorkflowStepTemplate[];
}
export interface WorkflowStepTemplate {
  id: string; name: string; description_fr: string; tool_page: string;
  tool_module: string; order: number; inputs: string[]; outputs: string[];
  auto_params: Record<string, any>; tips_fr: string;
}
export interface WorkflowInstance {
  workflow_id: string; template_id: string; name: string; target: string;
  started_at: string; status: string; steps: WorkflowStepInstance[];
  current_step: number; overall_progress: number;
}
export interface WorkflowStepInstance {
  id: string; name: string; description_fr: string; tool_page: string;
  order: number; status: string; started_at: string | null;
  completed_at: string | null; result_summary: string; output_data: Record<string, any>;
  notes: string; tips_fr: string; auto_params: Record<string, any>;
}
export interface AIModel { name: string; size: string; }

// --- Live Attack Dashboard ---
export interface LiveEvent {
  event_id: string; timestamp: string; source_module: string; operation_id: string;
  event_type: string; severity: string; title: string; detail: string;
  metadata: Record<string, any>; visual_type: string; icon: string; color: string;
}
export interface LiveOperation {
  operation_id: string; type: string; target: string; status: string;
  progress: number; findings_count: number; started_at: string; module: string;
}
export interface LiveDashboard {
  operations: LiveOperation[]; total_operations: number; total_findings: number;
  critical_findings: number; risk_score: number; recent_events: LiveEvent[];
  active_alerts: LiveAlert[];
}
export interface LiveAlert {
  id: string; timestamp: string; type: string; message_fr: string;
  severity: string; acknowledged: boolean; operation_id: string;
}
export interface LiveRiskScore {
  current: number; trend: string; history: { timestamp: string; score: number }[];
  factors: Record<string, number>;
}
export interface LiveAttackMap {
  nodes: { id: string; ip: string; hostname: string; os: string; compromised: boolean; ports: number[]; vulns: number }[];
  edges: { source: string; target: string; type: string; label: string }[];
}
export interface LiveFindingStats {
  by_severity: Record<string, number>; by_category: Record<string, number>;
  by_module: Record<string, number>; total: number;
}

// --- Headless Browser Scanner ---
export interface HeadlessScan {
  scan_id: string; target: string; status: string; started_at: string;
  completed_at: string | null; config: HeadlessScanConfig;
  summary: { pages_visited: number; js_files: number; forms: number; api_calls: number;
    dom_xss: number; js_findings: number; total_findings: number };
}
export interface HeadlessScanConfig {
  browser: string; viewport: string; max_pages: number; timeout: number;
  user_agent: string;
}
export interface HeadlessPage {
  url: string; title: string; status_code: number; content_type: string;
  js_frameworks: string[]; load_time_ms: number; scripts_count: number;
  forms_count: number; api_calls_count: number;
}
export interface HeadlessDomXss {
  id: string; url: string; source: string; sink: string; payload: string;
  proof: string; severity: string; confirmed: boolean;
}
export interface HeadlessJsFinding {
  id: string; file: string; line: number; type: string; snippet: string;
  severity: string; description: string; cve: string | null;
}
export interface HeadlessFormResult {
  url: string; action: string; method: string; fields: string[];
  csrf_present: boolean; vulns: string[];
}
export interface HeadlessApiEndpoint {
  url: string; method: string; params: string[]; auth_type: string;
  idor_vulnerable: boolean;
}
export interface HeadlessAuthAnalysis {
  login_url: string; brute_force_protection: boolean;
  session_config: Record<string, any>; jwt_analysis: Record<string, any> | null;
}
export interface HeadlessCookie {
  name: string; domain: string; path: string; httponly: boolean;
  secure: boolean; samesite: string; expires: string; issues: string[];
}
export interface HeadlessLive {
  current_url: string; pages_done: number; total_estimated: number;
  phase: string; progress: number;
}

// --- Auto-Exploit Engine ---
export interface AutoExploitSession {
  session_id: string; target: string; mode: string; status: string;
  started_at: string; current_phase: string; config: AutoExploitConfig;
  phases: AutoExploitPhase[]; findings: AutoExploitFinding[];
  stats: { total_requests: number; total_vulns: number; total_time: number; phases_completed: number };
  overall_progress: number;
}
export interface AutoExploitConfig {
  max_depth: number; timeout_per_phase: number; aggressiveness: number;
  scope_strict: boolean; excluded_modules: string[];
}
export interface AutoExploitPhase {
  id: string; name: string; status: string; started_at: string | null;
  completed_at: string | null; progress: number; findings_count: number;
  result_summary: string; output_data: Record<string, any>;
}
export interface AutoExploitFinding {
  id: string; phase: string; type: string; severity: string; title: string;
  detail: string; evidence: string; confirmed: boolean; cvss: number | null;
  remediation_fr: string;
}
export interface AutoExploitLogEntry {
  timestamp: string; phase: string; action: string; detail: string;
  severity: string; icon: string;
}
export interface AutoExploitLive {
  current_phase: string; progress: number; status: string;
  log: AutoExploitLogEntry[]; findings_count: number;
}

// --- UEBA types ---

export interface UbaEntity {
  id: string;
  entity_type: string;
  entity_key: string;
  total_events: number;
  current_score: number;
  high_risk: boolean;
  score_reasons: Record<string, number>;
  first_seen: string | null;
  last_seen: string | null;
  updated_at: string | null;
  hours_top?: Record<string, number>;
  event_types_top?: Record<string, number>;
  geos_top?: Record<string, number>;
  src_ips_top?: Record<string, number>;
  user_agents_top?: Record<string, number>;
}

export interface UbaListResponse {
  entities: UbaEntity[];
  high_risk_threshold: number;
  count: number;
}

export interface UbaSummary {
  total_entities: number;
  high_risk_count: number;
  high_risk_threshold: number;
  by_type: Record<string, number>;
  top_risky: UbaEntity[];
}

export interface UbaRefreshResponse {
  entities_updated: number;
  events_consumed: number;
  high_risk_count: number;
}

// --- Case Management types ---

export interface CaseSlaStatus {
  response_deadline: string;
  resolution_deadline: string;
  response_breached: boolean;
  resolution_breached: boolean;
  any_breach: boolean;
  minutes_to_resolution: number;
}

export interface CaseSummary {
  id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  severity: string;
  assignee_id: string | null;
  assignee_username: string | null;
  incident_ids: string[];
  tags: string[];
  resolution: string | null;
  sla_breached: boolean;
  created_at: string | null;
  updated_at: string | null;
  closed_at: string | null;
  sla?: CaseSlaStatus;
}

export interface CaseEvidenceItem {
  id: string;
  case_id: string;
  kind: string;
  title: string;
  sha256: string | null;
  extra: Record<string, any>;
  collected_by: string | null;
  collected_at: string | null;
  custody_chain: Array<{
    actor: string; action: string; ts: string; prev_hash: string; hash: string;
  }>;
  content_size: number;
}

export interface CaseTimelineItem {
  id: string;
  ts: string | null;
  kind: string;
  actor_username: string | null;
  message: string;
  data: Record<string, any>;
}

export interface CaseStats {
  total: number;
  open: number;
  sla_breached: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
}

// --- Compliance types ---

export interface ComplianceFrameworkInfo {
  id: string;
  name: string;
  version: string;
  url: string;
  description: string;
  controls_count: number;
}

export interface ComplianceControlReport {
  id: string;
  title: string;
  description: string;
  mandatory: boolean;
  status: "covered" | "partial" | "uncovered" | "manual";
  capabilities: string[];
  covered_capabilities: string[];
  missing_capabilities: string[];
  evidence: Record<string, Array<{ type: string; ref: string }>>;
}

export interface ComplianceFrameworkReport {
  framework: { id: string; name: string; version: string; url: string };
  summary: {
    controls_total: number;
    by_status: Record<string, number>;
    coverage_score: number;
  };
  controls: ComplianceControlReport[];
}

export interface ComplianceGlobalReport {
  summary: Array<{
    id: string; name: string;
    controls_total: number; coverage_score: number;
    by_status: Record<string, number>;
  }>;
  reports: Record<string, ComplianceFrameworkReport>;
}
