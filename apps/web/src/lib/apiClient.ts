import type {
  AdminUser,
  AnomalyBaselineStat,
  AnomalyRunResponse,
  AuditLogEntry,
  Event,
  EventListParams,
  EventsPerMinuteBucket,
  GeoEvent,
  GraphData,
  HeatmapCell,
  Incident,
  IncidentDetail,
  IncidentListParams,
  IncidentStatus,
  ChatResponse,
  ClassifierInfo,
  ClassifyResponse,
  KpiResponse,
  LogSourceStatus,
  MLDetectResponse,
  MLModelInfo,
  MitreCoverageResponse,
  MitreNavigatorLayer,
  MitreStatsResponse,
  RulesRunResponse,
  ScanHistoryEntry,
  ScannerResult,
  SigmaRuleInfo,
  ThreatScoreComputeResponse,
  ThreatScoreEntry,
  TILookupResult,
  TIStatsResponse,
  InvestigateResult,
  ReconResult,
  CrawlWordResult,
  MutateResult,
  UsernameResult,
  PatternResult,
  CompanyProfileResult,
  MergeResult,
  WorkflowTemplate,
  WorkflowInstance,
  WorkflowStepInstance,
  LiveDashboard,
  LiveEvent,
  LiveFindingStats,
  LiveRiskScore,
  LiveOperation,
  LiveAttackMap,
  LiveAlert,
  AutoExploitSession,
  AutoExploitLive,
  AutoExploitFinding,
  AutoExploitLogEntry,
  HeadlessScan,
  HeadlessScanConfig,
  HeadlessPage,
  HeadlessDomXss,
  HeadlessJsFinding,
  HeadlessFormResult,
  HeadlessApiEndpoint,
  HeadlessAuthAnalysis,
  HeadlessCookie,
  HeadlessLive,
  CampaignScenarioInfo,
  CampaignState,
  CampaignSummary,
  CampaignEvent,
  UbaEntity,
  UbaListResponse,
  UbaSummary,
  UbaRefreshResponse,
  CaseSummary,
  CaseEvidenceItem,
  CaseTimelineItem,
  CaseStats,
  ComplianceFrameworkInfo,
  ComplianceFrameworkReport,
  ComplianceGlobalReport,
  BloodHoundExportRequest,
  BloodHoundExportResponse,
  BloodHoundSchemaInfo,
  K8sAuditResult,
  K8sRbacChecks,
  ShellcodeEncodeRequest,
  ShellcodeEncodeResponse,
  ShellcodeBadByteCheck,
  ShellcodeNopSledResponse,
  ShellcodeMethods,
  AiStatus,
  LlmCallRequest,
  LlmCallResponse,
  TriageResult,
  RagSearchResult,
  RuleGenerateRequest,
  RuleGenerateResponse,
} from "./types";

// In the browser we MUST go through the server-side proxy (/api/proxy).
// The proxy injects the X-API-Key header server-side, so the secret is
// never exposed to the JavaScript bundle.
// On the server (SSR), call the backend directly with the server-only key.
const IS_BROWSER = typeof window !== "undefined";
const BASE_URL = IS_BROWSER
  ? "/api/proxy"
  : (process.env.INTERNAL_API_BASE_URL ??
     process.env.NEXT_PUBLIC_API_BASE_URL ??
     "http://127.0.0.1:8000");
// API_KEY is NEVER read in the browser. Server-side requests use INTERNAL_API_KEY.
const API_KEY = IS_BROWSER ? "" : (process.env.INTERNAL_API_KEY ?? "");

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Generic JSON envelope returned by backend endpoints not yet strictly typed.
 * Aliased to `any` intentionally: many pentest endpoints return heterogeneous
 * shapes consumed dynamically by pages (e.g. `r?.listeners`, `s.job_id`), and
 * downstream pages sometimes set typed state from the result. A stricter
 * `Record<string, unknown>` would force dozens of page-side casts without
 * adding real safety. Prefer a concrete interface when the contract stabilizes.
 * TODO: narrow per-endpoint as backend contracts stabilize.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ApiJson = any;

function buildQuery(params: Record<string, string | number | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") {
      sp.set(k, String(v));
    }
  }
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

interface RequestOptions {
  signal?: AbortSignal;
  timeout?: number;
}

async function request<T>(
  path: string,
  init?: RequestInit,
  opts?: RequestOptions,
): Promise<T> {
  const controller = new AbortController();
  const externalSignal = opts?.signal ?? init?.signal;

  // Link external signal to our controller
  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort(externalSignal.reason);
    } else {
      externalSignal.addEventListener("abort", () =>
        controller.abort(externalSignal.reason),
      );
    }
  }

  const timeout = opts?.timeout ?? DEFAULT_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort("Request timeout"), timeout);

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
        ...(init?.headers as Record<string, string> | undefined),
      },
    });

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        if (body?.detail) detail = String(body.detail);
      } catch {
        /* ignore parse errors */
      }
      throw new Error(`API ${res.status}: ${detail}`);
    }

    return res.json() as Promise<T>;
  } finally {
    clearTimeout(timer);
  }
}

/** Verifie l'etat de sante de l'API backend. */
export function getHealth(opts?: RequestOptions): Promise<{ status: string }> {
  return request("/health", undefined, opts);
}

/** Recupere la liste des evenements de securite avec filtres optionnels. */
export function listEvents(
  params: EventListParams = {},
  opts?: RequestOptions,
): Promise<Event[]> {
  const { limit, offset, severity, event_type, src_ip } = params;
  return request<Event[]>(
    `/events${buildQuery({ limit, offset, severity, event_type, src_ip })}`,
    undefined,
    opts,
  );
}

/** Recupere un evenement par son identifiant. */
export function getEvent(id: string, opts?: RequestOptions): Promise<Event> {
  return request<Event>(`/events/${encodeURIComponent(id)}`, undefined, opts);
}

/** Recupere la liste des incidents avec filtres optionnels. */
export function listIncidents(
  params: IncidentListParams = {},
  opts?: RequestOptions,
): Promise<Incident[]> {
  const { limit, offset, severity, status_filter, rule_id } = params;
  return request<Incident[]>(
    `/incidents${buildQuery({ limit, offset, severity, status_filter, rule_id })}`,
    undefined,
    opts,
  );
}

/** Recupere le detail d'un incident par son identifiant. */
export function getIncident(
  id: string,
  opts?: RequestOptions,
): Promise<IncidentDetail> {
  return request<IncidentDetail>(
    `/incidents/${encodeURIComponent(id)}`,
    undefined,
    opts,
  );
}

/** Met a jour le statut d'un incident (open, ack, closed). */
export function updateIncidentStatus(
  id: string,
  newStatus: IncidentStatus,
  opts?: RequestOptions,
): Promise<Incident> {
  return request<Incident>(
    `/incidents/${encodeURIComponent(id)}`,
    { method: "PATCH", body: JSON.stringify({ status: newStatus }) },
    opts,
  );
}

/** Lance l'evaluation des regles de correlation sur les evenements. */
export function runRules(opts?: RequestOptions): Promise<RulesRunResponse> {
  return request<RulesRunResponse>(
    "/rules/run",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

// --- KPIs ---

/** Recupere les indicateurs cles de performance du SOC. */
export function getKpis(opts?: RequestOptions): Promise<KpiResponse> {
  return request<KpiResponse>("/stats/kpis", undefined, opts);
}

// --- Stats endpoints ---

/** Recupere le nombre d'evenements par minute sur une periode donnee. */
export function getEventsPerMinute(
  params: { minutes?: number } = {},
  opts?: RequestOptions,
): Promise<EventsPerMinuteBucket[]> {
  return request<EventsPerMinuteBucket[]>(
    `/stats/events-per-minute${buildQuery({ minutes: params.minutes })}`,
    undefined,
    opts,
  );
}

/** Recupere les donnees de la heatmap des attaques par jour. */
export function getAttackHeatmap(
  params: { days?: number } = {},
  opts?: RequestOptions,
): Promise<HeatmapCell[]> {
  return request<HeatmapCell[]>(
    `/stats/attack-heatmap${buildQuery({ days: params.days })}`,
    undefined,
    opts,
  );
}

/** Recupere les evenements geolocalises pour la carte des menaces. */
export function getGeoEvents(
  params: { limit?: number } = {},
  opts?: RequestOptions,
): Promise<GeoEvent[]> {
  return request<GeoEvent[]>(
    `/stats/geo-events${buildQuery({ limit: params.limit })}`,
    undefined,
    opts,
  );
}

/** Recupere les donnees du graphe de relations (IP, utilisateurs, incidents). */
export function getRelationshipGraph(
  params: { limit?: number } = {},
  opts?: RequestOptions,
): Promise<GraphData> {
  return request<GraphData>(
    `/stats/graph${buildQuery({ limit: params.limit })}`,
    undefined,
    opts,
  );
}

/** Injecte des donnees de demo pour le graphe et le dashboard. */
export function injectDemoData(opts?: RequestOptions): Promise<{ events_created: number }> {
  return request<{ events_created: number }>(
    "/stats/demo-data",
    { method: "POST" },
    opts,
  );
}

// --- MITRE ATT&CK ---

/** Recupere les statistiques de couverture MITRE ATT&CK. */
export function getMitreStats(opts?: RequestOptions): Promise<MitreStatsResponse> {
  return request<MitreStatsResponse>("/stats/mitre", undefined, opts);
}

/** Recupere la couverture MITRE par tactique (regles vs techniques). */
export function getMitreCoverage(opts?: RequestOptions): Promise<MitreCoverageResponse> {
  return request<MitreCoverageResponse>("/detection/mitre/coverage", undefined, opts);
}

/** Recupere une couche compatible MITRE ATT&CK Navigator (v4.5). */
export function getMitreNavigator(opts?: RequestOptions): Promise<MitreNavigatorLayer> {
  return request<MitreNavigatorLayer>("/detection/mitre/navigator", undefined, opts);
}

// --- Red Team Campaign Engine (Vague 11) ---

export function listCampaignScenarios(opts?: RequestOptions) {
  return request<{ scenarios: CampaignScenarioInfo[] }>(
    "/pentest/campaign/scenarios",
    undefined,
    opts,
  );
}

export function listCampaignActions(opts?: RequestOptions) {
  return request<{ actions: string[] }>("/pentest/campaign/actions", undefined, opts);
}

export function listCampaigns(opts?: RequestOptions) {
  return request<{ campaigns: CampaignSummary[] }>("/pentest/campaign/", undefined, opts);
}

export function startCampaign(
  scenario: string,
  targetOverride?: string,
  opts?: RequestOptions,
) {
  return request<{ campaign_id: string; scenario: string; target: string; stages: number }>(
    "/pentest/campaign/start",
    {
      method: "POST",
      body: JSON.stringify({ scenario, target_override: targetOverride }),
    },
    opts,
  );
}

export function getCampaignState(id: string, opts?: RequestOptions) {
  return request<CampaignState>(`/pentest/campaign/${id}`, undefined, opts);
}

export function getCampaignTimeline(id: string, limit = 200, opts?: RequestOptions) {
  return request<{ campaign_id: string; timeline: CampaignEvent[]; count: number }>(
    `/pentest/campaign/${id}/timeline?limit=${limit}`,
    undefined,
    opts,
  );
}

export function cancelCampaign(id: string, opts?: RequestOptions) {
  return request<{ campaign_id: string; status: string }>(
    `/pentest/campaign/${id}/cancel`,
    { method: "POST" },
    opts,
  );
}

// --- Chat ---

/** Envoie un message a l'assistant (pentest si engagement_id, sinon SOC). */
export function sendChatMessage(
  message: string,
  conversationId?: string,
  engagementId?: string,
  preferProvider?: "anthropic" | "openai" | "ollama",
  opts?: RequestOptions,
): Promise<ChatResponse> {
  return request<ChatResponse>(
    "/chat",
    {
      method: "POST",
      body: JSON.stringify({
        message,
        conversation_id: conversationId,
        engagement_id: engagementId,
        prefer_provider: preferProvider,
      }),
    },
    { ...opts, timeout: 120_000 },
  );
}

/** Liste les engagements red team (pour selecteur chat). */
export function listEngagements(
  opts?: RequestOptions,
): Promise<
  Array<{
    id: string;
    name: string;
    client_name: string;
    status: string;
    kill_switch_active: boolean;
  }>
> {
  return request("/redteam/engagements", { method: "GET" }, opts);
}

/** Liste les conversations (optionnellement par engagement). */
export function listConversations(
  engagementId?: string,
  opts?: RequestOptions,
): Promise<{
  conversations: Array<{
    conversation_id: string;
    started_at: string;
    last_msg: string;
    msg_count: number;
    total_cost_usd: number;
  }>;
}> {
  const qs = engagementId ? `?engagement_id=${encodeURIComponent(engagementId)}` : "";
  return request(`/chat/conversations${qs}`, { method: "GET" }, opts);
}

// --- ML Detection ---

/** Lance la detection d'anomalies par le modele ML (Isolation Forest). */
export function runMLDetection(opts?: RequestOptions): Promise<MLDetectResponse> {
  return request<MLDetectResponse>(
    "/ml/detect",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

/** Recupere les informations sur le modele ML (statut, echantillons, etc.). */
export function getMLModelInfo(opts?: RequestOptions): Promise<MLModelInfo> {
  return request<MLModelInfo>("/ml/model-info", undefined, opts);
}

/** Lance la classification automatique des incidents par le modele ML. */
export function classifyIncidents(opts?: RequestOptions): Promise<ClassifyResponse> {
  return request<ClassifyResponse>(
    "/ml/classify",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

/** Recupere les informations sur le classifieur d'incidents. */
export function getClassifierInfo(opts?: RequestOptions): Promise<ClassifierInfo> {
  return request<ClassifierInfo>("/ml/classifier-info", undefined, opts);
}

// --- Threat Scores ---

/** Recupere la liste des scores de menace par IP. */
export function getThreatScores(
  params: { limit?: number; min_score?: number } = {},
  opts?: RequestOptions,
): Promise<ThreatScoreEntry[]> {
  return request<ThreatScoreEntry[]>(
    `/threat-scores${buildQuery(params)}`,
    undefined,
    opts,
  );
}

/** Recupere le score de menace d'une IP specifique. */
export function getThreatScore(
  ip: string,
  opts?: RequestOptions,
): Promise<ThreatScoreEntry> {
  return request<ThreatScoreEntry>(
    `/threat-scores/${encodeURIComponent(ip)}`,
    undefined,
    opts,
  );
}

/** Declenche le calcul des scores de menace pour toutes les IP. */
export function computeThreatScores(
  opts?: RequestOptions,
): Promise<ThreatScoreComputeResponse> {
  return request<ThreatScoreComputeResponse>(
    "/threat-scores/compute",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

// --- Anomaly detection ---

/** Lance la detection d'anomalies statistiques sur les metriques. */
export function runAnomaly(opts?: RequestOptions): Promise<AnomalyRunResponse> {
  return request<AnomalyRunResponse>(
    "/anomaly/run",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

/** Recupere les lignes de base pour la detection d'anomalies. */
export function getAnomalyBaselines(
  params: { metric_type?: string; limit?: number } = {},
  opts?: RequestOptions,
): Promise<AnomalyBaselineStat[]> {
  return request<AnomalyBaselineStat[]>(
    `/anomaly/baselines${buildQuery(params)}`,
    undefined,
    opts,
  );
}

// --- Scanner ---

/** Analyse un domaine ou une URL via le scanner de securite. */
export function scanTarget(
  target: string,
  opts?: RequestOptions,
): Promise<ScannerResult> {
  return request<ScannerResult>(
    "/scanner/analyze",
    { method: "POST", body: JSON.stringify({ target }) },
    { ...opts, timeout: 60_000 },
  );
}

/** Retourne l'historique des scans. */
export function fetchScanHistory(
  params: { limit?: number; offset?: number; target?: string } = {},
  opts?: RequestOptions,
): Promise<ScanHistoryEntry[]> {
  return request<ScanHistoryEntry[]>(
    `/scanner/history${buildQuery(params)}`,
    undefined,
    opts,
  );
}

/** Retourne le detail complet d'un scan passe. */
export function fetchScanDetail(
  scanId: string,
  opts?: RequestOptions,
): Promise<ScannerResult> {
  return request<ScannerResult>(`/scanner/history/${scanId}`, undefined, opts);
}

/** URL de telechargement PDF d'un scan. */
export function getScanPdfUrl(scanId: string): string {
  return `${BASE_URL}/export/scan/${scanId}/pdf`;
}

/** URL de telechargement PDF d'un incident. */
export function getIncidentPdfUrl(incidentId: string): string {
  return `${BASE_URL}/export/incident/${incidentId}/pdf`;
}

// --- Admin ---

/** Liste les utilisateurs (admin). */
export function fetchUsers(
  params: { limit?: number; offset?: number } = {},
  opts?: RequestOptions,
): Promise<AdminUser[]> {
  return request<AdminUser[]>(`/admin/users${buildQuery(params)}`, undefined, opts);
}

/** Modifie un utilisateur (admin). */
export function updateUser(
  userId: string,
  body: { role?: string; is_active?: boolean },
  opts?: RequestOptions,
): Promise<AdminUser> {
  return request<AdminUser>(
    `/admin/users/${userId}`,
    { method: "PATCH", body: JSON.stringify(body) },
    opts,
  );
}

/** Supprime un utilisateur (admin). */
export function deleteUser(
  userId: string,
  opts?: RequestOptions,
): Promise<void> {
  return request<void>(
    `/admin/users/${userId}`,
    { method: "DELETE" },
    opts,
  );
}

/** Journal d'audit (admin). */
export function fetchAuditLog(
  params: { limit?: number; offset?: number; action?: string } = {},
  opts?: RequestOptions,
): Promise<AuditLogEntry[]> {
  return request<AuditLogEntry[]>(
    `/admin/audit-log${buildQuery(params)}`,
    undefined,
    opts,
  );
}

// --- Log Sources ---

/** Liste les sources de logs actives. */
export function getLogSources(opts?: RequestOptions): Promise<LogSourceStatus[]> {
  return request<LogSourceStatus[]>("/log-sources", undefined, opts);
}

// --- Threat Intelligence ---

/** Lookup TI d'une adresse IP. */
export function lookupIP(
  ip: string,
  opts?: RequestOptions,
): Promise<TILookupResult> {
  return request<TILookupResult>(
    `/threat-intel/lookup/${encodeURIComponent(ip)}`,
    undefined,
    opts,
  );
}

/** Statistiques d'utilisation des APIs TI. */
export function getTIStats(opts?: RequestOptions): Promise<TIStatsResponse> {
  return request<TIStatsResponse>("/threat-intel/stats", undefined, opts);
}

// --- SIGMA Rules ---

/** Liste les regles SIGMA importees. */
export function listSigmaRules(
  params: { enabled_only?: boolean } = {},
  opts?: RequestOptions,
): Promise<SigmaRuleInfo[]> {
  return request<SigmaRuleInfo[]>(
    `/sigma${buildQuery({ enabled_only: params.enabled_only ? "true" : undefined })}`,
    undefined,
    opts,
  );
}

/** Importe une regle SIGMA depuis du YAML. */
export function importSigmaRule(
  yamlContent: string,
  opts?: RequestOptions,
): Promise<SigmaRuleInfo> {
  return request<SigmaRuleInfo>(
    "/sigma/import",
    { method: "POST", body: JSON.stringify({ yaml_content: yamlContent }) },
    opts,
  );
}

/** Active ou desactive une regle SIGMA. */
export function toggleSigmaRule(
  ruleId: number,
  enabled: boolean,
  opts?: RequestOptions,
): Promise<SigmaRuleInfo> {
  return request<SigmaRuleInfo>(
    `/sigma/${ruleId}`,
    { method: "PATCH", body: JSON.stringify({ enabled }) },
    opts,
  );
}

// --- Investigation / OSINT ---

/** Investigation complete d'une IP ou d'un domaine. */
export function investigate(
  target: string,
  opts?: RequestOptions,
): Promise<InvestigateResult> {
  return request<InvestigateResult>(
    `/investigate/${encodeURIComponent(target)}`,
    undefined,
    { ...opts, timeout: 30_000 },
  );
}

/** Audit de securite complet d'une IP ou d'un domaine. */
export function runRecon(
  target: string,
  opts?: RequestOptions,
): Promise<ReconResult> {
  return request<ReconResult>(
    `/recon/${encodeURIComponent(target)}`,
    undefined,
    { ...opts, timeout: 60_000 },
  );
}

/** Supprime une regle SIGMA. */
export function deleteSigmaRule(
  ruleId: number,
  opts?: RequestOptions,
): Promise<void> {
  return request<void>(
    `/sigma/${ruleId}`,
    { method: "DELETE" },
    opts,
  );
}

// --- Pentest Lab ---

import type {
  BruteForceResult,
  WebScanResult,
  StressTestResult,
  BannerResult,
  DirBustResult,
  PayloadTestResult,
  NetworkDiscoveryResult,
  ExploitResult,
} from "./types";

/** Brute force un service (SSH/FTP/HTTP). */
export function pentestBruteforce(
  body: {
    target: string; port?: number; service?: string;
    usernames?: string[]; passwords?: string[];
    http_path?: string; http_user_field?: string; http_pass_field?: string;
    max_threads?: number;
  },
  opts?: RequestOptions,
): Promise<BruteForceResult> {
  return request<BruteForceResult>(
    "/pentest/bruteforce",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 120_000 },
  );
}

/** Scan de vulnerabilites web. */
export function pentestWebScan(
  body: { target_url: string; tests?: string[]; max_threads?: number },
  opts?: RequestOptions,
): Promise<WebScanResult> {
  return request<WebScanResult>(
    "/pentest/webscan",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 120_000 },
  );
}

/** Stress test HTTP. */
export function pentestStress(
  body: { target_url: string; total_requests?: number; concurrency?: number; method?: string },
  opts?: RequestOptions,
): Promise<StressTestResult> {
  return request<StressTestResult>(
    "/pentest/stress",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 300_000 },
  );
}

/** Banner grabbing. */
export function pentestBanner(
  body: { target: string; ports?: number[] },
  opts?: RequestOptions,
): Promise<BannerResult> {
  return request<BannerResult>(
    "/pentest/banner",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 60_000 },
  );
}

/** Directory bruteforce. */
export function pentestDirbust(
  body: { target_url: string; extensions?: string[]; max_threads?: number },
  opts?: RequestOptions,
): Promise<DirBustResult> {
  return request<DirBustResult>(
    "/pentest/dirbust",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 120_000 },
  );
}

/** Test de payloads d'injection. */
export function pentestPayload(
  body: { target_url: string; parameter: string; payload_type?: string; method?: string; payloads?: string[] },
  opts?: RequestOptions,
): Promise<PayloadTestResult> {
  return request<PayloadTestResult>(
    "/pentest/payload",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 60_000 },
  );
}

/** Decouverte reseau. */
export function pentestDiscovery(
  body: { subnet: string; timeout?: number },
  opts?: RequestOptions,
): Promise<NetworkDiscoveryResult> {
  return request<NetworkDiscoveryResult>(
    "/pentest/discovery",
    { method: "POST", body: JSON.stringify(body) },
    { ...opts, timeout: 120_000 },
  );
}

/** Suggestions d'exploits. */
export function pentestExploits(
  services: { port: number; service: string; banner: string }[],
  opts?: RequestOptions,
): Promise<ExploitResult> {
  return request<ExploitResult>(
    "/pentest/exploits",
    { method: "POST", body: JSON.stringify(services) },
    { ...opts, timeout: 15_000 },
  );
}

// --- Pentest extended modules ---

import type {
  WafDetectResult,
  SslAuditResult,
  SubdomainTakeoverResult,
  CorsTestResult,
  HttpMethodsResult,
  FuzzerResult,
  CmsScanResult,
  CrawlResult,
  AuthBypassResult,
  DnsReconResult,
  SsrfTestResult,
  JwtAnalyzeResult,
  SqliAdvancedResult,
  XssHunterResult,
  LfiExploitResult,
  SstiResult,
  XxeResult,
  RaceConditionResult,
  GraphqlResult,
  UploadBypassResult,
  SqliExtractResult,
  RevShellResult,
  PostExploitResult,
  NosqlResult,
  LdapResult,
  ProtoPollutionResult,
  SmugglingResult,
  WsInjectResult,
  CrlfResult,
  OpenRedirectResult,
  PrivescResult,
  CredDumpResult,
  PivotScanResult,
  PayloadEncodeResult,
  PhishingResult,
  ScanResultEntry,
  ScanStats,
  PipelinePreset,
  PipelineStatus,
  WordlistInfo,
} from "./types";

export function pentestWafDetect(body: { target: string }, opts?: RequestOptions): Promise<WafDetectResult> {
  return request<WafDetectResult>("/pentest/waf-detect", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestSslAudit(body: { target: string; port?: number }, opts?: RequestOptions): Promise<SslAuditResult> {
  return request<SslAuditResult>("/pentest/ssl-audit", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestSubdomainTakeover(body: { domain: string }, opts?: RequestOptions): Promise<SubdomainTakeoverResult> {
  return request<SubdomainTakeoverResult>("/pentest/subdomain-takeover", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

export function pentestCors(body: { target: string }, opts?: RequestOptions): Promise<CorsTestResult> {
  return request<CorsTestResult>("/pentest/cors-test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

export function pentestHttpMethods(body: { target: string }, opts?: RequestOptions): Promise<HttpMethodsResult> {
  return request<HttpMethodsResult>("/pentest/http-methods", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

export function pentestFuzz(body: { target: string; parameter: string; rounds?: number }, opts?: RequestOptions): Promise<FuzzerResult> {
  return request<FuzzerResult>("/pentest/fuzz", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

export function pentestCmsScan(body: { target: string }, opts?: RequestOptions): Promise<CmsScanResult> {
  return request<CmsScanResult>("/pentest/cms-scan", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestCrawl(body: { target: string; max_pages?: number }, opts?: RequestOptions): Promise<CrawlResult> {
  return request<CrawlResult>("/pentest/crawl", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

export function pentestAuthBypass(body: { target: string }, opts?: RequestOptions): Promise<AuthBypassResult> {
  return request<AuthBypassResult>("/pentest/auth-bypass", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestDnsRecon(body: { domain: string }, opts?: RequestOptions): Promise<DnsReconResult> {
  return request<DnsReconResult>("/pentest/dns-recon", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestSsrf(body: { target: string; parameter: string }, opts?: RequestOptions): Promise<SsrfTestResult> {
  return request<SsrfTestResult>("/pentest/ssrf-test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

export function pentestJwt(body: { token: string }, opts?: RequestOptions): Promise<JwtAnalyzeResult> {
  return request<JwtAnalyzeResult>("/pentest/jwt-analyze", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

// --- Advanced Attack modules ---
export function pentestSqliAdvanced(body: { target: string; parameter: string; method?: string }, opts?: RequestOptions): Promise<SqliAdvancedResult> {
  return request<SqliAdvancedResult>("/pentest/sqli-advanced", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}
export function pentestXssHunter(body: { target: string; parameter: string }, opts?: RequestOptions): Promise<XssHunterResult> {
  return request<XssHunterResult>("/pentest/xss-hunter", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}
export function pentestLfiExploit(body: { target: string; parameter: string }, opts?: RequestOptions): Promise<LfiExploitResult> {
  return request<LfiExploitResult>("/pentest/lfi-exploit", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestSsti(body: { target: string; parameter: string }, opts?: RequestOptions): Promise<SstiResult> {
  return request<SstiResult>("/pentest/ssti", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestXxe(body: { target: string; endpoint?: string }, opts?: RequestOptions): Promise<XxeResult> {
  return request<XxeResult>("/pentest/xxe", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestRaceCondition(body: { target: string; concurrency?: number; total?: number }, opts?: RequestOptions): Promise<RaceConditionResult> {
  return request<RaceConditionResult>("/pentest/race-condition", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestGraphql(body: { target: string }, opts?: RequestOptions): Promise<GraphqlResult> {
  return request<GraphqlResult>("/pentest/graphql", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestUploadBypass(body: { target: string; endpoint: string; field_name?: string }, opts?: RequestOptions): Promise<UploadBypassResult> {
  return request<UploadBypassResult>("/pentest/upload-bypass", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestSqliExtract(body: { target: string; parameter: string; method?: string; technique?: string; columns?: number; database?: string; table?: string; dump_limit?: number }, opts?: RequestOptions): Promise<SqliExtractResult> {
  return request<SqliExtractResult>("/pentest/sqli-extract", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 180_000 });
}
export function pentestRevShell(body: { lhost: string; lport: number; shell_type?: string; encoding?: string }, opts?: RequestOptions): Promise<RevShellResult> {
  return request<RevShellResult>("/pentest/revshell", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 10_000 });
}
export function pentestPostExploit(body: { target: string; parameter?: string; method?: string; os_target?: string; modules?: string[] }, opts?: RequestOptions): Promise<PostExploitResult> {
  return request<PostExploitResult>("/pentest/post-exploit", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 180_000 });
}
// --- Modules 32-43 ---
export function pentestNosql(body: { target: string; parameter?: string; method?: string }, opts?: RequestOptions): Promise<NosqlResult> {
  return request<NosqlResult>("/pentest/nosql", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}
export function pentestLdap(body: { target: string; parameter?: string; method?: string }, opts?: RequestOptions): Promise<LdapResult> {
  return request<LdapResult>("/pentest/ldap", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestProtoPollution(body: { target: string; method?: string }, opts?: RequestOptions): Promise<ProtoPollutionResult> {
  return request<ProtoPollutionResult>("/pentest/proto-pollution", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestSmuggling(body: { target: string }, opts?: RequestOptions): Promise<SmugglingResult> {
  return request<SmugglingResult>("/pentest/http-smuggling", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestWsInject(body: { target: string }, opts?: RequestOptions): Promise<WsInjectResult> {
  return request<WsInjectResult>("/pentest/ws-inject", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestCrlf(body: { target: string; parameter?: string }, opts?: RequestOptions): Promise<CrlfResult> {
  return request<CrlfResult>("/pentest/crlf", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestOpenRedirect(body: { target: string; parameter?: string }, opts?: RequestOptions): Promise<OpenRedirectResult> {
  return request<OpenRedirectResult>("/pentest/open-redirect", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}
export function pentestPrivesc(body: { target: string; parameter?: string; method?: string; os_target?: string }, opts?: RequestOptions): Promise<PrivescResult> {
  return request<PrivescResult>("/pentest/privesc", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}
export function pentestCredDump(body: { raw_output: string }, opts?: RequestOptions): Promise<CredDumpResult> {
  return request<CredDumpResult>("/pentest/cred-dump", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}
export function pentestPivotScan(body: { target: string; parameter?: string; method?: string; subnet?: string; ports?: number[] }, opts?: RequestOptions): Promise<PivotScanResult> {
  return request<PivotScanResult>("/pentest/pivot-scan", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 300_000 });
}
export function pentestPayloadEncode(body: { payload: string; encodings?: string[] }, opts?: RequestOptions): Promise<PayloadEncodeResult> {
  return request<PayloadEncodeResult>("/pentest/payload-encode", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 10_000 });
}
export function pentestPhishing(body: { target_url: string; capture_url: string }, opts?: RequestOptions): Promise<PhishingResult> {
  return request<PhishingResult>("/pentest/phishing-gen", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

// --- Scan History & Persistence ---
export async function listScans(params?: { module_id?: string; target?: string; severity?: string; limit?: number; offset?: number }, opts?: RequestOptions): Promise<ScanResultEntry[]> {
  const res = await request<{ items: ScanResultEntry[]; total: number; limit: number; offset: number } | ScanResultEntry[]>("/scans" + buildQuery(params || {}), { method: "GET" }, opts);
  return Array.isArray(res) ? res : res.items;
}
export function getScan(id: string, opts?: RequestOptions): Promise<ScanResultEntry> {
  return request<ScanResultEntry>(`/scans/${id}`, { method: "GET" }, opts);
}
export function saveScan(body: { module_id: string; target: string; mode: string; result_json: string; duration_ms: number; findings_count: number; severity_max?: string; notes?: string }, opts?: RequestOptions): Promise<ScanResultEntry> {
  return request<ScanResultEntry>("/scans", { method: "POST", body: JSON.stringify(body) }, opts);
}
export function deleteScan(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/scans/${id}`, { method: "DELETE" }, opts);
}
export function getScanStats(opts?: RequestOptions): Promise<ScanStats> {
  return request<ScanStats>("/scans/stats", { method: "GET" }, opts);
}
export function exportScanJson(id: string): string {
  return `${BASE_URL}/scans/${id}/export/json`;
}
export function exportScanPdf(id: string): string {
  return `${BASE_URL}/scans/${id}/export/pdf`;
}
export function exportScanCsv(id: string): string {
  return `${BASE_URL}/scans/${id}/export/csv`;
}

// --- Pipeline ---
export function listPipelinePresets(opts?: RequestOptions): Promise<Record<string, PipelinePreset>> {
  return request<Record<string, PipelinePreset>>("/pentest/pipelines/presets", { method: "GET" }, opts);
}
export function startPipeline(body: { name: string; target: string; mode?: string; steps: { module_id: string; config?: Record<string, unknown>; condition?: string }[] }, opts?: RequestOptions): Promise<{ pipeline_id: string; status: string; total_steps: number }> {
  return request<{ pipeline_id: string; status: string; total_steps: number }>("/pentest/pipelines/start", { method: "POST", body: JSON.stringify(body) }, opts);
}
export function getPipelineStatus(id: string, opts?: RequestOptions): Promise<PipelineStatus> {
  return request<PipelineStatus>(`/pentest/pipelines/${id}`, { method: "GET" }, opts);
}
export function listPipelines(opts?: RequestOptions): Promise<PipelineStatus[]> {
  return request<PipelineStatus[]>("/pentest/pipelines", { method: "GET" }, opts);
}
export function getPipelineStreamUrl(id: string): string {
  return `${BASE_URL}/pentest/pipelines/${id}/stream`;
}

// --- Wordlists ---
export function listWordlists(opts?: RequestOptions): Promise<WordlistInfo[]> {
  return request<WordlistInfo[]>("/wordlists", { method: "GET" }, opts);
}
export function getWordlist(name: string, opts?: RequestOptions): Promise<{ name: string; count: number; entries: string[] }> {
  return request<{ name: string; count: number; entries: string[] }>(`/wordlists/${name}`, { method: "GET" }, opts);
}

// === Scan Sessions ===
import type {
  ScanSession,
  SessionFinding,
  ChainSuggestion,
  HttpHistoryEntry,
  NvdCve,
  PentestTemplate,
  TemplateScanResult,
} from "./types";

export const createSession = (data: { name: string; target: string; auth?: Record<string, unknown> }) =>
  request<ScanSession>("/pentest/sessions/", { method: "POST", body: JSON.stringify(data) });
export const listSessions = () => request<ScanSession[]>("/pentest/sessions/");
export const getSession = (id: string) => request<ScanSession>(`/pentest/sessions/${id}`);
export const deleteSession = (id: string) => request<void>(`/pentest/sessions/${id}`, { method: "DELETE" });
export const updateSessionAuth = (id: string, auth: Record<string, unknown>) =>
  request<ScanSession>(`/pentest/sessions/${id}/auth`, { method: "PATCH", body: JSON.stringify(auth) });
export const getSessionFindings = (id: string) => request<SessionFinding[]>(`/pentest/sessions/${id}/findings`);
export const getSessionChain = (id: string) => request<ChainSuggestion[]>(`/pentest/sessions/${id}/chain`);
export const getSessionHistory = (id: string, page?: number) =>
  request<{ entries: HttpHistoryEntry[]; total: number }>(`/pentest/sessions/${id}/history?page=${page || 1}`);
export const exportSession = (id: string) => request<ApiJson>(`/pentest/sessions/${id}/export`);

// === NVD CVE ===
export const searchNvdCves = (keyword: string, max?: number) =>
  request<{ results: NvdCve[]; total: number }>(`/pentest/nvd/search?keyword=${encodeURIComponent(keyword)}&max_results=${max || 20}`);
export const getNvdCve = (cveId: string) => request<NvdCve>(`/pentest/nvd/cve/${cveId}`);
export const searchNvdProduct = (vendor: string, product: string, version: string) =>
  request<{ results: NvdCve[] }>(`/pentest/nvd/product?vendor=${vendor}&product=${product}&version=${version}`);

// === Templates ===
export const listTemplates = () => request<PentestTemplate[]>("/pentest/templates/");
export const getTemplate = (id: string) => request<ApiJson>(`/pentest/templates/${id}`);
export const runTemplateScan = (data: { target: string; template_ids?: string[]; tags?: string[]; severity?: string[] }) =>
  request<{ results: TemplateScanResult[]; total_matched: number; duration_ms: number }>("/pentest/templates/scan", { method: "POST", body: JSON.stringify(data) });
export const getTemplateTags = () => request<string[]>("/pentest/templates/tags");

// --- Network Evasion ---
import type {
  NetworkInfo,
  ProxyChainResult,
  TorStatus,
  DnsTunnelResult,
  DomainFrontResult,
  CdnFrontingEntry,
  EgressResult,
  HttpTunnelResult,
  EvasionAdvice,
} from "./types";

/** Recupere les informations reseau locales. */
export function getNetworkInfo(opts?: RequestOptions): Promise<NetworkInfo> {
  return request<NetworkInfo>("/pentest/network/info", undefined, opts);
}

/** Teste une chaine de proxies. */
export function testProxyChain(body: { proxies: string[]; target_url: string }, opts?: RequestOptions): Promise<ProxyChainResult> {
  return request<ProxyChainResult>("/pentest/network/proxy-chain/test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

/** Connexion Tor. */
export function torConnect(body: { control_port?: number; socks_port?: number; password?: string }, opts?: RequestOptions): Promise<TorStatus> {
  return request<TorStatus>("/pentest/network/tor/connect", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

/** Nouvelle identite Tor. */
export function torNewIdentity(body: { control_port?: number; password?: string }, opts?: RequestOptions): Promise<TorStatus> {
  return request<TorStatus>("/pentest/network/tor/new-identity", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

/** Voir le circuit Tor. */
export function torCircuit(body: { control_port?: number; password?: string }, opts?: RequestOptions): Promise<TorStatus> {
  return request<TorStatus>("/pentest/network/tor/circuit", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

/** Encode des donnees en requetes DNS. */
export function dnsTunnelEncode(body: { data: string; domain: string; record_type?: string }, opts?: RequestOptions): Promise<DnsTunnelResult> {
  return request<DnsTunnelResult>("/pentest/network/dns-tunnel/encode", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

/** Decode des donnees depuis des requetes DNS. */
export function dnsTunnelDecode(body: { encoded_data: string; domain?: string }, opts?: RequestOptions): Promise<DnsTunnelResult> {
  return request<DnsTunnelResult>("/pentest/network/dns-tunnel/decode", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

/** Teste la faisabilite de l'exfiltration DNS. */
export function dnsTunnelExfilTest(body: { domain: string }, opts?: RequestOptions): Promise<DnsTunnelResult> {
  return request<DnsTunnelResult>("/pentest/network/dns-tunnel/exfil-test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

/** Teste le domain fronting. */
export function domainFrontTest(body: { front_domain: string; real_host: string; path?: string }, opts?: RequestOptions): Promise<DomainFrontResult> {
  return request<DomainFrontResult>("/pentest/network/domain-front/test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

/** Liste les CDN supportant le fronting. */
export function getCdnFrontingList(opts?: RequestOptions): Promise<CdnFrontingEntry[]> {
  return request<CdnFrontingEntry[]>("/pentest/network/domain-front/cdn-list", undefined, opts);
}

/** Scan des ports de sortie. */
export function egressScan(body: { target: string; ports: string; preset?: string }, opts?: RequestOptions): Promise<EgressResult> {
  return request<EgressResult>("/pentest/network/egress/scan", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

/** Test de tunnel HTTP. */
export function httpTunnelTest(body: { proxy_url: string; target: string; method?: string }, opts?: RequestOptions): Promise<HttpTunnelResult> {
  return request<HttpTunnelResult>("/pentest/network/http-tunnel/test", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 30_000 });
}

/** Conseiller d'evasion reseau. */
export function getEvasionAdvice(body: { tor_available?: boolean; proxy_available?: boolean; dns_unrestricted?: boolean; icmp_allowed?: boolean }, opts?: RequestOptions): Promise<EvasionAdvice[]> {
  return request<EvasionAdvice[]>("/pentest/network/advisor", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 15_000 });
}

// --- Hash Cracker ---
import type {
  HashIdentifyResult,
  HashCrackResult,
  HashBatchResult,
  PentestReportInfo,
  ReportTemplate,
  ReportSummary,
} from "./types";

/** Identifie le type d'un hash. */
export function identifyHash(hash: string, opts?: RequestOptions): Promise<HashIdentifyResult> {
  return request<HashIdentifyResult>("/pentest/hash/identify", { method: "POST", body: JSON.stringify({ hash }) }, opts);
}

/** Crack une liste de hashes via dictionnaire. */
export function crackHashes(body: { hashes: string[]; hash_type?: string; wordlist?: string; rules?: string[] }, opts?: RequestOptions): Promise<{ results: HashCrackResult[] }> {
  return request<{ results: HashCrackResult[] }>("/pentest/hash/crack", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

/** Lookup rapide via rainbow tables. */
export function rainbowLookup(hashes: string[], opts?: RequestOptions): Promise<HashCrackResult[]> {
  return request<HashCrackResult[]>("/pentest/hash/rainbow", { method: "POST", body: JSON.stringify({ hashes }) }, opts);
}

/** Brute force un hash. */
export function bruteforceHash(body: { hash: string; hash_type: string; charset: string; min_length: number; max_length: number }, opts?: RequestOptions): Promise<HashCrackResult> {
  return request<HashCrackResult>("/pentest/hash/bruteforce", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 300_000 });
}

/** Genere des hashes a partir d'un texte. */
export function generateHashes(text: string, algorithms: string[], opts?: RequestOptions): Promise<Record<string, string>> {
  return request<Record<string, string>>("/pentest/hash/generate", { method: "POST", body: JSON.stringify({ text, algorithms }) }, opts);
}

/** Crack batch de hashes avec strategie. */
export function batchCrack(body: { hashes: string[]; strategy: string }, opts?: RequestOptions): Promise<HashBatchResult> {
  return request<HashBatchResult>("/pentest/hash/batch", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 300_000 });
}

/** Statistiques des operations de hash. */
export function getHashStats(opts?: RequestOptions): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>("/pentest/hash/stats", undefined, opts);
}

// --- Pentest Reports ---

/** Genere un rapport PDF et retourne un blob URL pour telechargement. */
export async function generateReport(body: Record<string, unknown>): Promise<string> {
  const res = await fetch(`${BASE_URL}/pentest/report/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { const b = await res.json(); if (b?.detail) detail = String(b.detail); } catch { /* ignore */ }
    throw new Error(`API ${res.status}: ${detail}`);
  }
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

/** Resume rapide de scans selectionnes. */
export function getReportSummary(scan_ids: string[], opts?: RequestOptions): Promise<ReportSummary> {
  return request<ReportSummary>("/pentest/report/summary", { method: "POST", body: JSON.stringify({ scan_ids }) }, opts);
}

/** Liste les templates de rapport disponibles. */
export function getReportTemplates(opts?: RequestOptions): Promise<ReportTemplate[]> {
  return request<ReportTemplate[]>("/pentest/report/templates", undefined, opts);
}

/** Historique des rapports generes. */
export function getReportHistory(opts?: RequestOptions): Promise<PentestReportInfo[]> {
  return request<PentestReportInfo[]>("/pentest/report/history", undefined, opts);
}

// --- Wordlist Generator ---

/** Crawl un site web et extrait des mots pour une wordlist. */
export function crawlWordlist(body: Record<string, unknown>, opts?: RequestOptions): Promise<CrawlWordResult> {
  return request<CrawlWordResult>("/pentest/wordgen/crawl", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 60_000 });
}

/** Applique des mutations sur une liste de mots de base. */
export function mutateWords(body: Record<string, unknown>, opts?: RequestOptions): Promise<MutateResult> {
  return request<MutateResult>("/pentest/wordgen/mutate", { method: "POST", body: JSON.stringify(body) }, opts);
}

/** Genere des noms d'utilisateur a partir de noms complets. */
export function generateUsernames(body: Record<string, unknown>, opts?: RequestOptions): Promise<UsernameResult> {
  return request<UsernameResult>("/pentest/wordgen/usernames", { method: "POST", body: JSON.stringify(body) }, opts);
}

/** Genere des mots a partir d'un pattern avec variables. */
export function generatePattern(body: Record<string, unknown>, opts?: RequestOptions): Promise<PatternResult> {
  return request<PatternResult>("/pentest/wordgen/pattern", { method: "POST", body: JSON.stringify(body) }, opts);
}

/** Genere une wordlist contextuelle basee sur un profil entreprise. */
export function companyProfile(body: Record<string, unknown>, opts?: RequestOptions): Promise<CompanyProfileResult> {
  return request<CompanyProfileResult>("/pentest/wordgen/company-profile", { method: "POST", body: JSON.stringify(body) }, opts);
}

/** Fusionne, deduplique et filtre des listes de mots. */
export function mergeWordlists(body: Record<string, unknown>, opts?: RequestOptions): Promise<MergeResult> {
  return request<MergeResult>("/pentest/wordgen/merge", { method: "POST", body: JSON.stringify(body) }, opts);
}

/** Statistiques du generateur de wordlists. */
export function getWordgenStats(opts?: RequestOptions): Promise<Record<string, unknown>> {
  return request<Record<string, unknown>>("/pentest/wordgen/stats", undefined, opts);
}

// --- Deep Scan ---
import type { DeepScanResult, DeepScanStatus, DeepScanEntry } from "./types";

/** Lance un scan profond complet (crawl + attaque). */
export function deepScan(body: Record<string, unknown>, opts?: RequestOptions): Promise<DeepScanResult> {
  return request<DeepScanResult>("/pentest/deep/scan", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 300_000 });
}

/** Lance un scan profond rapide. */
export function quickDeepScan(body: Record<string, unknown>, opts?: RequestOptions): Promise<DeepScanResult> {
  return request<DeepScanResult>("/pentest/deep/quick", { method: "POST", body: JSON.stringify(body) }, { ...opts, timeout: 120_000 });
}

/** Recupere le statut d'un scan profond en cours. */
export async function getDeepScanStatus(scanId: string, opts?: RequestOptions): Promise<DeepScanStatus & { result?: DeepScanResult }> {
  const raw = await request<ApiJson>(`/pentest/deep/status/${encodeURIComponent(scanId)}`, undefined, opts);
  const mapped: DeepScanStatus & { result?: DeepScanResult } = {
    scan_id: raw.scan_id,
    phase: raw.phase,
    progress: raw.progress ?? raw.percentage ?? 0,
    pages_crawled: raw.pages_crawled ?? 0,
    attack_points: raw.attack_points ?? 0,
    tests_run: raw.tests_run ?? raw.tests_done ?? 0,
    findings: raw.findings ?? raw.findings_so_far ?? 0,
    status: raw.status,
  };
  if (raw.result) mapped.result = raw.result;
  return mapped;
}

/** Liste les scans profonds precedents. */
export async function listDeepScans(opts?: RequestOptions): Promise<DeepScanEntry[]> {
  const res = await request<{ scans: DeepScanEntry[] } | DeepScanEntry[]>("/pentest/deep/scans", undefined, opts);
  if (Array.isArray(res)) return res;
  return (res.scans || []).map((s: DeepScanEntry & { created_at?: string }) => ({ ...s, date: s.date || s.created_at || "" }));
}

// ═══════════════════════════════════════════════════════════════════════════
// BLIND EXTRACTION
// ═══════════════════════════════════════════════════════════════════════════

export function blindExtractTime(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/blind/extract/time", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function blindExtractBoolean(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/blind/extract/boolean", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function blindExtractSchema(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/blind/extract/schema", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function blindCalibrate(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/blind/calibrate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function blindJobStatus(jobId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/blind/status/${encodeURIComponent(jobId)}`, undefined, opts);
}
export function blindListJobs(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/blind/jobs", undefined, opts);
}
export function blindGetPayloads(dbms: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/blind/payloads/${encodeURIComponent(dbms)}`, undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// OOB CALLBACK
// ═══════════════════════════════════════════════════════════════════════════

export function oobCreateListener(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/oob/listener", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function oobGeneratePayloads(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/oob/payloads", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function oobGetListener(token: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/oob/listener/${encodeURIComponent(token)}`, undefined, opts);
}
export function oobListListeners(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/oob/listeners", undefined, opts);
}
export function oobDeleteListener(token: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/oob/listener/${encodeURIComponent(token)}`, { method: "DELETE" }, opts);
}
export function oobGetCallbacks(limit?: number, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/oob/callbacks${limit ? `?limit=${limit}` : ""}`, undefined, opts);
}
export function oobPollListener(token: string, timeout?: number, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/oob/poll/${encodeURIComponent(token)}${timeout ? `?timeout=${timeout}` : ""}`, { method: "POST" }, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// SSRF ADVANCED
// ═══════════════════════════════════════════════════════════════════════════

export function ssrfFullTest(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/test", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function ssrfCloudMetadata(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/cloud-metadata", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function ssrfIpBypass(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/ip-bypass", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function ssrfGopher(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/gopher", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function ssrfPortScan(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/port-scan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function ssrfCheatsheet(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/ssrf/cheatsheet", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// SUBDOMAIN DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════

export function subdomainScan(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/subdomain/scan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function subdomainQuick(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/subdomain/quick", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function subdomainJobStatus(jobId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/subdomain/status/${encodeURIComponent(jobId)}`, undefined, opts);
}
export function subdomainListJobs(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/subdomain/jobs", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// WAF BYPASS
// ═══════════════════════════════════════════════════════════════════════════

export function wafBypassTest(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/waf-bypass/test", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function wafFingerprint(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/waf-bypass/fingerprint", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function wafPolyglots(data?: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/waf-bypass/polyglots", { method: "POST", body: JSON.stringify(data || {}), headers: { "Content-Type": "application/json" } }, opts);
}
export function wafEncode(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/waf-bypass/encode", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function wafGetPayloads(waf: string, vulnType: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/waf-bypass/payloads/${encodeURIComponent(waf)}/${encodeURIComponent(vulnType)}`, undefined, opts);
}
export function wafCheatsheet(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/waf-bypass/cheatsheet", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// EXFILTRATION
// ═══════════════════════════════════════════════════════════════════════════

export function exfilPlan(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/plan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilDNS(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/dns", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilHTTP(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/http", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilICMP(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/icmp", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilStego(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/stego", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilChunked(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/chunked", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function exfilTechniques(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/exfil/techniques", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════

export function persistWebshell(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/webshell", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function persistBackdoor(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/backdoor", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function persistDropper(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/dropper", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function persistCron(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/cron", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function persistSSHKey(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/ssh-key", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function persistTechniques(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/persist/techniques", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// ANTI-FORENSICS
// ═══════════════════════════════════════════════════════════════════════════

export function antiforensicsCleanLogs(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/clean-logs", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsTimestomp(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/timestomp", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsCleanHistory(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/clean-history", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsShred(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/shred", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsEvidenceCheck(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/evidence-check", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsCleanupPlan(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/cleanup-plan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function antiforensicsTechniques(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/antiforensics/techniques", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// KILL CHAIN
// ═══════════════════════════════════════════════════════════════════════════

export function killchainPlan(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/killchain/plan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function killchainPhase(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/killchain/phase", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function killchainTemplates(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/killchain/templates", undefined, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// SHELL HANDLER
// ═══════════════════════════════════════════════════════════════════════════

export function shellStartListener(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/listener/start", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellStopListener(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/listener/stop", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellListListeners(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/listeners", undefined, opts);
}
export function shellListSessions(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/sessions", undefined, opts);
}
export function shellGetSession(sessionId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}`, undefined, opts);
}
export function shellExec(sessionId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}/exec`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellUpload(sessionId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}/upload`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellDownload(sessionId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}/download`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellUpgrade(sessionId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}/upgrade`, { method: "POST" }, opts);
}
export function shellKillSession(sessionId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/shell/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" }, opts);
}
export function shellGetPayloads(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/payloads", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function shellGeneratePayload(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/shell/payloads/generate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// ATTACK CHAIN
// ═══════════════════════════════════════════════════════════════════════════

export function chainStart(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/chain/start", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function chainList(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/chain/chains", undefined, opts);
}
export function chainGet(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}`, undefined, opts);
}
export function chainDelete(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}`, { method: "DELETE" }, opts);
}
export function chainAddFinding(chainId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/finding`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function chainAddCredential(chainId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/credential`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function chainSuggestions(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/suggestions`, undefined, opts);
}
export function chainExecute(chainId: string, data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/execute`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function chainAutoAdvance(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/auto-advance`, { method: "POST" }, opts);
}
export function chainLog(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/log`, undefined, opts);
}
export function chainReport(chainId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/chain/chains/${encodeURIComponent(chainId)}/report`, undefined, opts);
}
export function chainRules(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/chain/rules", undefined, opts);
}
export function chainAddRule(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/chain/rules", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// SQLi ENGINE
// ═══════════════════════════════════════════════════════════════════════════

export function sqliDetect(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/detect", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliExtract(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/extract", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliSchema(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/schema", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliDump(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/dump", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliPrivileges(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/privileges", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliFileRead(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/file-read", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliOsCmd(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/os-cmd", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}
export function sqliJobs(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/jobs", undefined, opts);
}
export function sqliJobStatus(jobId: string, opts?: RequestOptions) {
  return request<ApiJson>(`/pentest/sqli/jobs/${encodeURIComponent(jobId)}`, undefined, opts);
}
export function sqliTampers(opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/tampers", undefined, opts);
}
export function sqliTestTamper(data: Record<string, unknown>, opts?: RequestOptions) {
  return request<ApiJson>("/pentest/sqli/test-tamper", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts);
}

// ═══════════════════════════════════════════════════════════════════════════
// SESSION MANAGER
// ═══════════════════════════════════════════════════════════════════════════
export function sessMgrCreate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/create", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrLogin(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/login", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrProbe(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/probe", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrDetectAuth(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/detect-auth", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrRequest(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/request", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrList(opts?: RequestOptions) { return request<ApiJson>("/pentest/sessions-mgr/sessions", undefined, opts); }
export function sessMgrGet(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/sessions-mgr/sessions/${encodeURIComponent(id)}`, undefined, opts); }
export function sessMgrUpdateCookies(id: string, data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/sessions-mgr/sessions/${encodeURIComponent(id)}/cookies`, { method: "PUT", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function sessMgrRefresh(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/sessions-mgr/sessions/${encodeURIComponent(id)}/refresh`, { method: "POST" }, opts); }
export function sessMgrDelete(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/sessions-mgr/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }, opts); }
export function sessMgrExport(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/sessions-mgr/sessions/${encodeURIComponent(id)}/export`, undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// PRIVILEGE ESCALATION
// ═══════════════════════════════════════════════════════════════════════════
export function privescScan(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/scan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescSuid(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/suid", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescSudo(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/sudo", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescKernel(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/kernel", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescCron(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/cron", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescWindows(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/windows-check", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function privescGtfobins(binary: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/privesc/gtfobins/${encodeURIComponent(binary)}`, undefined, opts); }
export function privescTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/privesc/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// CREDENTIAL AUDITOR
// ═══════════════════════════════════════════════════════════════════════════
export function credsScan(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/scan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsLinuxFiles(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/linux-files", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsWindowsFiles(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/windows-files", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsParse(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/parse", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsSSHKeys(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/ssh-keys", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsBrowser(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/browser", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsCloud(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/cloud", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsValidate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/validate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function credsTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/creds/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// LATERAL MOVEMENT
// ═══════════════════════════════════════════════════════════════════════════
export function lateralSpray(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/spray", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralPtH(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/pth", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralPtT(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/ptt", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralPsexec(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/psexec", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralWmi(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/wmi", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralWinrm(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/winrm", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralSSHPivot(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/ssh-pivot", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralPivotPlan(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/pivot-plan", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralDeploy(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/deploy", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralDiscover(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/discover", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralChisel(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/chisel", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lateralTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/lateral/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// XSS ENGINE
// ═══════════════════════════════════════════════════════════════════════════
export function xssConfirm(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/confirm", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssDetectContext(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/detect-context", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssStealCookie(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/steal-cookie", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssHijack(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/hijack", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssKeylogger(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/keylogger", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssPhishing(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/phishing", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssHook(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/xss-engine/hook", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function xssPayloads(context: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/xss-engine/payloads/${encodeURIComponent(context)}`, undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// LFI TO RCE
// ═══════════════════════════════════════════════════════════════════════════
export function lfiConfirm(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/confirm", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiRead(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/read", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiLogPoison(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/log-poison", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiWrapper(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/wrapper", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiProc(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/proc", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiSessionInclude(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/session-include", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiAutoChain(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/auto-chain", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function lfiTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/lfi-rce/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// PROTOCOL EXPLOITER
// ═══════════════════════════════════════════════════════════════════════════
export function protocolSmbEnum(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/smb/enumerate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolSmbVulns(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/smb/check-vulns", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolLdapEnum(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/ldap/enumerate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolLdapInject(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/ldap/inject", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolRdpCheck(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/rdp/check", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolFtpCheck(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/ftp/check", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolSnmpEnum(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/snmp/enumerate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolDnsCheck(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/dns/check", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolSmtpEnum(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/smtp/enumerate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function protocolTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/protocols/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// EXECUTION BRIDGE
// ═══════════════════════════════════════════════════════════════════════════
export function bridgeExecute(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/execute", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeBatch(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/batch", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeScript(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/script", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeModule(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/module", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeSessions(opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/sessions", undefined, opts); }
export function bridgeHistory(opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/history", undefined, opts); }
export function bridgeClearHistory(opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/history", { method: "DELETE" }, opts); }
export function bridgeCreateTunnel(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/tunnel", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeDeleteTunnel(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/bridge/tunnel/${encodeURIComponent(id)}`, { method: "DELETE" }, opts); }
export function bridgeListTunnels(opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/tunnels", undefined, opts); }
export function bridgeUpload(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/upload", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function bridgeDownload(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/bridge/download", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// C2 SERVER
// ═══════════════════════════════════════════════════════════════════════════
export function c2CreateListener(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/listeners", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function c2ListListeners(opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/listeners", undefined, opts); }
export function c2DeleteListener(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/listeners/${encodeURIComponent(id)}`, { method: "DELETE" }, opts); }
export function c2ListAgents(opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/agents", undefined, opts); }
export function c2GetAgent(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(id)}`, undefined, opts); }
export function c2SendTask(agentId: string, data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(agentId)}/task`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function c2AgentTasks(agentId: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(agentId)}/tasks`, undefined, opts); }
export function c2AgentShell(agentId: string, data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(agentId)}/shell`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function c2KillAgent(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(id)}`, { method: "DELETE" }, opts); }
export function c2AgentSleep(agentId: string, data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/agents/${encodeURIComponent(agentId)}/sleep`, { method: "PATCH", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function c2Dashboard(opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/dashboard", undefined, opts); }
export function c2GenerateImplant(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/implants/generate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function c2ListProfiles(opts?: RequestOptions) { return request<ApiJson>("/pentest/c2/profiles", undefined, opts); }
export function c2EventLog(limit?: number, opts?: RequestOptions) { return request<ApiJson>(`/pentest/c2/log${limit ? `?limit=${limit}` : ""}`, undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// HTTP PROXY
// ═══════════════════════════════════════════════════════════════════════════
export function proxyStart(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/start", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyStop(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/stop", { method: "POST" }, opts); }
export function proxyStatus(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/status", undefined, opts); }
export function proxyHistory(params?: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/history${params ? `?${params}` : ""}`, undefined, opts); }
export function proxyHistoryDetail(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/history/${encodeURIComponent(id)}`, undefined, opts); }
export function proxyClearHistory(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/history", { method: "DELETE" }, opts); }
export function proxyReplay(id: string, data?: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/replay/${encodeURIComponent(id)}`, { method: "POST", body: data ? JSON.stringify(data) : undefined, headers: { "Content-Type": "application/json" } }, opts); }
export function proxySend(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/send", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxySetScope(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/scope", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyGetScope(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/scope", undefined, opts); }
export function proxyToggleIntercept(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/intercept/toggle", { method: "POST" }, opts); }
export function proxySetInterceptRules(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/intercept/rules", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyInterceptQueue(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/intercept/queue", undefined, opts); }
export function proxyForward(id: string, data?: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/intercept/forward/${encodeURIComponent(id)}`, { method: "POST", body: data ? JSON.stringify(data) : undefined, headers: { "Content-Type": "application/json" } }, opts); }
export function proxyDrop(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/intercept/drop/${encodeURIComponent(id)}`, { method: "POST" }, opts); }
export function proxySetMatchReplace(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/match-replace", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyGetMatchReplace(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/match-replace", undefined, opts); }
export function proxySitemap(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/sitemap", undefined, opts); }
export function proxyCompare(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/compare", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyHighlight(id: string, data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>(`/pentest/proxy/highlight/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyExport(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/export", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function proxyStats(opts?: RequestOptions) { return request<ApiJson>("/pentest/proxy/stats", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// AV/EDR EVASION
// ═══════════════════════════════════════════════════════════════════════════
export function evasionEncode(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/encode", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionShellcode(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/shellcode", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionAmsi(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/amsi-bypass", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionLoader(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/loader", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionProcessInject(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/process-inject", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionUnhook(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/unhook", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionSignatures(opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/signatures", undefined, opts); }
export function evasionObfuscate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/obfuscate-script", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionSandbox(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/sandbox-detect", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function evasionTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/evasion/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// FUZZER
// ═══════════════════════════════════════════════════════════════════════════
export function fuzzerParams(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/params", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerHeaders(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/headers", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerDirectories(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/directories", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerVhost(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/vhost", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerAuth(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/auth", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerMutate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/mutate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerApiDiscover(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/api-discover", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerRace(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/race", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function fuzzerJobs(opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/jobs", undefined, opts); }
export function fuzzerJobDetail(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/fuzzer/jobs/${encodeURIComponent(id)}`, undefined, opts); }
export function fuzzerDeleteJob(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/fuzzer/jobs/${encodeURIComponent(id)}`, { method: "DELETE" }, opts); }
export function fuzzerWordlists(opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/wordlists", undefined, opts); }
export function fuzzerTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/fuzzer/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// NETWORK SCANNER
// ═══════════════════════════════════════════════════════════════════════════
export function netscanTcp(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/tcp", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanSyn(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/syn", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanUdp(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/udp", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanBanner(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/banner", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanSweep(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/sweep", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanOsDetect(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/os-detect", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanSsl(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/ssl", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanTraceroute(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/traceroute", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanDns(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/dns", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function netscanJobs(opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/jobs", undefined, opts); }
export function netscanJobDetail(id: string, opts?: RequestOptions) { return request<ApiJson>(`/pentest/netscan/jobs/${encodeURIComponent(id)}`, undefined, opts); }
export function netscanCommonPorts(opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/common-ports", undefined, opts); }
export function netscanTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/netscan/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// EXPLOIT DEV
// ═══════════════════════════════════════════════════════════════════════════
export function exploitPatternCreate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/pattern/create", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitPatternOffset(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/pattern/offset", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitPack(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/pack", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitRopGadgets(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/rop/gadgets", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitRopChain(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/rop/chain", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitFormatString(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/format-string", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitShellcodeGen(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/shellcode/generate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitShellcodeEncode(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/shellcode/encode", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitEgghunter(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/egghunter", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitHeap(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/heap", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitBadChars(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/bad-chars", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function exploitTechniques(opts?: RequestOptions) { return request<ApiJson>("/pentest/exploit-dev/techniques", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// AI ASSISTANT
// ═══════════════════════════════════════════════════════════════════════════
export function aiAnalyze(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/analyze", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiSuggestAttack(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/suggest-attack", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiExplainVuln(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/explain-vuln", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiGeneratePayload(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/generate-payload", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiReviewOutput(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/review-output", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiWriteReport(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/write-report", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiDeobfuscate(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/deobfuscate", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiCraftBypass(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/craft-bypass", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiChat(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/chat", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }
export function aiPersonas(opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/personas", undefined, opts); }
export function aiModels(opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/models", undefined, opts); }

// ═══════════════════════════════════════════════════════════════════════════
// WORKFLOWS
// ═══════════════════════════════════════════════════════════════════════════
export function workflowTemplates(opts?: RequestOptions): Promise<WorkflowTemplate[]> {
  return request<WorkflowTemplate[]>("/pentest/workflows/templates", undefined, opts);
}
export function workflowTemplateDetail(id: string, opts?: RequestOptions): Promise<WorkflowTemplate> {
  return request<WorkflowTemplate>(`/pentest/workflows/templates/${id}`, undefined, opts);
}
export function workflowStart(body: { template_id: string; target: string; custom_name?: string }, opts?: RequestOptions): Promise<WorkflowInstance> {
  return request<WorkflowInstance>("/pentest/workflows/start", { method: "POST", body: JSON.stringify(body) }, opts);
}
export function workflowGet(id: string, opts?: RequestOptions): Promise<WorkflowInstance> {
  return request<WorkflowInstance>(`/pentest/workflows/${id}`, undefined, opts);
}
export function workflowCurrent(id: string, opts?: RequestOptions): Promise<WorkflowStepInstance & { next_params: Record<string, unknown> }> {
  return request<WorkflowStepInstance & { next_params: Record<string, unknown> }>(`/pentest/workflows/${id}/current`, undefined, opts);
}
export function workflowStepStart(wfId: string, stepId: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${wfId}/steps/${stepId}/start`, { method: "POST" }, opts);
}
export function workflowStepComplete(wfId: string, stepId: string, body: { result_summary: string; output_data: Record<string, unknown> }, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${wfId}/steps/${stepId}/complete`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function workflowStepSkip(wfId: string, stepId: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${wfId}/steps/${stepId}/skip`, { method: "POST" }, opts);
}
export function workflowStepNotes(wfId: string, stepId: string, body: { notes: string }, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${wfId}/steps/${stepId}/notes`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function workflowComplete(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${id}/complete`, { method: "POST" }, opts);
}
export function workflowAbandon(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/workflows/${id}/abandon`, { method: "POST" }, opts);
}
export function workflowActive(opts?: RequestOptions): Promise<WorkflowInstance[]> {
  return request<WorkflowInstance[]>("/pentest/workflows/active", undefined, opts);
}
export function workflowReport(id: string, opts?: RequestOptions): Promise<{ markdown: string }> {
  return request<{ markdown: string }>(`/pentest/workflows/${id}/report`, undefined, opts);
}
export function workflowNextParams(id: string, opts?: RequestOptions): Promise<Record<string, unknown>> {
  return request<ApiJson>(`/pentest/workflows/${id}/next-params`, undefined, opts);
}
export function aiChainAnalyze(data: Record<string, unknown>, opts?: RequestOptions) { return request<ApiJson>("/pentest/ai/chain-analyze", { method: "POST", body: JSON.stringify(data), headers: { "Content-Type": "application/json" } }, opts); }

// --- Live Attack Dashboard ---
export function liveDashboard(opts?: RequestOptions): Promise<LiveDashboard> {
  return request<LiveDashboard>("/pentest/live/dashboard", undefined, opts);
}
export function liveTimeline(params?: { limit?: number; offset?: number; severity?: string; module?: string }, opts?: RequestOptions): Promise<LiveEvent[]> {
  return request<LiveEvent[]>("/pentest/live/timeline" + buildQuery(params || {}), undefined, opts);
}
export function liveFindingsStats(opts?: RequestOptions): Promise<LiveFindingStats> {
  return request<LiveFindingStats>("/pentest/live/findings/stats", undefined, opts);
}
export function liveRiskScore(opts?: RequestOptions): Promise<LiveRiskScore> {
  return request<LiveRiskScore>("/pentest/live/risk-score", undefined, opts);
}
export function liveOperations(opts?: RequestOptions): Promise<LiveOperation[]> {
  return request<LiveOperation[]>("/pentest/live/operations", undefined, opts);
}
export function liveAttackMap(opts?: RequestOptions): Promise<LiveAttackMap> {
  return request<LiveAttackMap>("/pentest/live/attack-map", undefined, opts);
}
export function liveAlerts(opts?: RequestOptions): Promise<LiveAlert[]> {
  return request<LiveAlert[]>("/pentest/live/alerts", undefined, opts);
}
export function liveAckAlert(alertId: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/live/alerts/${alertId}/acknowledge`, { method: "POST" }, opts);
}
export function liveKillAll(opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>("/pentest/live/kill-switch/global", { method: "POST" }, opts);
}
export function liveKillOp(opId: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/live/kill-switch/${opId}`, { method: "POST" }, opts);
}
export function liveSimulate(opts?: RequestOptions): Promise<{ operation_id: string }> {
  return request<{ operation_id: string }>("/pentest/live/simulate", { method: "POST" }, opts);
}
export function liveStats(opts?: RequestOptions): Promise<Record<string, unknown>> {
  return request<ApiJson>("/pentest/live/stats", undefined, opts);
}

// --- Auto-Exploit Engine ---
export function autoExploitLaunch(body: { target: string; mode: string; config?: Partial<{ max_depth: number; timeout_per_phase: number; aggressiveness: number; scope_strict: boolean; excluded_modules: string[] }> }, opts?: RequestOptions): Promise<{ session_id: string; status: string }> {
  return request<{ session_id: string; status: string }>("/pentest/auto-exploit/launch", { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } }, opts);
}
export function autoExploitGet(id: string, opts?: RequestOptions): Promise<AutoExploitSession> {
  return request<AutoExploitSession>(`/pentest/auto-exploit/${id}`, undefined, opts);
}
export function autoExploitLive(id: string, opts?: RequestOptions): Promise<AutoExploitLive> {
  return request<AutoExploitLive>(`/pentest/auto-exploit/${id}/live`, undefined, opts);
}
export function autoExploitFindings(id: string, severity?: string, opts?: RequestOptions): Promise<AutoExploitFinding[]> {
  const q = severity ? `?severity=${severity}` : "";
  return request<AutoExploitFinding[]>(`/pentest/auto-exploit/${id}/findings${q}`, undefined, opts);
}
export function autoExploitResume(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/auto-exploit/${id}/resume`, { method: "POST" }, opts);
}
export function autoExploitPause(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/auto-exploit/${id}/pause`, { method: "POST" }, opts);
}
export function autoExploitAbort(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/auto-exploit/${id}/abort`, { method: "POST" }, opts);
}
export function autoExploitSkipPhase(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/auto-exploit/${id}/skip-phase`, { method: "POST" }, opts);
}
export function autoExploitReport(id: string, opts?: RequestOptions): Promise<{ markdown: string }> {
  return request<{ markdown: string }>(`/pentest/auto-exploit/${id}/report`, undefined, opts);
}
export function autoExploitTimeline(id: string, opts?: RequestOptions): Promise<{ timeline: AutoExploitLogEntry[] }> {
  return request<{ timeline: AutoExploitLogEntry[] }>(`/pentest/auto-exploit/${id}/timeline`, undefined, opts);
}
export function autoExploitSessions(opts?: RequestOptions): Promise<AutoExploitSession[]> {
  return request<AutoExploitSession[]>("/pentest/auto-exploit/sessions", undefined, opts);
}

// --- Headless Browser Scanner ---
export function headlessScanLaunch(body: { target: string; config?: Partial<HeadlessScanConfig> }, opts?: RequestOptions): Promise<{ scan_id: string; status: string }> {
  return request<{ scan_id: string; status: string }>("/pentest/headless/scan", { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } }, opts);
}
export function headlessScanGet(id: string, opts?: RequestOptions): Promise<HeadlessScan> {
  return request<HeadlessScan>(`/pentest/headless/${id}`, undefined, opts);
}
export function headlessScanLive(id: string, opts?: RequestOptions): Promise<HeadlessLive> {
  return request<HeadlessLive>(`/pentest/headless/${id}/live`, undefined, opts);
}
export function headlessScanPages(id: string, opts?: RequestOptions): Promise<HeadlessPage[]> {
  return request<HeadlessPage[]>(`/pentest/headless/${id}/pages`, undefined, opts);
}
export function headlessScanDomXss(id: string, opts?: RequestOptions): Promise<HeadlessDomXss[]> {
  return request<HeadlessDomXss[]>(`/pentest/headless/${id}/dom-xss`, undefined, opts);
}
export function headlessScanJs(id: string, opts?: RequestOptions): Promise<HeadlessJsFinding[]> {
  return request<HeadlessJsFinding[]>(`/pentest/headless/${id}/js-analysis`, undefined, opts);
}
export function headlessScanForms(id: string, opts?: RequestOptions): Promise<HeadlessFormResult[]> {
  return request<HeadlessFormResult[]>(`/pentest/headless/${id}/forms`, undefined, opts);
}
export function headlessScanApi(id: string, opts?: RequestOptions): Promise<HeadlessApiEndpoint[]> {
  return request<HeadlessApiEndpoint[]>(`/pentest/headless/${id}/api-map`, undefined, opts);
}
export function headlessScanAuth(id: string, opts?: RequestOptions): Promise<HeadlessAuthAnalysis> {
  return request<HeadlessAuthAnalysis>(`/pentest/headless/${id}/auth`, undefined, opts);
}
export function headlessScanCookies(id: string, opts?: RequestOptions): Promise<HeadlessCookie[]> {
  return request<HeadlessCookie[]>(`/pentest/headless/${id}/cookies`, undefined, opts);
}
export function headlessScanAbort(id: string, opts?: RequestOptions): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/pentest/headless/${id}/abort`, { method: "POST" }, opts);
}
export function headlessScans(opts?: RequestOptions): Promise<HeadlessScan[]> {
  return request<HeadlessScan[]>("/pentest/headless/scans", undefined, opts);
}

// ─── UEBA ──────────────────────────────────────────────────────────────────
export function ubaRefresh(lookbackMin = 60, opts?: RequestOptions): Promise<UbaRefreshResponse> {
  return request<UbaRefreshResponse>(`/uba/refresh?lookback_min=${lookbackMin}`, { method: "POST" }, opts);
}
export function ubaListEntities(minScore = 0, limit = 100, opts?: RequestOptions): Promise<UbaListResponse> {
  return request<UbaListResponse>(`/uba/entities?min_score=${minScore}&limit=${limit}`, undefined, opts);
}
export function ubaGetEntity(entityType: string, entityKey: string, opts?: RequestOptions): Promise<UbaEntity> {
  return request<UbaEntity>(`/uba/entities/${encodeURIComponent(entityType)}/${encodeURIComponent(entityKey)}`, undefined, opts);
}
export function ubaSummary(opts?: RequestOptions): Promise<UbaSummary> {
  return request<UbaSummary>(`/uba/summary`, undefined, opts);
}

// ─── Case Management ────────────────────────────────────────────────────────
export function casesList(filters: { status?: string; priority?: string; sla_breached?: boolean; limit?: number } = {}, opts?: RequestOptions): Promise<{ cases: CaseSummary[]; count: number }> {
  const p = new URLSearchParams();
  if (filters.status) p.set("status", filters.status);
  if (filters.priority) p.set("priority", filters.priority);
  if (filters.sla_breached !== undefined) p.set("sla_breached", String(filters.sla_breached));
  if (filters.limit) p.set("limit", String(filters.limit));
  const q = p.toString();
  return request<{ cases: CaseSummary[]; count: number }>(`/cases/${q ? `?${q}` : ""}`, undefined, opts);
}
export function casesStats(opts?: RequestOptions): Promise<CaseStats> {
  return request<CaseStats>(`/cases/stats`, undefined, opts);
}
export function casesGet(id: string, opts?: RequestOptions): Promise<CaseSummary> {
  return request<CaseSummary>(`/cases/${id}`, undefined, opts);
}
export function casesCreate(body: {
  title: string; description?: string; priority?: string; severity?: string;
  incident_ids?: string[]; tags?: string[];
  sla_response_minutes?: number; sla_resolution_minutes?: number;
}, opts?: RequestOptions): Promise<CaseSummary> {
  return request<CaseSummary>(`/cases/`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function casesTransition(id: string, status: string, note = "", opts?: RequestOptions): Promise<CaseSummary> {
  return request<CaseSummary>(`/cases/${id}/transition`, {
    method: "POST", body: JSON.stringify({ status, note }),
  }, opts);
}
export function casesAssign(id: string, body: { assignee_id?: string; assignee_username?: string }, opts?: RequestOptions): Promise<CaseSummary> {
  return request<CaseSummary>(`/cases/${id}/assign`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function casesClose(id: string, resolution: string, summary = "", opts?: RequestOptions): Promise<CaseSummary> {
  return request<CaseSummary>(`/cases/${id}/close`, {
    method: "POST", body: JSON.stringify({ resolution, summary }),
  }, opts);
}
export function casesAddEvidence(id: string, body: { kind: string; title: string; content: string; extra?: Record<string, unknown> }, opts?: RequestOptions): Promise<CaseEvidenceItem> {
  return request<CaseEvidenceItem>(`/cases/${id}/evidence`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function casesListEvidence(id: string, opts?: RequestOptions): Promise<{ evidence: CaseEvidenceItem[]; count: number }> {
  return request<{ evidence: CaseEvidenceItem[]; count: number }>(`/cases/${id}/evidence`, undefined, opts);
}
export function casesGetTimeline(id: string, opts?: RequestOptions): Promise<{ case_id: string; timeline: CaseTimelineItem[]; count: number }> {
  return request<{ case_id: string; timeline: CaseTimelineItem[]; count: number }>(`/cases/${id}/timeline`, undefined, opts);
}
export function casesScanSla(opts?: RequestOptions): Promise<{ newly_breached: string[]; count: number }> {
  return request<{ newly_breached: string[]; count: number }>(`/cases/sla/scan`, { method: "POST" }, opts);
}

// ─── Compliance ────────────────────────────────────────────────────────────
export function complianceFrameworks(opts?: RequestOptions): Promise<{ frameworks: ComplianceFrameworkInfo[]; count: number }> {
  return request<{ frameworks: ComplianceFrameworkInfo[]; count: number }>(`/compliance/frameworks`, undefined, opts);
}
export function complianceFrameworkReport(fid: string, opts?: RequestOptions): Promise<ComplianceFrameworkReport> {
  return request<ComplianceFrameworkReport>(`/compliance/frameworks/${fid}/report`, undefined, opts);
}
export function complianceGlobalReport(opts?: RequestOptions): Promise<ComplianceGlobalReport> {
  return request<ComplianceGlobalReport>(`/compliance/report`, undefined, opts);
}

// ─── Vague 13 — BloodHound ─────────────────────────────────────────────────
export function bloodhoundExport(body: BloodHoundExportRequest, opts?: RequestOptions): Promise<BloodHoundExportResponse> {
  return request<BloodHoundExportResponse>(`/pentest/bloodhound/export`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function bloodhoundExample(opts?: RequestOptions): Promise<BloodHoundExportResponse> {
  return request<BloodHoundExportResponse>(`/pentest/bloodhound/example`, { method: "POST" }, opts);
}
export function bloodhoundSchema(opts?: RequestOptions): Promise<BloodHoundSchemaInfo> {
  return request<BloodHoundSchemaInfo>(`/pentest/bloodhound/schema`, undefined, opts);
}

// ─── Vague 13 — K8s RBAC ───────────────────────────────────────────────────
export function k8sRbacAudit(manifest: string, target_principal: string | null = null, opts?: RequestOptions): Promise<K8sAuditResult> {
  return request<K8sAuditResult>(`/pentest/k8s/rbac/audit`, {
    method: "POST",
    body: JSON.stringify({ manifest, target_principal }),
  }, opts);
}
export function k8sRbacChecks(opts?: RequestOptions): Promise<K8sRbacChecks> {
  return request<K8sRbacChecks>(`/pentest/k8s/rbac/checks`, undefined, opts);
}

// ─── Vague 13 — Shellcode encoder ──────────────────────────────────────────
export function shellcodeEncode(body: ShellcodeEncodeRequest, opts?: RequestOptions): Promise<ShellcodeEncodeResponse> {
  return request<ShellcodeEncodeResponse>(`/pentest/shellcode/encode`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function shellcodeBadBytesCheck(payload: string, input_encoding: "hex" | "base64", bad_bytes: string[] | string | null, opts?: RequestOptions): Promise<ShellcodeBadByteCheck> {
  return request<ShellcodeBadByteCheck>(`/pentest/shellcode/bad-bytes/check`, {
    method: "POST",
    body: JSON.stringify({ payload, input_encoding, bad_bytes }),
  }, opts);
}
export function shellcodeNopSled(length: number, arch: string, opts?: RequestOptions): Promise<ShellcodeNopSledResponse> {
  return request<ShellcodeNopSledResponse>(`/pentest/shellcode/nop-sled`, {
    method: "POST",
    body: JSON.stringify({ length, arch }),
  }, opts);
}
export function shellcodeMethods(opts?: RequestOptions): Promise<ShellcodeMethods> {
  return request<ShellcodeMethods>(`/pentest/shellcode/methods`, undefined, opts);
}

// ─── Vague 14 — AI Native ──────────────────────────────────────────────────
export function aiStatus(opts?: RequestOptions): Promise<AiStatus> {
  return request<AiStatus>(`/ai/status`, undefined, opts);
}
export function aiLlmCall(body: LlmCallRequest, opts?: RequestOptions): Promise<LlmCallResponse> {
  return request<LlmCallResponse>(`/ai/llm/call`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function aiTriageInline(body: {
  title: string; severity?: string; src_ip?: string; dst_ip?: string;
  username?: string; event_type?: string; message?: string; extra?: Record<string, unknown>;
  prefer?: string;
}, opts?: RequestOptions): Promise<TriageResult> {
  return request<TriageResult>(`/ai/triage/inline`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function aiTriageEvent(eventId: string, prefer?: string, opts?: RequestOptions): Promise<TriageResult> {
  const qs = prefer ? `?prefer=${encodeURIComponent(prefer)}` : "";
  return request<TriageResult>(`/ai/triage/event/${encodeURIComponent(eventId)}${qs}`, { method: "POST" }, opts);
}
export function aiTriageIncident(incidentId: string, prefer?: string, opts?: RequestOptions): Promise<TriageResult> {
  const qs = prefer ? `?prefer=${encodeURIComponent(prefer)}` : "";
  return request<TriageResult>(`/ai/triage/incident/${encodeURIComponent(incidentId)}${qs}`, { method: "POST" }, opts);
}
export function aiRagSearch(body: {
  query: string; top_k?: number; min_score?: number;
  include_events?: boolean; include_incidents?: boolean; lookback_hours?: number;
}, opts?: RequestOptions): Promise<RagSearchResult> {
  return request<RagSearchResult>(`/ai/rag/search`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function aiRagCorpus(lookbackHours = 168, opts?: RequestOptions): Promise<{ corpus_size: number; by_kind: Record<string, number>; approx_token_count: number }> {
  return request(`/ai/rag/corpus?lookback_hours=${lookbackHours}`, undefined, opts);
}
export function aiRulesGenerate(body: RuleGenerateRequest, opts?: RequestOptions): Promise<RuleGenerateResponse> {
  return request<RuleGenerateResponse>(`/ai/rules/generate`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function aiRulesFromEvent(eventId: string, params: { enrich_with_llm?: boolean; formats?: string[]; prefer?: string } = {}, opts?: RequestOptions): Promise<RuleGenerateResponse> {
  const sp = new URLSearchParams();
  if (params.enrich_with_llm) sp.set("enrich_with_llm", "true");
  if (params.prefer) sp.set("prefer", params.prefer);
  (params.formats ?? []).forEach((f) => sp.append("formats", f));
  const qs = sp.toString() ? `?${sp.toString()}` : "";
  return request<RuleGenerateResponse>(`/ai/rules/from-event/${encodeURIComponent(eventId)}${qs}`, { method: "POST" }, opts);
}

// ─── IOC Management ────────────────────────────────────────────────────────
export interface IocApi {
  id: number;
  type: string;
  value: string;
  state: string;
  confidence: number;
  tlp: string;
  source: string;
  tags: string[];
  mitre_techniques: string[];
  kill_chain_phase: string | null;
  metadata: Record<string, unknown>;
  stix_id: string | null;
  first_seen: string | null;
  last_seen: string | null;
  expiry: string | null;
  sightings_count: number;
}
export interface IocCreatePayload {
  type: string;
  value: string;
  source?: string;
  confidence?: number;
  tlp?: string;
  tags?: string[];
  mitre_techniques?: string[];
  kill_chain_phase?: string;
  ttl_hours?: number;
}
export function listIocs(params: {
  type?: string; state?: string; tlp?: string; source?: string;
  search?: string; confidence_min?: number; limit?: number; offset?: number;
} = {}, opts?: RequestOptions): Promise<{ iocs: IocApi[]; count: number }> {
  return request(`/ioc${buildQuery(params)}`, undefined, opts);
}
export function createIoc(body: IocCreatePayload, opts?: RequestOptions): Promise<{ status: string; ioc: IocApi }> {
  return request(`/ioc`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function revokeIoc(id: number, opts?: RequestOptions): Promise<{ status: string }> {
  return request(`/ioc/${id}/revoke`, { method: "POST" }, opts);
}
export function markIocFalsePositive(id: number, opts?: RequestOptions): Promise<{ status: string }> {
  return request(`/ioc/${id}/false-positive`, { method: "POST" }, opts);
}
export function bulkImportIocs(body: { format: "text" | "csv" | "stix"; data: string; source?: string; default_confidence?: number; default_tlp?: string }, opts?: RequestOptions): Promise<{ status: string; count: number }> {
  return request(`/ioc/bulk`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function getIocGraph(limit = 200, opts?: RequestOptions): Promise<{ nodes: { id: number; type: string; value: string; confidence: number }[]; edges: { source: number; target: number; type: string }[] }> {
  return request(`/ioc/graph?limit=${limit}`, undefined, opts);
}

// ---------------------------------------------------------------------------
// SOAR
// ---------------------------------------------------------------------------
export interface PlaybookSummaryApi {
  id: string; name: string; description: string; category: string;
  trigger_type: string; enabled: boolean; builtin: boolean;
  version: number; tags: string[] | null; created_at: string;
}
export interface PlaybookStepApi { name: string; action: string; params?: Record<string, unknown>; condition?: string; on_error?: string }
export interface PlaybookDefinitionApi { steps: PlaybookStepApi[]; rollback_on_failure?: boolean }
export interface PlaybookReadApi extends PlaybookSummaryApi {
  trigger_config: Record<string, unknown> | null;
  definition: PlaybookDefinitionApi;
  updated_at: string;
}
export interface ExecutionReadApi {
  id: string; playbook_id: string; playbook_name: string;
  status: string; trigger: string;
  input_data: Record<string, unknown> | null;
  result: Record<string, unknown> | null;
  error: string | null; dry_run: boolean;
  started_at: string | null; finished_at: string | null;
  duration_ms: number | null; created_at: string;
}
export interface SoarMetricsApi {
  total_playbooks: number; enabled_playbooks: number;
  total_executions: number; completed: number; failed: number;
  cancelled: number; running: number;
  avg_duration_ms: number | null; success_rate: number;
  playbook_usage: { playbook_id: string; playbook_name: string; count: number }[];
  recent_executions: { id: string; playbook_name: string; status: string; started_at: string | null }[];
}
export function listPlaybooks(opts?: RequestOptions): Promise<PlaybookSummaryApi[]> {
  return request(`/soar/playbooks`, undefined, opts);
}
export function getPlaybook(id: string, opts?: RequestOptions): Promise<PlaybookReadApi> {
  return request(`/soar/playbooks/${id}`, undefined, opts);
}
export function getPlaybookHistory(id: string, limit = 50, opts?: RequestOptions): Promise<ExecutionReadApi[]> {
  return request(`/soar/playbooks/${id}/history?limit=${limit}`, undefined, opts);
}
export function executePlaybook(id: string, body: { input_data?: Record<string, unknown>; trigger?: string; incident_id?: string | null } = {}, opts?: RequestOptions): Promise<ExecutionReadApi> {
  return request(`/soar/playbooks/${id}/execute`, { method: "POST", body: JSON.stringify({ input_data: body.input_data ?? {}, trigger: body.trigger ?? "manual", incident_id: body.incident_id ?? null }) }, opts);
}
export function simulatePlaybook(id: string, body: { input_data?: Record<string, unknown>; trigger?: string } = {}, opts?: RequestOptions): Promise<ExecutionReadApi> {
  return request(`/soar/playbooks/${id}/simulate`, { method: "POST", body: JSON.stringify({ input_data: body.input_data ?? {}, trigger: body.trigger ?? "manual" }) }, opts);
}
export function listExecutions(params: { status?: string; playbook_id?: string; limit?: number } = {}, opts?: RequestOptions): Promise<ExecutionReadApi[]> {
  return request(`/soar/executions${buildQuery(params)}`, undefined, opts);
}
export function getExecution(id: string, opts?: RequestOptions): Promise<ExecutionReadApi & { steps?: { name: string; action: string; status: string; output?: unknown; error?: string | null; duration_ms?: number | null }[] }> {
  return request(`/soar/executions/${id}`, undefined, opts);
}
export function cancelExecution(id: string, opts?: RequestOptions): Promise<{ status: string }> {
  return request(`/soar/executions/${id}/cancel`, { method: "POST" }, opts);
}
export function getSoarMetrics(opts?: RequestOptions): Promise<SoarMetricsApi> {
  return request(`/soar/metrics`, undefined, opts);
}

// ---------------------------------------------------------------------------
// Alerts (channels + rules)
// ---------------------------------------------------------------------------
export interface AlertChannelApi {
  id: string; channel_type: string; name: string;
  config_json: string; enabled: boolean; min_severity: string;
  created_at: string; updated_at: string;
}
export interface AlertRuleApi {
  id: string; name: string; description: string;
  conditions_json: string; channel_id: string;
  enabled: boolean; priority: number;
  created_at: string; updated_at?: string;
}
export function listAlertChannels(opts?: RequestOptions): Promise<AlertChannelApi[]> {
  return request(`/alerts/channels`, undefined, opts);
}
export function createAlertChannel(body: { channel_type: string; name: string; config_json?: string; min_severity?: string }, opts?: RequestOptions): Promise<AlertChannelApi> {
  return request(`/alerts/channels`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function updateAlertChannel(id: string, body: Partial<{ name: string; channel_type: string; config_json: string; enabled: boolean; min_severity: string }>, opts?: RequestOptions): Promise<AlertChannelApi> {
  return request(`/alerts/channels/${id}`, { method: "PUT", body: JSON.stringify(body) }, opts);
}
export function deleteAlertChannel(id: string, opts?: RequestOptions): Promise<{ status: string }> {
  return request(`/alerts/channels/${id}`, { method: "DELETE" }, opts);
}
export function testAlertChannel(id: string, opts?: RequestOptions): Promise<{ status: string; message?: string }> {
  return request(`/alerts/channels/${id}/test`, { method: "POST" }, opts);
}
export function listAlertRules(opts?: RequestOptions): Promise<AlertRuleApi[]> {
  return request(`/alerts/rules`, undefined, opts);
}
export function createAlertRule(body: { name: string; description?: string; conditions_json?: string; channel_id: string; priority?: number }, opts?: RequestOptions): Promise<AlertRuleApi> {
  return request(`/alerts/rules`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function updateAlertRule(id: string, body: Partial<{ name: string; description: string; conditions_json: string; channel_id: string; enabled: boolean; priority: number }>, opts?: RequestOptions): Promise<AlertRuleApi> {
  return request(`/alerts/rules/${id}`, { method: "PUT", body: JSON.stringify(body) }, opts);
}
export function deleteAlertRule(id: string, opts?: RequestOptions): Promise<{ status: string }> {
  return request(`/alerts/rules/${id}`, { method: "DELETE" }, opts);
}
export function listAlertDedupFingerprints(opts?: RequestOptions): Promise<{ fingerprints: { fingerprint: string; count: number; first_seen: string; last_seen: string }[] }> {
  return request(`/alerts/dedup/fingerprints`, undefined, opts);
}

// ---------------------------------------------------------------------------
// Pentest Brute Force
// ---------------------------------------------------------------------------
export interface BruteScopeApi { targets: string[] }
export interface BruteWordlistsApi { usernames: string[]; passwords: string[] }
export interface BruteCredential { username: string; password: string }
export interface BruteAttemptApi {
  username: string; password?: string; success: boolean;
  error?: string | null; response_code?: number | null; response_length?: number | null;
}
export interface BruteResultApi {
  id?: number; target: string; service: string; port?: number | null;
  total_attempts: number; successful: number; duration_ms?: number | null;
  credentials_found: BruteCredential[]; attempts?: BruteAttemptApi[];
  started_at?: string; finished_at?: string;
}
export function getBruteScope(opts?: RequestOptions): Promise<BruteScopeApi> {
  return request(`/pentest/brute/scope`, undefined, opts);
}
export function setBruteScope(targets: string[], opts?: RequestOptions): Promise<BruteScopeApi> {
  return request(`/pentest/brute/scope`, { method: "POST", body: JSON.stringify({ targets }) }, opts);
}
export function getBruteWordlists(opts?: RequestOptions): Promise<BruteWordlistsApi> {
  return request(`/pentest/brute/wordlists`, undefined, opts);
}
export function getBruteResults(limit = 50, opts?: RequestOptions): Promise<{ total: number; results: BruteResultApi[] }> {
  return request(`/pentest/brute/results?limit=${limit}`, undefined, opts);
}
export function bruteSsh(body: { target: string; port?: number; usernames: string[]; passwords: string[]; timeout?: number; concurrency?: number; stop_on_success?: boolean; max_attempts?: number }, opts?: RequestOptions): Promise<BruteResultApi> {
  return request(`/pentest/brute/ssh`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function bruteFtp(body: { target: string; port?: number; usernames: string[]; passwords: string[]; timeout?: number; concurrency?: number; stop_on_success?: boolean }, opts?: RequestOptions): Promise<BruteResultApi> {
  return request(`/pentest/brute/ftp`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function bruteHttpBasic(body: { url: string; usernames: string[]; passwords: string[]; timeout?: number; concurrency?: number; stop_on_success?: boolean; auth_type?: string }, opts?: RequestOptions): Promise<BruteResultApi> {
  return request(`/pentest/brute/http-basic`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function bruteHttpForm(body: { url: string; method?: string; username_field: string; password_field: string; usernames: string[]; passwords: string[]; success_indicator?: string; failure_indicator?: string; timeout?: number; concurrency?: number; stop_on_success?: boolean; follow_redirects?: boolean; extra_fields?: Record<string, string>; csrf_field?: string; csrf_url?: string }, opts?: RequestOptions): Promise<BruteResultApi> {
  return request(`/pentest/brute/http-form`, { method: "POST", body: JSON.stringify(body) }, opts);
}

// ---------------------------------------------------------------------------
// Pentest Web Crawler
// ---------------------------------------------------------------------------
export interface CrawlerScopeApi { domains: string[] }
export interface CrawlerPageApi {
  url: string; status_code?: number | null; title?: string | null;
  forms?: { action?: string; method?: string; inputs?: { name: string; type: string }[] }[];
  links?: string[]; technologies?: string[];
}
export interface CrawlerResultApi {
  base_url: string; pages_crawled: number; pages: CrawlerPageApi[];
  forms_found?: number; technologies?: string[]; duration_ms?: number;
}
export function getCrawlerScope(opts?: RequestOptions): Promise<CrawlerScopeApi> {
  return request(`/pentest/crawler/scope`, undefined, opts);
}
export function setCrawlerScope(domains: string[], opts?: RequestOptions): Promise<CrawlerScopeApi> {
  return request(`/pentest/crawler/scope`, { method: "POST", body: JSON.stringify({ domains }) }, opts);
}
export function crawlerCrawl(body: { url: string; max_depth?: number; max_pages?: number; timeout?: number; concurrency?: number; follow_subdomains?: boolean; user_agent?: string; extract_forms?: boolean; extract_js_links?: boolean; check_robots?: boolean; check_sitemap?: boolean }, opts?: RequestOptions): Promise<CrawlerResultApi> {
  return request(`/pentest/crawler/crawl`, { method: "POST", body: JSON.stringify(body) }, opts);
}
export function crawlerAnalyze(body: { url: string; timeout?: number; user_agent?: string }, opts?: RequestOptions): Promise<CrawlerPageApi & { technologies?: string[]; headers?: Record<string, string> }> {
  return request(`/pentest/crawler/analyze`, { method: "POST", body: JSON.stringify(body) }, opts);
}
