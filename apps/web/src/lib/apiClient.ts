import type {
  AnomalyBaselineStat,
  AnomalyRunResponse,
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
  MLDetectResponse,
  MLModelInfo,
  MitreStatsResponse,
  RulesRunResponse,
  ThreatScoreComputeResponse,
  ThreatScoreEntry,
} from "./types";

// In the browser, use the Next.js rewrite proxy to avoid CORS issues.
// On the server (SSR) or when NEXT_PUBLIC_API_BASE_URL is set explicitly,
// call the backend directly.
const BASE_URL =
  typeof window !== "undefined"
    ? "/api/proxy"
    : (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000");
const API_KEY =
  process.env.NEXT_PUBLIC_API_KEY ?? "dev-insecure-key";

const DEFAULT_TIMEOUT_MS = 15_000;

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

export function getHealth(opts?: RequestOptions): Promise<{ status: string }> {
  return request("/health", undefined, opts);
}

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

export function getEvent(id: string, opts?: RequestOptions): Promise<Event> {
  return request<Event>(`/events/${encodeURIComponent(id)}`, undefined, opts);
}

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

export function runRules(opts?: RequestOptions): Promise<RulesRunResponse> {
  return request<RulesRunResponse>(
    "/rules/run",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

// --- KPIs ---

export function getKpis(opts?: RequestOptions): Promise<KpiResponse> {
  return request<KpiResponse>("/stats/kpis", undefined, opts);
}

// --- Stats endpoints ---

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

// --- MITRE ATT&CK ---

export function getMitreStats(opts?: RequestOptions): Promise<MitreStatsResponse> {
  return request<MitreStatsResponse>("/stats/mitre", undefined, opts);
}

// --- Chat ---

export function sendChatMessage(
  message: string,
  conversationId?: string,
  opts?: RequestOptions,
): Promise<ChatResponse> {
  return request<ChatResponse>(
    "/chat",
    {
      method: "POST",
      body: JSON.stringify({
        message,
        conversation_id: conversationId,
      }),
    },
    { ...opts, timeout: 30_000 },
  );
}

// --- ML Detection ---

export function runMLDetection(opts?: RequestOptions): Promise<MLDetectResponse> {
  return request<MLDetectResponse>(
    "/ml/detect",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

export function getMLModelInfo(opts?: RequestOptions): Promise<MLModelInfo> {
  return request<MLModelInfo>("/ml/model-info", undefined, opts);
}

export function classifyIncidents(opts?: RequestOptions): Promise<ClassifyResponse> {
  return request<ClassifyResponse>(
    "/ml/classify",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

export function getClassifierInfo(opts?: RequestOptions): Promise<ClassifierInfo> {
  return request<ClassifierInfo>("/ml/classifier-info", undefined, opts);
}

// --- Threat Scores ---

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

export function runAnomaly(opts?: RequestOptions): Promise<AnomalyRunResponse> {
  return request<AnomalyRunResponse>(
    "/anomaly/run",
    { method: "POST", body: JSON.stringify({}) },
    opts,
  );
}

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
