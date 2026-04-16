"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { Incident, IncidentDetail, IncidentListParams, IncidentStatus } from "@/lib/types";

const PROXY = "/api/proxy";

async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: "include", ...init });
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

function toQueryString(params: IncidentListParams = {}): string {
  const sp = new URLSearchParams();
  if (params.limit !== undefined) sp.set("limit", String(params.limit));
  if (params.offset !== undefined) sp.set("offset", String(params.offset));
  if (params.severity) sp.set("severity", params.severity);
  if (params.status_filter) sp.set("status_filter", params.status_filter);
  if (params.rule_id) sp.set("rule_id", params.rule_id);
  const qs = sp.toString();
  return qs ? `?${qs}` : "";
}

export const incidentsKeys = {
  all: ["incidents"] as const,
  list: (params?: IncidentListParams) => [...incidentsKeys.all, "list", params ?? {}] as const,
  detail: (id: string) => [...incidentsKeys.all, "detail", id] as const,
};

export function useIncidents(params?: IncidentListParams) {
  return useQuery({
    queryKey: incidentsKeys.list(params),
    queryFn: () => jsonFetch<Incident[]>(`${PROXY}/incidents${toQueryString(params)}`),
  });
}

export function useIncidentDetail(id: string | null) {
  return useQuery({
    queryKey: id ? incidentsKeys.detail(id) : ["incidents", "detail", "_none"],
    queryFn: () => jsonFetch<IncidentDetail>(`${PROXY}/incidents/${id}`),
    enabled: !!id,
  });
}

export function useUpdateIncidentStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: string; status: IncidentStatus }) => {
      return jsonFetch<Incident>(`${PROXY}/incidents/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
    },
    onSuccess: (_data, { id }) => {
      void qc.invalidateQueries({ queryKey: incidentsKeys.detail(id) });
      void qc.invalidateQueries({ queryKey: incidentsKeys.all });
    },
  });
}
