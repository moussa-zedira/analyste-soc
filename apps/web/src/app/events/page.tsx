"use client";

import { Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { listEvents } from "@/lib/apiClient";
import { eventColumns } from "@/lib/columns";
import { DEFAULT_LIMIT, EVENT_SEVERITY_OPTIONS } from "@/lib/constants";
import { readInt, readParam, useFetchData, usePushParams } from "@/lib/hooks";
import { DataTable } from "@/components/DataTable";
import { FilterBar, FilterInput, FilterSelect } from "@/components/FilterBar";
import { Pagination } from "@/components/Pagination";

function EventsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const pushParams = usePushParams("/events");

  const limit = readInt(searchParams, "limit", DEFAULT_LIMIT);
  const offset = readInt(searchParams, "offset", 0);
  const severity = readParam(searchParams, "severity", "");
  const eventType = readParam(searchParams, "event_type", "");
  const srcIp = readParam(searchParams, "src_ip", "");

  const { data, loading, error } = useFetchData(
    (signal) =>
      listEvents(
        {
          limit,
          offset,
          ...(severity ? { severity } : {}),
          ...(eventType ? { event_type: eventType } : {}),
          ...(srcIp ? { src_ip: srcIp } : {}),
        },
        { signal },
      ),
    [],
    [limit, offset, severity, eventType, srcIp],
  );

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Events</h1>

      <FilterBar onReset={() => router.push("/events")}>
        <FilterSelect
          label="Severity"
          value={severity}
          options={EVENT_SEVERITY_OPTIONS}
          onChange={(v) => pushParams({ severity: v, offset: 0 })}
        />
        <FilterInput
          label="Event type"
          value={eventType}
          placeholder="e.g. auth.fail"
          onChange={(v) => pushParams({ event_type: v, offset: 0 })}
        />
        <FilterInput
          label="Source IP"
          value={srcIp}
          placeholder="e.g. 10.0.0.1"
          onChange={(v) => pushParams({ src_ip: v, offset: 0 })}
        />
      </FilterBar>

      <div className="rounded-lg border border-gray-200 bg-white dark:border-gray-800 dark:bg-gray-900">
        <DataTable
          columns={eventColumns}
          data={data}
          loading={loading}
          error={error}
        />
        {!loading && !error && (
          <div className="px-3 pb-3">
            <Pagination
              offset={offset}
              limit={limit}
              count={data.length}
              onChange={(o) => pushParams({ offset: o })}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default function EventsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-40 items-center justify-center text-gray-500">
          Loading...
        </div>
      }
    >
      <EventsContent />
    </Suspense>
  );
}
