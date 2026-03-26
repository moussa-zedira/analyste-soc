import type { Column } from "@/components/DataTable";
import { SeverityBadge } from "@/components/Badge";
import type { Event } from "./types";

const SEVERITY_RANK: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export const eventColumns: Column<Event>[] = [
  {
    header: "Timestamp",
    accessor: (r) => (
      <span className="whitespace-nowrap text-gray-400">
        {new Date(r.ts).toLocaleString()}
      </span>
    ),
    sortValue: (r) => r.ts,
  },
  { header: "Source", accessor: (r) => r.source },
  {
    header: "Type",
    accessor: (r) => r.event_type,
    sortValue: (r) => r.event_type,
  },
  {
    header: "Severity",
    accessor: (r) => <SeverityBadge value={r.severity} />,
    sortValue: (r) => SEVERITY_RANK[r.severity] ?? -1,
  },
  {
    header: "Source IP",
    accessor: (r) => r.src_ip ?? "-",
    sortValue: (r) => r.src_ip ?? "",
  },
  { header: "User", accessor: (r) => r.username ?? "-" },
  {
    header: "Message",
    accessor: (r) => (
      <span className="block max-w-xs truncate" title={r.message ?? ""}>
        {r.message ?? "-"}
      </span>
    ),
  },
];
