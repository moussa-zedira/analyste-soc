"use client";

import { type ReactNode, useMemo, useState } from "react";

export interface Column<T> {
  header: string;
  accessor: (row: T) => ReactNode;
  /** Return a sortable primitive for this column. If omitted, column is not sortable. */
  sortValue?: (row: T) => string | number;
  className?: string;
}

type SortDir = "asc" | "desc";

function SortIcon({ dir }: { dir: SortDir | null }) {
  if (!dir) {
    return (
      <svg
        className="ml-1 inline h-3 w-3 text-gray-600"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l4-4 4 4M8 15l4 4 4-4" />
      </svg>
    );
  }
  return (
    <svg
      className={`ml-1 inline h-3 w-3 text-cyan-glow transition-transform ${dir === "desc" ? "rotate-180" : ""}`}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2.5}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 15.75l7.5-7.5 7.5 7.5" />
    </svg>
  );
}

const SKELETON_ROWS = 8;

/** Tableau de donnees generique avec tri par colonnes et etats de chargement. */
export function DataTable<T extends { id: string }>({
  columns,
  data,
  loading,
  error,
  onRowClick,
}: {
  columns: Column<T>[];
  data: T[];
  loading: boolean;
  error: string | null;
  onRowClick?: (row: T) => void;
}) {
  const [sortCol, setSortCol] = useState<number | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const handleSort = (idx: number) => {
    if (!columns[idx].sortValue) return;
    if (sortCol === idx) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortCol(idx);
      setSortDir("asc");
    }
  };

  const sortedData = useMemo(() => {
    if (sortCol === null) return data;
    const fn = columns[sortCol].sortValue;
    if (!fn) return data;
    const sorted = [...data].sort((a, b) => {
      const va = fn(a);
      const vb = fn(b);
      if (va < vb) return -1;
      if (va > vb) return 1;
      return 0;
    });
    return sortDir === "desc" ? sorted.reverse() : sorted;
  }, [data, sortCol, sortDir, columns]);

  // Skeleton loading
  if (loading) {
    return (
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-cyan-glow/10 text-xs uppercase">
              {columns.map((col) => (
                <th key={col.header} className={`px-3 py-3 font-medium text-cyan-glow/40 ${col.className ?? ""}`}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: SKELETON_ROWS }).map((_, i) => (
              <tr key={i} className="border-b border-cyan-glow/5">
                {columns.map((col) => (
                  <td key={col.header} className={`px-3 py-3 ${col.className ?? ""}`}>
                    <div className="skeleton h-4 w-3/4 rounded" />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-40 items-center justify-center glass-panel border-red-500/20 text-sm text-red-400">
        <span className="mr-2">&#x25B2;</span>
        {error}
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="flex h-40 flex-col items-center justify-center gap-2 text-gray-500">
        <svg className="h-8 w-8 text-cyan-glow/20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
        </svg>
        <span className="text-xs tracking-wider">NO RESULTS FOUND</span>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="sticky top-0 z-10 bg-space-deep/95 backdrop-blur-sm">
          <tr className="border-b border-cyan-glow/10 text-xs uppercase">
            {columns.map((col, idx) => {
              const sortable = !!col.sortValue;
              const isActive = sortCol === idx;
              return (
                <th
                  key={col.header}
                  onClick={() => sortable && handleSort(idx)}
                  className={`px-3 py-3 font-medium select-none ${col.className ?? ""} ${
                    sortable
                      ? "cursor-pointer transition-colors hover:text-cyan-glow/70"
                      : ""
                  } ${isActive ? "text-cyan-glow" : "text-cyan-glow/40"}`}
                >
                  {col.header}
                  {sortable && <SortIcon dir={isActive ? sortDir : null} />}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sortedData.map((row, i) => (
            <tr
              key={row.id}
              onClick={() => onRowClick?.(row)}
              className={`border-b border-cyan-glow/5 transition-colors duration-150 ${
                onRowClick
                  ? "cursor-pointer hover:bg-cyan-glow/5"
                  : "hover:bg-cyan-glow/[0.02]"
              }`}
              style={{
                animation: i < 20
                  ? `slide-up 0.25s ease-out ${Math.min(i * 0.02, 0.4)}s both`
                  : "none",
              }}
            >
              {columns.map((col) => (
                <td
                  key={col.header}
                  className={`px-3 py-2.5 ${col.className ?? ""}`}
                >
                  {col.accessor(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
