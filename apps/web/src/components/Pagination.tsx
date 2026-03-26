"use client";

const PAGE_SIZES = [25, 50, 100];

export function Pagination({
  offset,
  limit,
  count,
  onChange,
  onLimitChange,
}: {
  offset: number;
  limit: number;
  count: number;
  onChange: (newOffset: number) => void;
  onLimitChange?: (newLimit: number) => void;
}) {
  const page = Math.floor(offset / limit) + 1;
  const hasPrev = offset > 0;
  const hasNext = count === limit;
  const rangeStart = offset + 1;
  const rangeEnd = offset + count;

  return (
    <div className="flex items-center justify-between border-t border-gray-200 px-1 pt-3 dark:border-gray-800">
      <div className="flex items-center gap-3">
        <p className="text-sm text-gray-400 dark:text-gray-500">
          Page {page}
          {count > 0 && (
            <span className="text-gray-500 dark:text-gray-400">
              {" "}&middot; {rangeStart}–{rangeEnd}
            </span>
          )}
        </p>
        {onLimitChange && (
          <select
            value={limit}
            onChange={(e) => onLimitChange(Number(e.target.value))}
            className="rounded border border-gray-300 bg-gray-100 px-2 py-1 text-xs text-gray-500 outline-none transition-colors focus:border-blue-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-400"
            aria-label="Rows per page"
          >
            {PAGE_SIZES.map((s) => (
              <option key={s} value={s}>
                {s} / page
              </option>
            ))}
          </select>
        )}
      </div>
      <div className="flex gap-1.5">
        <button
          disabled={!hasPrev}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="rounded-lg border border-gray-300 bg-gray-100 px-3 py-1.5 text-sm text-gray-600 transition-all duration-150 hover:bg-gray-200 active:scale-95 disabled:cursor-not-allowed disabled:opacity-40 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          aria-label="Previous page"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
          </svg>
        </button>
        <button
          disabled={!hasNext}
          onClick={() => onChange(offset + limit)}
          className="rounded-lg border border-gray-300 bg-gray-100 px-3 py-1.5 text-sm text-gray-600 transition-all duration-150 hover:bg-gray-200 active:scale-95 disabled:cursor-not-allowed disabled:opacity-40 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          aria-label="Next page"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
          </svg>
        </button>
      </div>
    </div>
  );
}
