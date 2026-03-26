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
    <div className="flex items-center justify-between border-t border-cyan-glow/10 px-1 pt-3">
      <div className="flex items-center gap-3">
        <p className="text-xs text-gray-500">
          <span className="font-mono text-cyan-glow/60">PAGE {page}</span>
          {count > 0 && (
            <span className="text-gray-600">
              {" "}&middot; {rangeStart}&ndash;{rangeEnd}
            </span>
          )}
        </p>
        {onLimitChange && (
          <select
            value={limit}
            onChange={(e) => onLimitChange(Number(e.target.value))}
            className="rounded-md border border-cyan-glow/15 bg-space-dark px-2 py-1 text-xs text-gray-400 outline-none transition-colors focus:border-cyan-glow/40"
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
          className="rounded-md border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-gray-400 transition-all hover:border-cyan-glow/40 hover:bg-cyan-glow/10 hover:text-cyan-glow active:scale-95 disabled:cursor-not-allowed disabled:opacity-30"
          aria-label="Previous page"
        >
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
          </svg>
        </button>
        <button
          disabled={!hasNext}
          onClick={() => onChange(offset + limit)}
          className="rounded-md border border-cyan-glow/20 bg-space-mid/50 px-3 py-1.5 text-gray-400 transition-all hover:border-cyan-glow/40 hover:bg-cyan-glow/10 hover:text-cyan-glow active:scale-95 disabled:cursor-not-allowed disabled:opacity-30"
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
