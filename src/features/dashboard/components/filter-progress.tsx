"use client";

/**
 * Visible feedback while a filter change is being fetched.
 *
 * Two parts, because one alone is not enough:
 *  - a page-wide bar pinned to the top of the viewport, so the refresh is
 *    noticeable even when the user is looking at a chart further down;
 *  - an inline chip beside the control that was just changed, so it is obvious
 *    which action is in flight.
 */
export function FilterProgressBar({ active }: { active: boolean }) {
  if (!active) return null;

  return (
    <div
      role="progressbar"
      aria-label="Loading filtered results"
      aria-busy="true"
      className="pointer-events-none fixed inset-x-0 top-0 z-[60] h-0.5 overflow-hidden bg-line"
    >
      <div className="filter-progress-sweep h-full w-1/3 bg-accent" />
    </div>
  );
}

export function FilterPendingChip({
  active,
  label = "Updating…",
}: {
  active: boolean;
  label?: string;
}) {
  return (
    <span
      aria-live="polite"
      className={[
        "flex items-center gap-1.5 text-[11px] text-muted transition-opacity duration-150",
        active ? "opacity-100" : "opacity-0",
      ].join(" ")}
    >
      <span
        aria-hidden="true"
        className="h-3 w-3 shrink-0 animate-spin rounded-full border-[1.5px] border-line-strong border-t-accent"
      />
      {active ? label : null}
    </span>
  );
}
