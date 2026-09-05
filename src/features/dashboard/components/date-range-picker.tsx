"use client";

import { useCallback } from "react";

import { Caption } from "@/components/ui/caption";
import { FilterButton } from "@/components/ui/top-bar";
import {
  FilterPendingChip,
  FilterProgressBar,
} from "@/features/dashboard/components/filter-progress";
import { useFilterNav } from "@/features/dashboard/lib/use-filter-nav";
import { dateInputValue } from "@/features/dashboard/lib/window";
import { cn } from "@/lib/utils/cn";

const WINDOWS = [
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "30d", label: "30d" },
  { id: "all", label: "All" },
] as const;

export function DateRangePicker() {
  const { isPending, navigate: push, params } = useFilterNav();
  const from = dateInputValue(params.get("from"));
  const to = dateInputValue(params.get("to"));
  const custom = Boolean(from || to);
  const currentWindow = custom ? null : (params.get("window") ?? "all");

  const selectWindow = useCallback(
    (id: string) => {
      const next = new URLSearchParams(params.toString());
      if (id === "all") next.delete("window");
      else next.set("window", id);
      next.delete("from");
      next.delete("to");
      push(next);
    },
    [params, push],
  );

  const setDate = useCallback(
    (key: "from" | "to", value: string) => {
      const next = new URLSearchParams(params.toString());
      if (value) next.set(key, value);
      else next.delete(key);
      next.delete("window");
      push(next);
    },
    [params, push],
  );

  const clear = useCallback(() => {
    const next = new URLSearchParams(params.toString());
    next.delete("from");
    next.delete("to");
    next.delete("window");
    push(next);
  }, [params, push]);

  return (
    <div className="flex min-w-0 flex-wrap items-end gap-x-6 gap-y-3">
      <FilterProgressBar active={isPending} />

      <div className="flex flex-col gap-1">
        <Caption>Window</Caption>
        <div className="flex h-8 items-center gap-0.5 rounded-md border border-line bg-base p-0.5">
          {WINDOWS.map((item) => (
            <FilterButton
              key={item.id}
              active={currentWindow === item.id}
              disabled={isPending}
              onClick={() => selectWindow(item.id)}
            >
              {item.label}
            </FilterButton>
          ))}
        </div>
      </div>

      <div className="flex items-end gap-2">
        <DateField
          label="From"
          value={from}
          max={to || undefined}
          disabled={isPending}
          onChange={(value) => setDate("from", value)}
        />
        <span className="mb-2 text-[11px] text-subtle" aria-hidden="true">
          →
        </span>
        <DateField
          label="To"
          value={to}
          min={from || undefined}
          disabled={isPending}
          onChange={(value) => setDate("to", value)}
        />
        {custom ? (
          <button
            type="button"
            onClick={clear}
            disabled={isPending}
            className="mb-1.5 text-[11px] text-muted hover:text-ink disabled:opacity-40"
          >
            Reset
          </button>
        ) : null}
        <span className="mb-1.5">
          <FilterPendingChip active={isPending} />
        </span>
      </div>
    </div>
  );
}

function DateField({
  label,
  value,
  min,
  max,
  disabled,
  onChange,
}: {
  label: string;
  value: string;
  min?: string;
  max?: string;
  disabled?: boolean;
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex flex-col gap-1">
      <Caption>{label}</Caption>
      <span
        className={cn(
          "flex h-8 items-center rounded-md border bg-field px-2",
          value ? "border-line-strong" : "border-line",
          "focus-within:border-line-strong",
          disabled && "opacity-50",
        )}
      >
        <input
          type="date"
          value={value}
          min={min}
          max={max}
          disabled={disabled}
          onChange={(event) => onChange(event.target.value)}
          className="w-[9.75rem] bg-transparent font-mono text-[11px] leading-4 text-ink outline-none"
        />
      </span>
    </label>
  );
}
