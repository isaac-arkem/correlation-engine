"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback } from "react";

import { Caption } from "@/components/ui/caption";
import { FilterButton } from "@/components/ui/top-bar";
import { dateInputValue } from "@/features/dashboard/lib/window";
import { cn } from "@/lib/utils/cn";

const WINDOWS = [
  { id: "24h", label: "24h" },
  { id: "7d", label: "7d" },
  { id: "30d", label: "30d" },
  { id: "all", label: "All" },
] as const;

export function DateRangePicker() {
  const router = useRouter();
  const params = useSearchParams();
  const from = dateInputValue(params.get("from"));
  const to = dateInputValue(params.get("to"));
  const custom = Boolean(from || to);
  const currentWindow = custom ? null : (params.get("window") ?? "all");

  const push = useCallback(
    (next: URLSearchParams) => {
      const query = next.toString();
      router.replace(query ? `?${query}` : "/", { scroll: false });
    },
    [router],
  );

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
      <div className="flex flex-col gap-1">
        <Caption>Window</Caption>
        <div className="flex h-8 items-center gap-0.5 rounded-md border border-line bg-base p-0.5">
          {WINDOWS.map((item) => (
            <FilterButton
              key={item.id}
              active={currentWindow === item.id}
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
          onChange={(value) => setDate("from", value)}
        />
        <span className="mb-2 text-[11px] text-subtle" aria-hidden="true">
          →
        </span>
        <DateField
          label="To"
          value={to}
          min={from || undefined}
          onChange={(value) => setDate("to", value)}
        />
        {custom ? (
          <button
            type="button"
            onClick={clear}
            className="mb-1.5 text-[11px] text-muted hover:text-ink"
          >
            Reset
          </button>
        ) : null}
      </div>
    </div>
  );
}

function DateField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: string;
  min?: string;
  max?: string;
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
        )}
      >
        <input
          type="date"
          value={value}
          min={min}
          max={max}
          onChange={(event) => onChange(event.target.value)}
          className="w-[9.75rem] bg-transparent font-mono text-[11px] leading-4 text-ink outline-none"
        />
      </span>
    </label>
  );
}
