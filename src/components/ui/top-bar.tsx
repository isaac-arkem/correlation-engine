"use client";

import type { ReactNode } from "react";

import { Caption } from "@/components/ui/caption";
import { NotificationBell } from "@/features/notifications/components/notification-bell";
import { cn } from "@/lib/utils/cn";

export function TopBar({ children }: { children: ReactNode }) {
  return (
    <header className="relative z-40 shrink-0 bg-base/95 backdrop-blur">
      <div className="flex items-end gap-3 px-4 py-2.5 lg:px-6">
        <div className="flex min-w-0 flex-1 flex-wrap items-end justify-between gap-x-6 gap-y-3">
          {children}
        </div>
        <div className="hidden shrink-0 lg:block">
          <NotificationBell />
        </div>
      </div>
    </header>
  );
}

export function ContextTile({
  kicker,
  title,
}: {
  kicker?: string;
  title: string;
}) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      {kicker ? <Caption>{kicker}</Caption> : null}
      <div className="flex h-8 items-center rounded-md border border-line bg-field px-3">
        <span className="truncate text-[12px] font-semibold text-highlight">
          {title}
        </span>
      </div>
    </div>
  );
}

export function FilterGroup({
  children,
  label,
}: {
  children: ReactNode;
  label?: string;
}) {
  return (
    <div className="flex items-center gap-2">
      {label ? (
        <span className="font-mono text-[10px] font-medium uppercase tracking-[0.08em] text-subtle">
          {label}
        </span>
      ) : null}
      <div className="flex items-center gap-0.5 rounded-md border border-line bg-base p-0.5">
        {children}
      </div>
    </div>
  );
}

export function FilterButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick?: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "h-7 rounded-[5px] px-2.5 text-[11px] leading-4",
        active
          ? "bg-field font-medium text-ink"
          : "text-muted hover:text-ink",
      )}
    >
      {children}
    </button>
  );
}
