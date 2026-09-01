"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { useState } from "react";

import { BrandMark } from "@/components/brand/mark";
import { siteConfig } from "@/config/site";
import { signOut } from "@/features/auth/actions";
import { NotificationBell } from "@/features/notifications/components/notification-bell";
import { cn } from "@/lib/utils/cn";

const NAV = [
  { href: "/", label: "Insights" },
  { href: "/correlate", label: "Correlate" },
  { href: "/evaluation", label: "Evaluation" },
  { href: "/methodology", label: "Methodology" },
  { href: "/help", label: "Help" },
];

function CorrelateIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" />
      <polyline points="7 9 12 4 17 9" />
      <line x1="12" y1="4" x2="12" y2="16" />
    </svg>
  );
}

function MethodologyIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M12 3v18M3 12h18" />
      <path d="M8 8l8 8M16 8l-8 8" />
      <circle cx="12" cy="12" r="9" />
    </svg>
  );
}

function HelpIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M9.5 9.5a2.5 2.5 0 0 1 4.95.5c0 1.5-2.45 2-2.45 3.5" />
      <circle cx="12" cy="17" r=".5" fill="currentColor" />
    </svg>
  );
}

function EvaluationIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M9 11l3 3L22 4" />
      <path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11" />
    </svg>
  );
}

function InsightsIcon() {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  );
}

export function Sidebar({ userEmail }: { userEmail?: string }) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  const params = useSearchParams();
  const query = params.toString();

  function isActive(href: string) {
    if (href === "/") return pathname === "/" || pathname.startsWith("/incidents");
    return pathname.startsWith(href);
  }

  return (
    <aside
      className={cn(
        "hidden shrink-0 flex-col overflow-hidden border-r border-line bg-field lg:flex",
        "gap-0.5 px-1.5 py-2 transition-[width] duration-300 ease-[cubic-bezier(0.25,1,0.5,1)]",
        open ? "w-[13.5rem]" : "w-[3.25rem]",
      )}
      aria-label="Navigation"
    >
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-label="Toggle sidebar"
        className={cn(
          "mb-1 flex h-9 items-center gap-2.5 rounded-md px-2 text-ink",
          !open && "justify-center px-0",
        )}
      >
        <span className="flex w-7 justify-center">
          <BrandMark />
        </span>
        {open ? (
          <>
            <span className="text-[12px] font-semibold text-highlight">
              {siteConfig.name}
            </span>
            <svg className="ml-auto rotate-180" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
              <path d="m9 18 6-6-6-6" />
            </svg>
          </>
        ) : null}
      </button>

      <nav className="mt-1 flex flex-1 flex-col gap-0.5">
        {NAV.map((item) => {
          const active = isActive(item.href);
          return (
            <Link
              key={item.href}
              href={item.href === "/" && query ? `${item.href}?${query}` : item.href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "flex h-9 items-center gap-2.5 rounded-md px-2 text-muted hover:bg-hover hover:text-ink",
                active && "bg-hover text-ink",
                !open && "justify-center px-0",
              )}
            >
              <span className="flex w-7 justify-center">
                {item.href === "/help" ? <HelpIcon /> : item.href === "/methodology" ? <MethodologyIcon /> : item.href === "/correlate" ? <CorrelateIcon /> : item.href === "/evaluation" ? <EvaluationIcon /> : <InsightsIcon />}
              </span>
              {open ? <span className="text-[12px]">{item.label}</span> : null}
            </Link>
          );
        })}
      </nav>

      <div className={cn("mt-auto flex flex-col gap-0.5 border-t border-line pt-1", !open && "items-center")}>
        <div className={cn("flex items-center px-1", !open && "justify-center px-0")}>
          <NotificationBell />
        </div>
      </div>

      <div
        className={cn(
          "flex h-11 items-center gap-2 border-t border-line px-1",
          !open && "justify-center px-0",
        )}
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-neutral-800 text-[10px] font-semibold text-ink ring-1 ring-line">
          {userEmail ? userEmail.slice(0, 2).toUpperCase() : "OP"}
        </span>
        {open ? (
          <div className="flex min-w-0 flex-1 items-center gap-1.5">
            <span className="truncate font-mono text-[10px] text-muted">
              {userEmail ?? "Operator"}
            </span>
            <form action={signOut} className="ml-auto">
              <button
                type="submit"
                className="text-[10px] text-muted hover:text-ink"
              >
                Out
              </button>
            </form>
          </div>
        ) : null}
      </div>
    </aside>
  );
}
