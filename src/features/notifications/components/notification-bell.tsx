"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";

import { cn } from "@/lib/utils/cn";
import {
  getNotifications,
  markAllAsRead,
  markAsRead,
  type Notification,
} from "../actions";

const TYPE_STYLE: Record<string, { dot: string; border: string }> = {
  critical: { dot: "bg-red-500", border: "border-red-500/30" },
  warning: { dot: "bg-yellow-500", border: "border-yellow-500/30" },
  info: { dot: "bg-blue-500", border: "border-blue-500/30" },
  success: { dot: "bg-green-500", border: "border-green-500/30" },
};

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

export function NotificationBell() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unread, setUnread] = useState(0);
  const [, startTransition] = useTransition();
  const panelRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    const data = await getNotifications();
    setNotifications(data.notifications);
    setUnread(data.unreadCount);
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  function handleNotificationClick(n: Notification) {
    if (!n.read) {
      startTransition(async () => {
        await markAsRead(n.id);
        setNotifications((prev) =>
          prev.map((x) => (x.id === n.id ? { ...x, read: true } : x)),
        );
        setUnread((c) => Math.max(0, c - 1));
      });
    }
    if (n.link) {
      router.push(n.link);
      setOpen(false);
    }
  }

  function handleMarkAll() {
    startTransition(async () => {
      await markAllAsRead();
      setNotifications((prev) => prev.map((x) => ({ ...x, read: true })));
      setUnread(0);
    });
  }

  return (
    <div ref={panelRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="relative flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-ink transition-colors"
        aria-label="Notifications"
      >
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
          <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 01-3.46 0" />
        </svg>
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-red-500 px-1 text-[9px] font-bold text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-80 overflow-hidden rounded-lg border border-line bg-base shadow-2xl">
          <div className="flex items-center justify-between border-b border-line px-3 py-2">
            <span className="text-[12px] font-semibold text-highlight">Notifications</span>
            {unread > 0 && (
              <button
                type="button"
                onClick={handleMarkAll}
                className="text-[10px] text-muted hover:text-ink"
              >
                Mark all read
              </button>
            )}
          </div>

          <div className="max-h-80 overflow-y-auto overscroll-contain">
            {notifications.length === 0 ? (
              <p className="px-3 py-6 text-center text-[11px] text-subtle">
                No notifications yet.
              </p>
            ) : (
              notifications.map((n) => {
                const style = TYPE_STYLE[n.type] ?? TYPE_STYLE.info;
                return (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() => handleNotificationClick(n)}
                    className={cn(
                      "flex w-full gap-2.5 border-b border-line/50 px-3 py-2.5 text-left transition-colors hover:bg-hover",
                      !n.read && "bg-field/50",
                    )}
                  >
                    <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", style.dot)} />
                    <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className={cn(
                          "truncate text-[11px] text-ink",
                          !n.read && "font-semibold",
                        )}>
                          {n.title}
                        </span>
                        <span className="shrink-0 text-[9px] text-subtle">
                          {timeAgo(n.createdAt)}
                        </span>
                      </div>
                      <p className="text-[10px] leading-relaxed text-muted line-clamp-2">
                        {n.message}
                      </p>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
