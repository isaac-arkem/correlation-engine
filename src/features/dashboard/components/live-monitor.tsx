"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/utils/cn";

interface PollResult {
  newEvents: number;
  totalEvents: number;
  incidentCount: number;
  pollCount: number;
  maxPolls: number;
}

export function LiveMonitor() {
  const router = useRouter();
  const params = useSearchParams();
  const isLive = params.get("live") === "true";
  const runId = params.get("run");

  const [result, setResult] = useState<PollResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(false);
  const [done, setDone] = useState(false);
  const activeRef = useRef(false);
  const busyRef = useRef(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const runIdRef = useRef(runId);
  runIdRef.current = runId;

  // Start on mount
  useEffect(() => {
    if (isLive && runId) {
      activeRef.current = true;
      setActive(true);
    }
  }, [isLive, runId]);

  // Poll loop
  useEffect(() => {
    if (!active || !runId) return;

    async function poll() {
      if (!activeRef.current || busyRef.current) return;
      busyRef.current = true;

      try {
        const res = await fetch("/api/correlate/live/poll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ runId: runIdRef.current }),
        });

        if (!activeRef.current) return;

        const data = await res.json();
        if (!res.ok) {
          setError(data.error ?? "Poll failed");
          stop();
          return;
        }

        const r = data as PollResult;
        setResult(r);
        setError(null);

        if (r.pollCount >= r.maxPolls) {
          await fetch("/api/correlate/live/stop", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ runId: runIdRef.current }),
          });
          stop();
          setDone(true);
        }
      } catch (err) {
        if (!activeRef.current) return;
        setError(err instanceof Error ? err.message : "Network error");
        stop();
      } finally {
        busyRef.current = false;
      }
    }

    function stop() {
      activeRef.current = false;
      setActive(false);
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    }

    // First poll right away
    poll();

    // Then every 30s
    intervalRef.current = setInterval(poll, 30_000);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
        intervalRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  // Refresh dashboard only once when polling finishes
  useEffect(() => {
    if (done) {
      const next = new URLSearchParams(params.toString());
      next.delete("live");
      router.replace(`?${next.toString()}`, { scroll: false });
      router.refresh();
    }
  }, [done, params, router]);

  async function handleStop() {
    activeRef.current = false;
    setActive(false);
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    if (runId) {
      await fetch("/api/correlate/live/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId }),
      });
    }

    const next = new URLSearchParams(params.toString());
    next.delete("live");
    router.replace(`?${next.toString()}`, { scroll: false });
    router.refresh();
  }

  if (!isLive || !runId) return null;

  return (
    <div
      className={cn(
        "flex items-center gap-4 rounded-md border px-4 py-2.5",
        active
          ? "border-green-500/30 bg-green-500/5"
          : error
            ? "border-red-500/30 bg-red-500/5"
            : "border-line bg-field"
      )}
    >
      {active && (
        <span className="relative flex h-2.5 w-2.5 shrink-0">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
          <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-500" />
        </span>
      )}

      <div className="flex flex-1 flex-wrap items-center gap-x-4 gap-y-1 text-[11px]">
        <span className="font-semibold text-ink">
          {active ? "Live Polling" : error ? "Poll Error" : "Polling Complete"}
        </span>

        {result && (
          <>
            <span className="text-muted">
              <span className="font-mono font-semibold text-ink">
                {result.totalEvents}
              </span>{" "}
              events
            </span>
            <span className="text-muted">
              <span className="font-mono font-semibold text-ink">
                {result.incidentCount}
              </span>{" "}
              incidents
            </span>
            <span className="text-subtle">
              Cycle {result.pollCount}/{result.maxPolls}
            </span>
            {result.newEvents > 0 && (
              <span className="text-green-400">+{result.newEvents} new</span>
            )}
          </>
        )}

        {error && <span className="text-red-400">{error}</span>}
      </div>

      {active && (
        <button
          type="button"
          onClick={handleStop}
          className="shrink-0 rounded-md border border-line bg-field px-3 py-1 text-[10px] font-semibold text-subtle hover:border-red-500/40 hover:text-red-400 transition-colors"
        >
          Stop
        </button>
      )}
    </div>
  );
}
