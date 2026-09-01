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
  pollInterval?: number;
}

export function LiveMonitor() {
  const router = useRouter();
  const params = useSearchParams();
  const isLive = params.get("live") === "true";
  const runId = params.get("run");

  const [result, setResult] = useState<PollResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState(isLive && !!runId);
  const stoppedRef = useRef(false);
  const paramsRef = useRef(params);
  paramsRef.current = params;

  function clearLiveFlag() {
    const next = new URLSearchParams(paramsRef.current.toString());
    if (!next.has("live")) return;
    next.delete("live");
    const query = next.toString();
    router.replace(query ? `?${query}` : "/", { scroll: false });
  }

  useEffect(() => {
    if (!isLive || !runId) {
      setError(null);
      setActive(false);
      return;
    }

    stoppedRef.current = false;
    setActive(true);
    setError(null);

    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const abort = new AbortController();

    async function markDone() {
      if (runId) {
        await fetch("/api/correlate/live/stop", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ runId }),
        }).catch(() => undefined);
      }
      if (stoppedRef.current) return;
      setActive(false);
      setError(null);
      clearLiveFlag();
    }

    async function tick() {
      if (stoppedRef.current || !runId) return;

      try {
        const res = await fetch("/api/correlate/live/poll", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ runId }),
          signal: abort.signal,
        });

        if (stoppedRef.current) return;

        const data = await res.json();
        if (!res.ok) {
          // Finished runs are expected after the last cycle — not an error.
          if (data.error === "Run already completed") {
            await markDone();
            return;
          }
          setError(data.error ?? "Poll failed");
          setActive(false);
          return;
        }

        const r = data as PollResult;
        setResult(r);
        setError(null);

        if (r.pollCount >= r.maxPolls) {
          await markDone();
          return;
        }

        const waitMs = Math.max(10, r.pollInterval ?? 30) * 1000;
        timeoutId = setTimeout(tick, waitMs);
      } catch (err) {
        if (stoppedRef.current || abort.signal.aborted) return;
        setError(err instanceof Error ? err.message : "Network error");
        setActive(false);
      }
    }

    tick();

    return () => {
      stoppedRef.current = true;
      abort.abort();
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [isLive, runId, router]);

  async function handleStop() {
    stoppedRef.current = true;
    setActive(false);
    setError(null);

    if (runId) {
      await fetch("/api/correlate/live/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId }),
      });
    }

    clearLiveFlag();
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
