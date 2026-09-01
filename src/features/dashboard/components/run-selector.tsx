"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useState, useTransition } from "react";

import { Caption } from "@/components/ui/caption";
import { cn } from "@/lib/utils/cn";
import { deleteRun } from "../actions";

interface Run {
  id: string;
  label: string;
  sourceType: string;
  status: string;
  eventCount: number;
  incidentCount: number;
  createdAt: string;
}

export function RunSelector({
  runs,
  activeRunId,
}: {
  runs: Run[];
  activeRunId: string;
}) {
  const router = useRouter();
  const params = useSearchParams();
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const selectRun = useCallback(
    (runId: string) => {
      const next = new URLSearchParams(params.toString());
      next.set("run", runId);
      next.delete("live");
      const query = next.toString();
      router.replace(query ? `?${query}` : "/", { scroll: false });
    },
    [params, router],
  );

  const visibleRuns = runs.filter((r) => r.status === "completed" || r.status === "running");
  const activeRun = visibleRuns.find((r) => r.id === activeRunId);

  function handleDeleteClick() {
    if (!activeRunId) return;
    setConfirmId(activeRunId);
  }

  function handleConfirmDelete() {
    if (!confirmId) return;
    startTransition(async () => {
      const { success, error } = await deleteRun(confirmId);
      if (!success) {
        alert(error ?? "Failed to delete run");
        setConfirmId(null);
        return;
      }
      setConfirmId(null);
      // Switch to another run or go to correlate page if none left
      const remaining = visibleRuns.filter((r) => r.id !== confirmId);
      if (remaining.length > 0) {
        selectRun(remaining[0].id);
      } else {
        router.replace("/correlate");
      }
      router.refresh();
    });
  }

  return (
    <div className="relative flex flex-col gap-1">
      <Caption>Dataset</Caption>
      <div className="flex items-center gap-1.5">
        <div
          className={cn(
            "flex h-8 flex-1 items-center rounded-md border border-line bg-field px-1",
          )}
        >
          <select
            value={activeRunId}
            onChange={(e) => selectRun(e.target.value)}
            className="w-full min-w-[10rem] bg-transparent font-mono text-[11px] leading-4 text-ink outline-none"
          >
            {visibleRuns.map((run) => (
              <option key={run.id} value={run.id}>
                {run.sourceType === "elasticsearch" ? "[LIVE] " : ""}
                {run.label} ({run.incidentCount} incidents, {run.eventCount}{" "}
                events)
              </option>
            ))}
          </select>
        </div>

        {visibleRuns.length > 0 && (
          <button
            type="button"
            onClick={handleDeleteClick}
            title="Delete this dataset"
            className={cn(
              "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-line bg-field",
              "text-[12px] text-subtle hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400",
              "transition-colors",
            )}
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M3 6h18" />
              <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6" />
              <path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2" />
              <line x1="10" y1="11" x2="10" y2="17" />
              <line x1="14" y1="11" x2="14" y2="17" />
            </svg>
          </button>
        )}
      </div>

      {/* Confirmation popover */}
      {confirmId && (
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={() => setConfirmId(null)}
          />
          <div className="absolute left-0 top-full z-50 mt-1 w-72 rounded-md border border-red-500/30 bg-base px-3 py-3 shadow-lg">
            <p className="text-[11px] text-ink">
              Delete{" "}
              <span className="font-semibold">
                {activeRun?.label ?? "this dataset"}
              </span>
              ? This will permanently remove{" "}
              <span className="font-mono font-semibold">
                {activeRun?.eventCount.toLocaleString() ?? "all"} events
              </span>{" "}
              and{" "}
              <span className="font-mono font-semibold">
                {activeRun?.incidentCount ?? "all"} incidents
              </span>
              .
            </p>
            <div className="mt-2 flex items-center gap-2">
              <button
                type="button"
                onClick={handleConfirmDelete}
                disabled={isPending}
                className={cn(
                  "rounded-md bg-red-500 px-3 py-1 text-[11px] font-semibold text-white",
                  "hover:bg-red-600 disabled:opacity-50",
                )}
              >
                {isPending ? "Deleting…" : "Yes, delete"}
              </button>
              <button
                type="button"
                onClick={() => setConfirmId(null)}
                disabled={isPending}
                className="rounded-md border border-line px-3 py-1 text-[11px] text-subtle hover:text-ink"
              >
                Cancel
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
