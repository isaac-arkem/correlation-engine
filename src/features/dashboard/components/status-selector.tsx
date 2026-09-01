"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { TONES, statusTone } from "@/components/ui/tone";
import type { IncidentStatus } from "../actions";
import { updateIncidentStatus } from "../actions";

const STATUS_LABELS: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False Positive",
};

export function StatusSelector({
  incidentId,
  currentStatus,
  userEmail,
}: {
  incidentId: string;
  currentStatus: IncidentStatus;
  userEmail?: string;
}) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  async function handleChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const next = e.target.value as IncidentStatus;
    if (next === currentStatus) return;

    startTransition(async () => {
      const result = await updateIncidentStatus(
        incidentId,
        next,
        userEmail ?? "unknown",
      );
      if (result.success) router.refresh();
    });
  }

  const colors = TONES[statusTone(currentStatus)];

  return (
    <span
      className="relative inline-flex items-center gap-1.5 rounded-brand border px-1.5 py-0.5 text-[10px] font-medium"
      style={{
        background: colors.bg,
        borderColor: colors.border,
        color: colors.text,
        opacity: isPending ? 0.6 : 1,
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: colors.dot }}
      />
      <select
        value={currentStatus}
        onChange={handleChange}
        disabled={isPending}
        className="appearance-none bg-transparent pr-3 font-medium uppercase outline-none"
        style={{ color: "inherit" }}
      >
        {(Object.keys(STATUS_LABELS) as IncidentStatus[]).map((s) => (
          <option key={s} value={s}>
            {STATUS_LABELS[s]}
          </option>
        ))}
      </select>
      <svg
        className="pointer-events-none absolute right-1.5 top-1/2 h-2 w-2 -translate-y-1/2"
        viewBox="0 0 8 8"
        fill="currentColor"
      >
        <path d="M1 3l3 3 3-3z" />
      </svg>
    </span>
  );
}
