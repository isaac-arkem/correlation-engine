"use client";

import { useState } from "react";
import { cn } from "@/lib/utils/cn";
import { CorrelateForm } from "./correlate-form";
import { LiveForm } from "./live-form";

const TABS = [
  { key: "file", label: "File Upload" },
  { key: "live", label: "Live from ELK" },
] as const;

type Tab = (typeof TABS)[number]["key"];

export function CorrelateTabs() {
  const [tab, setTab] = useState<Tab>("file");

  return (
    <div className="flex flex-col gap-6">
      <div className="flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            onClick={() => setTab(t.key)}
            className={cn(
              "px-3 py-1.5 text-[11px] font-semibold transition-colors",
              tab === t.key
                ? "border-b-2 border-accent text-ink"
                : "text-subtle hover:text-muted"
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "file" && <CorrelateForm />}
      {tab === "live" && <LiveForm />}
    </div>
  );
}
