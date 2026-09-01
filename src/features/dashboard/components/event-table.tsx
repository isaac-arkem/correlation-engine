"use client";

import { useState } from "react";

import { Caption } from "@/components/ui/caption";
import { FilterButton, FilterGroup } from "@/components/ui/top-bar";
import { StatusPill } from "@/components/ui/status-pill";
import { Tag } from "@/components/ui/tag";
import { phaseTone } from "@/components/ui/tone";
import { formatDateTime, formatNumber } from "@/lib/utils/format";
import {
  PHASE_KEYS,
  phaseLabel as phaseLabelUtil,
  sourceLabel,
} from "@/lib/utils/phases";
import type { EventRow } from "../actions";

const PHASES = ["all", ...PHASE_KEYS] as const;

function phaseLabel(phase: string) {
  if (phase === "all") return "All";
  return phaseLabelUtil(phase);
}

export function EventTable({
  events,
  totalCount,
  phaseBreakdown,
}: {
  events: EventRow[];
  totalCount: number;
  phaseBreakdown: Record<string, number>;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const byPhase =
    filter === "all"
      ? events
      : events.filter((e) => e.killChainPhase === filter);

  const needle = search.trim().toLowerCase();
  const filtered = needle
    ? byPhase.filter(
        (e) =>
          (e.signature ?? "").toLowerCase().includes(needle) ||
          (e.message ?? "").toLowerCase().includes(needle) ||
          (e.srcIp ?? "").includes(needle) ||
          (e.destIp ?? "").includes(needle) ||
          e.source.toLowerCase().includes(needle)
      )
    : byPhase;

  const reconCount = phaseBreakdown["reconnaissance"] ?? 0;
  const shownRecon = events.filter(
    (e) => e.killChainPhase === "reconnaissance",
  ).length;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <FilterGroup label="Phase">
          {PHASES.map((phase) => {
            const count =
              phase === "all" ? events.length : (phaseBreakdown[phase] ?? 0);
            if (phase !== "all" && count === 0) return null;
            return (
              <FilterButton
                key={phase}
                active={filter === phase}
                onClick={() => setFilter(phase)}
              >
                {phaseLabel(phase)}
              </FilterButton>
            );
          })}
        </FilterGroup>
        <span className="flex h-7 items-center rounded-md border border-line bg-base px-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, signature…"
            className="w-36 bg-transparent text-[11px] text-ink placeholder:text-subtle outline-none"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="ml-1 text-[10px] text-subtle hover:text-ink"
            >
              ×
            </button>
          )}
        </span>
      </div>

      {filter === "all" && reconCount > shownRecon ? (
        <Caption className="mb-2 normal-case tracking-normal">
          Showing {shownRecon} of {formatNumber(reconCount)} reconnaissance
          probes. Other phases in full.
        </Caption>
      ) : null}

      {events.length < totalCount ? (
        <Caption className="mb-2 normal-case tracking-normal">
          Showing {formatNumber(events.length)} of {formatNumber(totalCount)}{" "}
          linked events.
        </Caption>
      ) : null}

      <div className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-auto">
        {filtered.map((ev) => {
          const open = expanded === ev.id;
          const phase = ev.killChainPhase ?? "unknown";

          return (
            <button
              key={ev.id}
              type="button"
              onClick={() => setExpanded(open ? null : ev.id)}
              className="shrink-0 rounded-md border border-line bg-base px-2.5 py-2 text-left transition-colors hover:border-line-strong"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-[12px] font-medium text-ink">
                  {ev.eventType ?? (ev.eventId != null ? `EID ${ev.eventId}` : "event")}
                </span>
                <StatusPill
                  tone={phaseTone(phase)}
                  label={phaseLabel(phase)}
                />
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                <Tag>{formatDateTime(ev.eventTime)}</Tag>
                <Tag>{sourceLabel(ev.source)}</Tag>
                {ev.srcIp ? <Tag>{ev.srcIp}</Tag> : null}
                {ev.destIp ? <Tag>→ {ev.destIp}</Tag> : null}
              </div>
              <p className="mt-1.5 truncate text-[11px] text-muted">
                {ev.signature ?? ev.message?.slice(0, 120) ?? "—"}
              </p>
              {open && ev.message ? (
                <p className="mt-2 border-l border-line-strong pl-2 text-[11px] text-muted">
                  {ev.message}
                </p>
              ) : null}
            </button>
          );
        })}

        {filtered.length === 0 ? (
          <p className="py-8 text-center text-[12px] text-subtle">
            No events for this filter.
          </p>
        ) : null}
      </div>
    </div>
  );
}
