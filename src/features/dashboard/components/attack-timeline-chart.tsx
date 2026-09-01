"use client";

import { useMemo } from "react";
import {
  CartesianGrid,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";

import type { EventRow } from "../actions";
import {
  PHASE_MAP,
  phaseShortLabel,
  phaseColor,
  phaseOrder,
  sourceLabel,
} from "@/lib/utils/phases";

function formatAxisDate(ts: number) {
  const d = new Date(ts);
  return `${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
}

interface Point {
  time: number;
  phase: number;
  phaseKey: string;
  phaseName: string;
  source: string;
  signature: string;
  srcIp: string;
  destIp: string;
}

export function AttackTimelineChart({ events }: { events: EventRow[] }) {
  const seriesMap = useMemo(() => {
    const map = new Map<string, Point[]>();

    for (const ev of events) {
      const phase = ev.killChainPhase;
      if (!phase || !PHASE_MAP[phase]) continue;

      const point: Point = {
        time: new Date(ev.eventTime).getTime(),
        phase: phaseOrder(phase),
        phaseKey: phase,
        phaseName: phaseShortLabel(phase),
        source: ev.source,
        signature: ev.signature ?? ev.message?.slice(0, 100) ?? "-",
        srcIp: ev.srcIp ?? "-",
        destIp: ev.destIp ?? "-",
      };

      const existing = map.get(phase) ?? [];
      existing.push(point);
      map.set(phase, existing);
    }

    return map;
  }, [events]);

  if (seriesMap.size === 0) {
    return (
      <p className="py-6 text-center text-[11px] text-subtle">
        No timeline data.
      </p>
    );
  }

  const phases = Array.from(seriesMap.keys()).sort(
    (a, b) => phaseOrder(a) - phaseOrder(b)
  );

  return (
    <ResponsiveContainer width="100%" height={220}>
      <ScatterChart margin={{ top: 8, right: 8, bottom: 4, left: -8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#333" />
        <XAxis
          type="number"
          dataKey="time"
          domain={["dataMin", "dataMax"]}
          tickFormatter={formatAxisDate}
          tick={{ fontSize: 10, fill: "#a3a3a3" }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          type="number"
          dataKey="phase"
          domain={[0.5, 5.5]}
          ticks={[1, 2, 3, 4, 5]}
          tickFormatter={(v: number) => {
            const entry = Object.values(PHASE_MAP).find(
              (p) => p.order === v
            );
            return entry ? entry.shortLabel : "";
          }}
          tick={{ fontSize: 10, fill: "#a3a3a3" }}
          axisLine={false}
          tickLine={false}
          width={52}
        />
        <ZAxis range={[20, 20]} />
        <Tooltip
          content={({ payload }) => {
            if (!payload?.[0]) return null;
            const p = payload[0].payload as Point;
            const desc = PHASE_MAP[p.phaseKey]?.description ?? "";
            return (
              <div
                style={{
                  background: "#141414",
                  border: `1px solid ${phaseColor(p.phaseKey) ?? "#333"}`,
                  borderRadius: 8,
                  padding: "10px 14px",
                  maxWidth: 340,
                  fontSize: 11,
                  lineHeight: "16px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    marginBottom: 6,
                  }}
                >
                  <span
                    style={{
                      display: "inline-block",
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: phaseColor(p.phaseKey) ?? "#737373",
                    }}
                  />
                  <span
                    style={{
                      color: phaseColor(p.phaseKey) ?? "#e5e5e5",
                      fontWeight: 700,
                      fontSize: 12,
                      textTransform: "uppercase",
                      letterSpacing: "0.04em",
                    }}
                  >
                    {p.phaseName}
                  </span>
                </div>
                <div
                  style={{
                    color: "#a3a3a3",
                    marginBottom: 8,
                    fontSize: 11,
                  }}
                >
                  {desc}
                </div>
                <div
                  style={{
                    borderTop: "1px solid #2a2a2a",
                    paddingTop: 6,
                    display: "flex",
                    flexDirection: "column",
                    gap: 3,
                  }}
                >
                  <Row label="Time" value={new Date(p.time).toISOString().replace("T", " ").slice(0, 19)} />
                  <Row label="Flow" value={`${p.srcIp} → ${p.destIp}`} />
                  <Row label="Source" value={sourceLabel(p.source)} />
                  <Row label="Detail" value={p.signature} />
                </div>
              </div>
            );
          }}
        />
        {phases.map((phase) => (
          <Scatter
            key={phase}
            data={seriesMap.get(phase)}
            fill={phaseColor(phase) ?? "#737373"}
            opacity={0.7}
          />
        ))}
      </ScatterChart>
    </ResponsiveContainer>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: "flex", gap: 6, fontSize: 10 }}>
      <span style={{ color: "#666", flexShrink: 0, width: 40 }}>{label}</span>
      <span
        style={{
          color: "#d4d4d4",
          fontFamily: "monospace",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {value}
      </span>
    </div>
  );
}
