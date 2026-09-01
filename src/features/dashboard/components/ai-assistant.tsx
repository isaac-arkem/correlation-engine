"use client";

import { useRef, useState } from "react";

import { cn } from "@/lib/utils/cn";
import type { OverviewStats, IncidentSummary, IncidentDetail } from "../actions";

interface Message {
  role: "user" | "assistant";
  content: string;
}

function buildContext(stats: OverviewStats, incidents: IncidentSummary[]): string {
  const lines: string[] = [];

  lines.push(`Total events: ${stats.totalEvents}`);
  lines.push(`Classified events: ${stats.classifiedEvents}`);
  lines.push(`Total incidents: ${stats.incidentCount}`);
  lines.push(`Unreviewed critical/high: ${stats.unreviewedCritical}`);

  lines.push(`\nEvents by source: ${Object.entries(stats.bySource).map(([k, v]) => `${k}: ${v}`).join(", ")}`);
  lines.push(`Events by kill chain phase: ${Object.entries(stats.byPhase).map(([k, v]) => `${k}: ${v}`).join(", ")}`);
  lines.push(`Incidents by severity: ${Object.entries(stats.bySeverity).map(([k, v]) => `${k}: ${v}`).join(", ")}`);

  if (incidents.length > 0) {
    lines.push(`\nIncident details:`);
    for (const inc of incidents.slice(0, 20)) {
      lines.push(
        `- ${inc.severity.toUpperCase()} (risk ${inc.riskScore}): ${inc.attackerIp} → ${inc.victimIp} | ` +
        `${inc.eventCount} events | phases: ${inc.phasesDetected.join(", ")} | ` +
        `status: ${inc.status} | ${inc.summary}`
      );
    }
  }

  return lines.join("\n");
}

function buildIncidentContext(incident: IncidentDetail): string {
  const lines: string[] = [];
  lines.push(`Viewing single incident detail page.`);
  lines.push(`Attacker IP: ${incident.attackerIp}`);
  lines.push(`Victim IP: ${incident.victimIp}`);
  lines.push(`Severity: ${incident.severity}`);
  lines.push(`Risk score: ${incident.riskScore}/100`);
  lines.push(`Status: ${incident.status}`);
  lines.push(`Total events: ${incident.eventCount}`);
  lines.push(`Phases detected (${incident.phaseCount}/5): ${incident.phasesDetected.join(", ")}`);
  lines.push(`Phase breakdown: ${Object.entries(incident.phaseBreakdown).map(([k, v]) => `${k}: ${v}`).join(", ")}`);
  lines.push(`Time range: ${incident.firstSeen} to ${incident.lastSeen}`);
  lines.push(`Summary: ${incident.summary}`);

  if (incident.events.length > 0) {
    lines.push(`\nSample events (first 15):`);
    for (const ev of incident.events.slice(0, 15)) {
      lines.push(
        `- [${ev.source}] ${ev.eventTime} | ${ev.srcIp ?? "?"} → ${ev.destIp ?? "?"} | ` +
        `phase: ${ev.killChainPhase ?? "unclassified"} | ${ev.signature ?? ev.message ?? ev.eventType ?? ""}`
      );
    }
  }

  return lines.join("\n");
}

const DASHBOARD_SUGGESTIONS = [
  "What is happening on my dashboard?",
  "Which incidents need urgent attention?",
  "Explain the attack phases detected",
  "Summarize the threat landscape",
];

const INCIDENT_SUGGESTIONS = [
  "Explain this incident to me",
  "How serious is this attack?",
  "What do the attack phases mean?",
  "What should I do about this?",
];

export function AiAssistant({
  stats,
  incidents,
  incident,
}: {
  stats?: OverviewStats;
  incidents?: IncidentSummary[];
  incident?: IncidentDetail;
}) {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  async function ask(question: string) {
    if (!question.trim() || loading) return;

    const userMsg: Message = { role: "user", content: question.trim() };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/api/ai/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: question.trim(),
          context: incident
            ? buildIncidentContext(incident)
            : buildContext(stats!, incidents!),
        }),
      });

      const data = await res.json();
      const reply: Message = {
        role: "assistant",
        content: res.ok ? data.answer : (data.error ?? "Something went wrong."),
      };
      setMessages((prev) => [...prev, reply]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Network error — could not reach the AI service." },
      ]);
    } finally {
      setLoading(false);
      setTimeout(() => {
        scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
      }, 50);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={cn(
          "fixed bottom-4 right-4 z-50 flex h-11 w-11 items-center justify-center rounded-full",
          "bg-yellow-500/90 text-black shadow-lg hover:bg-yellow-400 transition-colors",
        )}
        title="GCTU-SIEM Assistant"
      >
        <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
        </svg>
      </button>
    );
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 flex w-80 flex-col overflow-hidden rounded-lg border border-line bg-base shadow-2xl sm:w-96">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-line bg-field px-3 py-2.5">
        <span className="flex h-6 w-6 items-center justify-center rounded-full bg-yellow-500/20">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#eab308" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
          </svg>
        </span>
        <span className="flex-1 text-[12px] font-semibold text-highlight">GCTU-SIEM Assistant</span>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="text-subtle hover:text-ink"
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M18 6L6 18M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex flex-1 flex-col gap-2 overflow-y-auto overscroll-contain p-3" style={{ maxHeight: "28rem", minHeight: "14rem" }}>
        {messages.length === 0 && (
          <div className="flex flex-col gap-2">
            <p className="text-[11px] text-muted">
              {incident
                ? "Ask me about this incident — what happened, how serious it is, or what to do next."
                : "Ask me anything about your dashboard data — incidents, events, attack phases, or severity levels."}
            </p>
            <div className="flex flex-wrap gap-1.5">
              {(incident ? INCIDENT_SUGGESTIONS : DASHBOARD_SUGGESTIONS).map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => ask(s)}
                  className="rounded-md border border-line bg-field px-2 py-1 text-[10px] text-muted hover:border-yellow-500/40 hover:text-ink transition-colors"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div
            key={i}
            className={cn(
              "max-w-[85%] rounded-md px-2.5 py-2 text-[11px] leading-relaxed",
              msg.role === "user"
                ? "ml-auto bg-yellow-500/15 text-ink"
                : "mr-auto bg-field text-muted",
            )}
          >
            {msg.content}
          </div>
        ))}

        {loading && (
          <div className="mr-auto flex items-center gap-1 rounded-md bg-field px-3 py-2">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-yellow-500" />
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-yellow-500 [animation-delay:150ms]" />
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-yellow-500 [animation-delay:300ms]" />
          </div>
        )}
      </div>

      {/* Input */}
      <form
        onSubmit={(e) => { e.preventDefault(); ask(input); }}
        className="flex items-center gap-2 border-t border-line px-3 py-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask about your data..."
          maxLength={500}
          disabled={loading}
          className="flex-1 bg-transparent text-[11px] text-ink outline-none placeholder:text-subtle disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-yellow-500/20 text-yellow-500 hover:bg-yellow-500/30 disabled:opacity-30 transition-colors"
        >
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="22" y1="2" x2="11" y2="13" />
            <polygon points="22 2 15 22 11 13 2 9 22 2" />
          </svg>
        </button>
      </form>
    </div>
  );
}
