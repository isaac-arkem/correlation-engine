import { Caption } from "@/components/ui/caption";
import { formatNumber } from "@/lib/utils/format";
import { PHASES as PHASE_LIST } from "@/lib/utils/phases";
import { TONES, type Tone } from "@/components/ui/tone";
import { GlossaryTerm } from "./glossary-tooltip";

const PHASE_TONES: Record<string, Tone> = {
  reconnaissance: "info",
  delivery: "warn",
  exploitation: "danger",
  persistence: "danger",
  command_and_control: "danger",
};

const PHASES = PHASE_LIST.map((p) => ({
  key: p.key,
  label: p.shortLabel,
  short: p.shortLabel.slice(0, 3).toUpperCase(),
  tone: (PHASE_TONES[p.key] ?? "neutral") as Tone,
}));

export function KillChainBar({
  detected,
  size = "md",
}: {
  detected: string[];
  size?: "sm" | "md";
}) {
  const set = new Set(detected);

  return (
    <div className="flex items-center gap-1">
      {PHASES.map((phase) => {
        const active = set.has(phase.key);
        const colors = TONES[active ? phase.tone : "neutral"];
        return (
          <span
            key={phase.key}
            title={phase.label}
            className="inline-flex items-center gap-1 rounded-brand border px-1.5 py-0.5 font-mono text-[10px]"
            style={{
              background: colors.bg,
              borderColor: colors.border,
              color: colors.text,
              opacity: active ? 1 : 0.45,
            }}
          >
            <span
              className="h-1.5 w-1.5 rounded-full"
              style={{ background: colors.dot }}
            />
            {size === "sm" ? phase.short : phase.label}
          </span>
        );
      })}
    </div>
  );
}

export function KillChainTimeline({
  detected,
  breakdown,
}: {
  detected: string[];
  breakdown: Record<string, number>;
}) {
  const set = new Set(detected);

  return (
    <div className="flex flex-col gap-1.5">
      {PHASES.map((phase) => {
        const active = set.has(phase.key);
        const count = breakdown[phase.key] ?? 0;
        const colors = TONES[active ? phase.tone : "neutral"];

        return (
          <div
            key={phase.key}
            className="shrink-0 rounded-md border border-line bg-base px-2.5 py-2"
            style={{ opacity: active ? 1 : 0.4 }}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate text-[12px] font-medium text-ink">
                <GlossaryTerm term={phase.key}>
                  {phase.label}
                </GlossaryTerm>
              </span>
              <span
                className="h-1.5 w-1.5 shrink-0 rounded-full"
                style={{ background: colors.dot }}
              />
            </div>
            <Caption className="mt-0.5">
              {active && count > 0
                ? `${formatNumber(count)} events`
                : "Not detected"}
            </Caption>
          </div>
        );
      })}
    </div>
  );
}
