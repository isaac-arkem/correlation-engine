export type Tone = "active" | "warn" | "danger" | "info" | "neutral";

export const TONES: Record<
  Tone,
  { dot: string; text: string; bg: string; border: string }
> = {
  active: {
    dot: "#6fbf73",
    text: "#6fbf73",
    bg: "#16261a",
    border: "#274d33",
  },
  warn: {
    dot: "#a88940",
    text: "#a88940",
    bg: "#2a2113",
    border: "#4d3f22",
  },
  danger: {
    dot: "#c55f5f",
    text: "#d68080",
    bg: "#2c1414",
    border: "#8f3f3f",
  },
  info: {
    dot: "#60a5fa",
    text: "#60a5fa",
    bg: "#172554",
    border: "#1d4ed8",
  },
  neutral: {
    dot: "#737373",
    text: "#a3a3a3",
    bg: "#1a1a1a",
    border: "#3a3a3a",
  },
};

export function severityTone(severity: string): Tone {
  if (severity === "critical" || severity === "high") return "danger";
  if (severity === "medium") return "warn";
  if (severity === "low") return "active";
  return "neutral";
}

export function statusTone(status: string): Tone {
  if (status === "new") return "info";
  if (status === "investigating") return "warn";
  if (status === "resolved") return "active";
  if (status === "false_positive") return "neutral";
  return "neutral";
}

export function phaseTone(phase: string): Tone {
  if (phase === "reconnaissance") return "info";
  if (phase === "delivery") return "warn";
  if (phase === "exploitation" || phase === "persistence") return "danger";
  if (phase === "command_and_control") return "danger";
  return "neutral";
}
