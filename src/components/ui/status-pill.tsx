import { TONES, type Tone } from "@/components/ui/tone";

export function StatusPill({
  tone,
  label,
}: {
  tone: Tone;
  label: string;
}) {
  const colors = TONES[tone];

  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-brand border px-1.5 py-0.5 text-[10px] font-medium"
      style={{
        background: colors.bg,
        borderColor: colors.border,
        color: colors.text,
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: colors.dot }}
      />
      {label}
    </span>
  );
}
