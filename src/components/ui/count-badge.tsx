import { cn } from "@/lib/utils/cn";

export function CountBadge({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded-brand border border-line bg-base px-2 py-0.5 font-mono text-[11px] font-semibold text-ink",
        className,
      )}
    >
      {children}
    </span>
  );
}
