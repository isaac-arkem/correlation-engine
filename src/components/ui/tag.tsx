import { cn } from "@/lib/utils/cn";

export function Tag({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "rounded-brand bg-neutral-800 px-1.5 py-0.5 font-mono text-[10px] text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}
