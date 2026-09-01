import type { ReactNode } from "react";

import { cn } from "@/lib/utils/cn";

type CaptionProps = {
  children: ReactNode;
  className?: string;
};

export function Caption({ children, className }: CaptionProps) {
  return (
    <p
      className={cn(
        "font-mono text-[10px] font-medium uppercase leading-[14px] tracking-[0.08em] text-subtle",
        className,
      )}
    >
      {children}
    </p>
  );
}
