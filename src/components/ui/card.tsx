import type { ReactNode } from "react";

import { cn } from "@/lib/utils/cn";

export function Card({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-h-0 flex-col overflow-hidden rounded-md border border-line bg-field",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex shrink-0 items-center gap-1.5 border-b border-line py-2.5">
      <h3 className="flex-1 truncate px-3 text-[12px] font-semibold text-highlight">
        {title}
      </h3>
      {children ? <div className="shrink-0 pr-3">{children}</div> : null}
    </div>
  );
}

export function CardBody({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex min-h-0 flex-1 flex-col overflow-y-auto overscroll-contain p-2", className)}>
      {children}
    </div>
  );
}
