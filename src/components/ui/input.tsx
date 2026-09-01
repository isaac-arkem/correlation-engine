import type { InputHTMLAttributes } from "react";

import { cn } from "@/lib/utils/cn";

type InputProps = InputHTMLAttributes<HTMLInputElement>;

export function Input({ className, ...props }: InputProps) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-brand border border-line bg-base px-3 text-[12px] leading-[18px] text-highlight outline-none placeholder:text-subtle focus:border-line-strong",
        className,
      )}
      {...props}
    />
  );
}
