import type { ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils/cn";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost";
};

export function Button({
  className,
  type = "button",
  variant = "primary",
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cn(
        "inline-flex h-9 items-center justify-center rounded-brand px-3 text-[12px] font-medium leading-[18px] transition-colors duration-200 disabled:opacity-60",
        variant === "primary" &&
          "bg-accent text-inverse hover:bg-accent-hover",
        variant === "ghost" &&
          "bg-transparent text-muted hover:bg-hover hover:text-ink",
        className,
      )}
      {...props}
    />
  );
}
