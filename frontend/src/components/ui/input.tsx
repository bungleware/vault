import * as React from "react";

import { cn } from "@/lib/utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "file:text-foreground placeholder:text-muted-foreground selection:bg-ring selection:text-primary-foreground h-9 w-full min-w-0 rounded-md border bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none file:inline-flex file:h-7 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm",
        "border-border bg-[color-mix(in_oklab,var(--bg-1)_30%,transparent)]",
        "focus-visible:border-ring focus-visible:ring-[color-mix(in_oklab,var(--accent-blue)_40%,transparent)] focus-visible:ring-[3px]",
        "aria-invalid:ring-[color-mix(in_oklab,var(--danger-0)_30%,transparent)] aria-invalid:border-destructive-foreground",
        className
      )}
      {...props}
    />
  );
}

export { Input };
