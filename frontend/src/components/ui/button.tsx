import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-[var(--button-radius)] text-sm font-medium transition-all cursor-pointer active:scale-95 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive border border-[var(--button-border)]",
  {
    variants: {
      variant: {
        default:
          "bg-[linear-gradient(180deg,var(--button-gradient-from)_0%,var(--button-gradient-to)_100%)] text-primary-foreground hover:brightness-120",
        hot: "border-[var(--button-hot-border)] bg-[linear-gradient(180deg,var(--button-gradient-hot-from)_0%,var(--button-gradient-hot-to)_100%)] text-primary-foreground hover:brightness-120",
        destructive:
          "bg-destructive text-white hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60",
        outline:
          "border border-[var(--button-border)] bg-transparent text-foreground hover:bg-[linear-gradient(180deg,var(--button-gradient-from)_0%,var(--button-gradient-to)_100%)]",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80",
        ghost: "text-accent-foreground border-none",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-10 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 rounded-[calc(var(--button-radius)-4px)] gap-1.5 px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-[calc(var(--button-radius)+0px)] px-6 has-[>svg]:px-4",
        icon: "size-9",
        "icon-sm": "size-8",
        "icon-lg": "size-11",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  }) {
  const Comp = asChild ? Slot : "button";

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      // style={{
      //   cornerShape: "squircle",
      //   borderRadius: "200px",
      // }}
      {...props}
    />
  );
}

export { Button, buttonVariants };
