import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface ModalIconProps {
  icon: LucideIcon;
  variant?: "default" | "destructive" | "warning" | "success";
  className?: string;
}

const variantStyles = {
  default: {
    container: "bg-white/10 border border-white/20",
    icon: "text-white",
  },
  destructive: {
    container: "bg-red-500/10 border border-red-500/20",
    icon: "text-red-500",
  },
  warning: {
    container: "bg-amber-500/10 border border-amber-500/20",
    icon: "text-amber-500",
  },
  success: {
    container: "bg-green-500/10 border border-green-500/20",
    icon: "text-green-500",
  },
};

export default function ModalIcon({
  icon: Icon,
  variant = "default",
  className,
}: ModalIconProps) {
  const styles = variantStyles[variant];

  return (
    <div className="flex justify-center mb-4">
      <div
        className={cn(
          "w-14 h-14 rounded-full flex items-center justify-center",
          styles.container,
          className
        )}
      >
        <Icon className={cn("size-7", styles.icon)} />
      </div>
    </div>
  );
}
