import { AlertTriangle, Info, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

interface WarningBoxProps {
  variant?: "warning" | "danger" | "info";
  title?: string;
  children: React.ReactNode;
  className?: string;
}

const variants = {
  warning: {
    icon: AlertTriangle,
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    iconColor: "text-yellow-500",
    titleColor: "text-yellow-500",
  },
  danger: {
    icon: ShieldAlert,
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    iconColor: "text-red-500",
    titleColor: "text-red-500",
  },
  info: {
    icon: Info,
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    iconColor: "text-blue-500",
    titleColor: "text-blue-500",
  },
};

export function WarningBox({
  variant = "warning",
  title,
  children,
  className,
}: WarningBoxProps) {
  const config = variants[variant];
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "rounded-lg border p-4",
        config.bg,
        config.border,
        className
      )}
    >
      <div className="flex gap-3">
        <Icon className={cn("w-5 h-5 mt-0.5 flex-shrink-0", config.iconColor)} />
        <div className="flex-1">
          {title && (
            <h4 className={cn("font-semibold mb-1", config.titleColor)}>
              {title}
            </h4>
          )}
          <div className="text-sm text-muted-foreground">{children}</div>
        </div>
      </div>
    </div>
  );
}
