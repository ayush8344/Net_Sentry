import type { LucideIcon } from "lucide-react";

export default function StatCard({
  label,
  value,
  hint,
  icon: Icon,
  accent = "accent",
}: {
  label: string;
  value: string;
  hint?: string;
  icon?: LucideIcon;
  accent?: "accent" | "success" | "warning" | "danger" | "teal";
}) {
  const accentClass = {
    accent: "text-accent bg-accent/10",
    success: "text-success bg-success/10",
    warning: "text-warning bg-warning/10",
    danger: "text-danger bg-danger/10",
    teal: "text-teal bg-teal/10",
  }[accent];

  return (
    <div className="card flex items-start justify-between gap-3 p-4">
      <div>
        <p className="text-xs text-muted">{label}</p>
        <p className="mt-1.5 text-2xl font-semibold tracking-tight text-foreground">{value}</p>
        {hint && <p className="mt-1 text-[11px] text-muted-dim">{hint}</p>}
      </div>
      {Icon && (
        <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${accentClass}`}>
          <Icon size={17} />
        </div>
      )}
    </div>
  );
}
