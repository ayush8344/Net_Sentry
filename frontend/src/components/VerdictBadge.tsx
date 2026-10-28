import type { Verdict } from "@/lib/types";

const STYLES: Record<Verdict, string> = {
  Benign: "bg-success/10 text-success border-success/30",
  Suspicious: "bg-warning/10 text-warning border-warning/30",
  Attack: "bg-danger/10 text-danger border-danger/30",
};

export default function VerdictBadge({ verdict, size = "md" }: { verdict: Verdict; size?: "sm" | "md" }) {
  const padding = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-3 py-1 text-xs";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${STYLES[verdict]} ${padding}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {verdict}
    </span>
  );
}
