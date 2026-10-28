import type { Verdict } from "@/lib/types";

const COLORS: Record<Verdict, string> = {
  Benign: "var(--success)",
  Suspicious: "var(--warning)",
  Attack: "var(--danger)",
};

export default function RiskGauge({ value, verdict }: { value: number; verdict: Verdict }) {
  const pct = Math.max(0, Math.min(100, value));
  const color = COLORS[verdict];

  return (
    <div className="relative flex flex-col items-center">
      <svg viewBox="0 0 200 118" className="w-full max-w-[220px]">
        <path
          d="M 14 104 A 86 86 0 0 1 186 104"
          fill="none"
          stroke="var(--border)"
          strokeWidth="14"
          strokeLinecap="round"
          pathLength={100}
        />
        <path
          d="M 14 104 A 86 86 0 0 1 186 104"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          pathLength={100}
          strokeDasharray={`${pct} 100`}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
      </svg>
      <div className="absolute top-[52px] flex flex-col items-center">
        <span className="text-4xl font-bold tracking-tight" style={{ color }}>
          {Math.round(value)}
        </span>
        <span className="text-[11px] text-muted-dim">risk score / 99</span>
      </div>
    </div>
  );
}
