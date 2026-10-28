import type { DetectionResponse } from "@/lib/types";
import VerdictBadge from "./VerdictBadge";

function formatTime(ts: string) {
  const d = new Date(ts);
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export default function ThreatTable({
  items,
  onSelect,
}: {
  items: DetectionResponse[];
  onSelect?: (item: DetectionResponse) => void;
}) {
  if (items.length === 0) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-muted-dim">
        No detections logged yet — run something through Detect.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted-dim">
            <th className="px-3 py-2 font-medium">Time</th>
            <th className="px-3 py-2 font-medium">ID</th>
            <th className="px-3 py-2 font-medium">Source → Dest</th>
            <th className="px-3 py-2 font-medium">Proto</th>
            <th className="px-3 py-2 font-medium">Verdict</th>
            <th className="px-3 py-2 font-medium">Family</th>
            <th className="px-3 py-2 font-medium">Score</th>
            <th className="px-3 py-2 font-medium">Model</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr
              key={item.id}
              onClick={() => onSelect?.(item)}
              className={`border-b border-border/60 transition-colors ${onSelect ? "cursor-pointer hover:bg-surface-raised" : ""}`}
            >
              <td className="px-3 py-2 text-muted-dim mono text-xs whitespace-nowrap">{formatTime(item.timestamp)}</td>
              <td className="px-3 py-2 mono text-xs text-muted">{item.id}</td>
              <td className="px-3 py-2 mono text-xs text-muted whitespace-nowrap">
                {item.flow?.source_ip ?? "—"} <span className="text-muted-dim">→</span> {item.flow?.destination_ip ?? "—"}
                {item.flow?.dst_port ? <span className="text-muted-dim">:{item.flow.dst_port}</span> : null}
              </td>
              <td className="px-3 py-2 text-muted">{item.flow?.protocol ?? "—"}</td>
              <td className="px-3 py-2">
                <VerdictBadge verdict={item.verdict} size="sm" />
              </td>
              <td className="px-3 py-2 text-muted">{item.attack_family}</td>
              <td className="px-3 py-2 mono text-foreground">{item.risk_score}</td>
              <td className="px-3 py-2 text-muted-dim text-xs">{item.llm_enabled ? "Claude" : "template"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
