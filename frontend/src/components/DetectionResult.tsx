import { Sparkles, FileText } from "lucide-react";
import type { DetectionResponse } from "@/lib/types";
import VerdictBadge from "./VerdictBadge";
import RiskGauge from "./RiskGauge";
import ShapBars from "./ShapBars";

export default function DetectionResult({ result }: { result: DetectionResponse }) {
  return (
    <div className="space-y-5">
      <div className="flex flex-col items-center gap-3 sm:flex-row sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <VerdictBadge verdict={result.verdict} />
            <span className="text-sm font-medium text-foreground">{result.attack_family}</span>
          </div>
          <p className="mt-1 text-xs text-muted-dim">
            {result.id} · {result.model} · scored in {result.latency_ms.toFixed(1)} ms
          </p>
        </div>
        <RiskGauge value={result.risk_score} verdict={result.verdict} />
      </div>

      <div className="grid grid-cols-3 gap-3 text-center text-xs">
        <div className="card-raised px-2 py-2.5">
          <p className="text-muted-dim">Probability</p>
          <p className="mono mt-0.5 text-sm text-foreground">{(result.probability * 100).toFixed(1)}%</p>
        </div>
        <div className="card-raised px-2 py-2.5">
          <p className="text-muted-dim">Confidence</p>
          <p className="mono mt-0.5 text-sm text-foreground">{(result.confidence * 100).toFixed(1)}%</p>
        </div>
        <div className="card-raised px-2 py-2.5">
          <p className="text-muted-dim">Threshold</p>
          <p className="mono mt-0.5 text-sm text-foreground">{result.threshold.toFixed(3)}</p>
        </div>
      </div>

      <div className="card-raised p-4">
        <div className="flex items-center gap-2 text-xs font-medium text-foreground">
          {result.llm_enabled ? <Sparkles size={13} className="text-accent" /> : <FileText size={13} className="text-muted-dim" />}
          Analyst narrative
          <span className="rounded-full border border-border px-1.5 py-0.5 text-[10px] font-normal text-muted-dim">
            {result.llm_enabled ? "Claude" : "offline template"}
          </span>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-muted">{result.analyst_summary}</p>
      </div>

      <div>
        <p className="mb-2 text-xs font-medium text-foreground">
          Why — {result.explanation_method}
        </p>
        <ShapBars attributions={result.attributions} />
      </div>

      <div>
        <p className="mb-2 text-xs font-medium text-foreground">Recommended next steps</p>
        <ul className="space-y-1.5">
          {result.recommendations.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-xs text-muted">
              <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" />
              {r}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
