"use client";

import {
  Bar,
  BarChart,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Attribution } from "@/lib/types";

export default function ShapBars({ attributions, limit = 8 }: { attributions: Attribution[]; limit?: number }) {
  const data = attributions.slice(0, limit).map((a) => ({
    feature: a.feature,
    contribution: a.contribution,
    direction: a.direction,
    value: a.value,
    description: a.description,
  }));

  return (
    <div style={{ width: "100%", height: Math.max(220, data.length * 34) }}>
      <ResponsiveContainer>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 24, bottom: 4, left: 4 }}>
          <XAxis type="number" tick={{ fill: "var(--muted-dim)", fontSize: 11 }} stroke="var(--border)" />
          <YAxis
            type="category"
            dataKey="feature"
            width={128}
            tick={{ fill: "var(--muted)", fontSize: 11 }}
            stroke="var(--border)"
          />
          <ReferenceLine x={0} stroke="var(--border)" />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              fontSize: 12,
              color: "var(--foreground)",
            }}
            formatter={(val, _name, props) => {
              const num = Number(val);
              const payload = props.payload as { value?: string } | undefined;
              return [`${num > 0 ? "+" : ""}${num.toFixed(3)} (value: ${payload?.value})`, "SHAP contribution"];
            }}
            labelFormatter={(label) => label}
          />
          <Bar dataKey="contribution" radius={3}>
            {data.map((d, i) => (
              <Cell key={i} fill={d.direction === "risk" ? "var(--danger)" : "var(--teal)"} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
