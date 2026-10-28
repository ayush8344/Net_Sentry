"use client";

import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ImportanceItem } from "@/lib/types";

export default function ImportanceBars({ items, limit = 10 }: { items: ImportanceItem[]; limit?: number }) {
  const data = items.slice(0, limit);

  return (
    <div style={{ width: "100%", height: Math.max(220, data.length * 30) }}>
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
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              fontSize: 12,
              color: "var(--foreground)",
            }}
            formatter={(val) => [Number(val).toFixed(4), "mean |SHAP|"]}
          />
          <Bar dataKey="mean_abs_shap" radius={3} fill="var(--accent)" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
