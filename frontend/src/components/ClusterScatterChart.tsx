"use client";

import {
  CartesianGrid,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import type { ClusterPoint } from "@/lib/types";

const CLUSTER_COLORS = ["var(--accent)", "var(--teal)", "#818cf8", "#f472b6", "#facc15", "#4ade80"];

export default function ClusterScatterChart({ points }: { points: ClusterPoint[] }) {
  const groups = new Map<number, ClusterPoint[]>();
  const outliers: ClusterPoint[] = [];
  for (const p of points) {
    if (p.outlier) {
      outliers.push(p);
      continue;
    }
    if (!groups.has(p.cluster)) groups.set(p.cluster, []);
    groups.get(p.cluster)!.push(p);
  }

  return (
    <div style={{ width: "100%", height: 380 }}>
      <ResponsiveContainer>
        <ScatterChart margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis type="number" dataKey="x" name="PC1" tick={{ fill: "var(--muted-dim)", fontSize: 11 }} stroke="var(--border)" />
          <YAxis type="number" dataKey="y" name="PC2" tick={{ fill: "var(--muted-dim)", fontSize: 11 }} stroke="var(--border)" />
          <ZAxis range={[28, 28]} />
          <Tooltip
            cursor={{ strokeDasharray: "3 3" }}
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              fontSize: 12,
              color: "var(--foreground)",
            }}
          />
          {[...groups.entries()].map(([clusterId, pts]) => (
            <Scatter
              key={clusterId}
              name={`cluster ${clusterId}`}
              data={pts}
              fill={CLUSTER_COLORS[clusterId % CLUSTER_COLORS.length]}
              fillOpacity={0.75}
            />
          ))}
          {outliers.length > 0 && (
            <Scatter name="DBSCAN outlier" data={outliers} fill="var(--danger)" shape="cross" />
          )}
        </ScatterChart>
      </ResponsiveContainer>
    </div>
  );
}
