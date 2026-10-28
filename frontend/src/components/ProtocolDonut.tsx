"use client";

import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

const COLORS: Record<string, string> = {
  TCP: "var(--accent)",
  UDP: "var(--teal)",
  ICMP: "#f472b6",
};

export default function ProtocolDonut({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).filter(([, v]) => v > 0);
  if (entries.length === 0) {
    return <p className="flex h-[200px] items-center justify-center text-sm text-muted-dim">No traffic scored yet.</p>;
  }
  const chartData = entries.map(([name, value]) => ({ name, value }));

  return (
    <div style={{ width: "100%", height: 200 }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie data={chartData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={78} paddingAngle={3}>
            {chartData.map((d) => (
              <Cell key={d.name} fill={COLORS[d.name] ?? "var(--muted-dim)"} stroke="var(--surface)" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "var(--surface-raised)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              fontSize: 12,
              color: "var(--foreground)",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
