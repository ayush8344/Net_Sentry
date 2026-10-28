"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, RefreshCw, X } from "lucide-react";
import TopBar from "@/components/TopBar";
import ThreatTable from "@/components/ThreatTable";
import DetectionResult from "@/components/DetectionResult";
import StatCard from "@/components/StatCard";
import { api } from "@/lib/api";
import type { DetectionResponse, ThreatLogResponse, Verdict } from "@/lib/types";

const VERDICTS: Verdict[] = ["Benign", "Suspicious", "Attack"];

export default function ThreatLogPage() {
  const [log, setLog] = useState<ThreatLogResponse | null>(null);
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "">("");
  const [selected, setSelected] = useState<DetectionResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api
      .threatLog({ limit: 200, verdict: verdictFilter || undefined })
      .then(setLog)
      .finally(() => setLoading(false));
  }, [verdictFilter]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount and whenever the filter changes
    load();
  }, [load]);

  const stats = log?.stats;

  return (
    <>
      <TopBar title="Threat Log" subtitle="Every flow scored in this session, most recent first" />
      <main className="flex-1 space-y-5 p-6">
        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Total scored" value={stats ? String(stats.total) : "—"} accent="accent" />
          <StatCard label="Benign" value={stats ? String(stats.by_verdict.Benign ?? 0) : "—"} accent="success" />
          <StatCard label="Suspicious" value={stats ? String(stats.by_verdict.Suspicious ?? 0) : "—"} accent="warning" />
          <StatCard label="Attack" value={stats ? String(stats.by_verdict.Attack ?? 0) : "—"} accent="danger" />
        </section>

        <section className="card p-5">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div className="flex rounded-lg border border-border bg-surface-raised p-1 text-xs">
              <button
                onClick={() => setVerdictFilter("")}
                className={`rounded-md px-3 py-1.5 transition-colors ${verdictFilter === "" ? "bg-accent/10 text-accent" : "text-muted hover:text-foreground"}`}
              >
                All
              </button>
              {VERDICTS.map((v) => (
                <button
                  key={v}
                  onClick={() => setVerdictFilter(v)}
                  className={`rounded-md px-3 py-1.5 transition-colors ${verdictFilter === v ? "bg-accent/10 text-accent" : "text-muted hover:text-foreground"}`}
                >
                  {v}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={load}
                className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground"
              >
                <RefreshCw size={13} className={loading ? "animate-spin" : ""} /> Refresh
              </button>
              <a
                href={api.exportThreatLogUrl()}
                className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted hover:text-foreground"
              >
                <Download size={13} /> Export CSV
              </a>
            </div>
          </div>
          <ThreatTable items={log?.items ?? []} onSelect={setSelected} />
        </section>
      </main>

      {selected && (
        <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={() => setSelected(null)}>
          <div
            className="h-full w-full max-w-md overflow-y-auto border-l border-border bg-background p-5"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-4 flex items-center justify-between">
              <p className="text-sm font-semibold text-foreground">Detection detail</p>
              <button onClick={() => setSelected(null)} className="text-muted-dim hover:text-foreground">
                <X size={18} />
              </button>
            </div>
            <DetectionResult result={selected} />
          </div>
        </div>
      )}
    </>
  );
}
