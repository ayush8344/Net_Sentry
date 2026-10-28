"use client";

import { useCallback, useEffect, useState } from "react";
import { Activity, AlertTriangle, Network, Play, Square, Waves, X } from "lucide-react";
import TopBar from "@/components/TopBar";
import ThreatTable from "@/components/ThreatTable";
import DetectionResult from "@/components/DetectionResult";
import StatCard from "@/components/StatCard";
import { api } from "@/lib/api";
import type { DetectionResponse, LiveFeedResponse } from "@/lib/types";

const POLL_MS = 2000;

export default function LivePage() {
  const [feed, setFeed] = useState<LiveFeedResponse | null>(null);
  const [selected, setSelected] = useState<DetectionResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .liveFeed(200)
      .then(setFeed)
      .catch(() => {});
  }, []);

  useEffect(() => {
    load();
    const id = setInterval(load, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const toggle = async () => {
    setBusy(true);
    setError(null);
    try {
      if (feed?.status.running) await api.liveStop();
      else await api.liveStart();
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message.replace(/^\d+:\s*/, "") : String(e));
    } finally {
      setBusy(false);
    }
  };

  const status = feed?.status;
  const items = feed?.items ?? [];
  const flagged = items.filter((d) => d.verdict !== "Benign").length;
  const running = status?.running ?? false;

  return (
    <>
      <TopBar title="Live Capture" subtitle="Real-time packets from this machine, grouped into flows and scored as they finish" />
      <main className="flex-1 space-y-5 p-6">
        <section className="card flex flex-wrap items-center justify-between gap-4 p-5">
          <div className="flex items-center gap-3">
            <span className={`relative flex h-3 w-3 ${running ? "" : "opacity-60"}`}>
              {running && <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-60" />}
              <span className={`relative inline-flex h-3 w-3 rounded-full ${running ? "bg-success" : "bg-muted-dim"}`} />
            </span>
            <div>
              <p className="text-sm font-semibold text-foreground">{running ? "Capturing" : "Stopped"}</p>
              <p className="text-[11px] text-muted-dim mono">
                {status?.method ? `${status.method} · ${status.interface}` : "Not started yet"}
              </p>
            </div>
          </div>
          <button
            onClick={toggle}
            disabled={busy || !feed}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50 ${
              running
                ? "border border-danger/40 bg-danger/10 text-danger hover:bg-danger/20"
                : "bg-accent text-background hover:bg-accent/90"
            }`}
          >
            {running ? <Square size={14} /> : <Play size={14} />}
            {busy ? "Working…" : running ? "Stop capture" : "Start capture"}
          </button>
        </section>

        {(error || status?.error) && (
          <section className="card flex gap-3 border-warning/40 p-4 text-sm">
            <AlertTriangle size={18} className="mt-0.5 shrink-0 text-warning" />
            <p className="text-foreground">{error ?? status?.error}</p>
          </section>
        )}

        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Packets seen" value={String(status?.packets_seen ?? 0)} icon={Waves} accent="accent" />
          <StatCard label="Active flows" value={String(status?.active_flows ?? 0)} icon={Network} accent="teal" />
          <StatCard label="Flows scored" value={String(status?.flows_scored ?? 0)} icon={Activity} accent="success" />
          <StatCard
            label="Flagged"
            value={String(flagged)}
            hint="Suspicious + Attack in feed"
            icon={AlertTriangle}
            accent={flagged ? "danger" : "warning"}
          />
        </section>

        <section className="card p-5">
          <p className="mb-4 text-sm font-semibold text-foreground">Live verdicts</p>
          <ThreatTable items={items} onSelect={setSelected} />
          <p className="mt-4 text-[11px] text-muted-dim">
            Flows end after 5 s idle, 30 s active, or a FIN/RST. The model was trained on synthetic CICIDS2018-style
            data, so verdicts on real home/office traffic are indicative, not authoritative.
          </p>
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
