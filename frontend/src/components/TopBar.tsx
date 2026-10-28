"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { HealthResponse } from "@/lib/types";

export default function TopBar({ title, subtitle }: { title: string; subtitle?: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      api
        .health()
        .then((h) => {
          if (!cancelled) {
            setHealth(h);
            setError(false);
          }
        })
        .catch(() => {
          if (!cancelled) setError(true);
        });
    };
    poll();
    const id = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const statusColor = error
    ? "bg-danger"
    : health?.status === "training"
    ? "bg-warning"
    : "bg-success";
  const statusLabel = error ? "backend unreachable" : health?.status === "training" ? "training model" : "live";

  return (
    <header className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-background/80 px-6 py-4 backdrop-blur-sm">
      <div>
        <h1 className="text-lg font-semibold text-foreground">{title}</h1>
        {subtitle && <p className="text-sm text-muted">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-4 text-xs text-muted">
        {health?.model && (
          <span className="hidden lg:inline mono text-muted-dim">{health.model}</span>
        )}
        {health?.threshold !== null && health?.threshold !== undefined && (
          <span className="hidden sm:inline">
            threshold <span className="mono text-foreground">{health.threshold.toFixed(3)}</span>
          </span>
        )}
        <span className="flex items-center gap-1.5 rounded-full border border-border bg-surface px-2.5 py-1">
          <span className={`h-1.5 w-1.5 rounded-full pulse-dot ${statusColor}`} />
          {statusLabel}
        </span>
      </div>
    </header>
  );
}
