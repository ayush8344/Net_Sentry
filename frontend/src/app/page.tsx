"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, Gauge, ShieldCheck, Timer, TrendingUp, AlertTriangle } from "lucide-react";
import TopBar from "@/components/TopBar";
import StatCard from "@/components/StatCard";
import ImportanceBars from "@/components/ImportanceBars";
import ProtocolDonut from "@/components/ProtocolDonut";
import ThreatTable from "@/components/ThreatTable";
import { api } from "@/lib/api";
import type { ImportanceItem, ModelMetrics, ThreatLogResponse } from "@/lib/types";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);
  const [importance, setImportance] = useState<ImportanceItem[]>([]);
  const [log, setLog] = useState<ThreatLogResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.modelMetrics(), api.modelImportance(), api.threatLog({ limit: 8 })])
      .then(([m, imp, l]) => {
        if (cancelled) return;
        setMetrics(m);
        setImportance(imp);
        setLog(l);
      })
      .catch((e) => !cancelled && setError(String(e)));
    return () => {
      cancelled = true;
    };
  }, []);

  const rb = metrics?.radiant_boost;
  const rf = metrics?.random_forest_baseline;
  const gen = metrics?.generalization;

  return (
    <>
      <TopBar title="Dashboard" subtitle="RadiantBoost model status, evaluation, and live traffic overview" />
      <main className="flex-1 space-y-6 p-6">
        {error && (
          <div className="card border-danger/40 bg-danger/5 p-4 text-sm text-danger">
            Could not reach the backend: {error}. Is <code className="mono">uvicorn app.main:app</code> running on port 8000?
          </div>
        )}

        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="ROC-AUC (held-out test)"
            value={rb ? rb.roc_auc.toFixed(4) : "—"}
            hint={rb ? `vs RF baseline ${rf?.roc_auc.toFixed(4)}` : undefined}
            icon={TrendingUp}
            accent="accent"
          />
          <StatCard
            label="Accuracy"
            value={rb ? `${(rb.accuracy * 100).toFixed(2)}%` : "—"}
            hint={rb ? `precision ${(rb.precision * 100).toFixed(1)}% · recall ${(rb.recall * 100).toFixed(1)}%` : undefined}
            icon={ShieldCheck}
            accent="success"
          />
          <StatCard
            label="Decision threshold"
            value={rb ? rb.threshold.toFixed(3) : "—"}
            hint="auto-selected for 95% TPR / ≤2% FPR"
            icon={Gauge}
            accent="teal"
          />
          <StatCard
            label="Single-flow latency"
            value={rb ? `${rb.single_flow_latency_ms.toFixed(1)} ms` : "—"}
            hint={rb ? `trained in ${rb.train_seconds.toFixed(1)}s` : undefined}
            icon={Timer}
            accent="accent"
          />
        </section>

        <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="card p-5 lg:col-span-2">
            <h2 className="text-sm font-semibold text-foreground">Model comparison</h2>
            <p className="mt-0.5 text-xs text-muted-dim">
              RadiantBoost (GB + XGB, isotonic-calibrated) vs. a Random Forest baseline vs. the fast-path NB+KNN
              ensemble — same tuning budget, same held-out CICIDS2018-profile test set.
            </p>
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted-dim">
                    <th className="py-2 pr-4 font-medium">Model</th>
                    <th className="py-2 pr-4 font-medium">Accuracy</th>
                    <th className="py-2 pr-4 font-medium">Precision</th>
                    <th className="py-2 pr-4 font-medium">Recall</th>
                    <th className="py-2 pr-4 font-medium">ROC-AUC</th>
                  </tr>
                </thead>
                <tbody className="text-muted">
                  <tr className="border-b border-border/60">
                    <td className="py-2 pr-4 font-medium text-accent">RadiantBoost</td>
                    <td className="py-2 pr-4 mono">{rb ? (rb.accuracy * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rb ? (rb.precision * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rb ? (rb.recall * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rb ? rb.roc_auc.toFixed(4) : "—"}</td>
                  </tr>
                  <tr className="border-b border-border/60">
                    <td className="py-2 pr-4">Random Forest baseline</td>
                    <td className="py-2 pr-4 mono">{rf ? (rf.accuracy * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rf ? (rf.precision * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rf ? (rf.recall * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{rf ? rf.roc_auc.toFixed(4) : "—"}</td>
                  </tr>
                  <tr>
                    <td className="py-2 pr-4">Fast-path (NB + KNN, SMOTE)</td>
                    <td className="py-2 pr-4 mono">{metrics ? (metrics.fast_path_ensemble.accuracy * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{metrics ? (metrics.fast_path_ensemble.precision * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono">{metrics ? (metrics.fast_path_ensemble.recall * 100).toFixed(2) + "%" : "—"}</td>
                    <td className="py-2 pr-4 mono text-muted-dim">— (OR-rule, recall-biased)</td>
                  </tr>
                </tbody>
              </table>
            </div>
            {metrics && !metrics.using_real_data && (
              <p className="mt-4 rounded-lg border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] text-warning">
                Trained on synthetic, real-schema CICIDS2018-profile data — the real dataset is gated. Drop real CSVs
                into <span className="mono">backend/data_raw/cicids2018/</span> and retrain to use them.
              </p>
            )}
          </div>

          <div className="card p-5">
            <h2 className="text-sm font-semibold text-foreground">Traffic by protocol</h2>
            <p className="mt-0.5 text-xs text-muted-dim">Live, from this session&apos;s scored flows.</p>
            <ProtocolDonut data={log?.stats.by_protocol ?? {}} />
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="card p-5 lg:col-span-2">
            <h2 className="text-sm font-semibold text-foreground">Global feature importance</h2>
            <p className="mt-0.5 text-xs text-muted-dim">
              Mean |SHAP| over a held-out sample — what RadiantBoost relies on in general (see Detect for per-flow explanations).
            </p>
            <div className="mt-3">
              <ImportanceBars items={importance} />
            </div>
          </div>

          <div className="card p-5">
            <h2 className="text-sm font-semibold text-foreground">Cross-dataset generalization</h2>
            <p className="mt-0.5 text-xs text-muted-dim">CICIDS2018-trained model, evaluated elsewhere.</p>
            <div className="mt-4 space-y-4 text-sm">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-muted">ISCX-VPN tunneled-traffic</span>
                  <span className="mono text-foreground">{gen ? gen.iscx_vpn.roc_auc.toFixed(3) : "—"} AUC</span>
                </div>
                <p className="mt-1 flex items-start gap-1.5 text-[11px] text-muted-dim">
                  <AlertTriangle size={12} className="mt-0.5 shrink-0 text-warning" />
                  Near-random transfer — expected distribution shift, not a bug. Demonstrates why single-benchmark
                  evaluation overstates real-world readiness.
                </p>
              </div>
              <div className="border-t border-border pt-3">
                <div className="flex items-center justify-between">
                  <span className="text-muted">CAIDA backbone (unsupervised)</span>
                  <span className="mono text-foreground">{gen ? (gen.caida.flagged_fraction * 100).toFixed(1) : "—"}% flagged</span>
                </div>
                <p className="mt-1 text-[11px] text-muted-dim">
                  DBSCAN outlier fraction {gen ? (gen.caida.outlier_fraction_dbscan * 100).toFixed(1) : "—"}% (auto-tuned eps,
                  no ground truth available).
                </p>
              </div>
            </div>
          </div>
        </section>

        <section className="card p-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-foreground">Recent detections</h2>
              <p className="mt-0.5 text-xs text-muted-dim">Latest flows scored in this session.</p>
            </div>
            <Link href="/threat-log" className="flex items-center gap-1 text-xs text-accent hover:underline">
              <Activity size={13} /> View full threat log
            </Link>
          </div>
          <div className="mt-3">
            <ThreatTable items={log?.items ?? []} />
          </div>
        </section>
      </main>
    </>
  );
}
