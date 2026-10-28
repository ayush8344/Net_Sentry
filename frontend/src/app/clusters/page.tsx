"use client";

import { useEffect, useState } from "react";
import TopBar from "@/components/TopBar";
import StatCard from "@/components/StatCard";
import ClusterScatterChart from "@/components/ClusterScatterChart";
import { api } from "@/lib/api";
import type { ClusterSnapshot, DatasetName } from "@/lib/types";
import { Boxes, CircleDashed, Percent } from "lucide-react";

const OPTIONS: { value: DatasetName; label: string; note: string }[] = [
  { value: "cicids2018", label: "CICIDS2018", note: "labeled attack traffic, clustered unsupervised (no labels used)" },
  { value: "caida", label: "CAIDA", note: "unlabeled real backbone traffic — the only analysis available" },
];

export default function ClustersPage() {
  const [dataset, setDataset] = useState<DatasetName>("cicids2018");
  const [snapshot, setSnapshot] = useState<ClusterSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset view before the new dataset's fetch resolves
    setSnapshot(null);
    setError(null);
    api.clusters(dataset).then(setSnapshot).catch((e) => setError(String(e)));
  }, [dataset]);

  return (
    <>
      <TopBar title="Clustering" subtitle="K-Means + DBSCAN on engineered features, run before any labels are used" />
      <main className="flex-1 space-y-5 p-6">
        <div className="flex gap-2">
          {OPTIONS.map((o) => (
            <button
              key={o.value}
              onClick={() => setDataset(o.value)}
              className={`rounded-lg border px-3 py-1.5 text-sm transition-colors ${
                dataset === o.value ? "border-accent/50 bg-accent/10 text-accent" : "border-border text-muted hover:text-foreground"
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <p className="text-xs text-muted-dim">{OPTIONS.find((o) => o.value === dataset)?.note}</p>

        {error && <div className="card border-danger/40 bg-danger/5 p-4 text-sm text-danger">{error}</div>}

        <section className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Points plotted" value={snapshot ? String(snapshot.points.length) : "—"} icon={Boxes} accent="accent" />
          <StatCard label="K-Means clusters" value={snapshot ? String(snapshot.n_clusters) : "—"} icon={CircleDashed} accent="teal" />
          <StatCard
            label="DBSCAN outliers"
            value={snapshot ? `${(snapshot.outlier_fraction * 100).toFixed(1)}%` : "—"}
            hint={snapshot ? `auto eps ${snapshot.dbscan_eps.toFixed(3)}` : undefined}
            icon={Percent}
            accent="warning"
          />
          <StatCard
            label="PCA explained variance"
            value={snapshot ? snapshot.explained_variance.map((v) => `${(v * 100).toFixed(0)}%`).join(" + ") : "—"}
            hint="2D projection for display only"
            accent="accent"
          />
        </section>

        <section className="card p-5">
          <h2 className="text-sm font-semibold text-foreground">PCA projection</h2>
          <p className="mt-0.5 text-xs text-muted-dim">
            Each point is one flow, reduced from the full engineered feature space to 2 dimensions for plotting.
            Crosses are DBSCAN outliers — points that don&apos;t fit any dense cluster.
          </p>
          <div className="mt-3">
            {snapshot ? (
              <ClusterScatterChart points={snapshot.points} />
            ) : (
              <div className="flex h-[380px] items-center justify-center text-sm text-muted-dim">Loading clusters...</div>
            )}
          </div>
        </section>
      </main>
    </>
  );
}
