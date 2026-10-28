"use client";

import { useEffect, useState } from "react";
import TopBar from "@/components/TopBar";
import { api } from "@/lib/api";
import type { DatasetInfo, DatasetName, DatasetPreview } from "@/lib/types";
import { Database, FlaskConical } from "lucide-react";

export default function DatasetsPage() {
  const [datasets, setDatasets] = useState<DatasetInfo[]>([]);
  const [active, setActive] = useState<DatasetName>("cicids2018");
  const [preview, setPreview] = useState<DatasetPreview | null>(null);

  useEffect(() => {
    api.datasets().then(setDatasets);
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset preview before the new dataset's fetch resolves
    setPreview(null);
    api.datasetPreview(active, 8).then(setPreview);
  }, [active]);

  return (
    <>
      <TopBar title="Datasets" subtitle="One canonical schema, many sources — real CSVs override synthetic automatically" />
      <main className="flex-1 space-y-5 p-6">
        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {datasets.map((d) => (
            <button
              key={d.name}
              onClick={() => setActive(d.name)}
              className={`card p-4 text-left transition-colors hover:border-accent/40 ${active === d.name ? "border-accent/60" : ""}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-foreground">{d.name}</span>
                <span
                  className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] ${
                    d.using_real_data ? "bg-success/10 text-success" : "bg-warning/10 text-warning"
                  }`}
                >
                  {d.using_real_data ? <Database size={10} /> : <FlaskConical size={10} />}
                  {d.using_real_data ? "real data" : "synthetic"}
                </span>
              </div>
              <p className="mt-2 text-xs leading-relaxed text-muted-dim">{d.description}</p>
            </button>
          ))}
        </section>

        <section className="card p-5">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-foreground">Preview — {active}</h2>
            <p className="text-[11px] text-muted-dim">
              first 8 rows, canonical schema (after the heuristic column mapper)
            </p>
          </div>
          {preview ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-[10px] uppercase tracking-wide text-muted-dim">
                    {preview.columns.map((c) => (
                      <th key={c} className="whitespace-nowrap px-2.5 py-2 font-medium">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {preview.rows.map((row, i) => (
                    <tr key={i} className="border-b border-border/60">
                      {preview.columns.map((c) => (
                        <td key={c} className="mono whitespace-nowrap px-2.5 py-1.5 text-muted">
                          {String(row[c])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex h-32 items-center justify-center text-sm text-muted-dim">Loading preview...</div>
          )}
        </section>

        <section className="card border-warning/30 bg-warning/5 p-5 text-sm text-warning">
          <p className="font-medium">Why synthetic data?</p>
          <p className="mt-1 text-xs leading-relaxed text-warning/90">
            The real CICIDS2018, CAIDA, and ISCX-VPN2016 datasets are gated behind signed data-sharing agreements and
            multi-gigabyte downloads. Every loader here (<code className="mono">backend/app/data/loaders.py</code>)
            maps real, differently-named CSV headers onto the same canonical schema via a heuristic column mapper —
            drop real exports into <code className="mono">backend/data_raw/&lt;dataset&gt;/</code> and retrain to use
            them automatically, no code changes needed.
          </p>
        </section>
      </main>
    </>
  );
}
