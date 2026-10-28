"use client";

import { useRef, useState } from "react";
import { Loader2, Radar, UploadCloud } from "lucide-react";
import TopBar from "@/components/TopBar";
import FlowForm from "@/components/FlowForm";
import DetectionResult from "@/components/DetectionResult";
import ThreatTable from "@/components/ThreatTable";
import { api } from "@/lib/api";
import { DEFAULT_FLOW, PRESETS } from "@/lib/presets";
import type { BatchDetectionResponse, DatasetName, DetectionResponse, FlowFeatures } from "@/lib/types";

const DATASETS: { value: DatasetName; label: string }[] = [
  { value: "cicids2018", label: "CICIDS2018" },
  { value: "iscx_vpn", label: "ISCX-VPN2016" },
  { value: "caida", label: "CAIDA" },
  { value: "sample", label: "Sample / synthetic" },
];

export default function DetectPage() {
  const [mode, setMode] = useState<"manual" | "batch">("manual");
  const [dataset, setDataset] = useState<DatasetName>("cicids2018");
  const [flow, setFlow] = useState<FlowFeatures>(DEFAULT_FLOW);
  const [result, setResult] = useState<DetectionResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [batchResult, setBatchResult] = useState<BatchDetectionResponse | null>(null);
  const [batchLoading, setBatchLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const runDetect = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.detect(dataset, flow);
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const runBatch = async () => {
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError("Choose a CSV file first.");
      return;
    }
    setBatchLoading(true);
    setError(null);
    try {
      const res = await api.detectBatch(dataset, file);
      setBatchResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setBatchLoading(false);
    }
  };

  return (
    <>
      <TopBar title="Detect" subtitle="Score a single flow, or upload a CSV for batch scoring" />
      <main className="flex-1 p-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex rounded-lg border border-border bg-surface p-1 text-sm">
            <button
              onClick={() => setMode("manual")}
              className={`rounded-md px-3 py-1.5 transition-colors ${mode === "manual" ? "bg-accent/10 text-accent" : "text-muted hover:text-foreground"}`}
            >
              Manual flow
            </button>
            <button
              onClick={() => setMode("batch")}
              className={`rounded-md px-3 py-1.5 transition-colors ${mode === "batch" ? "bg-accent/10 text-accent" : "text-muted hover:text-foreground"}`}
            >
              Batch CSV
            </button>
          </div>

          <div className="flex items-center gap-2 text-sm">
            <span className="text-xs text-muted-dim">Dataset profile</span>
            <select
              className="rounded-lg border border-border bg-surface-raised px-2.5 py-1.5 text-sm text-foreground outline-none focus:border-accent/60"
              value={dataset}
              onChange={(e) => setDataset(e.target.value as DatasetName)}
            >
              {DATASETS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="card mb-5 border-danger/40 bg-danger/5 p-3 text-sm text-danger">{error}</div>
        )}

        {mode === "manual" ? (
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <div className="card p-5">
              <div className="mb-4 flex flex-wrap gap-2">
                {PRESETS.map((p) => (
                  <button
                    key={p.label}
                    title={p.description}
                    onClick={() => setFlow(p.flow)}
                    className="rounded-full border border-border bg-surface-raised px-3 py-1 text-xs text-muted transition-colors hover:border-accent/50 hover:text-accent"
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <FlowForm flow={flow} onChange={setFlow} />
              <button
                onClick={runDetect}
                disabled={loading}
                className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
              >
                {loading ? <Loader2 size={15} className="animate-spin" /> : <Radar size={15} />}
                {loading ? "Scoring..." : "Score this flow"}
              </button>
            </div>

            <div className="card p-5">
              {result ? (
                <DetectionResult result={result} />
              ) : (
                <div className="flex h-full min-h-[300px] flex-col items-center justify-center text-center text-sm text-muted-dim">
                  <Radar size={28} className="mb-3 text-muted-dim" />
                  Pick a preset or edit the flow, then score it to see the verdict, SHAP explanation, and analyst
                  narrative here.
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="space-y-5">
            <div className="card p-5">
              <p className="text-sm text-foreground">Upload a flow CSV</p>
              <p className="mt-1 text-xs text-muted-dim">
                Headers are mapped heuristically (CICIDS2018/ISCX-VPN/CAIDA-style column names all work), so you can
                drop in an export directly. Batches are capped at 200 rows for demo latency.
              </p>
              <div className="mt-4 flex items-center gap-3">
                <input
                  ref={fileRef}
                  type="file"
                  accept=".csv"
                  className="flex-1 rounded-lg border border-dashed border-border bg-surface-raised px-3 py-2 text-sm text-muted file:mr-3 file:rounded-md file:border-0 file:bg-accent/10 file:px-3 file:py-1.5 file:text-xs file:text-accent"
                />
                <button
                  onClick={runBatch}
                  disabled={batchLoading}
                  className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2.5 text-sm font-medium text-background transition-opacity hover:opacity-90 disabled:opacity-50"
                >
                  {batchLoading ? <Loader2 size={15} className="animate-spin" /> : <UploadCloud size={15} />}
                  {batchLoading ? "Scoring..." : "Upload & score"}
                </button>
              </div>
            </div>

            {batchResult && (
              <div className="card p-5">
                <div className="mb-3 flex items-center gap-4 text-sm">
                  <span className="text-foreground">
                    Scored <span className="mono">{batchResult.total_rows}</span> rows
                  </span>
                  <span className="text-danger">
                    <span className="mono">{batchResult.flagged}</span> flagged
                  </span>
                </div>
                <ThreatTable
                  items={batchResult.detections}
                  onSelect={(item) => {
                    setResult(item);
                    setMode("manual");
                  }}
                />
              </div>
            )}
          </div>
        )}
      </main>
    </>
  );
}
