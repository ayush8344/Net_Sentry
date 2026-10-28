import TopBar from "@/components/TopBar";
import { Check, X, Minus } from "lucide-react";

const POSITIONING = [
  { capability: "Automated, continuous scoring", wireshark: "no", zeek: "partial", netsentry: "yes" },
  { capability: "Learns patterns from data (ML)", wireshark: "no", zeek: "no", netsentry: "yes" },
  { capability: "Calibrated probability scores", wireshark: "no", zeek: "no", netsentry: "yes" },
  { capability: "Per-detection explainability (SHAP)", wireshark: "no", zeek: "no", netsentry: "yes" },
  { capability: "Analyst-readable narrative output", wireshark: "no", zeek: "no", netsentry: "yes" },
  { capability: "Works fully offline / zero-cost", wireshark: "yes", zeek: "yes", netsentry: "yes" },
] as const;

function Mark({ v }: { v: "yes" | "no" | "partial" }) {
  if (v === "yes") return <Check size={14} className="mx-auto text-success" />;
  if (v === "no") return <X size={14} className="mx-auto text-danger" />;
  return <Minus size={14} className="mx-auto text-warning" />;
}

const PIPELINE = [
  { step: "1. Data Collection", detail: "Sample CSV, CICIDS2018, ISCX-VPN2016, CAIDA (pcap) — one canonical schema via a heuristic column mapper." },
  { step: "2. Preprocessing", detail: "Cleaning, time features, protocol one-hot, TCP flag features, port binning, flow aggregates — 23 engineered features." },
  { step: "3. Protocol Separation", detail: "TCP vs UDP subsets for protocol-specific analysis and visualization." },
  { step: "4. Clustering", detail: "K-Means + DBSCAN (auto-tuned eps) before any labels are used — surfaces groupings and outliers, essential for unlabeled CAIDA." },
  { step: "5. Detection", detail: "RadiantBoost: GradientBoosting + XGBoost, RandomizedSearchCV-tuned, isotonic-calibrated, threshold auto-selected for 95% TPR / ≤2% FPR." },
  { step: "6. Explainability + LLM + Reporting", detail: "SHAP TreeExplainer for local/global attribution, Claude API (or offline template) for narratives, CSV threat log + dashboard." },
];

const TECH_STACK = [
  { layer: "Data capture", tools: "scapy (pcap), pandas (CSV)" },
  { layer: "Preprocessing", tools: "pandas, numpy, scikit-learn (LabelEncoder, StandardScaler)" },
  { layer: "Unsupervised", tools: "scikit-learn (KMeans, DBSCAN, NearestNeighbors for eps)" },
  { layer: "Supervised detection", tools: "scikit-learn (GradientBoosting, RandomForest, NB, KNN, CalibratedClassifierCV), XGBoost, imbalanced-learn (SMOTE)" },
  { layer: "Explainability", tools: "SHAP (TreeExplainer)" },
  { layer: "LLM narrative", tools: "Anthropic Claude API, graceful offline fallback" },
  { layer: "API / backend", tools: "FastAPI, Pydantic, uvicorn" },
  { layer: "Frontend", tools: "Next.js, TypeScript, Tailwind CSS, Recharts" },
];

export default function AboutPage() {
  return (
    <>
      <TopBar title="About" subtitle="Motivation, positioning, and architecture" />
      <main className="flex-1 space-y-8 p-6">
        <section className="card p-6">
          <h2 className="text-sm font-semibold text-foreground">The gap in today&apos;s intrusion-detection tooling</h2>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="card-raised p-4">
              <p className="text-sm font-medium text-foreground">Wireshark</p>
              <ul className="mt-2 space-y-1.5 text-xs text-muted">
                <li>A human manually applies filters and recognizes patterns visually</li>
                <li>No built-in ML, no automated scoring</li>
                <li>Doesn&apos;t scale to continuous classification of large traffic volumes</li>
              </ul>
            </div>
            <div className="card-raised p-4">
              <p className="text-sm font-medium text-foreground">Zeek</p>
              <ul className="mt-2 space-y-1.5 text-xs text-muted">
                <li>Logs structured flow records, flags traffic via handwritten scripts</li>
                <li>Detection is rule/signature-based, not learned from data</li>
                <li>No calibrated probability scores, no explainability of why something was flagged</li>
              </ul>
            </div>
          </div>
          <p className="mt-4 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3 text-sm italic text-accent">
            Neither tool closes the loop from raw traffic to an explained, automated threat verdict — that&apos;s the
            gap this project targets.
          </p>
        </section>

        <section className="card p-6">
          <h2 className="text-sm font-semibold text-foreground">Where NetSentry fits</h2>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted-dim">
                  <th className="py-2 pr-4 font-medium">Capability</th>
                  <th className="py-2 px-4 text-center font-medium">Wireshark</th>
                  <th className="py-2 px-4 text-center font-medium">Zeek</th>
                  <th className="py-2 px-4 text-center font-medium">NetSentry</th>
                </tr>
              </thead>
              <tbody>
                {POSITIONING.map((row) => (
                  <tr key={row.capability} className="border-b border-border/60">
                    <td className="py-2.5 pr-4 text-muted">{row.capability}</td>
                    <td className="py-2.5 px-4">
                      <Mark v={row.wireshark} />
                    </td>
                    <td className="py-2.5 px-4">
                      <Mark v={row.zeek} />
                    </td>
                    <td className="py-2.5 px-4">
                      <Mark v={row.netsentry} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="card p-6">
          <h2 className="text-sm font-semibold text-foreground">Six-phase pipeline</h2>
          <div className="mt-4 space-y-3">
            {PIPELINE.map((p) => (
              <div key={p.step} className="flex flex-col gap-1 border-l-2 border-accent/40 pl-4 sm:flex-row sm:gap-4">
                <p className="w-56 shrink-0 text-sm font-medium text-foreground">{p.step}</p>
                <p className="text-sm text-muted">{p.detail}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="card p-6">
          <h2 className="text-sm font-semibold text-foreground">Why Gradient Boosting replaces Random Forest</h2>
          <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="card-raised p-4">
              <p className="text-sm font-medium text-muted">Random Forest (baseline)</p>
              <ul className="mt-2 space-y-1.5 text-xs text-muted">
                <li>Bagged trees trained independently, in parallel</li>
                <li>Averages away variance, robust out of the box</li>
                <li>Less sensitive to hyperparameters, lower precision ceiling on imbalanced intrusion data</li>
              </ul>
            </div>
            <div className="card-raised border border-accent/30 p-4">
              <p className="text-sm font-medium text-accent">RadiantBoost — GB + XGBoost (chosen)</p>
              <ul className="mt-2 space-y-1.5 text-xs text-muted">
                <li>Trees built sequentially — each corrects the previous tree&apos;s errors</li>
                <li>Typically better precision on imbalanced intrusion data</li>
                <li>Trade-off: needs careful tuning (learning rate, depth) to avoid overfitting</li>
              </ul>
            </div>
          </div>
          <p className="mt-4 text-xs italic text-muted-dim">
            Both are tuned with RandomizedSearchCV and calibrated identically — see the Dashboard for the live,
            measured comparison on this run&apos;s held-out test set.
          </p>
        </section>

        <section className="card p-6">
          <h2 className="text-sm font-semibold text-foreground">Tech stack</h2>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-[11px] uppercase tracking-wide text-muted-dim">
                  <th className="py-2 pr-4 font-medium">Layer</th>
                  <th className="py-2 pr-4 font-medium">Tools</th>
                </tr>
              </thead>
              <tbody>
                {TECH_STACK.map((row) => (
                  <tr key={row.layer} className="border-b border-border/60">
                    <td className="py-2.5 pr-4 font-medium text-accent">{row.layer}</td>
                    <td className="py-2.5 pr-4 text-muted">{row.tools}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="card p-6 text-center">
          <p className="text-sm font-medium text-foreground">NetSentry — Explainable Network Intrusion Detection</p>
          <p className="mt-1 text-xs text-muted-dim">Ayush Gupta (23BCE0157) · Kartikay Chauhan (24BCE0689)</p>
        </section>
      </main>
    </>
  );
}
