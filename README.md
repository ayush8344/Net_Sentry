# NetSentry

**Explainable, ML-driven network intrusion detection.** NetSentry closes the gap between manual packet-analysis
tools (Wireshark, Zeek) and modern ML-IDS research: raw traffic goes in, a calibrated threat probability comes
out, backed by a SHAP explanation and a plain-language analyst narrative — automatically, not by a human staring
at filters.

Final-year computer networks project — Ayush Gupta (23BCE0157), Kartikay Chauhan (24BCE0689).

## What's here

- **`backend/`** — FastAPI service + the full ML pipeline: dataset loaders, feature engineering, K-Means/DBSCAN
  clustering, a calibrated GradientBoosting + XGBoost ensemble ("RadiantBoost"), a Random Forest baseline for
  comparison, a SHAP `TreeExplainer` explainability layer, and an Anthropic Claude narrative layer with an
  offline fallback.
- **`frontend/`** — Next.js + TypeScript + Tailwind dashboard: live detection (manual flow or batch CSV), a
  threat log, SHAP explanations, a clustering explorer, and model metrics.

## Research focus

Wireshark requires a human to apply filters and recognize patterns visually — no automated scoring. Zeek logs
structured flow records but flags traffic via handwritten, signature-based scripts — no learning from data, no
calibrated probabilities, no explanation of *why* something was flagged. NetSentry targets that gap: automated,
calibrated, explainable, narrated verdicts.

Dataset profiles (see [Data note](#data-note) below):

| Dataset | Role |
|---|---|
| CICIDS2018 | Primary training/evaluation set (labeled attack families) |
| ISCX-VPN2016 | Repurposed as tunneled-traffic detection — cross-dataset generalization test |
| CAIDA | Unlabeled real backbone traffic — unsupervised clustering + threshold sanity-check |

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

On first run (no `artifacts/radiant_boost.joblib` yet) the API trains everything automatically — takes about
10–20 seconds. To retrain explicitly (e.g. after dropping in real data): `python -m app.training`.

Run the test suite: `python -m pytest tests/ -v`.

Optional: set `ANTHROPIC_API_KEY` (and optionally `LLM_MODEL`, default `claude-sonnet-5`) to enable live Claude
analyst narratives. Without it, a deterministic offline template generates the narrative from the same SHAP
values — the app is fully functional with zero external dependency.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. It proxies `/api/*` to the backend on port 8000 (configurable via the `BACKEND_URL`
env var, see `next.config.ts`).

### Live capture (real-time traffic)

The **Live Capture** page sniffs packets on this machine's default interface (`backend/app/live.py`, via scapy),
groups them into bidirectional flows (ending after 5 s idle, 30 s active, or FIN/RST), and scores each finished
flow with RadiantBoost — results also land in the Threat Log with a `LIVE-` id. Live flows use the offline
narrative template so they don't consume the Claude call budget.

Capture needs packet-level access: on Windows install [Npcap](https://npcap.com) ("WinPcap API-compatible mode")
and restart the backend, **or** run the backend from an Administrator terminal (IPv4-only raw-socket fallback).
On Linux/macOS run the backend with `sudo`.

## Data note

The real CICIDS2018, CAIDA, and ISCX-VPN2016 datasets are gated behind signed data-sharing agreements and
multi-gigabyte downloads, so they aren't bundled here. `backend/app/data/synthetic.py` generates flow-level
records with each benchmark's *native column names* and realistic per-class statistics (including label noise,
so metrics land in a believable ~97% range rather than a suspicious 100%), which exercises the entire pipeline —
loading, column mapping, feature engineering, training, clustering, SHAP, narrative generation — end to end.

To use real data: drop exported CSVs (or CAIDA pcap-derived flow CSVs) into `backend/data_raw/<dataset>/` and
retrain. `backend/app/data/loaders.py`'s heuristic column mapper (`map_flow_csv_columns`) handles differently
named/ordered headers automatically — no code changes needed. The Datasets page in the UI shows which profile is
currently backed by real vs. synthetic data.

## Model notes

- **RadiantBoost** (`backend/app/models/radiant_boost.py`) is the production detector: `GradientBoostingClassifier`
  + `XGBClassifier`, each tuned with `RandomizedSearchCV` (3-fold CV, scored on ROC-AUC) and isotonic-calibrated
  via `CalibratedClassifierCV`. Final score is the mean of both models' calibrated probabilities. The decision
  threshold is auto-selected for 95% TPR / ≤2% FPR, falling back to max(TPR−FPR).
- A **Random Forest baseline** (`models/baseline.py`) is tuned and calibrated identically, for a fair
  sequential-vs-independent tree-building comparison — see the Dashboard for the live, measured numbers.
- A **fast-path ensemble** (`models/fast_path.py`) — Naive Bayes + KNN on SMOTE-oversampled data, OR-rule,
  recall-biased — represents the cheap first-pass alternative described in the design writeup.
- **Explainability**: `shap.TreeExplainer` runs on RadiantBoost's underlying (unwrapped-from-calibration)
  Gradient Boosting estimator, producing both global feature importance and per-flow signed local attributions.
- **Attack-family labeling** is a separate, simple rule-based layer over the raw engineered features (port-scan
  breadth, SYN ratio, entropy, etc.) — deliberately decoupled from SHAP rank, since one or two features can
  dominate global importance and would otherwise mask a clearer signal further down the ranking.

## Evaluation

Compare RadiantBoost against the Random Forest baseline on accuracy, F1, recall (minority/attack class), and
ROC-AUC — all shown live on the Dashboard. Then look at cross-dataset generalization: the CICIDS2018-trained
model transfers poorly to ISCX-VPN traffic (near-random AUC) by design — this is the expected distribution-shift
finding the write-up calls out, not a bug, and it's the reason a single-benchmark evaluation overstates
real-world readiness.
