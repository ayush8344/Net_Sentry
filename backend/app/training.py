"""Training orchestration — builds every artifact `main.py` serves at runtime.

Run with `python -m app.training` from `backend/`. Produces, under
`artifacts/`:
  - radiant_boost.joblib   (the production GB+XGB calibrated ensemble)
  - fast_path.joblib       (NB+KNN SMOTE OR-ensemble)
  - metrics.json           (per-dataset metrics, generalization test, params)
  - shap_importance.json   (global feature importance)
  - clusters_<dataset>.json (2D cluster scatter data for the dashboard)
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                              recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from . import config
from .clustering import cluster_features
from .data import loaders
from .explain import RadiantBoostExplainer
from .features import engineer_frame
from .models.baseline import RandomForestBaseline
from .models.fast_path import FastPathEnsemble
from .models.radiant_boost import RadiantBoost


def _binary_target(label_series: pd.Series, positive_values: set[str]) -> np.ndarray:
    return label_series.isin(positive_values).astype(int).values


def train_primary() -> dict:
    """CICIDS2018 profile: the primary train/evaluation dataset."""
    print("[1/5] Loading CICIDS2018 profile...")
    raw = loaders.load_cicids2018()
    y = _binary_target(raw["label"], {"DoS", "PortScan", "BruteForce", "Bot"})
    X = engineer_frame(raw)
    feature_names = list(X.columns)

    X_train, X_temp, y_train, y_temp = train_test_split(X.values, y, test_size=0.4, stratify=y, random_state=config.RANDOM_STATE)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=config.RANDOM_STATE)

    print("[2/5] Fitting Random Forest baseline...")
    baseline = RandomForestBaseline().fit(X_train, y_train)
    baseline_proba = baseline.predict_proba(X_test)

    print("[3/5] Fitting RadiantBoost (GradientBoosting + XGBoost)...")
    started = time.perf_counter()
    radiant = RadiantBoost().fit(X_train, y_train, X_val, y_val, feature_names)
    train_seconds = round(time.perf_counter() - started, 2)

    print("[4/5] Fitting fast-path ensemble (Naive Bayes + KNN, SMOTE)...")
    fast_path = FastPathEnsemble().fit(X_train, y_train)

    print("[5/5] Scoring held-out test set + SHAP global importance...")
    radiant_proba = radiant.predict_proba(X_test)
    radiant_pred = (radiant_proba >= radiant.threshold).astype(int)
    fast_pred = fast_path.predict(X_test)

    inference_started = time.perf_counter()
    radiant.predict_proba(X_test[:1])
    latency_ms = round((time.perf_counter() - inference_started) * 1000, 3)

    explainer = RadiantBoostExplainer(radiant)
    sample_idx = np.random.default_rng(config.RANDOM_STATE).choice(len(X_test), size=min(400, len(X_test)), replace=False)
    shap_importance = explainer.global_importance(X_test[sample_idx])

    metrics = {
        "radiant_boost": {
            "accuracy": round(float(accuracy_score(y_test, radiant_pred)), 4),
            "f1_macro": round(float(f1_score(y_test, radiant_pred, average="macro")), 4),
            "precision": round(float(precision_score(y_test, radiant_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, radiant_pred, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, radiant_proba)), 4),
            "threshold": round(float(radiant.threshold), 4),
            "train_seconds": train_seconds,
            "single_flow_latency_ms": latency_ms,
            **radiant.metrics,
        },
        "random_forest_baseline": {
            "accuracy": round(float(accuracy_score(y_test, (baseline_proba >= 0.5).astype(int))), 4),
            "precision": round(float(precision_score(y_test, (baseline_proba >= 0.5).astype(int), zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, (baseline_proba >= 0.5).astype(int), zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, baseline_proba)), 4),
            "cv_roc_auc": round(float(baseline.cv_roc_auc), 4),
        },
        "fast_path_ensemble": {
            "accuracy": round(float(accuracy_score(y_test, fast_pred)), 4),
            "recall": round(float(recall_score(y_test, fast_pred, zero_division=0)), 4),
            "precision": round(float(precision_score(y_test, fast_pred, zero_division=0)), 4),
        },
        "class_balance": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "using_real_data": loaders.is_using_real_data("cicids2018"),
    }

    radiant.save(config.ARTIFACTS_DIR / "radiant_boost.joblib")
    import joblib
    joblib.dump(fast_path, config.ARTIFACTS_DIR / "fast_path.joblib")

    cluster_sample = X.sample(min(1200, len(X)), random_state=config.RANDOM_STATE)
    clusters = cluster_features(cluster_sample)
    (config.ARTIFACTS_DIR / "clusters_cicids2018.json").write_text(json.dumps(clusters))

    return {"metrics": metrics, "shap_importance": shap_importance, "radiant": radiant, "explainer": explainer}


def evaluate_generalization(radiant: RadiantBoost) -> dict:
    """Cross-dataset generalization test: score ISCX-VPN traffic (tunneled
    traffic repurposed as the positive class) with the CICIDS2018-trained
    model, and sanity-check thresholds against unlabeled CAIDA backbone
    traffic."""
    print("Evaluating generalization on ISCX-VPN + CAIDA...")
    iscx_raw = loaders.load_iscx_vpn()
    y_iscx = _binary_target(iscx_raw["label"], {"VPN"})
    X_iscx = engineer_frame(iscx_raw)
    proba_iscx = radiant.predict_proba(X_iscx.values)
    pred_iscx = (proba_iscx >= radiant.threshold).astype(int)

    caida_raw = loaders.load_caida()
    X_caida = engineer_frame(caida_raw)
    proba_caida = radiant.predict_proba(X_caida.values)
    flagged_fraction_caida = float((proba_caida >= radiant.threshold).mean())
    caida_clusters = cluster_features(X_caida.sample(min(1200, len(X_caida)), random_state=config.RANDOM_STATE))
    (config.ARTIFACTS_DIR / "clusters_caida.json").write_text(json.dumps(caida_clusters))

    return {
        "iscx_vpn": {
            "task": "tunneled-traffic detection (VPN vs non-VPN, cross-dataset)",
            "roc_auc": round(float(roc_auc_score(y_iscx, proba_iscx)), 4),
            "accuracy": round(float(accuracy_score(y_iscx, pred_iscx)), 4),
            "recall": round(float(recall_score(y_iscx, pred_iscx, zero_division=0)), 4),
            "using_real_data": loaders.is_using_real_data("iscx_vpn"),
        },
        "caida": {
            "task": "unsupervised sanity-check (no ground truth)",
            "flagged_fraction": round(flagged_fraction_caida, 4),
            "outlier_fraction_dbscan": round(caida_clusters["outlier_fraction"], 4),
            "using_real_data": loaders.is_using_real_data("caida"),
        },
    }


def run_all() -> dict:
    primary = train_primary()
    generalization = evaluate_generalization(primary["radiant"])

    metrics = primary["metrics"]
    metrics["generalization"] = generalization
    metrics["trained_at"] = datetime.now(timezone.utc).isoformat()
    metrics["feature_count"] = len(primary["radiant"].feature_names)

    (config.ARTIFACTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (config.ARTIFACTS_DIR / "shap_importance.json").write_text(json.dumps(primary["shap_importance"], indent=2))

    if not config.THREAT_LOG_PATH.exists():
        pd.DataFrame(columns=[
            "id", "timestamp", "dataset", "source_ip", "destination_ip", "protocol", "dst_port",
            "model", "verdict", "attack_family", "probability", "threshold", "risk_score", "confidence",
            "top_feature_1", "top_feature_2", "top_feature_3", "analyst_summary", "llm_enabled",
            "analyst_notes", "action_taken",
        ]).to_csv(config.THREAT_LOG_PATH, index=False)

    print("\nTraining complete. Metrics written to artifacts/metrics.json")
    print(json.dumps(metrics["radiant_boost"], indent=2))
    return metrics


if __name__ == "__main__":
    run_all()
