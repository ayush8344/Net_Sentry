"""RadiantBoost — the production detector.

A calibrated Gradient Boosting + XGBoost ensemble. Chosen over a Random
Forest baseline (see `baseline.py`) because sequential, error-correcting
tree building consistently gave better precision on this imbalanced
intrusion data during model comparison, at the cost of needing careful
tuning to avoid overfitting.

    score(x) = mean(P_gb_calibrated(malicious | x), P_xgb_calibrated(malicious | x))

Both branches go through the same `RandomizedSearchCV` -> isotonic
calibration -> ROC-AUC-scored pipeline so the comparison against the
baseline isolates tree-building strategy, not tuning effort.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import roc_curve
from sklearn.model_selection import RandomizedSearchCV
from xgboost import XGBClassifier

from ..config import MAX_FPR, RANDOM_STATE, TARGET_TPR

GB_PARAM_GRID = {
    "n_estimators": [80, 120, 160],
    "learning_rate": [0.03, 0.05, 0.1],
    "max_depth": [2, 3, 4],
    "subsample": [0.8, 1.0],
}

XGB_PARAM_GRID = {
    "n_estimators": [80, 120, 160],
    "learning_rate": [0.03, 0.05, 0.1],
    "max_depth": [3, 4, 5],
    "subsample": [0.8, 1.0],
    "colsample_bytree": [0.7, 1.0],
}


def _unwrap_calibrated(calibrated: CalibratedClassifierCV):
    """CalibratedClassifierCV wraps a clone of the base estimator per fold.
    SHAP's TreeExplainer needs the raw tree structure, not the calibration
    wrapper, so pull the first fold's fitted estimator back out."""
    fold = calibrated.calibrated_classifiers_[0]
    return getattr(fold, "estimator", None) or getattr(fold, "base_estimator", None)


@dataclass
class RadiantBoost:
    name: str = "RadiantBoost (GB + XGB, isotonic-calibrated)"
    feature_names: list[str] = field(default_factory=list)
    threshold: float = 0.5
    gb_calibrated: CalibratedClassifierCV | None = None
    xgb_calibrated: CalibratedClassifierCV | None = None
    metrics: dict = field(default_factory=dict)

    def fit(self, X_train: np.ndarray, y_train: np.ndarray, X_val: np.ndarray, y_val: np.ndarray,
            feature_names: list[str], n_iter: int = 8) -> "RadiantBoost":
        self.feature_names = feature_names

        gb_search = RandomizedSearchCV(
            GradientBoostingClassifier(random_state=RANDOM_STATE), GB_PARAM_GRID,
            n_iter=n_iter, cv=3, scoring="roc_auc", random_state=RANDOM_STATE, n_jobs=-1,
        ).fit(X_train, y_train)
        xgb_search = RandomizedSearchCV(
            XGBClassifier(random_state=RANDOM_STATE, eval_metric="logloss"), XGB_PARAM_GRID,
            n_iter=n_iter, cv=3, scoring="roc_auc", random_state=RANDOM_STATE, n_jobs=-1,
        ).fit(X_train, y_train)

        self.gb_calibrated = CalibratedClassifierCV(gb_search.best_estimator_, method="isotonic", cv=3).fit(X_train, y_train)
        self.xgb_calibrated = CalibratedClassifierCV(xgb_search.best_estimator_, method="isotonic", cv=3).fit(X_train, y_train)

        self.threshold = self._select_threshold(X_val, y_val)
        self.metrics = {
            "gb_best_params": gb_search.best_params_,
            "xgb_best_params": xgb_search.best_params_,
            "gb_cv_roc_auc": round(float(gb_search.best_score_), 4),
            "xgb_cv_roc_auc": round(float(xgb_search.best_score_), 4),
        }
        return self

    def _select_threshold(self, X_val: np.ndarray, y_val: np.ndarray) -> float:
        proba = self.predict_proba(X_val)
        fpr, tpr, thresholds = roc_curve(y_val, proba)
        candidates = [(t, tp, fp) for t, tp, fp in zip(thresholds, tpr, fpr) if tp >= TARGET_TPR and fp <= MAX_FPR]
        if candidates:
            return float(sorted(candidates, key=lambda c: c[2])[0][0])
        best_idx = int(np.argmax(tpr - fpr))
        return float(thresholds[best_idx])

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        gb_p = self.gb_calibrated.predict_proba(X)[:, 1]
        xgb_p = self.xgb_calibrated.predict_proba(X)[:, 1]
        return (gb_p + xgb_p) / 2.0

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        t = self.threshold if threshold is None else threshold
        return (self.predict_proba(X) >= t).astype(int)

    def raw_gb_estimator(self):
        return _unwrap_calibrated(self.gb_calibrated)

    def raw_xgb_estimator(self):
        return _unwrap_calibrated(self.xgb_calibrated)

    def save(self, path) -> None:
        joblib.dump(self, path)

    @classmethod
    def load(cls, path) -> "RadiantBoost":
        return joblib.load(path)
