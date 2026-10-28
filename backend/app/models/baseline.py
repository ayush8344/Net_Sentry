"""Random Forest baseline — bagged trees trained independently and averaged.
Robust out of the box and less sensitive to hyperparameters than boosting,
but with a lower precision ceiling on this imbalanced intrusion data. Tuned
and calibrated identically to RadiantBoost (`radiant_boost.py`) so the
comparison isolates sequential vs. independent tree-building, not effort."""

from __future__ import annotations

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV

from ..config import RANDOM_STATE

RF_PARAM_GRID = {
    "n_estimators": [100, 200, 300],
    "max_depth": [None, 8, 12, 16],
    "min_samples_leaf": [1, 2, 4],
}


class RandomForestBaseline:
    name = "Random Forest baseline (bagged, calibrated)"

    def __init__(self) -> None:
        self.calibrated: CalibratedClassifierCV | None = None
        self.cv_roc_auc: float = 0.0

    def fit(self, X_train: np.ndarray, y_train: np.ndarray, n_iter: int = 6) -> "RandomForestBaseline":
        search = RandomizedSearchCV(
            RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1), RF_PARAM_GRID,
            n_iter=n_iter, cv=3, scoring="roc_auc", random_state=RANDOM_STATE, n_jobs=-1,
        ).fit(X_train, y_train)
        self.cv_roc_auc = float(search.best_score_)
        self.calibrated = CalibratedClassifierCV(search.best_estimator_, method="isotonic", cv=3).fit(X_train, y_train)
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.calibrated.predict_proba(X)[:, 1]
