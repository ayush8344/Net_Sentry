"""Fast-path ensemble — Naive Bayes + KNN, tuned lightly and trained on
SMOTE-oversampled data to fight class imbalance. Flags malicious if *either*
model crosses its threshold (an OR-rule), biasing the ensemble toward high
recall at the cost of some precision — useful as a cheap first-pass filter
ahead of the heavier, calibrated RadiantBoost verdict."""

from __future__ import annotations

import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import GridSearchCV
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier

from ..config import RANDOM_STATE


class FastPathEnsemble:
    name = "Fast-path ensemble (Naive Bayes + KNN, SMOTE, OR-rule)"

    def __init__(self) -> None:
        self.nb: GaussianNB | None = None
        self.knn: KNeighborsClassifier | None = None
        self.threshold = 0.5

    def fit(self, X_train: np.ndarray, y_train: np.ndarray) -> "FastPathEnsemble":
        X_res, y_res = SMOTE(random_state=RANDOM_STATE).fit_resample(X_train, y_train)

        nb_search = GridSearchCV(GaussianNB(), {"var_smoothing": [1e-9, 1e-7, 1e-5]}, cv=3, scoring="f1")
        nb_search.fit(X_res, y_res)
        self.nb = nb_search.best_estimator_

        knn_search = GridSearchCV(KNeighborsClassifier(), {"n_neighbors": [3, 5, 9]}, cv=3, scoring="f1")
        knn_search.fit(X_res, y_res)
        self.knn = knn_search.best_estimator_
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        nb_p = self.nb.predict_proba(X)[:, 1]
        knn_p = self.knn.predict_proba(X)[:, 1]
        return np.maximum(nb_p, knn_p)  # OR-rule: either model's confidence wins

    def predict(self, X: np.ndarray, threshold: float | None = None) -> np.ndarray:
        t = self.threshold if threshold is None else threshold
        return (self.predict_proba(X) >= t).astype(int)
