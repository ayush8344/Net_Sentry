"""Unsupervised clustering — run before any labels are used, to surface
natural traffic groupings and outliers. The only analysis available for
CAIDA, which ships with no ground truth at all."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import StandardScaler

from .config import RANDOM_STATE


def _auto_eps(scaled: np.ndarray, min_samples: int, percentile: float = 75) -> float:
    """Standard k-distance heuristic: eps as a percentile of each point's
    distance to its min_samples-th nearest neighbor. Avoids a fixed magic
    constant that only makes sense for one dataset's feature scale."""
    neighbors = NearestNeighbors(n_neighbors=min_samples).fit(scaled)
    distances, _ = neighbors.kneighbors(scaled)
    k_distances = distances[:, -1]
    return float(np.percentile(k_distances, percentile))


def cluster_features(features: pd.DataFrame, n_clusters: int = 4) -> dict:
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features.values)

    kmeans = KMeans(n_clusters=n_clusters, random_state=RANDOM_STATE, n_init=10).fit(scaled)
    min_samples = 8
    eps = _auto_eps(scaled, min_samples)
    dbscan = DBSCAN(eps=eps, min_samples=min_samples).fit(scaled)

    pca = PCA(n_components=2, random_state=RANDOM_STATE)
    coords = pca.fit_transform(scaled)

    outlier_mask = dbscan.labels_ == -1
    outlier_fraction = float(outlier_mask.mean())

    points = [
        {
            "x": round(float(coords[i, 0]), 3),
            "y": round(float(coords[i, 1]), 3),
            "cluster": int(kmeans.labels_[i]),
            "outlier": bool(outlier_mask[i]),
        }
        for i in range(len(features))
    ]
    return {
        "points": points,
        "outlier_fraction": outlier_fraction,
        "n_clusters": n_clusters,
        "dbscan_eps": round(eps, 4),
        "kmeans_inertia": float(kmeans.inertia_),
        "explained_variance": [round(float(v), 4) for v in pca.explained_variance_ratio_],
    }
