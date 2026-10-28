from app.clustering import cluster_features
from app.data import loaders
from app.features import engineer_frame


def test_cluster_features_returns_a_point_per_row():
    df = loaders.load_sample_dataset(n=150)
    features = engineer_frame(df)
    result = cluster_features(features, n_clusters=3)
    assert len(result["points"]) == 150
    assert 0.0 <= result["outlier_fraction"] <= 1.0
    assert result["dbscan_eps"] > 0


def test_cluster_eps_adapts_to_feature_scale():
    df = loaders.load_caida(n=150)
    features = engineer_frame(df)
    result = cluster_features(features, n_clusters=3)
    # a reasonable eps keeps most points inside some cluster, not all flagged as outliers
    assert result["outlier_fraction"] < 0.5
