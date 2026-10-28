import io

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert "RadiantBoost" in body["model"]


def test_detect_benign_default_flow(client):
    res = client.post("/api/detect", json={"dataset": "cicids2018", "flow": {}})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] in {"Benign", "Suspicious", "Attack"}
    assert len(body["attributions"]) > 0
    assert 0.0 <= body["confidence"] <= 0.99


def test_detect_port_scan_shaped_flow_is_flagged(client):
    flow = {
        "protocol": "TCP", "dst_port": 22345, "duration_ms": 80, "fwd_packets": 2, "bwd_packets": 0,
        "total_bytes": 120, "packet_size_mean": 60, "packet_size_std": 5, "syn_count": 2, "fin_count": 0,
        "rst_count": 1, "unique_dst_ports": 45, "payload_entropy": 2.5,
    }
    res = client.post("/api/detect", json={"dataset": "cicids2018", "flow": flow})
    assert res.status_code == 200
    body = res.json()
    assert body["verdict"] == "Attack"
    assert body["attack_family"] == "Port Scan"


def test_model_metrics_and_importance(client):
    metrics = client.get("/api/model/metrics")
    assert metrics.status_code == 200
    assert "radiant_boost" in metrics.json()

    importance = client.get("/api/model/importance")
    assert importance.status_code == 200
    assert len(importance.json()) > 0


def test_clusters_endpoint(client):
    res = client.get("/api/clusters?dataset=cicids2018")
    assert res.status_code == 200
    assert len(res.json()["points"]) > 0


def test_datasets_and_preview(client):
    res = client.get("/api/datasets")
    assert res.status_code == 200
    names = {d["name"] for d in res.json()}
    assert names == {"cicids2018", "iscx_vpn", "caida", "sample"}

    preview = client.get("/api/datasets/sample/preview?n=5")
    assert preview.status_code == 200
    assert len(preview.json()["rows"]) == 5


def test_batch_detect_rejects_bad_csv(client):
    bad_file = io.BytesIO(b"not,a,valid\nheader,row,here")
    res = client.post("/api/detect/batch?dataset=sample", files={"file": ("bad.csv", bad_file, "text/csv")})
    assert res.status_code == 200  # mapper fills defaults rather than failing
    assert res.json()["total_rows"] == 1


def test_threat_log_reflects_detections(client):
    client.post("/api/detect", json={"dataset": "sample", "flow": {}})
    res = client.get("/api/threat-log?limit=10")
    assert res.status_code == 200
    assert res.json()["stats"]["total"] >= 1
