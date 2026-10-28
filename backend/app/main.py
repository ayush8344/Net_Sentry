from __future__ import annotations

import io
import json
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pandas as pd
from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from . import config, live, llm, store, training
from .data.loaders import map_flow_csv_columns, is_using_real_data, load_dataset
from .explain import (RadiantBoostExplainer, infer_attack_family,
                       readable_feature_values)
from .features import FEATURE_NAMES, engineer_one
from .models.radiant_boost import RadiantBoost
from .schemas import (BatchDetectionResponse, DetectionRequest,
                       DetectionResponse, FlowFeatures)

state: dict = {"model": None, "explainer": None, "metrics": {}, "shap_importance": [], "training": False}


def _load_artifacts() -> bool:
    model_path = config.ARTIFACTS_DIR / "radiant_boost.joblib"
    metrics_path = config.ARTIFACTS_DIR / "metrics.json"
    if not model_path.exists() or not metrics_path.exists():
        return False
    state["model"] = RadiantBoost.load(model_path)
    state["explainer"] = RadiantBoostExplainer(state["model"])
    state["metrics"] = json.loads(metrics_path.read_text())
    importance_path = config.ARTIFACTS_DIR / "shap_importance.json"
    if importance_path.exists():
        state["shap_importance"] = json.loads(importance_path.read_text())
    return True


def _train_and_load() -> None:
    state["training"] = True
    try:
        training.run_all()
        _load_artifacts()
    finally:
        state["training"] = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not _load_artifacts():
        print("No trained model found — training on synthetic + real-schema data now (first run only)...")
        _train_and_load()
    yield
    live.capture.stop()


app = FastAPI(title="NetSentry API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"], allow_headers=["*"],
)


def _require_model() -> RadiantBoost:
    if state["model"] is None:
        raise HTTPException(503, "Model is not ready yet — training in progress.")
    return state["model"]


def _score_flow(dataset: str, flow: FlowFeatures, source: str = "manual") -> DetectionResponse:
    model = _require_model()
    explainer: RadiantBoostExplainer = state["explainer"]

    started = time.perf_counter()
    vector = engineer_one(flow)
    probability = float(model.predict_proba(vector.reshape(1, -1))[0])
    threshold = model.threshold
    watch_threshold = threshold * 0.6

    if probability >= threshold:
        verdict = "Attack"
    elif probability >= watch_threshold:
        verdict = "Suspicious"
    else:
        verdict = "Benign"

    raw_values = readable_feature_values(vector)
    attributions = explainer.local_attributions(vector, raw_values)
    feature_values = dict(zip(FEATURE_NAMES, vector))
    attack_family = infer_attack_family(feature_values, verdict)
    if probability >= threshold:
        confidence = 0.5 + (probability - threshold) / max(1 - threshold, 1e-6) * 0.49
    else:
        confidence = 0.5 + (threshold - probability) / max(threshold, 1e-6) * 0.49
    confidence = round(min(confidence, 0.99), 3)
    risk_score = round(min(99, max(1, probability * 100)))

    # Live capture can score hundreds of flows a minute — keep it on the offline
    # template so it doesn't burn the capped Claude budget meant for manual analysis.
    summary, llm_enabled = llm.analyst_summary(dataset, verdict, attack_family, confidence, attributions[:3],
                                               allow_llm=source != "live")

    recommendations = [
        "Correlate with Zeek conn.log / dns.log for this IP pair before escalating.",
        "Use Wireshark to inspect the first suspicious handshake at the packet level.",
        "Quarantine only after validating the source asset and business context.",
    ] if verdict != "Benign" else ["No action required — traffic is consistent with expected behavior."]

    response = DetectionResponse(
        id=f"{'LIVE' if source == 'live' else 'NS'}-{uuid.uuid4().hex[:8].upper()}", dataset=dataset, verdict=verdict,
        attack_family=attack_family, confidence=confidence, risk_score=risk_score,
        probability=round(probability, 4), threshold=round(threshold, 4),
        latency_ms=round((time.perf_counter() - started) * 1000, 3), model=model.name,
        explanation_method="SHAP TreeExplainer (local attribution)", attributions=attributions,
        analyst_summary=summary, recommendations=recommendations, llm_enabled=llm_enabled,
        timestamp=datetime.now(timezone.utc).isoformat(), flow=flow, source=source,
    )
    store.append(response)
    return response


@app.get("/api/health")
def health() -> dict:
    model = state["model"]
    return {
        "status": "training" if state["training"] else "ok",
        "model": model.name if model else None,
        "threshold": round(model.threshold, 4) if model else None,
        "datasets": list(config.DATASET_PROFILES),
        "llm_calls_remaining": llm.calls_remaining(),
    }


@app.get("/api/model/metrics")
def model_metrics() -> dict:
    if not state["metrics"]:
        raise HTTPException(503, "Metrics not available yet.")
    return state["metrics"]


@app.get("/api/model/importance")
def model_importance() -> list[dict]:
    return state["shap_importance"]


@app.get("/api/clusters")
def clusters(dataset: str = "cicids2018") -> dict:
    path = config.ARTIFACTS_DIR / f"clusters_{dataset}.json"
    if not path.exists():
        raise HTTPException(404, f"No cluster snapshot for '{dataset}'.")
    return json.loads(path.read_text())


@app.get("/api/datasets")
def datasets() -> list[dict]:
    descriptions = {
        "cicids2018": "Enterprise traffic with labeled attack families — primary training/evaluation dataset.",
        "iscx_vpn": "VPN vs non-VPN traffic, repurposed as tunneled-traffic detection — generalization test.",
        "caida": "Unlabeled real backbone traffic — unsupervised clustering + threshold sanity-check.",
        "sample": "Quick synthetic demo set — canonical schema already applied.",
    }
    return [
        {"name": name, "description": descriptions[name], "using_real_data": is_using_real_data(name)}
        for name in config.DATASET_PROFILES
    ]


@app.get("/api/datasets/{dataset}/preview")
def dataset_preview(dataset: str, n: int = 10) -> dict:
    if dataset not in config.DATASET_PROFILES:
        raise HTTPException(404, f"Unknown dataset '{dataset}'.")
    df = load_dataset(dataset, n=min(n, 50))
    return {"columns": list(df.columns), "rows": df.head(n).fillna("").to_dict(orient="records")}


@app.post("/api/detect", response_model=DetectionResponse)
def detect(request: DetectionRequest) -> DetectionResponse:
    return _score_flow(request.dataset, request.flow)


@app.post("/api/detect/batch", response_model=BatchDetectionResponse)
async def detect_batch(dataset: str = "cicids2018", file: UploadFile = File(...)) -> BatchDetectionResponse:
    if dataset not in config.DATASET_PROFILES:
        raise HTTPException(400, f"Unknown dataset '{dataset}'.")
    raw_bytes = await file.read()
    try:
        raw_df = pd.read_csv(io.BytesIO(raw_bytes))
    except Exception as exc:
        raise HTTPException(400, f"Could not parse CSV: {exc}") from exc

    canonical = map_flow_csv_columns(raw_df).head(200)  # cap batch size for demo latency
    detections = []
    for row in canonical.to_dict(orient="records"):
        flow = FlowFeatures(
            source_ip=row["source_ip"], destination_ip=row["destination_ip"], protocol=row["protocol"],
            src_port=row["src_port"], dst_port=row["dst_port"], duration_ms=row["duration_ms"],
            fwd_packets=row["fwd_packets"], bwd_packets=row["bwd_packets"], total_bytes=row["total_bytes"],
            packet_size_mean=row["packet_size_mean"], packet_size_std=row["packet_size_std"],
            syn_count=row["syn_count"], fin_count=row["fin_count"], rst_count=row["rst_count"],
            unique_dst_ports=row["unique_dst_ports"], payload_entropy=row["payload_entropy"],
            is_vpn=bool(row["is_vpn"]), hour_of_day=row["hour_of_day"],
        )
        detections.append(_score_flow(dataset, flow))

    flagged = sum(1 for d in detections if d.verdict != "Benign")
    return BatchDetectionResponse(dataset=dataset, total_rows=len(detections), flagged=flagged, detections=detections)


@app.get("/api/threat-log")
def threat_log(limit: int = 100, verdict: str | None = None, dataset: str | None = None) -> dict:
    items = store.recent(limit=limit, verdict=verdict, dataset=dataset)
    return {"items": items, "stats": store.stats()}


@app.get("/api/threat-log/export")
def export_threat_log() -> StreamingResponse:
    if not config.THREAT_LOG_PATH.exists():
        raise HTTPException(404, "No threat log yet.")
    data = config.THREAT_LOG_PATH.read_bytes()
    return StreamingResponse(io.BytesIO(data), media_type="text/csv",
                              headers={"Content-Disposition": "attachment; filename=threat_log.csv"})


@app.post("/api/train")
def retrain(background_tasks: BackgroundTasks) -> dict:
    if state["training"]:
        return {"status": "already training"}
    background_tasks.add_task(_train_and_load)
    return {"status": "started"}


# Live capture is scored against the CICIDS2018 profile — it's the enterprise-traffic
# dataset RadiantBoost is trained and thresholded on.
LIVE_DATASET = "cicids2018"


def _score_live_flow(flow: FlowFeatures) -> None:
    _score_flow(LIVE_DATASET, flow, source="live")


@app.get("/api/live/status")
def live_status() -> dict:
    return live.capture.status()


@app.post("/api/live/start")
def live_start() -> dict:
    _require_model()
    try:
        live.capture.start(_score_live_flow)
    except live.LiveCaptureError as exc:
        raise HTTPException(503, str(exc)) from exc
    return live.capture.status()


@app.post("/api/live/stop")
def live_stop() -> dict:
    live.capture.stop()
    return live.capture.status()


@app.get("/api/live/feed")
def live_feed(limit: int = 100) -> dict:
    return {"status": live.capture.status(), "items": store.recent(limit=limit, source="live")}
