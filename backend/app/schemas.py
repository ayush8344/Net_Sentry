from typing import Literal, Optional

from pydantic import BaseModel, Field

DatasetName = Literal["cicids2018", "iscx_vpn", "caida", "sample"]
Protocol = Literal["TCP", "UDP", "ICMP"]


class FlowFeatures(BaseModel):
    """Raw, human-editable flow record. `features.engineer()` turns this into the
    numeric vector the models actually see."""

    source_ip: str = "10.10.4.21"
    destination_ip: str = "172.16.0.12"
    protocol: Protocol = "TCP"
    src_port: int = Field(51514, ge=0, le=65535)
    dst_port: int = Field(443, ge=0, le=65535)
    duration_ms: float = Field(820.0, ge=0)
    fwd_packets: int = Field(120, ge=0)
    bwd_packets: int = Field(94, ge=0)
    total_bytes: float = Field(158_000, ge=0)
    packet_size_mean: float = Field(410.0, ge=0)
    packet_size_std: float = Field(180.0, ge=0)
    syn_count: int = Field(1, ge=0)
    fin_count: int = Field(1, ge=0)
    rst_count: int = Field(0, ge=0)
    unique_dst_ports: int = Field(2, ge=0)
    payload_entropy: float = Field(6.9, ge=0, le=8)
    is_vpn: bool = False
    hour_of_day: int = Field(14, ge=0, le=23)


class DetectionRequest(BaseModel):
    dataset: DatasetName = "cicids2018"
    flow: FlowFeatures = FlowFeatures()


class Attribution(BaseModel):
    feature: str
    value: str
    contribution: float
    direction: Literal["risk", "benign"]
    description: str = ""


class DetectionResponse(BaseModel):
    id: str
    dataset: DatasetName
    verdict: Literal["Benign", "Suspicious", "Attack"]
    attack_family: str
    confidence: float
    risk_score: int
    probability: float
    threshold: float
    latency_ms: float
    model: str
    explanation_method: str
    attributions: list[Attribution]
    analyst_summary: str
    recommendations: list[str]
    llm_enabled: bool
    timestamp: str
    flow: Optional[FlowFeatures] = None
    source: Literal["manual", "live"] = "manual"


class ModelMetrics(BaseModel):
    name: str
    trained_at: str
    threshold: float
    datasets: dict


class ImportanceItem(BaseModel):
    feature: str
    mean_abs_shap: float


class ClusterPoint(BaseModel):
    x: float
    y: float
    cluster: int
    outlier: bool
    dataset: DatasetName


class BatchDetectionResponse(BaseModel):
    dataset: DatasetName
    total_rows: int
    flagged: int
    detections: list[DetectionResponse]
