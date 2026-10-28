"""In-memory + CSV-backed threat log. Simple by design: a single process
demo dashboard doesn't need a database, and appending to CSV keeps every run
auditable on disk (matches the project's `threat_log.csv` deliverable)."""

from __future__ import annotations

import csv
import threading
from collections import deque

from .config import THREAT_LOG_PATH
from .schemas import DetectionResponse

_lock = threading.Lock()
_recent: deque[DetectionResponse] = deque(maxlen=500)

CSV_FIELDS = [
    "id", "timestamp", "dataset", "source_ip", "destination_ip", "protocol", "dst_port",
    "model", "verdict", "attack_family", "probability", "threshold", "risk_score", "confidence",
    "top_feature_1", "top_feature_2", "top_feature_3", "analyst_summary", "llm_enabled",
    "analyst_notes", "action_taken",
]


def append(detection: DetectionResponse) -> None:
    with _lock:
        _recent.appendleft(detection)
        top = detection.attributions[:3]
        top_names = [a.feature for a in top] + [""] * (3 - len(top))
        row = {
            "id": detection.id, "timestamp": detection.timestamp, "dataset": detection.dataset,
            "source_ip": detection.flow.source_ip if detection.flow else "",
            "destination_ip": detection.flow.destination_ip if detection.flow else "",
            "protocol": detection.flow.protocol if detection.flow else "",
            "dst_port": detection.flow.dst_port if detection.flow else "",
            "model": detection.model, "verdict": detection.verdict, "attack_family": detection.attack_family,
            "probability": detection.probability, "threshold": detection.threshold,
            "risk_score": detection.risk_score, "confidence": detection.confidence,
            "top_feature_1": top_names[0], "top_feature_2": top_names[1], "top_feature_3": top_names[2],
            "analyst_summary": detection.analyst_summary, "llm_enabled": detection.llm_enabled,
            "analyst_notes": "", "action_taken": "",
        }
        file_exists = THREAT_LOG_PATH.exists()
        with open(THREAT_LOG_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)


def recent(limit: int = 100, verdict: str | None = None, dataset: str | None = None,
           source: str | None = None) -> list[DetectionResponse]:
    with _lock:
        items = list(_recent)
    if verdict:
        items = [d for d in items if d.verdict == verdict]
    if dataset:
        items = [d for d in items if d.dataset == dataset]
    if source:
        items = [d for d in items if d.source == source]
    return items[:limit]


def stats() -> dict:
    with _lock:
        items = list(_recent)
    total = len(items)
    by_verdict = {"Benign": 0, "Suspicious": 0, "Attack": 0}
    by_protocol: dict[str, int] = {}
    top_sources: dict[str, int] = {}
    for d in items:
        by_verdict[d.verdict] = by_verdict.get(d.verdict, 0) + 1
        if d.flow:
            by_protocol[d.flow.protocol] = by_protocol.get(d.flow.protocol, 0) + 1
            top_sources[d.flow.source_ip] = top_sources.get(d.flow.source_ip, 0) + 1
    return {
        "total": total,
        "by_verdict": by_verdict,
        "by_protocol": by_protocol,
        "top_sources": sorted(top_sources.items(), key=lambda kv: kv[1], reverse=True)[:5],
    }
