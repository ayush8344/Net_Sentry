"""Explainability layer — SHAP TreeExplainer over RadiantBoost's underlying
Gradient Boosting tree structure.

Neither a raw probability score nor a packet capture tells an analyst *why*
a flow was flagged. `shap.TreeExplainer` computes exact Shapley values for
tree ensembles: each feature gets a signed contribution toward "malicious"
vs. "benign" for one specific flow (local), or averaged across a sample to
show what the model relies on in general (global).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import shap

from .features import FEATURE_NAMES
from .models.radiant_boost import RadiantBoost
from .schemas import Attribution

FEATURE_DESCRIPTIONS = {
    "duration_ms": "Flow duration — very short or unusually long flows deviate from typical session behavior.",
    "total_packets": "Total packet count for the flow.",
    "total_bytes": "Total bytes transferred; unusually large transfers can indicate exfiltration or flooding.",
    "bytes_per_sec": "Sustained high byte rate is unusual for most legitimate flow profiles.",
    "packets_per_sec": "High packet rate is characteristic of scanning or flooding behavior.",
    "fwd_bwd_ratio": "A lopsided forward/backward packet ratio suggests one-directional (scan or flood) traffic.",
    "packet_size_mean": "Average packet size; very small, uniform packets are typical of scans or floods.",
    "packet_size_std": "Packet size variance; low variance suggests automated/scripted traffic.",
    "syn_count": "SYN packet count — elevated values are a classic scan or SYN-flood signal.",
    "fin_count": "FIN packet count relative to the flow's normal teardown behavior.",
    "rst_count": "Reset count — frequent resets can indicate probing or failed brute-force attempts.",
    "syn_flag_ratio": "Share of packets that are SYNs; high ratios point to scanning/flooding.",
    "unique_dst_ports": "Distinct destination ports contacted — high values are a strong port-scan signal.",
    "payload_entropy": "Payload randomness; high entropy is typical of encrypted C2 or tunneled traffic.",
    "is_vpn": "Whether the flow traversed a known VPN/tunnel interface.",
    "hour_sin": "Cyclical encoding of time of day.",
    "hour_cos": "Cyclical encoding of time of day.",
    "proto_tcp": "Transport protocol is TCP.",
    "proto_udp": "Transport protocol is UDP.",
    "proto_icmp": "Transport protocol is ICMP.",
    "port_well_known": "Destination port is in the well-known range (<=1023).",
    "port_registered": "Destination port is in the registered range.",
    "port_dynamic": "Destination port is in the dynamic/ephemeral range.",
}


class RadiantBoostExplainer:
    def __init__(self, model: RadiantBoost) -> None:
        self.model = model
        raw_gb = model.raw_gb_estimator()
        self.explainer = shap.TreeExplainer(raw_gb)

    def _shap_values(self, X: np.ndarray) -> np.ndarray:
        raw = self.explainer.shap_values(X)
        values = raw[1] if isinstance(raw, list) else raw
        return np.asarray(values)

    def global_importance(self, X_sample: np.ndarray) -> list[dict]:
        values = self._shap_values(X_sample)
        mean_abs = np.abs(values).mean(axis=0)
        ranked = sorted(zip(FEATURE_NAMES, mean_abs), key=lambda kv: kv[1], reverse=True)
        return [{"feature": f, "mean_abs_shap": round(float(v), 4)} for f, v in ranked]

    def local_attributions(self, x_row: np.ndarray, raw_values: dict[str, str]) -> list[Attribution]:
        values = self._shap_values(x_row.reshape(1, -1))[0]
        attributions = []
        for feature, contribution in zip(FEATURE_NAMES, values):
            attributions.append(Attribution(
                feature=feature,
                value=raw_values.get(feature, ""),
                contribution=round(float(contribution), 4),
                direction="risk" if contribution >= 0 else "benign",
                description=FEATURE_DESCRIPTIONS.get(feature, ""),
            ))
        return sorted(attributions, key=lambda a: abs(a.contribution), reverse=True)


def readable_feature_values(vector: np.ndarray) -> dict[str, str]:
    return {name: f"{value:.2f}" for name, value in zip(FEATURE_NAMES, vector)}


def infer_attack_family(feature_values: dict[str, float], verdict: str) -> str:
    """Attack-family labeling is a separate, simpler concern from SHAP
    explanation: it applies domain thresholds directly to the engineered
    feature values, independent of each feature's *relative* SHAP
    magnitude (which is dominated by packet_size_mean/payload_entropy
    globally and would otherwise mask a clear port-scan or brute-force
    signal further down the ranking)."""
    if verdict == "Benign":
        return "Expected traffic"

    v = feature_values
    if v.get("unique_dst_ports", 0) >= 10:
        return "Port Scan"
    if v.get("syn_flag_ratio", 0) > 0.5 or v.get("packets_per_sec", 0) > 500:
        return "DoS / Flood"
    if (v.get("rst_count", 0) > 3 or v.get("syn_count", 0) > 5) and v.get("port_dynamic", 0) < 1:
        return "Brute Force"
    if v.get("payload_entropy", 0) > 7.2 and v.get("port_dynamic", 0) >= 1:
        return "Command & Control Beacon"
    if v.get("payload_entropy", 0) > 7.0:
        return "Encrypted / Tunneled Traffic"
    return "Anomalous Traffic" if verdict == "Attack" else "Low-confidence Anomaly"
