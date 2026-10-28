"""Feature engineering shared by training and inference.

Turns a raw flow record (either a `FlowFeatures` model or a mapped DataFrame
row with the same canonical columns) into the fixed-order numeric vector every
model in this project is trained and scored on. Keeping this in one place is
what lets `explain.py` attach human-readable feature names to SHAP values.
"""

from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .schemas import FlowFeatures

FEATURE_NAMES = [
    "duration_ms",
    "total_packets",
    "total_bytes",
    "bytes_per_sec",
    "packets_per_sec",
    "fwd_bwd_ratio",
    "packet_size_mean",
    "packet_size_std",
    "syn_count",
    "fin_count",
    "rst_count",
    "syn_flag_ratio",
    "unique_dst_ports",
    "payload_entropy",
    "is_vpn",
    "hour_sin",
    "hour_cos",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "port_well_known",
    "port_registered",
    "port_dynamic",
]


def _port_bin(port: int) -> tuple[int, int, int]:
    if port <= 1023:
        return (1, 0, 0)
    if port <= 49151:
        return (0, 1, 0)
    return (0, 0, 1)


def _row_to_vector(row: dict) -> list[float]:
    duration_ms = max(float(row["duration_ms"]), 1.0)
    fwd = float(row["fwd_packets"])
    bwd = float(row["bwd_packets"])
    total_packets = fwd + bwd
    total_bytes = float(row["total_bytes"])
    duration_s = duration_ms / 1000.0
    bytes_per_sec = total_bytes / duration_s
    packets_per_sec = total_packets / duration_s
    fwd_bwd_ratio = fwd / (bwd + 1.0)
    syn = float(row["syn_count"])
    fin = float(row["fin_count"])
    rst = float(row["rst_count"])
    syn_flag_ratio = syn / (total_packets + 1.0)
    hour = int(row["hour_of_day"])
    hour_sin = math.sin(2 * math.pi * hour / 24)
    hour_cos = math.cos(2 * math.pi * hour / 24)
    proto = str(row["protocol"]).upper()
    proto_tcp = 1.0 if proto == "TCP" else 0.0
    proto_udp = 1.0 if proto == "UDP" else 0.0
    proto_icmp = 1.0 if proto == "ICMP" else 0.0
    well_known, registered, dynamic = _port_bin(int(row["dst_port"]))

    return [
        duration_ms,
        total_packets,
        total_bytes,
        bytes_per_sec,
        packets_per_sec,
        fwd_bwd_ratio,
        float(row["packet_size_mean"]),
        float(row["packet_size_std"]),
        syn,
        fin,
        rst,
        syn_flag_ratio,
        float(row["unique_dst_ports"]),
        float(row["payload_entropy"]),
        1.0 if row["is_vpn"] else 0.0,
        hour_sin,
        hour_cos,
        proto_tcp,
        proto_udp,
        proto_icmp,
        float(well_known),
        float(registered),
        float(dynamic),
    ]


def engineer_one(flow: FlowFeatures) -> np.ndarray:
    return np.array(_row_to_vector(flow.model_dump()), dtype=float)


def engineer_frame(df: pd.DataFrame) -> pd.DataFrame:
    """`df` must already be in canonical column form (see data/loaders.py)."""
    vectors = [_row_to_vector(row) for row in df.to_dict(orient="records")]
    return pd.DataFrame(vectors, columns=FEATURE_NAMES, index=df.index)
