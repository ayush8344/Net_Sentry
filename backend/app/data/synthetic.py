"""Synthetic flow generators.

The real CICIDS2018, CAIDA, and ISCX-VPN2016 datasets are gated (signed data
requests / multi-GB downloads) and are not bundled here. These generators
produce flow-level records with the *native column names and realistic
per-class statistics* of each benchmark, so the rest of the pipeline
(loading -> column mapping -> feature engineering -> training -> clustering
-> SHAP -> LLM narrative) is fully exercised end to end without them.

Drop real exported CSVs (or CAIDA pcap-derived flow CSVs) into
`backend/data_raw/<dataset>/` and `loaders.load_dataset()` will use those
instead automatically, via the same heuristic column mapper.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

WELL_KNOWN_PORTS = [80, 443, 53, 22, 25, 110, 143]
DYNAMIC_PORTS = list(range(49152, 65535))


def _rng(seed: int) -> np.random.Generator:
    return np.random.default_rng(seed)


def _base_ip(rng: np.random.Generator, n: int, octet3_range=(0, 255)) -> np.ndarray:
    return np.array(
        [f"10.{rng.integers(0, 255)}.{rng.integers(*octet3_range)}.{rng.integers(1, 254)}" for _ in range(n)]
    )


def _class_block(rng: np.random.Generator, n: int, **dists) -> pd.DataFrame:
    return pd.DataFrame({k: v(rng, n) for k, v in dists.items()})


def _inject_label_noise(df: pd.DataFrame, label_col: str, rng: np.random.Generator, rate: float = 0.035) -> pd.DataFrame:
    """Real annotation pipelines mislabel a small fraction of flows. Without
    this, the clean-room class boundaries below make the classifiers look
    unrealistically perfect (ROC-AUC = 1.0). Relabeling a few rows without
    touching their underlying feature values caps achievable accuracy at a
    believable ceiling and gives SHAP genuinely borderline cases to explain."""
    labels = df[label_col].unique().tolist()
    n_flip = int(len(df) * rate)
    flip_idx = rng.choice(df.index, size=n_flip, replace=False)
    for idx in flip_idx:
        current = df.at[idx, label_col]
        alternatives = [l for l in labels if l != current]
        df.at[idx, label_col] = rng.choice(alternatives)
    return df


def generate_cicids2018(n: int = 6000, seed: int = 42) -> pd.DataFrame:
    rng = _rng(seed)
    weights = {"BENIGN": 0.68, "DoS": 0.11, "PortScan": 0.09, "BruteForce": 0.07, "Bot": 0.05}
    labels = rng.choice(list(weights.keys()), size=n, p=list(weights.values()))
    rows = []
    for label in labels:
        if label == "BENIGN":
            row = dict(
                duration=rng.uniform(50, 3000), fwd=rng.integers(4, 60), bwd=rng.integers(4, 60),
                bytes_total=rng.uniform(2_000, 60_000), pktlen_mean=rng.uniform(300, 650),
                pktlen_std=rng.uniform(40, 140), syn=rng.integers(0, 2), fin=rng.integers(0, 2),
                rst=0, uniq_ports=rng.integers(1, 3), entropy=rng.uniform(5.2, 6.9),
                dstport=int(rng.choice(WELL_KNOWN_PORTS)), proto="TCP" if rng.random() < 0.85 else "UDP",
            )
        elif label == "DoS":
            row = dict(
                duration=rng.uniform(200, 4000), fwd=rng.integers(400, 4000), bwd=rng.integers(0, 40),
                bytes_total=rng.uniform(80_000, 900_000), pktlen_mean=rng.uniform(60, 200),
                pktlen_std=rng.uniform(5, 30), syn=rng.integers(200, 3000), fin=0,
                rst=rng.integers(0, 50), uniq_ports=1, entropy=rng.uniform(3.0, 5.0),
                dstport=int(rng.choice([80, 443, 8080])), proto="TCP",
            )
        elif label == "PortScan":
            row = dict(
                duration=rng.uniform(10, 400), fwd=rng.integers(1, 4), bwd=rng.integers(0, 2),
                bytes_total=rng.uniform(40, 400), pktlen_mean=rng.uniform(40, 90),
                pktlen_std=rng.uniform(2, 15), syn=rng.integers(1, 3), fin=0,
                rst=rng.integers(0, 2), uniq_ports=rng.integers(15, 80), entropy=rng.uniform(2.0, 4.0),
                dstport=int(rng.integers(1, 65535)), proto="TCP",
            )
        elif label == "BruteForce":
            row = dict(
                duration=rng.uniform(300, 6000), fwd=rng.integers(20, 150), bwd=rng.integers(20, 150),
                bytes_total=rng.uniform(4_000, 40_000), pktlen_mean=rng.uniform(80, 220),
                pktlen_std=rng.uniform(10, 50), syn=rng.integers(10, 120), fin=rng.integers(0, 5),
                rst=rng.integers(5, 90), uniq_ports=1, entropy=rng.uniform(4.0, 5.8),
                dstport=int(rng.choice([22, 21, 23, 3389])), proto="TCP",
            )
        else:  # Bot / C2
            row = dict(
                duration=rng.uniform(1000, 20000), fwd=rng.integers(3, 30), bwd=rng.integers(3, 30),
                bytes_total=rng.uniform(500, 6_000), pktlen_mean=rng.uniform(90, 260),
                pktlen_std=rng.uniform(60, 180), syn=rng.integers(0, 3), fin=rng.integers(0, 2),
                rst=rng.integers(0, 3), uniq_ports=rng.integers(1, 5), entropy=rng.uniform(7.2, 7.98),
                dstport=int(rng.choice(DYNAMIC_PORTS)), proto="TCP" if rng.random() < 0.7 else "UDP",
            )
        row["Label"] = label
        rows.append(row)

    df = pd.DataFrame(rows)
    df["Src IP"] = _base_ip(rng, n)
    df["Dst IP"] = _base_ip(rng, n)
    # A slice of CICIDS2018 ships with anonymized victim IPs — mirror that.
    anon_mask = rng.random(n) < 0.08
    df.loc[anon_mask, "Dst IP"] = "REDACTED"
    df["Src Port"] = rng.integers(1024, 65535, size=n)
    df["Uniq Dst Ports"] = df.pop("uniq_ports")
    df["Payload Entropy"] = df.pop("entropy")
    df["Is VPN"] = False
    df["Hour"] = rng.integers(0, 24, size=n)
    df = _inject_label_noise(df, "Label", rng)
    return df.rename(columns={
        "duration": "Flow Duration", "fwd": "Tot Fwd Pkts", "bwd": "Tot Bwd Pkts",
        "bytes_total": "TotLen Pkts", "pktlen_mean": "Fwd Pkt Len Mean", "pktlen_std": "Fwd Pkt Len Std",
        "syn": "SYN Flag Cnt", "fin": "FIN Flag Cnt", "rst": "RST Flag Cnt",
        "dstport": "Dst Port", "proto": "Protocol",
    })


def generate_iscx_vpn(n: int = 3000, seed: int = 7) -> pd.DataFrame:
    rng = _rng(seed)
    is_vpn = rng.random(n) < 0.35
    rows = []
    for vpn in is_vpn:
        if vpn:
            row = dict(
                duration=rng.uniform(2000, 60000), total_fwd_packets=rng.integers(50, 900),
                total_backward_packets=rng.integers(50, 900), flow_bytes_total=rng.uniform(20_000, 500_000),
                packet_length_mean=rng.uniform(200, 500), packet_length_std=rng.uniform(5, 25),
                syn_flag_count=rng.integers(0, 2), fin_flag_count=rng.integers(0, 2), rst_flag_count=0,
                uniq_dst_ports=rng.integers(1, 3), entropy=rng.uniform(7.3, 7.99),
                destination_port=int(rng.choice([443, 1194, 500, 4500])), protocol_name="UDP" if rng.random() < 0.6 else "TCP",
            )
        else:
            row = dict(
                duration=rng.uniform(50, 4000), total_fwd_packets=rng.integers(4, 80),
                total_backward_packets=rng.integers(4, 80), flow_bytes_total=rng.uniform(1_000, 60_000),
                packet_length_mean=rng.uniform(250, 700), packet_length_std=rng.uniform(60, 220),
                syn_flag_count=rng.integers(0, 2), fin_flag_count=rng.integers(0, 2), rst_flag_count=0,
                uniq_dst_ports=rng.integers(1, 4), entropy=rng.uniform(4.5, 6.8),
                destination_port=int(rng.choice(WELL_KNOWN_PORTS)), protocol_name="TCP" if rng.random() < 0.85 else "UDP",
            )
        row["label"] = "VPN" if vpn else "NonVPN"
        rows.append(row)

    df = pd.DataFrame(rows)
    df["src_ip"] = _base_ip(rng, n)
    df["dst_ip"] = _base_ip(rng, n)
    df["source_port"] = rng.integers(1024, 65535, size=n)
    df["hour_of_day"] = rng.integers(0, 24, size=n)
    # The VPN flag itself is the label for this profile — never expose it as an
    # input feature, or the classifier would just read the answer back out.
    df["vpn_flag"] = False
    df = _inject_label_noise(df, "label", rng)
    return df


def generate_caida(n: int = 2500, seed: int = 99) -> pd.DataFrame:
    rng = _rng(seed)
    anomalous = rng.random(n) < 0.06
    rows = []
    for anom in anomalous:
        if anom:
            row = dict(
                dur_ms=rng.uniform(20, 500), pkts_fwd=rng.integers(300, 5000), pkts_bwd=rng.integers(0, 30),
                bytes_total=rng.uniform(50_000, 700_000), pktlen_avg=rng.uniform(40, 120),
                pktlen_std=rng.uniform(5, 25), syn=rng.integers(100, 2000), fin=0, rst=rng.integers(0, 40),
                srcport=int(rng.integers(1024, 65535)), dstport=int(rng.choice([80, 443, 53])), proto="TCP",
            )
        else:
            row = dict(
                dur_ms=rng.uniform(20, 5000), pkts_fwd=rng.integers(1, 200), pkts_bwd=rng.integers(1, 200),
                bytes_total=rng.uniform(200, 90_000), pktlen_avg=rng.uniform(80, 900),
                pktlen_std=rng.uniform(10, 300), syn=rng.integers(0, 3), fin=rng.integers(0, 2),
                rst=rng.integers(0, 2), srcport=int(rng.integers(1024, 65535)),
                dstport=int(rng.choice(WELL_KNOWN_PORTS + DYNAMIC_PORTS[:20])), proto=rng.choice(["TCP", "UDP", "ICMP"]),
            )
        rows.append(row)

    df = pd.DataFrame(rows)
    df["srcip"] = _base_ip(rng, n)
    df["dstip"] = _base_ip(rng, n)
    df["uniqports"] = rng.integers(1, 6, size=n)
    df["hour"] = rng.integers(0, 24, size=n)
    # CAIDA backbone captures ship with no attack labels at all.
    return df


def generate_sample(n: int = 1200, seed: int = 1) -> pd.DataFrame:
    """Already in canonical column form — used for `load_sample_dataset()`."""
    rng = _rng(seed)
    weights = {"BENIGN": 0.75, "DoS": 0.08, "PortScan": 0.09, "BruteForce": 0.05, "Bot": 0.03}
    labels = rng.choice(list(weights.keys()), size=n, p=list(weights.values()))
    rows = []
    for label in labels:
        if label == "BENIGN":
            row = dict(duration_ms=rng.uniform(50, 3000), fwd_packets=rng.integers(4, 60), bwd_packets=rng.integers(4, 60),
                       total_bytes=rng.uniform(2_000, 60_000), packet_size_mean=rng.uniform(300, 650),
                       packet_size_std=rng.uniform(40, 140), syn_count=rng.integers(0, 2), fin_count=rng.integers(0, 2),
                       rst_count=0, unique_dst_ports=rng.integers(1, 3), payload_entropy=rng.uniform(5.2, 6.9),
                       dst_port=int(rng.choice(WELL_KNOWN_PORTS)), protocol="TCP", is_vpn=False)
        elif label == "DoS":
            row = dict(duration_ms=rng.uniform(200, 4000), fwd_packets=rng.integers(400, 4000), bwd_packets=rng.integers(0, 40),
                       total_bytes=rng.uniform(80_000, 900_000), packet_size_mean=rng.uniform(60, 200),
                       packet_size_std=rng.uniform(5, 30), syn_count=rng.integers(200, 3000), fin_count=0,
                       rst_count=rng.integers(0, 50), unique_dst_ports=1, payload_entropy=rng.uniform(3.0, 5.0),
                       dst_port=int(rng.choice([80, 443, 8080])), protocol="TCP", is_vpn=False)
        elif label == "PortScan":
            row = dict(duration_ms=rng.uniform(10, 400), fwd_packets=rng.integers(1, 4), bwd_packets=rng.integers(0, 2),
                       total_bytes=rng.uniform(40, 400), packet_size_mean=rng.uniform(40, 90),
                       packet_size_std=rng.uniform(2, 15), syn_count=rng.integers(1, 3), fin_count=0,
                       rst_count=rng.integers(0, 2), unique_dst_ports=rng.integers(15, 80), payload_entropy=rng.uniform(2.0, 4.0),
                       dst_port=int(rng.integers(1, 65535)), protocol="TCP", is_vpn=False)
        elif label == "BruteForce":
            row = dict(duration_ms=rng.uniform(300, 6000), fwd_packets=rng.integers(20, 150), bwd_packets=rng.integers(20, 150),
                       total_bytes=rng.uniform(4_000, 40_000), packet_size_mean=rng.uniform(80, 220),
                       packet_size_std=rng.uniform(10, 50), syn_count=rng.integers(10, 120), fin_count=rng.integers(0, 5),
                       rst_count=rng.integers(5, 90), unique_dst_ports=1, payload_entropy=rng.uniform(4.0, 5.8),
                       dst_port=int(rng.choice([22, 21, 23, 3389])), protocol="TCP", is_vpn=False)
        else:
            row = dict(duration_ms=rng.uniform(1000, 20000), fwd_packets=rng.integers(3, 30), bwd_packets=rng.integers(3, 30),
                       total_bytes=rng.uniform(500, 6_000), packet_size_mean=rng.uniform(90, 260),
                       packet_size_std=rng.uniform(60, 180), syn_count=rng.integers(0, 3), fin_count=rng.integers(0, 2),
                       rst_count=rng.integers(0, 3), unique_dst_ports=rng.integers(1, 5), payload_entropy=rng.uniform(7.2, 7.98),
                       dst_port=int(rng.choice(DYNAMIC_PORTS)), protocol="TCP", is_vpn=bool(rng.random() < 0.3))
        row["label"] = label
        rows.append(row)

    df = pd.DataFrame(rows)
    df["source_ip"] = _base_ip(rng, n)
    df["destination_ip"] = _base_ip(rng, n)
    df["src_port"] = rng.integers(1024, 65535, size=n)
    df["hour_of_day"] = rng.integers(0, 24, size=n)
    df = _inject_label_noise(df, "label", rng)
    return df
