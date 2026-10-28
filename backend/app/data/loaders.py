"""Dataset loaders — one canonical schema, many sources.

`load_dataset(name)` looks for real CSVs dropped into `data_raw/<name>/`
first (mapping their headers heuristically, however they're spelled), and
falls back to the matching synthetic generator otherwise. This mirrors the
loader design described in the project write-up: CICIDS2018, ISCX-VPN2016,
and CAIDA all funnel through the same `map_flow_csv_columns` heuristic.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from ..config import DATA_RAW_DIR
from . import synthetic

CANONICAL_COLUMNS = [
    "source_ip", "destination_ip", "protocol", "src_port", "dst_port", "duration_ms",
    "fwd_packets", "bwd_packets", "total_bytes", "packet_size_mean", "packet_size_std",
    "syn_count", "fin_count", "rst_count", "unique_dst_ports", "payload_entropy",
    "is_vpn", "hour_of_day", "label",
]

# canonical field -> normalized (lowercase, no spaces/underscores) header synonyms
_SYNONYMS: dict[str, set[str]] = {
    "source_ip": {"srcip", "sourceip"},
    "destination_ip": {"dstip", "destinationip"},
    "protocol": {"protocol", "proto", "protocolname"},
    "src_port": {"srcport", "sourceport"},
    "dst_port": {"dstport", "destinationport"},
    "duration_ms": {"flowduration", "duration", "durms", "durationms"},
    "fwd_packets": {"totfwdpkts", "totalfwdpackets", "pktsfwd", "fwdpackets"},
    "bwd_packets": {"totbwdpkts", "totalbackwardpackets", "pktsbwd", "bwdpackets"},
    "total_bytes": {"totlenpkts", "totlenfwdpkts", "flowbytestotal", "bytestotal", "totalbytes"},
    "packet_size_mean": {"fwdpktlenmean", "packetlengthmean", "pktlenavg", "packetsizemean"},
    "packet_size_std": {"fwdpktlenstd", "packetlengthstd", "pktlenstd", "packetsizestd"},
    "syn_count": {"synflagcnt", "synflagcount", "syn"},
    "fin_count": {"finflagcnt", "finflagcount", "fin"},
    "rst_count": {"rstflagcnt", "rstflagcount", "rst"},
    "unique_dst_ports": {"uniqdstports", "uniqports", "uniquedstports"},
    "payload_entropy": {"payloadentropy", "entropy"},
    "is_vpn": {"isvpn", "vpnflag"},
    "hour_of_day": {"hour", "hourofday"},
    "label": {"label", "class", "attack"},
}

_DEFAULTS = {
    "source_ip": "0.0.0.0", "destination_ip": "0.0.0.0", "protocol": "TCP",
    "src_port": 0, "dst_port": 0, "duration_ms": 500.0, "fwd_packets": 1,
    "bwd_packets": 1, "total_bytes": 500.0, "packet_size_mean": 300.0,
    "packet_size_std": 50.0, "syn_count": 0, "fin_count": 0, "rst_count": 0,
    "unique_dst_ports": 1, "payload_entropy": 6.0, "is_vpn": False,
    "hour_of_day": 12, "label": None,
}


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def map_flow_csv_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Heuristically rename whatever headers a source dataset ships with onto
    the canonical schema every downstream module (features/clustering/models)
    expects."""
    normalized_lookup = {_normalize(c): c for c in df.columns}
    rename: dict[str, str] = {}
    for canonical, synonyms in _SYNONYMS.items():
        for norm_col, original_col in normalized_lookup.items():
            if norm_col in synonyms:
                rename[original_col] = canonical
                break

    mapped = df.rename(columns=rename)
    out = pd.DataFrame(index=mapped.index)
    for col in CANONICAL_COLUMNS:
        if col in mapped.columns:
            out[col] = mapped[col]
        else:
            out[col] = _DEFAULTS[col]

    out["protocol"] = out["protocol"].astype(str).str.upper().replace({"NAN": "TCP"})
    out.loc[~out["protocol"].isin(["TCP", "UDP", "ICMP"]), "protocol"] = "TCP"
    for col in ["src_port", "dst_port", "fwd_packets", "bwd_packets", "syn_count",
                "fin_count", "rst_count", "unique_dst_ports", "hour_of_day"]:
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(_DEFAULTS[col]).astype(int)
    for col in ["duration_ms", "total_bytes", "packet_size_mean", "packet_size_std", "payload_entropy"]:
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(_DEFAULTS[col]).astype(float)
    out["is_vpn"] = out["is_vpn"].astype(bool)
    out["destination_ip"] = out["destination_ip"].fillna("REDACTED").astype(str)
    out["source_ip"] = out["source_ip"].fillna("REDACTED").astype(str)
    return out


def _load_real_csvs(dataset: str) -> pd.DataFrame | None:
    folder = DATA_RAW_DIR / dataset
    csv_files = sorted(Path(folder).glob("*.csv")) if folder.exists() else []
    if not csv_files:
        return None
    frames = [pd.read_csv(f, low_memory=False) for f in csv_files]
    raw = pd.concat(frames, ignore_index=True)
    return map_flow_csv_columns(raw)


def load_sample_dataset(n: int = 1200, seed: int = 1) -> pd.DataFrame:
    return map_flow_csv_columns(synthetic.generate_sample(n, seed))


def load_cicids2018(n: int = 6000, seed: int = 42) -> pd.DataFrame:
    real = _load_real_csvs("cicids2018")
    if real is not None:
        return real
    return map_flow_csv_columns(synthetic.generate_cicids2018(n, seed))


def load_iscx_vpn(n: int = 3000, seed: int = 7) -> pd.DataFrame:
    real = _load_real_csvs("iscx_vpn")
    if real is not None:
        return real
    return map_flow_csv_columns(synthetic.generate_iscx_vpn(n, seed))


def load_caida(n: int = 2500, seed: int = 99) -> pd.DataFrame:
    real = _load_real_csvs("caida")
    if real is not None:
        return real
    return map_flow_csv_columns(synthetic.generate_caida(n, seed))


_LOADERS = {
    "sample": load_sample_dataset,
    "cicids2018": load_cicids2018,
    "iscx_vpn": load_iscx_vpn,
    "caida": load_caida,
}


def load_dataset(name: str, **kwargs) -> pd.DataFrame:
    if name not in _LOADERS:
        raise ValueError(f"Unknown dataset '{name}'. Expected one of {list(_LOADERS)}.")
    return _LOADERS[name](**kwargs)


def is_using_real_data(name: str) -> bool:
    folder = DATA_RAW_DIR / name
    return folder.exists() and any(folder.glob("*.csv"))
