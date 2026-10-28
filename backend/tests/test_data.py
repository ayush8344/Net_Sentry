import pandas as pd

from app.data import loaders
from app.data.loaders import CANONICAL_COLUMNS, map_flow_csv_columns


def test_canonical_columns_present_for_every_profile():
    for name in ["sample", "cicids2018", "iscx_vpn", "caida"]:
        df = loaders.load_dataset(name, n=50)
        assert list(df.columns) == CANONICAL_COLUMNS
        assert len(df) == 50


def test_column_mapper_is_heuristic_and_case_insensitive():
    raw = pd.DataFrame({
        "Dst Port": [443, 22],
        "PROTOCOL": ["tcp", "udp"],
        "Flow Duration": [100.0, 5000.0],
        "Tot Fwd Pkts": [10, 200],
        "Tot Bwd Pkts": [8, 0],
    })
    mapped = map_flow_csv_columns(raw)
    assert list(mapped["dst_port"]) == [443, 22]
    assert list(mapped["protocol"]) == ["TCP", "UDP"]
    assert list(mapped["fwd_packets"]) == [10, 200]


def test_column_mapper_fills_missing_columns_with_defaults():
    raw = pd.DataFrame({"dst_port": [80]})
    mapped = map_flow_csv_columns(raw)
    assert mapped.loc[0, "protocol"] == "TCP"
    assert mapped.loc[0, "unique_dst_ports"] == 1
    assert mapped.loc[0, "is_vpn"] == False  # noqa: E712


def test_iscx_vpn_never_leaks_is_vpn_as_a_feature():
    df = loaders.load_iscx_vpn(n=200)
    assert not df["is_vpn"].any(), "is_vpn must stay False for iscx_vpn rows — it's the label, not a feature"
    assert set(df["label"].unique()) <= {"VPN", "NonVPN"}


def test_caida_has_no_labels():
    df = loaders.load_caida(n=100)
    assert df["label"].isna().all()
