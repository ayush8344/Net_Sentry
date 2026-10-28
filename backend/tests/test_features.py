import numpy as np

from app.data import loaders
from app.explain import infer_attack_family
from app.features import FEATURE_NAMES, engineer_frame, engineer_one
from app.schemas import FlowFeatures


def test_engineer_one_matches_feature_names_length():
    vector = engineer_one(FlowFeatures())
    assert vector.shape == (len(FEATURE_NAMES),)
    assert np.all(np.isfinite(vector))


def test_engineer_frame_matches_engineer_one_row_by_row():
    df = loaders.load_sample_dataset(n=25)
    frame_vectors = engineer_frame(df).values
    for i, row in enumerate(df.to_dict(orient="records")):
        flow = FlowFeatures(
            source_ip=row["source_ip"], destination_ip=row["destination_ip"], protocol=row["protocol"],
            src_port=row["src_port"], dst_port=row["dst_port"], duration_ms=row["duration_ms"],
            fwd_packets=row["fwd_packets"], bwd_packets=row["bwd_packets"], total_bytes=row["total_bytes"],
            packet_size_mean=row["packet_size_mean"], packet_size_std=row["packet_size_std"],
            syn_count=row["syn_count"], fin_count=row["fin_count"], rst_count=row["rst_count"],
            unique_dst_ports=row["unique_dst_ports"], payload_entropy=row["payload_entropy"],
            is_vpn=bool(row["is_vpn"]), hour_of_day=row["hour_of_day"],
        )
        single = engineer_one(flow)
        assert np.allclose(frame_vectors[i], single), f"row {i} mismatch between engineer_frame and engineer_one"


def test_port_binning_is_mutually_exclusive():
    for port, expected_index in [(80, 20), (8080, 21), (60000, 22)]:
        flow = FlowFeatures(dst_port=port)
        vector = engineer_one(flow)
        bins = vector[20:23]
        assert bins.sum() == 1.0
        assert bins[expected_index - 20] == 1.0


def test_attack_family_rules_are_mutually_sensible():
    feature_values = dict.fromkeys(FEATURE_NAMES, 0.0)

    scan = {**feature_values, "unique_dst_ports": 40}
    assert infer_attack_family(scan, "Attack") == "Port Scan"

    flood = {**feature_values, "syn_flag_ratio": 0.8}
    assert infer_attack_family(flood, "Attack") == "DoS / Flood"

    brute = {**feature_values, "rst_count": 10, "port_dynamic": 0}
    assert infer_attack_family(brute, "Attack") == "Brute Force"

    beacon = {**feature_values, "payload_entropy": 7.5, "port_dynamic": 1}
    assert infer_attack_family(beacon, "Attack") == "Command & Control Beacon"

    assert infer_attack_family(feature_values, "Benign") == "Expected traffic"
