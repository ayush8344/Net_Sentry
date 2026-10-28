from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from app import live
from app.live import FlowTracker


def _pkt(layer, ts):
    pkt = layer
    pkt.time = ts
    return pkt


def _tracker():
    flows = []
    return FlowTracker(flows.append), flows


def test_tcp_session_becomes_one_bidirectional_flow():
    tracker, flows = _tracker()
    c, s = "10.0.0.5", "93.184.216.34"
    tracker.add_packet(_pkt(IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="S"), 100.0))
    tracker.add_packet(_pkt(IP(src=s, dst=c) / TCP(sport=443, dport=50000, flags="SA"), 100.1))
    tracker.add_packet(_pkt(IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="A") / Raw(bytes(range(256))), 100.2))
    tracker.add_packet(_pkt(IP(src=c, dst=s) / TCP(sport=50000, dport=443, flags="FA"), 100.5))

    assert tracker.sweep(now=100.6) == 0  # still inside the FIN grace period
    assert tracker.sweep(now=102.0) == 1
    flow = flows[0]
    assert (flow.source_ip, flow.destination_ip, flow.dst_port, flow.protocol) == (c, s, 443, "TCP")
    assert (flow.fwd_packets, flow.bwd_packets) == (3, 1)
    assert flow.syn_count == 2 and flow.fin_count == 1 and flow.rst_count == 0
    assert flow.duration_ms == 500.0
    assert flow.payload_entropy == 8.0  # all 256 byte values once → maximal entropy
    assert tracker.active_flows == 0


def test_idle_flow_expires():
    tracker, flows = _tracker()
    tracker.add_packet(_pkt(IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / Raw(b"q"), 10.0))
    assert tracker.sweep(now=10.0 + live.IDLE_TIMEOUT_S - 0.1) == 0
    assert tracker.sweep(now=10.0 + live.IDLE_TIMEOUT_S) == 1
    assert flows[0].protocol == "UDP"


def test_port_scan_counts_unique_destination_ports():
    tracker, flows = _tracker()
    for i, port in enumerate(range(1000, 1040)):
        tracker.add_packet(_pkt(IP(src="10.0.0.66", dst="10.0.0.1") / TCP(sport=40000, dport=port, flags="S"), 50.0 + i * 0.01))
    tracker.sweep(flush=True, now=51.0)
    assert len(flows) == 40
    assert max(f.unique_dst_ports for f in flows) == 40


def test_vpn_port_is_flagged():
    tracker, flows = _tracker()
    tracker.add_packet(_pkt(IP(src="10.0.0.5", dst="1.2.3.4") / UDP(sport=40001, dport=51820), 1.0))
    tracker.sweep(flush=True, now=2.0)
    assert flows[0].is_vpn is True
