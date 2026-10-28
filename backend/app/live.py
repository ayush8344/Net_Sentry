"""Real-time capture layer — sniffs packets off the local network interface with
scapy, groups them into bidirectional flows, and hands each finished flow to
the detector as a `FlowFeatures` record (the same schema the Detect page and
batch CSV upload use).

A flow is keyed on its 5-tuple and ends when it goes idle, runs past the
active timeout, or closes with FIN/RST. `unique_dst_ports` is computed per
source IP over a sliding window, which is what makes port scans visible.

Capture backends, tried in order:
  1. Npcap/libpcap (layer 2) — the normal path; needs Npcap on Windows.
  2. Windows native raw socket (layer 3, IPv4 only) — no driver needed, but
     the backend must run from an Administrator terminal.
"""

from __future__ import annotations

import math
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .schemas import FlowFeatures

IDLE_TIMEOUT_S = 5.0
ACTIVE_TIMEOUT_S = 30.0
CLOSE_GRACE_S = 1.0
PORT_WINDOW_S = 60.0
SWEEP_INTERVAL_S = 1.0
MAX_ACTIVE_FLOWS = 10_000
ENTROPY_SAMPLE_BYTES = 4096

TCP_FIN, TCP_SYN, TCP_RST = 0x01, 0x02, 0x04
VPN_PORTS = {("UDP", 1194), ("UDP", 51820), ("UDP", 500), ("UDP", 4500), ("TCP", 1194), ("TCP", 1723)}

INSTALL_HINT = (
    "Live capture needs packet-capture access. Either install Npcap from https://npcap.com "
    "(tick 'Install Npcap in WinPcap API-compatible mode') and restart the backend, or start "
    "the backend from an Administrator terminal."
)


class LiveCaptureError(RuntimeError):
    pass


@dataclass
class _Flow:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    first_seen: float
    last_seen: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    total_bytes: int = 0
    size_sum: float = 0.0
    size_sq_sum: float = 0.0
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    payload: bytearray = field(default_factory=bytearray)
    closing_at: float | None = None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _parse(pkt) -> tuple | None:
    """Returns (src, dst, protocol, sport, dport, size, tcp_flags, payload) or None."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    if IP in pkt:
        ip = pkt[IP]
        proto_num = ip.proto
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        proto_num = ip.nh
    else:
        return None

    if TCP in pkt:
        l4 = pkt[TCP]
        return ip.src, ip.dst, "TCP", l4.sport, l4.dport, len(ip), int(l4.flags), bytes(l4.payload)
    if UDP in pkt:
        l4 = pkt[UDP]
        return ip.src, ip.dst, "UDP", l4.sport, l4.dport, len(ip), 0, bytes(l4.payload)
    if proto_num in (1, 58):  # ICMP / ICMPv6
        return ip.src, ip.dst, "ICMP", 0, 0, len(ip), 0, bytes(ip.payload)
    return None


class FlowTracker:
    """Packet → flow aggregation. Thread-safe; timestamps come from the packets
    themselves so it can be driven deterministically in tests."""

    def __init__(self, on_flow: Callable[[FlowFeatures], None]):
        self._on_flow = on_flow
        self._lock = threading.Lock()
        self._flows: dict[tuple, _Flow] = {}
        self._ports_by_src: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.packets_seen = 0
        self.flows_emitted = 0
        self.flows_dropped = 0

    @property
    def active_flows(self) -> int:
        with self._lock:
            return len(self._flows)

    def add_packet(self, pkt) -> None:
        parsed = _parse(pkt)
        if parsed is None:
            return
        src, dst, protocol, sport, dport, size, flags, payload = parsed
        ts = float(pkt.time)

        with self._lock:
            self.packets_seen += 1
            key = (src, sport, dst, dport, protocol)
            reverse = (dst, dport, src, sport, protocol)
            if key in self._flows:
                flow, forward = self._flows[key], True
            elif reverse in self._flows:
                flow, forward = self._flows[reverse], False
            else:
                if len(self._flows) >= MAX_ACTIVE_FLOWS:
                    self.flows_dropped += 1
                    return
                flow = _Flow(src, dst, protocol, sport, dport, first_seen=ts, last_seen=ts)
                self._flows[key] = flow
                forward = True
                self._ports_by_src[src].append((ts, dport))

            flow.last_seen = max(flow.last_seen, ts)
            if forward:
                flow.fwd_packets += 1
            else:
                flow.bwd_packets += 1
            flow.total_bytes += size
            flow.size_sum += size
            flow.size_sq_sum += size * size
            if flags & TCP_SYN:
                flow.syn_count += 1
            if flags & TCP_FIN:
                flow.fin_count += 1
            if flags & TCP_RST:
                flow.rst_count += 1
            if flags & (TCP_FIN | TCP_RST) and flow.closing_at is None:
                flow.closing_at = ts
            room = ENTROPY_SAMPLE_BYTES - len(flow.payload)
            if room > 0 and payload:
                flow.payload.extend(payload[:room])

    def sweep(self, now: float | None = None, flush: bool = False) -> int:
        """Emits every flow that has finished as of `now` (or all of them if `flush`)."""
        now = time.time() if now is None else now
        finished: list[FlowFeatures] = []
        with self._lock:
            for key, flow in list(self._flows.items()):
                done = (
                    flush
                    or now - flow.last_seen >= IDLE_TIMEOUT_S
                    or now - flow.first_seen >= ACTIVE_TIMEOUT_S
                    or (flow.closing_at is not None and now - flow.closing_at >= CLOSE_GRACE_S)
                )
                if done:
                    del self._flows[key]
                    finished.append(self._to_features(flow, now))
            self._prune_port_windows(now)
            self.flows_emitted += len(finished)

        for features in finished:
            self._on_flow(features)
        return len(finished)

    def _prune_port_windows(self, now: float) -> None:
        for src in list(self._ports_by_src):
            window = self._ports_by_src[src]
            while window and now - window[0][0] > PORT_WINDOW_S:
                window.popleft()
            if not window:
                del self._ports_by_src[src]

    def _to_features(self, flow: _Flow, now: float) -> FlowFeatures:
        packets = flow.fwd_packets + flow.bwd_packets
        mean = flow.size_sum / packets
        std = math.sqrt(max(0.0, flow.size_sq_sum / packets - mean * mean))
        unique_ports = {port for ts, port in self._ports_by_src.get(flow.src_ip, ())
                        if now - ts <= PORT_WINDOW_S} | {flow.dst_port}
        is_vpn = (flow.protocol, flow.dst_port) in VPN_PORTS or (flow.protocol, flow.src_port) in VPN_PORTS
        return FlowFeatures(
            source_ip=flow.src_ip, destination_ip=flow.dst_ip, protocol=flow.protocol,
            src_port=flow.src_port, dst_port=flow.dst_port,
            duration_ms=round((flow.last_seen - flow.first_seen) * 1000, 3),
            fwd_packets=flow.fwd_packets, bwd_packets=flow.bwd_packets,
            total_bytes=flow.total_bytes, packet_size_mean=round(mean, 2), packet_size_std=round(std, 2),
            syn_count=flow.syn_count, fin_count=flow.fin_count, rst_count=flow.rst_count,
            unique_dst_ports=len(unique_ports),
            payload_entropy=round(min(8.0, _entropy(bytes(flow.payload))), 3),
            is_vpn=is_vpn, hour_of_day=time.localtime(flow.first_seen).tm_hour,
        )


class LiveCapture:
    """Owns the sniffer + sweeper threads. One instance per process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sniffer = None
        self._sweeper: threading.Thread | None = None
        self._stop = threading.Event()
        self._tracker: FlowTracker | None = None
        self.method: str | None = None
        self.interface: str | None = None
        self.started_at: str | None = None
        self.error: str | None = None

    @property
    def running(self) -> bool:
        return self._sniffer is not None

    def _open_socket(self):
        from scapy.config import conf

        if conf.use_pcap:
            try:
                sock = conf.L2listen(iface=conf.iface, filter="ip or ip6")
                return sock, "Npcap (layer 2)", str(conf.iface)
            except Exception as exc:
                raise LiveCaptureError(f"Npcap is installed but capture failed to open: {exc}") from exc
        try:
            sock = conf.L3socket(promisc=True)
            return sock, "Windows raw socket (layer 3, IPv4)", str(conf.iface)
        except Exception as exc:
            raise LiveCaptureError(f"{INSTALL_HINT} (Details: {exc})") from exc

    def start(self, on_flow: Callable[[FlowFeatures], None]) -> None:
        from scapy.sendrecv import AsyncSniffer

        with self._lock:
            if self.running:
                return
            sock, self.method, self.interface = self._open_socket()
            self._tracker = FlowTracker(on_flow)
            self._stop.clear()
            self._sniffer = AsyncSniffer(opened_socket=sock, prn=self._tracker.add_packet, store=False)
            self._sniffer.start()
            self._sweeper = threading.Thread(target=self._sweep_loop, name="netsentry-live-sweeper", daemon=True)
            self._sweeper.start()
            self.started_at = datetime.now(timezone.utc).isoformat()
            self.error = None

    def _sweep_loop(self) -> None:
        while not self._stop.wait(SWEEP_INTERVAL_S):
            try:
                self._tracker.sweep()
            except Exception as exc:  # keep capturing even if one flow fails to score
                self.error = f"Scoring error: {exc}"

    def stop(self) -> None:
        with self._lock:
            if not self.running:
                return
            self._stop.set()
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
            if self._sweeper:
                self._sweeper.join(timeout=5)
            self._tracker.sweep(flush=True)

    def status(self) -> dict:
        tracker = self._tracker
        return {
            "running": self.running,
            "method": self.method,
            "interface": self.interface,
            "started_at": self.started_at,
            "packets_seen": tracker.packets_seen if tracker else 0,
            "active_flows": tracker.active_flows if tracker else 0,
            "flows_scored": tracker.flows_emitted if tracker else 0,
            "flows_dropped": tracker.flows_dropped if tracker else 0,
            "error": self.error,
        }


capture = LiveCapture()
