import time
from typing import Dict, List, Tuple, Any, Callable, Optional
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


class NetworkAnalyzer:
    """
    Analyzes network packets for potential security events, such as SYN floods.
    """
    def __init__(
        self,
        syn_flood_threshold: int = 100,
        syn_flood_ratio: float = 10.0,
        on_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.syn_flood_threshold: int = syn_flood_threshold
        self.syn_flood_ratio: float = syn_flood_ratio
        self.on_alert: Optional[Callable[[Dict[str, Any]], None]] = on_alert
        # List of all triggered alerts
        self.alerts: List[Dict[str, Any]] = []
        # Packet counter for tracking progress
        self.packet_count: int = 0
        # SYN flood state tracking
        self.syn_sent_count: Dict[str, int] = {}
        self.syn_ack_received_count: Dict[str, int] = {}
        self.syn_flood_alerted: set[str] = set()
        self.last_packet_time: float = 0.0

    def process_packet(self, packet: Packet) -> None:
        """
        Process a single packet and inspect for potential SYN floods.
        """
        self.packet_count += 1
        packet_time: float = (
            float(packet.time) if packet.time is not None else time.time()
        )
        self.last_packet_time = packet_time

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return

        src_ip: str = (
            packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        )
        dst_ip: str = (
            packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        )

        # SYN Flood Detection
        if packet.haslayer(TCP):
            flags = str(packet[TCP].flags)
            is_syn = "S" in flags and "A" not in flags
            is_syn_ack = "S" in flags and "A" in flags

            if is_syn:
                self.syn_sent_count[src_ip] = self.syn_sent_count.get(src_ip, 0) + 1
            elif is_syn_ack:
                self.syn_ack_received_count[dst_ip] = self.syn_ack_received_count.get(dst_ip, 0) + 1

            if src_ip in self.syn_sent_count and self.syn_sent_count[src_ip] >= self.syn_flood_threshold:
                sent = self.syn_sent_count[src_ip]
                received = self.syn_ack_received_count.get(src_ip, 0)
                ratio = sent / max(1, received)
                if ratio >= self.syn_flood_ratio:
                    if src_ip not in self.syn_flood_alerted:
                        self.syn_flood_alerted.add(src_ip)
                        alert_msg = (
                            f"SYN_FLOOD Alert: {src_ip} sent {sent} SYN packets "
                            f"but received only {received} SYN-ACK packets"
                        )
                        alert = {
                            "type": "SYN_FLOOD",
                            "source_ip": src_ip,
                            "timestamp": packet_time,
                            "message": alert_msg,
                            "syn_sent_count": sent,
                            "syn_ack_received_count": received,
                        }
                        self.alerts.append(alert)
                        if self.on_alert is not None:
                            self.on_alert(alert)

    def evaluate_syn_floods(self) -> None:
        """
        Evaluate any IPs that might have reached the SYN flood threshold by the end.
        """
        for ip, sent in list(self.syn_sent_count.items()):
            if sent >= self.syn_flood_threshold:
                received = self.syn_ack_received_count.get(ip, 0)
                ratio = sent / max(1, received)
                if ratio >= self.syn_flood_ratio:
                    if ip not in self.syn_flood_alerted:
                        self.syn_flood_alerted.add(ip)
                        alert_msg = (
                            f"SYN_FLOOD Alert: {ip} sent {sent} SYN packets "
                            f"but received only {received} SYN-ACK packets"
                        )
                        alert_time = self.last_packet_time if self.last_packet_time > 0 else time.time()
                        alert = {
                            "type": "SYN_FLOOD",
                            "source_ip": ip,
                            "timestamp": alert_time,
                            "message": alert_msg,
                            "syn_sent_count": sent,
                            "syn_ack_received_count": received,
                        }
                        self.alerts.append(alert)
                        if self.on_alert is not None:
                            self.on_alert(alert)


