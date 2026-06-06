import time
from typing import Dict, List, Tuple, Any
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


class NetworkAnalyzer:
    """
    Analyzes network packets for potential security events, such as port scans.
    """
    def __init__(self, threshold: int = 20, window: float = 5.0) -> None:
        self.threshold: int = threshold
        self.window: float = window
        # Maps source IP to a list of (timestamp, (destination_port, protocol))
        self.port_scan_history: Dict[str, List[Tuple[float, Tuple[int, str]]]] = {}
        # Maps source IP to the last alert timestamp (float)
        self.last_alert_time: Dict[str, float] = {}
        # List of all triggered alerts
        self.alerts: List[Dict[str, Any]] = []
        # Packet counter for periodic cleanup
        self.packet_count: int = 0

    def process_packet(self, packet: Packet) -> None:
        """
        Process a single packet and inspect for potential port scans.
        """
        self.packet_count += 1
        packet_time: float = (
            float(packet.time) if packet.time is not None else time.time()
        )

        if self.packet_count % 1000 == 0:
            self._cleanup_history(packet_time)

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return

        # Check for destination port in TCP/UDP layer
        dport = None
        proto = None
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            proto = "TCP"
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport
            proto = "UDP"

        if dport is None:
            return

        src_ip: str = (
            packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        )

        # Add connection to history
        if src_ip not in self.port_scan_history:
            self.port_scan_history[src_ip] = []
        self.port_scan_history[src_ip].append((packet_time, (dport, proto)))

        # Remove ports scanned outside the sliding window
        cutoff_time = packet_time - self.window
        self.port_scan_history[src_ip] = [
            (ts, port_info) for ts, port_info in self.port_scan_history[src_ip]
            if ts >= cutoff_time
        ]

        # Prune key if history becomes empty
        if not self.port_scan_history[src_ip]:
            del self.port_scan_history[src_ip]

        # Calculate unique destination ports scanned within the window
        if src_ip in self.port_scan_history:
            unique_ports = {
                port_info for ts, port_info in self.port_scan_history[src_ip]
            }
        else:
            unique_ports = set()

        # If threshold of unique ports is exceeded, check for alert suppression
        if len(unique_ports) > self.threshold:
            last_alert = self.last_alert_time.get(src_ip)
            if last_alert is None or (packet_time - last_alert >= self.window):
                self.last_alert_time[src_ip] = packet_time
                alert_msg = (
                    f"PORT_SCAN Alert: {src_ip} scanned {len(unique_ports)} "
                    f"unique ports in {self.window}s"
                )
                print(alert_msg)
                self.alerts.append({
                    "type": "PORT_SCAN",
                    "source_ip": src_ip,
                    "timestamp": packet_time,
                    "message": alert_msg,
                    "unique_ports_count": len(unique_ports)
                })

    def _cleanup_history(self, current_time: float) -> None:
        """
        Periodically clean up the history dictionary to remove inactive IPs.
        """
        cutoff_time = current_time - self.window
        inactive_ips = []
        for src_ip, history in list(self.port_scan_history.items()):
            pruned_history = [
                (ts, port_info) for ts, port_info in history
                if ts >= cutoff_time
            ]
            if not pruned_history:
                inactive_ips.append(src_ip)
            else:
                self.port_scan_history[src_ip] = pruned_history

        for src_ip in inactive_ips:
            del self.port_scan_history[src_ip]

