import time
from typing import Dict, List, Set, Tuple, Any
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

class NetworkAnalyzer:
    """
    Analyzes network packets for potential security events, such as port scans.
    """
    def __init__(self, threshold: int = 20, window: float = 5.0) -> None:
        self.threshold: int = threshold
        self.window: float = window
        # Maps source IP to a list of (timestamp, destination_port) tuples
        self.history: Dict[str, List[Tuple[float, int]]] = {}
        # Maps source IP to the last alert timestamp (float)
        self.last_alert_time: Dict[str, float] = {}
        # List of all triggered alerts
        self.alerts: List[Dict[str, Any]] = []

    def process_packet(self, packet: Packet) -> None:
        """
        Process a single packet and inspect for potential port scans.
        """
        if not packet.haslayer(IP):
            return

        # Check for destination port in TCP/UDP layer
        dport = None
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport

        if dport is None:
            return

        src_ip: str = packet[IP].src
        packet_time: float = float(packet.time) if packet.time is not None else time.time()

        # Add connection to history
        if src_ip not in self.history:
            self.history[src_ip] = []
        self.history[src_ip].append((packet_time, dport))

        # Remove ports scanned outside the sliding window
        cutoff_time = packet_time - self.window
        self.history[src_ip] = [
            (ts, port) for ts, port in self.history[src_ip] if ts >= cutoff_time
        ]

        # Calculate unique destination ports scanned within the window
        unique_ports = {port for ts, port in self.history[src_ip]}

        # If threshold of unique ports is exceeded, check for alert suppression
        if len(unique_ports) > self.threshold:
            last_alert = self.last_alert_time.get(src_ip)
            if last_alert is None or (packet_time - last_alert >= self.window):
                self.last_alert_time[src_ip] = packet_time
                alert_msg = f"PORT_SCAN Alert: {src_ip} scanned {len(unique_ports)} unique ports in {self.window}s"
                print(alert_msg)
                self.alerts.append({
                    "type": "PORT_SCAN",
                    "source_ip": src_ip,
                    "timestamp": packet_time,
                    "message": alert_msg,
                    "unique_ports_count": len(unique_ports)
                })
