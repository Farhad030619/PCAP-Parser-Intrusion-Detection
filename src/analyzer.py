import time
from collections import defaultdict
from typing import Dict, List, Set, Any, Callable, Optional
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet


class NetworkAnalyzer:
    def __init__(
        self,
        syn_flood_threshold: int = 100,
        syn_flood_ratio: float = 10.0,
        arp_spoof_enabled: bool = True,
        dns_tunnel_threshold: int = 50,
        dns_tunnel_min_length: int = 50,
        brute_force_threshold: int = 20,
        brute_force_window: float = 10.0,
        on_alert: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_ratio = syn_flood_ratio
        self.arp_spoof_enabled = arp_spoof_enabled
        self.dns_tunnel_threshold = dns_tunnel_threshold
        self.dns_tunnel_min_length = dns_tunnel_min_length
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window
        self.on_alert = on_alert

        self.alerts: List[Dict[str, Any]] = []
        self.packet_count: int = 0
        self.last_packet_time: float = 0.0

        self.syn_sent_count: Dict[str, int] = {}
        self.syn_ack_received_count: Dict[str, int] = {}
        self.syn_flood_alerted: Set[str] = set()

        self.arp_table: Dict[str, Set[str]] = defaultdict(set)
        self.arp_spoof_alerted: Set[str] = set()

        self.dns_query_tracker: Dict[str, List[int]] = defaultdict(list)
        self.dns_tunnel_alerted: Set[str] = set()

        self.connection_tracker: Dict[str, List[float]] = defaultdict(list)
        self.brute_force_alerted: Set[str] = set()

    def _emit_alert(self, alert: Dict[str, Any]) -> None:
        self.alerts.append(alert)
        if self.on_alert is not None:
            self.on_alert(alert)

    def process_packet(self, packet: Packet) -> None:
        self.packet_count += 1
        packet_time = (
            float(packet.time) if packet.time is not None else time.time()
        )
        self.last_packet_time = packet_time

        if self.arp_spoof_enabled and packet.haslayer(ARP):
            self._check_arp_spoof(packet, packet_time)

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return

        src_ip = (
            packet[IP].src if packet.haslayer(IP) else packet[IPv6].src
        )
        dst_ip = (
            packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst
        )

        if packet.haslayer(TCP):
            self._check_syn_flood(packet, src_ip, dst_ip, packet_time)
            self._check_brute_force(packet, src_ip, packet_time)

        if packet.haslayer(UDP) and packet.haslayer(DNS):
            self._check_dns_tunnel(packet, src_ip, packet_time)

    def _check_syn_flood(self, packet: Packet, src_ip: str, dst_ip: str, packet_time: float) -> None:
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
                    self._emit_alert({
                        "type": "SYN_FLOOD",
                        "source_ip": src_ip,
                        "timestamp": packet_time,
                        "message": (
                            f"SYN Flood: {src_ip} sent {sent} SYN packets "
                            f"with only {received} SYN-ACK replies (ratio {ratio:.1f})"
                        ),
                        "syn_sent_count": sent,
                        "syn_ack_received_count": received,
                    })

    def _check_arp_spoof(self, packet: Packet, packet_time: float) -> None:
        arp = packet[ARP]
        if arp.op == 2:
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc

            self.arp_table[sender_ip].add(sender_mac)

            if len(self.arp_table[sender_ip]) > 1 and sender_ip not in self.arp_spoof_alerted:
                self.arp_spoof_alerted.add(sender_ip)
                macs = ", ".join(sorted(self.arp_table[sender_ip]))
                self._emit_alert({
                    "type": "ARP_SPOOF",
                    "source_ip": sender_ip,
                    "timestamp": packet_time,
                    "message": (
                        f"ARP Spoofing: IP {sender_ip} is claimed by "
                        f"multiple MAC addresses: {macs}"
                    ),
                    "mac_addresses": list(self.arp_table[sender_ip]),
                })

    def _check_dns_tunnel(self, packet: Packet, src_ip: str, packet_time: float) -> None:
        if not packet.haslayer(DNSQR):
            return

        qname = packet[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="ignore")

        query_len = len(qname)
        if query_len >= self.dns_tunnel_min_length:
            self.dns_query_tracker[src_ip].append(query_len)

            count = len(self.dns_query_tracker[src_ip])
            if count >= self.dns_tunnel_threshold and src_ip not in self.dns_tunnel_alerted:
                self.dns_tunnel_alerted.add(src_ip)
                avg_len = sum(self.dns_query_tracker[src_ip]) / count
                self._emit_alert({
                    "type": "DNS_TUNNEL",
                    "source_ip": src_ip,
                    "timestamp": packet_time,
                    "message": (
                        f"DNS Tunneling: {src_ip} sent {count} suspiciously long "
                        f"DNS queries (avg length {avg_len:.0f} chars)"
                    ),
                    "query_count": count,
                    "avg_query_length": round(avg_len, 1),
                })

    def _check_brute_force(self, packet: Packet, src_ip: str, packet_time: float) -> None:
        flags = str(packet[TCP].flags)
        is_syn = "S" in flags and "A" not in flags

        if not is_syn:
            return

        tracker = self.connection_tracker[src_ip]
        tracker.append(packet_time)

        cutoff = packet_time - self.brute_force_window
        self.connection_tracker[src_ip] = [t for t in tracker if t > cutoff]

        if len(self.connection_tracker[src_ip]) >= self.brute_force_threshold:
            if src_ip not in self.brute_force_alerted:
                self.brute_force_alerted.add(src_ip)
                count = len(self.connection_tracker[src_ip])
                self._emit_alert({
                    "type": "BRUTE_FORCE",
                    "source_ip": src_ip,
                    "timestamp": packet_time,
                    "message": (
                        f"Brute-Force: {src_ip} opened {count} connections "
                        f"in {self.brute_force_window:.0f}s window"
                    ),
                    "connection_count": count,
                    "window_seconds": self.brute_force_window,
                })

    def evaluate_syn_floods(self) -> None:
        for ip, sent in list(self.syn_sent_count.items()):
            if sent >= self.syn_flood_threshold:
                received = self.syn_ack_received_count.get(ip, 0)
                ratio = sent / max(1, received)
                if ratio >= self.syn_flood_ratio:
                    if ip not in self.syn_flood_alerted:
                        self.syn_flood_alerted.add(ip)
                        alert_time = self.last_packet_time if self.last_packet_time > 0 else time.time()
                        self._emit_alert({
                            "type": "SYN_FLOOD",
                            "source_ip": ip,
                            "timestamp": alert_time,
                            "message": (
                                f"SYN Flood: {ip} sent {sent} SYN packets "
                                f"with only {received} SYN-ACK replies (ratio {ratio:.1f})"
                            ),
                            "syn_sent_count": sent,
                            "syn_ack_received_count": received,
                        })
