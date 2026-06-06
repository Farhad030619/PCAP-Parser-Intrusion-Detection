#!/usr/bin/env python3
"""
Helper script to generate a mock PCAP file containing:
1. Normal TCP traffic (handshakes, data exchange).
2. A Port Scan attack (more than 20 unique ports scanned within 5 seconds).
3. A SYN Flood attack (150 SYN packets from one source IP, and no SYN-ACK responses).
"""

import time
from scapy.all import Ether, IP, TCP, UDP, wrpcap

def generate_mock_pcap(filename: str = "test.pcap") -> None:
    print(f"Generating mock PCAP file '{filename}'...")
    packets = []
    
    # 1. Normal traffic (IP: 192.168.1.50)
    # 5 normal connections to port 80 and 443 with complete handshakes
    base_time = time.time()
    for i in range(5):
        t = base_time + float(i) * 0.5
        # Client SYN
        pkt1 = Ether()/IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=1025+i, dport=80, flags="S")
        pkt1.time = t
        # Server SYN-ACK
        pkt2 = Ether()/IP(src="192.168.1.1", dst="192.168.1.50")/TCP(sport=80, dport=1025+i, flags="SA")
        pkt2.time = t + 0.01
        # Client ACK
        pkt3 = Ether()/IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=1025+i, dport=80, flags="A")
        pkt3.time = t + 0.02
        
        packets.extend([pkt1, pkt2, pkt3])

    # 2. Port Scan attack (IP: 10.0.0.99)
    # Scanning 25 ports in less than 2 seconds
    scan_start_time = base_time + 10.0
    for port in range(1, 26):
        t = scan_start_time + (float(port) * 0.05)
        # SYN packets to 25 different ports
        pkt = Ether()/IP(src="10.0.0.99", dst="192.168.1.1")/TCP(sport=5000, dport=port, flags="S")
        pkt.time = t
        packets.append(pkt)

    # 3. SYN Flood attack (IP: 172.16.0.4)
    # 120 SYN packets to port 80 in a short period, with only 1 SYN-ACK response
    flood_start_time = base_time + 20.0
    for i in range(120):
        t = flood_start_time + (float(i) * 0.01)
        pkt = Ether()/IP(src="172.16.0.4", dst="192.168.1.1")/TCP(sport=2000+i, dport=80, flags="S")
        pkt.time = t
        packets.append(pkt)
        
    # Just 1 SYN-ACK response to simulate a heavy imbalance (DoS)
    pkt_sa = Ether()/IP(src="192.168.1.1", dst="172.16.0.4")/TCP(sport=80, dport=2000, flags="SA")
    pkt_sa.time = flood_start_time + 0.05
    packets.append(pkt_sa)

    # Save to PCAP
    wrpcap(filename, packets)
    print(f"Successfully generated '{filename}' with {len(packets)} packets!")

if __name__ == "__main__":
    generate_mock_pcap("test.pcap")
