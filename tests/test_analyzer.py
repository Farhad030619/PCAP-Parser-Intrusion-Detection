import pytest
from scapy.layers.inet import IP, TCP, UDP
from src.analyzer import NetworkAnalyzer

def test_port_scan_detection():
    # 1. Instantiate NetworkAnalyzer with threshold 20 and window 5.0 seconds.
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)

    # 2. Craft a normal traffic pattern (e.g. 5 packets to different ports over 5 seconds) using Scapy
    # and assert no alerts are raised.
    # We will send 5 packets to ports 80, 81, 82, 83, 84 starting at t=0.0, spacing them by 1.0s.
    normal_ip = "192.168.1.10"
    for i in range(5):
        pkt = IP(src=normal_ip, dst="192.168.1.1") / TCP(dport=80 + i)
        pkt.time = float(i)  # t = 0.0, 1.0, 2.0, 3.0, 4.0
        analyzer.process_packet(pkt)

    # Assert no alerts are raised for the normal IP
    normal_alerts = [a for a in analyzer.alerts if a["source_ip"] == normal_ip]
    assert len(normal_alerts) == 0, f"Expected no alerts for normal traffic, but got: {normal_alerts}"

    # 3. Craft a scan traffic pattern (21 packets to different ports within 3 seconds) using Scapy
    # and assert that a "PORT_SCAN" alert is triggered for the scanner IP.
    scan_ip = "192.168.1.50"
    # Sending 21 packets to ports 1000-1020, timestamp within 3 seconds (e.g. t = 10.0 to 12.0)
    for i in range(21):
        pkt = IP(src=scan_ip, dst="192.168.1.1") / TCP(dport=1000 + i)
        pkt.time = 10.0 + (i * 0.1)  # t = 10.0, 10.1, ..., 12.0 (total 2.0 seconds window span)
        analyzer.process_packet(pkt)

    # Assert that a "PORT_SCAN" alert is triggered for the scanner IP
    scan_alerts = [
        a for a in analyzer.alerts 
        if a["source_ip"] == scan_ip and a["type"] == "PORT_SCAN"
    ]
    assert len(scan_alerts) >= 1, "Expected at least one PORT_SCAN alert for the scanner IP"
    
    # Check alert details
    alert = scan_alerts[0]
    assert alert["source_ip"] == scan_ip
    assert alert["type"] == "PORT_SCAN"

def test_port_scan_cooldown_and_sliding_window():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "192.168.1.100"

    # Send 21 packets to 21 unique TCP ports from t=0.0 to t=2.0.
    # Alert should trigger at the 21st packet (t=2.0).
    for i in range(21):
        pkt = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=2000 + i)
        pkt.time = i * 0.1  # t=0.0 to t=2.0
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 1, "Expected exactly 1 alert to be triggered"
    assert analyzer.alerts[0]["timestamp"] == 2.0

    # Send 5 more packets to 5 new unique TCP ports from t=2.1 to t=4.0.
    # Since these are within the cooldown window (last alert was at t=2.0, window is 5.0s, so cooldown ends at t=7.0),
    # no new alert should be triggered.
    for i in range(5):
        pkt = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=3000 + i)
        pkt.time = 2.1 + (i * 0.1)  # t=2.1 to t=2.5
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 1, "Expected no additional alerts due to cooldown"

    # Send 21 packets to 21 new unique TCP ports from t=8.0 to t=10.0.
    # Since t=8.0 is outside the cooldown window (8.0 - 2.0 = 6.0 >= 5.0),
    # and these 21 packets are unique within the sliding window [3.0, 8.0+],
    # a new alert should be triggered.
    for i in range(21):
        pkt = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=4000 + i)
        pkt.time = 8.0 + (i * 0.1)  # t=8.0 to t=10.0
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 2, "Expected a second alert to be triggered after cooldown expired"
    assert analyzer.alerts[1]["timestamp"] == 10.0

def test_spaced_out_ports_no_alert():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "192.168.1.120"

    # Send 25 packets to 25 unique TCP ports, one packet every 1.0s (from t=0.0 to t=24.0).
    # The sliding window of 5.0 seconds will only contain at most 5 unique ports.
    # Thus, no alert should be triggered.
    for i in range(25):
        pkt = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=5000 + i)
        pkt.time = float(i)
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 0, "Spaced out scans should not trigger any alerts"

def test_udp_port_scan():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "192.168.1.150"

    # Send 21 UDP packets to 21 unique UDP ports from t=0.0 to t=2.0.
    for i in range(21):
        pkt = IP(src=scanner_ip, dst="192.168.1.1") / UDP(dport=6000 + i)
        pkt.time = i * 0.1
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 1, "UDP scans should also trigger port scan alerts"
    assert analyzer.alerts[0]["source_ip"] == scanner_ip
    assert analyzer.alerts[0]["type"] == "PORT_SCAN"
