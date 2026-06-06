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


def test_port_scan_multi_ip_isolation():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    ip_a = "192.168.1.10"
    ip_b = "192.168.1.20"

    # Send 15 unique TCP port packets from ip_a, and 15 unique TCP port packets from ip_b.
    # Total unique ports scanned across both is 30, but each has only scanned 15.
    # Since threshold is 20, neither should trigger an alert.
    for i in range(15):
        pkt_a = IP(src=ip_a, dst="192.168.1.1") / TCP(dport=1000 + i)
        pkt_a.time = float(i * 0.1)
        analyzer.process_packet(pkt_a)

        pkt_b = IP(src=ip_b, dst="192.168.1.1") / TCP(dport=2000 + i)
        pkt_b.time = float(i * 0.1)
        analyzer.process_packet(pkt_b)

    assert len(analyzer.alerts) == 0, (
        "No alerts should be triggered because each IP only scanned 15 ports"
    )

    # Now, scan 6 more ports from ip_a to cross the threshold of 20 unique ports for ip_a.
    for i in range(15, 21):
        pkt_a = IP(src=ip_a, dst="192.168.1.1") / TCP(dport=1000 + i)
        pkt_a.time = float(i * 0.1)
        analyzer.process_packet(pkt_a)

    # Now ip_a has scanned 21 unique ports. ip_a should trigger an alert, but ip_b should not.
    assert len(analyzer.alerts) == 1
    assert analyzer.alerts[0]["source_ip"] == ip_a


def test_ipv6_port_scan():
    from scapy.layers.inet6 import IPv6
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "2001:db8::1"

    # Send 21 TCP packets to 21 unique TCP ports from scanner_ip
    for i in range(21):
        pkt = IPv6(src=scanner_ip, dst="2001:db8::2") / TCP(dport=3000 + i)
        pkt.time = i * 0.1
        analyzer.process_packet(pkt)

    assert len(analyzer.alerts) == 1, "IPv6 port scans should trigger alerts"
    assert analyzer.alerts[0]["source_ip"] == scanner_ip
    assert analyzer.alerts[0]["type"] == "PORT_SCAN"


def test_protocol_ambiguity_unique_ports():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "192.168.1.100"

    # Send packets to same port number but different protocols:
    # We send to 11 unique ports on TCP and 11 unique ports on UDP, all using the same port numbers (e.g. 80 to 90).
    # If the analyzer only tracks port numbers, it would see 11 unique ports and NOT alert.
    # If it tracks (dport, protocol) pairs, it would see 22 unique port/protocol combinations and alert.
    for i in range(11):
        pkt_tcp = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=80 + i)
        pkt_tcp.time = i * 0.1
        analyzer.process_packet(pkt_tcp)

        pkt_udp = IP(src=scanner_ip, dst="192.168.1.1") / UDP(dport=80 + i)
        pkt_udp.time = i * 0.1
        analyzer.process_packet(pkt_udp)

    assert len(analyzer.alerts) == 1, (
        "Protocol distinction should count TCP and UDP on same port separately"
    )


def test_history_pruning_and_periodic_cleanup():
    analyzer = NetworkAnalyzer(threshold=20, window=5.0)
    scanner_ip = "192.168.1.10"

    # Send packet from IP_A at t = 1.0
    pkt_a = IP(src=scanner_ip, dst="192.168.1.1") / TCP(dport=80)
    pkt_a.time = 1.0
    analyzer.process_packet(pkt_a)
    assert scanner_ip in analyzer.port_scan_history

    # Now send 1000 packets from IP_B at t = 10.0.
    # The periodic cleanup should run, and since IP_A is inactive, its key should be deleted.
    for i in range(1000):
        pkt_b = IP(src="192.168.1.20", dst="192.168.1.1") / TCP(dport=80)
        pkt_b.time = 10.0
        analyzer.process_packet(pkt_b)

    assert scanner_ip not in analyzer.port_scan_history

