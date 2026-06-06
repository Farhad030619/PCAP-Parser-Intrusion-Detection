import datetime
import subprocess
import sys
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import wrpcap
from src.analyzer import NetworkAnalyzer


def test_syn_flood_detection():
    # Instantiate analyzer with default threshold values
    analyzer = NetworkAnalyzer()

    # 1. Normal traffic: IP sends 50 SYN packets and receives 50 SYN-ACK packets
    normal_ip = "192.168.1.100"
    for i in range(50):
        # IP sends SYN (TCP flag has 'S' but not 'A')
        syn_pkt = IP(src=normal_ip, dst="192.168.1.1") / TCP(flags="S", dport=80)
        syn_pkt.time = float(i)
        analyzer.process_packet(syn_pkt)

        # IP receives SYN-ACK (TCP flag has both 'S' and 'A')
        syn_ack_pkt = IP(src="192.168.1.1", dst=normal_ip) / TCP(flags="SA", sport=80)
        syn_ack_pkt.time = float(i) + 0.01
        analyzer.process_packet(syn_ack_pkt)

    # Evaluate at the end
    analyzer.evaluate_syn_floods()

    # Assert no alerts are raised
    normal_alerts = [a for a in analyzer.alerts if a["source_ip"] == normal_ip and a["type"] == "SYN_FLOOD"]
    assert len(normal_alerts) == 0, f"Expected no SYN_FLOOD alerts for normal IP, got: {normal_alerts}"

    # 2. SYN Flood traffic: IP sends 120 SYN packets but receives only 2 SYN-ACK packets
    flood_ip = "192.168.1.200"

    # Send 120 SYN packets
    for i in range(120):
        syn_pkt = IP(src=flood_ip, dst="192.168.1.1") / TCP(flags="S", dport=80)
        syn_pkt.time = 100.0 + float(i)
        analyzer.process_packet(syn_pkt)

    # Send 2 SYN-ACK packets received by flood_ip
    for i in range(2):
        syn_ack_pkt = IP(src="192.168.1.1", dst=flood_ip) / TCP(flags="SA", sport=80)
        syn_ack_pkt.time = 100.0 + float(i) + 0.01
        analyzer.process_packet(syn_ack_pkt)

    # Evaluate at the end
    analyzer.evaluate_syn_floods()

    # Assert a "SYN_FLOOD" alert is triggered for this source IP
    flood_alerts = [
        a for a in analyzer.alerts
        if a["source_ip"] == flood_ip and a["type"] == "SYN_FLOOD"
    ]
    assert len(flood_alerts) >= 1, "Expected SYN_FLOOD alert to be triggered for the flood IP"


def test_pcap_parsing_integration(tmp_path):
    pcap_file = tmp_path / "test_scan.pcap"
    log_file = tmp_path / "test_alerts.log"

    packets = []
    # Simulate a SYN flood: 6 SYN packets, threshold 5, ratio 5.0
    for i in range(6):
        pkt = IP(src="192.168.1.60", dst="192.168.1.1") / TCP(flags="S", dport=80)
        pkt.time = 200.0 + i * 0.1
        packets.append(pkt)

    wrpcap(str(pcap_file), packets)

    # Run the CLI as a subprocess
    cmd = [
        sys.executable,
        "src/cli.py",
        str(pcap_file),
        "--syn-threshold", "5",
        "--syn-ratio", "5.0",
        "-o", str(log_file),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    # Check exit code
    assert result.returncode == 0, f"CLI failed with stderr: {result.stderr}"

    # Check console output
    assert "Analyzing PCAP file:" in result.stdout
    assert "Processed" in result.stdout or "packets" in result.stdout
    assert "[ALERT]" in result.stdout
    assert "\033[91m" in result.stdout  # Red alert output
    assert "\033[92m" in result.stdout  # Green summary output
    assert "Analysis completed." in result.stdout

    # Check log file contents
    assert log_file.exists(), "Log file was not created"
    log_content = log_file.read_text()
    assert "SYN_FLOOD Alert:" in log_content
    # Timestamp should be in the log file
    current_year = str(datetime.datetime.now().year)
    assert current_year in log_content


def test_on_alert_callback():
    triggered_alerts = []

    def log_alert(alert):
        triggered_alerts.append(alert)

    analyzer = NetworkAnalyzer(syn_flood_threshold=5, syn_flood_ratio=5.0, on_alert=log_alert)

    # Send 6 SYN packets to cross threshold of 5
    for i in range(6):
        pkt = IP(src="192.168.1.60", dst="192.168.1.1") / TCP(flags="S", dport=80)
        pkt.time = float(i)
        analyzer.process_packet(pkt)

    assert len(triggered_alerts) == 1
    assert triggered_alerts[0]["type"] == "SYN_FLOOD"
    assert triggered_alerts[0]["source_ip"] == "192.168.1.60"


def test_cli_missing_file():
    # Runs the CLI via subprocess with a non-existent file
    cmd = [
        sys.executable,
        "src/cli.py",
        "non_existent_file.pcap",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 1
    assert "not found" in result.stderr.lower() or "error" in result.stderr.lower()


def test_cli_corrupted_pcap(tmp_path):
    # Writes invalid binary data to a temporary file and runs the CLI on it
    corrupted_file = tmp_path / "corrupted.pcap"
    corrupted_file.write_bytes(b"invalid binary data header and packets that cannot be parsed by pcap reader")
    
    cmd = [
        sys.executable,
        "src/cli.py",
        str(corrupted_file),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 1
    assert "error" in result.stderr.lower() or "parsing" in result.stderr.lower()


def test_cli_invalid_log_dir(tmp_path):
    # Runs the CLI with an invalid log file directory path
    pcap_file = tmp_path / "dummy.pcap"
    pcap_file.write_bytes(b"")
    
    cmd = [
        sys.executable,
        "src/cli.py",
        str(pcap_file),
        "-o", "/non_existent_directory_12345/invalid_log_path.log"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 1
    assert "unable to initialize log file" in result.stderr.lower() or "error" in result.stderr.lower()
