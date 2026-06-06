# Network Analysis Tool (IDS) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a command-line network analysis tool in Python using `scapy` that parses `.pcap` files, detects port scans and SYN floods, prints color-coded warnings, saves log files, and includes a Wireshark generation guide.

**Architecture:**
- **`src/analyzer.py`**: Core detection class `NetworkAnalyzer` that processes packets using Scapy. Tracks sliding window timestamps for port scanning and computes SYN/SYN-ACK ratios per IP.
- **`src/cli.py`**: CLI interface with arguments, color-coded terminal logging (using ANSI colors), file logging, and progress reporting.
- **`tests/test_analyzer.py`**: Unit and integration tests verifying detection algorithms using programmatically generated Scapy packets.
- **`WIRESHARK_GUIDE.md`**: Guide for generating test PCAPs with Wireshark.

**Tech Stack:**
- Python 3.12+ (specifically Python 3.14 on this machine)
- Scapy (for PCAP parsing and packet crafting)
- Pytest (for testing)

---

### Task 1: Project Setup and Configuration

**Files:**
- Create: `pyproject.toml`
- Create: `requirements.txt`
- Create: `src/__init__.py`
- Create: `tests/__init__.py`

**Step 1: Write pyproject.toml and requirements.txt**

`pyproject.toml`:
```toml
[project]
name = "pcap-ids-tool"
version = "0.1.0"
description = "A PCAP-Parser & Intrusion Detection Script"
requires-python = ">=3.12"
dependencies = [
    "scapy>=2.6.0",
]

[dependency-groups]
dev = [
    "pytest>=8.0.0",
]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

`requirements.txt`:
```text
scapy>=2.6.0
pytest>=8.0.0
```

**Step 2: Create empty __init__.py files for modular package structure**
- Run: `mkdir -p src tests`
- Run: `touch src/__init__.py tests/__init__.py`

**Step 3: Install development dependencies**
- Run: `./.venv/bin/pip install -r requirements.txt`
- Expected: pytest and scapy installed in `.venv`.

**Step 4: Commit Setup**
- Run command to commit the setup files.

---

### Task 2: Implement and Test Port Scan Detection

**Files:**
- Create: `src/analyzer.py`
- Create: `tests/test_analyzer.py`

**Step 1: Write the test for Port Scan detection in `tests/test_analyzer.py`**
We will craft packets with Scapy representing a scan (>20 ports in 5 seconds) and a normal behavior (10 ports in 5 seconds).

```python
import pytest
from scapy.all import IP, TCP, Ether
from src.analyzer import NetworkAnalyzer

def test_detect_port_scan():
    analyzer = NetworkAnalyzer(port_scan_threshold=20, port_scan_window=5.0)
    
    # Normal traffic: 5 packets to different ports over 5 seconds
    packets = []
    for i in range(5):
        pkt = Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/TCP(dport=80+i)
        pkt.time = float(i)
        packets.append(pkt)
    
    for pkt in packets:
        analyzer.process_packet(pkt)
    
    assert len(analyzer.alerts) == 0

    # Scan traffic: 21 packets to different ports within 3 seconds
    packets = []
    for i in range(21):
        pkt = Ether()/IP(src="192.168.1.20", dst="192.168.1.1")/TCP(dport=1000+i)
        pkt.time = 10.0 + (i * 0.1)  # All within 2.1 seconds
        packets.append(pkt)
        
    for pkt in packets:
        analyzer.process_packet(pkt)
        
    # Should trigger at least one port scan alert for 192.168.1.20
    port_scan_alerts = [a for a in analyzer.alerts if a["type"] == "PORT_SCAN" and a["src_ip"] == "192.168.1.20"]
    assert len(port_scan_alerts) > 0
    assert port_scan_alerts[0]["src_ip"] == "192.168.1.20"
```

**Step 2: Run test to verify it fails**
- Run: `./.venv/bin/pytest tests/test_analyzer.py -k test_detect_port_scan -v`
- Expected: ModuleNotFoundError or ImportError for `src.analyzer`.

**Step 3: Write the core `NetworkAnalyzer` in `src/analyzer.py` with port scan detection**

```python
from collections import defaultdict
from typing import Dict, List, Tuple, Any

class NetworkAnalyzer:
    def __init__(self, port_scan_threshold: int = 20, port_scan_window: float = 5.0):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        
        # Maps src_ip -> list of (timestamp, dport)
        self.port_scan_history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        # Maps src_ip -> last alert timestamp to avoid spamming
        self.last_port_scan_alert: Dict[str, float] = {}
        
        self.alerts: List[Dict[str, Any]] = []

    def process_packet(self, packet: Any) -> None:
        if not packet.haslayer('IP'):
            return
            
        src_ip = packet['IP'].src
        packet_time = float(packet.time)
        
        # Determine destination port if it exists (TCP or UDP)
        dport = None
        if packet.haslayer('TCP'):
            dport = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            dport = packet['UDP'].dport
            
        if dport is not None:
            self._check_port_scan(src_ip, dport, packet_time)

    def _check_port_scan(self, src_ip: str, dport: int, packet_time: float) -> None:
        history = self.port_scan_history[src_ip]
        # Clean up older than window
        cutoff = packet_time - self.port_scan_window
        history = [item for item in history if item[0] >= cutoff]
        history.append((packet_time, dport))
        self.port_scan_history[src_ip] = history
        
        # Calculate unique destination ports
        unique_ports = {port for _, port in history}
        
        if len(unique_ports) > self.port_scan_threshold:
            # Check cooldown
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if packet_time - last_alert >= self.port_scan_window:
                self.last_port_scan_alert[src_ip] = packet_time
                alert = {
                    "type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "timestamp": packet_time,
                    "details": f"Source IP {src_ip} scanned {len(unique_ports)} unique ports in less than {self.port_scan_window}s."
                }
                self.alerts.append(alert)
```

**Step 4: Run test to verify it passes**
- Run: `./.venv/bin/pytest tests/test_analyzer.py -k test_detect_port_scan -v`
- Expected: PASS

**Step 5: Commit**
- Git commit port scan implementation.

---

### Task 3: Implement and Test SYN-Flood Detection

**Files:**
- Modify: `src/analyzer.py`
- Modify: `tests/test_analyzer.py`

**Step 1: Write test for SYN Flood detection in `tests/test_analyzer.py`**
We will craft packets showing:
1. Normal TCP handshake behavior (equal or close SYN to SYN-ACK ratios).
2. SYN Flood behavior (many SYN packets sent by IP, 0 or very few SYN-ACK packets received by IP).

```python
def test_detect_syn_flood():
    analyzer = NetworkAnalyzer(syn_flood_threshold=10, syn_flood_ratio=5.0)
    
    # Case 1: Normal connections. 10 SYNs sent, 10 SYN-ACKs received back
    for i in range(10):
        # SYN sent
        pkt_syn = Ether()/IP(src="192.168.1.50", dst="192.168.1.1")/TCP(flags="S", dport=80)
        pkt_syn.time = float(i)
        analyzer.process_packet(pkt_syn)
        
        # SYN-ACK received back (dst is the client IP)
        pkt_syn_ack = Ether()/IP(src="192.168.1.1", dst="192.168.1.50")/TCP(flags="SA", sport=80)
        pkt_syn_ack.time = float(i) + 0.01
        analyzer.process_packet(pkt_syn_ack)
        
    # Check alert triggering (should be none)
    syn_flood_alerts = [a for a in analyzer.alerts if a["type"] == "SYN_FLOOD"]
    assert len(syn_flood_alerts) == 0

    # Case 2: SYN flood. 20 SYNs sent from 192.168.1.60, 0 SYN-ACKs received by 192.168.1.60
    for i in range(20):
        pkt_syn = Ether()/IP(src="192.168.1.60", dst="192.168.1.1")/TCP(flags="S", dport=80)
        pkt_syn.time = 100.0 + float(i)
        analyzer.process_packet(pkt_syn)
        
    # Trigger active evaluation (usually evaluated periodically or at the end)
    analyzer.evaluate_syn_floods()
    
    syn_flood_alerts = [a for a in analyzer.alerts if a["type"] == "SYN_FLOOD" and a["src_ip"] == "192.168.1.60"]
    assert len(syn_flood_alerts) == 1
    assert "192.168.1.60" in syn_flood_alerts[0]["details"]
```

**Step 2: Run test to verify it fails**
- Run: `./.venv/bin/pytest tests/test_analyzer.py -k test_detect_syn_flood -v`
- Expected: FAIL due to missing arguments in `__init__` or missing method `evaluate_syn_floods`.

**Step 3: Update `NetworkAnalyzer` in `src/analyzer.py` to support SYN flood detection**

```python
class NetworkAnalyzer:
    def __init__(self, 
                 port_scan_threshold: int = 20, 
                 port_scan_window: float = 5.0,
                 syn_flood_threshold: int = 100,
                 syn_flood_ratio: float = 10.0):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_ratio = syn_flood_ratio
        
        # Port scan state
        self.port_scan_history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self.last_port_scan_alert: Dict[str, float] = {}
        
        # SYN flood state
        # Track SYN sent by source IP
        self.syn_sent_count: Dict[str, int] = defaultdict(int)
        # Track SYN-ACK received by destination IP
        self.syn_ack_received_count: Dict[str, int] = defaultdict(int)
        
        # Prevent duplicate alerts for SYN flood per IP
        self.syn_flood_alerted: set[str] = set()
        
        self.alerts: List[Dict[str, Any]] = []

    def process_packet(self, packet: Any) -> None:
        if not packet.haslayer('IP'):
            return
            
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        packet_time = float(packet.time)
        
        # Port scanning detection
        dport = None
        if packet.haslayer('TCP'):
            dport = packet['TCP'].dport
            self._track_tcp_flags(src_ip, dst_ip, packet['TCP'].flags)
        elif packet.haslayer('UDP'):
            dport = packet['UDP'].dport
            
        if dport is not None:
            self._check_port_scan(src_ip, dport, packet_time)

    def _track_tcp_flags(self, src_ip: str, dst_ip: str, flags: Any) -> None:
        # Flags in Scapy can be a string representation or an integer.
        # String contains 'S' for SYN, 'A' for ACK, etc.
        flag_str = str(flags)
        
        is_syn = 'S' in flag_str
        is_ack = 'A' in flag_str
        
        if is_syn and not is_ack:
            # SYN packet sent by src_ip
            self.syn_sent_count[src_ip] += 1
        elif is_syn and is_ack:
            # SYN-ACK packet received by dst_ip
            self.syn_ack_received_count[dst_ip] += 1

    def _check_port_scan(self, src_ip: str, dport: int, packet_time: float) -> None:
        history = self.port_scan_history[src_ip]
        cutoff = packet_time - self.port_scan_window
        history = [item for item in history if item[0] >= cutoff]
        history.append((packet_time, dport))
        self.port_scan_history[src_ip] = history
        
        unique_ports = {port for _, port in history}
        
        if len(unique_ports) > self.port_scan_threshold:
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if packet_time - last_alert >= self.port_scan_window:
                self.last_port_scan_alert[src_ip] = packet_time
                alert = {
                    "type": "PORT_SCAN",
                    "src_ip": src_ip,
                    "timestamp": packet_time,
                    "details": f"Source IP {src_ip} scanned {len(unique_ports)} unique ports in less than {self.port_scan_window}s."
                }
                self.alerts.append(alert)

    def evaluate_syn_floods(self) -> None:
        """Evaluates SYN-to-SYN-ACK ratios for all IPs and triggers alerts if thresholds are exceeded."""
        for ip, syn_sent in self.syn_sent_count.items():
            if syn_sent >= self.syn_flood_threshold and ip not in self.syn_flood_alerted:
                syn_ack_received = self.syn_ack_received_count.get(ip, 0)
                
                # Calculate ratio (use 1 as base to avoid division by zero)
                ratio = syn_sent / max(1, syn_ack_received)
                
                if ratio >= self.syn_flood_ratio:
                    self.syn_flood_alerted.add(ip)
                    alert = {
                        "type": "SYN_FLOOD",
                        "src_ip": ip,
                        "timestamp": None,  # Aggregate alert, no single timestamp
                        "details": f"SYN Flood detected from IP {ip}. SYN Sent: {syn_sent}, SYN-ACK Received: {syn_ack_received} (Ratio: {ratio:.1f}x)."
                    }
                    self.alerts.append(alert)
```

**Step 4: Run tests to verify all tests pass**
- Run: `./.venv/bin/pytest tests/test_analyzer.py -v`
- Expected: All tests PASS.

**Step 5: Commit**
- Git commit SYN flood implementation.

---

### Task 4: CLI Implementation, Color-Coded Terminal Output, and Logging

**Files:**
- Create: `src/cli.py`

**Step 1: Write CLI implementation with colorized logs and file logging**
We want the tool to read a PCAP path, parse it packet-by-packet (using Scapy's `PcapReader` to be memory-efficient), display alerts instantly, write alerts to a log file, and output a summary report.

Key UI requirements:
- Red color-coded messages for threats.
- Green for safe or complete processes.
- Yellow for scanning progress/warnings.
- Logging to `ids_alerts.log` (or custom file).

Let's design `src/cli.py` using standard argument parsing (`argparse`).

**Step 2: Write tests/integration check for CLI**
We can verify command execution by using a test helper to run the CLI on a generated test pcap file. Let's make sure we have a function in `tests/test_analyzer.py` that builds a test `.pcap` file.

```python
import tempfile
from scapy.all import wrpcap

def test_pcap_parsing_integration():
    # Generate a temporary pcap file
    packets = []
    # Add normal packets
    packets.append(Ether()/IP(src="192.168.1.100", dst="192.168.1.1")/TCP(flags="S", dport=80))
    packets.append(Ether()/IP(src="192.168.1.1", dst="192.168.1.100")/TCP(flags="SA", sport=80))
    
    # Add port scanning packets (25 packets to 25 ports from 10.0.0.5)
    for port in range(25):
        pkt = Ether()/IP(src="10.0.0.5", dst="192.168.1.1")/TCP(dport=100+port)
        pkt.time = 10.0 + port * 0.05
        packets.append(pkt)
        
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        wrpcap(tmp.name, packets)
        pcap_path = tmp.name
        
    # Test our analyzer on this pcap file
    analyzer = NetworkAnalyzer(port_scan_threshold=20, port_scan_window=5.0)
    
    # Read pcap using PcapReader
    from scapy.all import PcapReader
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            analyzer.process_packet(pkt)
            
    analyzer.evaluate_syn_floods()
    
    # Verify port scan detected
    port_scanners = [a["src_ip"] for a in analyzer.alerts if a["type"] == "PORT_SCAN"]
    assert "10.0.0.5" in port_scanners
```

**Step 3: Run integration test**
- Run: `./.venv/bin/pytest tests/test_analyzer.py -v`
- Expected: PASS.

**Step 4: Create the executable CLI `src/cli.py`**
Use `argparse` to handle parameters. Use ANSI colors for terminal output:
- Red: `\033[91m`
- Green: `\033[92m`
- Yellow: `\033[93m`
- Cyan: `\033[96m`
- Reset: `\033[0m`

---

### Task 5: Wireshark Guide & Readme

**Files:**
- Create: `WIRESHARK_GUIDE.md`
- Create: `README.md`

**Step 1: Write `WIRESHARK_GUIDE.md`**
Describe step-by-step instructions:
1. Opening Wireshark.
2. Capturing traffic (selecting interface).
3. Simulating a port scan using `nmap` (e.g. `nmap -F 192.168.1.1`).
4. Simulating a SYN Flood using `hping3` (e.g. `hping3 -S -p 80 --flood 192.168.1.1`).
5. Stopping capture and saving as `.pcap`.

**Step 2: Write `README.md`**
Detail installation, execution, test runs, and CLI argument usage.

---

### Task 6: Final Verification

**Step 1: Verify linting and formatting**
- Run: `pytest tests/test_analyzer.py`
- Verify that everything is correct and there are no warnings or errors.
