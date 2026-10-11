# Network Traffic Analyzer & Intrusion Detection System (IDS)

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/packet--engine-Scapy-red.svg)](https://scapy.net/)
[![FastAPI](https://img.shields.io/badge/dashboard-FastAPI%20%2B%20WebSockets-teal.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-23%20passed-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

A signature-based network intrusion detection system (NIDS) and packet capture analysis tool in Python. Supports live network interface packet capture and offline `.pcap` analysis, featuring four behavioral detection engines, structured alert logging, and an asynchronous real-time WebSocket dashboard.

Developed by **Farhad Jelve** (B.Sc. Electrical Engineering, KTH Royal Institute of Technology | Cisco CCNP Enterprise Core certified).

---

## Detection Engines

The engine processes raw packet frames using Scapy and validates traffic against four security detection models:

1. **SYN-Flood Denial of Service (DoS):**
   Tracks TCP state ratios. If an IP address transmits high volumes of TCP SYN packets with disproportionately low SYN-ACK acknowledgments, the engine flags anomalous connection exhaustion attempts.

2. **ARP Spoofing & Cache Poisoning:**
   Maintains dynamic IP-to-MAC state tables. If multiple hardware MAC addresses advertise ownership of a single IP address, the system alerts on potential Man-in-the-Middle (MitM) positioning.

3. **DNS Tunneling & Data Exfiltration:**
   Inspects DNS query labels and payload lengths. Detects encoded subdomains and exfiltration channels characterized by unusually long, high-entropy query strings.

4. **Port Scanning & Reconnaissance:**
   Monitors connection attempt frequencies per source IP across configurable time windows (e.g. 20 connection attempts in 10 seconds) to identify reconnaissance sweeps.

---

## System Architecture

```text
       [Network Interface (Live) / Saved .pcap File]
                            │
                            ▼
               ┌────────────────────────┐
               │    Scapy Sniffer Core   │
               └────────────┬───────────┘
                            │ Raw Packets
                            ▼
               ┌────────────────────────┐
               │ Detection Engine Array │
               │ • SYN Flood Ratio      │
               │ • ARP Spoofing Cache   │
               │ • DNS Tunnel Entropy   │
               │ • Port Scan Velocity   │
               └────────────┬───────────┘
                            │ Anomaly Alerts
              ┌─────────────┴─────────────┐
              ▼                           ▼
   ┌──────────────────────┐   ┌──────────────────────┐
   │ Structured JSON Log  │   │ FastAPI WebSocket UI │
   │ (Audit & SIEM Feed)  │   │ (Live Real-Time Feed)│
   └──────────────────────┘   └──────────────────────┘
```

---

## Installation & Setup

Requirements: Python 3.10+ and libpcap / tcpdump dependencies for live packet capture.

```bash
git clone https://github.com/Farhad030619/PCAP-Parser-Intrusion-Detection.git
cd PCAP-Parser-Intrusion-Detection

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### 1. Offline PCAP File Analysis
Analyze an existing Wireshark packet capture:
```bash
python3 src/cli.py test.pcap
```

With custom alert thresholds and log export:
```bash
python3 src/cli.py test.pcap --syn-threshold 50 --syn-ratio 5.0 -o alerts.log
```

### 2. Live Interface Sniffing
Promiscuous packet capture requires raw socket privileges:
```bash
sudo .venv/bin/python3 src/cli.py --live
```

### 3. Real-Time Web Dashboard
Start the asynchronous FastAPI and WebSocket web service:
```bash
# Start on localhost (recommended for secure operations)
python3 src/web_ui.py --host 127.0.0.1 --port 8000
```
Access the real-time visual monitor at `http://127.0.0.1:8000`.

---

## Testing

Run the full pytest suite (23 unit and integration tests):
```bash
pytest -v
```

---

## Author
**Farhad Jelve**
- **Education:** B.Sc. Electrical Engineering, KTH Royal Institute of Technology
- **Certifications:** Cisco Certified Network Professional (CCNP Enterprise) and CCNA
- **Specialization:** Network Security, Protocol Analysis, NetDevOps
- **LinkedIn:** [Farhad Jelve](https://www.linkedin.com/in/farhad-jelve-9771a1270/)
