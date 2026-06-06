import pytest
import os
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.packet import Packet
from src.web_ui import app, ip_service_map, process_packet, active_hosts, NetworkAnalyzer

@pytest.fixture
def client():
    # Ensure static directories and files exist for testing, since FastAPI serves static files.
    os.makedirs("src/static", exist_ok=True)
    if not os.path.exists("src/static/index.html"):
        with open("src/static/index.html", "w") as f:
            f.write("<html><body>Test Dashboard</body></html>")
            
    return TestClient(app)

def test_get_interfaces(client):
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)

def test_start_stop_sniffing(client):
    # Ensure starting sniffing returns correct status
    # We can post thresholds
    payload = {
        "interface": "lo0",
        "threshold": 15,
        "window": 10.0,
        "syn_flood_threshold": 50,
        "syn_flood_ratio": 5.0
    }
    response = client.post("/api/start", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "started"
    
    # Try stopping
    response = client.post("/api/stop")
    assert response.status_code == 200
    assert response.json()["status"] == "stopped"

def test_get_alerts_and_hosts(client):
    # Get current alerts
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert "alerts" in response.json()
    assert isinstance(response.json()["alerts"], list)
    
    # Get active hosts
    response = client.get("/api/hosts")
    assert response.status_code == 200
    assert "hosts" in response.json()
    assert isinstance(response.json()["hosts"], list)

def test_dns_mapping_and_service_labeling():
    # Clear map
    ip_service_map.clear()
    
    # Create a mock DNS response packet for tiktok
    # Query: tiktok.com, Answer: IP 1.2.3.4
    dns_pkt = (
        IP(src="8.8.8.8", dst="192.168.1.5") /
        UDP(sport=53, dport=12345) /
        DNS(qr=1, ancount=1, an=DNSRR(rrname="tiktok.com.", type=1, rdata="1.2.3.4"))
    )
    
    # Process it using process_packet
    # Wait, process_packet might try to broadcast to websockets.
    # In tests, if there are no websockets connected, it should not fail.
    process_packet(dns_pkt)
    
    # Assert that 1.2.3.4 is mapped to "TikTok"
    assert ip_service_map.get("1.2.3.4") == "TikTok"
    
    # Now check mapping for an IP packet with mapped IP as source or destination
    ip_pkt = IP(src="1.2.3.4", dst="192.168.1.5")
    process_packet(ip_pkt)
    # We want to test that process_packet labels the packet info correctly.
    # We can check that the host lists are updated
    assert "1.2.3.4" in active_hosts
    assert "192.168.1.5" in active_hosts

def test_serve_static_files(client):
    # Test fallback route serving index.html
    response = client.get("/")
    assert response.status_code == 200
    assert "Test Dashboard" in response.text
    
    # Test serving static files
    response = client.get("/static/index.html")
    assert response.status_code == 200
    assert "Test Dashboard" in response.text

def test_lock_type():
    import threading
    from src.web_ui import lock
    # Ensure it is an RLock (re-entrant lock)
    assert isinstance(lock, threading._RLock) or type(lock).__name__ == "RLock"

def test_reentrant_lock_prevents_deadlock():
    import threading
    import src.web_ui
    from scapy.layers.inet import IP, TCP
    
    # Set up analyzer with a very low threshold so port scan is triggered on 2nd packet
    src.web_ui.analyzer = NetworkAnalyzer(
        threshold=1,
        window=5.0,
        on_alert=src.web_ui.handle_analyzer_alert
    )
    
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=80, flags="S")
    pkt2 = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=12345, dport=443, flags="S")
    
    def run_process():
        src.web_ui.process_packet(pkt1)
        src.web_ui.process_packet(pkt2)

    t = threading.Thread(target=run_process)
    t.start()
    t.join(timeout=2.0)
    
    # If the thread is still alive, it deadlocked because process_packet held the lock
    # while calling handle_analyzer_alert (which tried to acquire the lock again).
    is_alive = t.is_alive()
    assert not is_alive, "Deadlock occurred in process_packet during alert callback!"
