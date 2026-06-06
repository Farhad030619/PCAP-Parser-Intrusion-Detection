import os
import time
import json
import asyncio
import threading
from typing import Dict, List, Set, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scapy.all import sniff, get_if_list
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.analyzer import NetworkAnalyzer

# Ensure static directory exists
os.makedirs("src/static", exist_ok=True)

# State Management
should_sniff: bool = False
sniffer_thread: Optional[threading.Thread] = None
analyzer: Optional[NetworkAnalyzer] = None
ip_service_map: Dict[str, str] = {}
active_hosts: Set[str] = set()
alerts: List[Dict[str, Any]] = []
active_connections: List[WebSocket] = []
loop: Optional[asyncio.AbstractEventLoop] = None
lock = threading.RLock()

async def broadcast_message(message: dict) -> None:
    """Send a message to all active WebSockets."""
    for connection in list(active_connections):
        try:
            await connection.send_json(message)
        except Exception:
            if connection in active_connections:
                active_connections.remove(connection)

def handle_analyzer_alert(alert: Dict[str, Any]) -> None:
    """Format and broadcast threat alerts."""
    with lock:
        alerts.append(alert)
    if loop and active_connections:
        asyncio.run_coroutine_threadsafe(
            broadcast_message(alert),
            loop
        )

def process_packet(packet: Any) -> None:
    """Inspect DNS queries/responses and map IPs to services, and then analyze traffic."""
    global analyzer, ip_service_map, active_hosts, loop
    
    # 1. DNS Mapping logic
    if packet.haslayer(DNS) and packet[DNS].qr == 1 and packet.haslayer(DNSRR):
        i = 1
        while True:
            rr = packet.getlayer(DNSRR, i)
            if rr is None:
                break
            
            # Type 1 is A record
            if rr.type == 1:
                domain = rr.rrname
                if isinstance(domain, bytes):
                    domain = domain.decode("utf-8", errors="ignore")
                if domain.endswith("."):
                    domain = domain[:-1]
                domain = domain.lower()
                
                ip_addr = rr.rdata
                if isinstance(ip_addr, bytes):
                    ip_addr = ip_addr.decode("utf-8", errors="ignore")
                
                service = None
                if "tiktok" in domain or "byteoversea" in domain:
                    service = "TikTok"
                elif "youtube" in domain or "googlevideo" in domain:
                    service = "YouTube"
                elif "spotify" in domain:
                    service = "Spotify"
                elif "netflix" in domain or "nflx" in domain:
                    service = "Netflix"
                elif "github" in domain:
                    service = "GitHub"
                elif "google" in domain:
                    service = "Google"
                
                if service:
                    with lock:
                        ip_service_map[ip_addr] = service
            i += 1

    # 2. Extract IP Src / Dst and label with services
    src = None
    dst = None
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst

    if src or dst:
        service = None
        with lock:
            if src in ip_service_map:
                service = ip_service_map[src]
            elif dst in ip_service_map:
                service = ip_service_map[dst]
            
            if src:
                active_hosts.add(src)
            if dst:
                active_hosts.add(dst)

        # Get protocol name
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        else:
            proto = "OTHER"

        packet_time = float(packet.time) if packet.time is not None else time.time()
        packet_info = {
            "type": "packet",
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": len(packet),
            "service": service,
            "time": packet_time
        }

        # Process packet through analyzer
        with lock:
            if analyzer:
                analyzer.process_packet(packet)

        # Broadcast packet details
        if loop and active_connections:
            asyncio.run_coroutine_threadsafe(
                broadcast_message(packet_info),
                loop
            )

def start_sniff_logic(
    interface: str,
    syn_flood_threshold: int = 100,
    syn_flood_ratio: float = 10.0
) -> str:
    """Start live sniffing backend logic."""
    global should_sniff, sniffer_thread, analyzer
    with lock:
        if should_sniff:
            if analyzer:
                analyzer.syn_flood_threshold = syn_flood_threshold
                analyzer.syn_flood_ratio = syn_flood_ratio
            return "already running"
        
        should_sniff = True
        analyzer = NetworkAnalyzer(
            syn_flood_threshold=syn_flood_threshold,
            syn_flood_ratio=syn_flood_ratio,
            on_alert=handle_analyzer_alert
        )
        
        # Reset lists for new sniffing session
        active_hosts.clear()
        alerts.clear()

        def run_sniff():
            try:
                sniff(
                    iface=interface,
                    prn=process_packet,
                    stop_filter=lambda p: not should_sniff
                )
            except Exception as e:
                print(f"Error in sniffing thread: {e}")

        sniffer_thread = threading.Thread(target=run_sniff, daemon=True)
        sniffer_thread.start()
        
    return "started"

def stop_sniff_logic() -> str:
    """Stop live sniffing backend logic."""
    global should_sniff, sniffer_thread
    with lock:
        if not should_sniff:
            return "not running"
        should_sniff = False
    if sniffer_thread:
        # Give it a bit to exit, but don't block the web server thread excessively
        sniffer_thread.join(timeout=1.0)
    return "stopped"

# Pydantic schema for start endpoint
class StartRequest(BaseModel):
    interface: str
    syn_flood_threshold: Optional[int] = 100
    syn_flood_ratio: Optional[float] = 10.0

@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    yield
    # Stop sniffing on shutdown
    stop_sniff_logic()

app = FastAPI(lifespan=lifespan)

# REST Endpoints
@app.get("/api/interfaces")
@app.get("/interfaces")
def api_get_interfaces() -> dict:
    return {"interfaces": get_if_list()}

@app.post("/api/start")
@app.post("/start")
def api_start_sniffing(req: StartRequest) -> dict:
    status = start_sniff_logic(
        interface=req.interface,
        syn_flood_threshold=req.syn_flood_threshold if req.syn_flood_threshold is not None else 100,
        syn_flood_ratio=req.syn_flood_ratio if req.syn_flood_ratio is not None else 10.0
    )
    return {"status": status}

@app.post("/api/stop")
@app.post("/stop")
def api_stop_sniffing() -> dict:
    status = stop_sniff_logic()
    return {"status": status}

@app.get("/api/status")
@app.get("/status")
def api_get_status() -> dict:
    with lock:
        return {"status": "started" if should_sniff else "stopped"}

@app.get("/api/alerts")
def api_get_alerts() -> dict:
    with lock:
        return {"alerts": list(alerts)}

@app.get("/api/hosts")
def api_get_hosts() -> dict:
    with lock:
        return {"hosts": list(active_hosts)}

# WebSocket connection endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    global loop
    if loop is None:
        loop = asyncio.get_running_loop()
    try:
        while True:
            # Client commands
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                action = msg.get("action")
                if action == "get_interfaces":
                    await websocket.send_json({
                        "type": "interfaces",
                        "interfaces": get_if_list()
                    })
                elif action == "start":
                    iface = msg.get("interface")
                    syn_flood_threshold = msg.get("syn_flood_threshold", 100)
                    syn_flood_ratio = msg.get("syn_flood_ratio", 10.0)
                    
                    status = start_sniff_logic(
                        interface=iface,
                        syn_flood_threshold=syn_flood_threshold,
                        syn_flood_ratio=syn_flood_ratio
                    )
                    await websocket.send_json({
                        "type": "status",
                        "status": status
                    })
                elif action == "stop":
                    status = stop_sniff_logic()
                    await websocket.send_json({
                        "type": "status",
                        "status": status
                    })
                elif action == "get_alerts":
                    with lock:
                        current_alerts = list(alerts)
                    await websocket.send_json({
                        "type": "alerts",
                        "alerts": current_alerts
                    })
                elif action == "get_hosts":
                    with lock:
                        current_hosts = list(active_hosts)
                    await websocket.send_json({
                        "type": "hosts",
                        "hosts": current_hosts
                    })
            except Exception as e:
                try:
                    await websocket.send_json({
                        "type": "error",
                        "message": str(e)
                    })
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)

# Mount static files
app.mount("/static", StaticFiles(directory="src/static"), name="static")

# Fallback route for home page
@app.get("/")
def read_index() -> FileResponse:
    index_path = "src/static/index.html"
    if not os.path.exists(index_path):
        with open(index_path, "w") as f:
            f.write("<html><body>Welcome to PCAP IDS Dashboard</body></html>")
    return FileResponse(index_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.web_ui:app", host="0.0.0.0", port=8000, reload=True)
