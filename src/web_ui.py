import os
import time
import json
import asyncio
import threading
import re
from typing import Dict, List, Set, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
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

os.makedirs("src/static", exist_ok=True)


def load_services_config() -> List[Dict[str, Any]]:
    config_paths = [
        os.path.join(os.path.dirname(__file__), '..', 'services.json'),
        'services.json',
    ]
    for path in config_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            with open(abs_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data.get('services', [])
    return []


import logging

SERVICE_CONFIG: List[Dict[str, Any]] = load_services_config()

logger = logging.getLogger("ids_alerts_web")
logger.setLevel(logging.INFO)
logger.handlers.clear()

try:
    log_file_path = "ids_alerts.log"
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter("%(asctime)s - [ALERT] %(message)s")
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
except Exception as e:
    print(f"Warning: Unable to initialize web UI alert log file: {e}")

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
    for connection in list(active_connections):
        try:
            await connection.send_json(message)
        except Exception:
            if connection in active_connections:
                active_connections.remove(connection)


def handle_analyzer_alert(alert: Dict[str, Any]) -> None:
    with lock:
        alerts.append(alert)
    
    try:
        logger.info(alert["message"])
    except Exception as e:
        print(f"Error logging alert: {e}")

    if loop and active_connections:
        asyncio.run_coroutine_threadsafe(
            broadcast_message(alert),
            loop
        )


def process_packet(packet: Any) -> None:
    global analyzer, ip_service_map, active_hosts, loop
    
    if packet.haslayer(DNS) and packet[DNS].qr == 1 and packet.haslayer(DNSRR):
        i = 1
        while True:
            rr = packet.getlayer(DNSRR, i)
            if rr is None:
                break
            
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
                for svc in SERVICE_CONFIG:
                    if any(keyword in domain for keyword in svc.get('domains', [])):
                        service = svc['name']
                        break
                
                if service:
                    with lock:
                        ip_service_map[ip_addr] = service
            i += 1

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

        with lock:
            if analyzer:
                analyzer.process_packet(packet)

        if loop and active_connections:
            asyncio.run_coroutine_threadsafe(
                broadcast_message(packet_info),
                loop
            )


def validate_sniff_params(interface: str, syn_flood_threshold: int, syn_flood_ratio: float) -> None:
    if not interface or not re.match(r'^[a-zA-Z0-9.\-_:]+$', interface):
        raise ValueError("Invalid network interface name format.")
    if syn_flood_threshold <= 0 or syn_flood_threshold > 1000000:
        raise ValueError("SYN flood threshold must be between 1 and 1,000,000.")
    if syn_flood_ratio <= 0.0 or syn_flood_ratio > 1000000.0:
        raise ValueError("SYN flood ratio must be positive and less than 1,000,000.")


def start_sniff_logic(
    interface: str,
    syn_flood_threshold: int = 100,
    syn_flood_ratio: float = 10.0
) -> str:
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
    global should_sniff, sniffer_thread
    with lock:
        if not should_sniff:
            return "not running"
        should_sniff = False
    if sniffer_thread:
        sniffer_thread.join(timeout=1.0)
    return "stopped"


class StartRequest(BaseModel):
    interface: str
    syn_flood_threshold: Optional[int] = 100
    syn_flood_ratio: Optional[float] = 10.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    global loop
    loop = asyncio.get_running_loop()
    yield
    stop_sniff_logic()


app = FastAPI(lifespan=lifespan)


@app.get("/api/interfaces")
@app.get("/interfaces")
def api_get_interfaces() -> dict:
    return {"interfaces": get_if_list()}


@app.post("/api/start")
@app.post("/start")
def api_start_sniffing(req: StartRequest) -> dict:
    syn_threshold = req.syn_flood_threshold if req.syn_flood_threshold is not None else 100
    syn_ratio = req.syn_flood_ratio if req.syn_flood_ratio is not None else 10.0
    try:
        validate_sniff_params(req.interface, syn_threshold, syn_ratio)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    status = start_sniff_logic(
        interface=req.interface,
        syn_flood_threshold=syn_threshold,
        syn_flood_ratio=syn_ratio
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


@app.get("/api/services")
@app.get("/services")
def api_get_services() -> dict:
    return {"services": [s["name"] for s in SERVICE_CONFIG]}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    global loop
    if loop is None:
        loop = asyncio.get_running_loop()
    try:
        while True:
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
                    
                    try:
                        validate_sniff_params(iface, syn_flood_threshold, syn_flood_ratio)
                        status = start_sniff_logic(
                            interface=iface,
                            syn_flood_threshold=syn_flood_threshold,
                            syn_flood_ratio=syn_flood_ratio
                        )
                        await websocket.send_json({
                            "type": "status",
                            "status": status
                        })
                    except ValueError as e:
                        await websocket.send_json({
                            "type": "error",
                            "message": str(e)
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


app.mount("/static", StaticFiles(directory="src/static"), name="static")


@app.get("/")
def read_index() -> FileResponse:
    index_path = "src/static/index.html"
    if not os.path.exists(index_path):
        with open(index_path, "w") as f:
            f.write("<html><body>Welcome to PCAP IDS Dashboard</body></html>")
    return FileResponse(index_path)


if __name__ == "__main__":
    import argparse
    import uvicorn
    
    parser = argparse.ArgumentParser(description="PCAP IDS Web Dashboard")
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind the server to (default: 127.0.0.1 for local security)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to run the server on (default: 8000)"
    )
    args = parser.parse_args()
    
    uvicorn.run("src.web_ui:app", host=args.host, port=args.port, reload=True)
