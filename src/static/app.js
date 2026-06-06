// Global State
let ws = null;
let packetCount = 0;
let hostsCount = 0;
const hostsMap = new Map(); // IP -> { element, count, status }
let alertsCount = 0;
let isSniffing = false;
const serviceTimers = {};

// Service Config
const services = {
    "TikTok": { cardId: "service-tiktok", packetCount: 0 },
    "YouTube": { cardId: "service-youtube", packetCount: 0 },
    "Spotify": { cardId: "service-spotify", packetCount: 0 },
    "Netflix": { cardId: "service-netflix", packetCount: 0 },
    "GitHub": { cardId: "service-github", packetCount: 0 },
    "Google": { cardId: "service-google", packetCount: 0 }
};

// DOM Elements
const selectInterface = document.getElementById("interface-select");
const btnStart = document.getElementById("start-btn");
const btnStop = document.getElementById("stop-btn");
const btnSettingsToggle = document.getElementById("settings-toggle");
const btnSettingsClose = document.getElementById("settings-close");
const drawerSettings = document.getElementById("settings-drawer");
const overlayDrawer = document.getElementById("drawer-overlay");

const valPackets = document.getElementById("val-packets");
const valHosts = document.getElementById("val-hosts");
const valAlerts = document.getElementById("val-alerts");
const valAlertBadgeCount = document.getElementById("alert-badge-count");

const alertLogs = document.getElementById("alert-logs");
const packetStreamBody = document.getElementById("packet-stream-body");
const hostsList = document.getElementById("hosts-list");

const sliderPortThreshold = document.getElementById("slider-port-threshold");
const sliderPortWindow = document.getElementById("slider-port-window");
const sliderSynThreshold = document.getElementById("slider-syn-threshold");
const sliderSynRatio = document.getElementById("slider-syn-ratio");

const valPortThreshold = document.getElementById("val-port-threshold");
const valPortWindow = document.getElementById("val-port-window");
const valSynThreshold = document.getElementById("val-syn-threshold");
const valSynRatio = document.getElementById("val-syn-ratio");

// Initialize application
document.addEventListener("DOMContentLoaded", init);

async function init() {
    setupEventListeners();
    await fetchInterfaces();
    await checkInitialSniffingStatus();
    connectWebSocket();
}

// Event Listeners Setup
function setupEventListeners() {
    // Control Buttons
    btnStart.addEventListener("click", startSniffing);
    btnStop.addEventListener("click", stopSniffing);
    
    // Settings Drawer
    btnSettingsToggle.addEventListener("click", openSettings);
    btnSettingsClose.addEventListener("click", closeSettings);
    overlayDrawer.addEventListener("click", closeSettings);
    
    // Sliders input events for immediate display updates and throttling threshold sending
    sliderPortThreshold.addEventListener("input", (e) => {
        valPortThreshold.textContent = e.target.value;
        sendThresholds();
    });
    sliderPortWindow.addEventListener("input", (e) => {
        valPortWindow.textContent = parseFloat(e.target.value).toFixed(1) + "s";
        sendThresholds();
    });
    sliderSynThreshold.addEventListener("input", (e) => {
        valSynThreshold.textContent = e.target.value;
        sendThresholds();
    });
    sliderSynRatio.addEventListener("input", (e) => {
        valSynRatio.textContent = parseFloat(e.target.value).toFixed(1);
        sendThresholds();
    });
}

// Drawer handlers
function openSettings() {
    drawerSettings.classList.add("open");
    drawerSettings.setAttribute("aria-hidden", "false");
    btnSettingsToggle.setAttribute("aria-expanded", "true");
    overlayDrawer.classList.add("visible");
}

function closeSettings() {
    drawerSettings.classList.remove("open");
    drawerSettings.setAttribute("aria-hidden", "true");
    btnSettingsToggle.setAttribute("aria-expanded", "false");
    overlayDrawer.classList.remove("visible");
}

// Fetch network interfaces
async function fetchInterfaces() {
    try {
        const response = await fetch("/interfaces");
        const data = await response.json();
        populateInterfaces(data.interfaces);
    } catch (err) {
        console.warn("Failed to fetch /interfaces. Retrying with /api/interfaces...", err);
        try {
            const response = await fetch("/api/interfaces");
            const data = await response.json();
            populateInterfaces(data.interfaces);
        } catch (err2) {
            console.error("Failed to retrieve network interfaces:", err2);
        }
    }
}

function populateInterfaces(interfaces) {
    selectInterface.innerHTML = "";
    if (!interfaces || interfaces.length === 0) {
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "No interfaces found";
        selectInterface.appendChild(opt);
        return;
    }
    
    interfaces.forEach(iface => {
        const opt = document.createElement("option");
        opt.value = iface;
        opt.textContent = iface;
        selectInterface.appendChild(opt);
    });
    
    // Choose sensible default interface
    if (interfaces.includes("en0")) selectInterface.value = "en0";
    else if (interfaces.includes("eth0")) selectInterface.value = "eth0";
    else if (interfaces.includes("lo0")) selectInterface.value = "lo0";
    else if (interfaces.includes("lo")) selectInterface.value = "lo";
    else selectInterface.value = interfaces[0];
}

// Check if sniffer is running on backend
async function checkInitialSniffingStatus() {
    try {
        const response = await fetch("/status");
        const data = await response.json();
        if (data.status === "started") {
            setSniffingState(true);
        } else {
            setSniffingState(false);
        }
    } catch (err) {
        console.warn("Failed to check status from /status, trying /api/status...", err);
        try {
            const response = await fetch("/api/status");
            const data = await response.json();
            setSniffingState(data.status === "started");
        } catch (err2) {
            console.error("Could not fetch status:", err2);
        }
    }
}

// WebSocket Connection
function connectWebSocket() {
    const wsProto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProto}//${window.location.host}/ws`;
    
    ws = new WebSocket(wsUrl);
    
    const statusDiv = document.getElementById("connection-status");
    const statusText = statusDiv.querySelector(".status-text");
    
    ws.onopen = () => {
        statusDiv.className = "connection-status connected";
        statusText.textContent = "Connected";
        console.log("WebSocket connected successfully");
        
        // Fetch current snapshot of data
        ws.send(JSON.stringify({ action: "get_alerts" }));
        ws.send(JSON.stringify({ action: "get_hosts" }));
    };
    
    ws.onclose = () => {
        statusDiv.className = "connection-status disconnected";
        statusText.textContent = "Disconnected";
        console.warn("WebSocket disconnected. Attempting reconnection in 3 seconds...");
        setTimeout(connectWebSocket, 3000);
    };
    
    ws.onerror = (err) => {
        console.error("WebSocket encountered an error:", err);
    };
    
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleWSMessage(msg);
        } catch (e) {
            console.error("Failed to parse WebSocket message:", e);
        }
    };
}

// WS Message router
function handleWSMessage(msg) {
    if (!msg) return;
    
    // Check if it's a direct packet or alert update
    if (msg.type === "packet") {
        processPacket(msg);
    } else if (msg.type === "PORT_SCAN" || msg.type === "SYN_FLOOD") {
        processAlert(msg);
    } else if (msg.type === "alerts") {
        // Clear alerts placeholder and render current alert logs
        const placeholder = alertLogs.querySelector(".placeholder-msg");
        if (placeholder && msg.alerts.length > 0) placeholder.remove();
        
        msg.alerts.forEach(alert => {
            addAlertToUI(alert, false);
        });
        
        alertsCount = msg.alerts.length;
        valAlerts.textContent = alertsCount;
        valAlertBadgeCount.textContent = alertsCount;
        
        // Mark threat alert IPs as suspicious
        msg.alerts.forEach(alert => {
            if (alert.source_ip) {
                markHostSuspicious(alert.source_ip);
            }
        });
    } else if (msg.type === "hosts") {
        msg.hosts.forEach(ip => {
            addOrUpdateHost(ip, 0);
        });
    } else if (msg.type === "status") {
        if (msg.status === "started" || msg.status === "already running") {
            setSniffingState(true);
        } else if (msg.status === "stopped") {
            setSniffingState(false);
        }
    }
}

// Process single packet
function processPacket(packet) {
    // 1. Increment total packet counter
    packetCount++;
    valPackets.textContent = packetCount.toLocaleString();
    
    // 2. Prepend row to real-time table
    addPacketToStream(packet);
    
    // 3. Update active hosts map
    if (packet.src) addOrUpdateHost(packet.src, 1);
    if (packet.dst) addOrUpdateHost(packet.dst, 1);
    
    // 4. Update service monitoring grid if packet has identified service
    if (packet.service) {
        updateServiceCard(packet.service);
    }
}

// Add row to Packet Stream table
function addPacketToStream(packet) {
    const placeholder = packetStreamBody.querySelector(".placeholder-row");
    if (placeholder) placeholder.remove();
    
    const tr = document.createElement("tr");
    tr.className = "new-packet-row";
    
    const packetTime = packet.time ? new Date(packet.time * 1000) : new Date();
    const timeStr = packetTime.toLocaleTimeString() + "." + String(packetTime.getMilliseconds()).padStart(3, '0');
    
    const protoClass = `proto-${(packet.proto || "other").toLowerCase()}`;
    const serviceName = packet.service || "";
    const serviceClass = serviceName ? `service-lbl-${serviceName.toLowerCase()}` : "";
    
    tr.innerHTML = `
        <td class="cell-time">${timeStr}</td>
        <td class="cell-ip">${packet.src || "N/A"}</td>
        <td class="cell-ip">${packet.dst || "N/A"}</td>
        <td><span class="cell-proto ${protoClass}">${packet.proto || "OTHER"}</span></td>
        <td>${packet.length || 0} B</td>
        <td class="cell-service ${serviceClass}">${serviceName}</td>
    `;
    
    packetStreamBody.insertBefore(tr, packetStreamBody.firstChild);
    
    // Enforce 50 rows limit
    while (packetStreamBody.children.length > 50) {
        packetStreamBody.lastChild.remove();
    }
}

// Add or update active host entry
function addOrUpdateHost(ip, incrementBy = 1) {
    if (!ip) return;
    
    const placeholder = hostsList.querySelector(".placeholder-msg");
    if (placeholder) placeholder.remove();
    
    const hostId = `host-${ip.replace(/\./g, '-')}`;
    
    if (hostsMap.has(ip)) {
        const host = hostsMap.get(ip);
        host.count += incrementBy;
        
        const countEl = host.element.querySelector(".host-packet-count");
        if (countEl && incrementBy > 0) {
            countEl.textContent = host.count;
        }
    } else {
        const li = document.createElement("li");
        li.className = "host-item";
        li.id = hostId;
        
        li.innerHTML = `
            <div class="host-info">
                <span class="host-ip">${ip}</span>
                <span class="host-stats"><span class="host-packet-count">${incrementBy}</span> packets</span>
            </div>
            <span class="host-badge-status status-safe">Safe</span>
        `;
        
        hostsList.appendChild(li);
        
        hostsMap.set(ip, {
            element: li,
            count: incrementBy,
            status: "safe"
        });
        
        hostsCount = hostsMap.size;
        valHosts.textContent = hostsCount;
    }
}

// Mark a host as suspicious
function markHostSuspicious(ip) {
    if (!ip) return;
    
    if (!hostsMap.has(ip)) {
        addOrUpdateHost(ip, 0);
    }
    
    const host = hostsMap.get(ip);
    host.status = "suspicious";
    
    const badge = host.element.querySelector(".host-badge-status");
    if (badge) {
        badge.className = "host-badge-status status-suspicious";
        badge.textContent = "Suspicious";
    }
}

// Trigger active state on Service Card
function updateServiceCard(serviceName) {
    const service = services[serviceName];
    if (!service) return;
    
    service.packetCount++;
    
    const card = document.getElementById(service.cardId);
    if (!card) return;
    
    // Update counter
    const numEl = card.querySelector(".counter-num");
    if (numEl) numEl.textContent = service.packetCount.toLocaleString();
    
    // Add glowing class and toggle pill status
    card.classList.add("active");
    const statusPill = card.querySelector(".status-pill");
    if (statusPill) {
        statusPill.textContent = "Active";
        statusPill.className = "status-pill status-active";
    }
    
    // Reset timer to remove glow after 2 seconds of inactivity
    if (serviceTimers[serviceName]) {
        clearTimeout(serviceTimers[serviceName]);
    }
    
    serviceTimers[serviceName] = setTimeout(() => {
        card.classList.remove("active");
        if (statusPill) {
            statusPill.textContent = "Idle";
            statusPill.className = "status-pill status-idle";
        }
        delete serviceTimers[serviceName];
    }, 2000);
}

// Process incoming Alert
function processAlert(alert) {
    // 1. Play visual flash effect
    triggerVisualAlert();
    
    // 2. Prepend alert card
    addAlertToUI(alert, true);
    
    // 3. Increment counters
    alertsCount++;
    valAlerts.textContent = alertsCount;
    valAlertBadgeCount.textContent = alertsCount;
    
    // 4. Mark source IP as suspicious in Hosts list
    if (alert.source_ip) {
        markHostSuspicious(alert.source_ip);
    }
}

// Render alert in the Live Alert Logs
function addAlertToUI(alert, shouldFlash) {
    const placeholder = alertLogs.querySelector(".placeholder-msg");
    if (placeholder) placeholder.remove();
    
    const alertId = `alert-${alert.source_ip}-${alert.timestamp}`.replace(/\./g, '-');
    if (document.getElementById(alertId)) return; // prevent duplicate logs
    
    const alertDiv = document.createElement("div");
    alertDiv.id = alertId;
    alertDiv.className = "alert-item";
    
    const alertTime = alert.timestamp ? new Date(alert.timestamp * 1000) : new Date();
    const timeStr = alertTime.toLocaleTimeString() + "." + String(alertTime.getMilliseconds()).padStart(3, '0');
    
    alertDiv.innerHTML = `
        <div class="alert-header">
            <span class="alert-type">${alert.type}</span>
            <span class="alert-time">${timeStr}</span>
        </div>
        <div class="alert-ip">IP: ${alert.source_ip}</div>
        <div class="alert-detail">${alert.message}</div>
    `;
    
    alertLogs.insertBefore(alertDiv, alertLogs.firstChild);
}

// Trigger body flashing visual cue
function triggerVisualAlert() {
    document.body.classList.remove("alarm-flash");
    void document.body.offsetWidth; // Force Reflow
    document.body.classList.add("alarm-flash");
    
    setTimeout(() => {
        document.body.classList.remove("alarm-flash");
    }, 400);
}

// Update local UI state for Start/Stop sniffing
function setSniffingState(active) {
    isSniffing = active;
    
    if (active) {
        btnStart.disabled = true;
        btnStop.disabled = false;
        selectInterface.disabled = true;
    } else {
        btnStart.disabled = false;
        btnStop.disabled = true;
        selectInterface.disabled = false;
    }
}

// Start Sniffing
async function startSniffing() {
    const selectedIface = selectInterface.value;
    if (!selectedIface) {
        alert("Please select a valid network interface first.");
        return;
    }
    
    const payload = {
        interface: selectedIface,
        threshold: parseInt(sliderPortThreshold.value),
        window: parseFloat(sliderPortWindow.value),
        syn_flood_threshold: parseInt(sliderSynThreshold.value),
        syn_flood_ratio: parseFloat(sliderSynRatio.value)
    };
    
    try {
        const response = await fetch("/start", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        if (data.status === "started" || data.status === "already running") {
            setSniffingState(true);
            console.log("Sniffing session initialized.");
        } else {
            console.error("Sniffing start rejected:", data.status);
        }
    } catch (err) {
        console.error("Network error during sniffing start request:", err);
    }
}

// Stop Sniffing
async function stopSniffing() {
    try {
        const response = await fetch("/stop", {
            method: "POST"
        });
        
        const data = await response.json();
        if (data.status === "stopped") {
            setSniffingState(false);
            console.log("Sniffing session halted.");
        } else {
            console.error("Sniffing stop rejected:", data.status);
        }
    } catch (err) {
        console.error("Network error during sniffing stop request:", err);
    }
}

// Send settings values to backend on range updates
let sendThresholdsTimeout = null;
function sendThresholds() {
    if (!isSniffing) return;
    
    // Debounce backend requests to avoid hammering on slider drag
    if (sendThresholdsTimeout) clearTimeout(sendThresholdsTimeout);
    
    sendThresholdsTimeout = setTimeout(async () => {
        const payload = {
            interface: selectInterface.value,
            threshold: parseInt(sliderPortThreshold.value),
            window: parseFloat(sliderPortWindow.value),
            syn_flood_threshold: parseInt(sliderSynThreshold.value),
            syn_flood_ratio: parseFloat(sliderSynRatio.value)
        };
        
        try {
            await fetch("/start", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });
            console.log("Analyzer thresholds updated dynamically.");
        } catch (err) {
            console.error("Failed to update thresholds:", err);
        }
    }, 300);
}
