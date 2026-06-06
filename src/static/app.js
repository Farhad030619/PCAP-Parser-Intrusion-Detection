// Helper for XSS escaping
function escapeHTML(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Global State
let ws = null;
let packetCount = 0;
let hostsCount = 0;
const hostsMap = new Map(); // IP -> { element, count, status }
let alertsCount = 0;
let isSniffing = false;
// Service Config — populated dynamically from traffic
const services = new Map(); // serviceName -> { cardElement, packetCount }
const serviceTimers = {};

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

const sliderSynThreshold = document.getElementById("slider-syn-threshold");
const sliderSynRatio = document.getElementById("slider-syn-ratio");

const valSynThreshold = document.getElementById("val-syn-threshold");
const valSynRatio = document.getElementById("val-syn-ratio");

// Mitigation Modal DOM Elements
const mitigationModal = document.getElementById("mitigation-modal");
const modalTitle = document.getElementById("modal-title");
const modalType = document.getElementById("modal-type");
const modalIp = document.getElementById("modal-ip");
const modalSeverity = document.getElementById("modal-severity");
const modalExplanation = document.getElementById("modal-explanation");
const modalCommands = document.getElementById("modal-commands");
const closeModal = document.querySelector(".close-modal");

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
    sliderSynThreshold.addEventListener("input", (e) => {
        valSynThreshold.textContent = e.target.value;
        sendThresholds();
    });
    sliderSynRatio.addEventListener("input", (e) => {
        valSynRatio.textContent = parseFloat(e.target.value).toFixed(1);
        sendThresholds();
    });

    // Mitigation Modal Events
    if (closeModal) {
        closeModal.addEventListener("click", closeMitigationModal);
    }
    if (mitigationModal) {
        mitigationModal.addEventListener("click", (e) => {
            if (e.target === mitigationModal) {
                closeMitigationModal();
            }
        });
    }
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && mitigationModal && mitigationModal.classList.contains("visible")) {
            closeMitigationModal();
        }
    });
}

function closeMitigationModal() {
    if (mitigationModal) {
        mitigationModal.classList.remove("visible");
        setTimeout(() => {
            if (!mitigationModal.classList.contains("visible")) {
                mitigationModal.style.display = "";
            }
        }, 300);
    }
}

function openMitigationModal(alert) {
    if (!mitigationModal) return;
    
    // Threat intelligence database — known attack types
    const knownThreats = {
        "SYN_FLOOD": {
            title: "SYN-Flood (DoS) Attack",
            type: "SYN-Flood (Denial of Service)",
            severity: "CRITICAL",
            known: true,
            explanation: "En SYN-Flood-attack försöker överbelasta din dator/server genom att skicka mängder av halva TCP-anslutningsförfrågningar (SYN-paket) utan att slutföra anslutningen. Detta gör att serverns anslutningskö fylls upp och legitima användare inte kan nå tjänsten.",
            mitigation: (ip) => `# === macOS (pfctl) ===\necho "block in quick from ${ip} to any" | sudo pfctl -a custom.block -f -\n\n# === Linux (iptables) ===\nsudo iptables -A INPUT -s ${ip} -j DROP\n\n# === Verifiera blockering ===\n# macOS: sudo pfctl -a custom.block -sr\n# Linux: sudo iptables -L -n | grep ${ip}`
        },
        "ARP_SPOOF": {
            title: "ARP-Spoofing (MitM) Detekterat",
            type: "ARP-Spoofing (Man-in-the-Middle)",
            severity: "HIGH",
            known: true,
            explanation: "En ARP-spoofing-attack sker när en angripare skickar falska ARP-meddelanden på det lokala nätverket. Detta gör att angriparens MAC-adress associeras med en legitim IP-adress (t.ex. routerns), vilket låter angriparen avlyssna eller manipulera din nätverkstrafik.",
            mitigation: (ip) => `# Statisk ARP-mappning för skydd av gateway (macOS/Linux):\n# Hitta din routers IP och korrekta MAC, konfigurera dem statiskt:\nsudo arp -s <Gateway_IP> <Legitim_MAC>\n\n# Exempel:\n# sudo arp -s 192.168.1.1 00:11:22:33:44:55`
        },
        "DNS_TUNNEL": {
            title: "DNS-Tunneling Detekterat",
            type: "DNS-Tunneling (Dataexfiltrering)",
            severity: "HIGH",
            known: true,
            explanation: "DNS-tunneling innebär att en angripare tunnlar godtycklig data (t.ex. känsliga filer eller fjärrstyrning) via DNS-protokollet. Det sker oftast genom att skicka många extremt långa subdomänförfrågningar till en extern namnserver kontrollerad av angriparen.",
            mitigation: (ip) => `# === macOS (pfctl) ===\necho "block out quick to ${ip}" | sudo pfctl -a custom.block -f -\n\n# === Linux (iptables) ===\nsudo iptables -A OUTPUT -d ${ip} -p udp --dport 53 -j DROP\n\n# Blockera DNS-trafik till den misstänkta externa namnservern.`
        },
        "BRUTE_FORCE": {
            title: "Brute-Force / Portskanning",
            type: "Brute-Force Anslutningsförsök",
            severity: "WARNING",
            known: true,
            explanation: "Systemet har upptäckt en stor mängd snabba och upprepade anslutningsförsök (TCP SYN) från denna käll-IP inom en kort tidsram. Detta kan tyda på ett brute-force-försök mot lokala tjänster (t.ex. SSH) eller en portskanning för att kartlägga öppna portar.",
            mitigation: (ip) => `# === macOS (pfctl) ===\necho "block in quick from ${ip} to any" | sudo pfctl -a custom.block -f -\n\n# === Linux (iptables) ===\nsudo iptables -A INPUT -s ${ip} -j DROP`
        }
    };
    
    const threatInfo = knownThreats[alert.type] || null;
    const ip = alert.source_ip || "<IP>";
    
    if (threatInfo) {
        modalTitle.textContent = threatInfo.title;
        modalType.innerHTML = `${escapeHTML(threatInfo.type)} <span class="known-threat-badge">Känt hot ✓</span>`;
        modalSeverity.textContent = threatInfo.severity;
        modalSeverity.className = "severity-badge severity-" + threatInfo.severity.toLowerCase();
        modalExplanation.textContent = threatInfo.explanation;
        modalCommands.textContent = threatInfo.mitigation(ip);
    } else {
        modalTitle.textContent = "Okänt hot detekterat";
        modalType.innerHTML = `${escapeHTML(alert.type || "UNKNOWN")} <span class="unknown-threat-badge">Okänt hot</span>`;
        modalSeverity.textContent = "WARNING";
        modalSeverity.className = "severity-badge severity-warning";
        modalExplanation.textContent = "Detta hot kunde inte identifieras automatiskt. Kontrollera loggarna noggrant och undersök IP-adressen.";
        modalCommands.textContent = `# Blockera IP-adressen som försiktighetsåtgärd:\n# macOS: echo "block in quick from ${ip} to any" | sudo pfctl -a custom.block -f -\n# Linux: sudo iptables -A INPUT -s ${ip} -j DROP`;
    }
    
    modalIp.textContent = ip;
    
    mitigationModal.style.display = "flex";
    mitigationModal.offsetHeight; // force reflow
    mitigationModal.classList.add("visible");
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
    } else if (msg.type === "SYN_FLOOD") {
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
    
    const protoClass = `proto-${escapeHTML((packet.proto || "other").toLowerCase())}`;
    const serviceName = packet.service || "";
    
    tr.innerHTML = `
        <td class="cell-time">${escapeHTML(timeStr)}</td>
        <td class="cell-ip">${escapeHTML(packet.src || "N/A")}</td>
        <td class="cell-ip">${escapeHTML(packet.dst || "N/A")}</td>
        <td><span class="cell-proto ${protoClass}">${escapeHTML(packet.proto || "OTHER")}</span></td>
        <td>${escapeHTML(packet.length || 0)} B</td>
        <td class="cell-service">${escapeHTML(serviceName)}</td>
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
                <span class="host-ip">${escapeHTML(ip)}</span>
                <span class="host-stats"><span class="host-packet-count">${escapeHTML(incrementBy)}</span> packets</span>
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

// Create or update a service card dynamically
function updateServiceCard(serviceName) {
    if (!serviceName) return;
    
    const servicesGrid = document.getElementById("services-grid");
    if (!servicesGrid) return;
    
    // Remove placeholder on first service
    const placeholder = document.getElementById("services-placeholder");
    if (placeholder) placeholder.remove();
    
    if (services.has(serviceName)) {
        // Update existing
        const svc = services.get(serviceName);
        svc.packetCount++;
        
        const countEl = svc.cardElement.querySelector(".counter-num");
        if (countEl) countEl.textContent = svc.packetCount.toLocaleString();
        
        // Pulse effect on activity
        svc.cardElement.classList.add("active");
        const indicator = svc.cardElement.querySelector(".activity-indicator");
        if (indicator) indicator.className = "activity-indicator indicator-active";
        
        if (serviceTimers[serviceName]) clearTimeout(serviceTimers[serviceName]);
        serviceTimers[serviceName] = setTimeout(() => {
            svc.cardElement.classList.remove("active");
            if (indicator) indicator.className = "activity-indicator indicator-idle";
            delete serviceTimers[serviceName];
        }, 3000);
    } else {
        // Create new card
        const card = document.createElement("div");
        card.className = "service-card active";
        card.dataset.service = serviceName;
        
        card.innerHTML = `
            <div class="service-row">
                <span class="activity-indicator indicator-active"></span>
                <span class="service-name">${escapeHTML(serviceName)}</span>
            </div>
            <div class="service-stats">
                <span class="counter-num">1</span>
                <span class="counter-lbl">packets</span>
            </div>
        `;
        
        servicesGrid.appendChild(card);
        
        services.set(serviceName, {
            cardElement: card,
            packetCount: 1
        });
        
        // Set idle timer
        serviceTimers[serviceName] = setTimeout(() => {
            card.classList.remove("active");
            const indicator = card.querySelector(".activity-indicator");
            if (indicator) indicator.className = "activity-indicator indicator-idle";
            delete serviceTimers[serviceName];
        }, 3000);
    }
}

// Process incoming Alert
function processAlert(alert) {
    // 1. Prepend alert card (triggers visual flash if shouldFlash is true)
    addAlertToUI(alert, true);
    
    // 2. Increment counters
    alertsCount++;
    valAlerts.textContent = alertsCount;
    valAlertBadgeCount.textContent = alertsCount;
    
    // 3. Mark source IP as suspicious in Hosts list
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
            <span class="alert-type">${escapeHTML(alert.type)}</span>
            <span class="alert-time">${escapeHTML(timeStr)}</span>
        </div>
        <div class="alert-ip">IP: ${escapeHTML(alert.source_ip)}</div>
        <div class="alert-detail">${escapeHTML(alert.message)}</div>
    `;
    
    alertDiv.addEventListener("click", () => {
        openMitigationModal(alert);
    });
    
    alertLogs.insertBefore(alertDiv, alertLogs.firstChild);

    if (shouldFlash) {
        triggerVisualAlert();
    }
}

// Trigger screen flash visual cue using alert overlay element
function triggerVisualAlert() {
    const overlay = document.getElementById("alert-overlay");
    if (!overlay) return;
    overlay.classList.add("active");
    
    setTimeout(() => {
        overlay.classList.remove("active");
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
