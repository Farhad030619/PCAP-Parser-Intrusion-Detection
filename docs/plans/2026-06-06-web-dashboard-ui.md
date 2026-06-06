# Web Dashboard UI Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a gorgeous, premium web-based graphical user interface (Web GUI) for the PCAP IDS. The dashboard will connect via WebSockets to a Python FastAPI backend, showing live traffic metrics, glowing brand cards when popular services (TikTok, YouTube, etc.) are active, live alert warnings with flashing red states, a network host list, and real-time settings adjustments via sliders.

**Architecture:**
- **`src/web_ui.py`**: A FastAPI backend running uvicorn. Spawns a background thread to sniff live packets using Scapy. Broadcasts packets, active hosts, service states, and alerts in JSON format over a WebSocket connection to connected clients. Tracks DNS queries to resolve IP-to-Service mappings (e.g. mapping TikTok IPs).
- **`src/static/index.html`**: Structured dashboard utilizing glassmorphism elements, clean layout.
- **`src/static/style.css`**: Vanilla CSS following the "Rich Aesthetics" guidelines. Uses Inter font, sleek dark slate palette, neon glowing cards for services, and dynamic animations.
- **`src/static/app.js`**: JavaScript to handle WebSocket lifecycle, update DOM elements, pulse service cards, and bind UI control actions (start/stop, adjust sliders).

**Tech Stack:**
- FastAPI, uvicorn (for WebSockets and serving static files)
- Scapy (network capture backend)
- Chart.js (optional, for traffic visualization)
- Vanilla HTML/CSS/JS (no Tailwind, pure CSS custom properties)

---

### Task 1: Update Dependencies and Setup FastAPI Backend

**Files:**
- Modify: `pyproject.toml`
- Modify: `requirements.txt`
- Create: `src/web_ui.py`

**Step 1: Update dependencies**
Add `fastapi` and `uvicorn` to dependencies.

**Step 2: Implement FastAPI app in `src/web_ui.py`**
- Create background Scapy thread that feeds packets to a queue or process loop.
- Implement DNS resolver tracker:
  - Check UDP port 53 (DNS) queries. Map resolved IPs to service names:
    - `"tiktok"` or `"byteoversea"` -> TikTok
    - `"youtube"` or `"googlevideo"` -> YouTube
    - `"spotify"` -> Spotify
    - `"google"` -> Google
    - `"github"` -> GitHub
    - `"netflix"` -> Netflix
- Add WebSocket endpoint `/ws` which sends live packet events, active services state, and alerts.
- Serve static files from `src/static/`.

---

### Task 2: Create Web Frontend (HTML, CSS, JS)

**Files:**
- Create: `src/static/index.html`
- Create: `src/static/style.css`
- Create: `src/static/app.js`

**Step 1: Write `index.html`**
Create clean dashboard layout:
- Top bar with connection status, interface selector, and start/stop controls.
- Main dashboard area with counters (Packets, active hosts, alerts).
- Service cards (TikTok, YouTube, Spotify, Google, GitHub, Netflix) with placeholder styling ready for glowing indicators.
- Live alerts log.
- Live packets table.
- Active host list.
- Settings panel with sliders.

**Step 2: Write `style.css`**
- Apply CSS variables for primary, secondary, slate, neon colors.
- Use glassmorphism: `background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08);`.
- Custom glowing indicator animations (`@keyframes pulse-glow`, `@keyframes alarm-flash`).
- Set specific brand colors for brand glows:
  - TikTok: `#ff0050` / `#00f2fe`
  - Spotify: `#1db954`
  - YouTube: `#ff0000`
  - Google: `#4285f4`
  - GitHub: `#ffffff`
  - Netflix: `#e50914`

**Step 3: Write `app.js`**
- Establish WebSocket connection.
- Update packet counter, active host list, and live logs.
- When packet service matches (e.g. "TikTok"), add "active" class to TikTok card to trigger the neon glow, and fade it out after 2 seconds of inactivity.
- If a threat alert is received, trigger a screen-flash effect and append an alert card with red neon borders.
- Sync UI sliders with WebSocket commands to adjust `NetworkAnalyzer` settings.

---

### Task 3: Implement Web Interface Tests and Documentation

**Files:**
- Create: `tests/test_web.py`
- Modify: `README.md`

**Step 1: Implement basic tests**
- Verify FastAPI starts up and serves static files.
- Verify WebSocket connection succeeds.

**Step 2: Update README.md**
- Describe how to start the Web UI (`sudo python3 src/web_ui.py`).
- Show screenshot/UI description.
