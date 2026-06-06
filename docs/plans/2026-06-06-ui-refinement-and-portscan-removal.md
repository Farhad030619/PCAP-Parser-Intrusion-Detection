# UI Refinement & Port Scan Removal Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refine the project by removing port scan detection (focusing solely on SYN Flood DoS), redesigning the web UI to look clean, human-designed and professional, removing the top-left logo, renaming the system to "NetShield IDS Dashboard", and implementing an interactive mitigation popup modal when clicking on threat alerts.

**Architecture:**
- **`src/analyzer.py`**: Remove port scan history, threshold, and logic. Keep only `syn_flood_threshold` and `syn_flood_ratio`.
- **`src/cli.py` & `src/web_ui.py`**: Remove port scan CLI arguments/REST parameters and simplify the analysis loop.
- **`src/static/index.html`**:
  - Rename title to "NetShield IDS Dashboard".
  - Remove the top-left header icon.
  - Remove port scan settings sliders.
  - Add a Modal structure (`#mitigation-modal`) to display threat details.
- **`src/static/style.css`**:
  - Simplify CSS: Tone down glowing brand-card animations. Ensure a clean, readable, professional corporate-grade dark security theme.
  - Implement styled modal stylesheet (`.modal`, `.modal-content`, etc.).
- **`src/static/app.js`**:
  - Remove references to port scans.
  - Wire up dynamic modal creation: clicking an alert displays the modal, injects threat context, severity, and mitigation instructions (e.g. pfctl firewall commands), and closes when clicking the close button or overlay.
- **`tests/`**: Remove port scan tests and verify all tests pass.

---

### Task 1: Clean codebase (Remove Port Scan detection)

**Files:**
- Modify: `src/analyzer.py`
- Modify: `src/cli.py`
- Modify: `src/web_ui.py`
- Modify: `tests/test_analyzer.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_web.py`

**Step 1: Simplify NetworkAnalyzer**
- Remove all port scan tracking and cooldown logic.
- Keep only SYN Flood logic.

**Step 2: Simplify CLI & Web API**
- Remove `-t`/`--port-threshold` and `-w`/`--port-window`.

**Step 3: Remove port scan tests & update existing tests**
- Delete test cases verifying port scan behavior. Keep and update CLI, Web and SYN Flood tests.
- Run `pytest` to verify.

---

### Task 2: Redesign Frontend (Human Design, Rename, Remove Icon, Add Modal)

**Files:**
- Modify: `src/static/index.html`
- Modify: `src/static/style.css`
- Modify: `src/static/app.js`

**Step 1: Update `index.html`**
- Change title and heading to "NetShield IDS".
- Remove the header icon `<img>` or SVG.
- Remove port scan sliders from the settings panel.
- Add markup for the `#mitigation-modal`:
  ```html
  <div id="mitigation-modal" class="modal">
      <div class="modal-content">
          <span class="close-modal">&times;</span>
          <h2 id="modal-title"></h2>
          <div class="modal-body">
              <p><strong>Typ av hot:</strong> <span id="modal-type"></span></p>
              <p><strong>Källa:</strong> <span id="modal-ip"></span></p>
              <p><strong>Allvarlighetsgrad:</strong> <span id="modal-severity" class="severity-badge"></span></p>
              <div id="modal-explanation"></div>
              <h3>Åtgärdsförslag (Mitigation):</h3>
              <pre id="modal-commands"></pre>
          </div>
      </div>
  </div>
  ```

**Step 2: Update `style.css`**
- Adjust typography and colors: Make colors balanced, less flashing.
- Add modal styles: semi-transparent backdrop overlay, transition scales, close buttons.

**Step 3: Update `app.js`**
- Remove port scan handlers.
- When an alert is created, add an event listener so clicking on it displays the modal:
  - Populate title, type, source IP, description, and copy-pasteable firewall commands (such as `sudo pfctl` for macOS or `sudo iptables` for Linux) to block the attacker IP.

---

### Task 3: Final Verification & Docs

**Files:**
- Modify: `README.md`
- Modify: `WIRESHARK_GUIDE.md`

**Step 1: Update README.md and guides**
- Remove references to port scans.
- Rename references from "Antigravity" to "NetShield".

**Step 2: Run pytest**
- Execute all tests to ensure 100% success.
