# Live Sniffing Upgrade Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Upgrade the PCAP IDS tool to support real-time network sniffing (live mode) in addition to offline PCAP parsing, allowing users to run the program in the background and receive live security alerts.

**Architecture:**
- **`src/cli.py`**: Add a new argument `--live` and optional `--interface` (to specify a network card, e.g. `eth0` or `en0`).
  - If `--live` is specified, use Scapy's `sniff()` function to capture packets from the network interface in real time and pass them to `NetworkAnalyzer.process_packet`.
  - Otherwise, parse the PCAP file as before.
- **`tests/test_analyzer.py`**: Add tests to ensure `--live` parsing handles inputs correctly and integration works.

**Tech Stack:**
- Python 3.12+ / Scapy / Pytest

---

### Task 1: Update CLI to Support Live Sniffing Argument and Flow

**Files:**
- Modify: `src/cli.py`

**Step 1: Modify arguments in `src/cli.py`**
- Change `pcap_file` to be optional if `--live` is specified:
  - We can use `nargs="?"` for `pcap_file`.
  - Add `--live` flag (boolean, action="store_true").
  - Add `-i` / `--interface` (string, default None, to select specific interface).

**Step 2: Add Live Sniffing Loop in `src/cli.py`**
- In `main()`, if `args.live` is True:
  - Print Cyan start message: `"Starting live network sniffing on interface: [default/configured]..."`
  - Setup packet sniffer:
    ```python
    from scapy.all import sniff
    # Run sniff with prn=analyzer.process_packet and store=False (so we don't save all packets in RAM)
    try:
        sniff(iface=args.interface, prn=analyzer.process_packet, store=False)
    except KeyboardInterrupt:
        # Graceful exit on Ctrl+C
        print("\n\033[92mStopping live sniffing...\033[0m")
    ```
- Add keyboard interrupt handling to print final summary statistics when the user stops the live capture with Ctrl+C.

---

### Task 2: Implement Unit and Integration Tests for Live Mode

**Files:**
- Modify: `tests/test_analyzer.py`

**Step 1: Write integration tests**
- Verify that if `pcap_file` is not provided and `--live` is NOT specified, the CLI exits with code 1 and prints an error.
- Verify that `--live` starts sniffing without throwing errors (mocking Scapy's `sniff` function to ensure we don't block tests waiting for actual packets).

---

### Task 3: Update Readme and Wireshark Guide

**Files:**
- Modify: `README.md`
- Modify: `WIRESHARK_GUIDE.md`

**Step 1: Update README.md**
- Document the new `--live` and `-i` / `--interface` arguments.
- Show examples of how to run live sniffing (noting that `sudo` is required on macOS/Linux for live sniffing due to raw socket access requirements).

**Step 2: Update WIRESHARK_GUIDE.md**
- Mention that live sniffing can be run directly using the CLI tool instead of manually capturing in Wireshark and loading, providing a direct comparison.
